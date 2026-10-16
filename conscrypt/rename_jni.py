#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""rename_jni.py: give the system copy of Conscrypt its own JNI library name (review 1b, 2026-10-09).

    python3 -I rename_jni.py IN.jar OUT.jar      the aar's classes.jar -> the classes.jar that kktls-conscrypt dexes
    python3 -I rename_jni.py --selftest

Why: the aar's org.conscrypt.NativeCryptoJni calls System.loadLibrary("conscrypt_jni"). The 4.4 linker keys loaded
libraries by BASENAME (bionic/linker/linker.cpp find_loaded_library; soinfo_alloc stores the basename; DT_SONAME plays no
part), while Dalvik keys them by path. An app that bundles Conscrypt loads /data/app-lib/<pkg>/libconscrypt_jni.so; with
the gate on the wrapper's loader would load /system/lib/libconscrypt_jni.so: whichever comes second gets the first one's
handle from dlopen, and its JNI_OnLoad runs again against the other class loader's org.conscrypt classes (a different
Conscrypt version aborts the process in RegisterNatives, the same version overwrites the first user's cached class
references). Renaming the system copy's library to libkktls_conscrypt_jni.so (module libkktls_conscrypt_jni, the aar's .so
byte-identical) gives both copies their own soinfo. Pre-loading the renamed file from the wrapper cannot work:
NativeCrypto's static block still calls NativeCryptoJni.init(), whose loadLibrary("conscrypt_jni") then finds no file,
and the UnsatisfiedLinkError it catches makes Conscrypt unavailable.

What it does: in org/conscrypt/NativeCryptoJni.class the one CONSTANT_Utf8 "conscrypt_jni" (the operand of a
CONSTANT_String, i.e. the string literal) becomes "kktls_conscrypt_jni". The constant pool is parsed, not byte-replaced:
the entry's length changes, and every constant-pool reference is by index, so nothing else in the class moves.
Refuses (exit 1) unless the jar holds exactly one such Utf8, in that class, used only as a string literal, and no
"kktls_conscrypt_jni" yet; "conscrypt_gmscore_jni" and every other entry stay as they are. Every other member is carried
byte-for-byte (org/conscrypt/conscrypt.properties reaches the dex jar as a resource).

Deterministic: members in input order, all STORED (no zlib-version dependence), date 1980-01-01 00:00:00, mode 0644,
so the output sha256 is pinned in SHA256SUMS ("rename_jni/classes.jar") and checked by conscrypt/Android.mk. Stdlib
only, Python 3.4 compatible (the build container's python3 is 3.4.3).
"""
import hashlib
import io
import os
import struct
import sys
import tempfile
import zipfile

OLD = b"conscrypt_jni"
NEW = b"kktls_conscrypt_jni"
TARGET = "org/conscrypt/NativeCryptoJni.class"
DATE = (1980, 1, 1, 0, 0, 0)

# constant-pool tags -> fixed payload size (Utf8 = 1 is variable); 5/6 take two slots
CP_SIZE = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}


class RenameError(Exception):
    pass


def parse_cp(data):
    """[(index, tag, start, end)] of every constant-pool entry, and the offset just after the pool."""
    if data[:4] != b"\xca\xfe\xba\xbe" or len(data) < 10:
        raise RenameError("not a class file")
    count = struct.unpack_from(">H", data, 8)[0]
    entries, off, i = [], 10, 1
    try:
        while i < count:
            tag = data[off]
            if tag == 1:
                n = struct.unpack_from(">H", data, off + 1)[0]
                end = off + 3 + n
            elif tag in CP_SIZE:
                end = off + 1 + CP_SIZE[tag]
            else:
                raise RenameError("unknown constant-pool tag %d at entry %d" % (tag, i))
            if end > len(data):
                raise RenameError("truncated constant pool at entry %d" % i)
            entries.append((i, tag, off, end))
            off = end
            i += 2 if tag in (5, 6) else 1
    except (IndexError, struct.error):
        raise RenameError("truncated constant pool at entry %d" % i)
    return entries, off


def utf8_value(data, entry):
    return data[entry[2] + 3:entry[3]]


def find_utf8(data, value):
    """Constant-pool indices of the Utf8 entries equal to value, and of the entries that refer to each of them."""
    entries, _ = parse_cp(data)
    hits = [e[0] for e in entries if e[1] == 1 and utf8_value(data, e) == value]
    users = {}
    for idx, tag, start, end in entries:
        refs = []
        if tag in (7, 8, 16, 19, 20):  # Class, String, MethodType, Module, Package -> one Utf8 index
            refs = [struct.unpack_from(">H", data, start + 1)[0]]
        elif tag == 12:  # NameAndType -> name and descriptor
            refs = list(struct.unpack_from(">HH", data, start + 1))
        for r in refs:
            if r in hits:
                users.setdefault(r, []).append(tag)
    return hits, users


def rewrite_class(data):
    """data with the single Utf8 OLD replaced by NEW (constant pool rebuilt, the rest copied)."""
    entries, cp_end = parse_cp(data)
    out = [data[:10]]
    done = 0
    for idx, tag, start, end in entries:
        if tag == 1 and data[start + 3:end] == OLD:
            out.append(b"\x01" + struct.pack(">H", len(NEW)) + NEW)
            done += 1
        else:
            out.append(data[start:end])
    out.append(data[cp_end:])
    if done != 1:
        raise RenameError("%s: %d Utf8 %r rewritten, want 1" % (TARGET, done, OLD.decode()))
    return b"".join(out)


def scan(members):
    """{class name: (hits of OLD, hits of NEW, users of the OLD hits)} for every .class member that has either."""
    found = {}
    for name, data in members:
        if not name.endswith(".class"):
            continue
        old, users = find_utf8(data, OLD)
        new, _ = find_utf8(data, NEW)
        if old or new:
            found[name] = (old, new, users)
    return found


def check_input(members):
    found = scan(members)
    problems = []
    for name, (old, new, users) in sorted(found.items()):
        if new:
            problems.append("%s already has the Utf8 %r (rewritten twice?)" % (name, NEW.decode()))
        if old and name != TARGET:
            problems.append("%s has the Utf8 %r (only %s may load the library)" % (name, OLD.decode(), TARGET))
    tgt = found.get(TARGET)
    if tgt is None or len(tgt[0]) != 1:
        problems.append("%s: %d Utf8 %r, want exactly 1" % (TARGET, 0 if tgt is None else len(tgt[0]), OLD.decode()))
    else:
        tags = tgt[2].get(tgt[0][0], [])
        if tags != [8]:
            problems.append("%s: Utf8 %r is used by constant-pool tags %s, want one CONSTANT_String (8) only"
                            % (TARGET, OLD.decode(), tags))
    if problems:
        raise RenameError("; ".join(problems))


def check_output(members):
    found = scan(members)
    olds = sorted(n for n, v in found.items() if v[0])
    news = [(n, len(v[1])) for n, v in sorted(found.items()) if v[1]]
    if olds or news != [(TARGET, 1)]:
        raise RenameError("output: Utf8 %r in %s, Utf8 %r in %s (want none, and once in %s)"
                          % (OLD.decode(), olds, NEW.decode(), news, TARGET))


def read_members(path):
    with zipfile.ZipFile(path) as z:
        infos = [i for i in z.infolist() if not i.filename.endswith("/")]
        names = [i.filename for i in infos]
        if len(set(names)) != len(names):
            raise RenameError("%s has duplicate member names" % path)
        return [(i.filename, z.read(i)) for i in infos]


def write_members(path, members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, data in members:
            zi = zipfile.ZipInfo(name, DATE)
            zi.compress_type = zipfile.ZIP_STORED
            zi.create_system = 3
            zi.external_attr = 0o100644 << 16
            z.writestr(zi, data)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(buf.getvalue())
    os.rename(tmp, path)


def rename(src, dst):
    members = read_members(src)
    check_input(members)
    out = [(n, rewrite_class(d) if n == TARGET else d) for n, d in members]
    check_output(out)
    if [n for n, _ in out] != [n for n, _ in members]:
        raise RenameError("member list changed")
    changed = [n for (n, a), (_, b) in zip(members, out) if a != b]
    if changed != [TARGET]:
        raise RenameError("changed members %s, want only %s" % (changed, TARGET))
    write_members(dst, out)
    return len(out)


# --- selftest: synthetic class files (constant pool + an empty class body), no Conscrypt code ---------------------------

def _utf8(s):
    b = s.encode("utf-8")
    return b"\x01" + struct.pack(">H", len(b)) + b


def _class(strings=(), class_names=(), extra=b"", tail=b"\x00\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"):
    """A class file whose pool holds each string as Utf8 + CONSTANT_String, each class name as Utf8 + CONSTANT_Class,
    plus a Long (two slots) and a non-ASCII Utf8 so the slot arithmetic and byte copying are exercised."""
    cp = []
    for s in strings:
        cp.append(_utf8(s))
        cp.append(b"\x08" + struct.pack(">H", len(cp)))  # String -> the Utf8 just added (1-based index = len(cp))
    for c in class_names:
        cp.append(_utf8(c))
        cp.append(b"\x07" + struct.pack(">H", len(cp)))
    cp.append(b"\x05" + struct.pack(">q", 0x0123456789ABCDEF))
    n = len(cp) + 2  # the long takes two slots
    cp.append(_utf8("caf\u00e9-\u0434"))
    n += 1
    return b"\xca\xfe\xba\xbe\x00\x00\x00\x33" + struct.pack(">H", n) + b"".join(cp) + extra + tail


def _jar(path, members, compress=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compress) as z:
        for n, d in members:
            z.writestr(n, d)


def selftest():
    good_target = _class(["com.google.android.gms.org.conscrypt", "conscrypt_gmscore_jni", "conscrypt_jni"],
                         ["org/conscrypt/NativeCryptoJni", "java/lang/System"])
    other = _class(["hello"], ["org/conscrypt/Other"])
    props = b"org.conscrypt.version=2.5.3\n"
    base = [("org/conscrypt/Other.class", other), (TARGET, good_target), ("org/conscrypt/conscrypt.properties", props)]
    cases = [
        ("good", base, None),
        ("no target class", [m for m in base if m[0] != TARGET], "want exactly 1"),
        ("target without the literal", [("org/conscrypt/Other.class", other),
                                        (TARGET, _class(["conscrypt_gmscore_jni"], ["org/conscrypt/NativeCryptoJni"]))],
         "want exactly 1"),
        ("gmscore name only", [(TARGET, _class(["conscrypt_gmscore_jni"]))], "want exactly 1"),
        ("literal in a second class", base + [("org/conscrypt/Platform.class", _class(["conscrypt_jni"]))],
         "only org/conscrypt/NativeCryptoJni.class may load"),
        ("name used as a class name, not a string", [(TARGET, _class([], ["conscrypt_jni"]))], "CONSTANT_String"),
        ("already rewritten", [(TARGET, _class(["kktls_conscrypt_jni", "conscrypt_jni"]))], "already has"),
        ("truncated class", [(TARGET, good_target[:40])], "truncated"),
        ("unknown constant-pool tag", [(TARGET, good_target[:10] + b"\x02" + good_target[11:])], "unknown constant-pool"),
    ]
    # a pool with two Utf8 "conscrypt_jni" entries (javac never emits that, a hand-edited class could)
    two = _class(["conscrypt_jni"])
    cnt = struct.unpack_from(">H", two, 8)[0]
    two = two[:8] + struct.pack(">H", cnt + 1) + two[10:10] + _utf8("conscrypt_jni") + two[10:]
    cases.append(("literal twice in the target", [(TARGET, two)], "want exactly 1"))
    ok = True
    td = tempfile.mkdtemp(prefix="rename-jni-")
    try:
        for label, members, want_err in cases:
            src, dst = os.path.join(td, "in.jar"), os.path.join(td, "out.jar")
            _jar(src, members)
            try:
                rename(src, dst)
                err = None
            except RenameError as e:
                err = str(e)
            good = (err is None) if want_err is None else (err is not None and want_err in err)
            print("selftest %s %s: %s" % ("ok  " if good else "FAIL", label, err or "renamed"))
            ok &= good
        # the good output: only the target changed, the rewritten pool parses, the class body is intact
        src, dst, dst2 = (os.path.join(td, n) for n in ("in.jar", "out.jar", "out2.jar"))
        _jar(src, base)
        rename(src, dst)
        out = read_members(dst)
        checks = []
        checks.append(("member order and names kept", [n for n, _ in out] == [n for n, _ in base]))
        checks.append(("other members byte-identical", [d for n, d in out if n != TARGET] ==
                       [d for n, d in base if n != TARGET]))
        t = dict(out)[TARGET]
        checks.append(("target: one Utf8 kktls_conscrypt_jni, no conscrypt_jni", find_utf8(t, NEW)[0] and
                       len(find_utf8(t, NEW)[0]) == 1 and not find_utf8(t, OLD)[0]))
        checks.append(("target: gmscore name untouched", len(find_utf8(t, b"conscrypt_gmscore_jni")[0]) == 1))
        checks.append(("target: non-ASCII Utf8 and the class body after the pool unchanged",
                       t.endswith(_utf8("caf\u00e9-\u0434") + good_target[-14:]) and len(t) == len(good_target) + len(NEW) - len(OLD)))
        checks.append(("target: same pool indices (the String still points at the renamed Utf8)",
                       find_utf8(t, NEW)[1] == find_utf8(good_target, OLD)[1]))
        with zipfile.ZipFile(dst) as z:
            checks.append(("all members STORED, 1980-01-01, 0644",
                           all(i.compress_type == zipfile.ZIP_STORED and i.date_time == DATE and
                               (i.external_attr >> 16) == 0o100644 for i in z.infolist())))
        rename(src, dst2)
        with open(dst, "rb") as a, open(dst2, "rb") as b:
            checks.append(("two runs byte-identical", a.read() == b.read()))
        _jar(src, base, zipfile.ZIP_STORED)  # input compression does not leak into the output
        rename(src, dst2)
        with open(dst, "rb") as a, open(dst2, "rb") as b:
            checks.append(("output independent of the input's compression", a.read() == b.read()))
        try:
            rename(dst, os.path.join(td, "out3.jar"))
            checks.append(("refuses its own output", False))
        except RenameError as e:
            checks.append(("refuses its own output", "already has" in str(e) or "want exactly 1" in str(e)))
        for label, good in checks:
            print("selftest %s %s" % ("ok  " if good else "FAIL", label))
            ok &= bool(good)
    finally:
        for n in os.listdir(td):
            os.remove(os.path.join(td, n))
        os.rmdir(td)
    print("SELFTEST %s (%d cases)" % ("PASS" if ok else "FAIL", len(cases) + len(checks)))
    return ok


def main(argv):
    if argv[1:] == ["--selftest"]:
        return 0 if selftest() else 1
    if len(argv) != 3:
        sys.stderr.write("usage: rename_jni.py IN.jar OUT.jar | --selftest\n")
        return 2
    try:
        n = rename(argv[1], argv[2])
    except (RenameError, zipfile.BadZipfile, IOError, OSError) as e:
        sys.stderr.write("rename_jni.py: %s: %s\n" % (argv[1], e))
        return 1
    with open(argv[2], "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    print("rename_jni.py: %s -> %s (%d members, %s: Utf8 %s -> %s), sha256 %s"
          % (argv[1], argv[2], n, TARGET, OLD.decode(), NEW.decode(), digest))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
