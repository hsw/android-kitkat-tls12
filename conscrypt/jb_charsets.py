#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""jb_charsets.py: take java.nio.charset.StandardCharsets (API 19) out of the Jelly Bean copy of Conscrypt.

    python3 -I jb_charsets.py IN.jar OUT.jar      the rename_jni.py output -> the classes.jar that the JB dex is made of
    python3 -I jb_charsets.py --selftest

Why: Conscrypt 2.6-alpha2 reads StandardCharsets.US_ASCII / UTF_8 in SSLUtils (ALPN: toProtocolBytes,
toProtocolString, decodeProtocols), NativeSsl (exportKeyingMaterial, clientPSKKeyRequested) and ScryptSecretKeyFactory.
The class is new in API 19 and d8 does not backport it, so on Android 4.1-4.3 every such access throws
NoClassDefFoundError: with ALPN negotiated, getApplicationProtocol() and close() of a Conscrypt socket fail (Task 1
smoke, apicheck WARN on API 16-18). The 4.4 dex is not touched (4.4 has the class).

What it does:
  1. in every class, the CONSTANT_Utf8 "java/nio/charset/StandardCharsets" becomes "org/conscrypt/KktlsStandardCharsets".
     The constant pool is parsed, not byte-replaced (the entry's length changes, every reference is by index). Refuses
     (exit 1) unless that Utf8 is used by CONSTANT_Class entries only, every Fieldref on the class names a field the shim
     has (US_ASCII or UTF_8, descriptor Ljava/nio/charset/Charset;), no Methodref/InterfaceMethodref names the class,
     no descriptor or signature names the type (Ljava/nio/charset/StandardCharsets;), no Utf8 holds the dotted name
     java.nio.charset.StandardCharsets (a reflective Class.forName would still reach the API 19 class), at least one
     class uses it, and neither the new name nor the shim member exists yet;
  2. appends org/conscrypt/KktlsStandardCharsets.class, generated here (no javac: the bytes must not depend on a
     compiler), equivalent to

         package org.conscrypt;
         public final class KktlsStandardCharsets {
             public static final java.nio.charset.Charset US_ASCII = java.nio.charset.Charset.forName("US-ASCII");
             public static final java.nio.charset.Charset UTF_8 = java.nio.charset.Charset.forName("UTF-8");
             private KktlsStandardCharsets() {}
         }

     (class file version 50, no branches, so no StackMapTable; Charset.forName exists since API 1, and both charsets
     are required on every Java platform). It is in package org.conscrypt, the only package the dex may hold
     (check_prebuilt.py dex-classes), and is loaded by the same class loader as the classes that use it.

Every other member is carried byte-for-byte. Deterministic: members in input order, the shim last, all STORED,
1980-01-01 00:00:00, mode 0644, so the output sha256 is pinned in SHA256SUMS ("2.6-alpha2/jb_charsets:classes.jar") and
checked by mkstage.py --jb. Stdlib only, Python 3.4 compatible.
"""
import hashlib
import os
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python3 -I leaves the script directory off sys.path
from rename_jni import RenameError, parse_cp, read_members, write_members, DATE  # noqa: E402

OLD = b"java/nio/charset/StandardCharsets"
NEW = b"org/conscrypt/KktlsStandardCharsets"
OLD_DESC = b"L" + OLD + b";"
OLD_DOTTED = OLD.replace(b"/", b".")  # the binary name, as Class.forName takes it
SHIM = NEW.decode() + ".class"
CHARSET_DESC = b"Ljava/nio/charset/Charset;"
FIELDS = ((b"US_ASCII", b"US-ASCII"), (b"UTF_8", b"UTF-8"))  # (field, charset name), in the shim's field order


class CharsetsError(RenameError):
    pass


def pool(data):
    """{index: (tag, start, end)} and the offset after the pool."""
    entries, end = parse_cp(data)
    return {i: (t, s, e) for i, t, s, e in entries}, end


def _u16(data, off):
    return struct.unpack_from(">H", data, off)[0]


def utf8_at(data, cp, idx):
    e = cp.get(idx)
    if e is None or e[0] != 1:
        raise CharsetsError("constant-pool index %d is not a Utf8" % idx)
    return data[e[1] + 3:e[2]]


def uses(data):
    """(Utf8 indices equal to OLD, {tag: count} of the entries referring to them, [(field, descriptor)] of the
    Fieldrefs on the class, number of Methodref/InterfaceMethodref on the class, whether OLD_DESC occurs inside any Utf8,
    whether NEW occurs as a Utf8)."""
    cp, _ = pool(data)
    hits = {i for i, (t, s, e) in cp.items() if t == 1 and data[s + 3:e] == OLD}
    users = {}
    for i, (t, s, e) in cp.items():
        refs = []
        if t in (7, 8, 16, 19, 20):
            refs = [_u16(data, s + 1)]
        elif t == 12:
            refs = [_u16(data, s + 1), _u16(data, s + 3)]
        for r in refs:
            if r in hits:
                users[t] = users.get(t, 0) + 1
    classes = {i for i, (t, s, e) in cp.items() if t == 7 and _u16(data, s + 1) in hits}
    fields, methods = [], 0
    for i, (t, s, e) in cp.items():
        if t in (9, 10, 11) and _u16(data, s + 1) in classes:
            if t == 9:
                nt = cp.get(_u16(data, s + 3))
                if nt is None or nt[0] != 12:
                    raise CharsetsError("Fieldref %d has no NameAndType" % i)
                fields.append((utf8_at(data, cp, _u16(data, nt[1] + 1)), utf8_at(data, cp, _u16(data, nt[1] + 3))))
            else:
                methods += 1
    desc = any(t == 1 and OLD_DESC in data[s + 3:e] for t, s, e in cp.values())
    new = any(t == 1 and data[s + 3:e] == NEW for t, s, e in cp.values())
    return hits, users, fields, methods, desc, new


def dotted(data):
    """Whether any Utf8 of the class contains OLD_DOTTED (a string literal for reflection, or part of one)."""
    cp, _ = pool(data)
    return any(t == 1 and OLD_DOTTED in data[s + 3:e] for t, s, e in cp.values())


def rewrite_class(data):
    """data with every Utf8 OLD replaced by NEW (constant pool rebuilt, the rest copied)."""
    entries, cp_end = parse_cp(data)
    out = [data[:10]]
    for idx, tag, start, end in entries:
        if tag == 1 and data[start + 3:end] == OLD:
            out.append(b"\x01" + struct.pack(">H", len(NEW)) + NEW)
        else:
            out.append(data[start:end])
    out.append(data[cp_end:])
    return b"".join(out)


def shim_class():
    """The bytes of org/conscrypt/KktlsStandardCharsets.class (see the module docstring)."""
    cp, index = [], {}

    def add(entry):
        if entry not in index:
            cp.append(entry)
            index[entry] = len(cp)
        return index[entry]

    def utf8(s):
        return add(b"\x01" + struct.pack(">H", len(s)) + s)

    def ref(tag, *idx):
        return add(bytes([tag]) + b"".join(struct.pack(">H", i) for i in idx))

    def cls(name):
        return ref(7, utf8(name))

    def nat(name, desc):
        return ref(12, utf8(name), utf8(desc))

    this, sup = cls(NEW), cls(b"java/lang/Object")
    code = utf8(b"Code")
    init, clinit, void = utf8(b"<init>"), utf8(b"<clinit>"), utf8(b"()V")
    obj_init = ref(10, sup, nat(b"<init>", b"()V"))
    for_name = ref(10, cls(b"java/nio/charset/Charset"), nat(b"forName", b"(Ljava/lang/String;)Ljava/nio/charset/Charset;"))
    body = b""
    fields = b""
    for field, name in FIELDS:
        s = ref(8, utf8(name))
        f = ref(9, this, nat(field, CHARSET_DESC))
        if s > 255:
            raise CharsetsError("ldc index %d does not fit one byte" % s)
        body += b"\x12" + bytes([s]) + b"\xb8" + struct.pack(">H", for_name) + b"\xb3" + struct.pack(">H", f)
        fields += struct.pack(">HHHH", 0x0019, utf8(field), utf8(CHARSET_DESC), 0)  # public static final

    def method(access, name, max_stack, max_locals, insns):
        attr = struct.pack(">HHI", max_stack, max_locals, len(insns)) + insns + struct.pack(">HH", 0, 0)
        return struct.pack(">HHHH", access, name, void, 1) + struct.pack(">HI", code, len(attr)) + attr

    methods = (method(0x0002, init, 1, 1, b"\x2a\xb7" + struct.pack(">H", obj_init) + b"\xb1") +  # private <init>
               method(0x0008, clinit, 1, 0, body + b"\xb1"))                                     # static <clinit>
    return (b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 50, len(cp) + 1) + b"".join(cp) +
            struct.pack(">HHHH", 0x0031, this, sup, 0) +  # public final super, no interfaces
            struct.pack(">H", len(FIELDS)) + fields + struct.pack(">H", 2) + methods + struct.pack(">H", 0))


def check_input(members):
    problems, users_found = [], []
    shim_fields = {f for f, _ in FIELDS}
    for name, data in members:
        if name == SHIM:
            problems.append("%s already exists (rewritten twice?)" % SHIM)
        if not name.endswith(".class"):
            continue
        hits, users, fields, methods, desc, new = uses(data)
        if new:
            problems.append("%s already has the Utf8 %r (rewritten twice?)" % (name, NEW.decode()))
        if desc:
            problems.append("%s names the type %s in a descriptor or signature" % (name, OLD_DESC.decode()))
        if dotted(data):
            problems.append("%s has a Utf8 with %s (reflection would still load the API 19 class)"
                            % (name, OLD_DOTTED.decode()))
        if not hits:
            continue
        users_found.append(name)
        if set(users) != {7}:
            problems.append("%s: Utf8 %r is used by constant-pool tags %s, want CONSTANT_Class (7) only"
                            % (name, OLD.decode(), sorted(users)))
        if methods:
            problems.append("%s calls %d method(s) of %s (the shim has fields only)" % (name, methods, OLD.decode()))
        for f, d in fields:
            if f not in shim_fields or d != CHARSET_DESC:
                problems.append("%s reads %s.%s %s (the shim has %s)" % (name, OLD.decode(), f.decode(), d.decode(),
                                                                         ", ".join(sorted(x.decode() for x in shim_fields))))
    if not users_found:
        problems.append("no class uses %s" % OLD.decode())
    if problems:
        raise CharsetsError("; ".join(problems))
    return users_found


def check_output(members):
    names = [n for n, _ in members]
    if names.count(SHIM) != 1 or names[-1] != SHIM:
        raise CharsetsError("output: %s must be the last member, once" % SHIM)
    for name, data in members:
        if name.endswith(".class"):
            hits, _, _, _, desc, _ = uses(data)
            if hits or desc or dotted(data):
                raise CharsetsError("output: %s still names %s" % (name, OLD.decode()))


def convert(src, dst):
    members = read_members(src)
    users = check_input(members)
    out = [(n, rewrite_class(d) if n in users else d) for n, d in members] + [(SHIM, shim_class())]
    check_output(out)
    changed = [n for (n, a), (_, b) in zip(members, out) if a != b]
    if changed != users:
        raise CharsetsError("changed members %s, want %s" % (changed, users))
    write_members(dst, out)
    return users


# --- selftest: synthetic class files (constant pool + an empty class body), no Conscrypt code ---------------------------

def _class(fields=(), methods=(), strings=(), descs=(), tail=b"\x00\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"):
    """A class file whose pool holds Fieldrefs (class, field, descriptor), Methodrefs (class, method, descriptor),
    String literals and bare Utf8 descriptors, plus a Long (two slots) and a non-ASCII Utf8."""
    cp, index = [], {}

    def add(e):
        if e not in index:
            cp.append(e)
            index[e] = len(cp) + sum(1 for x in cp[:-1] if x[:1] == b"\x05")
        return index[e]

    def utf8(s):
        return add(b"\x01" + struct.pack(">H", len(s)) + s)

    def ref(tag, *i):
        return add(bytes([tag]) + b"".join(struct.pack(">H", x) for x in i))

    for tag, items in ((9, fields), (10, methods)):
        for c, n, d in items:
            ref(tag, ref(7, utf8(c)), ref(12, utf8(n), utf8(d)))
    for s in strings:
        ref(8, utf8(s))
    for d in descs:
        utf8(d)
    add(b"\x05" + struct.pack(">q", 0x0123456789ABCDEF))
    utf8("caf\u00e9-\u0434".encode("utf-8"))
    n = len(cp) + 2
    return b"\xca\xfe\xba\xbe\x00\x00\x00\x33" + struct.pack(">H", n) + b"".join(cp) + tail


def _jar(path, members, compress=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compress) as z:
        for n, d in members:
            z.writestr(n, d)


def selftest():
    ascii_ref = (OLD, b"US_ASCII", CHARSET_DESC)
    utf8_ref = (OLD, b"UTF_8", CHARSET_DESC)
    user1 = _class(fields=[ascii_ref, utf8_ref], methods=[(b"java/lang/String", b"getBytes", b"()[B")])
    user2 = _class(fields=[ascii_ref])
    other = _class(strings=[b"hello"], methods=[(b"java/nio/charset/Charset", b"forName", b"(Ljava/lang/String;)V")])
    props = b"org.conscrypt.version.major=2\n"
    base = [("org/conscrypt/A.class", user1), ("org/conscrypt/B.class", other), ("org/conscrypt/C.class", user2),
            ("org/conscrypt/conscrypt.properties", props)]
    cases = [
        ("good", base, None),
        ("no user", [("org/conscrypt/B.class", other)], "no class uses"),
        ("field the shim lacks", base + [("org/conscrypt/D.class", _class(fields=[(OLD, b"ISO_8859_1", CHARSET_DESC)]))],
         "reads java/nio/charset/StandardCharsets.ISO_8859_1"),
        ("field with another descriptor", [("org/conscrypt/D.class", _class(fields=[(OLD, b"UTF_8", b"Ljava/lang/Object;")]))],
         "the shim has"),
        ("method call on the class", [("org/conscrypt/D.class", _class(fields=[ascii_ref], methods=[(OLD, b"x", b"()V")]))],
         "calls 1 method"),
        ("name as a string literal", [("org/conscrypt/D.class", _class(fields=[ascii_ref], strings=[OLD]))],
         "want CONSTANT_Class (7) only"),
        ("dotted name as a string literal", [("org/conscrypt/D.class", _class(fields=[ascii_ref], strings=[OLD_DOTTED]))],
         "has a Utf8 with java.nio.charset.StandardCharsets"),
        ("dotted name only (Class.forName)", base + [("org/conscrypt/D.class", _class(strings=[b"x" + OLD_DOTTED + b"$1"]))],
         "has a Utf8 with java.nio.charset.StandardCharsets"),
        ("type in a descriptor", [("org/conscrypt/D.class", _class(fields=[ascii_ref], descs=[b"()" + OLD_DESC]))],
         "in a descriptor"),
        ("already rewritten", [("org/conscrypt/D.class", _class(fields=[ascii_ref, (NEW, b"UTF_8", CHARSET_DESC)]))],
         "already has"),
        ("shim member present", base + [(SHIM, shim_class())], "already exists"),
        ("truncated class", [("org/conscrypt/A.class", user1[:40])], "truncated"),
    ]
    ok = True
    checks = []
    td = tempfile.mkdtemp(prefix="jb-charsets-")
    try:
        for label, members, want_err in cases:
            src, dst = os.path.join(td, "in.jar"), os.path.join(td, "out.jar")
            _jar(src, members)
            try:
                convert(src, dst)
                err = None
            except RenameError as e:
                err = str(e)
            good = (err is None) if want_err is None else (err is not None and want_err in err)
            print("selftest %s %s: %s" % ("ok  " if good else "FAIL", label, err or "rewritten"))
            ok &= good
        src, dst, dst2 = (os.path.join(td, n) for n in ("in.jar", "out.jar", "out2.jar"))
        _jar(src, base)
        users = convert(src, dst)
        out = read_members(dst)
        o = dict(out)
        checks.append(("users = the two classes with the Fieldrefs", users == ["org/conscrypt/A.class", "org/conscrypt/C.class"]))
        checks.append(("member order kept, shim last", [n for n, _ in out] == [n for n, _ in base] + [SHIM]))
        checks.append(("other members byte-identical", o["org/conscrypt/B.class"] == other and
                       o["org/conscrypt/conscrypt.properties"] == props))
        a = o["org/conscrypt/A.class"]
        h, u, f, m, d, new = uses(a)
        checks.append(("user: no old Utf8, the new one present, fields kept", not h and new and
                       len(a) == len(user1) + len(NEW) - len(OLD)))
        cp, _ = pool(a)
        checks.append(("user: same pool indices, Fieldrefs now on the shim",
                       sorted(cp) == sorted(pool(user1)[0]) and
                       sum(1 for t, s, e in cp.values() if t == 1 and a[s + 3:e] == NEW) == 1))
        checks.append(("user: non-ASCII Utf8 and the class body after the pool unchanged",
                       a[pool(a)[1] - 11:] == user1[pool(user1)[1] - 11:]))
        s = o[SHIM]
        scp, send = pool(s)
        names = {s[e[1] + 3:e[2]] for e in scp.values() if e[0] == 1}
        checks.append(("shim: parses, version 50, names its class, fields, Charset.forName and both charsets",
                       s[4:8] == b"\x00\x00\x00\x32" and
                       {NEW, b"US_ASCII", b"UTF_8", b"US-ASCII", b"UTF-8", b"forName", CHARSET_DESC} <= names))
        checks.append(("shim: public final, this = the shim, super = Object, no interfaces, 2 fields",
                       struct.unpack_from(">HHHH", s, send) == (0x0031, 2, 4, 0) and
                       utf8_at(s, scp, _u16(s, scp[2][1] + 1)) == NEW and
                       utf8_at(s, scp, _u16(s, scp[4][1] + 1)) == b"java/lang/Object" and
                       _u16(s, send + 8) == 2))
        checks.append(("shim: same bytes on every call", shim_class() == shim_class()))
        with zipfile.ZipFile(dst) as z:
            checks.append(("all members STORED, 1980-01-01, 0644",
                           all(i.compress_type == zipfile.ZIP_STORED and i.date_time == DATE and
                               (i.external_attr >> 16) == 0o100644 for i in z.infolist())))
        convert(src, dst2)
        with open(dst, "rb") as x, open(dst2, "rb") as y:
            checks.append(("two runs byte-identical", x.read() == y.read()))
        _jar(src, base, zipfile.ZIP_STORED)
        convert(src, dst2)
        with open(dst, "rb") as x, open(dst2, "rb") as y:
            checks.append(("output independent of the input's compression", x.read() == y.read()))
        try:
            convert(dst, os.path.join(td, "out3.jar"))
            checks.append(("refuses its own output", False))
        except RenameError as e:
            checks.append(("refuses its own output", "already" in str(e)))
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
        sys.stderr.write("usage: jb_charsets.py IN.jar OUT.jar | --selftest\n")
        return 2
    try:
        users = convert(argv[1], argv[2])
    except (RenameError, zipfile.BadZipfile, IOError, OSError) as e:
        sys.stderr.write("jb_charsets.py: %s: %s\n" % (argv[1], e))
        return 1
    with open(argv[2], "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    print("jb_charsets.py: %s -> %s (%s -> %s in %s; + %s), sha256 %s"
          % (argv[1], argv[2], OLD.decode(), NEW.decode(), ", ".join(users), SHIM, digest))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
