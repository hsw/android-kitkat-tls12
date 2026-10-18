#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""apicheck.py: which platform classes and members does a Conscrypt classes.jar reference that the 4.4 runtime lacks?

    python3 -I apicheck.py JAR --lib CORE.jar [--lib FRAMEWORK.jar ...] [--dex DEX.jar] [--allow apicheck-allow.txt]
                           [--baseline OLD_CLASSES.jar] [--api LEVEL] [--quiet]
    python3 -I apicheck.py --selftest

JAR is the jar before d8 (the aar's classes.jar, or rename_jni.py's output). Every class, field and method reference of
its classes (CONSTANT_Class/Fieldref/Methodref/InterfaceMethodref, the super class and the interfaces) that points
outside the jar is resolved against the class files of the --lib jars, unpacked here (never `javap -cp`, which falls
back to the host JDK silently). Members are looked up along the super class chain and all super interfaces (and
java/lang/Object), the way the VM resolves them. Arrays resolve to java/lang/Object. Each unresolved reference is printed
with its call sites (Class.method(desc) of every instruction that uses it; "<extends>"/"<implements>" for supertypes;
"<pool>" for an entry no instruction uses), and classified:

  d8        --dex is given and the reference is no longer in the dex jar's type/field/method ids: d8 --min-api 19 has
            desugared or backported it (e.g. Long.hashCode(J), API 24, in NativeRef.hashCode)
  allowed   an --allow line covers the reference and every one of its call sites; the line's reason names the guard
            (Build.VERSION.SDK_INT check, a class never instantiated on API 19, ...)
  WARN      neither: printed as "⚠️" and the exit status is 1

--baseline marks each unresolved reference that the baseline jar (the 2.5.3 classes.jar, which ran on the emulator and on
a device) has as well: "(also in baseline)"; new ones get "(new)". It only annotates, it never changes the verdict.

Allow file: one entry per line, '#' starts a comment line. Fields separated by ' | ':
    REF | SITES | REASON
REF is a class (javax/net/ssl/ExtendedSSLSession), a method (java/lang/Long.hashCode(J)I) or a field
(android/os/Build$VERSION.SDK_INT:I). SITES is a comma list of call-site prefixes ("org/conscrypt/Platform",
"org/conscrypt/Platform.wrapSSLSession", or "*"). A reference is allowed only if every call site matches a prefix.

The --lib set for Conscrypt on Android 4.4: out/target/common/obj/JAVA_LIBRARIES/{core,framework,conscrypt}_intermediates/
classes.jar of a built 4.4 tree (core = java.*, javax.*, dalvik.*; framework = android.*; conscrypt = the platform
com.android.org.conscrypt the KitKat adapter extends). Stdlib only; the jars are read as data.

--api LEVEL names the API level the --lib set is from and checks the dex against it: every D8 marker of the --dex jar
("~~D8{...,"min-api":N,...}") must have N <= LEVEL, else a dex built for a newer API (whose backports d8 left out, e.g.
java.util.Objects below 19) is checked against an older runtime; the mismatch is a WARN. For Jelly Bean (API 16, 17,
18) the --lib set is {core,framework}_intermediates/classes.jar of a built tree of that base (there is no platform
com.android.org.conscrypt before 4.4).
Exit status: 0 = no WARN, 1 = at least one WARN, 2 = usage or unreadable input.
"""
import argparse
import io
import json
import os
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python3 -I leaves the script directory off sys.path
from dexparse import dex_strings  # noqa: E402  (after the sys.path line)

# ------------------------------------------------------------------------------------------------- class file parsing

TAG_SIZES = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}


class ClassFileError(ValueError):
    pass


class ClassFile:
    """name, super_name, interfaces, fields {(name, desc)}, methods {(name, desc)}, refs [(kind, owner, name, desc)]
    with kind class/field/method, and sites {ref: set of sites}."""

    def __init__(self, data, want_code=True):
        self.data = data
        if data[:4] != b"\xca\xfe\xba\xbe":
            raise ClassFileError("not a class file")
        self.major = struct.unpack_from(">H", data, 6)[0]
        n = struct.unpack_from(">H", data, 8)[0]
        cp = [None] * n
        tags = [0] * n
        pos = 10
        i = 1
        while i < n:
            tag = data[pos]
            tags[i] = tag
            if tag == 1:
                ln = struct.unpack_from(">H", data, pos + 1)[0]
                cp[i] = data[pos + 3:pos + 3 + ln].decode("utf-8", "replace")
                pos += 3 + ln
            elif tag in TAG_SIZES:
                cp[i] = data[pos + 1:pos + 1 + TAG_SIZES[tag]]
                pos += 1 + TAG_SIZES[tag]
                if tag in (5, 6):
                    i += 1
            else:
                raise ClassFileError("unknown constant-pool tag %d at %d" % (tag, pos))
            i += 1
        self.cp, self.tags = cp, tags
        self.tag_counts = {}
        for t in tags:
            if t:
                self.tag_counts[t] = self.tag_counts.get(t, 0) + 1
        _, this, sup, ni = struct.unpack_from(">HHHH", data, pos)
        pos += 8
        self.name = self.class_name(this)
        self.super_name = self.class_name(sup) if sup else None
        self.interfaces = [self.class_name(struct.unpack_from(">H", data, pos + 2 * k)[0]) for k in range(ni)]
        pos += 2 * ni
        self.fields, pos = self._members(pos, None)
        self.method_codes = []
        self.methods, pos = self._members(pos, self.method_codes if want_code else None)

    def u2(self, idx_bytes, off=0):
        return struct.unpack_from(">H", idx_bytes, off)[0]

    def class_name(self, idx):
        if self.tags[idx] != 7:
            raise ClassFileError("pool #%d is not a class" % idx)
        return self.cp[self.u2(self.cp[idx])]

    def name_and_type(self, idx):
        b = self.cp[idx]
        return self.cp[self.u2(b)], self.cp[self.u2(b, 2)]

    def ref(self, idx):
        """(kind, owner, name, desc) of a Class/Fieldref/Methodref/InterfaceMethodref pool entry, else None."""
        tag = self.tags[idx]
        if tag == 7:
            return ("class", self.class_name(idx), "", "")
        if tag in (9, 10, 11):
            b = self.cp[idx]
            name, desc = self.name_and_type(self.u2(b, 2))
            return ("field" if tag == 9 else "method", self.class_name(self.u2(b)), name, desc)
        return None

    def _members(self, pos, codes):
        d = self.data
        n = struct.unpack_from(">H", d, pos)[0]
        pos += 2
        out = set()
        for _ in range(n):
            _, ni, di, na = struct.unpack_from(">HHHH", d, pos)
            pos += 8
            name, desc = self.cp[ni], self.cp[di]
            out.add((name, desc))
            for _ in range(na):
                an, ln = struct.unpack_from(">HI", d, pos)
                if codes is not None and self.cp[an] == "Code":
                    code_len = struct.unpack_from(">I", d, pos + 10)[0]
                    codes.append((name, desc, d[pos + 14:pos + 14 + code_len]))
                pos += 6 + ln
        return out, pos

    def code_refs(self):
        """Yields (method name, desc, pool index) for every instruction operand that is a pool index."""
        for mname, mdesc, code in self.method_codes:
            for idx in instruction_pool_refs(code):
                yield mname, mdesc, idx


# opcode -> length in bytes (including the opcode); 0 = variable (tableswitch, lookupswitch, wide)
OPLEN = [1] * 256
for _op in (0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3A, 0xA9, 0xBC):
    OPLEN[_op] = 2
for _op in list(range(0x99, 0xA9)) + [0x11, 0x13, 0x14, 0x84, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xBB, 0xBD,
                                      0xC0, 0xC1, 0xC6, 0xC7]:
    OPLEN[_op] = 3
OPLEN[0xC5] = 4
for _op in (0xB9, 0xBA, 0xC8, 0xC9):
    OPLEN[_op] = 5
OPLEN[0xAA] = OPLEN[0xAB] = OPLEN[0xC4] = 0
# opcodes whose u2 operand at +1 is a pool index (ldc has a u1 index)
POOL_U2 = {0x13, 0x14, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBD, 0xC0, 0xC1, 0xC5}


def instruction_pool_refs(code):
    pc = 0
    n = len(code)
    while pc < n:
        op = code[pc]
        if op == 0x12:
            yield code[pc + 1]
        elif op in POOL_U2:
            yield struct.unpack_from(">H", code, pc + 1)[0]
        ln = OPLEN[op]
        if ln:
            pc += ln
        elif op == 0xC4:  # wide
            pc += 6 if code[pc + 1] == 0x84 else 4
        else:
            base = pc + 1 + ((4 - (pc + 1) % 4) % 4)
            if op == 0xAA:  # tableswitch
                lo, hi = struct.unpack_from(">ii", code, base + 4)
                pc = base + 12 + 4 * (hi - lo + 1)
            else:  # lookupswitch
                npairs = struct.unpack_from(">i", code, base + 4)[0]
                pc = base + 8 + 8 * npairs


def collect_refs(cf):
    """{(kind, owner, name, desc): set(sites)} for the refs of one class (owner may be an array descriptor)."""
    out = {}
    used = set()
    for mname, mdesc, idx in cf.code_refs():
        r = cf.ref(idx)
        if r is None:
            continue
        used.add(idx)
        out.setdefault(r, set()).add("%s.%s%s" % (cf.name, mname, mdesc))
        if r[0] != "class":  # the owner class of a member ref is resolved as well
            out.setdefault(("class", r[1], "", ""), set()).add("%s.%s%s" % (cf.name, mname, mdesc))
    for i in range(1, len(cf.tags)):
        if cf.tags[i] in (7, 9, 10, 11) and i not in used:
            r = cf.ref(i)
            if r[0] == "class" and r[1] == cf.name:
                continue
            out.setdefault(r, set()).add("%s.<pool>" % cf.name)
    if cf.super_name:
        out.setdefault(("class", cf.super_name, "", ""), set()).add("%s.<extends>" % cf.name)
    for itf in cf.interfaces:
        out.setdefault(("class", itf, "", ""), set()).add("%s.<implements>" % cf.name)
    return out


def element_class(owner):
    """'[[Ljava/lang/String;' -> 'java/lang/String'; '[I' -> None (primitive array); plain names unchanged."""
    if not owner.startswith("["):
        return owner
    e = owner.lstrip("[")
    if e.startswith("L") and e.endswith(";"):
        return e[1:-1]
    return None


def read_jar_classes(path, want_code):
    out = {}
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.endswith(".class"):
                cf = ClassFile(z.read(n), want_code)
                out[cf.name] = cf
    return out


class Lib:
    def __init__(self, classes):
        self.classes = classes

    def has_member(self, owner, kind, name, desc, seen=None):
        """Field or method lookup through the super class chain and all super interfaces (JVMS 5.4.3.2/3/4)."""
        if seen is None:
            seen = set()
        if owner in seen or owner not in self.classes:
            return False
        seen.add(owner)
        cf = self.classes[owner]
        if (name, desc) in (cf.fields if kind == "field" else cf.methods):
            return True
        for nxt in ([cf.super_name] if cf.super_name else []) + cf.interfaces:
            if self.has_member(nxt, kind, name, desc, seen):
                return True
        if kind == "method" and owner != "java/lang/Object" and "java/lang/Object" not in seen:
            return self.has_member("java/lang/Object", kind, name, desc, seen)
        return False

    def missing(self, ref):
        kind, owner, name, desc = ref
        cls = element_class(owner)
        if cls is None:
            return None
        if owner.startswith("["):  # members of an array type: clone(), length, Object's methods
            if kind == "class":
                return None if cls in self.classes else "class"
            if kind == "method" and name == "clone" and desc == "()Ljava/lang/Object;":
                return None  # arrays implement clone() themselves
            return None if self.has_member("java/lang/Object", kind, name, desc) else "member"
        if cls not in self.classes:
            return "class"
        if kind != "class" and not self.has_member(cls, kind, name, desc):
            return "member"
        return None


def ref_str(ref):
    kind, owner, name, desc = ref
    if kind == "class":
        return owner
    if kind == "field":
        return "%s.%s:%s" % (owner, name, desc)
    return "%s.%s%s" % (owner, name, desc)


def unresolved(jar_classes, lib):
    """{ref string: (reason, sorted sites)} for references out of the jar that the lib does not resolve. A member whose
    owner class is missing is reported under the class only (the class line carries all sites)."""
    refs = {}
    for cf in jar_classes.values():
        for r, sites in collect_refs(cf).items():
            refs.setdefault(r, set()).update(sites)
    out = {}
    for r, sites in refs.items():
        cls = element_class(r[1])
        if cls is not None and cls in jar_classes:
            continue
        why = lib.missing(r)
        if why is None or (why == "class" and r[0] != "class"):
            continue
        out[ref_str(r)] = ("missing %s" % why, sorted(sites))
    return out


# ---------------------------------------------------------------------------------------------------------- dex ids

def dex_ids(d):
    """The class, field and method ids of one dex file in apicheck's ref_str form."""
    if d[:4] != b"dex\n":
        raise ValueError("not a dex file")
    s = dex_strings(d)
    tn, to = struct.unpack_from("<II", d, 0x40)
    types = [s[struct.unpack_from("<I", d, to + 4 * i)[0]] for i in range(tn)]
    pn, po = struct.unpack_from("<II", d, 0x48)
    protos = []
    for i in range(pn):
        _, ret, params = struct.unpack_from("<III", d, po + 12 * i)
        args = []
        if params:
            cnt = struct.unpack_from("<I", d, params)[0]
            args = [types[struct.unpack_from("<H", d, params + 4 + 2 * k)[0]] for k in range(cnt)]
        protos.append("(%s)%s" % ("".join(args), types[ret]))

    def cname(t):
        return t[1:-1] if t.startswith("L") and t.endswith(";") else t

    out = set(cname(t) for t in types)
    fn, fo = struct.unpack_from("<II", d, 0x50)
    for i in range(fn):
        c, t, nm = struct.unpack_from("<HHI", d, fo + 8 * i)
        out.add("%s.%s:%s" % (cname(types[c]), s[nm], types[t]))
    mn, mo = struct.unpack_from("<II", d, 0x58)
    for i in range(mn):
        c, p, nm = struct.unpack_from("<HHI", d, mo + 8 * i)
        out.add("%s.%s%s" % (cname(types[c]), s[nm], protos[p]))
    return out


def dexjar_ids(path):
    out = set()
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.startswith("classes") and n.endswith(".dex"):
                out |= dex_ids(z.read(n))
    return out


# ------------------------------------------------------------------------------------------------------- allow list

def read_allow(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(" | ")]
            if len(parts) != 3 or not all(parts):
                raise SystemExit("%s:%d: want 'REF | SITES | REASON'" % (path, ln))
            out.append((parts[0], [p.strip() for p in parts[1].split(",")], parts[2], ln))
    return out


def site_ok(site, prefixes):
    return any(p == "*" or site == p or any(site.startswith(p + c) for c in ".$(") for p in prefixes)


def classify(missing, dex, allow, baseline):
    """[(ref, why, sites, verdict, note)] sorted by verdict (WARN first) and ref."""
    rows = []
    used_allow = set()
    for ref, (why, sites) in sorted(missing.items()):
        base = "" if baseline is None else (" (also in baseline)" if ref in baseline else " (new)")
        if dex is not None and ref not in dex:
            rows.append((ref, why, sites, "d8", "not in the dex jar: desugared/backported by d8" + base))
            continue
        hit = [a for a in allow if a[0] == ref]
        if hit:
            uncovered = [s for s in sites if not any(site_ok(s, a[1]) for a in hit)]
            used_allow.update(a[3] for a in hit)
            if not uncovered:
                rows.append((ref, why, sites, "allowed", hit[0][2] + base))
                continue
            rows.append((ref, why, uncovered, "WARN", "call sites not covered by the allow line(s) %s%s"
                         % (",".join(str(a[3]) for a in hit), base)))
            continue
        rows.append((ref, why, sites, "WARN", "unguarded or unreviewed" + base))
    stale = [a for a in allow if a[3] not in used_allow]
    order = {"WARN": 0, "allowed": 1, "d8": 2}
    rows.sort(key=lambda r: (order[r[3]], r[0]))
    return rows, stale


def report(rows, stale, out=sys.stdout, quiet=False):
    counts = {"WARN": 0, "allowed": 0, "d8": 0}
    for ref, why, sites, verdict, note in rows:
        counts[verdict] += 1
        if quiet and verdict != "WARN":
            continue
        mark = "⚠️  WARN" if verdict == "WARN" else verdict
        print("%-8s %s  [%s] %s" % (mark, ref, why, note), file=out)
        for s in sites:
            print("           at %s" % s, file=out)
    for ref, _, _, ln in stale:
        print("note     allow line %d (%s) matches no unresolved reference" % (ln, ref), file=out)
    print("APICHECK %s: %d unresolved references: %d WARN, %d allowed, %d removed by d8" %
          ("PASS" if not counts["WARN"] else "FAIL", len(rows), counts["WARN"], counts["allowed"], counts["d8"]),
          file=out)
    return 1 if counts["WARN"] else 0


def dex_min_apis(path):
    """The min-api of every D8 marker string in the dex files of the jar (empty: no marker)."""
    apis = []
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.startswith("classes") and n.endswith(".dex"):
                for st in dex_strings(z.read(n)):
                    if st.startswith("~~D8{"):
                        try:
                            apis.append(int(json.loads(st[4:])["min-api"]))
                        except (ValueError, KeyError, TypeError):
                            apis.append(None)
    return apis


def run(jar, libs, dex=None, allow=None, baseline=None, out=sys.stdout, quiet=False, api=None):
    jar_classes = read_jar_classes(jar, True)
    lib_classes = {}
    for p in libs:
        lib_classes.update(read_jar_classes(p, False))
    lib = Lib(lib_classes)
    missing = unresolved(jar_classes, lib)
    base = None
    if baseline:
        base = set(unresolved(read_jar_classes(baseline, True), lib))
    dex_set = dexjar_ids(dex) if dex else None
    rows, stale = classify(missing, dex_set, read_allow(allow) if allow else [], base)
    hi = {}
    for cf in jar_classes.values():
        for t in (15, 16, 17, 18):
            hi[t] = hi.get(t, 0) + cf.tag_counts.get(t, 0)
    print("jar: %d classes, highest major %d; pool MethodHandle/MethodType/Dynamic/InvokeDynamic entries: %d/%d/%d/%d"
          % (len(jar_classes), max(c.major for c in jar_classes.values()), hi[15], hi[16], hi[17], hi[18]), file=out)
    print("lib: %d classes from %s" % (len(lib_classes), ", ".join(libs)), file=out)
    if api is not None and dex:
        apis = dex_min_apis(dex)
        bad = [a for a in apis if a is None or a > api]
        if bad:
            rows.insert(0, ("dex min-api %s" % ",".join("?" if a is None else str(a) for a in bad), "D8 marker",
                            [dex], "WARN", "the dex was built for a newer API than %d (re-dex with --min-api %d)"
                            % (api, api)))
        print("api: %d; dex min-api %s" % (api, ",".join("?" if a is None else str(a) for a in apis) or
                                           "unknown (no D8 marker)"), file=out)
    elif api is not None:
        print("api: %d" % api, file=out)
    return report(rows, stale, out, quiet)


# ---------------------------------------------------------------------------------------------------------- selftest

class _Pool:
    def __init__(self):
        self.items, self.index = [], {}

    def add(self, key, raw):
        if key not in self.index:
            self.items.append(raw)
            self.index[key] = len(self.items)
        return self.index[key]

    def utf8(self, s):
        b = s.encode("utf-8")
        return self.add(("u", s), b"\x01" + struct.pack(">H", len(b)) + b)

    def cls(self, name):
        return self.add(("c", name), b"\x07" + struct.pack(">H", self.utf8(name)))

    def member(self, tag, owner, name, desc):
        nt = self.add(("nt", name, desc), b"\x0c" + struct.pack(">HH", self.utf8(name), self.utf8(desc)))
        return self.add(("m", tag, owner, name, desc), bytes([tag]) + struct.pack(">HH", self.cls(owner), nt))


def make_class(name, super_name="java/lang/Object", interfaces=(), fields=(), methods=(), major=51):
    """methods: [(name, desc, [instr])], instr = ("invoke", owner, name, desc) | ("iface", ...) | ("get", owner, name,
    desc) | ("new"/"instanceof", cls) | ("switch",) (a tableswitch, to exercise the padding)."""
    p = _Pool()
    this = p.cls(name)
    sup = p.cls(super_name) if super_name else 0
    itf = [p.cls(i) for i in interfaces]
    fbytes = b"".join(struct.pack(">HHHH", 1, p.utf8(n), p.utf8(d), 0) for n, d in fields)
    code_name = p.utf8("Code")
    mbytes = b""
    for mn, md, instrs in methods:
        code = b""
        for ins in instrs:
            if ins[0] == "invoke":
                code += b"\xb6" + struct.pack(">H", p.member(10, *ins[1:]))
            elif ins[0] == "iface":
                code += b"\xb9" + struct.pack(">H", p.member(11, *ins[1:])) + b"\x01\x00"
            elif ins[0] == "get":
                code += b"\xb2" + struct.pack(">H", p.member(9, *ins[1:]))
            elif ins[0] in ("new", "instanceof"):
                code += (b"\xbb" if ins[0] == "new" else b"\xc1") + struct.pack(">H", p.cls(ins[1]))
            elif ins[0] == "switch":
                pad = (4 - (len(code) + 1) % 4) % 4
                code += b"\xaa" + b"\0" * pad + struct.pack(">iii", 0, 0, 1) + struct.pack(">ii", 0, 0)
        code += b"\xb1"
        attr = struct.pack(">HHI", 4, 4, len(code)) + code + struct.pack(">HH", 0, 0)
        mbytes += struct.pack(">HHHH", 1, p.utf8(mn), p.utf8(md), 1) + struct.pack(">HI", code_name, len(attr)) + attr
    body = struct.pack(">HHHH", 0x21, this, sup, len(itf)) + b"".join(struct.pack(">H", i) for i in itf)
    body += struct.pack(">H", len(fields)) + fbytes + struct.pack(">H", len(methods)) + mbytes + b"\0\0"
    return b"\xca\xfe\xba\xbe\x00\x00" + struct.pack(">H", major) + struct.pack(">H", len(p.items) + 1) + \
        b"".join(p.items) + body


def make_dex(classes, methods, extra_strings=()):
    """A dex file with just the id tables: classes = type names, methods = [(owner, name, '(params)ret')];
    extra_strings = more string_ids (a D8 marker)."""
    strings = set(extra_strings)
    types = set("L%s;" % c for c in classes)
    protos = set()
    for o, n, desc in methods:
        types.add("L%s;" % o)
        strings.add(n)
        params, ret = desc[1:].split(")")
        ps = []
        i = 0
        while i < len(params):
            j = i
            while params[j] == "[":
                j += 1
            j = params.index(";", j) + 1 if params[j] == "L" else j + 1
            ps.append(params[i:j])
            i = j
        types.update(ps + [ret])
        protos.add((tuple(ps), ret))
    strings |= types
    strings = sorted(strings)
    types = sorted(types)
    protos = sorted(protos)
    hdr = 0x70
    sid_off = hdr
    tid_off = sid_off + 4 * len(strings)
    pid_off = tid_off + 4 * len(types)
    mid_off = pid_off + 12 * len(protos)
    data_off = mid_off + 8 * len(methods)
    data = b""
    sdata = []
    for s in strings:
        sdata.append(data_off + len(data))
        b = s.encode("utf-8")
        data += bytes([len(s)]) + b + b"\0"
    plist = []
    for ps, _ in protos:
        while (data_off + len(data)) % 4:
            data += b"\0"
        if ps:
            plist.append(data_off + len(data))
            data += struct.pack("<I", len(ps)) + b"".join(struct.pack("<H", types.index(t)) for t in ps)
            if len(ps) % 2:
                data += b"\0\0"
        else:
            plist.append(0)
    si = {s: i for i, s in enumerate(strings)}
    out = bytearray(b"dex\n035\0" + b"\0" * (hdr - 8))
    struct.pack_into("<II", out, 0x38, len(strings), sid_off)
    struct.pack_into("<II", out, 0x40, len(types), tid_off)
    struct.pack_into("<II", out, 0x48, len(protos), pid_off)
    struct.pack_into("<II", out, 0x50, 0, 0)
    struct.pack_into("<II", out, 0x58, len(methods), mid_off)
    out += b"".join(struct.pack("<I", o) for o in sdata)
    out += b"".join(struct.pack("<I", si[t]) for t in types)
    for (ps, ret), po in zip(protos, plist):
        out += struct.pack("<III", 0, types.index(ret), po)
    for o, n, desc in methods:
        params, ret = desc[1:].split(")")
        key = None
        for k, (ps, r) in enumerate(protos):
            if "".join(ps) == params and r == ret:
                key = k
        out += struct.pack("<HHI", types.index("L%s;" % o), key, si[n])
    return bytes(out) + data


def selftest():
    td = tempfile.mkdtemp(prefix="apicheck-selftest-")
    fails = []

    def jar(name, members):
        p = os.path.join(td, name)
        with zipfile.ZipFile(p, "w") as z:
            for n, d in members:
                z.writestr(n, d)
        return p

    lib = jar("core.jar", [
        ("java/lang/Object.class", make_class("java/lang/Object", None, methods=[("hashCode", "()I", [])])),
        ("java/lang/Long.class", make_class("java/lang/Long", "java/lang/Number",
                                            methods=[("valueOf", "(J)Ljava/lang/Long;", [])])),
        ("java/lang/Number.class", make_class("java/lang/Number", methods=[("longValue", "()J", [])])),
        ("java/io/Closeable.class", make_class("java/io/Closeable", methods=[("close", "()V", [])])),
        ("java/net/Socket.class", make_class("java/net/Socket", interfaces=["java/io/Closeable"],
                                             fields=[("impl", "Ljava/net/SocketImpl;")],
                                             methods=[("getOutputStream", "()Ljava/io/OutputStream;", [])])),
        ("javax/net/ssl/SSLSocket.class", make_class("javax/net/ssl/SSLSocket", "java/net/Socket")),
    ])
    good_methods = [
        ("ok", "()V", [("invoke", "javax/net/ssl/SSLSocket", "getOutputStream", "()Ljava/io/OutputStream;"),
                       ("switch",),
                       ("iface", "javax/net/ssl/SSLSocket", "close", "()V"),
                       ("invoke", "javax/net/ssl/SSLSocket", "hashCode", "()I"),
                       ("get", "javax/net/ssl/SSLSocket", "impl", "Ljava/net/SocketImpl;"),
                       ("invoke", "java/lang/Long", "longValue", "()J"),
                       ("invoke", "[Ljava/lang/Long;", "clone", "()Ljava/lang/Object;"),
                       ("invoke", "org/conscrypt/B", "own", "()V")]),
    ]
    cls_a = make_class("org/conscrypt/A", methods=good_methods)
    cls_b = make_class("org/conscrypt/B", methods=[("own", "()V", [])])
    missing_long = ("hash", "()I", [("invoke", "java/lang/Long", "hashCode", "(J)I")])
    cls_c = make_class("org/conscrypt/C", methods=[missing_long])
    cls_d = make_class("org/conscrypt/D", "javax/net/ssl/ExtendedSSLSession")
    cls_e = make_class("org/conscrypt/Platform", methods=[
        ("wrap", "()V", [("instanceof", "javax/net/ssl/X509ExtendedTrustManager")]),
        ("other", "()V", [("new", "javax/net/ssl/X509ExtendedTrustManager")])])
    allow_all = os.path.join(td, "allow.txt")
    with open(allow_all, "w") as f:
        f.write("# test\njavax/net/ssl/ExtendedSSLSession | org/conscrypt/D | never loaded on 19\n"
                "javax/net/ssl/X509ExtendedTrustManager | org/conscrypt/Platform.wrap, org/conscrypt/Platform.other"
                " | SDK_INT >= 24\n")
    allow_part = os.path.join(td, "allow-part.txt")
    with open(allow_part, "w") as f:
        f.write("javax/net/ssl/X509ExtendedTrustManager | org/conscrypt/Platform.wrap | SDK_INT >= 24\n")
    dex_without = jar("d8.jar", [("classes.dex", make_dex(["org/conscrypt/C"],
                                                          [("org/conscrypt/C", "hash", "()I"),
                                                           ("java/lang/Long", "valueOf", "(J)Ljava/lang/Long;")]))])
    def d8_jar(name, min_api):
        marker = '~~D8{"backend":"dex","compilation-mode":"release","min-api":%d,"version":"9.2.4-dev"}' % min_api
        return jar(name, [("classes.dex", make_dex(["org/conscrypt/C"], [("org/conscrypt/C", "hash", "()I")],
                                                   [marker]))])

    dex16, dex19 = d8_jar("d8-16.jar", 16), d8_jar("d8-19.jar", 19)
    dex_with = jar("d8-kept.jar", [("classes.dex", make_dex(["org/conscrypt/C"],
                                                            [("java/lang/Long", "hashCode", "(J)I")]))])

    def case(label, members, want_rc, want_text=(), absent_text=(), **kw):
        p = jar("in.jar", members)
        buf = io.StringIO()
        try:
            rc = run(p, [lib], out=buf, **kw)
        except Exception as e:  # noqa: BLE001 - a selftest reports every failure
            rc, buf = -1, io.StringIO("exception %r" % e)
        text = buf.getvalue()
        ok = rc == want_rc and all(t in text for t in want_text) and not any(t in text for t in absent_text)
        print("selftest %s %s" % ("ok  " if ok else "FAIL", label))
        if not ok:
            fails.append(label)
            print("  rc=%s want %s\n  %s" % (rc, want_rc, text.replace("\n", "\n  ")))

    try:
        case("inherited, interface, Object, array and own refs resolve", [("org/conscrypt/A.class", cls_a),
                                                                         ("org/conscrypt/B.class", cls_b)], 0,
             ["0 unresolved"])
        case("missing method is WARN with its call site", [("org/conscrypt/C.class", cls_c)], 1,
             ["WARN", "java/lang/Long.hashCode(J)I", "at org/conscrypt/C.hash()I"])
        case("missing method removed by d8 is not WARN", [("org/conscrypt/C.class", cls_c)], 0,
             ["d8       java/lang/Long.hashCode(J)I"], dex=dex_without)
        case("missing method still in the dex is WARN", [("org/conscrypt/C.class", cls_c)], 1, ["WARN"], dex=dex_with)
        case("missing super class is WARN at <extends>", [("org/conscrypt/D.class", cls_d)], 1,
             ["javax/net/ssl/ExtendedSSLSession", "org/conscrypt/D.<extends>"])
        case("missing class via instanceof/new", [("org/conscrypt/Platform.class", cls_e)], 1,
             ["at org/conscrypt/Platform.wrap()V", "at org/conscrypt/Platform.other()V"])
        case("allow list covers all sites", [("org/conscrypt/D.class", cls_d),
                                             ("org/conscrypt/Platform.class", cls_e)], 0, ["2 allowed"],
             allow=allow_all)
        case("allow list missing a site is WARN", [("org/conscrypt/Platform.class", cls_e)], 1,
             ["not covered", "at org/conscrypt/Platform.other()V"], ["at org/conscrypt/Platform.wrap()V"],
             allow=allow_part)
        case("baseline marks old and new", [("org/conscrypt/C.class", cls_c), ("org/conscrypt/D.class", cls_d)], 1,
             ["hashCode(J)I  [missing member] unguarded or unreviewed (also in baseline)",
              "ExtendedSSLSession  [missing class] unguarded or unreviewed (new)"],
             baseline=jar("base.jar", [("org/conscrypt/C.class", cls_c)]))
        case("--api 16, dex min-api 16", [("org/conscrypt/B.class", cls_b)], 0, ["api: 16; dex min-api 16"],
             dex=dex16, api=16)
        case("--api 18, dex min-api 16", [("org/conscrypt/B.class", cls_b)], 0, ["api: 18; dex min-api 16"],
             dex=dex16, api=18)
        case("--api 16, dex min-api 19 is WARN", [("org/conscrypt/B.class", cls_b)], 1,
             ["WARN dex min-api 19", "re-dex with --min-api 16"], dex=dex19, api=16)
        case("--api 19, dex without a D8 marker", [("org/conscrypt/C.class", cls_c)], 0,
             ["api: 19; dex min-api unknown"], dex=dex_without, api=19)
        case("class at major 52 parses", [("org/conscrypt/C.class", make_class("org/conscrypt/C", methods=[
            missing_long], major=52))], 1, ["highest major 52"])
    finally:
        for n in os.listdir(td):
            os.remove(os.path.join(td, n))
        os.rmdir(td)
    print("SELFTEST %s" % ("PASS" if not fails else "FAIL: " + ", ".join(fails)))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("jar", nargs="?")
    ap.add_argument("--lib", action="append", default=[])
    ap.add_argument("--dex")
    ap.add_argument("--allow")
    ap.add_argument("--baseline")
    ap.add_argument("--quiet", action="store_true", help="print only the WARN rows and the summary")
    ap.add_argument("--api", type=int, help="API level of the --lib set; the --dex D8 min-api must not exceed it")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.jar or not a.lib:
        ap.print_usage(sys.stderr)
        return 2
    for p in [a.jar] + a.lib + [x for x in (a.dex, a.allow, a.baseline) if x]:
        if not os.path.isfile(p):
            print("apicheck: %s is missing" % p, file=sys.stderr)
            return 2
    return run(a.jar, a.lib, a.dex, a.allow, a.baseline, quiet=a.quiet, api=a.api)


if __name__ == "__main__":
    sys.exit(main())
