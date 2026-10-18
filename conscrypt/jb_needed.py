#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""jb_needed.py: make the aar's Conscrypt JNI library load libkktls_compat.so on Android 4.1 and 4.2 (an ELF edit).

    python3 -I jb_needed.py IN.so OUT.so      the aar's libconscrypt_jni.so (ARM or x86) -> the JB 4.1/4.2 library
    python3 -I jb_needed.py --selftest

Why: the 2.6-alpha2 .so imports symbols that the 4.1/4.2 bionic lacks (check_prebuilt.py JB_MISSING: 4.2 ARM getauxval;
4.1 ARM getauxval and six fortify functions, 4.1 x86 the six). conscrypt/compat/ builds libkktls_compat.so with exactly
the missing ones per base and ABI; the .so must name it in DT_NEEDED so the linker loads it and resolves the imports
there. The .dynamic of the aar's .so has no spare entry (27 entries, one DT_NULL), so nothing can be appended.

What it does (two in-place changes, the file size and every other byte stay):
  1. the DT_SONAME entry becomes a DT_NEEDED entry with the same string offset. The Jelly Bean linkers never read
     DT_SONAME (android-4.1.2_r2 linker.c and android-4.2.2_r1 linker.cpp key a library by its file's basename; their
     link_image/soinfo_link_image switch has no DT_SONAME case), so the tag is free to reuse there;
  2. the string it points at, "libconscrypt_jni.so", becomes "libkktls_compat.so" plus NUL padding (18 + 1 bytes in the
     19 + 1 of the old one).
The SONAME entry follows every DT_NEEDED entry, so the new one is the last: both JB linkers resolve an import in the
library itself, then LD_PRELOAD, then the DT_NEEDED libraries in .dynamic order (4.1 _do_lookup, 4.2 soinfo_do_lookup),
hence libc/libm/libdl/liblog always come before libkktls_compat.so. Refuses (exit 1) unless: ELF32 little-endian ET_DYN
for ARM or x86 with exactly one PT_DYNAMIC; exactly one DT_SONAME, after the last DT_NEEDED, naming exactly
"libconscrypt_jni.so"; no DT_NEEDED libkktls_compat.so yet; DT_STRTAB, DT_STRSZ, DT_SYMTAB and DT_HASH present; and no
other reference into .dynstr (a .dynsym name through DT_HASH's nchain, another string tag, a DT_VERNEED file or aux name,
a DT_VERDEF aux name) shares any byte of the old string (the linker may merge string tails). An input this tool already
edited (no DT_SONAME, the last DT_NEEDED is libkktls_compat.so at a string in exactly the layout written here) is copied
unchanged: running it twice gives the same bytes.

Only for 4.1/4.2: on 4.3 and 4.4 the aar's .so needs nothing and stays as it is (4.4's linker uses DT_SONAME for
nothing either, but there is no reason to change the file). Deterministic (no time, no input-dependent choices), so
mkstage.py --jb pins the outputs in SHA256SUMS ("2.6-alpha2/jb-compat/..."). Stdlib only, Python 3.4 compatible.
"""
import hashlib
import os
import struct
import sys
import tempfile

OLD = b"libconscrypt_jni.so"
NEW = b"libkktls_compat.so"
EM_ARM, EM_386 = 40, 3
ET_DYN = 3
PT_LOAD, PT_DYNAMIC = 1, 2
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SONAME, DT_RPATH, DT_RUNPATH = 0, 1, 4, 5, 6, 10, 14, 15, 29
DT_VERDEF, DT_VERDEFNUM, DT_VERNEED, DT_VERNEEDNUM = 0x6FFFFFFC, 0x6FFFFFFD, 0x6FFFFFFE, 0x6FFFFFFF
DT_AUXILIARY, DT_FILTER = 0x7FFFFFFD, 0x7FFFFFFF
STRING_TAGS = (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH, DT_AUXILIARY, DT_FILTER)
SLOT = len(OLD) + 1  # bytes of the old string with its NUL; the new string is NUL-padded to this size
assert len(NEW) + 1 <= SLOT


class NeededError(Exception):
    pass


class Dyn(object):
    """The parts of an ELF32-LE shared object this edit reads; every read is bounds-checked (NeededError)."""

    def __init__(self, data):
        self.data = data
        if len(data) < 52 or data[:4] != b"\x7fELF":
            raise NeededError("not an ELF file")
        if data[4] != 1 or data[5] != 1:
            raise NeededError("not ELF32 little-endian (class %d, data %d)" % (data[4], data[5]))
        e_type, self.machine = self.u("<HH", 16)
        if e_type != ET_DYN:
            raise NeededError("e_type %d, want ET_DYN" % e_type)
        if self.machine not in (EM_ARM, EM_386):
            raise NeededError("e_machine %d, want ARM (40) or x86 (3)" % self.machine)
        e_phoff, = self.u("<I", 28)
        e_phentsize, e_phnum = self.u("<HH", 42)
        if e_phentsize != 32:
            raise NeededError("e_phentsize %d" % e_phentsize)
        self.phdrs = [self.u("<IIIIIIII", e_phoff + 32 * i) for i in range(e_phnum)]
        dyns = [p for p in self.phdrs if p[0] == PT_DYNAMIC]
        if len(dyns) != 1:
            raise NeededError("%d PT_DYNAMIC program headers, want 1" % len(dyns))
        off, size = dyns[0][1], dyns[0][4]
        self.entries = []  # (file offset of the entry, tag, value), up to DT_NULL
        for i in range(size // 8):
            tag, val = self.u("<II", off + 8 * i)
            if tag == DT_NULL:
                break
            self.entries.append((off + 8 * i, tag, val))
        else:
            raise NeededError("no DT_NULL in PT_DYNAMIC")
        for t, name in ((DT_STRTAB, "DT_STRTAB"), (DT_STRSZ, "DT_STRSZ"), (DT_SYMTAB, "DT_SYMTAB"), (DT_HASH, "DT_HASH")):
            if len(self.values(t)) != 1:
                raise NeededError("%d %s entries, want 1" % (len(self.values(t)), name))
        self.strtab = self.vaddr(self.values(DT_STRTAB)[0])
        self.strsz = self.values(DT_STRSZ)[0]
        if self.strtab + self.strsz > len(data):
            raise NeededError(".dynstr runs past the end of the file")

    def u(self, fmt, off):
        if off < 0 or off + struct.calcsize(fmt) > len(self.data):
            raise NeededError("truncated: %d bytes at 0x%x" % (struct.calcsize(fmt), off))
        return struct.unpack_from(fmt, self.data, off)

    def values(self, tag):
        return [v for _, t, v in self.entries if t == tag]

    def vaddr(self, va):
        for p_type, p_offset, p_vaddr, _, p_filesz, _, _, _ in self.phdrs:
            if p_type == PT_LOAD and p_vaddr <= va < p_vaddr + p_filesz:
                return va - p_vaddr + p_offset
        raise NeededError("vaddr 0x%x is not in a PT_LOAD segment" % va)

    def string(self, idx):
        """(start, end) file offsets of the .dynstr string at idx; end = its NUL."""
        if idx >= self.strsz:
            raise NeededError("string index %d outside .dynstr (%d bytes)" % (idx, self.strsz))
        start = self.strtab + idx
        end = self.data.find(b"\0", start, self.strtab + self.strsz)
        if end < 0:
            raise NeededError("string at %d has no NUL inside .dynstr" % idx)
        return start, end

    def text(self, idx):
        s, e = self.string(idx)
        return self.data[s:e]

    def references(self):
        """[(what, string index)] of every .dynstr reference besides the dynamic string tags."""
        refs = []
        nchain = self.u("<II", self.vaddr(self.values(DT_HASH)[0]))[1]
        symtab = self.vaddr(self.values(DT_SYMTAB)[0])
        for i in range(1, nchain):
            refs.append(("symbol %d" % i, self.u("<I", symtab + 16 * i)[0]))
        if self.values(DT_VERNEED):
            off, num = self.vaddr(self.values(DT_VERNEED)[0]), (self.values(DT_VERNEEDNUM) or [0])[0]
            for _ in range(num):
                _, cnt, vn_file, vn_aux, vn_next = self.u("<HHIII", off)
                refs.append(("verneed file", vn_file))
                a = off + vn_aux
                for _ in range(cnt):
                    _, _, _, vna_name, vna_next = self.u("<IHHII", a)
                    refs.append(("verneed name", vna_name))
                    a += vna_next
                off += vn_next
        if self.values(DT_VERDEF):
            off, num = self.vaddr(self.values(DT_VERDEF)[0]), (self.values(DT_VERDEFNUM) or [0])[0]
            for _ in range(num):
                _, _, _, cnt, _, vd_aux, vd_next = self.u("<HHHHIII", off)
                a = off + vd_aux
                for _ in range(cnt):
                    vda_name, vda_next = self.u("<II", a)
                    refs.append(("verdef name", vda_name))
                    a += vda_next
                off += vd_next
        return refs


def state(data):
    """('pristine'|'edited', Dyn, entry offset of the SONAME/new NEEDED entry, string index); NeededError otherwise."""
    d = Dyn(data)
    sonames = [(o, v) for o, t, v in d.entries if t == DT_SONAME]
    needed = [(o, v) for o, t, v in d.entries if t == DT_NEEDED]
    names = [d.text(v) for _, v in needed]
    if not sonames:
        if names and names[-1] == NEW and names.count(NEW) == 1:
            o, v = needed[-1]
            s, e = d.string(v)
            if data[s:s + SLOT] != NEW + b"\0" * (SLOT - len(NEW)):
                raise NeededError("DT_NEEDED %s is not in the layout this tool writes" % NEW.decode())
            return "edited", d, o, v
        raise NeededError("no DT_SONAME (and not an output of this tool)")
    if len(sonames) != 1:
        raise NeededError("%d DT_SONAME entries, want 1" % len(sonames))
    o, v = sonames[0]
    if d.text(v) != OLD:
        raise NeededError("DT_SONAME %r, want %r" % (d.text(v).decode("latin-1"), OLD.decode()))
    if NEW in names:
        raise NeededError("already has DT_NEEDED %s next to DT_SONAME" % NEW.decode())
    if needed and needed[-1][0] > o:
        raise NeededError("DT_SONAME is not after the last DT_NEEDED (the new DT_NEEDED would not be searched last)")
    lo, hi = d.strtab + v, d.strtab + v + SLOT  # the bytes the edit overwrites
    refs = [("dynamic tag 0x%x" % t, val) for eo, t, val in d.entries if t in STRING_TAGS and eo != o] + d.references()
    for what, idx in refs:
        s, e = d.string(idx)
        if s < hi and e + 1 > lo:
            raise NeededError("%s (%r) shares bytes with the DT_SONAME string" % (what, d.data[s:e].decode("latin-1")))
    return "pristine", d, o, v


def edit(data):
    """(output bytes, 'edited'|'already edited')."""
    st, d, o, v = state(data)
    if st == "edited":
        return data, "already edited"
    b = bytearray(data)
    struct.pack_into("<I", b, o, DT_NEEDED)
    s = d.strtab + v
    b[s:s + SLOT] = NEW + b"\0" * (SLOT - len(NEW))
    out = bytes(b)
    st2, d2, o2, v2 = state(out)  # the output must read back as an edited file of the same layout
    diff = [i for i in range(len(data)) if data[i] != out[i]] if len(out) == len(data) else None
    if (st2 != "edited" or (o2, v2) != (o, v) or diff is None or
            any(not (o <= i < o + 4 or s <= i < s + SLOT) for i in diff)):
        raise NeededError("output check failed")
    want = [d.text(x) for _, t, x in d.entries if t == DT_NEEDED] + [NEW]
    if [d2.text(x) for _, t, x in d2.entries if t == DT_NEEDED] != want:
        raise NeededError("output DT_NEEDED list is not the input's plus %s" % NEW.decode())
    return out, "edited"


def convert(src, dst):
    with open(src, "rb") as f:
        data = f.read()
    out, what = edit(data)
    tmp = dst + ".partial"
    with open(tmp, "wb") as f:
        f.write(out)
    os.chmod(tmp, 0o644)
    os.replace(tmp, dst)
    return what, hashlib.sha256(out).hexdigest()


# --- selftest: synthetic ELF32 shared objects, no Conscrypt bytes --------------------------------------------------------
def _so(machine=EM_ARM, needed=(b"liblog.so", b"libc.so"), soname=OLD, soname_at=None, syms=(b"getauxval", b"JNI_OnLoad"),
        sym_refs=(), extra_tags=(), verneed=None, ei=(1, 1), e_type=ET_DYN, n_dynamic=1, no_null=False, dup_soname=False):
    """A minimal shared object: ELF header, PT_LOAD (whole file at vaddr 0), PT_DYNAMIC, .dynstr, .dynsym, DT_HASH,
    optional DT_VERNEED, .dynamic. soname_at = index among the NEEDED entries where DT_SONAME goes (default: after them);
    sym_refs = extra symbols whose st_name points at (string, byte offset inside it); extra_tags = (tag, string) entries;
    verneed = (file string, [aux strings])."""
    strs = bytearray(b"\0")
    index = {}

    def add(s):
        if s not in index:
            index[s] = len(strs)
            strs.extend(s + b"\0")
        return index[s]
    if soname is not None:
        add(soname)
    for n in needed:
        add(n)
    for s in syms:
        add(s)
    for s, _ in sym_refs:
        add(s)
    for _, s in extra_tags:
        add(s)
    if verneed:
        add(verneed[0])
        for a in verneed[1]:
            add(a)
    names = [index[s] for s in syms] + [index[s] + k for s, k in sym_refs]
    strtab = 52 + 32 * (1 + n_dynamic)
    symtab = (strtab + len(strs) + 3) & ~3
    nsym = len(names) + 1
    symb = b"\0" * 16 + b"".join(struct.pack("<IIIBBH", n, 0x100, 0, 0x12, 0, 1) for n in names)
    hash_off = symtab + len(symb)
    hashb = struct.pack("<III", 1, nsym, 0) + b"\0" * 4 * nsym  # one bucket; only nchain is read here
    vn_off = hash_off + len(hashb)
    vnb = b""
    if verneed:
        vnb = struct.pack("<HHIII", 1, len(verneed[1]), index[verneed[0]], 16, 0)
        for i, a in enumerate(verneed[1]):
            vnb += struct.pack("<IHHII", 0, 0, 2 + i, index[a], 16 if i + 1 < len(verneed[1]) else 0)
    dyn_off = vn_off + len(vnb)
    ents = [(DT_NEEDED, index[n]) for n in needed]
    if soname is not None:
        so_ent = [(DT_SONAME, index[soname])] * (2 if dup_soname else 1)
        at = len(needed) if soname_at is None else soname_at
        ents[at:at] = so_ent
    ents += [(t, index[s]) for t, s in extra_tags]
    ents += [(DT_HASH, hash_off), (DT_STRTAB, strtab), (DT_SYMTAB, symtab), (DT_STRSZ, len(strs)), (11, 16)]
    if verneed:
        ents += [(DT_VERNEED, vn_off), (DT_VERNEEDNUM, 1)]
    if not no_null:
        ents.append((DT_NULL, 0))
    dynb = b"".join(struct.pack("<II", t, v) for t, v in ents)
    total = dyn_off + len(dynb)
    # section headers (null, .dynstr, .dynsym) after the segment, for readers that go by sections (check_prebuilt.py)
    shdrs = b"\0" * 40 + struct.pack("<IIIIIIIIII", 0, 3, 2, strtab, strtab, len(strs), 0, 0, 1, 0)
    shdrs += struct.pack("<IIIIIIIIII", 0, 11, 2, symtab, symtab, len(symb), 1, 1, 4, 16)
    hdr = b"\x7fELF" + bytes([ei[0], ei[1], 1]) + b"\0" * 9
    hdr += struct.pack("<HHIIIIIHHHHHH", e_type, machine, 1, 0, 52, total, 0, 52, 32, 1 + n_dynamic, 40, 3, 0)
    ph = struct.pack("<IIIIIIII", PT_LOAD, 0, 0, 0, total, total, 6, 0x1000)
    ph += struct.pack("<IIIIIIII", PT_DYNAMIC, dyn_off, dyn_off, dyn_off, len(dynb), len(dynb), 6, 4) * n_dynamic
    body = bytearray(hdr + ph + strs)
    body.extend(b"\0" * (symtab - len(body)))
    body.extend(symb + hashb + vnb + dynb + shdrs)
    return bytes(body)


def _needed_names(data):
    d = Dyn(data)
    return [d.text(v) for _, t, v in d.entries if t == DT_NEEDED], [d.text(v) for _, t, v in d.entries if t == DT_SONAME]


def selftest():
    ok = True
    cases = [
        ("ELF64", _so(ei=(2, 1)), "not ELF32 little-endian"),
        ("big-endian", _so(ei=(1, 2)), "not ELF32 little-endian"),
        ("ET_EXEC", _so(e_type=2), "want ET_DYN"),
        ("MIPS", _so(machine=8), "e_machine 8"),
        ("truncated", _so()[:60], "truncated"),
        ("two PT_DYNAMIC", _so(n_dynamic=2), "2 PT_DYNAMIC"),
        ("no DT_NULL", _so(no_null=True), "no DT_NULL"),
        ("no DT_SONAME", _so(soname=None), "no DT_SONAME"),
        ("two DT_SONAME", _so(dup_soname=True), "2 DT_SONAME"),
        ("other DT_SONAME", _so(soname=b"libconscrypt_jnX.so"), "DT_SONAME"),
        ("DT_SONAME before a DT_NEEDED", _so(soname_at=1), "not after the last DT_NEEDED"),
        ("DT_NEEDED libkktls_compat.so already there", _so(needed=(b"libc.so", NEW)), "already has DT_NEEDED"),
        ("symbol name in the SONAME string's tail", _so(sym_refs=((OLD, 3),)), "symbol"),
        ("symbol name = the SONAME string", _so(sym_refs=((OLD, 0),)), "symbol"),
        ("DT_RUNPATH into the SONAME string", _so(extra_tags=((DT_RUNPATH, OLD),)), "dynamic tag 0x1d"),
        ("verneed name in the SONAME string", _so(verneed=(b"libc.so", [b"LIBC", OLD])), "verneed name"),
    ]
    for label, data, want in cases:
        try:
            edit(data)
            err = None
        except NeededError as e:
            err = str(e)
        good = err is not None and want in err
        print("selftest %s refuses %s: %s" % ("ok  " if good else "FAIL", label, err or "edited"))
        ok &= good
    checks = []
    for label, machine in (("ARM", EM_ARM), ("x86", EM_386)):
        src = _so(machine=machine, verneed=(b"libc.so", [b"LIBC"]), sym_refs=((b"getauxval", 3),))
        out, what = edit(src)
        needed, soname = _needed_names(out)
        diff = [i for i in range(len(src)) if src[i] != out[i]]
        checks.append(("%s: edited, NEEDED = input's + %s last, no SONAME" % (label, NEW.decode()),
                       what == "edited" and needed == [b"liblog.so", b"libc.so", NEW] and soname == []))
        checks.append(("%s: same size, only the entry tag and the string bytes differ (%d bytes)" % (label, len(diff)),
                       len(out) == len(src) and 0 < len(diff) <= 4 + SLOT))
        checks.append(("%s: string padded with NUL" % label, NEW + b"\0\0" in out and OLD not in out))
        again, what2 = edit(out)
        checks.append(("%s: idempotent (own output unchanged, 'already edited')" % label,
                       again == out and what2 == "already edited"))
        checks.append(("%s: deterministic" % label, edit(src)[0] == out))
    half = bytearray(_so())
    d = Dyn(bytes(half))
    o = [eo for eo, t, _ in d.entries if t == DT_SONAME][0]
    struct.pack_into("<I", half, o, DT_NEEDED)  # retagged, string not rewritten
    try:
        edit(bytes(half))
        checks.append(("refuses a half-edited file (tag retagged, old string)", False))
    except NeededError as e:
        checks.append(("refuses a half-edited file (tag retagged, old string)", "no DT_SONAME" in str(e)))
    td = tempfile.mkdtemp(prefix="jb-needed-")
    try:
        a, b = os.path.join(td, "in.so"), os.path.join(td, "out.so")
        with open(a, "wb") as f:
            f.write(_so())
        what, digest = convert(a, b)
        with open(b, "rb") as f:
            checks.append(("convert writes the edit, mode 0644", f.read() == edit(_so())[0] and
                           (os.stat(b).st_mode & 0o777) == 0o644 and not os.path.exists(b + ".partial")))
        checks.append(("convert on its own output keeps the bytes", convert(b, a) == ("already edited", digest)))
    finally:
        for n in os.listdir(td):
            os.remove(os.path.join(td, n))
        os.rmdir(td)
    for label, good in checks:
        print("selftest %s %s" % ("ok  " if good else "FAIL", label))
        ok &= bool(good)
    print("SELFTEST %s (%d cases)" % ("PASS" if ok else "FAIL", len(cases) + len(checks)))
    return ok


def main(argv):
    if argv[1:] == ["--selftest"]:
        return 0 if selftest() else 1
    if len(argv) != 3:
        sys.stderr.write(__doc__.split("\n\n")[1] + "\n")
        return 2
    try:
        what, digest = convert(argv[1], argv[2])
    except (NeededError, IOError, OSError) as e:
        sys.stderr.write("jb_needed.py: %s: %s\n" % (argv[1], e))
        return 1
    print("jb_needed.py: %s -> %s (%s: DT_SONAME %s -> DT_NEEDED %s), sha256 %s"
          % (argv[1], argv[2], what, OLD.decode(), NEW.decode(), digest))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
