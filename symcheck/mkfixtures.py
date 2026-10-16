#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write the ELF32 fixtures of test.sh into OUTDIR (stdlib only, no cross toolchain).

    python3 -I mkfixtures.py OUTDIR

Each fixture is a minimal ET_DYN with the section headers kktls-symcheck reads: null, .dynsym, .dynstr, .bss (the
section the defined symbols point at), .shstrtab; the section headers are last, so every truncated prefix of a fixture
loses them. The bad-*.so files each break one rule of the reader (exit 2 expected).
"""
import os
import struct
import sys

EM_386, EM_ARM, EM_MIPS = 3, 40, 8
LOCAL, GLOBAL, WEAK = 0, 1, 2
NOTYPE, OBJECT, FUNC, SECTION, TLS, IFUNC = 0, 1, 2, 3, 6, 10
DEFAULT, HIDDEN, PROTECTED = 0, 2, 3
UND, BSS, ABS = 0, 3, 0xFFF1

# (name, bind, type, visibility, shndx): the exports of "full" are the first eight entries
FULL = [
    ("kk_fa", GLOBAL, FUNC, DEFAULT, BSS),
    ("kk_fb", GLOBAL, FUNC, DEFAULT, BSS),
    ("kk_fc", GLOBAL, FUNC, DEFAULT, BSS),
    ("kk_obj", GLOBAL, OBJECT, DEFAULT, BSS),
    ("kk_weak", WEAK, FUNC, DEFAULT, BSS),
    ("kk_ifunc", GLOBAL, IFUNC, DEFAULT, BSS),
    ("kk_tls", GLOBAL, TLS, PROTECTED, BSS),
    ("kk_abs", GLOBAL, OBJECT, DEFAULT, ABS),
    # not exports
    ("kk_hidden", GLOBAL, FUNC, HIDDEN, BSS),
    ("kk_local", LOCAL, FUNC, DEFAULT, BSS),
    ("kk_undef", GLOBAL, FUNC, DEFAULT, UND),
    ("kk_weakundef", WEAK, OBJECT, DEFAULT, UND),
    ("kk_notype", GLOBAL, NOTYPE, DEFAULT, BSS),
    ("kk_section", GLOBAL, SECTION, DEFAULT, BSS),
]


def elf(syms, machine=EM_ARM, cls=1, data=1, etype=3, shentsize=40, no_shdrs=False, sym_entsize=16, sym_extra=0,
        link=2, strtab_type=3, strtab_nul=True, name_off=None, no_dynsym=False):
    # .dynstr
    dynstr = b"\0"
    offs = []
    for s in syms:
        offs.append(len(dynstr))
        dynstr += s[0].encode() + b"\0"
    if not strtab_nul:
        dynstr = dynstr[:-1]
    # .dynsym: locals first (ELF rule; the reader does not depend on it)
    order = sorted(range(len(syms)), key=lambda i: syms[i][1] != LOCAL)
    dynsym = b"\0" * 16
    for i in order:
        name, bind, typ, vis, ndx = syms[i]
        no = offs[i] if name_off is None else name_off
        dynsym += struct.pack("<IIIBBH", no, 0x100 + 4 * i, 4, (bind << 4) | typ, vis, ndx)
    nlocal = 1 + sum(1 for s in syms if s[1] == LOCAL)
    shstr = b"\0.dynsym\0.dynstr\0.bss\0.shstrtab\0"
    names = {n: shstr.index(n.encode()) for n in (".dynsym", ".dynstr", ".bss", ".shstrtab")}

    body = bytearray(52)
    def put(blob):
        while len(body) % 4:
            body.append(0)
        off = len(body)
        body.extend(blob)
        return off
    o_str, o_sym, o_shs = put(dynstr), put(dynsym), put(shstr)
    sh = [b"\0" * 40]
    sym_type = 2 if no_dynsym else 11  # SHT_SYMTAB instead of SHT_DYNSYM
    sh.append(struct.pack("<10I", names[".dynsym"], sym_type, 2, 0, o_sym, len(dynsym) + sym_extra, link, nlocal, 4,
                          sym_entsize))
    sh.append(struct.pack("<10I", names[".dynstr"], strtab_type, 2, 0, o_str, len(dynstr), 0, 0, 1, 0))
    sh.append(struct.pack("<10I", names[".bss"], 8, 3, 0x100, len(body), 0x100, 0, 0, 4, 0))
    sh.append(struct.pack("<10I", names[".shstrtab"], 3, 0, 0, o_shs, len(shstr), 0, 0, 1, 0))
    o_sh = put(b"".join(sh))
    ident = b"\x7fELF" + bytes([cls, data, 1, 0]) + b"\0" * 8
    hdr = ident + struct.pack("<HHIIIIIHHHHHH", etype, machine, 1, 0, 0, 0 if no_shdrs else o_sh, 0, 52, 0, 0,
                              shentsize, 0 if no_shdrs else len(sh), 4)
    body[:52] = hdr
    return bytes(body)


def without(name):
    return [s for s in FULL if s[0] != name]


def replace(name, **kw):
    out = []
    for s in FULL:
        if s[0] == name:
            s = (s[0], kw.get("bind", s[1]), kw.get("type", s[2]), kw.get("vis", s[3]), kw.get("ndx", s[4]))
        out.append(s)
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkfixtures.py OUTDIR")
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    files = {
        "full-arm.so": elf(FULL),
        "full-x86.so": elf(FULL, machine=EM_386),
        "minus-arm.so": elf(without("kk_fb")),
        "minus2-arm.so": elf([s for s in FULL if s[0] not in ("kk_fb", "kk_obj")]),
        "kind-arm.so": elf(replace("kk_obj", type=FUNC)),            # an object turned into a function
        "ifunc-arm.so": elf(replace("kk_ifunc", type=FUNC)),         # IFUNC and FUNC are the same kind
        "strong-arm.so": elf(replace("kk_weak", bind=GLOBAL)),       # binding may differ
        "hiddenfb-arm.so": elf(replace("kk_fb", vis=HIDDEN)),        # a hidden kk_fb is not an export
        "undeffb-arm.so": elf(replace("kk_fb", ndx=UND)),            # an imported kk_fb is not an export
        "dup-arm.so": elf(FULL + [FULL[0], ("kk_obj", GLOBAL, FUNC, DEFAULT, BSS)]),  # repeated name, two kinds
        "empty-arm.so": elf([]),
        # bad input
        "bad-elf64.so": elf(FULL, cls=2),
        "bad-bigendian.so": elf(FULL, data=2),
        "bad-exec.so": elf(FULL, etype=2),
        "bad-mips.so": elf(FULL, machine=EM_MIPS),
        "bad-shentsize.so": elf(FULL, shentsize=32),
        "bad-noshdrs.so": elf(FULL, no_shdrs=True),
        "bad-nodynsym.so": elf(FULL, no_dynsym=True),
        "bad-symentsize.so": elf(FULL, sym_entsize=12),
        "bad-symsize.so": elf(FULL, sym_extra=8),
        "bad-sympasteof.so": elf(FULL, sym_extra=1 << 20),
        "bad-link0.so": elf(FULL, link=0),
        "bad-link99.so": elf(FULL, link=99),
        "bad-linktype.so": elf(FULL, strtab_type=8),
        "bad-nameoff.so": elf(FULL, name_off=0x7FFFFFF0),
        "bad-nonul.so": elf(FULL, strtab_nul=False),
    }
    for name, blob in sorted(files.items()):
        with open(os.path.join(out, name), "wb") as f:
            f.write(blob)


if __name__ == "__main__":
    main()
