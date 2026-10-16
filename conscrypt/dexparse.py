# SPDX-License-Identifier: Apache-2.0
"""dexparse.py: the dex-file reading shared by apicheck.py and check_prebuilt.py (this directory) and other checkers.

Stdlib only. Those scripts run as `python3 -I`, which leaves the script directory off sys.path, so they import this
module after `sys.path.insert(0, <their own directory>)`. Layout: dalvik/libdex DexFile.h (header version 035):
string_ids at 0x38, type_ids at 0x40, proto_ids at 0x48, field_ids at 0x50, method_ids at 0x58, class_defs at 0x60.

    python3 -I dexparse.py --selftest
"""
import struct
import sys

DEX_MAGIC = b"dex\n"
STRING_IDS = 0x38   # string_ids_size, string_ids_off, then type_ids_size, type_ids_off
TYPE_IDS = 0x40
PROTO_IDS = 0x48
FIELD_IDS = 0x50
METHOD_IDS = 0x58
CLASS_DEFS = 0x60   # class_defs_size, class_defs_off
CLASS_DEF_SIZE = 32


def uleb128(d, pos):
    """(value, position after it) of the unsigned LEB128 at d[pos]."""
    v = shift = 0
    while True:
        b = d[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if b < 0x80:
            return v, pos
        shift += 7


def mutf8(b):
    """Modified UTF-8 (dex string_data) -> str: the two-byte NUL (0xC0 0x80) becomes U+0000; surrogate pairs and any
    other invalid sequence decode loosely ("replace"), which is enough for class, member and descriptor names."""
    return b.replace(b"\xc0\x80", b"\x00").decode("utf-8", "replace")


def dex_strings(d):
    """Every string_ids entry of a dex file, in index order, MUTF-8 decoded."""
    n, off = struct.unpack_from("<II", d, STRING_IDS)
    out = []
    for i in range(n):
        so = struct.unpack_from("<I", d, off + 4 * i)[0]
        _, p = uleb128(d, so)  # skip the utf16 length
        out.append(mutf8(d[p:d.index(b"\0", p)]))
    return out


def dex_tables(d):
    """(strings, types, classes) lists of a dex file: every string, every type descriptor and the descriptor of every
    defined class. Raises ValueError on a missing magic or a malformed table (no version check: callers decide)."""
    if d[:4] != DEX_MAGIC:
        raise ValueError("no dex magic")
    try:
        strings = dex_strings(d)
        t_size, t_off = struct.unpack_from("<II", d, TYPE_IDS)
        c_size, c_off = struct.unpack_from("<II", d, CLASS_DEFS)
        types = [strings[struct.unpack_from("<I", d, t_off + 4 * i)[0]] for i in range(t_size)]
        classes = [types[struct.unpack_from("<I", d, c_off + CLASS_DEF_SIZE * i)[0]] for i in range(c_size)]
    except (struct.error, IndexError, ValueError) as e:
        raise ValueError("malformed dex (%s: %s)" % (type(e).__name__, e))
    return strings, types, classes


# ---------------------------------------------------------------------------------------------------------- selftest

def make_dex(strings, types=(), classes=(), version=b"035\0"):
    """A minimal dex with only the string, type and class-def tables filled (enough for dex_tables). `strings` are
    bytes (already MUTF-8) or str (UTF-8 encoded); `types`/`classes` are indexes into strings/types."""
    head = bytearray(0x70)
    head[0:8] = DEX_MAGIC + version
    data = bytearray()
    base = 0x70
    s_ids = base
    t_ids = s_ids + 4 * len(strings)
    c_defs = t_ids + 4 * len(types)
    data_off = c_defs + CLASS_DEF_SIZE * len(classes)
    body = bytearray()
    offs = []
    for s in strings:
        raw = s if isinstance(s, bytes) else s.encode("utf-8")
        offs.append(data_off + len(body))
        body += bytes([min(len(raw), 0x7F)]) + raw + b"\0"
    for o in offs:
        data += struct.pack("<I", o)
    for t in types:
        data += struct.pack("<I", t)
    for c in classes:
        data += struct.pack("<I", c) + bytes(CLASS_DEF_SIZE - 4)
    struct.pack_into("<IIII", head, STRING_IDS, len(strings), s_ids, len(types), t_ids)
    struct.pack_into("<II", head, CLASS_DEFS, len(classes), c_defs)
    return bytes(head) + bytes(data) + bytes(body)


def selftest():
    fails = []

    def check(name, cond):
        print("%s %s" % ("ok  " if cond else "FAIL", name))
        if not cond:
            fails.append(name)

    check("uleb128 one byte", uleb128(b"\x05", 0) == (5, 1))
    check("uleb128 two bytes", uleb128(b"\x80\x01", 0) == (128, 2))
    check("uleb128 at an offset", uleb128(b"\xff\xe5\x8e\x26", 1) == (624485, 4))
    check("mutf8 ASCII", mutf8(b"Ljava/lang/Object;") == "Ljava/lang/Object;")
    check("mutf8 two-byte NUL", mutf8(b"a\xc0\x80b") == "a\x00b")
    check("mutf8 BMP character", mutf8("é".encode("utf-8")) == "é")
    d = make_dex([b"LA;", b"LB;", b"x\xc0\x80y", "ü"], types=[0, 1], classes=[1])
    check("dex_strings order and MUTF-8", dex_strings(d) == ["LA;", "LB;", "x\x00y", "ü"])
    check("dex_tables", dex_tables(d) == (["LA;", "LB;", "x\x00y", "ü"], ["LA;", "LB;"], ["LB;"]))
    for name, bad in (("no magic", b"xxxx" + d[4:]), ("truncated", d[:0x80]),
                      ("type index out of range", make_dex([b"LA;"], types=[5])),
                      ("unterminated string", d[:-1])):
        try:
            dex_tables(bad)
            check("dex_tables rejects: " + name, False)
        except ValueError:
            check("dex_tables rejects: " + name, True)
    print("SELFTEST %s (%d failed)" % ("OK" if not fails else "FAIL", len(fails)))
    return 0 if not fails else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    sys.stderr.write(__doc__)
    sys.exit(2)
