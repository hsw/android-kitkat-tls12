#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""rawzip.py: rewrite a zip (a jar, a recovery zip) with some entries swapped, copying all others byte for byte.

    python3 -I rawzip.py --list FILE        print the entries: offset, method, flags, crc, sizes, name

Python's zipfile would recompress every entry and drop the original headers. rewrite() copies the local header, the
compressed bytes and the data descriptor of every untouched entry as they are, in their original order; only the
swapped entries are compressed again (with their own method, stored or deflated), and their local header and central
directory record get the new CRC and sizes (data descriptor flag cleared). The central directory keeps every record's
fields (version, flags, times, attributes, extra, comment) but the new offsets; the archive comment is kept.

Refused (ZipError): zip64 (zip64 end record or locator, 0xffff/0xffffffff markers, a zip64 extra field in a local or
central header), multi-disk archives, encrypted entries, methods other than stored and deflated in a swapped entry,
inconsistent headers (local name differs from the central one, a data descriptor whose CRC or sizes differ from the
central record, overlapping entries), and output that would need zip64.

Stdlib only.
"""
import os
import struct
import sys
import zlib

EOCD_SIG, CEN_SIG, LOC_SIG, DD_SIG, Z64_LOC_SIG = 0x06054b50, 0x02014b50, 0x04034b50, 0x08074b50, 0x07064b50
EOCD = struct.Struct("<IHHHHIIH")              # sig, disk, cd disk, entries here, entries, cd size, cd offset, comment
CEN = struct.Struct("<IHHHHHHIIIHHHHHII")      # sig, made by, needed, flags, method, time, date, crc, csize, usize,
#                                                name len, extra len, comment len, disk, int attr, ext attr, offset
LOC = struct.Struct("<IHHHHHIIIHH")            # sig, needed, flags, method, time, date, crc, csize, usize, name, extra
FLAG_ENCRYPTED, FLAG_DD, FLAG_UTF8 = 0x0001, 0x0008, 0x0800
STORED, DEFLATED = 0, 8
MAX32, MAX16 = 0xffffffff, 0xffff
# an appended entry: made by unix (3) with zip 2.0, needs 2.0 (deflate), 1980-01-01 00:00 (DOS date and time)
NEW_MADE_BY, NEW_NEEDED, NEW_DATE, NEW_TIME = 0x0314, 20, 0x0021, 0


class ZipError(Exception):
    pass


class Entry(object):
    """One entry: the central record's fields, its raw extra/comment, and the byte range of its local record."""

    def __init__(self, fields, name, extra, comment):
        (_, self.made_by, self.needed, self.flags, self.method, self.time, self.date, self.crc, self.csize,
         self.usize, _, _, _, self.disk, self.int_attr, self.ext_attr, self.offset) = fields
        self.name, self.extra, self.comment = name, extra, comment
        self.end = None          # end of the local record (header, name, extra, data, data descriptor)
        self.data_start = None   # start of the compressed data

    @property
    def text(self):
        return self.name.decode("utf-8" if self.flags & FLAG_UTF8 else "cp437", "replace")


def has_zip64_extra(extra):
    i = 0
    while i + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, i)
        if tag == 0x0001:
            return True
        i += 4 + size
    return False


def read(data):
    """(entries in central directory order, archive comment) of a zip in memory."""
    lo = max(0, len(data) - EOCD.size - MAX16)
    pos = data.rfind(struct.pack("<I", EOCD_SIG), lo)
    while pos >= 0:
        if pos + EOCD.size <= len(data) and pos + EOCD.size + EOCD.unpack_from(data, pos)[7] == len(data):
            break
        pos = data.rfind(struct.pack("<I", EOCD_SIG), lo, pos)
    if pos < 0:
        raise ZipError("no end of central directory record")
    _, disk, cd_disk, n_here, n, cd_size, cd_off, clen = EOCD.unpack_from(data, pos)
    if pos >= 20 and struct.unpack_from("<I", data, pos - 20)[0] == Z64_LOC_SIG:
        raise ZipError("zip64 archive (zip64 end of central directory locator)")
    if MAX16 in (n_here, n) or MAX32 in (cd_size, cd_off):
        raise ZipError("zip64 archive (end record fields at their maximum)")
    if disk or cd_disk or n_here != n:
        raise ZipError("multi-disk archive")
    if cd_off + cd_size > pos:
        raise ZipError("central directory runs past the end record")
    comment = data[pos + EOCD.size:]
    entries, p = [], cd_off
    for _ in range(n):
        if p + CEN.size > cd_off + cd_size or struct.unpack_from("<I", data, p)[0] != CEN_SIG:
            raise ZipError("bad central directory record at %d" % p)
        f = CEN.unpack_from(data, p)
        nl, xl, cl = f[10], f[11], f[12]
        q = p + CEN.size
        e = Entry(f, data[q:q + nl], data[q + nl:q + nl + xl], data[q + nl + xl:q + nl + xl + cl])
        p = q + nl + xl + cl
        if MAX32 in (e.csize, e.usize, e.offset) or has_zip64_extra(e.extra):
            raise ZipError("%s: zip64 entry" % e.text)
        if e.disk:
            raise ZipError("%s: multi-disk archive" % e.text)
        if e.flags & FLAG_ENCRYPTED:
            raise ZipError("%s: encrypted entry" % e.text)
        local(data, e)
        entries.append(e)
    if p != cd_off + cd_size:
        raise ZipError("central directory size %d, records end at %d" % (cd_size, p - cd_off))
    spans = sorted((e.offset, e.end, e.text) for e in entries)
    for a, b in zip(spans, spans[1:]):
        if b[0] < a[1]:
            raise ZipError("entries %s and %s overlap" % (a[2], b[2]))
    if spans and spans[-1][1] > cd_off:
        raise ZipError("%s runs into the central directory" % spans[-1][2])
    return entries, comment


def local(data, e):
    """Sets e.data_start and e.end from the local header (and the data descriptor, flag bit 3)."""
    o = e.offset
    if o + LOC.size > len(data) or struct.unpack_from("<I", data, o)[0] != LOC_SIG:
        raise ZipError("%s: no local header at %d" % (e.text, o))
    _, _, flags, method, _, _, crc, csize, usize, nl, xl = LOC.unpack_from(data, o)
    name, extra = data[o + LOC.size:o + LOC.size + nl], data[o + LOC.size + nl:o + LOC.size + nl + xl]
    if name != e.name:
        raise ZipError("%s: local header names %r" % (e.text, name))
    if has_zip64_extra(extra):
        raise ZipError("%s: zip64 entry (local header)" % e.text)
    if method != e.method or (flags & FLAG_DD) != (e.flags & FLAG_DD):
        raise ZipError("%s: local header method/flags differ from the central record" % e.text)
    e.data_start = o + LOC.size + nl + xl
    end = e.data_start + e.csize
    if flags & FLAG_DD:
        sig = end + 4 <= len(data) and struct.unpack_from("<I", data, end)[0] == DD_SIG
        if sig and end + 16 <= len(data) and struct.unpack_from("<III", data, end + 4) == (e.crc, e.csize, e.usize):
            dd = struct.unpack_from("<III", data, end + 4)
            end += 16
        elif end + 12 <= len(data):
            dd = struct.unpack_from("<III", data, end)
            end += 12
        else:
            raise ZipError("%s: data descriptor past the end" % e.text)
        if dd != (e.crc, e.csize, e.usize):
            raise ZipError("%s: data descriptor differs from the central record" % e.text)
    elif (crc, csize, usize) != (e.crc, e.csize, e.usize):
        raise ZipError("%s: local header CRC/sizes differ from the central record" % e.text)
    if end > len(data):
        raise ZipError("%s: data past the end" % e.text)
    e.end = end


def compress(method, raw, name):
    if method == STORED:
        return raw
    if method == DEFLATED:
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        return c.compress(raw) + c.flush()
    raise ZipError("%s: compression method %d (only stored and deflated can be rewritten)" % (name, method))


def rewrite(src, dst, changes):
    """Write dst = src with changes {name: bytes (replace or append) | None (remove)}; every other entry is copied
    byte for byte. Appended entries go after the last one, deflated, in sorted name order. Returns the names written,
    in order."""
    with open(src, "rb") as f:
        data = f.read()
    entries, comment = read(data)
    byname = {}
    for e in entries:
        if e.text in byname:
            raise ZipError("duplicate entry %s" % e.text)
        byname[e.text] = e
    for n, v in changes.items():
        if v is None and n not in byname:
            raise ZipError("cannot remove %s: no such entry" % n)
    out, cen, names = bytearray(), [], []
    for e in sorted(entries, key=lambda e: e.offset):
        if e.text in changes and changes[e.text] is None:
            continue
        off = len(out)
        if e.text in changes:
            raw = changes[e.text]
            comp = compress(e.method, raw, e.text)
            flags, crc, csize, usize = e.flags & ~FLAG_DD, zlib.crc32(raw) & MAX32, len(comp), len(raw)
            lx = data[e.offset + LOC.size + len(e.name):e.data_start]   # the local extra field, kept
            out += LOC.pack(LOC_SIG, LOC.unpack_from(data, e.offset)[1], flags, e.method, e.time, e.date, crc,
                            csize, usize, len(e.name), len(lx))
            out += e.name + lx + comp
            rec = (e.made_by, e.needed, flags, e.method, e.time, e.date, crc, csize, usize)
        else:
            out += data[e.offset:e.end]
            rec = (e.made_by, e.needed, e.flags, e.method, e.time, e.date, e.crc, e.csize, e.usize)
        cen.append((e.offset, rec, e.name, e.extra, e.comment, e.int_attr, e.ext_attr, off))
        names.append(e.text)
    for n in sorted(k for k, v in changes.items() if v is not None and k not in byname):
        raw, bn = changes[n], n.encode("utf-8")
        comp = compress(DEFLATED, raw, n)
        flags = FLAG_UTF8 if any(c > 0x7f for c in bn) else 0
        crc = zlib.crc32(raw) & MAX32
        rec = (NEW_MADE_BY, NEW_NEEDED, flags, DEFLATED, NEW_TIME, NEW_DATE, crc, len(comp), len(raw))
        off = len(out)
        out += LOC.pack(LOC_SIG, NEW_NEEDED, flags, DEFLATED, NEW_TIME, NEW_DATE, crc, len(comp), len(raw), len(bn),
                        0) + bn + comp
        cen.append((None, rec, bn, b"", b"", 0, 0o100644 << 16, off))
        names.append(n)
    # the central directory keeps the source's record order (appended entries last)
    order = {e.offset: i for i, e in enumerate(entries)}
    cen.sort(key=lambda c: (c[0] is None, order.get(c[0], 0)))
    cd_off = len(out)
    for _, rec, name, extra, cmt, ia, ea, off in cen:
        if off > MAX32 or rec[7] > MAX32 or rec[8] > MAX32:
            raise ZipError("%s: the output would need zip64" % name.decode("utf-8", "replace"))
        out += CEN.pack(CEN_SIG, *rec, len(name), len(extra), len(cmt), 0, ia, ea, off) + name + extra + cmt
    cd_size = len(out) - cd_off
    if len(cen) >= MAX16 or cd_off >= MAX32 or cd_size >= MAX32:
        raise ZipError("the output would need zip64")
    out += EOCD.pack(EOCD_SIG, 0, 0, len(cen), len(cen), cd_size, cd_off, len(comment)) + comment
    atomic_write(dst, out)
    return names


def atomic_write(path, data):
    """Write data (bytes, or text as UTF-8) to path through path.tmp and os.replace: path is never left half
    written."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data.encode("utf-8") if isinstance(data, str) else data)
    os.replace(tmp, path)


def main(argv):
    if len(argv) < 2 or argv[0] != "--list":
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    rc = 0
    for p in argv[1:]:
        try:
            with open(p, "rb") as f:
                entries, _ = read(f.read())
        except (OSError, ZipError) as e:
            print("rawzip: %s: %s" % (p, e), file=sys.stderr)
            rc = 2
            continue
        for e in entries:
            print("%s %d %d 0x%04x %08x %d %d %s" % (p, e.offset, e.method, e.flags, e.crc, e.csize, e.usize, e.text))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
