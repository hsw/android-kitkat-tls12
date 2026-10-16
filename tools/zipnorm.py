#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""zipnorm.py: make an AOSP-built jar byte-reproducible, in place (kktls release `collect` step).

    python3 -I zipnorm.py [--mtime EPOCH] JAR...
    python3 -I zipnorm.py --selftest

Two builds of the same sources give jars whose members are identical but whose zip metadata carries the build: DOS
time/date of every entry, the 0x5455 extended timestamp and 0x7875 uid/gid extras (`zip` adds them to classes.dex),
the umask in the external attributes. This rewrites each jar as:
  - entries sorted by name (bytes), directory entries kept
  - every entry's DOS time/date = --mtime (default 1230768000 = 2009-01-01 00:00 UTC, as mkzips.sh)
  - the compressed data copied raw from the input (no recompression: the method, stored or deflated, and the
    compressed bytes stay as the build made them, so the result does not depend on this host's zlib)
  - no extra fields, no comments, no data descriptors; general purpose flags reduced to the UTF-8 bit; version made
    by 2.0/FAT, external and internal attributes 0
Then it re-reads the result with zipfile: the same names, and for each the same CRC, sizes, method and member bytes
as the input (CRC-checked by zipfile), before the input is replaced (same file mode).
Refused (exit 1, input unchanged): zip64, multi-disk, encryption, a method other than stored/deflated, local and
central names that differ, duplicate entry names, overlapping or truncated entries.
"""
import io
import os
import struct
import sys
import tempfile
import time
import warnings
import zipfile

DEFAULT_MTIME = 1230768000
LFH, CDH, EOCD = b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06"


class ZipError(Exception):
    pass


def dos_time(epoch):
    t = max(time.gmtime(epoch)[:6], (1980, 1, 1, 0, 0, 0))
    if t[0] > 2107:
        raise ZipError("mtime after 2107")
    return (t[3] << 11) | (t[4] << 5) | (t[5] // 2), ((t[0] - 1980) << 9) | (t[1] << 5) | t[2]


def read_entries(data):
    """-> [(name, method, flags, crc, csize, usize, raw)] in central directory order."""
    pos = data.rfind(EOCD, max(0, len(data) - 22 - 65535))
    if pos < 0 or len(data) - pos < 22:
        raise ZipError("no end of central directory record")
    disk, cd_disk, n_here, n, cd_size, cd_off, clen = struct.unpack("<HHHHIIH", data[pos + 4:pos + 22])
    if disk or cd_disk or n_here != n:
        raise ZipError("multi-disk zip")
    if n == 0xFFFF or 0xFFFFFFFF in (cd_size, cd_off) or (pos >= 20 and data[pos - 20:pos - 16] == b"PK\x06\x07"):
        raise ZipError("zip64 zip")
    if pos + 22 + clen != len(data):
        raise ZipError("data after the archive comment")
    if cd_off + cd_size > pos:
        raise ZipError("central directory overlaps its end record")
    out, p, spans = [], cd_off, []
    for _ in range(n):
        if data[p:p + 4] != CDH:
            raise ZipError("bad central directory header at %d" % p)
        (_vm, _vn, flags, method, _t, _d, crc, csize, usize, nlen, xlen, mlen, dstart, _ia, _ea,
         lho) = struct.unpack("<HHHHHHIIIHHHHHII", data[p + 4:p + 46])
        name = data[p + 46:p + 46 + nlen]
        p += 46 + nlen + xlen + mlen
        if dstart:
            raise ZipError("multi-disk entry %r" % name)
        if flags & 0x41:
            raise ZipError("encrypted entry %r" % name)
        if method not in (0, 8):
            raise ZipError("entry %r: method %d" % (name, method))
        if 0xFFFFFFFF in (csize, usize, lho):
            raise ZipError("zip64 entry %r" % name)
        if data[lho:lho + 4] != LFH:
            raise ZipError("entry %r: no local header at %d" % (name, lho))
        lnlen, lxlen = struct.unpack("<HH", data[lho + 26:lho + 30])
        if data[lho + 30:lho + 30 + lnlen] != name:
            raise ZipError("entry %r: local name differs" % name)
        start = lho + 30 + lnlen + lxlen
        if start + csize > cd_off:
            raise ZipError("entry %r: data runs into the central directory" % name)
        spans.append((lho, start + csize, name))
        out.append((name, method, flags, crc, csize, usize, data[start:start + csize]))
    if p != cd_off + cd_size:
        raise ZipError("central directory size mismatch")
    spans.sort()
    for a, b in zip(spans, spans[1:]):
        if b[0] < a[1]:
            raise ZipError("entries %r and %r overlap" % (a[2], b[2]))
    return out


def build(entries, mtime):
    t, d = dos_time(mtime)
    body, cd = io.BytesIO(), io.BytesIO()
    names = [e[0] for e in entries]
    if len(set(names)) != len(names):
        raise ZipError("duplicate entry names")
    for name, method, flags, crc, csize, usize, raw in sorted(entries, key=lambda e: e[0]):
        vn = 20 if method == 8 or name.endswith(b"/") else 10
        fl = flags & 0x0800
        off = body.tell()
        body.write(LFH + struct.pack("<HHHHHIIIHH", vn, fl, method, t, d, crc, csize, usize, len(name), 0) + name)
        body.write(raw)
        cd.write(CDH + struct.pack("<HHHHHHIIIHHHHHII", 20, vn, fl, method, t, d, crc, csize, usize, len(name),
                                   0, 0, 0, 0, 0, off) + name)
    cdb = cd.getvalue()
    n = len(entries)
    if n > 0xFFFE or body.tell() + len(cdb) >= 0xFFFFFFFF:
        raise ZipError("result needs zip64")
    return body.getvalue() + cdb + EOCD + struct.pack("<HHHHIIH", 0, 0, n, n, len(cdb), body.tell(), 0)


def verify(old, new):
    with zipfile.ZipFile(io.BytesIO(old)) as a, zipfile.ZipFile(io.BytesIO(new)) as b:
        ia = {i.filename: i for i in a.infolist()}
        ib = {i.filename: i for i in b.infolist()}
        if sorted(ia) != sorted(ib) or len(ia) != len(a.infolist()):
            raise ZipError("verify: names differ")
        raw_names = [e[0] for e in read_entries(new)]
        if raw_names != sorted(raw_names):
            raise ZipError("verify: result not sorted")
        for k, x in ia.items():
            y = ib[k]
            if (x.CRC, x.compress_size, x.file_size, x.compress_type) != (y.CRC, y.compress_size, y.file_size,
                                                                          y.compress_type):
                raise ZipError("verify: %s: crc/size/method differ" % k)
            if a.read(k) != b.read(k):
                raise ZipError("verify: %s: member bytes differ" % k)


def normalize(path, mtime=DEFAULT_MTIME):
    """Rewrite path in place; True if it changed."""
    with open(path, "rb") as f:
        old = f.read()
    new = build(read_entries(old), mtime)
    verify(old, new)
    if new == old:
        return False
    mode = os.stat(path).st_mode & 0o7777
    fd, tmp = tempfile.mkstemp(prefix=".zipnorm-", dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(new)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return True


def selftest():
    import shutil
    ok = True

    def check(cond, what):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + what)
        ok = ok and cond

    def jar(path, when, uid_extra):
        with zipfile.ZipFile(path, "w") as z:
            z.writestr(zipfile.ZipInfo("META-INF/", when), b"")
            i = zipfile.ZipInfo("META-INF/MANIFEST.MF", when)
            i.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(i, b"Manifest-Version: 1.0\r\nCreated-By: test\r\n\r\n")
            i = zipfile.ZipInfo("classes.dex", when)
            i.compress_type = zipfile.ZIP_DEFLATED
            i.extra = struct.pack("<HHB", 0x5455, 5, 3) + struct.pack("<I", int(time.mktime(when + (0, 0, -1)))) + \
                struct.pack("<HHBBIBI", 0x7875, 11, 1, 4, uid_extra, 4, uid_extra)
            i.external_attr = 0o100644 << 16 if uid_extra else 0o100600 << 16
            i.create_system = 3
            z.writestr(i, b"dex\n035\0" + bytes(range(256)) * 64)
            i = zipfile.ZipInfo("a/stored.txt", when)
            z.writestr(i, b"stored\n")
            i = zipfile.ZipInfo("Z/upper.properties", when)
            i.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(i, b"k=v\n" * 50)

    tmp = tempfile.mkdtemp(prefix="zipnorm-selftest-")
    try:
        a, b = os.path.join(tmp, "a.jar"), os.path.join(tmp, "b.jar")
        jar(a, (2026, 10, 15, 18, 36, 10), 1006)
        jar(b, (2026, 10, 16, 3, 1, 59), 1001)
        os.chmod(a, 0o640)
        with open(a, "rb") as f:
            orig = f.read()
        check(open(a, "rb").read() != open(b, "rb").read(), "two builds differ before")
        check(normalize(a) and normalize(b), "both rewritten")
        na, nb = open(a, "rb").read(), open(b, "rb").read()
        check(na == nb, "byte-identical after")
        check(os.stat(a).st_mode & 0o777 == 0o640, "file mode kept")
        with zipfile.ZipFile(a) as z, zipfile.ZipFile(io.BytesIO(orig)) as o:
            check(z.testzip() is None, "zipfile testzip clean")
            names = [i.filename for i in z.infolist()]
            check(names == sorted(names, key=lambda s: s.encode()), "entries sorted: %s" % names)
            check(all(i.date_time == (2009, 1, 1, 0, 0, 0) for i in z.infolist()), "every entry 2009-01-01 00:00")
            check(all(i.extra == b"" and i.external_attr == 0 and i.flag_bits == 0 for i in z.infolist()),
                  "no extras, attributes 0, no data descriptors")
            check(all(z.getinfo(n).compress_type == o.getinfo(n).compress_type and z.read(n) == o.read(n)
                      for n in o.namelist()), "methods and member bytes kept")
            raw_o = {e[0]: e[6] for e in read_entries(orig)}
            raw_n = {e[0]: e[6] for e in read_entries(na)}
            check(raw_o == raw_n, "compressed data copied raw")
        check(not normalize(a), "idempotent (second run leaves the file)")
        c = os.path.join(tmp, "c.jar")
        shutil.copy(a, c)
        normalize(c, 0)
        with zipfile.ZipFile(c) as z:
            check(z.infolist()[0].date_time == (1980, 1, 1, 0, 0, 0), "--mtime 0 clamps to 1980-01-01")
        bad = os.path.join(tmp, "bad.jar")
        with open(bad, "wb") as f:
            f.write(orig[:-30])
        try:
            normalize(bad)
            check(False, "truncated zip refused")
        except ZipError:
            check(open(bad, "rb").read() == orig[:-30], "truncated zip refused, file unchanged")
        enc = bytearray(orig)
        p = enc.find(CDH)
        enc[p + 8] |= 1
        with open(bad, "wb") as f:
            f.write(enc)
        try:
            normalize(bad)
            check(False, "encrypted entry refused")
        except ZipError:
            check(True, "encrypted entry refused")
        dup = os.path.join(tmp, "dup.jar")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # zipfile warns about the duplicate name it is asked to write
            with zipfile.ZipFile(dup, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("classes.dex", b"one")
                z.writestr("classes.dex", b"two")
        orig_dup = open(dup, "rb").read()
        try:
            normalize(dup)
            check(False, "duplicate entry names refused")
        except ZipError:
            check(open(dup, "rb").read() == orig_dup, "duplicate entry names refused, file unchanged")
    finally:
        shutil.rmtree(tmp)
    print("SELFTEST " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    mtime, args = DEFAULT_MTIME, list(argv)
    if args[:1] == ["--mtime"] and len(args) > 1:
        if not args[1].isdigit():
            print("zipnorm: --mtime %r is not a number" % args[1], file=sys.stderr)
            return 2
        mtime, args = int(args[1]), args[2:]
    if not args or any(a.startswith("-") for a in args):
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    rc = 0
    for p in args:
        try:
            print("%s: %s" % (p, "normalized" if normalize(p, mtime) else "already normal"))
        except (ZipError, OSError, zipfile.BadZipFile) as e:
            print("zipnorm: %s: %s" % (p, e), file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
