# SPDX-License-Identifier: Apache-2.0
"""Unit tests of rawzip.py: untouched entries are copied byte for byte (data descriptors with and without their
signature included), swapped entries read back with their new content, removals and appends, and the refusals (zip64,
encrypted, multi-disk, duplicate names, inconsistent headers, overlapping entries).

    python3 -I -m unittest discover tools/jarpatch/tests
"""
import contextlib
import io
import os
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rawzip  # noqa: E402


def deflate(raw):
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    return c.compress(raw) + c.flush()


def build(entries, comment=b"", extra=b""):
    """A zip from [(name, raw, method, dd)]; dd: None (sizes in the local header), "sig" or "nosig" (flag bit 3, a
    data descriptor with or without its signature). Returns (bytes, {name: local record bytes})."""
    out, cen, recs = bytearray(), bytearray(), {}
    for name, raw, method, dd in entries:
        bn, comp, crc = name.encode(), raw if method == 0 else deflate(raw), zlib.crc32(raw)
        flags = 0x0008 if dd else 0
        off = len(out)
        lsz = (0, 0, 0) if dd else (crc, len(comp), len(raw))
        out += rawzip.LOC.pack(rawzip.LOC_SIG, 20, flags, method, 0x6000, 0x4f21, *lsz, len(bn), len(extra)) + bn
        out += extra + comp
        if dd == "sig":
            out += struct.pack("<IIII", rawzip.DD_SIG, crc, len(comp), len(raw))
        elif dd == "nosig":
            out += struct.pack("<III", crc, len(comp), len(raw))
        recs[name] = bytes(out[off:])
        cen += rawzip.CEN.pack(rawzip.CEN_SIG, 0x0314, 20, flags, method, 0x6000, 0x4f21, crc, len(comp), len(raw),
                               len(bn), 0, 0, 0, 0, 0o100755 << 16, off) + bn
    cd = len(out)
    out += cen + rawzip.EOCD.pack(rawzip.EOCD_SIG, 0, 0, len(entries), len(entries), len(cen), cd, len(comment))
    return bytes(out + comment), recs


class RawZip(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)

    def path(self, name, data=None):
        p = os.path.join(self.t.name, name)
        if data is not None:
            with open(p, "wb") as f:
                f.write(data)
        return p

    def test_rewrite(self):
        entries = [("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", 8, "sig"),
                   ("classes.dex", b"dex\n035\0" + b"old" * 50, 8, "nosig"),
                   ("stored.txt", b"stored bytes", 0, None),
                   ("java/security/security.properties", b"a=1\n", 8, "sig"),
                   ("gone.txt", b"bye", 8, None)]
        data, recs = build(entries, comment=b"archive comment", extra=b"\xfe\xca\x00\x00")
        src, dst = self.path("in.jar", data), self.path("out.jar")
        new = {"classes.dex": b"dex\n035\0new", "java/security/security.properties": b"a=1\nkktls=1\n",
               "gone.txt": None, "added/b.txt": b"b", "added/a.txt": b"a"}
        names = rawzip.rewrite(src, dst, new)
        self.assertEqual(names, ["META-INF/MANIFEST.MF", "classes.dex", "stored.txt",
                                 "java/security/security.properties", "added/a.txt", "added/b.txt"])
        with open(dst, "rb") as f:
            out = f.read()
        # untouched entries: their whole local record (header, extra, data, data descriptor) byte for byte
        for n in ("META-INF/MANIFEST.MF", "stored.txt"):
            self.assertIn(recs[n], out, n)
        self.assertTrue(out.startswith(recs["META-INF/MANIFEST.MF"]))
        with zipfile.ZipFile(dst) as z:
            self.assertIsNone(z.testzip())
            self.assertEqual(z.namelist(), names)
            self.assertEqual(z.comment, b"archive comment")
            for n, raw in new.items():
                if raw is not None:
                    self.assertEqual(z.read(n), raw, n)
            info = {i.filename: i for i in z.infolist()}
            self.assertEqual(info["classes.dex"].flag_bits & 8, 0)               # sizes now in the local header
            self.assertEqual(info["classes.dex"].external_attr, 0o100755 << 16)   # central record fields kept
            self.assertEqual(info["classes.dex"].date_time, info["stored.txt"].date_time)
            self.assertEqual(info["stored.txt"].compress_type, 0)
        # the swapped entry keeps its local extra field; the swap is idempotent
        self.assertIn(b"classes.dex\xfe\xca\x00\x00", out)
        rawzip.rewrite(dst, self.path("again.jar"), {"classes.dex": b"dex\n035\0new"})
        with open(self.path("again.jar"), "rb") as f:
            self.assertEqual(f.read(), out)

    def test_python_data_descriptors(self):
        # zipfile writes data descriptors (with signature) to a stream it cannot seek
        class Stream(io.RawIOBase):
            def __init__(self):
                self.b = bytearray()

            def writable(self):
                return True

            def write(self, b):
                self.b += b
                return len(b)
        s = Stream()
        with zipfile.ZipFile(s, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("a", b"a" * 100)
            z.writestr("classes.dex", b"x" * 100)
        src = self.path("dd.jar", bytes(s.b))
        with zipfile.ZipFile(src) as z:
            self.assertTrue(all(i.flag_bits & 8 for i in z.infolist()))
        rawzip.rewrite(src, self.path("o.jar"), {"classes.dex": b"y"})
        with zipfile.ZipFile(self.path("o.jar")) as z:
            self.assertIsNone(z.testzip())
            self.assertEqual((z.read("a"), z.read("classes.dex")), (b"a" * 100, b"y"))

    def refused(self, data, needle, changes=None):
        src = self.path("bad.zip", data)
        with self.assertRaises(rawzip.ZipError) as cm:
            rawzip.rewrite(src, self.path("o.zip"), changes or {})
        self.assertIn(needle, str(cm.exception))
        self.assertFalse(os.path.exists(self.path("o.zip")))

    def test_zip64(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            with z.open("big", "w", force_zip64=True) as f:
                f.write(b"x")
        self.refused(b.getvalue(), "zip64")
        data, _ = build([("a", b"a", 8, None)])
        e = len(data) - rawzip.EOCD.size
        self.refused(data[:e + 16] + struct.pack("<I", 0xffffffff) + data[e + 20:], "zip64")
        loc = struct.pack("<IIQI", rawzip.Z64_LOC_SIG, 0, 0, 1)
        self.refused(data[:e] + loc + data[e:], "zip64")

    def test_cli(self):
        # an OSError or an unforeseen exception escaping a tool's main is exit 2 with one stderr line, never a
        # traceback with exit 1; main's own exit codes pass through
        def boom(exc):
            def main(argv):
                raise exc
            return main
        for exc, line in ((PermissionError(13, "Permission denied"), "t: error: [Errno 13] Permission denied\n"),
                          (BrokenPipeError(32, "Broken pipe"), "t: error: [Errno 32] Broken pipe\n"),
                          (ValueError("bad"), "t: unexpected error: ValueError: bad\n")):
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(rawzip.cli("t", boom(exc), []), 2)
            self.assertEqual(err.getvalue(), line)
        self.assertEqual(rawzip.cli("t", lambda argv: len(argv), ["a"]), 1)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rawzip.main(["--list", self.path("missing.zip")]), 2)

    def test_bad_input(self):
        data, _ = build([("a", b"a", 8, "sig")])
        self.refused(data[:-rawzip.EOCD.size], "no end of central directory")
        self.refused(data.replace(struct.pack("<I", zlib.crc32(b"a")), b"\0\0\0\0", 1), "data descriptor differs")
        enc = bytearray(data)
        cd = struct.unpack_from("<I", data, len(data) - 6)[0]
        struct.pack_into("<H", enc, cd + 8, 0x0009)
        self.refused(bytes(enc), "encrypted")
        self.refused(data, "no such entry", {"missing": None})
        data, _ = build([("a", b"a", 12, None)])     # bzip2: copied as is, cannot be swapped
        rawzip.rewrite(self.path("bz.zip", data), self.path("bz-out.zip"), {})
        self.refused(data, "compression method 12", {"a": b"b"})

    def test_inconsistent_layout(self):
        def cen_off(data, i):
            """Offset of the i-th central record of a build() zip (names of one byte, no extra, no comment)."""
            return struct.unpack_from("<I", data, len(data) - rawzip.EOCD.size + 16)[0] + i * (rawzip.CEN.size + 1)

        data, _ = build([("a", b"aa", 0, None), ("b", b"bb", 0, None)])
        # the local header names another entry than the central record
        bad = bytearray(data)
        bad[rawzip.LOC.size] = ord("x")
        self.refused(bytes(bad), "local header names")
        # local CRC/sizes (no data descriptor) differ from the central record
        bad = bytearray(data)
        struct.pack_into("<I", bad, 14, 0)
        self.refused(bytes(bad), "local header CRC/sizes differ from the central record")
        # multi-disk: in the end record, and in an entry
        bad = bytearray(data)
        struct.pack_into("<H", bad, len(data) - rawzip.EOCD.size + 4, 1)
        self.refused(bytes(bad), "multi-disk archive")
        bad = bytearray(data)
        struct.pack_into("<H", bad, cen_off(data, 1) + 34, 1)
        self.refused(bytes(bad), "b: multi-disk archive")
        # the same name twice
        self.refused(build([("a", b"1", 0, None), ("a", b"2", 0, None)])[0], "duplicate entry a")
        # overlapping entries: b's central record points at a copy of b's local record inside a's data
        _, recs = build([("b", b"bb", 0, None)])
        data, _ = build([("a", recs["b"], 0, None), ("b", b"bb", 0, None)])
        bad = bytearray(data)
        struct.pack_into("<I", bad, cen_off(data, 1) + 42, rawzip.LOC.size + 1)
        self.refused(bytes(bad), "entries a and b overlap")
        # the last entry's data runs into the central directory (local and central sizes agree, both too big)
        data, _ = build([("a", b"aa", 0, None), ("b", b"bb", 0, None)])
        bad = bytearray(data)
        b_loc = struct.unpack_from("<I", data, cen_off(data, 1) + 42)[0]
        struct.pack_into("<I", bad, b_loc + 18, 10)
        struct.pack_into("<I", bad, cen_off(data, 1) + 20, 10)
        self.refused(bytes(bad), "b runs into the central directory")


if __name__ == "__main__":
    unittest.main()
