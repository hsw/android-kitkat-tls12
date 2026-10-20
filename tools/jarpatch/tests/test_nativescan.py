# SPDX-License-Identifier: Apache-2.0
"""Unit tests of nativescan.py on ELF32 fixtures written here (ARM and x86 consumers, no dynamic section, ELF64,
truncated files, a strtab outside every PT_LOAD), a fake /system tree (symbolic links, an apk with lib/ entries, an
unreadable file) and the shipped AOSP 4.4 list.

    python3 -I -m unittest discover tools/jarpatch/tests
"""
import io
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import nativescan  # noqa: E402

EM_386, EM_ARM = 3, 40
VBASE = 0x8000      # PT_LOAD vaddr of offset 0: DT_STRTAB is a vaddr, the reader must map it


def elf(needed=(), machine=EM_ARM, dynamic=True, strtab_in_load=True):
    """A minimal ELF32 LE ET_DYN: header, PT_LOAD (whole file), PT_DYNAMIC, .dynstr, .dynamic; no section headers."""
    names = [n.encode() for n in needed]
    strtab = b"\0" + b"".join(n + b"\0" for n in names)
    offs, o = [], 1
    for n in names:
        offs.append(o)
        o += len(n) + 1
    phnum = 2 if dynamic else 1
    str_off = 52 + 32 * phnum
    dyn_off = (str_off + len(strtab) + 3) & ~3
    dyn = b"".join(struct.pack("<iI", 1, x) for x in offs)
    dyn += struct.pack("<iIiIiI", 5, (VBASE if strtab_in_load else 0x100000) + str_off, 10, len(strtab), 0, 0)
    size = dyn_off + (len(dyn) if dynamic else 0)
    ident = b"\x7fELF" + bytes([1, 1, 1]) + b"\0" * 9
    head = ident + struct.pack("<HHIIIIIHHHHHH", 3, machine, 1, 0, 52, 0, 0, 52, 32, phnum, 40, 0, 0)
    ph = struct.pack("<8I", 1, 0, VBASE, VBASE, size, size, 5, 0x1000)
    if dynamic:
        ph += struct.pack("<8I", 2, dyn_off, VBASE + dyn_off, VBASE + dyn_off, len(dyn), len(dyn), 6, 4)
    data = head + ph + strtab
    data += b"\0" * (dyn_off - len(data))
    return data + (dyn if dynamic else b"")


def write(root, rel, data):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    return p


class Needed(unittest.TestCase):
    def test_arm_and_x86(self):
        self.assertEqual(nativescan.needed(elf(["libc.so", "libssl.so"])), ["libc.so", "libssl.so"])
        self.assertEqual(nativescan.needed(elf(["libcrypto.so"], machine=EM_386)), ["libcrypto.so"])

    def test_not_a_consumer_or_not_scanned(self):
        self.assertEqual(nativescan.needed(elf(dynamic=False)), [])         # static: no PT_DYNAMIC
        self.assertEqual(nativescan.needed(elf()), [])                      # dynamic, no DT_NEEDED
        e64 = bytearray(elf(["libssl.so"]))
        e64[4] = 2
        self.assertIsNone(nativescan.needed(bytes(e64)))                    # ELF64
        self.assertIsNone(nativescan.needed(b"dey\n036\0" + b"\0" * 64))    # an odex, not ELF

    def test_truncated_and_malformed(self):
        e = elf(["libssl.so"])
        for cut in (20, 60, len(e) - 4):        # inside the header, the program headers, the dynamic section
            with self.assertRaises(nativescan.ElfError):
                nativescan.needed(e[:cut])
        with self.assertRaisesRegex(nativescan.ElfError, "outside every PT_LOAD"):
            nativescan.needed(elf(["libssl.so"], strtab_in_load=False))


class Scan(unittest.TestCase):
    def test_tree_report_and_list(self):
        with tempfile.TemporaryDirectory() as t:
            write(t, "lib/libssl.so", elf(["libcrypto.so", "libc.so"]))
            write(t, "bin/keystore", elf(["libcrypto.so"], machine=EM_386))
            write(t, "bin/oemd", elf(["libssl.so"]))
            write(t, "vendor/lib/libv.so", elf(["libcrypto.so"]))
            write(t, "xbin/static", elf(dynamic=False))
            write(t, "bin/sh", b"#!/system/bin/sh\n")
            write(t, "app/Old.odex", elf(["libssl.so"]))            # not a .so under app/: not read
            os.symlink("oemd", os.path.join(t, "bin", "oemd-link"))
            with zipfile.ZipFile(os.path.join(t, "app", "Vpn.apk"), "w") as z:
                z.writestr("classes.dex", b"dex\n035\0")
                z.writestr("lib/armeabi-v7a/libvpn.so", elf(["libssl.so"]))
            write(t, "priv-app/Bad.apk", b"not a zip")
            res = nativescan.scan(t)
            self.assertEqual(res["consumers"], [
                ("app/Vpn.apk!lib/armeabi-v7a/libvpn.so", ["libssl.so"]), ("bin/keystore", ["libcrypto.so"]),
                ("bin/oemd", ["libssl.so"]), ("lib/libssl.so", ["libcrypto.so"]),
                ("vendor/lib/libv.so", ["libcrypto.so"])])
            self.assertEqual([u[0] for u in res["unreadable"]], ["priv-app/Bad.apk"])
            lines, extra = nativescan.report(res, nativescan.read_list())
            self.assertEqual(extra, 3)
            self.assertIn("extra bin/oemd libssl.so", lines)
            self.assertIn("aosp bin/keystore libcrypto.so", lines)
            self.assertTrue(lines[0].startswith("scanned 8 file(s), 6 ELF32, 5 consumer(s)"), lines[0])
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
                self.assertEqual(nativescan.main(["--list", t]), 1)          # unreadable files: no list
            self.assertIn("priv-app/Bad.apk", err.getvalue())
            os.remove(os.path.join(t, "priv-app", "Bad.apk"))
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(nativescan.main(["--list", t]), 0)
            self.assertEqual(out.getvalue().split(), [c[0] for c in res["consumers"]])

    @unittest.skipIf(os.geteuid() == 0, "root lists any directory")
    def test_unlistable_directory(self):
        # a directory os.walk cannot list is reported, never dropped from the scan (not counted as a file)
        with tempfile.TemporaryDirectory() as t:
            write(t, "lib/libssl.so", elf(["libcrypto.so"]))
            write(t, "vendor/secret/libv.so", elf(["libssl.so"]))
            os.chmod(os.path.join(t, "vendor", "secret"), 0)
            try:
                res = nativescan.scan(t)
            finally:
                os.chmod(os.path.join(t, "vendor", "secret"), 0o755)
            self.assertEqual(res["consumers"], [("lib/libssl.so", ["libcrypto.so"])])
            self.assertEqual(res["unreadable"], [("vendor/secret/", "not listable: Permission denied")])
            lines, _ = nativescan.report(res, set())
            self.assertTrue(lines[0].startswith("scanned 1 file(s), 1 ELF32") and lines[0].endswith("; 1 unreadable"),
                            lines[0])
            self.assertIn("unreadable vendor/secret/: not listable: Permission denied", lines)

    def test_aosp_list(self):
        names = nativescan.read_list()
        self.assertIn("lib/libssl.so", names)
        self.assertIn("lib/libjavacrypto.so", names)
        self.assertTrue(all(not n.startswith("/") and " " not in n for n in names))


if __name__ == "__main__":
    unittest.main()
