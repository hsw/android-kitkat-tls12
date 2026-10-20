#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""nativescan.py: the native consumers of libssl.so/libcrypto.so in a copy of /system (ELF32 DT_NEEDED, stdlib only).

    nativescan.py --list DIR...                 the consumers of every DIR (a /system copy), one name per line, sorted
                                                (generates aosp44-ssl-consumers.txt from stock AOSP 4.4 images)
    nativescan.py --scan DIR [--aosp FILE]      the report kktls-jarpatch.py writes for an OEM/CM system

Scanned: every file under DIR/{lib,bin,xbin,vendor}, every *.so under DIR/{app,priv-app} (symbolic links are skipped:
their target is scanned where it lies inside the tree), and the lib/<abi>/*.so entries of each
DIR/{app,priv-app}/*.apk (named app/<name>.apk!lib/<abi>/<x>.so). A consumer is an ELF32 file whose dynamic section (found through the program
headers, so section-stripped vendor blobs are read too) names libssl.so or libcrypto.so in a DT_NEEDED entry. Files
that are not ELF, ELF64 or big-endian files, and ELF32 files without PT_DYNAMIC (static) are no consumers; an ELF32
file that cannot be read to its end (truncated, offsets outside the file, a strtab outside every PT_LOAD) is listed as
unreadable, and so is a directory that cannot be listed (as `<dir>/: not listable: <why>`, not counted as a file).
Names are paths relative to /system.

A name is "aosp" when the AOSP 4.4 list (aosp44-ssl-consumers.txt) has it, else "extra": code the vendor built, maybe
against its own OpenSSL headers. The test is by name only: a vendor may also have rebuilt a file that keeps an AOSP
name, so the report lists every consumer.
"""
import os
import struct
import sys
import zipfile

SSL_LIBS = ("libcrypto.so", "libssl.so")
TREES = ("lib", "bin", "xbin", "vendor", "app", "priv-app")
APK_DIRS = ("app", "priv-app")
PT_LOAD, PT_DYNAMIC = 1, 2
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ = 0, 1, 5, 10
HERE = os.path.dirname(os.path.abspath(__file__))
AOSP_LIST = os.path.join(HERE, "aosp44-ssl-consumers.txt")


class ElfError(Exception):
    pass


def needed(data):
    """DT_NEEDED names of an ELF32 little-endian file ([] when it has no PT_DYNAMIC); None when data is not such a
    file (not ELF, ELF64, big-endian); ElfError when it cannot be read."""
    if data[:4] != b"\x7fELF":
        return None
    if len(data) < 52:
        raise ElfError("truncated ELF header")
    if data[4] != 1 or data[5] != 1:     # EI_CLASS ELFCLASS32, EI_DATA ELFDATA2LSB
        return None
    phoff, = struct.unpack_from("<I", data, 28)
    phentsize, phnum = struct.unpack_from("<HH", data, 42)
    if phnum and phentsize != 32:
        raise ElfError("program header size %d" % phentsize)
    if phoff + phnum * 32 > len(data):
        raise ElfError("program headers beyond the end of the file")
    loads, dyn = [], None
    for i in range(phnum):
        p_type, p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<5I", data, phoff + i * 32)
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == PT_DYNAMIC and dyn is None:
            dyn = (p_offset, p_filesz)
    if dyn is None:
        return []
    off, size = dyn
    if off + size > len(data):
        raise ElfError("dynamic section beyond the end of the file")
    names, strtab, strsz = [], None, None
    for e in range(off, off + size - 7, 8):
        tag, val = struct.unpack_from("<iI", data, e)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            names.append(val)
        elif tag == DT_STRTAB:
            strtab = val
        elif tag == DT_STRSZ:
            strsz = val
    else:
        raise ElfError("dynamic section without DT_NULL")
    if not names:
        return []
    if strtab is None:
        raise ElfError("DT_NEEDED without DT_STRTAB")
    base = None
    for v, o, fs in loads:
        if v <= strtab < v + fs:
            base = o + strtab - v
            break
    if base is None:
        raise ElfError("DT_STRTAB outside every PT_LOAD")
    end = len(data) if strsz is None else min(len(data), base + strsz)
    res = []
    for n in names:
        s = base + n
        z = data.find(b"\0", s, end)
        if s >= end or z < 0:
            raise ElfError("DT_NEEDED name beyond the string table")
        res.append(data[s:z].decode("utf-8", "replace"))
    return res


def files(root):
    """(name, bytes or ElfError) of every file the scan reads under root (a /system copy), sorted by name, and
    (`<dir>/`, ElfError) of each directory os.walk cannot list; each apk is opened once."""
    items = []          # (name, path, apk member or None, error or None)

    def unlistable(e):
        rel = os.path.relpath(e.filename, root).replace(os.sep, "/") + "/"
        items.append((rel, e.filename, None, ElfError("not listable: %s" % (e.strerror or e))))

    for t in TREES:
        top = os.path.join(root, t)
        if not os.path.isdir(top) or os.path.islink(top):
            continue
        for d, dirs, fs in os.walk(top, onerror=unlistable):
            dirs.sort()
            for f in fs:
                p = os.path.join(d, f)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                rel = os.path.relpath(p, root).replace(os.sep, "/")
                if t in APK_DIRS:
                    if f.endswith(".apk") and d == top:
                        try:
                            with zipfile.ZipFile(p) as z:
                                items += [("%s!%s" % (rel, n), p, n, None) for n in z.namelist()
                                          if n.startswith("lib/") and n.endswith(".so")]
                        except (OSError, zipfile.BadZipFile) as e:
                            items.append((rel, p, None, ElfError("not a readable zip: %s" % e)))
                    if not f.endswith(".so"):
                        continue
                items.append((rel, p, None, None))
    items.sort(key=lambda x: x[0])
    z = None
    try:
        for name, p, member, err in items:
            if err is None:
                try:
                    if member is None:
                        with open(p, "rb") as f:
                            data = f.read()
                    else:
                        if z is None or z.filename != p:
                            if z is not None:
                                z.close()
                            z = None
                            z = zipfile.ZipFile(p)
                        data = z.read(member)
                except (OSError, zipfile.BadZipFile, KeyError) as e:
                    err = ElfError(str(e))
            yield name, err if err is not None else data
    finally:
        if z is not None:
            z.close()


def scan(root):
    """{"files": n, "elf": n, "consumers": [(name, [ssl libs])], "unreadable": [(name, why)]}"""
    res = {"files": 0, "elf": 0, "consumers": [], "unreadable": []}
    for name, data in files(root):
        res["files"] += not name.endswith("/")
        try:
            if isinstance(data, ElfError):
                raise data
            n = needed(data)
        except ElfError as e:
            res["unreadable"].append((name, str(e)))
            continue
        if n is None:
            continue
        res["elf"] += 1
        libs = sorted(set(n) & set(SSL_LIBS))
        if libs:
            res["consumers"].append((name, libs))
    return res


def read_list(path=AOSP_LIST):
    with open(path, encoding="utf-8") as f:
        return {l.strip() for l in f if l.strip() and not l.startswith("#")}


def report(res, aosp):
    """Report lines: a summary, then extra, aosp and unreadable lines."""
    extra = [c for c in res["consumers"] if c[0] not in aosp]
    known = [c for c in res["consumers"] if c[0] in aosp]
    out = ["scanned %d file(s), %d ELF32, %d consumer(s) of %s: %d extra, %d aosp; %d unreadable" % (
        res["files"], res["elf"], len(res["consumers"]), "/".join(SSL_LIBS), len(extra), len(known),
        len(res["unreadable"]))]
    out += ["extra %s %s" % (n, " ".join(l)) for n, l in extra]
    out += ["aosp %s %s" % (n, " ".join(l)) for n, l in known]
    out += ["unreadable %s: %s" % u for u in res["unreadable"]]
    return out, len(extra)


def main(argv):
    usage = "usage: nativescan.py --list DIR... | --scan DIR [--aosp FILE]"
    if len(argv) >= 2 and argv[0] == "--list":
        names = set()
        for d in argv[1:]:
            r = scan(d)
            if r["unreadable"]:
                for u in r["unreadable"]:
                    print("nativescan: %s: unreadable %s: %s" % ((d,) + u), file=sys.stderr)
                return 1
            names |= {n for n, _ in r["consumers"]}
        sys.stdout.write("".join(n + "\n" for n in sorted(names)))
        return 0
    if len(argv) in (2, 4) and argv[0] == "--scan" and (len(argv) == 2 or argv[2] == "--aosp"):
        lines, _ = report(scan(argv[1]), read_list(argv[3] if len(argv) == 4 else AOSP_LIST))
        sys.stdout.write("".join(l + "\n" for l in lines))
        return 0
    print(usage, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
