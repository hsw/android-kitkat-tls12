# SPDX-License-Identifier: Apache-2.0
"""kktlsfmt.py: formats and constants shared by the series tools check_artifacts.py, emu_layer_d.py and
check_tls_lists.py: the layer-A lists (A6, A7, the SSL_MODE bits), the layer-D file names, newc cpio, ramdisk images,
the BOOTCLASSPATH line of init.environ.rc, ELF DT_NEEDED and a file's sha256.

Stdlib only. The scripts run as `python3 -I`, which leaves the script directory off sys.path, so they import this
module after `sys.path.insert(0, <their own directory>)`. conscrypt/{apicheck,check_*}.py do not use
this module (they run from the device module directory on the build host without this tools/ folder); they share
dexparse.py from their own directory.
"""
import hashlib
import struct
import zlib

# ---- layer A: one definition, checked twice -- against the patched sources by check_tls_lists.py and against the
# built dex by check_artifacts.py.
# A6: the kktls default cipher suite list, in this order.
A6_DEFAULT_SUITES = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
]
# A7: the client's default protocols.
A7_CLIENT_PROTOCOLS = ["TLSv1", "TLSv1.1", "TLSv1.2"]
# The SSL_MODE bits of our OpenSSL 1.0.1u (Task 7c/7d, README §5.7): upstream SCSV is 0x80 (1.0.1j) and the Android
# cut-through patch uses 0x200, as Android 5.1 (libcore port of conscrypt 9ca6641). The KitKat/cm-11 1.0.1e numbering
# (SCSV 0x200, cut-through 0x20) is wrong on 1.0.1u: 0x20 is SSL_MODE_SEND_CLIENTHELLO_TIME and 0x200 is cut-through.
# Mixing the two numberings fails silently, so the values themselves are pinned here.
SSL_MODES = [("SSL_MODE_SEND_FALLBACK_SCSV", 0x80), ("SSL_MODE_HANDSHAKE_CUTTHROUGH", 0x200)]
SSL_MODES_NOTE = "OpenSSL 1.0.1u numbering, as Android 5.1; KitKat/cm-11 1.0.1e had SCSV 0x200, cut-through 0x20"

# ---- layer D

# Layer D has no boot jar: the default factory (io.github.hsw.kktls.KktlsDefaultSSLSocketFactory) is part of libcore
# (core.jar / core-libart.jar, libcore/0025) and loads Conscrypt (kktls-conscrypt.jar, installed in
# /system/framework, NOT a boot jar since review 2026-10-09) with its own PathClassLoader when that jar exists.
# OLD_BOOT_JAR: the factory's own boot jar before plan 20261015-android-kitkat-tls12-publish Task 4 (15-jar layout);
# a system copy that still has it is stale.
OLD_BOOT_JAR = "/system/framework/kktls-sslfactory.jar"
CONSCRYPT_JAR = "/system/framework/kktls-conscrypt.jar"
# The SSLv3-filtering wrapper socket (org.conscrypt.KktlsFilteringSSLSocket) for Conscrypt 2.6-alpha2; like
# kktls-conscrypt.jar it is installed in /system/framework but NOT a boot jar (same PathClassLoader).
FILTER_JAR = "/system/framework/kktls-sslfilter.jar"
# Its JNI library (review 1b): installed as lib/libkktls_conscrypt_jni.so (rename_jni.py rewrote the aar's
# System.loadLibrary("conscrypt_jni")); lib/libconscrypt_jni.so must not exist, the 4.4 linker dedups by basename and
# that is the name an app that bundles Conscrypt loads.
CONSCRYPT_SO = "lib/libkktls_conscrypt_jni.so"
AAR_CONSCRYPT_SO = "lib/libconscrypt_jni.so"


def tail_problem(rest, what):
    """'' when the bytes after WHAT are only zero padding, else why they are not (the kernel would unpack them)."""
    data = rest.lstrip(b"\0")
    if not data:
        return ""
    at = "%d byte(s) after %s (%d zero byte(s) of padding first)" % (len(rest), what, len(rest) - len(data))
    if data[:6] in (b"070701", b"070702"):
        return "a second cpio archive in %s: the kernel unpacks it over the first one" % at
    if data[:2] == b"\x1f\x8b":
        return "a second gzip member in %s: the kernel unpacks it over the first one" % at
    return "%s that are not zero padding: the kernel unpacks them or stops on them" % at


def cpio_parse(data):
    """[(fields[13], name, payload)] of an uncompressed newc cpio, TRAILER!!! included (raises RuntimeError).
    Only zero padding may follow TRAILER!!! (review 3, codex 6): the kernel's initramfs unpacker (init/initramfs.c,
    3.0) skips zeros after a trailer and then unpacks whatever archive comes next over the first one, so an appended
    archive (an init.rc override) must not be ignored."""
    out, off = [], 0
    while True:
        if data[off:off + 6] not in (b"070701", b"070702"):
            raise RuntimeError("no newc cpio header at offset %d" % off)
        if off + 110 > len(data):
            raise RuntimeError("truncated cpio header at offset %d" % off)
        f = [int(data[off + 6 + 8 * i:off + 14 + 8 * i], 16) for i in range(13)]
        name = data[off + 110:off + 110 + f[11] - 1].decode("utf-8", "replace")
        off = (off + 110 + f[11] + 3) & ~3
        payload = data[off:off + f[6]]
        if len(payload) != f[6]:
            raise RuntimeError("truncated cpio member %s" % name)
        out.append((f, name, payload))
        off = (off + f[6] + 3) & ~3
        if name == "TRAILER!!!":
            why = tail_problem(data[off:], "TRAILER!!!")
            if why:
                raise RuntimeError(why)
            return out


def cpio_write(members):
    """An uncompressed newc cpio of [(fields[13], name, payload)] (sizes recomputed)."""
    out = b""
    for f, name, payload in members:
        f = list(f)
        f[6] = len(payload)
        nm = name.encode() + b"\0"
        f[11] = len(nm)
        out += b"070701" + b"".join(b"%08X" % v for v in f) + nm
        out += b"\0" * (-len(out) % 4) + payload
        out += b"\0" * (-len(out) % 4)
    return out


def gunzip_one(raw):
    """The data of the single gzip member RAW holds; only zero padding may follow it (RuntimeError otherwise, or on a
    cut or corrupt stream). Not gzip.decompress: it joins every member (and skips the zeros between them), and the
    kernel unpacks each member's archive in turn, so a second member must fail here rather than be merged silently."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(raw) + d.flush()
    if not d.eof:
        raise RuntimeError("truncated gzip stream (no end of the first member)")
    why = tail_problem(d.unused_data, "the first gzip member")
    if why:
        raise RuntimeError(why)
    return out


def ramdisk_cpio(path):
    """cpio_parse() of a ramdisk image, gzip-compressed or plain newc cpio (raises RuntimeError naming the file).
    One gzip member and one cpio archive, each followed by zero padding only (gunzip_one, cpio_parse)."""
    with open(path, "rb") as f:
        raw = f.read()
    try:
        return cpio_parse(gunzip_one(raw) if raw[:2] == b"\x1f\x8b" else raw)
    except (RuntimeError, zlib.error) as e:  # zlib.error: a corrupt stream, a bad CRC or length
        raise RuntimeError("%s: %s" % (path, e))


# newc header fields (cpio_parse's fields[13]) that ramdisk_members keeps: what init sees of a member besides its bytes.
# c_ino, c_mtime, c_devmajor/c_devminor (the packing host's file system) and c_check are per-pack noise; c_nlink is left
# out too (mkbootfs and pack-ramdisk.py write no hard links: always 1), c_filesize/c_namesize are the payload and name.
CPIO_META = (("mode", 1), ("uid", 2), ("gid", 3), ("rdevmajor", 9), ("rdevminor", 10))


def ramdisk_members(path):
    """{name: (meta, payload)} of a ramdisk image (ramdisk_cpio), TRAILER!!! excluded. meta = the CPIO_META fields
    (mode, uid, gid, rdevmajor, rdevminor) as a tuple, so comparing two members compares ownership, permissions, file
    type and device numbers as well as the content (review 3, codex 3: uid/gid/rdev changes used to pass)."""
    return {name: (tuple(f[i] for _, i in CPIO_META), payload) for f, name, payload in ramdisk_cpio(path)
            if name != "TRAILER!!!"}


def meta_diff(a, b):
    """'uid 0 -> 1000, mode 0o100644 -> 0o100755' for two ramdisk_members metas ('' when equal)."""
    out = []
    for (k, _), x, y in zip(CPIO_META, a, b):
        if x != y:
            out.append("%s %s -> %s" % (k, oct(x) if k == "mode" else x, oct(y) if k == "mode" else y))
    return ", ".join(out)


def environ_bcp(text):
    """(line, [entries]) of the single 'export BOOTCLASSPATH <list>' line of an init.environ.rc text."""
    found = [ln for ln in text.splitlines() if ln.split()[:2] == ["export", "BOOTCLASSPATH"]]
    if len(found) != 1:
        raise RuntimeError("%d 'export BOOTCLASSPATH' lines, want 1" % len(found))
    words = found[0].split()
    if len(words) != 3:
        raise RuntimeError("BOOTCLASSPATH line has %d words, want 3 (a space in the list?)" % len(words))
    return found[0], words[2].split(":")


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ---- ELF DT_NEEDED (32-bit little-endian, parsed directly: no readelf on the Mac)
EM_ARM = 40
PT_LOAD, PT_DYNAMIC = 1, 2
DT_NULL, DT_NEEDED, DT_STRTAB = 0, 1, 5
ELF32_EHDR = "<16sHHIIIIIHHHHHH"  # e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize,
#                                   e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
ELF32_PHDR = "<IIIIIIII"  # p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
ELF32_DYN = "<iI"  # d_tag, d_val


def elf_needed(path):
    """(e_machine, [DT_NEEDED names]) of a 32-bit little-endian ELF. A malformed or truncated file raises RuntimeError
    (never struct.error/IndexError), so a check reports it as a FAIL."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        return _elf_needed(path, data)
    except (struct.error, IndexError, ValueError, UnicodeDecodeError) as e:
        raise RuntimeError("%s: malformed or truncated ELF (%s: %s)" % (path, type(e).__name__, e))


def _elf_needed(path, data):
    if len(data) < struct.calcsize(ELF32_EHDR) or data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise RuntimeError("%s is not a 32-bit little-endian ELF" % path)
    ehdr = struct.unpack_from(ELF32_EHDR, data, 0)
    e_machine, e_phoff, e_phentsize, e_phnum = ehdr[2], ehdr[5], ehdr[9], ehdr[10]
    loads, dyn = [], None
    for i in range(e_phnum):
        p_type, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(ELF32_PHDR, data, e_phoff + i * e_phentsize)[:5]
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == PT_DYNAMIC:
            dyn = (p_offset, p_filesz)
    if dyn is None:
        raise RuntimeError("%s has no PT_DYNAMIC" % path)

    def v2o(v):
        for va, off, sz in loads:
            if va <= v < va + sz:
                return off + v - va
        raise RuntimeError("address 0x%x not in a PT_LOAD of %s" % (v, path))

    needed, strtab = [], None
    step = struct.calcsize(ELF32_DYN)
    for j in range(0, dyn[1], step):
        tag, val = struct.unpack_from(ELF32_DYN, data, dyn[0] + j)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            needed.append(val)
        elif tag == DT_STRTAB:
            strtab = v2o(val)
    if needed and strtab is None:
        raise RuntimeError("%s has DT_NEEDED entries but no DT_STRTAB" % path)
    return e_machine, [data[strtab + n:data.index(b"\0", strtab + n)].decode() for n in needed]
