#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""check_artifacts.py: static validation of the BUILT layer-A artefacts and, with --layer d, of
the layer-D system files (Task 11; system-only since plan 20261015-android-kitkat-tls12-publish Task 4).

check_tls_lists.py checks the patched sources; this checks what the build produced, from the dex code and the ELF
bytes, so a stale or wrong module in /system is caught before an image goes to a device or the emulator.

    python3 -I check_artifacts.py DIR [--dexdump PATH] --old-ramdisk IMG --ramdisk IMG
    python3 -I check_artifacts.py DIR --layer d --old-ramdisk IMG --ramdisk IMG --product-environ FILE \
        [--boot-img IMG] [--sums SHA256SUMS]
    python3 -I check_artifacts.py DIR --layer release --abi armeabi-v7a|x86 [--sums SHA256SUMS]
    python3 -I check_artifacts.py --selftest [--d8 PATH --javac PATH]

DIR holds framework/{conscrypt,okhttp}.jar and lib/{libssl,libjavacrypto}.so (a copy of out/.../system, or the
artefact folder of the series README). dexdump comes from --dexdump, $DEXDUMP or Android build-tools 37.0.0 ($ANDROID_HOME, ~/Android/sdk, Homebrew).

Checks:
  a6-default-suites   NativeCrypto.getDefaultCipherSuites() builds exactly the A6 list, in order (const-string order)
  a7-protocols        NativeCrypto.getDefaultProtocols() builds exactly TLSv1, TLSv1.1, TLSv1.2
  scsv-constant       NativeCrypto.SSL_MODE_SEND_FALLBACK_SCSV = 128 (0x80, OpenSSL 1.0.1u) and
                      SSL_MODE_HANDSHAKE_CUTTHROUGH = 512 (0x200); the string TLS_FALLBACK_SCSV is in conscrypt
  okhttp-no-sslv3     no const-string "SSLv3" anywhere in okhttp.jar; "TLS_FALLBACK_SCSV" and "TLSv1" are there (A11)
  libssl-fallback     libssl.so carries the inappropriate-fallback alert/reason strings and is OpenSSL 1.0.1u
  libjavacrypto       libjavacrypto.so is an ARM ELF with NEEDED libssl.so and libcrypto.so (the symbol-level link
                      check is openssl-abi-check.py users)
  ramdisk-unchanged   layer A is system-only: --old-ramdisk (the image before the series) and --ramdisk (the new one)
                      have the same sha256. Without both files the check FAILS ("not checked"), it is never omitted

--layer d (layer D is system-only too: the default factory is in libcore's core.jar, and kktls-conscrypt.jar,
kktls-sslfilter.jar and libkktls_conscrypt_jni.so are plain /system files, none a boot jar). The seven layer-A checks
above run as well (ramdisk-unchanged included: --old-ramdisk = the image before layer D), plus:
  ramdisk-bootclasspath  BOOTCLASSPATH of the new ramdisk's init.environ.rc = that of --product-environ (the build's
                         generated obj/ETC/init.environ.rc_intermediates/init.environ.rc, i.e. PRODUCT_BOOT_JARS as make
                         resolved it), and no kktls-* jar is on it: neither kktls-conscrypt.jar (review 2026-10-09: an
                         app's own Conscrypt would be shadowed) nor the old kktls-sslfactory.jar (the 15-jar layout)
  bootimg-ramdisk        only with --boot-img: the ramdisk inside it (ANDROID! header) is byte-identical to --ramdisk
  bootjars-present       every BOOTCLASSPATH jar of the new ramdisk is in DIR/framework (a missing one stops every Java
                         process), DIR/framework/kktls-sslfactory.jar does NOT exist (stale out/ from the 15-jar layout),
                         DIR/framework/{kktls-conscrypt,kktls-sslfilter}.jar are installed, DIR/lib/libkktls_conscrypt_jni.so
                         is an ARM ELF that needs only libc/libdl/libm/liblog, and DIR/lib/libconscrypt_jni.so does NOT
                         exist (the 4.4 linker dedups by basename, an app's own Conscrypt uses that name)
  conscrypt-pin          DIR/framework/kktls-conscrypt.jar and DIR/lib/libkktls_conscrypt_jni.so are byte-identical to the
                         Conscrypt 2.6-alpha2 stage pinned in --sums (default conscrypt/SHA256SUMS of
                         this checkout, lines 2.6-alpha2/kktls-conscrypt.dex.jar and 2.6-alpha2/libkktls_conscrypt_jni.so;
                         the module installs the d8 dex jar as is, so a
                         2.5.3 image, a dx-built jar or a stale intermediate fails here)
--layer release (the generic release files of tools/kktls-release-build.sh, WORK/out/kktls/<tag>/<abi>/): the six
layer-A checks above (libjavacrypto with the e_machine of --abi), plus:
  release-files          DIR holds exactly the ten release files (lib/{libssl,libcrypto,libjavacrypto,
                         libkktls_conscrypt_jni}.so, framework/{core,core-libart,conscrypt,okhttp,kktls-conscrypt,
                         kktls-sslfilter}.jar) besides SHA256SUMS and BUILD-INFO.txt: a missing one fails, and so does any
                         other file (lib/libconscrypt_jni.so, kktls-sslfactory.jar, an .odex, ...)
  release-elf            every .so is ELF32 LE with the e_machine of --abi (ARM 40, x86 3); libkktls_conscrypt_jni.so
                         NEEDs only libc/libdl/libm/liblog
  release-dex            every jar holds classes.dex with dex magic 035 (the release replaces jars on devices whose
                         other .odex files are then re-dexopted; an odexed jar without classes.dex would not boot)
  conscrypt-pin          kktls-conscrypt.jar and the .so = the 2.6-alpha2 stage pins of --sums for --abi (x86:
                         2.6-alpha2/x86/libkktls_conscrypt_jni.so)
The release is system files only: no ramdisk or boot image belongs to it, so none is checked (not "passed"); the
release zips never touch the ramdisk.
This script owns the image facts (ramdisk, boot.img, jar presence in the system copy); the product-out facts of a
device build (BOOTCLASSPATH of root/ and of the generated file against core_base.mk, the provider property, the
wrapper in core.jar and the Conscrypt dex, the pinned .so) belong to the device tree's own checks.
"""
import argparse
import gzip
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python3 -I leaves the script directory off sys.path
# A6/A7/SSL_MODES: the same definition check_tls_lists.py checks against the patched sources
from kktlsfmt import (A6_DEFAULT_SUITES as A6, A7_CLIENT_PROTOCOLS as A7, AAR_CONSCRYPT_SO, CONSCRYPT_JAR,  # noqa: E402
                    CONSCRYPT_SO, DT_NEEDED, DT_NULL, DT_STRTAB, ELF32_DYN, ELF32_EHDR, ELF32_PHDR, EM_ARM,
                    FILTER_JAR, OLD_BOOT_JAR, PT_DYNAMIC, PT_LOAD, SSL_MODES, cpio_write, elf_needed, environ_bcp,
                    ramdisk_members, sha256_file)

NATIVE = "com.android.org.conscrypt.NativeCrypto"
CONSCRYPT_JNI_NEEDED = {"libc.so", "libdl.so", "libm.so", "liblog.so"}
BUILD_TOOLS = next((os.path.join(h, "build-tools", "37.0.0") for h in
                    (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
                     os.path.expanduser("~/Android/sdk"), "/opt/homebrew/share/android-commandlinetools")
                    if h and os.path.isdir(os.path.join(h, "build-tools", "37.0.0"))),
                   "/opt/homebrew/share/android-commandlinetools/build-tools/37.0.0")
# the layer-D artefact pins: stage file -> installed path. SUMS_REL is relative to the repository top, the nearest
# ancestor of this directory that has it.
SUMS_REL = "conscrypt/SHA256SUMS"


def _find_sums():
    d = os.path.dirname(os.path.abspath(__file__))
    while True:
        cand = os.path.join(d, *SUMS_REL.split("/"))
        if os.path.isfile(cand) or os.path.dirname(d) == d:
            return cand
        d = os.path.dirname(d)


CONSCRYPT_SUMS = _find_sums()
CONSCRYPT_PINS = (("2.6-alpha2/kktls-conscrypt.dex.jar", "framework/" + os.path.basename(CONSCRYPT_JAR)),
                  ("2.6-alpha2/libkktls_conscrypt_jni.so", CONSCRYPT_SO))
EM_386 = 3
# --layer release: ABI -> (e_machine, the SHA256SUMS line of its stage .so)
RELEASE_ABIS = {"armeabi-v7a": (EM_ARM, "2.6-alpha2/libkktls_conscrypt_jni.so"),
                "x86": (EM_386, "2.6-alpha2/x86/libkktls_conscrypt_jni.so")}
RELEASE_FILES = ["lib/libssl.so", "lib/libcrypto.so", "lib/libjavacrypto.so", CONSCRYPT_SO,
                 "framework/core.jar", "framework/core-libart.jar", "framework/conscrypt.jar", "framework/okhttp.jar",
                 "framework/" + os.path.basename(CONSCRYPT_JAR), "framework/" + os.path.basename(FILTER_JAR)]
RELEASE_META = ("SHA256SUMS", "BUILD-INFO.txt")
MACHINE_NAMES = {EM_ARM: "ARM", EM_386: "x86"}


def find_dexdump(arg):
    for c in (arg, os.environ.get("DEXDUMP"), os.path.join(BUILD_TOOLS, "dexdump"), shutil.which("dexdump")):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    sys.exit("dexdump not found: pass --dexdump or set DEXDUMP")


def dexdump_jar(dexdump, jar):
    """dexdump -d of every classes*.dex in the jar, concatenated."""
    out = []
    with zipfile.ZipFile(jar) as z, tempfile.TemporaryDirectory() as td:
        names = sorted(n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n))
        if not names:
            raise RuntimeError("%s has no classes.dex (odexed jar?)" % jar)
        for n in names:
            p = z.extract(n, td)
            out.append(subprocess.run([dexdump, "-d", p], check=True, capture_output=True).stdout.decode("utf-8", "replace"))
    return "\n".join(out)


def method_strings(dump, cls, method):
    """const-string operands of cls.method, in code order; None if the method is absent."""
    head = re.compile(r"\|\[[0-9a-f]+\] " + re.escape(cls + "." + method) + r":")
    lines = dump.splitlines()
    for i, ln in enumerate(lines):
        if head.search(ln):
            res = []
            for ln2 in lines[i + 1:]:
                if "|[" in ln2 or not re.match(r"^[0-9a-f]+:", ln2):
                    break
                m = re.search(r'const-string(?:/jumbo)? v\d+, "(.*)" // string@', ln2)
                if m:
                    res.append(m.group(1))
            return res
    return None


def static_value(dump, cls_desc, field):
    m = re.search(r"\(in " + re.escape(cls_desc) + r"\)\s*\n\s*name\s*: '" + re.escape(field)
                  + r"'\s*\n\s*type\s*: '\w'\s*\n\s*access\s*: [^\n]*\n\s*value\s*: (-?\d+)", dump)
    return int(m.group(1)) if m else None


def all_const_strings(dump):
    return set(re.findall(r'const-string(?:/jumbo)? v\d+, "(.*)" // string@', dump))


def check(results, name, fn):
    """Append (name, msgs) of fn() to results. Any error while reading an input (missing file, a jar without classes.dex,
    dexdump failing, a malformed ELF or cpio, ...) is that check's FAIL with the reason, never a traceback."""
    try:
        msgs = fn()
    except Exception as e:  # noqa: BLE001 -- the reason is printed under the FAIL line
        msgs = ["%s: %s" % (type(e).__name__, e)]
    results.append((name, msgs))


def run_checks(d, dexdump, machine=EM_ARM):
    results = []
    dumps = {}

    def dump(jar):
        """dexdump of DIR/framework/<jar>, made once; a failure is kept and raised again for every check that needs it."""
        if jar not in dumps:
            try:
                dumps[jar] = (dexdump_jar(dexdump, os.path.join(d, "framework", jar)), None)
            except Exception as e:  # noqa: BLE001 -- re-raised below, reported by check()
                dumps[jar] = (None, e)
        text, err = dumps[jar]
        if err is not None:
            raise err
        return text

    def a6():
        got = method_strings(dump("conscrypt.jar"), NATIVE, "getDefaultCipherSuites")
        if got is None:
            return ["NativeCrypto.getDefaultCipherSuites not found in conscrypt.jar"]
        return [] if got == A6 else ["default suites %s, want the A6 list %s" % (got, A6)]

    def a7():
        got = method_strings(dump("conscrypt.jar"), NATIVE, "getDefaultProtocols")
        if got is None:
            return ["NativeCrypto.getDefaultProtocols not found"]
        return [] if got == A7 else ["default protocols %s, want %s" % (got, A7)]

    def scsv():
        cdump = dump("conscrypt.jar")
        msgs = []
        desc = "L" + NATIVE.replace(".", "/") + ";"
        for field, want in SSL_MODES:
            v = static_value(cdump, desc, field)
            if v != want:
                msgs.append("%s = %s, want 0x%x" % (field, "missing" if v is None else hex(v), want))
        if "TLS_FALLBACK_SCSV" not in all_const_strings(cdump):
            msgs.append("no TLS_FALLBACK_SCSV string in conscrypt.jar")
        return msgs

    def okhttp():
        s = all_const_strings(dump("okhttp.jar"))
        msgs = []
        if "SSLv3" in s:
            msgs.append('okhttp.jar has a const-string "SSLv3" (SSLv3 fallback)')
        for want in ("TLS_FALLBACK_SCSV", "TLSv1"):
            if want not in s:
                msgs.append('okhttp.jar has no const-string "%s" (A11 fallback)' % want)
        return msgs

    def libssl():
        with open(os.path.join(d, "lib", "libssl.so"), "rb") as f:
            ssl = f.read()
        return ["libssl.so lacks %r" % want.decode() for want in
                (b"inappropriate fallback", b"tlsv1 alert inappropriate fallback", b"OpenSSL 1.0.1u") if want not in ssl]

    def libjavacrypto():
        mach, needed = elf_needed(os.path.join(d, "lib", "libjavacrypto.so"))
        msgs = [] if mach == machine else ["libjavacrypto.so e_machine %d, want %d (%s)" % (mach, machine,
                                                                                        MACHINE_NAMES[machine])]
        return msgs + ["libjavacrypto.so has no NEEDED %s (NEEDED %s)" % (lib, needed)
                       for lib in ("libssl.so", "libcrypto.so") if lib not in needed]

    for name, fn in (("a6-default-suites", a6), ("a7-protocols", a7), ("scsv-constant", scsv),
                     ("okhttp-no-sslv3", okhttp), ("libssl-fallback", libssl), ("libjavacrypto", libjavacrypto)):
        check(results, name, fn)
    return results


def check_ramdisk_unchanged(old_ramdisk, ramdisk):
    """Layer A only: ('ramdisk-unchanged', msgs); FAIL when either image is missing (the check is never omitted)."""
    if not (old_ramdisk and ramdisk):
        return [("ramdisk-unchanged", ["not checked: pass --old-ramdisk (before the series) and --ramdisk (the new "
                                       "build); layer A must not change the ramdisk"])]
    try:
        old, new = sha256_file(old_ramdisk), sha256_file(ramdisk)
    except OSError as e:
        return [("ramdisk-unchanged", ["%s: %s" % (type(e).__name__, e)])]
    return [("ramdisk-unchanged", [] if old == new else
             ["ramdisk sha256 %s (%s) -> %s (%s): layer A must not change the ramdisk" % (old, old_ramdisk, new,
                                                                                         ramdisk)])]


# ---- layer D: BOOTCLASSPATH, boot.img and the system files -------------------------------------------------------------------------

def bootimg_ramdisk(path):
    """The ramdisk bytes of an ANDROID! boot image (mkbootimg v0 header). A second reader of that header next to
    the boot image packer's parser, kept on purpose: this needs only the kernel/ramdisk sizes and the page size."""
    with open(path, "rb") as f:
        img = f.read()
    if img[:8] != b"ANDROID!":
        raise RuntimeError("%s has no ANDROID! magic" % path)
    kernel_size, _, ramdisk_size, _, _, _, _, page_size = struct.unpack_from("<8I", img, 8)
    off = page_size * (1 + (kernel_size + page_size - 1) // page_size)
    return img[off:off + ramdisk_size]


def read_pins(sums):
    """{stage name: sha256} of the CONSCRYPT_PINS lines of a SHA256SUMS file ('<64 hex>  <name>'); a missing or
    malformed line raises ValueError (the conscrypt-pin check FAILs with it)."""
    pins = {}
    with open(sums, encoding="utf-8") as f:
        for line in f:
            w = line.split()
            if len(w) == 2 and re.fullmatch(r"[0-9a-fA-F]{64}", w[0]):
                pins[w[1]] = w[0].lower()
    missing = [n for n, _ in CONSCRYPT_PINS if n not in pins]
    if missing:
        raise ValueError("%s pins no %s (64 hex digits)" % (sums, ", ".join(missing)))
    return {n: pins[n] for n, _ in CONSCRYPT_PINS}


def run_checks_d(d, old_ramdisk, ramdisk, boot_img, product_environ, sums=CONSCRYPT_SUMS):
    """The layer-D checks after the layer-A ones: ramdisk-unchanged (as layer A), ramdisk-bootclasspath, bootimg-ramdisk
    (only when boot_img is given), bootjars-present, conscrypt-pin."""
    results = check_ramdisk_unchanged(old_ramdisk, ramdisk)

    def bcp_of(img):
        return environ_bcp(ramdisk_members(img)["init.environ.rc"][1].decode("utf-8"))[1]

    def bcp():
        new = bcp_of(ramdisk)
        with open(product_environ, encoding="utf-8") as f:
            prod = environ_bcp(f.read())[1]
        msgs = []
        if new != prod:
            msgs.append("ramdisk BOOTCLASSPATH (%d jars) != PRODUCT_BOOT_JARS of %s (%d jars): only ramdisk %s, only "
                        "product %s" % (len(new), product_environ, len(prod), sorted(set(new) - set(prod)) or "-",
                                        sorted(set(prod) - set(new)) or "-"))
        for j in new:
            if os.path.basename(j).startswith("kktls-"):
                msgs.append("%s is on BOOTCLASSPATH: layer D has no boot jar (%s)" % (
                    j, "the 15-jar layout before the factory moved into core.jar" if j == OLD_BOOT_JAR else
                    "Conscrypt is loaded only by the factory's own loader, or it shadows apps' own Conscrypt"))
        return msgs

    def bootimg():
        with open(ramdisk, "rb") as f:
            want = f.read()
        got = bootimg_ramdisk(boot_img)
        if got == want:
            return []
        return ["ramdisk in %s (%d B, sha256 %s) != %s (%d B, sha256 %s): stale boot.img"
                % (boot_img, len(got), hashlib.sha256(got).hexdigest(), ramdisk, len(want),
                   hashlib.sha256(want).hexdigest())]

    def present():
        new = bcp_of(ramdisk)
        msgs = ["BOOTCLASSPATH jar missing from %s/framework: %s" % (d, j) for j in new
                if not j.startswith("/system/framework/") or not os.path.isfile(os.path.join(d, "framework",
                                                                                              os.path.basename(j)))]
        if os.path.lexists(os.path.join(d, "framework", os.path.basename(OLD_BOOT_JAR))):
            msgs.append("%s exists in %s/framework: the factory is in core.jar now (stale out/? installclean)" % (
                os.path.basename(OLD_BOOT_JAR), d))
        for jar, module in ((CONSCRYPT_JAR, "kktls-conscrypt"), (FILTER_JAR, "kktls-sslfilter")):
            if not os.path.isfile(os.path.join(d, "framework", os.path.basename(jar))):
                msgs.append("%s is not installed in %s/framework (PRODUCT_PACKAGES %s)" % (
                    os.path.basename(jar), d, module))
        if os.path.lexists(os.path.join(d, AAR_CONSCRYPT_SO)):
            msgs.append("%s exists: that basename is the one an app's own Conscrypt loads (4.4 linker dedup); only %s"
                        " may be installed" % (AAR_CONSCRYPT_SO, CONSCRYPT_SO))
        so = os.path.join(d, CONSCRYPT_SO)
        if not os.path.isfile(so):
            msgs.append("%s is missing" % CONSCRYPT_SO)
        else:
            mach, needed = elf_needed(so)
            if mach != EM_ARM:
                msgs.append("%s e_machine %d, want %d (ARM)" % (CONSCRYPT_SO, mach, EM_ARM))
            if not set(needed) <= CONSCRYPT_JNI_NEEDED:
                msgs.append("%s NEEDED %s, want a subset of %s" % (CONSCRYPT_SO, needed, sorted(CONSCRYPT_JNI_NEEDED)))
        return msgs

    def pinned():
        pins = read_pins(sums)
        msgs = []
        for stage, rel in CONSCRYPT_PINS:
            p = os.path.join(d, rel)
            if not os.path.isfile(p):
                msgs.append("%s is missing" % rel)
                continue
            got = sha256_file(p)
            if got != pins[stage]:
                msgs.append("%s sha256 %s, want %s (%s in %s)" % (rel, got, pins[stage], stage, sums))
        return msgs

    checks = [("ramdisk-bootclasspath", bcp)] + ([("bootimg-ramdisk", bootimg)] if boot_img else []) + [
        ("bootjars-present", present), ("conscrypt-pin", pinned)]
    for name, fn in checks:
        check(results, name, fn)
    return results


def run_checks_release(d, abi, sums=CONSCRYPT_SUMS):
    """The --layer release checks after the layer-A ones: release-files, release-elf, release-dex, conscrypt-pin."""
    machine, so_pin = RELEASE_ABIS[abi]
    results = []

    def files():
        have = sorted(os.path.relpath(os.path.join(r, f), d) for r, _, fs in os.walk(d) for f in fs)
        msgs = ["%s is missing" % f for f in RELEASE_FILES if f not in have]
        msgs += ["%s is not a release file (%s)" % (f, "the aar's basename: an app's own Conscrypt loads it"
                                                    if f == AAR_CONSCRYPT_SO else "stale or foreign output")
                 for f in have if f not in RELEASE_FILES and f not in RELEASE_META]
        return msgs

    def elf():
        msgs = []
        for rel in RELEASE_FILES:
            if not rel.endswith(".so"):
                continue
            mach, needed = elf_needed(os.path.join(d, rel))
            if mach != machine:
                msgs.append("%s e_machine %d, want %d (%s)" % (rel, mach, machine, MACHINE_NAMES[machine]))
            if rel == CONSCRYPT_SO and not set(needed) <= CONSCRYPT_JNI_NEEDED:
                msgs.append("%s NEEDED %s, want a subset of %s" % (rel, needed, sorted(CONSCRYPT_JNI_NEEDED)))
        return msgs

    def dex():
        msgs = []
        for rel in RELEASE_FILES:
            if not rel.endswith(".jar"):
                continue
            with zipfile.ZipFile(os.path.join(d, rel)) as z:
                if "classes.dex" not in z.namelist():
                    msgs.append("%s has no classes.dex (odexed?)" % rel)
                elif z.read("classes.dex")[:8] != b"dex\n035\0":
                    msgs.append("%s classes.dex magic %r, want dex 035" % (rel, z.read("classes.dex")[:8]))
        return msgs

    def pinned():
        pins = {}
        with open(sums, encoding="utf-8") as f:
            for line in f:
                w = line.split()
                if len(w) == 2 and re.fullmatch(r"[0-9a-fA-F]{64}", w[0]):
                    pins[w[1]] = w[0].lower()
        msgs = []
        for stage, rel in ((CONSCRYPT_PINS[0][0], CONSCRYPT_PINS[0][1]), (so_pin, CONSCRYPT_SO)):
            if stage not in pins:
                msgs.append("%s pins no %s" % (sums, stage))
                continue
            got = sha256_file(os.path.join(d, rel))
            if got != pins[stage]:
                msgs.append("%s sha256 %s, want %s (%s in %s)" % (rel, got, pins[stage], stage, sums))
        return msgs

    for name, fn in (("release-files", files), ("release-elf", elf), ("release-dex", dex), ("conscrypt-pin", pinned)):
        check(results, name, fn)
    return results


def report(results):
    """Print PASS/FAIL per check and 'RESULT PASS|FAIL (N of M)'; return the exit status (0 = every check passes)."""
    bad = 0
    for name, msgs in results:
        print("%s %s" % ("PASS" if not msgs else "FAIL", name))
        for m in msgs:
            print("     " + m)
        bad += bool(msgs)
    print("RESULT %s (%d of %d)" % ("PASS" if not bad else "FAIL", len(results) - bad, len(results)))
    return 1 if bad else 0


# ---- selftest: build tiny jars with javac + d8 and check good and broken ones ----------------------------------------

NATIVE_SRC = """package com.android.org.conscrypt;
public final class NativeCrypto {
    public static final long SSL_MODE_SEND_FALLBACK_SCSV = %(scsv)s;
    public static final long SSL_MODE_HANDSHAKE_CUTTHROUGH = %(cut)s;
    public static final String TLS_FALLBACK_SCSV = "TLS_FALLBACK_SCSV";
    static String fallback() { return "TLS_FALLBACK_SCSV"; }
    public static String[] getDefaultProtocols() { return new String[] { %(protocols)s }; }
    public static String[] getDefaultCipherSuites() { return new String[] { %(suites)s }; }
}
"""
OKHTTP_SRC = """package com.android.okhttp.internal;
public class Platform {
    public static String[] retry(boolean scsv) {
        return scsv ? new String[] { "%(proto)s", "TLS_FALLBACK_SCSV" } : new String[] { "%(proto)s" };
    }
}
"""


def _jar(td, name, srcs, javac, d8):
    src_dir = os.path.join(td, name, "src")
    cls_dir = os.path.join(td, name, "classes")
    files = []
    for rel, text in srcs.items():
        p = os.path.join(src_dir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        files.append(p)
    os.makedirs(cls_dir, exist_ok=True)
    subprocess.run([javac, "-nowarn", "--release", "8", "-d", cls_dir] + files, check=True, capture_output=True)
    classes = [os.path.join(r, f) for r, _, fs in os.walk(cls_dir) for f in fs if f.endswith(".class")]
    out = os.path.join(td, name, "out")
    os.makedirs(out, exist_ok=True)
    subprocess.run([d8, "--min-api", "19", "--output", out] + classes, check=True, capture_output=True)
    return os.path.join(out, "classes.dex")


def _fixture(td, tag, javac, d8, suites=A6, protocols=A7, scsv="0x80L", cut="0x200L", okproto="TLSv1",
             libssl_ver=b"1.0.1u"):
    d = os.path.join(td, tag)
    os.makedirs(os.path.join(d, "framework"))
    os.makedirs(os.path.join(d, "lib"))
    q = lambda xs: ", ".join('"%s"' % x for x in xs)
    for jar, srcs in (("conscrypt", {"com/android/org/conscrypt/NativeCrypto.java":
                                     NATIVE_SRC % {"scsv": scsv, "cut": cut, "protocols": q(protocols),
                                                  "suites": q(suites)}}),
                      ("okhttp", {"com/android/okhttp/internal/Platform.java": OKHTTP_SRC % {"proto": okproto}})):
        dex = _jar(td, tag + "-" + jar, srcs, javac, d8)
        with zipfile.ZipFile(os.path.join(d, "framework", jar + ".jar"), "w") as z:
            z.write(dex, "classes.dex")
    with open(os.path.join(d, "lib", "libssl.so"), "wb") as f:
        f.write(b"\0inappropriate fallback\0tlsv1 alert inappropriate fallback\0OpenSSL " + libssl_ver + b"\0")
    with open(os.path.join(d, "lib", "libjavacrypto.so"), "wb") as f:
        f.write(_elf(["libssl.so", "libcrypto.so", "libc.so"]))
    return d


ET_DYN = 3
DT_REL = 17  # any tag the parser ignores: stands in for DT_STRTAB when strtab=False


def _elf(needed, strtab=True, machine=EM_ARM):
    """A minimal ELF (ARM, or machine) with PT_LOAD + PT_DYNAMIC and the given NEEDED entries (strtab=False: no
    DT_STRTAB)."""
    want_strtab = strtab
    strtab, offs = b"\0", []
    for n in needed:
        offs.append(len(strtab))
        strtab += n.encode() + b"\0"
    ehsize, phentsize, dynsize = (struct.calcsize(f) for f in (ELF32_EHDR, ELF32_PHDR, ELF32_DYN))
    base = 0x1000  # vaddr of file offset 0 in the one PT_LOAD
    body_off = ehsize + 2 * phentsize
    dyn_len = dynsize * (len(needed) + 2)
    dyn = b"".join(struct.pack(ELF32_DYN, DT_NEEDED, o) for o in offs) + (
        struct.pack(ELF32_DYN, DT_STRTAB, base + body_off + dyn_len) if want_strtab else struct.pack(ELF32_DYN, DT_REL, 0)) \
        + struct.pack(ELF32_DYN, DT_NULL, 0)
    ident = b"\x7fELF\x01\x01\x01" + b"\0" * 9  # ELFCLASS32, ELFDATA2LSB, EV_CURRENT
    hdr = struct.pack(ELF32_EHDR, ident, ET_DYN, machine, 1, 0, ehsize, 0, 0, ehsize, phentsize, 2,
                      40, 0, 0)  # e_shentsize = sizeof(Elf32_Shdr), no section headers
    ph_load = struct.pack(ELF32_PHDR, PT_LOAD, 0, base, base, body_off + len(dyn) + len(strtab), 0, 5, 0x1000)
    ph_dyn = struct.pack(ELF32_PHDR, PT_DYNAMIC, body_off, base + body_off, 0, len(dyn), len(dyn), 6, 4)
    return hdr + ph_load + ph_dyn + dyn + strtab


BASE_BCP = ["/system/framework/%s.jar" % j for j in (
    "core", "conscrypt", "okhttp", "core-junit", "bouncycastle", "ext", "framework", "framework2", "telephony-common",
    "voip-common", "mms-common", "android.policy", "services", "apache-xml", "webviewchromium")]


def _newc(members, fields=None, noise=0, tail=b""):
    """gzip newc cpio of [(name, mode, data)], as mkbootfs + minigzip write a ramdisk (kktlsfmt.cpio_write fills the
    sizes; fields: ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor, rdevmajor, rdevminor, namesize,
    check). fields: {name: {field index: value}} overrides (a changed uid, rdev, ...); noise: added to every ino and
    mtime (per-pack values the comparison must ignore); tail: bytes after the archive inside the gzip stream."""
    out = []
    for ino, (name, mode, data) in enumerate(members + [("TRAILER!!!", 0, b"")]):
        f = [ino + 300000 + noise, mode, 0, 0, 1, noise, 0, 0, 0, 0, 0, 0, 0]
        for i, v in ((fields or {}).get(name) or {}).items():
            f[i] = v
        out.append((f, name, data))
    return gzip.compress(cpio_write(out) + tail)


# an appended archive that replaces init.rc (the kernel unpacks every archive of the image, the later one wins)
_OVERRIDE = cpio_write([([1, 0o100750, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], "init.rc", b"service evil /sbin/evil\n"),
                        ([2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], "TRAILER!!!", b"")])


def _environ(bcp):
    return ("on init\n    export ANDROID_ROOT /system\n    export BOOTCLASSPATH %s\n" % ":".join(bcp)).encode()


def _bootimg(ramdisk, page=2048):
    kernel = b"K" * 3000
    hdr = b"ANDROID!" + struct.pack("<8I", len(kernel), 0x60408000, len(ramdisk), 0x62000000, 0, 0, 0x60088000, page)
    pad = lambda b: b + b"\0" * (-len(b) % page)
    return pad(hdr) + pad(kernel) + pad(ramdisk)


def _fixture_d(td, tag, javac, d8, new_bcp=None, product_bcp=None, other_change=False, old_jar=False,
               stale_boot=False, drop_jar=None, jni_needed=("liblog.so", "libm.so", "libdl.so", "libc.so"),
               jni_name=CONSCRYPT_SO, aar_so=False, new_fields=None, noise=0, inner_tail=b"", outer_tail=b"",
               pin_override=None, pin_drop=None):
    """Layer-A fixture plus the layer-D files: old/new ramdisk (the same bytes unless new_bcp, other_change,
    new_fields, noise or a tail asks for a rebuilt one), boot.img, product environ, the 15 boot jars,
    kktls-conscrypt.jar and kktls-sslfilter.jar (installed, not boot jars), the .so; old_jar adds a stale
    kktls-sslfactory.jar. new_fields/noise: _newc overrides of the new ramdisk; inner_tail/outer_tail: bytes after its
    cpio archive (inside the gzip stream) / after its gzip member. SHA256SUMS pins the jar and .so as written (a
    missing one: the bytes it would have had); pin_override {stage name: sha256} replaces a pin, pin_drop leaves a line
    out."""
    d = _fixture(td, tag, javac, d8)
    for j in set(BASE_BCP + [CONSCRYPT_JAR, FILTER_JAR] + ([OLD_BOOT_JAR] if old_jar else [])):
        p = os.path.join(d, "framework", os.path.basename(j))
        if not os.path.exists(p):
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("classes.dex", b"dex\n035\0")
    if drop_jar:
        os.remove(os.path.join(d, "framework", drop_jar))
    with open(os.path.join(d, jni_name), "wb") as f:
        f.write(_elf(list(jni_needed)))
    if aar_so:
        with open(os.path.join(d, AAR_CONSCRYPT_SO), "wb") as f:
            f.write(_elf(list(jni_needed)))
    base = [("init.rc", 0o100750, b"import /init.environ.rc\n"), ("default.prop", 0o100644, b"ro.secure=1\n"),
            ("sbin", 0o40750, b""), ("dev/__null__", 0o20666, b"")]
    old = _newc(base + [("init.environ.rc", 0o100644, _environ(BASE_BCP))])
    if new_bcp is None and not (other_change or new_fields or noise or inner_tail or outer_tail):
        new = old
    else:
        nb = list(base)
        if other_change:
            nb[0] = ("init.rc", 0o100750, b"import /init.environ.rc\nservice x /system/bin/x\n")
        new = _newc(nb + [("init.environ.rc", 0o100644, _environ(BASE_BCP if new_bcp is None else new_bcp))],
                    new_fields, noise, inner_tail) + outer_tail
    good = {CONSCRYPT_PINS[0][0]: None, CONSCRYPT_PINS[1][0]: hashlib.sha256(_elf(list(jni_needed))).hexdigest()}
    lines = []
    for stage, rel in CONSCRYPT_PINS:
        p = os.path.join(d, rel)
        pin = (pin_override or {}).get(stage) or (sha256_file(p) if os.path.isfile(p) else good[stage] or "0" * 64)
        if stage != pin_drop:
            lines.append("%s  %s\n" % (pin, stage))
    with open(os.path.join(d, "SHA256SUMS"), "w") as f:
        f.write("0f0b0f03da2f9d42a2727035e78d97cfbbed67bf1cb9142910afb14bdeafd25e  classes.jar\n" + "".join(lines))
    for name, data in (("old-ramdisk.img", old), ("ramdisk.img", new), ("boot.img", _bootimg(b"stale" if stale_boot else new)),
                       ("product-init.environ.rc", _environ(BASE_BCP if product_bcp is None else product_bcp))):
        with open(os.path.join(d, name), "wb") as f:
            f.write(data)
    return d


def _fixture_release(td, tag, javac, d8, abi, drop=None, add=None, machines=None, jni_needed=("libc.so", "libdl.so"),
                     odex=None, pin_drop=None):
    """A release directory: the layer-A fixture plus the other release files as ELF/dex stand-ins of --abi, and
    SHA256SUMS (outside DIR, as the checkout's file is) pinning the jar and the .so as written. drop: a release file
    left out; add: an extra file; machines {rel: e_machine}: another machine for that .so; odex: a jar without
    classes.dex; pin_drop: a pin line left out."""
    d = _fixture(td, tag, javac, d8)
    machine, so_pin = RELEASE_ABIS[abi]
    ssl_strings = b"\0inappropriate fallback\0tlsv1 alert inappropriate fallback\0OpenSSL 1.0.1u\0"
    for rel, needed in (("lib/libssl.so", ["libcrypto.so", "libc.so"]), ("lib/libcrypto.so", ["libc.so"]),
                        ("lib/libjavacrypto.so", ["libssl.so", "libcrypto.so", "libc.so"]), (CONSCRYPT_SO, list(jni_needed))):
        with open(os.path.join(d, rel), "wb") as f:
            f.write(_elf(needed, machine=(machines or {}).get(rel, machine)) + (ssl_strings if "libssl" in rel else b""))
    for rel in RELEASE_FILES:
        p = os.path.join(d, rel)
        if rel.endswith(".jar") and not os.path.exists(p):
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("classes.dex", b"dex\n035\0" + rel.encode())
    if odex:
        with zipfile.ZipFile(os.path.join(d, odex), "w") as z:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    for rel in (add or ()):
        with open(os.path.join(d, rel), "wb") as f:
            f.write(_elf(["libc.so"], machine=machine))
    lines = ["%s  %s\n" % (sha256_file(os.path.join(d, rel)), stage)
             for stage, rel in ((CONSCRYPT_PINS[0][0], CONSCRYPT_PINS[0][1]), (so_pin, CONSCRYPT_SO))
             if stage != pin_drop]
    with open(os.path.join(td, tag + "-SHA256SUMS"), "w") as f:
        f.write("".join(lines))
    with open(os.path.join(d, "SHA256SUMS"), "w") as f:
        f.write("(the release's own sums: not read by the checks)\n")
    if drop:
        os.remove(os.path.join(d, drop))
    return d


def _run_d(d, dexdump, boot=True):
    j = lambda n: os.path.join(d, n)
    return run_checks(d, dexdump) + run_checks_d(d, j("old-ramdisk.img"), j("ramdisk.img"), j("boot.img") if boot else None,
                                                 j("product-init.environ.rc"), j("SHA256SUMS"))


def selftest(dexdump, javac, d8):
    fails = []
    with tempfile.TemporaryDirectory() as td:
        cases = [
            ("good", {}, set()),
            ("rc4-first", {"suites": ["SSL_RSA_WITH_RC4_128_MD5"] + A6}, {"a6-default-suites"}),
            ("gcm-missing", {"suites": A6[4:]}, {"a6-default-suites"}),
            ("order-swapped", {"suites": [A6[1], A6[0]] + A6[2:]}, {"a6-default-suites"}),
            ("sslv3-default", {"protocols": ["SSLv3", "TLSv1"]}, {"a7-protocols"}),
            ("scsv-kitkat-bit", {"scsv": "0x200L"}, {"scsv-constant"}),
            ("cutthrough-kitkat-bit", {"cut": "0x20L"}, {"scsv-constant"}),
            ("okhttp-sslv3", {"okproto": "SSLv3"}, {"okhttp-no-sslv3"}),
            ("libssl-1.0.1e", {"libssl_ver": b"1.0.1e"}, {"libssl-fallback"}),
        ]
        for tag, kw, want in cases:
            d = _fixture(td, tag, javac, d8, **kw)
            got = {n for n, m in run_checks(d, dexdump) if m}
            ok = got == want
            print("selftest %s %-16s failing checks %s, want %s" % ("ok  " if ok else "FAIL", tag, sorted(got),
                                                                     sorted(want)))
            if not ok:
                fails.append(tag)
        # ramdisk-unchanged (layer A): equal images pass, a changed one fails, missing arguments fail (never omitted)
        d = _fixture(td, "ramdisk", javac, d8)
        img = lambda n, data: (open(os.path.join(d, n), "wb").write(data), os.path.join(d, n))[1]
        same_a, same_b, other = img("r1.img", b"ramdisk"), img("r2.img", b"ramdisk"), img("r3.img", b"ramdisk2")
        for tag, args, want in (("ramdisk-equal", (same_a, same_b), set()),
                                ("ramdisk-changed", (same_a, other), {"ramdisk-unchanged"}),
                                ("ramdisk-not-given", (None, None), {"ramdisk-unchanged"}),
                                ("ramdisk-one-given", (same_a, None), {"ramdisk-unchanged"})):
            got = {n for n, m in run_checks(d, dexdump) + check_ramdisk_unchanged(*args) if m}
            ok = got == want
            print("selftest %s %-16s failing checks %s, want %s" % ("ok  " if ok else "FAIL", tag, sorted(got),
                                                                     sorted(want)))
            if not ok:
                fails.append(tag)
        # a malformed libjavacrypto.so is a FAIL of its check, not a traceback
        for tag, data in (("elf-truncated", _elf(["libssl.so", "libcrypto.so"])[:70]),
                          ("elf-no-strtab", _elf(["libssl.so", "libcrypto.so"], strtab=False))):
            d = _fixture(td, tag, javac, d8)
            with open(os.path.join(d, "lib", "libjavacrypto.so"), "wb") as f:
                f.write(data)
            got = {n for n, m in run_checks(d, dexdump) if m}
            ok = got == {"libjavacrypto"}
            print("selftest %s %-16s failing checks %s, want %s" % ("ok  " if ok else "FAIL", tag, sorted(got),
                                                                     ["libjavacrypto"]))
            if not ok:
                fails.append(tag)
        # a missing or unreadable input (a jar without classes.dex: odexed) is a FAIL of the checks that read it,
        # not a traceback
        conscrypt_checks = {"a6-default-suites", "a7-protocols", "scsv-constant"}
        for tag, rel, data, want in (("no-conscrypt-jar", "framework/conscrypt.jar", None, conscrypt_checks),
                                     ("odexed-conscrypt", "framework/conscrypt.jar", "zip", conscrypt_checks),
                                     ("not-a-zip-okhttp", "framework/okhttp.jar", b"not a zip", {"okhttp-no-sslv3"}),
                                     ("no-okhttp-jar", "framework/okhttp.jar", None, {"okhttp-no-sslv3"}),
                                     ("no-libssl", "lib/libssl.so", None, {"libssl-fallback"}),
                                     ("no-libjavacrypto", "lib/libjavacrypto.so", None, {"libjavacrypto"})):
            d = _fixture(td, tag, javac, d8)
            p = os.path.join(d, rel)
            os.remove(p)
            if data == "zip":
                with zipfile.ZipFile(p, "w") as z:
                    z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            elif data is not None:
                with open(p, "wb") as f:
                    f.write(data)
            res = run_checks(d, dexdump)
            got = {n for n, m in res if m}
            ok = got == want and len(res) == 6
            print("selftest %s %-16s failing checks %s, want %s" % ("ok  " if ok else "FAIL", tag, sorted(got),
                                                                     sorted(want)))
            if not ok:
                fails.append(tag)
        with_conscrypt = BASE_BCP + [CONSCRYPT_JAR]
        old15 = BASE_BCP + [OLD_BOOT_JAR]  # the layout before Task 4 (plan 20261015)
        member_checks = {"ramdisk-unchanged", "ramdisk-bootclasspath", "bootjars-present"}
        changed = {"ramdisk-unchanged"}
        d_cases = [
            ("d-good", {}, set()),
            # the 15-jar pair of before Task 4: ramdisk changed, kktls-sslfactory.jar on it and installed
            ("d-old-15-jar-pair", {"new_bcp": old15, "product_bcp": old15, "old_jar": True},
             {"ramdisk-unchanged", "ramdisk-bootclasspath", "bootjars-present"}),
            ("d-other-member", {"other_change": True}, changed),
            ("d-uid-changed", {"new_fields": {"init.rc": {2: 1000}}}, changed),
            ("d-environ-mode", {"new_fields": {"init.environ.rc": {1: 0o100755}}}, changed),
            ("d-ino-mtime-noise", {"noise": 77}, changed),  # a byte compare, as layer A
            ("d-product-15", {"product_bcp": old15}, {"ramdisk-bootclasspath"}),
            ("d-task11-bcp", {"new_bcp": with_conscrypt, "product_bcp": with_conscrypt},
             {"ramdisk-unchanged", "ramdisk-bootclasspath"}),
            ("d-sslfilter-first", {"new_bcp": [FILTER_JAR] + BASE_BCP, "product_bcp": [FILTER_JAR] + BASE_BCP},
             {"ramdisk-unchanged", "ramdisk-bootclasspath"}),
            ("d-old-jar-left", {"old_jar": True}, {"bootjars-present"}),
            ("d-bootjar-missing", {"drop_jar": "framework.jar"}, {"bootjars-present"}),
            ("d-sslfilter-not-installed", {"drop_jar": "kktls-sslfilter.jar"}, {"bootjars-present"}),
            ("d-conscrypt-not-installed", {"drop_jar": "kktls-conscrypt.jar"}, {"bootjars-present", "conscrypt-pin"}),
            ("d-jni-libssl", {"jni_needed": ("libssl.so", "libc.so")}, {"bootjars-present"}),
            ("d-jni-aar-name", {"jni_name": AAR_CONSCRYPT_SO}, {"bootjars-present", "conscrypt-pin"}),
            # Task 12 (plan 20261012): the installed jar and .so must be the pinned 2.6-alpha2 stage files
            ("d-pin-jar-other", {"pin_override": {CONSCRYPT_PINS[0][0]: "ab" * 32}}, {"conscrypt-pin"}),
            ("d-pin-so-253", {"pin_override": {CONSCRYPT_PINS[1][0]: "009ee440620105adefff81c5af4fafd23aebefff5b8d03d7180212c02983b532"}},
             {"conscrypt-pin"}),
            ("d-pin-line-missing", {"pin_drop": CONSCRYPT_PINS[1][0]}, {"conscrypt-pin"}),
            ("d-jni-both-names", {"aar_so": True}, {"bootjars-present"}),
            ("d-stale-bootimg", {"stale_boot": True}, {"bootimg-ramdisk"}),
            # review 3 codex 6: the kernel unpacks every archive of the image; only zero padding may follow the first
            # cpio archive and the first gzip member. bootimg-ramdisk is a byte compare and still passes (boot.img
            # carries the same appended bytes); the checks that read the members fail, and the bytes differ
            ("d-appended-cpio", {"inner_tail": _OVERRIDE}, member_checks),
            ("d-appended-cpio-padded", {"inner_tail": b"\0" * 512 + _OVERRIDE}, member_checks),
            ("d-appended-gzip", {"outer_tail": gzip.compress(_OVERRIDE)}, member_checks),
            ("d-appended-gzip-padded", {"outer_tail": b"\0" * 512 + gzip.compress(_OVERRIDE)}, member_checks),
            ("d-junk-after-trailer", {"inner_tail": b"\0" * 4 + b"junk"}, member_checks),
            ("d-junk-after-gzip", {"outer_tail": b"junk"}, member_checks),
            ("d-zero-pad-after-trailer", {"inner_tail": b"\0" * 132}, changed),
            ("d-zero-pad-after-gzip", {"outer_tail": b"\0" * 512}, changed),
        ]
        for tag, kw, want in d_cases:
            d = _fixture_d(td, tag, javac, d8, **kw)
            res = _run_d(d, dexdump)
            got = {n for n, m in res if m}
            ok = got == want and len(res) == 11
            print("selftest %s %-16s failing checks %s, want %s" % ("ok  " if ok else "FAIL", tag, sorted(got),
                                                                     sorted(want)))
            if not ok:
                fails.append(tag)
        # without --boot-img the check is not run (10 checks), the others as with it
        d = _fixture_d(td, "d-no-boot-img", javac, d8, stale_boot=True)
        res = _run_d(d, dexdump, boot=False)
        ok = not [n for n, m in res if m] and len(res) == 10 and "bootimg-ramdisk" not in [n for n, _ in res]
        print("selftest %s %-16s %d checks, failing %s" % ("ok  " if ok else "FAIL", "d-no-boot-img", len(res),
                                                            sorted(n for n, m in res if m)))
        if not ok:
            fails.append("d-no-boot-img")
        # --layer release
        x86_so = {CONSCRYPT_SO: EM_386}
        r_cases = [
            ("rel-good-arm", "armeabi-v7a", {}, set()),
            ("rel-good-x86", "x86", {}, set()),
            ("rel-filter-missing", "x86", {"drop": "framework/kktls-sslfilter.jar"}, {"release-files", "release-dex"}),
            ("rel-aar-so-name", "armeabi-v7a", {"add": [AAR_CONSCRYPT_SO]}, {"release-files"}),
            ("rel-old-factory-jar", "armeabi-v7a", {"add": ["framework/kktls-sslfactory.jar"]}, {"release-files"}),
            ("rel-arm-crypto-in-x86", "x86", {"machines": {"lib/libcrypto.so": EM_ARM}}, {"release-elf"}),
            ("rel-arm-javacrypto-x86", "x86", {"machines": {"lib/libjavacrypto.so": EM_ARM}},
             {"release-elf", "libjavacrypto"}),
            ("rel-x86-jni-in-arm", "armeabi-v7a", {"machines": x86_so}, {"release-elf"}),
            ("rel-jni-needs-libssl", "x86", {"jni_needed": ("libc.so", "libssl.so")}, {"release-elf"}),
            ("rel-odexed-core", "armeabi-v7a", {"odex": "framework/core.jar"}, {"release-dex"}),
            ("rel-odexed-conscrypt", "x86", {"odex": "framework/conscrypt.jar"},
             {"release-dex", "a6-default-suites", "a7-protocols", "scsv-constant"}),
            ("rel-x86-so-pin-missing", "x86", {"pin_drop": RELEASE_ABIS["x86"][1]}, {"conscrypt-pin"}),
            ("rel-jar-pin-missing", "armeabi-v7a", {"pin_drop": CONSCRYPT_PINS[0][0]}, {"conscrypt-pin"}),
        ]
        for tag, abi, kw, want in r_cases:
            d = _fixture_release(td, tag, javac, d8, abi, **kw)
            res = run_checks(d, dexdump, RELEASE_ABIS[abi][0]) + run_checks_release(d, abi, os.path.join(td, tag + "-SHA256SUMS"))
            got = {n for n, m in res if m}
            ok = got == want and len(res) == 10
            print("selftest %s %-22s failing checks %s, want %s" % ("ok  " if ok else "FAIL", tag, sorted(got),
                                                                     sorted(want)))
            if not ok:
                fails.append(tag)
        # an ARM release checked as x86 (the --abi decides): every .so and libjavacrypto fail, the pin of the x86 .so
        d = _fixture_release(td, "rel-arm-as-x86", javac, d8, "armeabi-v7a")
        sums_x86 = os.path.join(td, "rel-arm-as-x86-SHA256SUMS")
        res = run_checks(d, dexdump, EM_386) + run_checks_release(d, "x86", sums_x86)
        got = {n for n, m in res if m}
        want = {"libjavacrypto", "release-elf", "conscrypt-pin"}
        print("selftest %s %-22s failing checks %s, want %s" % ("ok  " if got == want else "FAIL", "rel-arm-as-x86",
                                                                 sorted(got), sorted(want)))
        if got != want:
            fails.append("rel-arm-as-x86")
    print("SELFTEST " + ("PASS" if not fails else "FAIL %s" % fails))
    return 1 if fails else 0



def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dir", nargs="?")
    ap.add_argument("--dexdump")
    ap.add_argument("--layer", choices=("a", "d", "release"), default="a")
    ap.add_argument("--abi", choices=sorted(RELEASE_ABIS), help="--layer release: the ABI of DIR")
    ap.add_argument("--old-ramdisk", help="ramdisk.img before the series (layer A) or before layer D (--layer d)")
    ap.add_argument("--ramdisk", help="the new ramdisk.img")
    ap.add_argument("--boot-img", help="--layer d, optional: the new boot.img (its ramdisk must be --ramdisk)")
    ap.add_argument("--product-environ", help="--layer d: obj/ETC/init.environ.rc_intermediates/init.environ.rc")
    ap.add_argument("--sums", default=CONSCRYPT_SUMS, help="--layer d: SHA256SUMS with the 2.6-alpha2 stage pins")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--javac", default=shutil.which("javac") or "javac")
    ap.add_argument("--d8", default=os.path.join(BUILD_TOOLS, "d8"))
    a = ap.parse_args()
    dexdump = find_dexdump(a.dexdump)
    if a.selftest:
        return selftest(dexdump, a.javac, a.d8)
    if not a.dir:
        ap.error("DIR is required")
    if a.layer == "release":
        if not a.abi:
            ap.error("--layer release needs --abi")
        return report(run_checks(a.dir, dexdump, RELEASE_ABIS[a.abi][0]) + run_checks_release(a.dir, a.abi, a.sums))
    if a.layer == "d":
        if not (a.old_ramdisk and a.ramdisk and a.product_environ):
            ap.error("--layer d needs --old-ramdisk, --ramdisk and --product-environ")
        return report(run_checks(a.dir, dexdump) + run_checks_d(a.dir, a.old_ramdisk, a.ramdisk, a.boot_img,
                                                                a.product_environ, a.sums))
    return report(run_checks(a.dir, dexdump) + check_ramdisk_unchanged(a.old_ramdisk, a.ramdisk))


if __name__ == "__main__":
    sys.exit(main())
