#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""check_prebuilt.py: static checks of a Conscrypt aar before it goes into an Android 4.4 build.

    python3 -I check_prebuilt.py AAR [--sums SHA256SUMS]
    python3 -I check_prebuilt.py --selftest AAR [--sums SHA256SUMS]

    python3 -I check_prebuilt.py --stage DIR [--sums SHA256SUMS] [--notice NOTICE] [--base 4.4|4.3|4.2|4.1]
                                 [--bionic FILE] [--bionic-x86 FILE]
    python3 -I check_prebuilt.py --selftest --stage DIR [--alpha3 AAR]
    python3 -I check_prebuilt.py --bionic-exports LIBDIR [--label TEXT]   print the export list of
                                 LIBDIR/{libc,libdl,libm,liblog}.so (TEXT names the build in the header)

Stdlib only; the aar is read as data (zipfile, struct), nothing from it is executed. Exit status 0 only if every check passes.

--stage DIR checks the 2.6-alpha2 stage, the files
mkstage.py puts in <tree>/stock/conscrypt/2.6-alpha2/: the dex jar kktls-conscrypt.dex.jar
(rename_jni.py, then d8 --min-api 19, plus conscrypt.properties), libkktls_conscrypt_jni.so (the aar's armeabi-v7a
.so, byte-identical) and x86/libkktls_conscrypt_jni.so (the aar's x86 .so, for the generic x86 release). Its checks
(CHECKS_STAGE):
  stage-present   the dex jar and both .so files exist
  stage-sha256    all three = their pinned lines (2.6-alpha2/...) in SHA256SUMS
  dex-jar         members exactly classes.dex + org/conscrypt/conscrypt.properties (no .class: a class-52 jar that
                  skipped d8 fails here), dex magic 035 (the newest version 4.4 Dalvik reads), adler32 checksum valid
  dex-classes     class_defs all under Lorg/conscrypt/, the classes the wrapper and the KitKat adapter need are there,
                  count = STAGE_CLASS_COUNT (423 classes + 2 d8 synthetics)
  dex-jni-name    the dex strings hold "kktls_conscrypt_jni" and not "conscrypt_jni" (rename_jni.py ran before d8)
  dex-properties  conscrypt.properties = 2.6.0 (what 2.6-alpha2 says), BoringSSL f91f1447...
  so-elf, so-needed, so-loader, so-exports   as for the aar
  so-symbols      every undefined GLOBAL symbol of the .so is exported by the 4.4 bionic (bionic44-exports.txt);
                  undefined WEAK symbols are reported, not failed (alpha3+ fail here: __read_chk, strtof, ...)
  x86-so-*        the same five checks for the x86 .so: e_machine x86 (3), symbols against --bionic-x86
                  (bionic44-exports-x86.txt: the 4.4 x86 libdl exports dl_iterate_phdr, ARM's dl_unwind_find_exidx)
  notice          NOTICE = its pinned sha256 and names this Conscrypt tag and BoringSSL commit

--base selects the bionic export lists of the so-symbols checks (BASES; --bionic/--bionic-x86 override them): 4.4
(default) or a Jelly Bean base, whose lists come from our own AOSP full-eng (ARM) and full_x86-eng builds of
android-4.3_r3, android-4.2.2_r1 and android-4.1.2_r2. Only the symbol lists change; the dex checks stay those of the
4.4 stage. The pristine 2.6-alpha2 .so misses exactly JB_MISSING on a JB base (the --selftest --stage cases assert it):
4.3 nothing, 4.2 ARM getauxval, 4.1 the fortify functions (both ABIs) and getauxval (ARM).
--compat FILE / --compat-x86 FILE (a JB base whose JB_MISSING is not empty for that ABI: 4.2 ARM, 4.1 both): the
libkktls_compat.so built in the base's tree (conscrypt/compat/). That ABI's .so checks then take the jb_needed.py output
jb-compat/[x86/]libkktls_conscrypt_jni.so of the stage instead of the aar's file: so-elf wants no DT_SONAME, so-needed
the aar's list plus libkktls_compat.so as the last entry (the JB linkers search DT_NEEDED in order, so libc and the
others come first), so-symbols resolves against the base's bionic plus the compat library's exports. A JB base adds the
checks compat / x86-compat: the library is ELF32 LE ET_DYN of the ABI with DT_HASH, = its pin
jb-compat/<base>/[x86/]libkktls_compat.so, exports exactly JB_MISSING of the base and ABI (besides COMPAT_CRT_EXPORTS,
which every library of the tree has and the Conscrypt .so does not import), none of them a bionic export, imports only
bionic exports, NEEDED only libc/liblog; on a base or ABI that needs nothing, a compat library given is a failure and
none given passes. --jb-missing BASE prints the ABIs of BASE that need the compat library and the symbols.
--jb checks the Jelly Bean stage of mkstage.py --jb instead (same file names): stage-sha256 takes the dex jar pin
2.6-alpha2/jb/kktls-conscrypt.dex.jar, and dex-classes wants 426 classes, the jb_charsets.py shim
org/conscrypt/KktlsStandardCharsets, no reference to java/nio/charset/StandardCharsets (API 19) and no string
holding the dotted java.nio.charset.StandardCharsets (a reflective Class.forName).

With the aar sha256 pinned, the structural checks below cannot fail on the pinned file; they are the vetting record that
re-runs whenever the pin moves (a new Conscrypt release: new SHA256SUMS lines, mkstage.py, this checker), and the
selftest proves each of them still reacts. A version bump edits: SHA256SUMS (four lines; rename_jni/classes.jar from
rename_jni.py), AAR_NAME and EXPECTED_PROPERTIES/CLASS_COUNT here, kktls_conscrypt_aar_name in Android.mk and the
version in mkstage.py and the build scripts.

Checks:
  aar-present     the aar exists
  aar-sha256      sha256 of the aar = the pinned line in SHA256SUMS
  members-sha256  classes.jar and jni/armeabi-v7a/libconscrypt_jni.so = their pinned sha256
  so-elf          the .so is ELF32 little-endian ARM, ET_DYN, SONAME libconscrypt_jni.so
  so-needed       DT_NEEDED only libc/libdl/libm/liblog (what the 4.4 bionic provides; no libc++_shared)
  so-loader       4.4 linker compatibility: SysV DT_HASH present, no PT_TLS, no TEXTREL, no RELR/APS2 packed relocs
  so-exports      JNI_OnLoad is exported (natives are registered there); the other exports are counted and reported
  class-major     every .class is a class file with major <= 51 (the 4.4 dx limit, DirectClassFile.java:72)
  class-packages  every class is under org/conscrypt/ (the jar must not carry classes of other packages: its own
                  loader's parent is the boot class loader, and an app may load it too); the classes the kktls wrapper and
                  the KitKat adapter need are there
  properties      org/conscrypt/conscrypt.properties = version 2.5.3, BoringSSL 49f0329110a1d93a5febc2bceceedc655d995420
"""
import argparse
import hashlib
import io
import os
import shutil
import struct
import sys
import tempfile
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python3 -I leaves the script directory off sys.path
from dexparse import dex_tables  # noqa: E402  (after the sys.path line)

AAR_NAME = "conscrypt-android-2.5.3.aar"
CLASSES = "classes.jar"
SO = "jni/armeabi-v7a/libconscrypt_jni.so"
ALLOWED_NEEDED = {"libc.so", "libdl.so", "libm.so", "liblog.so"}
MAX_MAJOR = 51
CLASS_COUNT = 308
REQUIRED_CLASSES = [
    "org/conscrypt/Conscrypt.class",
    "org/conscrypt/OpenSSLProvider.class",
    "org/conscrypt/NativeCrypto.class",
    "org/conscrypt/KitKatPlatformOpenSSLSocketImplAdapter.class",
    "org/conscrypt/KitKatPlatformOpenSSLSocketAdapterFactory.class",
]
PROPERTIES = "org/conscrypt/conscrypt.properties"
EXPECTED_PROPERTIES = {
    "org.conscrypt.boringssl.version": "49f0329110a1d93a5febc2bceceedc655d995420",
    "org.conscrypt.version.major": "2",
    "org.conscrypt.version.minor": "5",
    "org.conscrypt.version.patch": "3",
}
CHECKS = ["aar-present", "aar-sha256", "members-sha256", "so-elf", "so-needed", "so-loader", "so-exports",
          "class-major", "class-packages", "properties"]

# the 2.6-alpha2 stage (--stage); names are SHA256SUMS keys, the part after "2.6-alpha2/" is the file in the stage dir
STAGE_VERSION = "2.6-alpha2"
STAGE_AAR = STAGE_VERSION + "/conscrypt-android-2.6-alpha2.aar"
STAGE_DEXJAR = STAGE_VERSION + "/kktls-conscrypt.dex.jar"
STAGE_SO = STAGE_VERSION + "/libkktls_conscrypt_jni.so"
STAGE_SO_X86 = STAGE_VERSION + "/x86/libkktls_conscrypt_jni.so"  # the aar's x86 .so (generic x86 release)
STAGE_CLASS_COUNT = 425  # 423 classes of the aar + ConscryptSession$-CC and NativeRef$0 (d8 desugaring/backport)
# --jb: the Jelly Bean stage (mkstage.py --jb), same file names; its dex jar has its own pin and the jb_charsets.py shim
STAGE_DEXJAR_JB = STAGE_VERSION + "/jb/kktls-conscrypt.dex.jar"
STAGE_CLASS_COUNT_JB = 426  # the 425 above + org/conscrypt/KktlsStandardCharsets
JB_SHIM_TYPE = "Lorg/conscrypt/KktlsStandardCharsets;"
JB_ABSENT_TYPE = "Ljava/nio/charset/StandardCharsets;"  # API 19: must not be referenced by the JB dex
JB_ABSENT_DOTTED = "java.nio.charset.StandardCharsets"  # nor named for reflection (Class.forName) in any string
STAGE_PROPERTIES = {
    "org.conscrypt.boringssl.version": "f91f1447397c6719f9774dfb8e67329378e1f3d3",
    "org.conscrypt.version.major": "2",
    "org.conscrypt.version.minor": "6",
    "org.conscrypt.version.patch": "0",
}
STAGE_DEX_MEMBERS = ["classes.dex", PROPERTIES]
NOTICE_NAME = "NOTICE"  # the module NOTICE
NOTICE_MUST_NAME = ("google/conscrypt 2.6-alpha2", "f91f1447397c6719f9774dfb8e67329378e1f3d3")
BIONIC_EXPORTS = "bionic44-exports.txt"
BIONIC_EXPORTS_X86 = "bionic44-exports-x86.txt"
BASES = {b: ("bionic%s-exports.txt" % b.replace(".", ""), "bionic%s-exports-x86.txt" % b.replace(".", ""))
         for b in ("4.4", "4.3", "4.2", "4.1")}  # --base: (ARM list, x86 list)
_FORTIFY41 = {"__memcpy_chk", "__memmove_chk", "__memset_chk", "__open_2", "__strlen_chk", "__vsnprintf_chk"}
JB_MISSING = {  # the undefined GLOBAL symbols of the pristine 2.6-alpha2 .so that a JB bionic does not export
    ("4.3", "arm"): set(), ("4.3", "x86"): set(),
    ("4.2", "arm"): {"getauxval"}, ("4.2", "x86"): set(),
    ("4.1", "arm"): _FORTIFY41 | {"getauxval"}, ("4.1", "x86"): set(_FORTIFY41),
}
ABI_NAMES = {"arm": "armeabi-v7a", "x86": "x86"}  # JB_MISSING key -> Android ABI name
# the JB 4.1/4.2 .so of an ABI that needs libkktls_compat.so: jb_needed.py output (DT_SONAME -> DT_NEEDED), mkstage.py --jb
STAGE_SO_COMPAT = STAGE_VERSION + "/jb-compat/libkktls_conscrypt_jni.so"
STAGE_SO_COMPAT_X86 = STAGE_VERSION + "/jb-compat/x86/libkktls_conscrypt_jni.so"
COMPAT_NAME = "libkktls_compat.so"
COMPAT_ALLOWED_NEEDED = {"libc.so", "liblog.so"}
# exported by every library the JB tree links (linker-defined absolute symbols; 4.1's crtbegin_so/crtend_so): not part
# of the compat interface, never imported by the Conscrypt .so (checked), and libc's own come first anyway
COMPAT_CRT_EXPORTS = {"_edata", "__bss_start", "_end", "__on_dlclose", "__dso_handle", "__INIT_ARRAY__", "__FINI_ARRAY__"}
COMPAT_CHECKS = ["compat", "x86-compat"]


def needs_compat(base, abi):
    """abi: "arm" or "x86". True when the aar .so misses symbols on that base's bionic (JB_MISSING)."""
    return bool(JB_MISSING.get((base, abi)))


def compat_pin(base, abi):
    return "jb-compat/%s/%s%s" % (base, "x86/" if abi == "x86" else "", COMPAT_NAME)


ALPHA3_AAR = "negative/conscrypt-android-2.6-alpha3.aar"  # selftest fixture only, never staged
SO_CHECKS = ["so-elf", "so-needed", "so-loader", "so-exports", "so-symbols"]
CHECKS_STAGE = (["stage-present", "stage-sha256", "dex-jar", "dex-classes", "dex-jni-name", "dex-properties"] + SO_CHECKS
                + ["x86-" + c for c in SO_CHECKS] + ["notice"])

EM_ARM = 40
EM_386 = 3
MACHINE_NAMES = {EM_ARM: "ARM=40", EM_386: "x86=3"}
ET_DYN = 3
PT_DYNAMIC, PT_TLS = 2, 7
SHT_DYNSYM = 11
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SONAME, DT_TEXTREL, DT_FLAGS = 0, 1, 4, 5, 14, 22, 30
DT_RELR, DT_ANDROID_REL, DT_ANDROID_RELA = 36, 0x6000000F, 0x60000011
DF_TEXTREL = 0x4


def read_sums(path, required=(AAR_NAME, CLASSES, SO)):
    sums = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2 and len(parts[0]) == 64:
                sums[parts[1]] = parts[0].lower()
    for name in required:
        if name not in sums:
            raise SystemExit("%s: no sha256 line for %s" % (path, name))
    return sums


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class Elf32:
    """Just enough ELF32-LE to read the dynamic section and the dynamic symbol table."""

    def __init__(self, data):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.data = data
        self.ei_class, self.ei_data = data[4], data[5]
        if self.ei_class != 1 or self.ei_data != 1:
            raise ValueError("not ELF32 little-endian (class %d, data %d)" % (self.ei_class, self.ei_data))
        (self.e_type, self.e_machine, _, _, self.e_phoff, self.e_shoff, _, _, self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, _) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
        self.phdrs = [struct.unpack_from("<IIIIIIII", data, self.e_phoff + i * self.e_phentsize)
                      for i in range(self.e_phnum)]
        self.shdrs = [struct.unpack_from("<IIIIIIIIII", data, self.e_shoff + i * self.e_shentsize)
                      for i in range(self.e_shnum)] if self.e_shoff else []

    def vaddr_to_off(self, vaddr):
        for p_type, p_offset, p_vaddr, _, p_filesz, _, _, _ in self.phdrs:
            if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
                return vaddr - p_vaddr + p_offset
        raise ValueError("vaddr 0x%x not in a PT_LOAD segment" % vaddr)

    def dynamic(self):
        for p_type, p_offset, _, _, p_filesz, _, _, _ in self.phdrs:
            if p_type == PT_DYNAMIC:
                out = []
                for i in range(p_filesz // 8):
                    tag, val = struct.unpack_from("<iI", self.data, p_offset + i * 8)
                    if tag == DT_NULL:
                        break
                    out.append((tag & 0xFFFFFFFF, val))
                return out
        raise ValueError("no PT_DYNAMIC")

    def cstr(self, off):
        end = self.data.index(b"\0", off)
        return self.data[off:end].decode("latin-1")

    def dyn_strings(self, dyn, tag):
        strtab = self.vaddr_to_off(next(v for t, v in dyn if t == DT_STRTAB))
        return [self.cstr(strtab + v) for t, v in dyn if t == tag]

    def defined_dynsyms(self):
        for sh in self.shdrs:
            if sh[1] == SHT_DYNSYM:
                _, _, _, _, off, size, link, _, _, entsize = sh
                stroff = self.shdrs[link][4]
                names = []
                for i in range(1, size // entsize):
                    st_name, _, _, st_info, _, st_shndx = struct.unpack_from("<IIIBBH", self.data, off + i * entsize)
                    if st_shndx != 0 and (st_info >> 4) in (1, 2):  # defined GLOBAL or WEAK
                        names.append(self.cstr(stroff + st_name))
                return names
        raise ValueError("no .dynsym section")

    def undefined_dynsyms(self):
        """[(name, 'GLOBAL'|'WEAK')] of the undefined dynamic symbols."""
        for sh in self.shdrs:
            if sh[1] == SHT_DYNSYM:
                _, _, _, _, off, size, link, _, _, entsize = sh
                stroff = self.shdrs[link][4]
                out = []
                for i in range(1, size // entsize):
                    st_name, _, _, st_info, _, st_shndx = struct.unpack_from("<IIIBBH", self.data, off + i * entsize)
                    if st_shndx == 0 and st_name and (st_info >> 4) in (1, 2):
                        out.append((self.cstr(stroff + st_name), "GLOBAL" if st_info >> 4 == 1 else "WEAK"))
                return out
        raise ValueError("no .dynsym section")


def check_so(so, res, machine=EM_ARM, prefix="", compat=False):
    """so-* checks of one JNI .so; machine = the ABI's e_machine, prefix = the check name prefix ("x86-" for x86);
    compat: the jb_needed.py output (no SONAME, libkktls_compat.so the last NEEDED)."""
    try:
        elf = Elf32(so)
    except (ValueError, struct.error) as e:
        res[prefix + "so-elf"] = (False, str(e))
        return
    try:
        dyn = elf.dynamic()
        soname = elf.dyn_strings(dyn, DT_SONAME)
        needed = elf.dyn_strings(dyn, DT_NEEDED)
    except (ValueError, StopIteration, struct.error) as e:
        res[prefix + "so-elf"] = (False, "dynamic section: %s" % e)
        return
    bad = []
    if elf.e_machine != machine:
        bad.append("e_machine %d (want %s)" % (elf.e_machine, MACHINE_NAMES[machine]))
    if elf.e_type != ET_DYN:
        bad.append("e_type %d (want ET_DYN)" % elf.e_type)
    if soname != ([] if compat else ["libconscrypt_jni.so"]):
        bad.append("SONAME %s" % soname)
    res[prefix + "so-elf"] = (not bad, "; ".join(bad) or "ELF32 LE %s ET_DYN, %s"
                              % (MACHINE_NAMES[machine].split("=")[0],
                                 "no SONAME (jb_needed.py)" if compat else "SONAME libconscrypt_jni.so"))
    plain = needed[:-1] if compat and needed and needed[-1] == COMPAT_NAME else needed
    extra = sorted(set(plain) - ALLOWED_NEEDED)
    if compat and plain is needed:
        extra.append("no %s as the last entry" % COMPAT_NAME)
    res[prefix + "so-needed"] = (not extra, ("NEEDED outside libc/libdl/libm/liblog%s: %s"
                                             % (" + a last libkktls_compat.so" if compat else "", extra)) if extra
                                 else "NEEDED %s" % " ".join(needed))
    tags = {t for t, _ in dyn}
    flags = sum(v for t, v in dyn if t == DT_FLAGS)
    bad = []
    if DT_HASH not in tags:
        bad.append("no DT_HASH (the 4.4 linker has no GNU hash)")
    if any(p[0] == PT_TLS for p in elf.phdrs):
        bad.append("PT_TLS segment")
    if DT_TEXTREL in tags or flags & DF_TEXTREL:
        bad.append("TEXTREL")
    for t, name in ((DT_RELR, "DT_RELR"), (DT_ANDROID_REL, "DT_ANDROID_REL"), (DT_ANDROID_RELA, "DT_ANDROID_RELA")):
        if t in tags:
            bad.append(name)
    res[prefix + "so-loader"] = (not bad, "; ".join(bad) or "DT_HASH, no TLS/TEXTREL/packed relocations")
    try:
        exports = elf.defined_dynsyms()
    except (ValueError, IndexError, struct.error) as e:
        res[prefix + "so-exports"] = (False, str(e))
        return
    jni = [n for n in exports if n.startswith("Java_") or n in ("JNI_OnLoad", "JNI_OnUnload")]
    other = len(exports) - len(jni)
    res[prefix + "so-exports"] = ("JNI_OnLoad" in exports,
                         "JNI exports %s; %d other exported symbols (BoringSSL, not hidden; see README)"
                         % (",".join(sorted(jni)) or "none", other))


def check_classes(jar, res):
    try:
        z = zipfile.ZipFile(io.BytesIO(jar))
    except zipfile.BadZipFile as e:
        res["class-major"] = res["class-packages"] = res["properties"] = (False, "classes.jar: %s" % e)
        return
    names = z.namelist()
    classes = [n for n in names if n.endswith(".class")]
    bad_major = []
    worst = 0
    for n in classes:
        head = z.read(n)[:8]
        if len(head) < 8 or head[:4] != b"\xca\xfe\xba\xbe":
            bad_major.append("%s: not a class file" % n)
            continue
        major = struct.unpack(">H", head[6:8])[0]
        worst = max(worst, major)
        if major > MAX_MAJOR:
            bad_major.append("%s: major %d" % (n, major))
    res["class-major"] = (bool(classes) and not bad_major,
                          ("; ".join(bad_major[:5]) + (" (+%d)" % (len(bad_major) - 5) if len(bad_major) > 5 else ""))
                          if bad_major else "%d classes, highest major %d" % (len(classes), worst))
    outside = [n for n in classes if not n.startswith("org/conscrypt/")]
    missing = [n for n in REQUIRED_CLASSES if n not in names]
    bad = []
    if outside:
        bad.append("classes outside org/conscrypt/: %s" % outside[:5])
    if missing:
        bad.append("missing %s" % missing)
    if len(classes) != CLASS_COUNT:
        bad.append("%d classes (2.5.3 has %d)" % (len(classes), CLASS_COUNT))
    res["class-packages"] = (not bad, "; ".join(bad) or "%d classes, all under org/conscrypt/" % len(classes))
    if PROPERTIES not in names:
        res["properties"] = (False, "no %s" % PROPERTIES)
        return
    props = {}
    for line in z.read(PROPERTIES).decode("latin-1").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    diff = ["%s=%s (want %s)" % (k, props.get(k), v) for k, v in EXPECTED_PROPERTIES.items() if props.get(k) != v]
    res["properties"] = (not diff, "; ".join(diff) or "2.5.3, BoringSSL %s" %
                         EXPECTED_PROPERTIES["org.conscrypt.boringssl.version"][:8])


def check_aar(path, sums):
    """Returns {check: (ok, message)} for every name in CHECKS."""
    res = {}
    if not os.path.isfile(path):
        res["aar-present"] = (False, "%s is missing (download the pinned aar from Maven Central)" % path)
        for c in CHECKS[1:]:
            res[c] = (False, "not run: no aar")
        return res
    res["aar-present"] = (True, path)
    with open(path, "rb") as f:
        aar = f.read()
    got = sha256(aar)
    res["aar-sha256"] = (got == sums[AAR_NAME], "%s (pinned %s)" % (got, sums[AAR_NAME]))
    try:
        z = zipfile.ZipFile(io.BytesIO(aar))
        members = {n: z.read(n) for n in (CLASSES, SO) if n in z.namelist()}
    except zipfile.BadZipFile as e:
        for c in CHECKS[2:]:
            res[c] = (False, "aar is not a zip: %s" % e)
        return res
    bad = []
    for n in (CLASSES, SO):
        if n not in members:
            bad.append("%s missing" % n)
        elif sha256(members[n]) != sums[n]:
            bad.append("%s sha256 %s (pinned %s)" % (n, sha256(members[n]), sums[n]))
    res["members-sha256"] = (not bad, "; ".join(bad) or "classes.jar %s, .so %s" % (sums[CLASSES][:8], sums[SO][:8]))
    if SO in members:
        check_so(members[SO], res)
    else:
        for c in ("so-elf", "so-needed", "so-loader", "so-exports"):
            res[c] = (False, "%s missing" % SO)
    if CLASSES in members:
        check_classes(members[CLASSES], res)
    else:
        for c in ("class-major", "class-packages", "properties"):
            res[c] = (False, "%s missing" % CLASSES)
    return res


def report(res, out=sys.stdout):
    """Print PASS/FAIL per check and 'RESULT PASS|FAIL (N of M)'; return the exit status (0 = every check passes)."""
    for c in CHECKS:
        ok, msg = res[c]
        print("%-4s %-15s %s" % ("PASS" if ok else "FAIL", c, msg), file=out)
    failed = [c for c in CHECKS if not res[c][0]]
    print("RESULT %s (%d of %d)" % ("PASS" if not failed else "FAIL", len(CHECKS) - len(failed), len(CHECKS)),
          file=out)
    return 1 if failed else 0


# ------------------------------------------------------------------------------------------- 2.6-alpha2 stage mode

def read_bionic(path):
    with open(path) as f:
        return {ln.strip() for ln in f if ln.strip() and not ln.startswith("#")}


def bionic_exports(libdir, label="Android 4.4"):
    """Text of bionic44-exports.txt (or a JB base's list): the defined GLOBAL/WEAK dynamic symbols of the four libraries
    the .so may need; label names the build in the header."""
    names = set()
    head = ["# Defined GLOBAL/WEAK dynamic symbols of the bionic libraries a Conscrypt .so may need (check_prebuilt.py",
            "# --stage, check so-symbols); %s. Regenerate: python3 -I check_prebuilt.py --bionic-exports" % label,
            "# <PRODUCT_OUT>/system/lib (or obj/lib) of a build of the ABI --label TEXT; from:"]
    for lib in ("libc.so", "libdl.so", "libm.so", "liblog.so"):
        with open(os.path.join(libdir, lib), "rb") as f:
            data = f.read()
        names.update(Elf32(data).defined_dynsyms())
        head.append("#   %s  %s" % (sha256(data), lib))
    return "\n".join(head + sorted(names)) + "\n"


def check_symbols(so, bionic, res, prefix="", base="4.4", with_compat=False):
    try:
        und = Elf32(so).undefined_dynsyms()
    except (ValueError, IndexError, struct.error) as e:
        res[prefix + "so-symbols"] = (False, str(e))
        return
    missing = sorted(n for n, b in und if b == "GLOBAL" and n not in bionic)
    weak = sorted(n for n, b in und if b == "WEAK" and n not in bionic)
    where = "the %s bionic%s" % (base, " + libkktls_compat.so" if with_compat else "")
    msg = "%d undefined, all GLOBAL ones in %s" % (len(und), where)
    if missing:
        msg = "undefined GLOBAL not in %s: %s" % (where, " ".join(missing))
    if weak:
        msg += "; WEAK unresolved (BoringSSL checks them for NULL, e.g. the malloc hooks in crypto/mem.cc): %s" % " ".join(weak)
    res[prefix + "so-symbols"] = (not missing, msg)


def dex_checksum(d):
    return zlib.adler32(d[12:]) & 0xFFFFFFFF


def check_dexjar(jar, res, jb=False):
    names = ("dex-jar", "dex-classes", "dex-jni-name", "dex-properties")
    try:
        z = zipfile.ZipFile(io.BytesIO(jar))
        members = z.namelist()
        data = {n: z.read(n) for n in members if n in STAGE_DEX_MEMBERS}  # CRC-checked
    except (zipfile.BadZipFile, zlib.error) as e:
        for c in names:
            res[c] = (False, "dex jar: %s" % e)
        return
    dex = data.get("classes.dex")
    bad = []
    if sorted(members) != sorted(STAGE_DEX_MEMBERS):
        cls = [n for n in members if n.endswith(".class")]
        bad.append("members %s%s (want exactly %s)" % (
            ", ".join(sorted(members)[:4]), " ... (%d .class files: not dexed)" % len(cls) if cls else "",
            " + ".join(STAGE_DEX_MEMBERS)))
    if dex is not None:
        if dex[:8] != b"dex\n035\0":
            bad.append("dex magic %r (4.4 Dalvik reads 035)" % dex[:8])
        elif len(dex) < 0x70 or struct.unpack_from("<I", dex, 8)[0] != dex_checksum(dex):
            bad.append("dex adler32 checksum does not match the header")
    res["dex-jar"] = (not bad, "; ".join(bad) or "classes.dex (035, %d B, checksum OK) + %s" % (len(dex), PROPERTIES))
    if dex is None or bad:
        res["dex-classes"] = res["dex-jni-name"] = (False, "no valid classes.dex")
    else:
        try:
            strings, types, classes = dex_tables(dex)
        except ValueError as e:
            res["dex-classes"] = res["dex-jni-name"] = (False, "dex ids: %s" % e)
        else:
            outside = [c for c in classes if not c.startswith("Lorg/conscrypt/")]
            want = ["L%s;" % n[:-len(".class")] for n in REQUIRED_CLASSES]
            missing = [c for c in want if c not in classes]
            bad = []
            if outside:
                bad.append("classes outside org/conscrypt/: %s" % outside[:5])
            if missing:
                bad.append("missing %s" % missing)
            count = STAGE_CLASS_COUNT_JB if jb else STAGE_CLASS_COUNT
            if len(classes) != count:
                bad.append("%d class_defs (want %d)" % (len(classes), count))
            if jb and JB_SHIM_TYPE not in classes:
                bad.append("no %s (jb_charsets.py did not run)" % JB_SHIM_TYPE)
            if jb and JB_ABSENT_TYPE in types:
                bad.append("references %s (API 19)" % JB_ABSENT_TYPE)
            if jb and any(JB_ABSENT_DOTTED in x for x in strings):
                bad.append("a string holds %s (reflection would load the API 19 class)" % JB_ABSENT_DOTTED)
            res["dex-classes"] = (not bad, "; ".join(bad) or "%d class_defs, all under org/conscrypt/%s" % (
                len(classes), ", no StandardCharsets" if jb else ""))
            has_new, has_old = "kktls_conscrypt_jni" in strings, "conscrypt_jni" in strings
            res["dex-jni-name"] = (has_new and not has_old,
                                   "kktls_conscrypt_jni %s, conscrypt_jni %s" % ("present" if has_new else "MISSING",
                                                                              "PRESENT" if has_old else "absent"))
    if PROPERTIES not in members:
        res["dex-properties"] = (False, "no %s" % PROPERTIES)
        return
    props = {}
    for line in data[PROPERTIES].decode("latin-1").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    diff = ["%s=%s (want %s)" % (k, props.get(k), v) for k, v in sorted(STAGE_PROPERTIES.items()) if props.get(k) != v]
    res["dex-properties"] = (not diff, "; ".join(diff) or "2.6.0, BoringSSL %s" %
                             STAGE_PROPERTIES["org.conscrypt.boringssl.version"][:8])


def check_notice(path, sums, res):
    if not os.path.isfile(path):
        res["notice"] = (False, "%s is missing" % path)
        return
    with open(path, "rb") as f:
        data = f.read()
    bad = []
    got = sha256(data)
    if got != sums.get(NOTICE_NAME):
        bad.append("sha256 %s (pinned %s)" % (got, sums.get(NOTICE_NAME)))
    text = data.decode("utf-8", "replace")
    bad += ["does not name %s" % n for n in NOTICE_MUST_NAME if n not in text]
    res["notice"] = (not bad, "; ".join(bad) or "%s = pin %s" % (os.path.basename(path), got[:8]))


def compat_exports(data):
    """The defined GLOBAL/WEAK dynamic symbols of a compat library without COMPAT_CRT_EXPORTS."""
    return set(Elf32(data).defined_dynsyms()) - COMPAT_CRT_EXPORTS


def check_compat(lib, base, abi, bionic, so_undef, sums, res):
    """The compat / x86-compat check of one ABI; lib = the library bytes or None; so_undef = the undefined GLOBAL
    symbols of the Conscrypt .so of that ABI."""
    name = ("x86-" if abi == "x86" else "") + "compat"
    want = JB_MISSING.get((base, abi), set())
    if not want:
        res[name] = (lib is None, "%s given, but the %s %s bionic misses nothing" % (COMPAT_NAME, base, abi)
                     if lib is not None else "not needed: the %s %s bionic exports every import" % (base, abi))
        return
    if lib is None:
        res[name] = (False, "%s needed on %s %s (%s); none given (--compat%s)"
                     % (COMPAT_NAME, base, abi, " ".join(sorted(want)), "-x86" if abi == "x86" else ""))
        return
    bad = []
    try:
        elf = Elf32(lib)
        dyn = elf.dynamic()
        needed = elf.dyn_strings(dyn, DT_NEEDED)
        defined = elf.defined_dynsyms()
        undef = elf.undefined_dynsyms()
    except (ValueError, IndexError, StopIteration, struct.error) as e:
        res[name] = (False, "%s: %s" % (COMPAT_NAME, e))
        return
    machine = EM_386 if abi == "x86" else EM_ARM
    if elf.e_machine != machine or elf.e_type != ET_DYN:
        bad.append("e_machine %d e_type %d (want %s ET_DYN)" % (elf.e_machine, elf.e_type, MACHINE_NAMES[machine]))
    if DT_HASH not in {t for t, _ in dyn}:
        bad.append("no DT_HASH")
    pin = sums.get(compat_pin(base, abi))
    if sha256(lib) != pin:
        bad.append("sha256 %s (pinned %s: %s)" % (sha256(lib), compat_pin(base, abi), pin))
    exports = set(defined) - COMPAT_CRT_EXPORTS
    if exports != want:
        bad.append("exports %s, want exactly %s" % (" ".join(sorted(exports)) or "-", " ".join(sorted(want))))
    shadow = sorted(exports & bionic)
    if shadow:
        bad.append("exports bionic symbols %s" % " ".join(shadow))
    crt = sorted(COMPAT_CRT_EXPORTS & set(so_undef))
    if crt:
        bad.append("the Conscrypt .so imports %s" % " ".join(crt))
    missing = sorted(n for n, b in undef if b == "GLOBAL" and n not in bionic)
    if missing:
        bad.append("imports not in the %s bionic: %s" % (base, " ".join(missing)))
    extra = sorted(set(needed) - COMPAT_ALLOWED_NEEDED)
    if extra:
        bad.append("NEEDED %s (want libc/liblog only)" % " ".join(extra))
    res[name] = (not bad, "; ".join(bad) or "%s = pin %s, exports %s, %d imports in the %s bionic, NEEDED %s"
                 % (COMPAT_NAME, pin[:8], " ".join(sorted(exports)), len(undef), base, " ".join(needed)))


def check_stage(stage, sums, notice, bionic, bionic_x86, base="4.4", jb=False, compat=None, compat_x86=None):
    """{check: (ok, message)} for every name in CHECKS_STAGE; stage = the directory holding the stage files.
    bionic / bionic_x86: the export sets of the bionic of each ABI (so-symbols / x86-so-symbols) of base.
    jb: the Jelly Bean stage (its dex jar pin, class count, the StandardCharsets shim). compat / compat_x86: the bytes of
    libkktls_compat.so of the ABI (a JB base that needs it): that ABI's .so checks take the stage's jb-compat/ file."""
    res = {}
    files = {}
    absent = []
    dexkey = STAGE_DEXJAR_JB if jb else STAGE_DEXJAR
    so_key = STAGE_SO_COMPAT if compat is not None else STAGE_SO
    so_x86_key = STAGE_SO_COMPAT_X86 if compat_x86 is not None else STAGE_SO_X86
    for key, rel in ((dexkey, STAGE_DEXJAR), (so_key, so_key), (so_x86_key, so_x86_key)):
        p = os.path.join(stage, rel.split("/", 1)[1])
        if os.path.isfile(p):
            with open(p, "rb") as f:
                files[key] = f.read()
        else:
            absent.append(p)
    res["stage-present"] = (not absent, ("missing: %s (stage it with mkstage.py, version %s)"
                                         % (" ".join(absent), STAGE_VERSION)) if absent else stage)
    bad = ["%s sha256 %s (pinned %s)" % (k, sha256(v), sums.get(k)) for k, v in sorted(files.items())
           if sha256(v) != sums.get(k)]
    res["stage-sha256"] = (not absent and not bad, "; ".join(bad) or ("not run: files missing" if absent else
                           "%sdex jar %s, .so %s, x86 .so %s" % ("JB " if jb else "", sums[dexkey][:8],
                                                                 sums[so_key][:8], sums[so_x86_key][:8])))
    if dexkey in files:
        check_dexjar(files[dexkey], res, jb)
    else:
        for c in ("dex-jar", "dex-classes", "dex-jni-name", "dex-properties"):
            res[c] = (False, "no dex jar")
    for key, machine, prefix, syms, lib, abi in ((so_key, EM_ARM, "", bionic, compat, "arm"),
                                                 (so_x86_key, EM_386, "x86-", bionic_x86, compat_x86, "x86")):
        extra = set()
        if lib is not None:
            try:
                extra = compat_exports(lib)
            except (ValueError, IndexError, struct.error):
                pass  # the compat check reports it
        if key in files:
            check_so(files[key], res, machine, prefix, compat=lib is not None)
            check_symbols(files[key], syms | extra, res, prefix, base, with_compat=lib is not None)
            for c in SO_CHECKS[1:]:
                res.setdefault(prefix + c, (False, "not run: %s" % res[prefix + "so-elf"][1]))
        else:
            for c in SO_CHECKS:
                res[prefix + c] = (False, "no %s" % key.split("/", 1)[1])
        if base != "4.4":
            try:
                und = [n for n, b in Elf32(files[key]).undefined_dynsyms() if b == "GLOBAL"] if key in files else []
            except (ValueError, IndexError, struct.error):
                und = []
            check_compat(lib, base, abi, syms, und, sums, res)
    check_notice(notice, sums, res)
    return res


def stage_checks(res):
    """CHECKS_STAGE, plus compat / x86-compat for a JB base."""
    return CHECKS_STAGE + [c for c in COMPAT_CHECKS if c in res]


def report_stage(res, out=sys.stdout):
    names = stage_checks(res)
    for c in names:
        ok, msg = res[c]
        print("%-4s %-15s %s" % ("PASS" if ok else "FAIL", c, msg), file=out)
    failed = [c for c in names if not res[c][0]]
    print("RESULT %s (%d of %d)" % ("PASS" if not failed else "FAIL", len(names) - len(failed), len(names)), file=out)
    return 1 if failed else 0


# ---------------------------------------------------------------------------------------------------------- selftest

def rewrite_zip(data, edit, add=()):
    """Zip bytes -> zip bytes: edit(name, member) returns the new member data or None to drop it, or a (new_name, data)
    pair to rename it; `add` is a sequence of (name, data) members appended at the end."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as zi, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for info in zi.infolist():
            new = edit(info.filename, zi.read(info.filename))
            if new is None:
                continue
            if isinstance(new, tuple):
                info = zipfile.ZipInfo(new[0], info.date_time)
                new = new[1]
            zo.writestr(info, new)
        for name, d in add:
            zo.writestr(name, d)
    return out.getvalue()


def patch_dynamic(so, pick, new_tag=None, or_value=0):
    """Rewrites the first dynamic entry whose tag satisfies pick(tag): its tag (new_tag) and/or value (| or_value)."""
    elf = Elf32(so)
    b = bytearray(so)
    for p_type, p_offset, _, _, p_filesz, _, _, _ in elf.phdrs:
        if p_type != PT_DYNAMIC:
            continue
        for i in range(p_filesz // 8):
            off = p_offset + i * 8
            tag, val = struct.unpack_from("<iI", b, off)
            if tag == DT_NULL:
                break
            if pick(tag & 0xFFFFFFFF):
                struct.pack_into("<II", b, off, (tag & 0xFFFFFFFF) if new_tag is None else new_tag, val | or_value)
                return bytes(b)
    raise ValueError("no dynamic entry to patch")


def patch_phdr_type(so, old, new):
    elf = Elf32(so)
    b = bytearray(so)
    for i, ph in enumerate(elf.phdrs):
        if ph[0] == old:
            struct.pack_into("<I", b, elf.e_phoff + i * elf.e_phentsize, new)
            return bytes(b)
    raise ValueError("no program header of type 0x%x" % old)


# dynamic tags the 4.4 linker ignores or that only carry counts/versions; a selftest may turn one of them into another
# tag without breaking the checks it does not target
DT_SPARE = (0x6FFFFFFA, 0x6FFFFFFB, 0x6FFFFFF0, 0x6FFFFFFC, 0x6FFFFFFD, 0x6FFFFFFE, 0x6FFFFFFF, 0x6FFFFEF5)
PT_GNU_STACK = 0x6474E551


def selftest(aar, sums):
    """Each case mutates a copy of the real aar and names the checks that must fail: with exact=True exactly those
    (the mutated members' sha256 are re-pinned for the case, so only the targeted check reacts), else at least them."""
    tmp = tempfile.mkdtemp(prefix="check-prebuilt-selftest-")
    failures = []
    with open(aar, "rb") as f:
        real = f.read()
    members = {n: zipfile.ZipFile(io.BytesIO(real)).read(n) for n in (CLASSES, SO)}

    def case(name, data, expect, exact=True, pin="consistent"):
        """pin: "real" = the repository's SHA256SUMS; "consistent" = aar and members re-pinned to this fixture;
        "aar" = only the aar re-pinned (the member sha256 stay the real ones)."""
        path = os.path.join(tmp, "case.aar")
        if data is None:
            path = os.path.join(tmp, "nope.aar")
        else:
            with open(path, "wb") as f:
                f.write(data)
        s = dict(sums)
        if data is not None and pin != "real":
            s[AAR_NAME] = sha256(data)
            if pin == "consistent":
                try:
                    z = zipfile.ZipFile(io.BytesIO(data))
                    for n in (CLASSES, SO):
                        if n in z.namelist():
                            s[n] = sha256(z.read(n))
                except zipfile.BadZipFile:
                    pass
        res = check_aar(path, s)
        failed = {c for c in CHECKS if not res[c][0]}
        want = set(expect)
        ok = failed == want if exact else want <= failed
        print("selftest %s %-40s failed=%s%s" % ("ok  " if ok else "FAIL", name, ",".join(sorted(failed)) or "-",
                                                 "" if ok else "  (want %s%s)" % ("exactly " if exact else "",
                                                                                    ",".join(sorted(want)) or "-")))
        if not ok:
            failures.append(name)

    def so_case(name, fn, expect):
        case(name, rewrite_zip(real, lambda n, d: fn(d) if n == SO else d), expect)

    def jar_case(name, fn, expect, add=()):
        case(name, rewrite_zip(real, lambda n, d: rewrite_zip(d, fn, add) if n == CLASSES else d), expect)

    def set_machine(d):
        b = bytearray(d)
        struct.pack_into("<H", b, 18, 3)  # EM_386
        return bytes(b)

    def bump_major(n, d):
        if n == "org/conscrypt/Conscrypt.class":
            b = bytearray(d)
            struct.pack_into(">H", b, 6, 52)
            return bytes(b)
        return d

    with zipfile.ZipFile(io.BytesIO(members[CLASSES])) as zj:
        victim = next(n for n in zj.namelist() if n.endswith(".class") and n not in REQUIRED_CLASSES)

    try:
        case("pristine aar", real, (), pin="real")
        case("missing aar", None, CHECKS)
        flipped = bytearray(real)
        flipped[len(flipped) // 2] ^= 0xFF
        case("one byte flipped", bytes(flipped), ("aar-sha256",), exact=False, pin="real")
        case("aar re-zipped, members unchanged", rewrite_zip(real, lambda n, d: d), ("aar-sha256",), pin="real")
        case(".so one byte longer (member sha256)", rewrite_zip(real, lambda n, d: d + b"\0" if n == SO else d),
             ("members-sha256",), pin="aar")
        so_case("NEEDED libssl instead of liblog", lambda d: d.replace(b"liblog.so\0", b"libssl.so\0", 1), ("so-needed",))
        so_case("x86 e_machine", set_machine, ("so-elf",))
        so_case("no DT_HASH (GNU hash only)", lambda d: patch_dynamic(d, lambda t: t == DT_HASH, 0x6FFFFEF5),
                ("so-loader",))
        so_case("PT_TLS segment", lambda d: patch_phdr_type(d, PT_GNU_STACK, PT_TLS), ("so-loader",))
        so_case("DT_TEXTREL", lambda d: patch_dynamic(d, lambda t: t in DT_SPARE, DT_TEXTREL), ("so-loader",))
        so_case("DF_TEXTREL in DT_FLAGS", lambda d: patch_dynamic(d, lambda t: t == DT_FLAGS, or_value=DF_TEXTREL)
                if DT_FLAGS in {t for t, _ in Elf32(d).dynamic()}
                else patch_dynamic(d, lambda t: t in DT_SPARE, DT_FLAGS, or_value=DF_TEXTREL), ("so-loader",))
        so_case("DT_RELR packed relocations", lambda d: patch_dynamic(d, lambda t: t in DT_SPARE, DT_RELR),
                ("so-loader",))
        so_case("DT_ANDROID_REL (APS2) relocations", lambda d: patch_dynamic(d, lambda t: t in DT_SPARE,
                                                                               DT_ANDROID_REL), ("so-loader",))
        so_case("no JNI_OnLoad export", lambda d: d.replace(b"JNI_OnLoad\0", b"JNI_OnLoax\0", 1), ("so-exports",))
        case("no armeabi-v7a .so", rewrite_zip(real, lambda n, d: None if n == SO else d),
             ("members-sha256", "so-elf", "so-needed", "so-loader", "so-exports"))
        jar_case("class major 52", bump_major, ("class-major",))
        jar_case("class moved outside org/conscrypt (count kept)",
                 lambda n, d: ("java/lang/KktlsShadow.class", d) if n == victim else d, ("class-packages",))
        jar_case("one class more (count 309)", lambda n, d: d,
                 ("class-packages",), add=(("org/conscrypt/KktlsExtra.class", b"\xca\xfe\xba\xbe\0\0\0\x33"),))
        jar_case("required class missing", lambda n, d: None if n == REQUIRED_CLASSES[-1] else d, ("class-packages",))
        jar_case("other BoringSSL pin", lambda n, d: d.replace(b"49f0329110a1", b"207b6541e100", 1)
                 if n == PROPERTIES else d, ("properties",))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("SELFTEST %s" % ("PASS" if not failures else "FAIL: " + ", ".join(failures)))
    return 1 if failures else 0


def selftest_stage(stage, sums, notice, bionic, bionic_x86, alpha3=None, jb=None, jb_dexjar=None):
    """Mutated copies of the real stage; each case names exactly the checks that must fail (the mutated files are
    re-pinned for the case, so only the targeted check reacts). With alpha3 (the real 2.6-alpha3 aar, sha256 pinned as
    negative/...), its armeabi-v7a .so must fail so-symbols. jb = {base: (ARM export set, x86 export set)}: the pristine
    stage against each JB base fails exactly the so-symbols checks of the ABIs JB_MISSING names, and misses exactly
    JB_MISSING there. jb_dexjar (the real mkstage.py --jb dex jar, pinned): the JB stage passes on 4.3 with --jb, and each
    dex jar fails stage-sha256 and dex-classes when checked as the other."""
    tmp = tempfile.mkdtemp(prefix="check-prebuilt-stage-selftest-")
    failures = []
    files = {}
    for key in (STAGE_DEXJAR, STAGE_SO, STAGE_SO_X86):
        with open(os.path.join(stage, key.split("/", 1)[1]), "rb") as f:
            files[key] = f.read()
    with open(notice, "rb") as f:
        notice_data = f.read()

    def case(name, expect, dexjar=None, so=None, notice_bytes=None, pin=True, missing=(), so_x86=None, base="4.4",
             jbdex=False, compat=None, compat_x86=None, unpinned=()):
        d = os.path.join(tmp, "case")
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        cur = {STAGE_DEXJAR: files[STAGE_DEXJAR] if dexjar is None else dexjar,
               STAGE_SO: files[STAGE_SO] if so is None else so,
               STAGE_SO_X86: files[STAGE_SO_X86] if so_x86 is None else so_x86,
               STAGE_SO_COMPAT: edited[0] if so is None else so, STAGE_SO_COMPAT_X86: edited[1] if so_x86 is None else so_x86}
        s = dict(sums)
        for abi, lib in (("arm", compat), ("x86", compat_x86)):
            if lib is not None and abi not in unpinned:
                s[compat_pin(base, abi)] = sha256(lib)
        for k, v in cur.items():
            if k in missing:
                continue
            os.makedirs(os.path.dirname(os.path.join(d, k.split("/", 1)[1])), exist_ok=True)
            with open(os.path.join(d, k.split("/", 1)[1]), "wb") as f:
                f.write(v)
            if pin:
                s[k] = sha256(v)
                if k == STAGE_DEXJAR:
                    s[STAGE_DEXJAR_JB] = sha256(v)
        npath = os.path.join(d, NOTICE_NAME)
        nb = notice_data if notice_bytes is None else notice_bytes
        with open(npath, "wb") as f:
            f.write(nb)
        if pin and notice_bytes is not None and notice_bytes[:1] != b"#":  # "#..." = keep the real pin
            s[NOTICE_NAME] = sha256(nb)
        syms = (bionic, bionic_x86) if base == "4.4" else jb[base]
        res = check_stage(d, s, npath, syms[0], syms[1], base, jbdex, compat, compat_x86)
        failed = {c for c in stage_checks(res) if not res[c][0]}
        ok = failed == set(expect)
        print("selftest %s %-44s failed=%s%s" % ("ok  " if ok else "FAIL", name, ",".join(sorted(failed)) or "-",
                                                 "" if ok else "  (want exactly %s)" % (",".join(sorted(expect)) or "-")))
        if not ok:
            failures.append(name)

    def dex_edit(fn, jar=None):
        def edit(n, d):
            if n != "classes.dex":
                return d
            b = bytearray(fn(bytearray(d)))
            struct.pack_into("<I", b, 8, dex_checksum(bytes(b)))
            return bytes(b)
        return rewrite_zip(files[STAGE_DEXJAR] if jar is None else jar, edit)

    def rename_string(old, new):
        def fn(b):
            i = bytes(b).index(bytes([len(old)]) + old + b"\0")
            b[i:i + len(old) + 2] = bytes([len(new)]) + new + b"\0" + b"\0" * (len(old) - len(new))
            return b
        return fn

    import jb_needed  # noqa: E402  (same directory, on sys.path)
    edited = (jb_needed.edit(files[STAGE_SO])[0], jb_needed.edit(files[STAGE_SO_X86])[0])

    def fake_compat(abi, names, needed=(b"liblog.so", b"libc.so")):
        """A synthetic libkktls_compat.so exporting names (defined GLOBAL functions, no imports)."""
        return jb_needed._so(machine=EM_386 if abi == "x86" else EM_ARM, needed=needed, soname=COMPAT_NAME.encode(),
                             syms=tuple(n.encode() for n in sorted(names)))

    so_undef = [n for n, bind in Elf32(files[STAGE_SO]).undefined_dynsyms() if bind == "GLOBAL"]
    victim = next(n for n in sorted(so_undef) if len(n) > 4 and so_undef.count(n) == 1 and
                  files[STAGE_SO].count(b"\0" + n.encode() + b"\0") == 1)
    renamed_victim = victim[:-1] + ("X" if victim[-1] != "X" else "Y")
    x86 = files[STAGE_SO_X86]
    x86_undef = [n for n, bind in Elf32(x86).undefined_dynsyms() if bind == "GLOBAL"]
    x86_victim = next(n for n in sorted(x86_undef) if len(n) > 4 and x86_undef.count(n) == 1 and
                      x86.count(b"\0" + n.encode() + b"\0") == 1)
    x86_renamed = x86_victim[:-1] + ("X" if x86_victim[-1] != "X" else "Y")
    so_checks_x86 = tuple("x86-" + c for c in SO_CHECKS)

    try:
        case("pristine stage", (), pin=False)
        for b in sorted(jb or {}, reverse=True):
            case("pristine stage, %s bionic" % b, (("so-symbols", "compat") if JB_MISSING[(b, "arm")] else ()) +
                 (("x86-so-symbols", "x86-compat") if JB_MISSING[(b, "x86")] else ()), pin=False, base=b)
            libs = {abi: fake_compat(abi, JB_MISSING[(b, abi)]) if needs_compat(b, abi) else None for abi in ("arm", "x86")}
            if not any(libs.values()):
                case("%s: an edited .so and a compat lib given" % b, ("compat",), base=b,
                     so=edited[0], compat=fake_compat("arm", ["getauxval"]))
                continue
            case("%s: jb-compat .so + compat libs (%s)" % (b, ",".join(a for a in libs if libs[a])), (), base=b,
                 compat=libs["arm"], compat_x86=libs["x86"])
            abi = "arm" if libs["arm"] else "x86"
            p = "" if abi == "arm" else "x86-"
            kw = {"compat": libs["arm"], "compat_x86": libs["x86"], "base": b}
            one = sorted(JB_MISSING[(b, abi)])[0]

            def with_lib(lib, abi=abi, kw=kw):
                k = dict(kw)
                k["compat" if abi == "arm" else "compat_x86"] = lib
                return k
            case("%s %s compat also exports memcpy (a libc function)" % (b, abi), (p + "compat",),
                 **with_lib(fake_compat(abi, JB_MISSING[(b, abi)] | {"memcpy"})))
            case("%s %s compat lacks %s" % (b, abi, one), (p + "compat", p + "so-symbols"),
                 **with_lib(fake_compat(abi, JB_MISSING[(b, abi)] - {one})))
            case("%s %s compat NEEDED libssl" % (b, abi), (p + "compat",),
                 **with_lib(fake_compat(abi, JB_MISSING[(b, abi)], needed=(b"libssl.so", b"libc.so"))))
            case("%s %s compat not the pinned bytes" % (b, abi), (p + "compat",), unpinned=(abi,), **kw)
            case("%s %s compat of the other ABI" % (b, abi), (p + "compat",),
                 **with_lib(fake_compat("x86" if abi == "arm" else "arm", JB_MISSING[(b, abi)])))
            k = dict(kw)
            k["so" if abi == "arm" else "so_x86"] = files[STAGE_SO if abi == "arm" else STAGE_SO_X86]
            case("%s %s pristine .so with the compat lib" % (b, abi), (p + "so-elf", p + "so-needed"), **k)
            for abi, data, exports in (("arm", files[STAGE_SO], jb[b][0]), ("x86", files[STAGE_SO_X86], jb[b][1])):
                got = {n for n, bind in Elf32(data).undefined_dynsyms() if bind == "GLOBAL"} - exports
                ok = got == JB_MISSING[(b, abi)]
                print("selftest %s %-44s %s" % ("ok  " if ok else "FAIL", "%s %s misses exactly JB_MISSING" % (b, abi),
                                                " ".join(sorted(got)) or "-"))
                if not ok:
                    failures.append("%s %s missing set" % (b, abi))
        case("missing stage files", ("stage-present", "stage-sha256", "dex-jar", "dex-classes", "dex-jni-name",
                                     "dex-properties") + tuple(SO_CHECKS) + so_checks_x86,
             missing=(STAGE_DEXJAR, STAGE_SO, STAGE_SO_X86))
        case("x86 .so missing (an ARM-only stage)", ("stage-present", "stage-sha256") + so_checks_x86,
             missing=(STAGE_SO_X86,))
        x86_flip = bytearray(x86)
        x86_flip[len(x86_flip) // 2] ^= 0xFF
        case("x86 .so one byte flipped (real pins)", ("stage-sha256",), so_x86=bytes(x86_flip), pin=False)
        case("ARM .so in the x86 place", ("x86-so-elf",) + (("x86-so-symbols",) if set(so_undef) - bionic_x86 else ()),
             so_x86=files[STAGE_SO])
        case("x86 .so in the ARM place", ("so-elf",) + (("so-symbols",) if set(x86_undef) - bionic else ()),
             so=x86)
        case("x86 NEEDED libssl instead of liblog", ("x86-so-needed",),
             so_x86=x86.replace(b"liblog.so\0", b"libssl.so\0", 1))
        case("x86 undefined GLOBAL %s -> %s (not in bionic)" % (x86_victim, x86_renamed), ("x86-so-symbols",),
             so_x86=x86.replace(b"\0" + x86_victim.encode() + b"\0", b"\0" + x86_renamed.encode() + b"\0", 1))
        flipped = bytearray(files[STAGE_DEXJAR])
        flipped[len(flipped) // 2] ^= 0xFF
        case("dex jar one byte flipped (real pins)", ("stage-sha256", "dex-jar", "dex-classes", "dex-jni-name",
                                                      "dex-properties"),
             dexjar=bytes(flipped), pin=False)
        with zipfile.ZipFile(io.BytesIO(files[STAGE_DEXJAR])) as z:
            props = z.read(PROPERTIES)
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as z:  # a class-52 jar that skipped d8 (one class, the properties)
            cls = bytearray(b"\xca\xfe\xba\xbe\x00\x00\x00\x34")
            z.writestr("org/conscrypt/NativeCryptoJni.class", bytes(cls))
            z.writestr(PROPERTIES, props)
        case("class-52 jar without d8 as the dex jar", ("dex-jar", "dex-classes", "dex-jni-name"),
             dexjar=raw.getvalue())
        case("dex magic 039", ("dex-jar", "dex-classes", "dex-jni-name"),
             dexjar=dex_edit(lambda b: b[:4] + b"039" + b[7:]))
        case("dex checksum wrong", ("dex-jar", "dex-classes", "dex-jni-name"),
             dexjar=rewrite_zip(files[STAGE_DEXJAR], lambda n, d: d[:8] + bytes([d[8] ^ 1]) + d[9:]
                                if n == "classes.dex" else d))
        case("extra member", ("dex-jar", "dex-classes", "dex-jni-name"),
             dexjar=rewrite_zip(files[STAGE_DEXJAR], lambda n, d: d, add=(("META-INF/x", b"x"),)))
        case("JNI name not renamed", ("dex-jni-name",),
             dexjar=dex_edit(rename_string(b"kktls_conscrypt_jni", b"conscrypt_jni")))
        case("JNI name missing", ("dex-jni-name",),
             dexjar=dex_edit(rename_string(b"kktls_conscrypt_jni", b"kktls_conscrypt_jnX")))
        case("class outside org/conscrypt", ("dex-classes",),
             dexjar=dex_edit(rename_string(b"Lorg/conscrypt/NativeRef$0;", b"Ljava/lang/NativeRef$;")))
        case("other BoringSSL pin", ("dex-properties",),
             dexjar=rewrite_zip(files[STAGE_DEXJAR], lambda n, d: d.replace(b"f91f1447", b"49f03291", 1)
                                if n == PROPERTIES else d))
        case("NEEDED libssl instead of liblog", ("so-needed",),
             so=files[STAGE_SO].replace(b"liblog.so\0", b"libssl.so\0", 1))
        case("no DT_HASH (GNU hash only)", ("so-loader",),
             so=patch_dynamic(files[STAGE_SO], lambda t: t == DT_HASH, 0x6FFFFEF5))
        case("DT_TEXTREL", ("so-loader",), so=patch_dynamic(files[STAGE_SO], lambda t: t in DT_SPARE, DT_TEXTREL))
        case("undefined GLOBAL %s -> %s (not in bionic)" % (victim, renamed_victim), ("so-symbols",),
             so=files[STAGE_SO].replace(b"\0" + victim.encode() + b"\0", b"\0" + renamed_victim.encode() + b"\0", 1))
        case("no JNI_OnLoad export", ("so-exports",), so=files[STAGE_SO].replace(b"JNI_OnLoad\0", b"JNI_OnLoax\0", 1))
        case("NOTICE one byte changed (real pin)", ("notice",), notice_bytes=b"#" + notice_data[1:])
        case("NOTICE of another release (re-pinned)", ("notice",),
             notice_bytes=notice_data.replace(b"google/conscrypt 2.6-alpha2", b"google/conscrypt 2.5.3"))
        if alpha3:
            with open(alpha3, "rb") as f:
                a3 = f.read()
            if sha256(a3) != sums.get(ALPHA3_AAR):
                print("selftest FAIL alpha3 fixture sha256 %s is not the pin %s" % (sha256(a3), sums.get(ALPHA3_AAR)))
                failures.append("alpha3 fixture")
            else:
                a3so = zipfile.ZipFile(io.BytesIO(a3)).read(SO)
                case("real 2.6-alpha3 .so (NDK r27/r28)", ("so-symbols",), so=a3so)
        else:
            print("selftest skip real 2.6-alpha3 .so (no --alpha3 AAR)")
        if jb_dexjar:
            with open(jb_dexjar, "rb") as f:
                jd = f.read()
            if sha256(jd) != sums.get(STAGE_DEXJAR_JB):
                print("selftest FAIL JB dex jar sha256 %s is not the pin %s" % (sha256(jd), sums.get(STAGE_DEXJAR_JB)))
                failures.append("JB dex jar")
            else:
                case("JB stage (real pins), 4.3 bionic", (), dexjar=jd, pin=False, base="4.3", jbdex=True)
                case("JB stage, 4.3: the edited .so in the aar .so's place", ("so-elf", "so-needed"), dexjar=jd,
                     base="4.3", jbdex=True, so=edited[0])
                case("4.4 dex jar checked as the JB one", ("stage-sha256", "dex-classes"), pin=False, base="4.3",
                     jbdex=True)
                case("JB dex jar checked as the 4.4 one", ("stage-sha256", "dex-classes"), dexjar=jd, pin=False)
                case("JB dex jar with a dotted StandardCharsets string", ("dex-classes",), base="4.3", jbdex=True,
                     dexjar=dex_edit(rename_string(b"Alg.Alias.CertificateFactory.X.509", JB_ABSENT_DOTTED.encode()),
                                     jd))
        else:
            print("selftest skip JB dex jar cases (no --jb-dexjar FILE)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("SELFTEST %s" % ("PASS" if not failures else "FAIL: " + ", ".join(failures)))
    return 1 if failures else 0


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("aar", nargs="?")
    ap.add_argument("--sums", default=os.path.join(here, "SHA256SUMS"))
    ap.add_argument("--selftest", action="store_true",
                    help="mutate copies of AAR (or of the --stage files); each case names the checks that must fail")
    ap.add_argument("--stage", metavar="DIR", help="check the %s stage directory instead of an aar" % STAGE_VERSION)
    ap.add_argument("--notice", default=os.path.join(here, NOTICE_NAME))
    ap.add_argument("--base", choices=sorted(BASES), default="4.4",
                    help="--stage: the Android base whose bionic export lists so-symbols uses (default 4.4)")
    ap.add_argument("--bionic", help="ARM export list (default: the --base list, %s for 4.4)" % BIONIC_EXPORTS)
    ap.add_argument("--bionic-x86", help="x86 export list (default: the --base list, %s for 4.4)" % BIONIC_EXPORTS_X86)
    ap.add_argument("--label", default="Android 4.4", help="--bionic-exports: the build named in the list header")
    ap.add_argument("--alpha3", metavar="AAR", help="--selftest --stage: the real 2.6-alpha3 aar as a negative fixture")
    ap.add_argument("--jb", action="store_true",
                    help="--stage: the Jelly Bean stage of mkstage.py --jb (its dex jar pin %s)" % STAGE_DEXJAR_JB)
    ap.add_argument("--jb-dexjar", metavar="FILE", help="--selftest --stage: the real JB dex jar (mkstage.py --jb)")
    ap.add_argument("--compat", metavar="FILE", help="--stage, JB base: the ARM libkktls_compat.so of that base's tree")
    ap.add_argument("--compat-x86", metavar="FILE", help="--stage, JB base: the x86 libkktls_compat.so")
    ap.add_argument("--jb-missing", metavar="BASE", choices=sorted(b for b in BASES if b != "4.4"),
                    help="print '<abi> <symbols>' for each ABI of BASE that needs libkktls_compat.so, and exit")
    ap.add_argument("--bionic-exports", metavar="LIBDIR", help="print the bionic export list of LIBDIR and exit")
    a = ap.parse_args()
    if a.jb_missing:
        for abi in ("arm", "x86"):
            if needs_compat(a.jb_missing, abi):
                print("%s %s" % (ABI_NAMES[abi], " ".join(sorted(JB_MISSING[(a.jb_missing, abi)]))))
        return 0
    if a.bionic_exports:
        sys.stdout.write(bionic_exports(a.bionic_exports, a.label))
        return 0
    if a.stage:
        sums = read_sums(a.sums, (STAGE_DEXJAR, STAGE_DEXJAR_JB, STAGE_SO, STAGE_SO_X86, NOTICE_NAME))
        bionic = read_bionic(a.bionic or os.path.join(here, BASES[a.base][0]))
        bionic_x86 = read_bionic(a.bionic_x86 or os.path.join(here, BASES[a.base][1]))
        if a.selftest:
            if a.base != "4.4" or a.jb:
                sys.exit("--selftest --stage runs the 4.4 cases and every JB base itself; leave --base and --jb out")
            jb = {b: tuple(read_bionic(os.path.join(here, f)) for f in BASES[b]) for b in BASES if b != "4.4"}
            if not all(os.path.isfile(os.path.join(a.stage, k.split("/", 1)[1]))
                       for k in (STAGE_DEXJAR, STAGE_SO, STAGE_SO_X86)):
                sys.exit("selftest needs the real stage in %s" % a.stage)
            return selftest_stage(a.stage, sums, a.notice, bionic, bionic_x86, a.alpha3, jb, a.jb_dexjar)
        libs = []
        for f in (a.compat, a.compat_x86):
            if f is None:
                libs.append(None)
                continue
            if a.base == "4.4":
                sys.exit("--compat/--compat-x86 go with a Jelly Bean --base")
            with open(f, "rb") as fh:
                libs.append(fh.read())
        return report_stage(check_stage(a.stage, sums, a.notice, bionic, bionic_x86, a.base, a.jb, libs[0], libs[1]))
    if not a.aar:
        ap.error("AAR or --stage DIR is required")
    sums = read_sums(a.sums)
    if a.selftest:
        if not os.path.isfile(a.aar):
            sys.exit("selftest needs the real aar: %s is missing" % a.aar)
        return selftest(a.aar, sums)
    return report(check_aar(a.aar, sums))


if __name__ == "__main__":
    sys.exit(main())
