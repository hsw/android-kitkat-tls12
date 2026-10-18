#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""mkstage.py: the Conscrypt 2.6-alpha2 aar -> the layer D stage (dex jar + .so) for <tree>/stock/conscrypt/2.6-alpha2/.

    python3 -I mkstage.py AAR OUTDIR --java-libs DIR [--d8 D8] [--sums SHA256SUMS] [--jb]

DIR = <built 4.4 tree>/src/out/target/common/obj/JAVA_LIBRARIES; d8 gets its core_intermediates/classes.jar (java.*,
javax.*) and conscrypt_intermediates/classes.jar (com.android.org.conscrypt, the KitKat adapter's super class) as --lib.

The 4.4 dx reads class files up to major 51; 2.6-alpha2 is major 52 and calls Long.hashCode(J) (API 24). So the classes
are dexed outside the tree by d8 --min-api 19, which desugars and backports, and the module ships the dex jar as is:
  1. AAR sha256 = the pin "2.6-alpha2/conscrypt-android-2.6-alpha2.aar"; its classes.jar, armeabi-v7a and x86 .so = the
     pins "2.6-alpha2/aar:classes.jar", "2.6-alpha2/aar:jni/armeabi-v7a/libconscrypt_jni.so" and
     "2.6-alpha2/aar:jni/x86/libconscrypt_jni.so";
  2. rename_jni.py (the system copy loads libkktls_conscrypt_jni.so) -> pin "2.6-alpha2/rename_jni:classes.jar";
  3. d8 --release --min-api 19 --lib core --lib conscrypt -> classes.dex. Expected d8 warnings: exactly the two
     types 4.4 lacks for interface desugaring (javax.net.ssl.X509ExtendedTrustManager, ExtendedSSLSession); any other
     warning stops here;
  4. kktls-conscrypt.dex.jar = classes.dex + org/conscrypt/conscrypt.properties (carried from the jar, as the 2.5.3 dx
     module does), STORED, 1980-01-01, 0644 -> pin "2.6-alpha2/kktls-conscrypt.dex.jar";
  5. libkktls_conscrypt_jni.so = the aar's armeabi-v7a .so byte-identical -> pin "2.6-alpha2/libkktls_conscrypt_jni.so";
     x86/libkktls_conscrypt_jni.so = the aar's x86 .so -> pin "2.6-alpha2/x86/libkktls_conscrypt_jni.so" (the ARM file
     keeps its place at the top of the stage, where existing trees have it);
  6. OUTDIR gets conscrypt-android-2.6-alpha2.aar, kktls-conscrypt.dex.jar, libkktls_conscrypt_jni.so and
     x86/libkktls_conscrypt_jni.so (written as .partial, renamed after the pins matched).
--jb makes the Jelly Bean stage (Android 4.1-4.3; OUTDIR has the same file names, DIR is the JAVA_LIBRARIES of a built
JB tree): after step 2, jb_charsets.py moves the StandardCharsets (API 19) references to an own org.conscrypt shim ->
pin "2.6-alpha2/jb_charsets:classes.jar"; step 3 is d8 --release --min-api 16 --lib core (JB has no platform
conscrypt jar), expecting exactly three missing types (the two above and com.android.org.conscrypt.OpenSSLSocketImpl,
the KitKat adapter's super class: the JB hook takes the adapter's inner factory); the dex jar -> pin
"2.6-alpha2/jb/kktls-conscrypt.dex.jar". The .so files are the same pinned aar files (4.3 needs no change; 4.1/4.2 do,
see check_prebuilt.py JB_MISSING). One JB dex jar serves every JB base: the d8 output is the same with the 4.1, 4.2 and
4.3 core jar (checked 2026-10-18).
The d8 output does not depend on which built 4.4 core.jar is given (checked 2026-10-12 with two trees, with and without
framework/conscrypt jars); it does depend on the d8 version: pinned with D8 9.2.4-dev (SDK build-tools 37.0.0). A
different d8 that produces other bytes fails step 4 with both sha256 shown. Stdlib only; the aar is data.
"""
import argparse
import hashlib
import io
import os
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
V = "2.6-alpha2"
AAR_KEY = V + "/conscrypt-android-2.6-alpha2.aar"
CLASSES_KEY = V + "/aar:classes.jar"
SO_MEMBER = "jni/armeabi-v7a/libconscrypt_jni.so"
SO_KEY = V + "/aar:" + SO_MEMBER
SO_X86_MEMBER = "jni/x86/libconscrypt_jni.so"
SO_X86_KEY = V + "/aar:" + SO_X86_MEMBER
RENAMED_KEY = V + "/rename_jni:classes.jar"
DEXJAR_KEY = V + "/kktls-conscrypt.dex.jar"
JB_CHARSETS_KEY = V + "/jb_charsets:classes.jar"
JB_DEXJAR_KEY = V + "/jb/kktls-conscrypt.dex.jar"
STAGE_SO_KEY = V + "/libkktls_conscrypt_jni.so"
STAGE_SO_X86_KEY = V + "/x86/libkktls_conscrypt_jni.so"
PROPERTIES = "org/conscrypt/conscrypt.properties"
DATE = (1980, 1, 1, 0, 0, 0)
EXPECTED_D8_WARNINGS = {
    "javax.net.ssl.X509ExtendedTrustManager",
    "javax.net.ssl.ExtendedSSLSession",
}
EXPECTED_D8_WARNINGS_JB = EXPECTED_D8_WARNINGS | {"com.android.org.conscrypt.OpenSSLSocketImpl"}
DEFAULT_D8 = os.path.expanduser("~/Android/sdk/build-tools/37.0.0/d8")


class StageError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_sums(path):
    sums = {}
    with open(path) as f:
        for line in f:
            w = line.split()
            if len(w) == 2 and len(w[0]) == 64:
                sums[w[1]] = w[0].lower()
    return sums


def pinned(sums, key, data, what):
    got = sha256(data)
    if key not in sums:
        raise StageError("SHA256SUMS has no line for %s" % key)
    if got != sums[key]:
        raise StageError("%s sha256 %s is not the pin %s (%s)" % (what, got, sums[key], key))
    return got


def deterministic_jar(members):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for name, data in members:
            info = zipfile.ZipInfo(name, DATE)
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            z.writestr(info, data)
    return out.getvalue()


def d8_warnings(text):
    """The type names d8 could not find for desugaring, and every other non-empty line it printed."""
    types, other = set(), []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Warning in "):
            continue
        if line.startswith("Type `") and "` was not found" in line:
            types.add(line[len("Type `"):line.index("`", len("Type `"))])
        else:
            other.append(line)
    return types, other


def make_stage(aar, outdir, libs, d8, sums_path, log=print, jb=False):
    sums = read_sums(sums_path)
    with open(aar, "rb") as f:
        aar_data = f.read()
    log("aar      %s  %s" % (pinned(sums, AAR_KEY, aar_data, "aar"), aar))
    z = zipfile.ZipFile(io.BytesIO(aar_data))
    classes = z.read("classes.jar")
    so = z.read(SO_MEMBER)
    so_x86 = z.read(SO_X86_MEMBER)
    log("member   %s  classes.jar" % pinned(sums, CLASSES_KEY, classes, "classes.jar"))
    log("member   %s  %s" % (pinned(sums, SO_KEY, so, SO_MEMBER), SO_MEMBER))
    log("member   %s  %s" % (pinned(sums, SO_X86_KEY, so_x86, SO_X86_MEMBER), SO_X86_MEMBER))
    tmp = tempfile.mkdtemp(prefix="kktls-conscrypt-stage-")
    try:
        cj, rj, dj = (os.path.join(tmp, n) for n in ("classes.jar", "renamed.jar", "d8.jar"))
        with open(cj, "wb") as f:
            f.write(classes)
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "rename_jni.py"), cj, rj],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        if r.returncode:
            raise StageError("rename_jni.py failed: %s" % r.stdout.strip())
        with open(rj, "rb") as f:
            renamed = f.read()
        log("renamed  %s  rename_jni.py output" % pinned(sums, RENAMED_KEY, renamed, "renamed classes.jar"))
        expected = EXPECTED_D8_WARNINGS
        if jb:
            r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "jb_charsets.py"), rj, cj],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            if r.returncode:
                raise StageError("jb_charsets.py failed: %s" % r.stdout.strip())
            with open(cj, "rb") as f:
                log("charsets %s  jb_charsets.py output" % pinned(sums, JB_CHARSETS_KEY, f.read(), "jb_charsets classes.jar"))
            rj, expected = cj, EXPECTED_D8_WARNINGS_JB
        cmd = [d8, "--release", "--min-api", "16" if jb else "19"]
        for lib in libs:
            cmd += ["--lib", lib]
        cmd += ["--output", dj, rj]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        types, other = d8_warnings(r.stdout)
        if r.returncode or other or types != expected:
            raise StageError("d8 (rc %d) printed unexpected output: missing types %s (want %s); other: %s"
                             % (r.returncode, sorted(types), sorted(expected), other[:5]))
        log("d8       %s" % " ".join(cmd[:4] + ["--lib %s" % os.path.basename(os.path.dirname(l)) for l in libs]))
        log("d8       warnings: only the expected missing types %s" % ", ".join(sorted(types)))
        with zipfile.ZipFile(dj) as dz:
            names = dz.namelist()
            if names != ["classes.dex"]:
                raise StageError("d8 output holds %s, want classes.dex only" % names)
            dex = dz.read("classes.dex")
        props = zipfile.ZipFile(io.BytesIO(renamed)).read(PROPERTIES)
        dexjar = deterministic_jar([("classes.dex", dex), (PROPERTIES, props)])
        dkey = JB_DEXJAR_KEY if jb else DEXJAR_KEY
        log("dex jar  %s  kktls-conscrypt.dex.jar (classes.dex %s, %s)" % (pinned(sums, dkey, dexjar, "dex jar"),
                                                                         sha256(dex), dkey))
        log(".so      %s  libkktls_conscrypt_jni.so" % pinned(sums, STAGE_SO_KEY, so, "stage .so"))
        log(".so      %s  x86/libkktls_conscrypt_jni.so" % pinned(sums, STAGE_SO_X86_KEY, so_x86, "stage x86 .so"))
    finally:
        for n in os.listdir(tmp):
            os.remove(os.path.join(tmp, n))
        os.rmdir(tmp)
    # the JB stage has the 4.4 stage's file names (its dex jar is the JB one)
    for key, data in ((AAR_KEY, aar_data), (DEXJAR_KEY, dexjar), (STAGE_SO_KEY, so), (STAGE_SO_X86_KEY, so_x86)):
        dst = os.path.join(outdir, key.split("/", 1)[1])
        if not os.path.isdir(os.path.dirname(dst)):
            os.makedirs(os.path.dirname(dst))
        with open(dst + ".partial", "wb") as f:
            f.write(data)
        os.chmod(dst + ".partial", 0o644)
        os.replace(dst + ".partial", dst)
    log("staged   %s" % outdir)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("aar")
    ap.add_argument("outdir")
    ap.add_argument("--java-libs", required=True, metavar="DIR",
                    help="<built 4.4 tree>/src/out/target/common/obj/JAVA_LIBRARIES")
    ap.add_argument("--d8", default=os.environ.get("D8", DEFAULT_D8))
    ap.add_argument("--sums", default=os.path.join(HERE, "SHA256SUMS"))
    ap.add_argument("--jb", action="store_true", help="the Jelly Bean stage (DIR: JAVA_LIBRARIES of a built JB tree)")
    a = ap.parse_args()
    mods = ("core_intermediates",) if a.jb else ("core_intermediates", "conscrypt_intermediates")
    libs = [os.path.join(a.java_libs, m, "classes.jar") for m in mods]
    for p in [a.aar, a.d8] + libs:
        if not os.path.isfile(p):
            sys.exit("mkstage.py: %s is missing" % p)
    try:
        make_stage(a.aar, a.outdir, libs, a.d8, a.sums, jb=a.jb)
    except (StageError, zipfile.BadZipFile, KeyError, OSError) as e:
        sys.exit("mkstage.py: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
