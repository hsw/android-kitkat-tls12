#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""kktls-jarpatch.py: patch a 4.4 device's own core/core-libart/conscrypt/okhttp jars with the kktls Java layer A.

    kktls-jarpatch.py --adb SERIAL --release-dir DIR --out DIR [--accept-oem] [--set FILE] [--report FILE]
    kktls-jarpatch.py --system DIR --bootclasspath LIST --build-prop FILE --release-dir DIR --out DIR
                      [--accept-oem] [--set FILE] [--report FILE]

Inputs:
  --adb SERIAL        the device's /system over adb (no root needed: the files are world-readable): every
                      /system/framework/*.jar, every /system/{app,priv-app}/*.apk, /system/build.prop, the names of the
                      .odex files, whether /system/lib/libart.so exists, the installer marker /system/etc/kktls/
                      java.version and the BOOTCLASSPATH of a shell. The files are copied into OUT/device/.
  --system DIR        a copy of /system (DIR/framework/, or DIR/system/framework/), e.g. a mounted ROM image, with
  --bootclasspath L   the device's BOOTCLASSPATH (`/system/framework/core.jar:...`, from init.environ.rc) and
  --build-prop FILE   its build.prop.
  --release-dir DIR   a directory with the release's SHA256SUMS and the java zip of the device's line and ABI,
                      kktls-java-<4.4.2|4.4.4>-<armeabi-v7a|x86>-<release>.zip (the donor of the replacement classes);
                      the line follows ro.build.version.release (4.4.1, 4.4.2 -> 4.4.2; 4.4.3, 4.4.4 -> 4.4.4). Its
                      installer (kktls/checks.sh) must know the java-patched kind (and oem_ack for --accept-oem),
                      else tool error: the device would refuse the zips.
  --accept-oem        on an OEM/CM build (a build.prop key of installer/checks.sh KK_OEM_MARKERS, e.g. ro.cm.version):
                      also write device-bound copies of the release's openssl and conscrypt zips (see 7.); the release
                      dir must hold kktls-openssl-4.4-<abi>-<release>.zip and kktls-conscrypt-<abi>-<release>.zip.
  --set FILE          the set file instead of sets/<line>.txt (tests).
  --report FILE       write the per-line verdicts and the result there as well.

What it does (nothing on the device is changed):
  1. gates: Android 4.4.1 to 4.4.4 (4.4, android-4.4_r1/r1.2, lacks upstream SSLEngine and okhttp fixes that the
     series builds on and the patcher does not carry: refused), ABI armeabi-v7a or x86, a build fingerprint; no .odex in /system/{framework,app,priv-app}
     whose jar/apk lacks classes.dex (the installer's dex check: after core.jar changes Dalvik must re-dexopt them);
     the four jars present with exactly one classes.dex (core-libart.jar may be absent when /system/lib/libart.so is,
     a Dalvik-only ROM); an OEM/CM build (or --accept-oem): the native-consumer scan (nativescan.py: every ELF of
     /system/{lib,bin,xbin,vendor} and of the apps' lib/ that needs libssl.so or libcrypto.so, "extra" when not in
     aosp44-ssl-consumers.txt) is written to OUT/native-consumers.txt (over adb those directories are pulled first);
     without --accept-oem an OEM/CM build refuses: "OEM/CM build: rerun with --accept-oem after reading the report";
  2. reference check, one verdict per line of the set file (sets/<line>.txt, see mkset.py), on the normalized
     baksmali digests (normalize.py) of the device's classes and the sha256 of its non-dex entries:
       match               the device has the stock AOSP class/entry the series was applied to (or, for a class the
                           series adds, does not have it);
       vendor-modified     the device's class or entry differs from stock: the vendor changed it, and replacing it
                           would drop that change (also when it equals the kktls version, as some cm-11 classes do,
                           unless the device carries kktls);
       missing             the stock class or entry is not there;
       unexpected-present  a class the series adds is already there (not as kktls);
       already-kktls       the device already carries kktls: a class of io.github.hsw.kktls, the kktls
                           security.properties entry, or the installer marker java.version ("restore first");
     any verdict but match refuses, with the full list;
  3. the replacement: baksmali (debug info kept) of the device jar and of the donor jar; every class of the set is
     replaced by the donor's whole .smali file, the classes the series removes are deleted, smali -a 19 reassembles
     one classes.dex (type, proto, field and method id counts must stay below 65536); each donor jar as a whole must
     give the set's ours aggregate, and its classes and entries the set's ours digests (else the release dir and the
     set file do not belong together: tool error); a class of the device's conscrypt.jar that the set does not
     replace must declare no native method (the donor's libjavacrypto.so replaces the device's and registers only
     the stock 4.4 natives);
  4. round-trip invariant: the new classes.dex is disassembled again, every class not in the set must keep the digest
     it had on the device and every replaced class must have the set's ours digest;
  5. link check (linkcheck.py), per runtime (dalvik: BOOTCLASSPATH with core.jar; art: with core-libart.jar): every
     reference of the replacement classes must resolve on the patched boot class path, and every reference of the
     boot class path, the other framework jars and the app/priv-app dex that resolved before the patch must still
     resolve (a caller of a member the series removes refuses).

  6. the recovery zip (rawzip.py): each patched jar is the device jar with classes.dex and the set's entries swapped,
     every other entry copied byte for byte; the zip is the donor java zip with these jars in place of its own (a
     donor jar the device lacks, core-libart.jar on a Dalvik-only ROM, is dropped), the donor's libjavacrypto.so,
     installer and helpers, a NOTICE that says the jars are the device's own with the set's classes replaced (then
     the donor's notices), and a new kktls/zip.conf:
       kind=java-patched, release= (the donor's: the java.version marker the conscrypt zip checks), abi=, android=
       (the device's release), tag= (the donor's), jar.<name>=<sha256 of the device jar it was made from>,
       fingerprint=<sha256 of ro.build.fingerprint>;
     the installer (installer/checks.sh) installs it only on a system whose jars and fingerprint give these digests.
  7. --accept-oem: kktls-openssl-oem-4.4-<abi>-<release>-<fp8>.zip and kktls-conscrypt-oem-<abi>-<release>-<fp8>.zip,
     the release zips with oem_ack=<sha256 of ro.build.fingerprint> appended to zip.conf (every other entry byte for
     byte): their kinds skip the installer's OEM/CM gate on this system only. The java-patched zip needs no such line
     (it has no OEM/CM gate).

Output (exit 0): OUT/kktls-java-patched-<android>-<abi>-<release>-<8 hex of sha256(fingerprint)>.zip (for that
device only: it holds the device's own classes, not for redistribution), OUT/stage/jars/<jar>.jar (the patched jars),
OUT/stage/<jar>/classes.dex, OUT/stage/<jar>/<entry path> (the donor's bytes of the set's entries) and
OUT/stage/manifest.json (system, device jar sha256s, sha256 of ro.build.fingerprint, donor, per-jar staged files,
link check counts, the zip, with the scan: oem markers, extra consumers and the oem zips), with --accept-oem the two
oem zips, and OUT/native-consumers.txt after the scan (also when refused); with --adb, OUT/device/ holds the files
copied from the device (its build.prop with the raw fingerprint among them). The zips, the manifest and the report
carry only the sha256 of the fingerprint; nothing prints the raw one. OUT holds the device's own files: do not publish
it. OUT must not exist or be empty.

Exit 0 staged, 1 refused (each reason: jar, class, why), 2 usage, tool error or an unexpected error. Stdlib only; Java 8+ (`java` on PATH,
or $KKTLS_JAVA) and the smali/baksmali jars of fetch-smali.sh.
"""
import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)   # `python3 -I` leaves the script dir out
import linkcheck  # noqa: E402
import mkset  # noqa: E402
import nativescan  # noqa: E402
import normalize  # noqa: E402
import rawzip  # noqa: E402

LINES = {"4.4.1": "4.4.2", "4.4.2": "4.4.2", "4.4.3": "4.4.4", "4.4.4": "4.4.4"}
ABIS = ("armeabi-v7a", "x86")
KKTLS_PKG = "Lio/github/hsw/kktls/"
SUBDIRS = linkcheck.SUBDIRS
JAVA_MARKER = "etc/kktls/java.version"
ID_LIMIT = 65536
# installer/checks.sh KK_OEM_MARKERS (a test keeps the two equal): build.prop keys (prefix match) that only
# CyanogenMod-family and OEM firmwares set; the openssl and conscrypt zips refuse such a system unless their zip.conf
# carries oem_ack=<sha256 of its ro.build.fingerprint> (the --accept-oem copies)
OEM_MARKERS = """ro.cm. ro.modversion ro.cyanogen ro.miui. ro.build.version.emui ro.build.hw_emui ro.lewa. ro.aokp.
ro.pa. ro.pac. ro.slim. ro.omni. ro.mk. ro.mokee. ro.carbon. ro.rr. ro.dirtyunicorns. ro.liquid. ro.beanstalk.
ro.build.PDA ro.build.hidden_ver ro.build.sense. ro.htc. ro.lge. ro.semc. ro.sony. ro.yunos. ro.vivo.
ro.build.version.opporom ro.oppo. ro.mediatek. ro.flyme. ro.meizu. ro.coolpad. ro.zte. ro.lenovo. ro.asus.""".split()
NATIVE_REPORT = "native-consumers.txt"
# what an installer that can install the zips this tool writes has in its kktls/checks.sh, by capability (a test
# keeps each text in installer/checks.sh): java-patched = kk_precheck's case label of that kind, oem_ack = the
# zip.conf key kk_check_oem reads. A donor whose installer lacks one predates this tool: the device would refuse.
INSTALLER_CAPS = {"java-patched": "java-patched)", "oem_ack": "oem_ack"}
# ls error lines (adb shell on 4.4 merges the device's stderr into the output): toolbox prints "opendir failed, <why>"
# after the header of a directory it cannot read and "<path>: <why>" otherwise, busybox and toybox "ls: <path>: <why>"
# (newer busybox "ls: can't open '<path>': <why>"); any line holding one of LS_ERRORS is one too
LS_ERRORS = ("opendir failed", "Permission denied")
LS_ERROR_RE = re.compile(r"(?:ls: (?:can't open )?)?'?(/.*?)'?: (.+)\Z")
NO_SUCH_DIR = "No such file or directory"


class ToolError(Exception):
    pass


class Refused(Exception):
    def __init__(self, reasons):
        Exception.__init__(self, "%d reason(s)" % len(reasons))
        self.reasons = reasons   # [(jar or "-", name or "-", why)]


def log(msg):
    print("kktls-jarpatch: " + msg, file=sys.stderr)


sha256_file = mkset.sha256_file


def read_build_prop(path):
    """(props, keys) of a build.prop, read once: props {key: value} (comments skipped, keys and values stripped; the
    first definition of a key wins: ro.* properties are set once) and keys [the text before the first '=' of every
    line, unstripped, as installer/checks.sh kk_check_aosp's awk sees them: the OEM/CM marker test]."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().split("\n")
    except OSError as e:
        raise ToolError("build.prop: %s" % e)
    props = {}
    for l in lines:
        l = l.strip()
        if not l or l.startswith("#") or "=" not in l:
            continue
        k, v = l.split("=", 1)
        props.setdefault(k.strip(), v.strip())
    return props, [l.split("=", 1)[0] for l in lines]


class System(object):
    """What the patcher reads of a device's /system. root mirrors /system for the files that were read: framework/
    (every .jar), app/ and priv-app/ (every .apk) and, with --system, everything else of the copy."""

    def __init__(self, source, root, build_prop, bootclasspath, odex, libart, java_marker, adb=None):
        self.source = source              # "adb" or "system"
        self.props, self.prop_keys = read_build_prop(build_prop)   # see read_build_prop
        self.adb = adb                    # Adb of an --adb system (fetch_native pulls more of /system on demand)
        self.root = root
        self.bootclasspath = bootclasspath   # ["/system/framework/core.jar", ...]
        self.odex = odex                  # {subdir: sorted .odex names}
        self.libart = libart              # /system/lib/libart.so exists
        self.java_marker = java_marker    # contents of /system/etc/kktls/java.version or None

    def path(self, sub, name):
        return os.path.join(self.root, sub, name)


def parse_bootclasspath(text):
    bcp = [p for p in text.strip().split(":") if p]
    if not bcp:
        raise ToolError("empty BOOTCLASSPATH")
    for p in bcp:
        if not re.match(r"/system/framework/[^/]+\.jar\Z", p):
            raise ToolError("BOOTCLASSPATH entry %s is not a /system/framework jar" % p)
    return bcp


def from_system(d, bcp_text, build_prop):
    root = d
    if not os.path.isdir(os.path.join(root, "framework")) and os.path.isdir(os.path.join(d, "system", "framework")):
        root = os.path.join(d, "system")
    if not os.path.isdir(os.path.join(root, "framework")):
        raise ToolError("%s: no framework/ (and no system/framework/)" % d)
    bcp = parse_bootclasspath(bcp_text)
    for p in bcp:
        if not os.path.isfile(os.path.join(root, "framework", os.path.basename(p))):
            raise ToolError("BOOTCLASSPATH names %s, not in %s/framework" % (p, root))
    odex = {}
    for sub, _ in SUBDIRS:
        p = os.path.join(root, sub)
        odex[sub] = sorted(n for n in os.listdir(p) if n.endswith(".odex")) if os.path.isdir(p) else []
    marker = None
    mp = os.path.join(root, JAVA_MARKER)
    if os.path.isfile(mp):
        with open(mp, encoding="utf-8", errors="replace") as f:
            marker = f.read().strip()
    return System("system", root, build_prop, bcp, odex, os.path.isfile(os.path.join(root, "lib", "libart.so")),
                  marker)


class Adb(object):
    def __init__(self, serial):
        self.cmd = ["adb", "-s", serial]

    def run(self, args):
        try:
            r = subprocess.run(self.cmd + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            raise ToolError("adb: %s" % e)
        if r.returncode != 0:
            raise ToolError("adb %s failed (exit %d): %s" % (" ".join(args), r.returncode,
                                                             r.stderr.decode("utf-8", "replace").strip()[-300:]))
        return r.stdout.decode("utf-8", "replace").replace("\r", "")

    def shell(self, command):
        return self.run(["shell", command])

    def ls(self, d):
        """Sorted names in the device directory d; [] when d does not exist; ToolError on any other ls error line
        (old adb returns 0 whatever the device command did: the device's stderr, merged into the output, tells)."""
        names = [n.strip() for n in self.shell("ls %s 2>&1" % d).split("\n") if n.strip()]
        bad = [n for n in names if ls_error(n)]
        if len(names) == 1 and bad and ls_error(bad[0]) == (d, NO_SUCH_DIR):
            return []   # toolbox `D: No such file or directory`, busybox `ls: D: No such file or directory`
        if bad:
            raise ToolError("adb: %s is not listable: %s" % (d, bad[0]))
        return sorted(names)

    def pull(self, src, dst):
        self.run(["pull", src, dst])
        if not os.path.isfile(dst):
            raise ToolError("adb pull %s: no file arrived" % src)


def from_adb(serial, stage):
    """Copy what the patcher needs from the device's /system into stage/ (a /system mirror)."""
    adb = Adb(serial)
    state = adb.run(["get-state"]).strip()
    if state != "device":
        raise ToolError("adb: device %s is %s" % (serial, state or "not available"))
    odex = {}
    for sub, ext in SUBDIRS:
        names = adb.ls("/system/" + sub)
        if sub == "framework" and not any(n.endswith(".jar") for n in names):
            raise ToolError("adb: /system/framework lists no jar")
        odex[sub] = [n for n in names if n.endswith(".odex")]
        os.makedirs(os.path.join(stage, sub), exist_ok=True)
        files = [n for n in names if n.endswith(ext)]
        log("adb: pulling %d %s file(s) of /system/%s" % (len(files), ext, sub))
        for n in files:
            adb.pull("/system/%s/%s" % (sub, n), os.path.join(stage, sub, n))
    adb.pull("/system/build.prop", os.path.join(stage, "build.prop"))
    libart = "libart.so" in adb.ls("/system/lib")
    marker = None
    if os.path.basename(JAVA_MARKER) in adb.ls("/system/" + os.path.dirname(JAVA_MARKER)):
        marker = adb.shell("cat /system/" + JAVA_MARKER).strip()
    bcp = parse_bootclasspath(adb.shell("echo $BOOTCLASSPATH"))
    for p in bcp:
        if not os.path.isfile(os.path.join(stage, "framework", os.path.basename(p))):
            raise ToolError("BOOTCLASSPATH names %s, not in /system/framework" % p)
    bp = os.path.join(stage, "build.prop")
    return System("adb", stage, bp, bcp, odex, libart, marker, adb)


def ls_error(line):
    """(path or None, why) when line is an ls error line (LS_ERRORS, LS_ERROR_RE, or "ls: ..."), else None. An entry
    of `ls DIR` or `ls -lR DIR` never starts with "/" or "ls: " (a `PATH:` header of -R is no error line)."""
    if line.startswith("/") and line.endswith(":"):
        return None
    m = LS_ERROR_RE.match(line)
    if m:
        return m.group(1), m.group(2)
    if line.startswith("ls: ") or any(e in line for e in LS_ERRORS):
        return None, line
    return None


def ls_files(listing, top):
    """(sorted paths of the regular files, sorted [(path, why)] of the directories ls could not read) of a
    `ls -lR TOP 2>&1` listing (toolbox or busybox format; directories come as `PATH:` headers, symbolic links and
    other types are skipped; an error line (ls_error) names its path (busybox `ls: PATH: why`) or follows the header
    of the directory it is about (toolbox `opendir failed, why`); TOP itself missing is no error)."""
    res, errs, cur = [], set(), None
    for l in listing.split("\n"):
        l = l.rstrip()
        if l.endswith(":") and l.startswith("/"):
            cur = l[:-1]
            continue
        e = ls_error(l)
        if e:
            path, why = e if e[0] else (cur or top, l)
            if (path, why) == (top, NO_SUCH_DIR):
                continue
            if path == top or path.startswith(top + "/"):
                errs.add((path, why))
            continue
        if cur is None or not l.startswith("-"):
            continue
        name = l.split()[-1]
        if cur == top or cur.startswith(top + "/"):
            res.append(cur + "/" + name)
    return sorted(res), sorted(errs)


def fetch_native(system):
    """--adb: copy /system/{lib,bin,xbin,vendor} and the *.so files under /system/{app,priv-app} into the mirror for the
    native-consumer scan; a file that does not arrive or a directory ls cannot read (not readable for the shell user) is
    reported, not fatal (a directory that does not exist, as /system/vendor on many builds, is not an error line)."""
    failed = []
    for sub in nativescan.TREES:
        top = "/system/" + sub
        paths, errs = ls_files(system.adb.shell("ls -lR %s 2>&1" % top), top)
        failed += [(p[len("/system/"):] + "/", "not listable: %s" % why) for p, why in errs]
        if sub in nativescan.APK_DIRS:
            paths = [p for p in paths if p.endswith(".so")]
        log("adb: pulling %d file(s) of %s for the native-consumer scan" % (len(paths), top))
        for p in paths:
            dst = os.path.join(system.root, p[len("/system/"):])
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                system.adb.pull(p, dst)
            except ToolError as e:
                if os.path.lexists(dst):
                    os.remove(dst)
                failed.append((p[len("/system/"):], "adb pull failed: %s" % str(e)[-200:]))
    return failed


def oem_markers(keys):
    """The build.prop keys (System.prop_keys) that start with one of OEM_MARKERS, as kk_check_aosp tests them."""
    return sorted({k for k in keys for m in OEM_MARKERS if k.startswith(m)})


def find_donor(release_dir, line, abi):
    """(path, release, zip.conf) of kktls-java-<line>-<abi>-<release>.zip, checked against the dir's SHA256SUMS, its
    zip.conf and its installer."""
    pat = re.compile(r"kktls-java-%s-%s-([^/]+)\.zip\Z" % (re.escape(line), re.escape(abi)))
    try:
        found = sorted((n, pat.match(n).group(1)) for n in os.listdir(release_dir) if pat.match(n))
    except OSError as e:
        raise ToolError("--release-dir: %s" % e)
    if not found:
        raise ToolError("%s: no kktls-java-%s-%s-<release>.zip" % (release_dir, line, abi))
    if len(found) > 1:
        raise ToolError("%s: several java zips for %s %s (%s): keep one release" %
                        (release_dir, line, abi, ", ".join(n for n, _ in found)))
    name, rel = found[0]
    path, conf = release_zip(release_dir, name, {"kind": "java", "android": line, "abi": abi, "release": rel},
                             "java-patched")
    return path, rel, conf


def oem_sources(release_dir, abi, rel):
    """[(kind, path)] of the release's 4.4 openssl and conscrypt zips of this ABI (the sources of the --accept-oem
    copies), checked as the donor is."""
    return [(k, release_zip(release_dir, n, {"kind": k, "android": "4.4", "abi": abi, "release": rel}, "oem_ack")[0])
            for k, n in (("openssl", "kktls-openssl-4.4-%s-%s.zip" % (abi, rel)),
                         ("conscrypt", "kktls-conscrypt-%s-%s.zip" % (abi, rel)))]


def release_zip(release_dir, name, want, capability):
    """(path, zip.conf) of release_dir/name after its SHA256SUMS line, the zip.conf keys of want and its installer
    (kktls/checks.sh must have the INSTALLER_CAPS text of capability: an older installer refuses the zips written
    from it) are checked."""
    path = os.path.join(release_dir, name)
    if not os.path.isfile(path):
        raise ToolError("%s: no %s" % (release_dir, name))
    sums = {}
    try:
        with open(os.path.join(release_dir, "SHA256SUMS"), encoding="utf-8") as f:
            for l in f:
                p = l.split()
                if len(p) == 2:
                    sums[p[1].lstrip("*")] = p[0]
    except OSError as e:
        raise ToolError("--release-dir: SHA256SUMS: %s" % e)
    if name not in sums:
        raise ToolError("%s is not listed in SHA256SUMS" % name)
    if sha256_file(path) != sums[name]:
        raise ToolError("%s: sha256 differs from SHA256SUMS" % name)
    try:
        with zipfile.ZipFile(path) as z:
            conf = read_conf(z)
            names = set(z.namelist())
            installer = z.read("kktls/checks.sh").decode("utf-8", "replace") if "kktls/checks.sh" in names else ""
    except (OSError, KeyError, zipfile.BadZipFile) as e:
        raise ToolError("%s: no readable kktls/zip.conf: %s" % (name, e))
    for k, v in want.items():
        if conf.get(k) != v:
            raise ToolError("%s: zip.conf %s=%s, expected %s" % (name, k, conf.get(k), v))
    if INSTALLER_CAPS[capability] not in installer:
        raise ToolError("%s: its installer predates this tool (no %s in kktls/checks.sh): the device would refuse "
                        "the zips made from it; use the zips of the jarpatch tool's own release" %
                        (name, capability))
    return path, conf


def extract_donor(donor, jars, dst):
    out = {}
    os.makedirs(dst, exist_ok=True)
    with zipfile.ZipFile(donor) as z:
        names = set(z.namelist())
        for j in jars:
            n = "system/framework/%s.jar" % j
            if n not in names:
                raise ToolError("%s has no %s" % (os.path.basename(donor), n))
            out[j] = os.path.join(dst, j + ".jar")
            with z.open(n) as src, open(out[j], "wb") as f:
                shutil.copyfileobj(src, f)
    return out


def zip_conf(conf, rel, abi, android, jars, fp_sha):
    """zip.conf text of a java-patched zip: jars = [(name, sha256 of the device jar)]."""
    lines = ["kind=java-patched", "release=" + rel, "abi=" + abi, "android=" + android, "tag=" + conf.get("tag", "")]
    lines += ["jar.%s=%s" % j for j in jars]
    lines.append("fingerprint=" + fp_sha)
    return "".join(l + "\n" for l in lines)


def oem_conf(text, fp_sha):
    """zip.conf text of an --accept-oem copy: the release zip's lines unchanged, then oem_ack=<sha256 of the
    fingerprint> (checks.sh: the openssl and conscrypt kinds skip the OEM/CM gate only on that system)."""
    if any(l.startswith("oem_ack=") for l in text.split("\n")):
        raise ToolError("the release zip's zip.conf already has an oem_ack line")
    if text and not text.endswith("\n"):
        text += "\n"
    return text + "oem_ack=" + fp_sha + "\n"


def read_conf(z):
    """{key: value} of an open zip's kktls/zip.conf."""
    return dict(l.split("=", 1) for l in z.read("kktls/zip.conf").decode("utf-8", "replace").split("\n") if "=" in l)


def write_checked(src, dst, changes):
    """rawzip.rewrite(src, dst, changes {path: bytes | None (removed)}), then dst must pass testzip and give back every
    new entry's bytes."""
    try:
        rawzip.rewrite(src, dst, changes)
    except rawzip.ZipError as e:
        raise ToolError("%s: %s" % (os.path.basename(src), e))
    with zipfile.ZipFile(dst) as z:
        if z.testzip() is not None or any(z.read(n) != b for n, b in changes.items() if b is not None):
            raise ToolError("%s does not read back" % dst)


def patched_notice(donor_notice, donor_name, jars, tag):
    """NOTICE of a java-patched zip: what its jars are, then the donor java zip's notices."""
    head = ["Notices for a kktls java-patched zip",
            "",
            "This zip was made by kktls-jarpatch.py for one system from %s. Its" % donor_name,
            "system/framework/{%s}.jar are that system's own jars: every class and entry is the" % ",".join(jars),
            "vendor's, except the classes and entries listed in the jar patcher's set file, which come from the",
            "release java zip: AOSP %s libcore and external/okhttp with the kktls patch series" % tag,
            "(Apache License 2.0). The other files (installer, helpers, lib/libjavacrypto.so) are the release java",
            "zip's. Its notices follow; what they say about how the jars were built applies to the replaced classes",
            "only. The vendor's classes keep the vendor's terms.",
            "",
            "=" * 77,
            "Notices of %s" % donor_name,
            "=" * 77,
            ""]
    return "\n".join(head) + "\n" + donor_notice


def has_dex(path):
    """True/False: the zip has a classes.dex entry; None: not a readable zip."""
    try:
        with zipfile.ZipFile(path) as z:
            return "classes.dex" in z.namelist()
    except (OSError, zipfile.BadZipFile):
        return None


def check_odex(system):
    """The installer's dex check: every .odex in framework/app/priv-app needs its jar/apk with classes.dex next to it
    (the four set jars are checked by check_jars)."""
    reasons = []
    for sub, _ in SUBDIRS:
        for o in system.odex[sub]:
            base = o[:-len(".odex")]
            if sub == "framework" and base in mkset.JARS:
                continue
            f = [n for n in (base + ".jar", base + ".apk") if os.path.isfile(system.path(sub, n))]
            if not f:
                reasons.append(("-", "/system/%s/%s" % (sub, o), "odexed, no jar/apk next to it"))
                continue
            d = has_dex(system.path(sub, f[-1]))
            if d is None:
                reasons.append(("-", "/system/%s/%s" % (sub, f[-1]), "not a readable zip"))
            elif not d:
                reasons.append(("-", "/system/%s/%s" % (sub, f[-1]),
                                "odexed without classes.dex (odexed-and-stripped ROMs are not supported)"))
    return reasons


def check_jars(system):
    """([jars to patch], reasons): each set jar present with exactly one classes.dex; core-libart.jar may be absent on
    a Dalvik-only ROM (no /system/lib/libart.so)."""
    jars, reasons = [], []
    for j in mkset.JARS:
        p = system.path("framework", j + ".jar")
        if not os.path.isfile(p):
            if j == "core-libart" and not system.libart:
                log("core-libart.jar absent and no libart.so: Dalvik-only ROM, core-libart lines skipped")
                continue
            reasons.append((j, "-", "/system/framework/%s.jar is missing" % j))
            continue
        try:
            normalize.check_dex_jar(p)
        except normalize.NormalizeError as e:
            why = str(e).split(": ", 1)[-1]
            if j + ".odex" in system.odex["framework"]:
                why = "odexed without classes.dex (%s)" % why
            reasons.append((j, "-", why))
            continue
        jars.append(j)
    return jars, reasons


def disassemble(src, out, baksmali_jar):
    """baksmali d -a 19 (debug info kept) of a jar or dex into out; {descriptor: (path, digest)}."""
    normalize.baksmali(src, out, baksmali_jar)
    return normalize.index_dir(out)


def native_methods(path):
    """The `.method` lines of a smali file that declare a native method."""
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.startswith(".method ") and " native " in l]


def assemble(tree, dex, smali_jar):
    os.makedirs(os.path.dirname(dex), exist_ok=True)
    # one job: smali's parallel assembly writes the dex items in thread completion order, so the same tree gives
    # a different (equivalent) dex from run to run; the zip must be reproducible from the same /system and release
    cmd = [normalize.JAVA, "-jar", smali_jar, "a", "-a", normalize.BAKSMALI_API, "-j", "1", "-o", dex, tree]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    if r.returncode != 0 or not os.path.isfile(dex):
        raise ToolError("smali of %s failed (exit %d): %s" % (tree, r.returncode, r.stdout.strip()[-500:]))


# one line of the reference check: verdict (match, missing, vendor-modified, unexpected-present, already-kktls),
# kind (class, check, entry, marker), jar, name (class descriptor or entry path) and detail (text or "")
Verdict = collections.namedtuple("Verdict", "verdict kind jar name detail")


def verdicts(st, jars, dev, dev_entries, system):
    """([Verdict] for every line of the set file on the active jars, already-kktls resolved; already: the system
    carries kktls)."""
    res = []
    for j, c, stock, ours in st.classes:
        if j not in jars:
            continue
        d = dev[j].get(c, (None, None))[1]
        if stock is None:
            v = "match" if d is None else ("equals-ours" if d == ours else "unexpected-present")
        elif d is None:
            v = "missing"
        else:
            v = "match" if d == stock else ("equals-ours" if d == ours else "vendor-modified")
        res.append(Verdict(v, "class", j, c, ""))
    for j, c, stock in st.checks:
        if j not in jars:
            continue
        d = dev[j].get(c, (None, None))[1]
        res.append(Verdict("missing" if d is None else "match" if d == stock else "vendor-modified", "check", j, c,
                           ""))
    for j, p, stock, ours in st.entries:
        if j not in jars:
            continue
        d = dev_entries[j].get(p)
        if d == stock:
            v = "match"
        elif d is None:
            v = "missing"
        elif d == ours:
            v = "equals-ours"
        else:
            v = "unexpected-present" if stock is None else "vendor-modified"
        res.append(Verdict(v, "entry", j, p, ""))
    # kktls markers: a class of the kktls package, the kktls security.properties, the installer's java marker
    marks = []
    for j in jars:
        marks += [("class", j, c) for c in sorted(dev[j]) if c.startswith(KKTLS_PKG)]
    marks += [("entry", r.jar, r.name) for r in res if r.kind == "entry" and r.verdict == "equals-ours"]
    already = bool(marks) or system.java_marker is not None
    for i, r in enumerate(res):
        if r.verdict == "equals-ours":
            res[i] = r._replace(verdict="already-kktls" if already else "vendor-modified",
                                detail="equals the kktls version" if already else (
                                    "equals the kktls version, but the system carries no kktls marker (a vendor "
                                    "backport, or the series built into the image)"))
        elif already and r.kind == "class" and r.name.startswith(KKTLS_PKG) and r.verdict != "match":
            res[i] = r._replace(verdict="already-kktls", detail="kktls class present")
    named = {(r.jar, r.name) for r in res}
    for kind, j, c in marks:
        if (j, c) not in named:
            res.append(Verdict("already-kktls", kind, j, c, "kktls class present"))
    if system.java_marker is not None:
        res.append(Verdict("already-kktls", "marker", "-", "/system/" + JAVA_MARKER,
                           "installed: " + system.java_marker))
    return res, already


def describe(v, tag):
    """Reason text of a verdict line without its own detail."""
    return {"vendor-modified": "differs from stock %s (vendor change)" % tag,
            "missing": "stock %s has it, the device does not" % tag,
            "unexpected-present": "the series adds it, but the device already has a different one",
            "already-kktls": "kktls version present"}[v]


class Patcher(object):
    def __init__(self, system, release_dir, out, set_path=None, accept_oem=False):
        self.system, self.release_dir, self.out, self.set_path = system, release_dir, out, set_path
        self.accept_oem = accept_oem
        self.lines = []        # report lines
        self.verdicts = []     # [Verdict]
        self.oem = []          # the OEM/CM marker keys of build.prop
        # set by gates(): the device's release, its donor line, ABI and the sha256 of its build fingerprint
        self.android = self.line = self.abi = self.fp_sha = None

    def gates(self):
        p = self.system.props
        rel, abi, fp = (p.get("ro.build.version.release"), p.get("ro.product.cpu.abi"), p.get("ro.build.fingerprint"))
        reasons = []
        if rel == "4.4":
            reasons.append(("-", "ro.build.version.release", "Android 4.4 (android-4.4_r1/r1.2) lacks upstream SSLEngine "
                            "and okhttp fixes that the series builds on and this tool does not carry: only 4.4.1 to "
                            "4.4.4 are supported"))
        elif rel not in LINES:
            reasons.append(("-", "ro.build.version.release", "Android %s: only 4.4.1 to 4.4.4 are supported" % rel))
        if abi not in ABIS:
            reasons.append(("-", "ro.product.cpu.abi", "ABI %s: only %s are supported" % (abi, ", ".join(ABIS))))
        if not fp:
            reasons.append(("-", "ro.build.fingerprint", "build.prop has no build fingerprint"))
        if reasons:
            raise Refused(reasons)
        self.android, self.line, self.abi = rel, LINES[rel], abi
        self.fp_sha = hashlib.sha256(fp.encode("utf-8")).hexdigest()

    def load_set(self):
        path = self.set_path or os.path.join(HERE, "sets", self.line + ".txt")
        try:
            return path, mkset.read_set(path)
        except (OSError, mkset.SetError) as e:
            raise ToolError("set file: %s" % e)

    def run(self):
        s = self.system
        self.gates()
        set_path, st = self.load_set()
        donor, rel, donor_conf = find_donor(self.release_dir, self.line, self.abi)
        self.lines += ["android %s line %s abi %s" % (self.android, self.line, self.abi),
                       "fingerprint-sha256 " + self.fp_sha,
                       "donor %s" % os.path.basename(donor), "set %s %s" % (st.header["tag"], set_path)]
        oem_src = oem_sources(self.release_dir, self.abi, rel) if self.accept_oem else []
        work = os.path.join(self.out, "work")
        jars, dev, native, (bak, sma) = self.reference_check(st, work)
        dj = extract_donor(donor, jars, os.path.join(work, "donor-jars"))
        stage = os.path.join(self.out, "stage")
        manifest = {"source": s.source, "system": os.path.abspath(s.root), "android": self.android,
                    "line": self.line, "abi": self.abi, "fingerprint_sha256": self.fp_sha,
                    "bootclasspath": s.bootclasspath, "dalvik_only": "core-libart" not in jars,
                    "donor": os.path.abspath(donor), "donor_sha256": sha256_file(donor), "release": rel,
                    "set": os.path.abspath(set_path), "tag": st.header["tag"], "jars": {}}
        replaced_smali, changed, staged = {}, {}, {}
        for j in jars:
            manifest["jars"][j], staged[j], replaced_smali[j], changed[j] = self.patch_jar(
                j, st, dev[j], dj[j], work, stage, bak, sma)
        manifest["linkcheck"] = self.link_check(staged, replaced_smali, changed, "core-libart" not in jars)
        manifest["zip"], manifest["zip_sha256"] = self.write_zip(manifest, stage, donor, donor_conf)
        self.lines.append("zip %s sha256 %s" % (manifest["zip"], manifest["zip_sha256"]))
        if native is not None:
            manifest["oem"] = {"markers": self.oem, "native_report": NATIVE_REPORT, "extra": native, "zips": {}}
        for kind, src in oem_src:
            name, sha = self.write_oem_zip(kind, src, rel)
            manifest["oem"]["zips"][kind] = {"zip": name, "sha256": sha}
            self.lines.append("zip %s sha256 %s" % (name, sha))
        rawzip.atomic_write(os.path.join(stage, "manifest.json"),
                            json.dumps(manifest, indent=1, sort_keys=True) + "\n")
        shutil.rmtree(work, ignore_errors=True)
        return manifest

    def reference_check(self, st, work):
        """The device's side before anything is staged (odex, jars, OEM/CM scan, one verdict per set line, conscrypt
        natives); returns ([jars to patch], {jar: {descriptor: (smali path, digest)}} of the device jars (disassembled
        under work/device/), the number of extra native consumers or None without a scan, (baksmali.jar, smali.jar));
        raises Refused with every reason."""
        s = self.system
        jars, reasons = check_jars(s)
        reasons = check_odex(s) + reasons
        self.oem = oem_markers(s.prop_keys)
        native = None
        if self.oem or self.accept_oem:
            native = self.native_report()
            if self.oem and not self.accept_oem:
                reasons.append(("-", self.oem[0], "OEM/CM build: rerun with --accept-oem after reading the report %s "
                                "(the openssl and conscrypt zips refuse this system without the copies that option "
                                "writes)" % os.path.join(self.out, NATIVE_REPORT)))
        bak, sma = normalize.smali_jars()
        dev, dev_entries = {}, {}
        for j in jars:
            log("baksmali %s.jar (device)" % j)
            dev[j] = disassemble(s.path("framework", j + ".jar"), os.path.join(work, "device", j), bak)
            dev_entries[j] = mkset.entry_digests(s.path("framework", j + ".jar"))
        self.verdicts, already = verdicts(st, jars, dev, dev_entries, s)
        bad = [v for v in self.verdicts if v.verdict != "match"]
        if already:
            reasons.insert(0, ("-", "-", "the system already carries kktls: restore it first (kktls-restore zip), "
                                         "then patch the restored jars"))
        reasons += [(j, n, d or describe(v, st.header["tag"])) for v, k, j, n, d in bad]
        if "conscrypt" in jars:
            # set classes are replaced, check classes equal stock: only a vendor class can carry other natives
            listed = {c for jj, c, _, _ in st.classes if jj == "conscrypt"} | \
                     {c for jj, c, _ in st.checks if jj == "conscrypt"}
            for c, (p, _) in sorted(dev["conscrypt"].items()):
                nat = [] if c in listed else native_methods(p)
                if nat:
                    reasons.append(("conscrypt", c, "declares %d native method(s) (%s%s): the donor's "
                                    "libjavacrypto.so replaces the device's and registers only the stock 4.4 ones" %
                                    (len(nat), "; ".join(nat[:2]), "; ..." if len(nat) > 2 else "")))
        if reasons:
            raise Refused(reasons)
        log("reference check: %d lines match" % len(self.verdicts))
        return jars, dev, native, (bak, sma)

    def patch_jar(self, j, st, dev, donor_jar, work, stage, bak, sma):
        """Stage one jar: the set's classes of the donor jar donor_jar in the device's smali tree (dev: {descriptor:
        (smali path, digest)} of the device jar), assembled to stage/<j>/classes.dex and checked (id limits, round
        trip), the set's entries extracted; returns (its manifest entry, the dex path, {descriptor: smali path} of
        the replacement classes, {descriptor} of every set class of the jar)."""
        s = self.system
        log("baksmali %s.jar (donor)" % j)
        don = disassemble(donor_jar, os.path.join(work, "donor", j), bak)
        don_entries = mkset.entry_digests(donor_jar)
        if mkset.aggregate({c: dg for c, (_, dg) in don.items()}, don_entries) != st.ours[j]:
            raise ToolError("donor %s.jar does not give the set's ours aggregate (wrong release dir or set file: "
                            "the release and the set do not belong together)" % j)
        tree = os.path.join(work, "device", j)
        expect = {c: dg for c, (_, dg) in dev.items()}
        replaced = removed = 0
        replaced_smali, changed = {}, set()
        for jj, c, _, ours in st.classes:
            if jj != j:
                continue
            changed.add(c)
            if (don[c][1] if c in don else None) != ours:
                raise ToolError("donor %s.jar class %s does not match the set's ours digest (wrong release "
                                "dir or set file)" % (j, c))
            if ours is None:
                os.remove(dev[c][0])
                expect.pop(c)
                removed += 1
                continue
            dst = dev[c][0] if c in dev else os.path.join(tree, os.path.relpath(
                don[c][0], os.path.join(work, "donor", j)))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(don[c][0], dst)
            replaced_smali[c] = dst
            expect[c] = ours
            replaced += 1
        dex = os.path.join(stage, j, "classes.dex")
        log("smali %s.jar: %d class(es) replaced, %d removed" % (j, replaced, removed))
        assemble(tree, dex, sma)
        with open(dex, "rb") as f:
            ids = linkcheck.id_counts(f.read(linkcheck.HEADER_SIZE))
        over = ["%s ids %d" % (k, n) for k, n in sorted(ids.items()) if n >= ID_LIMIT]
        if over:
            raise Refused([(j, "classes.dex", "%s >= %d (single-dex jar)" % (", ".join(over), ID_LIMIT))])
        log("round-trip check %s.jar" % j)
        got = {c: dg for c, (_, dg) in disassemble(dex, os.path.join(work, "check", j), bak).items()}
        diff = sorted(c for c in set(expect) | set(got) if expect.get(c) != got.get(c))
        if diff:
            raise Refused([(j, c, "round trip: digest %s, expected %s" % (got.get(c, "-"), expect.get(c, "-")))
                           for c in diff])
        entries = {}
        for jj, p, _, ours in st.entries:
            if jj != j:
                continue
            if don_entries.get(p) != ours:
                raise ToolError("donor %s.jar entry %s does not match the set's ours sha256" % (j, p))
            entries[p] = None
            if ours is not None:
                dst = os.path.join(stage, j, p)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with zipfile.ZipFile(donor_jar) as z, open(dst, "wb") as f:
                    f.write(z.read(p))
                entries[p] = os.path.relpath(dst, stage)
        entry = {"device": os.path.abspath(s.path("framework", j + ".jar")),
                 "sha256": sha256_file(s.path("framework", j + ".jar")),
                 "odex": j + ".odex" in s.odex["framework"],
                 "dex": os.path.relpath(dex, stage), "entries": entries,
                 "replaced": replaced, "removed": removed, "classes": len(got)}
        return entry, dex, replaced_smali, changed

    def write_zip(self, manifest, stage, donor, conf):
        """The patched jars (stage/jars/<jar>.jar) and the recovery zip in OUT; returns (zip name, its sha256)."""
        jars, payload = [], {}
        for j in mkset.JARS:
            v = manifest["jars"].get(j)
            if v is None:
                payload["system/framework/%s.jar" % j] = None   # dropped when the donor has it (Dalvik-only)
                continue
            with open(os.path.join(stage, v["dex"]), "rb") as f:
                dex = f.read()
            entries = {}
            for p, rel in v["entries"].items():
                if rel is None:
                    entries[p] = None
                else:
                    with open(os.path.join(stage, rel), "rb") as f:
                        entries[p] = f.read()
            dst = os.path.join(stage, "jars", j + ".jar")
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            write_checked(v["device"], dst, dict(entries, **{"classes.dex": dex}))
            v["patched"], v["patched_sha256"] = os.path.relpath(dst, stage), sha256_file(dst)
            with open(dst, "rb") as f:
                payload["system/framework/%s.jar" % j] = f.read()
            jars.append((j, v["sha256"]))
        with zipfile.ZipFile(donor) as z:
            names = set(z.namelist())
            notice = z.read("NOTICE").decode("utf-8", "replace") if "NOTICE" in names else ""
        payload = {n: b for n, b in payload.items() if b is not None or n in names}
        payload["NOTICE"] = patched_notice(notice, os.path.basename(donor), [j for j, _ in jars],
                                           manifest["tag"]).encode("utf-8")
        payload["kktls/zip.conf"] = zip_conf(conf, manifest["release"], self.abi, self.android, jars,
                                             self.fp_sha).encode("utf-8")
        name = "kktls-java-patched-%s-%s-%s-%s.zip" % (self.android, self.abi, manifest["release"], self.fp_sha[:8])
        dst = os.path.join(self.out, name)
        write_checked(donor, dst, payload)
        log("wrote %s" % dst)
        return name, sha256_file(dst)

    def native_report(self):
        """Scan the device's native consumers of libssl/libcrypto, write OUT/native-consumers.txt and the report
        lines; returns the number of consumers not in the AOSP 4.4 list."""
        s = self.system
        failed = fetch_native(s) if s.adb is not None else []
        res = nativescan.scan(s.root)
        res["unreadable"] = sorted(res["unreadable"] + failed)
        try:
            aosp = nativescan.read_list()
        except OSError as e:
            raise ToolError("AOSP consumer list: %s" % e)
        lines, extra = nativescan.report(res, aosp)
        head = ["# kktls-jarpatch native-consumer report",
                "# OEM/CM markers in build.prop: %s" % (" ".join(self.oem) or "none"),
                "# The kktls openssl zip replaces /system/lib/libssl.so and libcrypto.so with OpenSSL 1.0.1u built from",
                "# the AOSP 4.4 sources. A file below that the vendor built against its own OpenSSL headers (other",
                "# SSL/SSL_CTX/... layouts) may crash or misbehave with them. 'extra' = not in the AOSP 4.4 list",
                "# (aosp44-ssl-consumers.txt); 'aosp' = an AOSP name, which a vendor may also have rebuilt;",
                "# 'unreadable' = not scanned. --accept-oem writes the openssl and conscrypt zips for this system",
                "# anyway: keep the kktls restore zip at hand."]
        path = os.path.join(self.out, NATIVE_REPORT)
        rawzip.atomic_write(path, "\n".join(head + lines) + "\n")
        self.lines += ["oem-marker " + m for m in self.oem] + ["native " + l for l in lines]
        log("native consumers: %s (%s)" % (lines[0], path))
        return extra

    def write_oem_zip(self, kind, src, rel):
        """OUT/kktls-<openssl-oem-4.4|conscrypt-oem>-<abi>-<rel>-<fp8>.zip: the release zip with oem_ack= appended to
        its zip.conf, every other entry copied byte for byte; returns (name, sha256)."""
        with zipfile.ZipFile(src) as z:
            text = z.read("kktls/zip.conf").decode("utf-8", "replace")
        name = "kktls-%s-oem-%s%s-%s-%s.zip" % (kind, "4.4-" if kind == "openssl" else "", self.abi, rel,
                                                self.fp_sha[:8])
        dst = os.path.join(self.out, name)
        write_checked(src, dst, {"kktls/zip.conf": oem_conf(text, self.fp_sha).encode("utf-8")})
        log("wrote %s (for this system only)" % dst)
        return name, sha256_file(dst)

    def write_report(self, path, result, reasons):
        """--report: the report lines, one line per verdict and per refusal reason, then `result staged|refused`."""
        out = ["# kktls-jarpatch report", "source %s" % self.system.source] + self.lines
        out += ["%s %s %s %s%s" % (v, k, j, n, (" - " + d) if d else "") for v, k, j, n, d in self.verdicts]
        out += ["refused %s %s: %s" % r for r in reasons]
        out.append("result " + result)
        rawzip.atomic_write(path, "\n".join(out) + "\n")

    def link_check(self, staged, replaced, changed, dalvik_only):
        s = self.system
        try:
            stats, misses = linkcheck.run(s.root, s.bootclasspath, staged, replaced, changed, dalvik_only, log)
        except linkcheck.LinkError as e:
            raise ToolError("link check: %s" % e)
        for rt, v in sorted(stats.items()):
            self.lines.append("linkcheck %s %s" % (rt, " ".join("%s=%d" % kv for kv in sorted(v.items()))))
            log("link check %s: %d dex, %d of %d references into the set checked, %d regression(s); %d replacement "
                "class reference(s), %d unresolved" % (rt, v["dex"], v["refs_checked"], v["refs_total"],
                                                       v["regressions"], v["outbound_refs"], v["outbound_misses"]))
        if misses:
            raise Refused([(w, n, "link check: " + why) for w, n, why in misses])
        return stats


def write_report(patcher, path, result, reasons):
    """Patcher.write_report; False (an error line printed) when it fails: a tool error (exit 2), never "refused"."""
    try:
        patcher.write_report(path, result, reasons)
        return True
    except OSError as e:
        print("kktls-jarpatch: error: --report %s: %s" % (path, e), file=sys.stderr)
    except Exception as e:     # as main's catch-all
        print("kktls-jarpatch: unexpected error: %s: %s" % (type(e).__name__, e), file=sys.stderr)
    return False


def main(argv):
    usage = ("usage: kktls-jarpatch.py (--adb SERIAL | --system DIR --bootclasspath LIST --build-prop FILE) "
             "--release-dir DIR --out DIR [--accept-oem] [--set FILE] [--report FILE]")
    opt = {}
    keys = ("--adb", "--system", "--bootclasspath", "--build-prop", "--release-dir", "--out", "--set", "--report")
    accept_oem = False
    while argv:
        a = argv.pop(0)
        if a in ("-h", "--help"):
            print(__doc__)
            return 0
        if a == "--accept-oem" and not accept_oem:
            accept_oem = True
            continue
        if a not in keys or not argv or a in opt:
            print(usage, file=sys.stderr)
            return 2
        opt[a] = argv.pop(0)
    sysopts = ("--system", "--bootclasspath", "--build-prop")
    if "--release-dir" not in opt or "--out" not in opt or \
            ("--adb" in opt) == any(k in opt for k in sysopts) or \
            ("--adb" not in opt and not all(k in opt for k in sysopts)):
        print(usage, file=sys.stderr)
        return 2
    out = opt["--out"]
    if os.path.exists(out) and (not os.path.isdir(out) or os.listdir(out)):
        print("kktls-jarpatch: --out %s exists and is not an empty directory" % out, file=sys.stderr)
        return 2
    patcher = None
    try:
        os.makedirs(out, exist_ok=True)
        if "--adb" in opt:
            system = from_adb(opt["--adb"], os.path.join(out, "device"))
        else:
            system = from_system(opt["--system"], opt["--bootclasspath"], opt["--build-prop"])
        patcher = Patcher(system, opt["--release-dir"], out, opt.get("--set"), accept_oem)
        m = patcher.run()
    except Refused as e:
        for j, n, why in e.reasons:
            print("kktls-jarpatch: REFUSED %s %s: %s" % (j, n, why), file=sys.stderr)
        if patcher and "--report" in opt and not write_report(patcher, opt["--report"], "refused", e.reasons):
            return 2
        return 1
    except (ToolError, normalize.NormalizeError, mkset.SetError, linkcheck.LinkError, OSError,
            zipfile.BadZipFile) as e:
        print("kktls-jarpatch: error: %s" % e, file=sys.stderr)
        return 2
    except Exception as e:     # a bug or an input nobody foresaw: never the "refused" exit
        print("kktls-jarpatch: unexpected error: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 2
    if "--report" in opt and not write_report(patcher, opt["--report"], "staged", []):
        print("kktls-jarpatch: the zips in %s are written; the report is not" % out, file=sys.stderr)
        return 2
    log("staged %s (%s)" % (os.path.join(out, "stage"), ", ".join(
        "%s %d replaced/%d removed" % (j, v["replaced"], v["removed"]) for j, v in sorted(m["jars"].items()))))
    log("zip %s (for this device only)" % os.path.join(out, m["zip"]))
    for kind, v in sorted(m.get("oem", {}).get("zips", {}).items()):
        log("%s zip %s (for this device only)" % (kind, os.path.join(out, v["zip"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
