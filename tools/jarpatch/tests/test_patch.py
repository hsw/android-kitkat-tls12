# SPDX-License-Identifier: Apache-2.0
"""Unit tests of kktls-jarpatch.py on fixture systems assembled from smali sources: the staged classes equal the
donor's (the oracle in fixture form), the round-trip invariant, and each refusal with its reason (vendor-modified
class, vendor-modified check class, missing class, unexpected class, stripped jar, already patched, a vendor backport
equal to the kktls class, and the link check hooked into the run: a caller of a class the series removes, a replacement
class calling a member the device's boot class path lacks). Skipped without Java and the smali jars of
fetch-smali.sh, except the pure-logic tests.

    python3 -I -m unittest discover tools/jarpatch/tests

Local only: with KKTLS_JARPATCH_ORACLE_SYSTEM (a /system copy holding framework/ and build.prop of a stock AOSP 4.4
build) and KKTLS_JARPATCH_ORACLE_RELEASE (the release dir with SHA256SUMS and the java zips) set, Oracle patches the
stock jars and compares every class with the release java zip of that line; KKTLS_JARPATCH_ORACLE_BOOTCLASSPATH (the
image's BOOTCLASSPATH) replaces the default core:conscrypt:okhttp for the link check.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
sys.path.insert(0, TOOL)
import mkset  # noqa: E402
import normalize  # noqa: E402
from test_nativescan import elf  # noqa: E402

SCRIPT = os.path.join(TOOL, "kktls-jarpatch.py")
_spec = importlib.util.spec_from_file_location("kktls_jarpatch", SCRIPT)
jp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(jp)

INT = "Ljava/lang/Integer;"                                        # check class (core, core-libart)
DHV = "Ljavax/net/ssl/DefaultHostnameVerifier;"                    # changed by the series
KK = "Lio/github/hsw/kktls/KktlsDefaultSSLSocketFactory;"          # added by the series (kktls package)
GONE = "Lcom/example/Gone;"                                        # removed by the series
VEN = "Lcom/vendor/Extra;"                                         # the vendor's own class, not in the set
NAT = "Lcom/android/org/conscrypt/NativeCrypto;"                   # changed
BIO = "Lcom/android/org/conscrypt/OpenSSLBIOInputStream;"          # check class (conscrypt)
ADDR = "Lcom/android/org/conscrypt/AddressUtils;"                  # added (not kktls package)
OKP = "Lcom/android/okhttp/internal/Platform;"                     # changed
OBJ = "Ljava/lang/Object;"                                         # ext.jar (boot class path, outside the set)
HELP = "Lcom/example/Helper;"                                      # ext.jar; ours' DefaultHostnameVerifier calls it
CALLER = "Lcom/vendor/Caller;"                                     # calls the removed class (link check tests)
PROPS = "java/security/security.properties"
REPLACED = {DHV, KK, NAT, ADDR, OKP}
JNI = [INT, NAT, BIO]
LINE, ABI, REL = "4.4.4", "armeabi-v7a", "vT"
DONOR = "kktls-java-%s-%s-%s.zip" % (LINE, ABI, REL)
OPENSSL, CONSCRYPT = "kktls-openssl-4.4-%s-%s.zip" % (ABI, REL), "kktls-conscrypt-%s-%s.zip" % (ABI, REL)
BCP = ":".join("/system/framework/%s.jar" % j for j in ("core", "conscrypt", "okhttp", "ext"))
FINGERPRINT = "fixture/fixture/fixture:4.4.4/FIX/1:user/test-keys"

FIXTURE = """\
.class public %(desc)s
.super Ljava/lang/Object;
.source "Fixture.java"


# direct methods
"""
VALUE = """\
.method public static value()I
    .registers 1

    .prologue
    .line %(line)d
    const/4 v0, %(const)s

    return v0
.end method
"""
CALL = """\
.method public static call()V
    .registers 1

    invoke-static {}, %(call)s

    return-void
.end method
"""


def fixture_smali(desc, line, const, call=None):
    """One class: value()I returning const (none when const is None), call()V invoking call (a static method ref);
    java.lang.Object has no superclass."""
    t = FIXTURE % {"desc": desc}
    if desc == OBJ:
        t = t.replace(".super %s\n" % OBJ, "")
    if const is not None:
        t += VALUE % {"line": line, "const": const}
    if call:
        t += CALL % {"call": call}
    return t


# {jar: ([(desc, line, const[, call])], {entry: bytes})}  (see fixture_smali)
STOCK = {
    "core": ([(INT, 3, "0x1"), (DHV, 3, "0x1"), (GONE, 3, "0x1")], {PROPS: b"a=1\n"}),
    "conscrypt": ([(NAT, 3, "0x1"), (BIO, 3, "0x1")], {}),
    "okhttp": ([(OKP, 3, "0x1")], {}),
}
STOCK["core-libart"] = STOCK["core"]
OURS = {
    "core": ([(INT, 3, "0x1"), (DHV, 3, "0x2", HELP + "->value()I"), (KK, 3, "0x1")], {PROPS: b"a=1\nkktls=1\n"}),
    "conscrypt": ([(NAT, 3, "0x3"), (BIO, 3, "0x1"), (ADDR, 3, "0x1")], {}),
    "okhttp": ([(OKP, 3, "0x2")], {}),
}
OURS["core-libart"] = OURS["core"]


def device_jars():
    """The stock jars with other line numbers (debug info only) and a vendor class in each."""
    return {j: ([(d, l + 10, c) for d, l, c in cls] + [(VEN, 5, "0x7")], dict(ent)) for j, (cls, ent) in STOCK.items()}


EXT = [(OBJ, 1, None), (HELP, 1, "0x1")]       # /system/framework/ext.jar of the device


def smali_or_skip(test):
    if not shutil.which(normalize.JAVA):
        test.skipTest("no %s on PATH" % normalize.JAVA)
    try:
        return normalize.smali_jars()
    except normalize.NormalizeError as e:
        test.skipTest("smali/baksmali not available: %s" % e)


def write_prop(path, **over):
    props = {"ro.build.version.release": LINE, "ro.product.cpu.abi": ABI, "ro.build.fingerprint": FINGERPRINT}
    props.update(over)
    with open(path, "w") as f:
        f.write("# fixture\n" + "".join("%s=%s\n" % kv for kv in props.items() if kv[1] is not None))


FAKE_ADB = r"""
import os, shutil, sys
root = os.environ["FAKE_ADB_ROOT"]
a = sys.argv[1:]
if a[:1] == ["-s"]:
    a = a[2:]
dev = lambda p: os.path.join(root, p.lstrip("/"))
if a == ["get-state"]:
    print("device")
elif a[:1] == ["pull"]:
    if not os.path.isfile(dev(a[1])) or a[1] == os.environ.get("FAKE_ADB_DENY"):
        sys.stderr.write("remote object '%s' does not exist\n" % a[1])
        sys.exit(1)
    shutil.copyfile(dev(a[1]), a[2])
elif a[:1] == ["shell"]:
    c = a[1]
    if c == "echo $BOOTCLASSPATH":
        sys.stdout.write(os.environ["FAKE_ADB_BCP"] + "\r\n")
    elif c.startswith("ls -lR ") and c.endswith(" 2>&1"):     # toolbox format, its stderr in the stream
        top = c[len("ls -lR "):-len(" 2>&1")]
        for d, dirs, files in os.walk(dev(top)):
            dirs.sort()
            sys.stdout.write("\r\n/%s:\r\n" % os.path.relpath(d, root))
            if "/" + os.path.relpath(d, root) == os.environ.get("FAKE_ADB_DENY_DIR"):
                sys.stdout.write("opendir failed, Permission denied\r\n")
                dirs[:] = []
                continue
            for n in sorted(dirs + files):
                p = os.path.join(d, n)
                if os.path.islink(p):
                    l = "lrwxrwxrwx root root 2014-01-01 00:00 %s -> %s" % (n, os.readlink(p))
                elif os.path.isdir(p):
                    l = "drwxr-xr-x root root 2014-01-01 00:00 " + n
                else:
                    l = "-rw-r--r-- root root %d 2014-01-01 00:00 %s" % (os.path.getsize(p), n)
                sys.stdout.write(l + "\r\n")
    elif c.startswith("ls ") and c.endswith(" 2>/dev/null"):
        d = dev(c[3:-len(" 2>/dev/null")])
        if os.path.isdir(d):
            sys.stdout.write("".join(n + "\r\n" for n in sorted(os.listdir(d))))
    elif c.startswith("cat "):
        with open(dev(c[4:])) as f:
            sys.stdout.write(f.read().replace("\n", "\r\n"))
    else:
        sys.exit(1)
else:
    sys.exit(1)
"""


class Fixture(unittest.TestCase):
    """Builds the stock, ours (donor) and device jars once; each test copies the device tree and mutates it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = cls.tmp.name
        cls.jars = None
        if not shutil.which(normalize.JAVA):
            return
        try:
            cls.jars = normalize.smali_jars()
        except normalize.NormalizeError:
            return
        n = 0
        cls.cache = {}
        for side, spec in (("stock", STOCK), ("ours", OURS), ("device", device_jars())):
            for j, (classes, entries) in spec.items():
                cls.make_jar(os.path.join(cls.base, side, "system", "framework", j + ".jar"), classes, entries)
                n += 1
        cls.make_jar(os.path.join(cls.base, "device", "system", "framework", "ext.jar"), EXT, {})
        write_prop(os.path.join(cls.base, "device", "system", "build.prop"))
        os.makedirs(os.path.join(cls.base, "device", "system", "app"))
        cls.make_jar(os.path.join(cls.base, "device", "system", "app", "Vendor.apk"), [(VEN, 1, "0x1")], {})
        # set file and release dir
        bak = cls.jars[0]
        with contextlib.redirect_stderr(io.StringIO()):
            text = mkset.make_set(mkset.collect(os.path.join(cls.base, "stock"), bak),
                                  mkset.collect(os.path.join(cls.base, "ours"), bak), JNI, "android-4.4.4_r2")
        cls.set = os.path.join(cls.base, "set.txt")
        with open(cls.set, "w") as f:
            f.write(text)
        cls.rel = os.path.join(cls.base, "release")
        cls.make_release(cls.rel, os.path.join(cls.base, "ours"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def make_jar(cls, out, classes, entries, dex=True):
        key = tuple(classes)
        if key not in cls.cache:
            src = tempfile.mkdtemp(dir=cls.base, prefix="src-")
            for spec in classes:
                p = os.path.join(src, spec[0][1:-1] + ".smali")
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f:
                    f.write(fixture_smali(*spec))
            d = src + ".dex"
            r = subprocess.run([normalize.JAVA, "-jar", cls.jars[1], "a", "-a", "19", "-o", d, src],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            assert r.returncode == 0 and os.path.isfile(d), r.stdout   # smali exits 0 on some errors
            cls.cache[key] = d
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            if dex:
                z.write(cls.cache[key], "classes.dex")
            for n, data in entries.items():
                z.writestr(n, data)

    @classmethod
    def make_release(cls, rel, ours, conf=None, installer="# java-patched) oem_ack\n"):
        """The donor java zip and the openssl and conscrypt zips the --accept-oem copies are made from; installer:
        their kktls/checks.sh (None: none, an installer older than the jar patcher)."""
        os.makedirs(rel, exist_ok=True)
        c = {"kind": "java", "release": REL, "abi": ABI, "android": LINE, "tag": "android-4.4.4_r2"}
        c.update(conf or {})
        with zipfile.ZipFile(os.path.join(rel, DONOR), "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("kktls/zip.conf", "".join("%s=%s\n" % kv for kv in c.items()))
            zf.writestr("NOTICE", "donor notices\n")
            if installer is not None:
                zf.writestr("kktls/checks.sh", installer)
            for j in mkset.JARS:
                zf.write(os.path.join(ours, "system", "framework", j + ".jar"), "system/framework/%s.jar" % j)
            zf.writestr("system/lib/libjavacrypto.so", b"\x7fELF fixture")
        for kind, name, payload in (("openssl", OPENSSL, "system/lib/libssl.so"),
                                    ("conscrypt", CONSCRYPT, "system/framework/kktls-conscrypt.jar")):
            with zipfile.ZipFile(os.path.join(rel, name), "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("kktls/zip.conf", "kind=%s\nrelease=%s\nabi=%s\nandroid=4.4\ntag=android-4.4.2_r2\n" %
                            (kind, REL, ABI))
                if installer is not None:
                    zf.writestr("kktls/checks.sh", installer, zipfile.ZIP_STORED)
                zf.writestr(payload, kind.encode() * 50)
        with open(os.path.join(rel, "SHA256SUMS"), "w") as f:
            for n in (DONOR, OPENSSL, CONSCRYPT):
                with open(os.path.join(rel, n), "rb") as z:
                    f.write("%s  %s\n" % (hashlib.sha256(z.read()).hexdigest(), n))

    def setUp(self):
        if self.jars is None:
            smali_or_skip(self)
        self.t = tempfile.TemporaryDirectory()
        self.dev = os.path.join(self.t.name, "dev")
        shutil.copytree(os.path.join(self.base, "device"), self.dev)
        self.sysdir = os.path.join(self.dev, "system")
        self.out = os.path.join(self.t.name, "out")
        self.report = os.path.join(self.t.name, "report.txt")

    def tearDown(self):
        self.t.cleanup()

    def device_jar(self, j, classes=None, entries=None, dex=True):
        dc, de = device_jars()[j]
        self.make_jar(os.path.join(self.sysdir, "framework", j + ".jar"), dc if classes is None else classes,
                      de if entries is None else entries, dex)

    def patch(self, *extra, adb=False, release=None):
        if adb:
            bindir = os.path.join(self.t.name, "bin")
            os.makedirs(bindir, exist_ok=True)
            fake = os.path.join(bindir, "adb")
            with open(fake, "w") as f:
                f.write("#!%s -I\n%s" % (sys.executable, FAKE_ADB))
            os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
            env = dict(os.environ, PATH=bindir + os.pathsep + os.environ.get("PATH", ""), FAKE_ADB_ROOT=self.dev,
                       FAKE_ADB_BCP=BCP)
            args = ["--adb", "emulator-5554"]
        else:
            env = None
            args = ["--system", self.dev, "--bootclasspath", BCP, "--build-prop",
                    os.path.join(self.sysdir, "build.prop")]
        args += ["--release-dir", release or self.rel, "--out", self.out, "--set", self.set, "--report", self.report]
        r = subprocess.run([sys.executable, "-I", SCRIPT] + args + list(extra), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True, env=env)
        return r.returncode, r.stdout

    def read_report(self):
        with open(self.report) as f:
            return f.read()

    def assertRefused(self, rc, out, *needles):
        self.assertEqual(rc, 1, out)
        for n in needles:
            self.assertIn(n, out)
        self.assertFalse(os.path.exists(os.path.join(self.out, "stage", "manifest.json")))

    def digests(self, src):
        d = tempfile.mkdtemp(dir=self.t.name)
        return {c: (p, dg) for c, (p, dg) in jp.disassemble(src, os.path.join(d, "o"), self.jars[0]).items()}


class Patch(Fixture):
    def check_staged(self, rc, out, jars=mkset.JARS):
        self.assertEqual(rc, 0, out)
        stage = os.path.join(self.out, "stage")
        with open(os.path.join(stage, "manifest.json")) as f:
            m = json.load(f)
        self.assertEqual(sorted(m["jars"]), sorted(jars))
        self.assertEqual((m["line"], m["abi"], m["release"], m["tag"]), (LINE, ABI, REL, "android-4.4.4_r2"))
        self.assertEqual(m["fingerprint_sha256"], hashlib.sha256(FINGERPRINT.encode()).hexdigest())
        self.assertNotIn(FINGERPRINT, json.dumps(m) + out + self.read_report())
        for j in jars:
            got = self.digests(os.path.join(stage, j, "classes.dex"))
            donor = self.digests(os.path.join(self.base, "ours", "system", "framework", j + ".jar"))
            device = self.digests(os.path.join(self.sysdir, "framework", j + ".jar"))
            # the oracle in fixture form: every class equals the donor's; a replaced class is the donor's whole
            # .smali file (debug info included), the others keep the device's text
            for c, (p, dg) in donor.items():
                self.assertEqual(got[c][1], dg, (j, c))
                with open(p if c in REPLACED else device[c][0]) as a, open(got[c][0]) as b:
                    self.assertEqual(a.read(), b.read(), (j, c))
            self.assertNotIn(GONE, got)
            self.assertEqual(got[VEN][1], device[VEN][1])          # the vendor class kept
            self.assertEqual(set(got), set(donor) | {VEN})
            v = m["jars"][j]
            with open(os.path.join(self.sysdir, "framework", j + ".jar"), "rb") as f:
                self.assertEqual(v["sha256"], hashlib.sha256(f.read()).hexdigest())
            if j in ("core", "core-libart"):
                with open(os.path.join(stage, j, PROPS), "rb") as f:
                    self.assertEqual(f.read(), b"a=1\nkktls=1\n")
                self.assertEqual((v["replaced"], v["removed"], v["entries"]), (2, 1, {PROPS: "%s/%s" % (j, PROPS)}))
        self.assertIn("result staged", self.read_report())
        return m

    def check_zip(self, m, jars=mkset.JARS):
        """The recovery zip: the donor with the patched jars and a java-patched zip.conf; each patched jar is the
        device jar with classes.dex and security.properties swapped, every other entry byte for byte."""
        fp = hashlib.sha256(FINGERPRINT.encode()).hexdigest()
        name = "kktls-java-patched-4.4.4-%s-%s-%s.zip" % (ABI, REL, fp[:8])
        self.assertEqual(m["zip"], name)
        path = os.path.join(self.out, name)
        with open(path, "rb") as f:
            self.assertEqual(m["zip_sha256"], hashlib.sha256(f.read()).hexdigest())
        stage = os.path.join(self.out, "stage")
        with zipfile.ZipFile(path) as z, zipfile.ZipFile(os.path.join(self.rel, DONOR)) as d:
            conf = ["kind=java-patched", "release=" + REL, "abi=" + ABI, "android=4.4.4", "tag=android-4.4.4_r2"]
            conf += ["jar.%s=%s" % (j, m["jars"][j]["sha256"]) for j in jars] + ["fingerprint=" + fp]
            self.assertEqual(z.read("kktls/zip.conf").decode().splitlines(), conf)
            self.assertEqual(z.namelist(), [n for n in d.namelist() if n != "system/framework/core-libart.jar" or
                                            "core-libart" in jars])
            self.assertEqual(z.read("system/lib/libjavacrypto.so"), d.read("system/lib/libjavacrypto.so"))
            notice = z.read("NOTICE").decode()
            self.assertTrue(notice.startswith("Notices for a kktls java-patched zip\n"), notice)
            self.assertIn("system/framework/{%s}.jar are that system's own jars" % ",".join(jars), notice)
            self.assertTrue(notice.endswith("Notices of %s\n%s\n\ndonor notices\n" % (DONOR, "=" * 77)), notice)
            for j in jars:
                data = z.read("system/framework/%s.jar" % j)
                with open(os.path.join(stage, m["jars"][j]["patched"]), "rb") as f:
                    self.assertEqual(data, f.read())
                with open(os.path.join(self.sysdir, "framework", j + ".jar"), "rb") as f:
                    dev = f.read()
                with zipfile.ZipFile(io.BytesIO(data)) as pj, zipfile.ZipFile(io.BytesIO(dev)) as dj:
                    self.assertEqual(pj.namelist(), dj.namelist())
                    with open(os.path.join(stage, j, "classes.dex"), "rb") as f:
                        self.assertEqual(pj.read("classes.dex"), f.read())
                    mf = dj.getinfo("META-INF/MANIFEST.MF")
                    start = mf.header_offset
                    end = min(i.header_offset for i in dj.infolist() if i.header_offset > start)
                    self.assertIn(dev[start:end], data)          # the untouched entry's local record, raw
                    if j in ("core", "core-libart"):
                        self.assertEqual(pj.read(PROPS), b"a=1\nkktls=1\n")

    def test_system(self):
        rc, out = self.patch()
        m = self.check_staged(rc, out)
        self.check_zip(m)
        self.assertIn("zip %s sha256 %s" % (m["zip"], m["zip_sha256"]), self.read_report())
        self.assertEqual((m["source"], m["bootclasspath"], m["dalvik_only"]), ("system", BCP.split(":"), False))
        self.assertFalse(os.path.exists(os.path.join(self.out, "work")))
        rep = self.read_report()
        for rt in ("dalvik", "art"):
            v = m["linkcheck"][rt]
            self.assertEqual((v["regressions"], v["outbound_misses"], v["outbound_classes"]), (0, 0, 5), rt)
            self.assertIn("linkcheck %s " % rt, rep)
        self.assertEqual(m["linkcheck"]["dalvik"]["bootclasspath"], 4)
        self.assertIn("match class core %s" % DHV, rep)
        self.assertIn("match check conscrypt %s" % BIO, rep)
        self.assertIn("match entry core %s" % PROPS, rep)

    def test_adb(self):
        rc, out = self.patch(adb=True)
        m = self.check_staged(rc, out)
        self.assertEqual((m["source"], m["bootclasspath"]), ("adb", BCP.split(":")))
        for p in ("framework/core.jar", "app/Vendor.apk", "build.prop"):
            self.assertTrue(os.path.isfile(os.path.join(self.out, "device", p)), p)

    def test_dalvik_only(self):
        os.remove(os.path.join(self.sysdir, "framework", "core-libart.jar"))
        rc, out = self.patch()
        m = self.check_staged(rc, out, jars=("core", "conscrypt", "okhttp"))
        self.check_zip(m, jars=("core", "conscrypt", "okhttp"))
        self.assertTrue(m["dalvik_only"])
        self.assertEqual(sorted(m["linkcheck"]), ["dalvik"])

    def test_core_libart_missing_with_art(self):
        os.remove(os.path.join(self.sysdir, "framework", "core-libart.jar"))
        os.makedirs(os.path.join(self.sysdir, "lib"))
        open(os.path.join(self.sysdir, "lib", "libart.so"), "w").close()
        rc, out = self.patch()
        self.assertRefused(rc, out, "core-libart -: /system/framework/core-libart.jar is missing")

    def test_odexed_jars_with_dex(self):
        for p in ("framework/core.odex", "app/Vendor.odex"):
            open(os.path.join(self.sysdir, p), "w").close()
        rc, out = self.patch()
        m = self.check_staged(rc, out)
        self.assertTrue(m["jars"]["core"]["odex"])

    def oem_system(self):
        """A CM build with an AOSP-named and an extra libssl consumer."""
        write_prop(os.path.join(self.sysdir, "build.prop"), **{"ro.cm.version": "11-20140804-NIGHTLY-fixture"})
        for p, need in (("lib/libjavacrypto.so", ["libssl.so"]), ("vendor/lib/libvendorssl.so", ["libcrypto.so"]),
                        ("bin/static", None)):
            os.makedirs(os.path.dirname(os.path.join(self.sysdir, p)), exist_ok=True)
            with open(os.path.join(self.sysdir, p), "wb") as f:
                f.write(elf(need) if need else elf(dynamic=False))

    def test_oem_refused_adb(self):
        # without --accept-oem: refused after the scan, the report is there; a file the shell cannot read is listed
        self.oem_system()
        os.makedirs(os.path.join(self.sysdir, "vendor", "secret"))
        with open(os.path.join(self.sysdir, "vendor", "secret", "libhidden.so"), "wb") as f:
            f.write(elf(["libssl.so"]))
        os.environ.update(FAKE_ADB_DENY="/system/bin/static", FAKE_ADB_DENY_DIR="/system/vendor/secret")
        try:
            rc, out = self.patch(adb=True)
        finally:
            del os.environ["FAKE_ADB_DENY"], os.environ["FAKE_ADB_DENY_DIR"]
        self.assertRefused(rc, out, "REFUSED - ro.cm.version: OEM/CM build: rerun with --accept-oem after reading "
                                    "the report " + os.path.join(self.out, "native-consumers.txt"))
        with open(os.path.join(self.out, "native-consumers.txt")) as f:
            rep = f.read().splitlines()
        self.assertIn("extra vendor/lib/libvendorssl.so libcrypto.so", rep)
        self.assertIn("aosp lib/libjavacrypto.so libssl.so", rep)
        self.assertTrue(any(l.startswith("unreadable bin/static: adb pull failed") for l in rep), rep)
        self.assertIn("unreadable vendor/secret/: not listable: opendir failed, Permission denied", rep)
        self.assertFalse([l for l in rep if "libhidden" in l], rep)
        self.assertIn("native extra vendor/lib/libvendorssl.so libcrypto.so", self.read_report())
        self.assertIn("oem-marker ro.cm.version", self.read_report())
        self.assertEqual(sorted(n for n in os.listdir(self.out) if n.endswith(".zip")), [])

    def test_oem_accepted(self):
        self.oem_system()
        rc, out = self.patch("--accept-oem")
        m = self.check_staged(rc, out)
        fp = hashlib.sha256(FINGERPRINT.encode()).hexdigest()
        names = {"openssl": "kktls-openssl-oem-4.4-%s-%s-%s.zip" % (ABI, REL, fp[:8]),
                 "conscrypt": "kktls-conscrypt-oem-%s-%s-%s.zip" % (ABI, REL, fp[:8])}
        self.assertEqual((m["oem"]["markers"], m["oem"]["extra"]), (["ro.cm.version"], 1))
        for kind, src in (("openssl", OPENSSL), ("conscrypt", CONSCRYPT)):
            path = os.path.join(self.out, names[kind])
            with open(path, "rb") as f:
                data = f.read()
            self.assertEqual(m["oem"]["zips"][kind], {"zip": names[kind],
                                                      "sha256": hashlib.sha256(data).hexdigest()})
            with open(os.path.join(self.rel, src), "rb") as f:
                orig = f.read()
            with zipfile.ZipFile(io.BytesIO(data)) as z, zipfile.ZipFile(io.BytesIO(orig)) as o:
                self.assertEqual(z.namelist(), o.namelist())
                self.assertEqual(z.read("kktls/zip.conf"), o.read("kktls/zip.conf") + b"oem_ack=" + fp.encode() + b"\n")
                cd = int.from_bytes(orig[orig.rfind(b"PK\5\6") + 16:][:4], "little")
                for i in o.infolist()[1:]:                       # every other entry's local record, raw
                    start = i.header_offset
                    end = min([j.header_offset for j in o.infolist() if j.header_offset > start] + [cd])
                    self.assertIn(orig[start:end], data, i.filename)
            self.assertIn("zip %s sha256 %s" % (names[kind], m["oem"]["zips"][kind]["sha256"]), self.read_report())


class Refusals(Fixture):
    def test_vendor_modified_class(self):
        self.device_jar("core", [(INT, 3, "0x1"), (DHV, 3, "0x5"), (GONE, 3, "0x1")])
        rc, out = self.patch()
        self.assertRefused(rc, out, "REFUSED core %s: differs from stock android-4.4.4_r2" % DHV)
        self.assertNotIn("core-libart %s" % DHV, out)
        self.assertIn("vendor-modified class core %s" % DHV, self.read_report())
        self.assertIn("result refused", self.read_report())

    def test_vendor_modified_check_class(self):
        self.device_jar("conscrypt", [(NAT, 3, "0x1"), (BIO, 3, "0x4")])
        rc, out = self.patch()
        self.assertRefused(rc, out, "REFUSED conscrypt %s: differs from stock" % BIO)
        self.assertIn("vendor-modified check conscrypt %s" % BIO, self.read_report())

    def test_missing_class(self):
        self.device_jar("conscrypt", [(BIO, 3, "0x1")])
        rc, out = self.patch()
        self.assertRefused(rc, out, "REFUSED conscrypt %s: stock android-4.4.4_r2 has it, the device does not" % NAT)

    def test_missing_entry(self):
        self.device_jar("core", entries={})
        rc, out = self.patch()
        self.assertRefused(rc, out, "REFUSED core %s: stock" % PROPS)

    def test_unexpected_present(self):
        self.device_jar("conscrypt", [(NAT, 3, "0x1"), (BIO, 3, "0x1"), (ADDR, 3, "0x5")])
        rc, out = self.patch()
        self.assertRefused(rc, out, "REFUSED conscrypt %s: the series adds it" % ADDR)
        self.assertNotIn("restore", out)

    def test_stripped_jar(self):
        self.device_jar("okhttp", dex=False)
        open(os.path.join(self.sysdir, "framework", "okhttp.odex"), "w").close()
        self.make_jar(os.path.join(self.sysdir, "app", "Vendor.apk"), [(VEN, 1, "0x1")], {}, dex=False)
        open(os.path.join(self.sysdir, "app", "Vendor.odex"), "w").close()
        open(os.path.join(self.sysdir, "app", "Orphan.odex"), "w").close()
        rc, out = self.patch()
        self.assertRefused(rc, out, "REFUSED okhttp -: odexed without classes.dex",
                           "REFUSED - /system/app/Vendor.apk: odexed without classes.dex",
                           "REFUSED - /system/app/Orphan.odex: odexed, no jar/apk next to it")

    def test_already_patched(self):
        for j in mkset.JARS:
            shutil.copyfile(os.path.join(self.base, "ours", "system", "framework", j + ".jar"),
                            os.path.join(self.sysdir, "framework", j + ".jar"))
        rc, out = self.patch()
        self.assertRefused(rc, out, "the system already carries kktls: restore it first",
                           "REFUSED core %s: equals the kktls version" % KK, "REFUSED core %s: equals the kktls" % DHV)
        self.assertNotIn("vendor-modified", self.read_report())
        self.assertIn("already-kktls entry core %s" % PROPS, self.read_report())

    def test_already_patched_marker_only(self):
        os.makedirs(os.path.join(self.sysdir, "etc", "kktls"))
        with open(os.path.join(self.sysdir, "etc", "kktls", "java.version"), "w") as f:
            f.write("v6\n")
        rc, out = self.patch()
        self.assertRefused(rc, out, "restore it first", "/system/etc/kktls/java.version: installed: v6")

    def test_already_patched_marker_adb(self):
        os.makedirs(os.path.join(self.sysdir, "etc", "kktls"))
        with open(os.path.join(self.sysdir, "etc", "kktls", "java.version"), "w") as f:
            f.write("v6\n")
        rc, out = self.patch(adb=True)
        self.assertRefused(rc, out, "restore it first", "installed: v6")

    def test_vendor_backport_equal_to_ours(self):
        # cm-11 ships some classes source-identical to the series: equal to ours, but no kktls on the system
        self.device_jar("core", [(INT, 3, "0x1"), (DHV, 3, "0x2", HELP + "->value()I"), (GONE, 3, "0x1")])
        rc, out = self.patch()
        self.assertRefused(rc, out, "REFUSED core %s: equals the kktls version, but the system carries no kktls" % DHV)
        self.assertNotIn("restore", out)

    def test_gates(self):
        for over, needle in (({"ro.build.version.release": "4.3"}, "Android 4.3: only 4.4.1 to 4.4.4"),
                             ({"ro.build.version.release": "4.4"}, "Android 4.4 (android-4.4_r1/r1.2) lacks upstream"),
                             ({"ro.product.cpu.abi": "armeabi"}, "ABI armeabi"),
                             ({"ro.build.fingerprint": None}, "no build fingerprint")):
            write_prop(os.path.join(self.sysdir, "build.prop"), **over)
            rc, out = self.patch()
            self.assertRefused(rc, out, needle)
            shutil.rmtree(self.out)

    def test_id_limit_and_round_trip(self):
        # in-process with a lowered id limit, then with a class lost before reassembly
        args = ["--system", self.dev, "--bootclasspath", BCP, "--build-prop", os.path.join(self.sysdir, "build.prop"),
                "--release-dir", self.rel, "--out", self.out, "--set", self.set]
        old = jp.ID_LIMIT
        jp.ID_LIMIT = 3
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(jp.main(list(args)), 1)
            self.assertRegex(err.getvalue(), r"REFUSED core classes.dex: method ids \d+, type ids \d+ >= 3")
        finally:
            jp.ID_LIMIT = old
        shutil.rmtree(self.out)
        real = jp.assemble

        def lossy(tree, dex, smali_jar):
            for d, _, files in os.walk(tree):
                for f in files:
                    if f == "Extra.smali":
                        os.remove(os.path.join(d, f))
            real(tree, dex, smali_jar)
        jp.assemble = lossy
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(jp.main(list(args)), 1)
            self.assertIn("REFUSED core %s: round trip" % VEN, err.getvalue())
        finally:
            jp.assemble = real


class LinkCheck(Fixture):
    """The link check inside the run (linkcheck.py itself: test_linkcheck.py)."""

    def test_caller_of_removed_class(self):
        # the series removes com.example.Gone: a caller outside the boot class path, in a framework jar and an apk
        for p in ("framework/caller.jar", "app/Caller.apk"):
            self.make_jar(os.path.join(self.sysdir, p), [(CALLER, 1, "0x1", GONE + "->value()I")], {})
        rc, out = self.patch()
        for p in ("framework/caller.jar", "app/Caller.apk"):
            for ref in (GONE, GONE + "->value()I"):
                self.assertIn("REFUSED /system/%s %s: link check: resolved before the patch, not after (dalvik, art)"
                              % (p, ref), out)
        self.assertRefused(rc, out)
        self.assertIn("result refused", self.read_report())

    def test_boot_jar_lacks_member(self):
        # ours' DefaultHostnameVerifier calls Helper.value(); this device's ext.jar has Helper without it
        self.make_jar(os.path.join(self.sysdir, "framework", "ext.jar"), [(OBJ, 1, None), (HELP, 1, None)], {})
        rc, out = self.patch()
        why = "link check: references %s->value()I, which does not resolve on the patched boot class path" % HELP
        self.assertRefused(rc, out, "REFUSED core %s: %s (dalvik)" % (DHV, why),
                           "REFUSED core-libart %s: %s (art)" % (DHV, why))

    def test_caller_kept_class(self):
        # a caller of a replaced class's kept member links
        self.make_jar(os.path.join(self.sysdir, "app", "Caller.apk"), [(CALLER, 1, "0x1", DHV + "->value()I")], {})
        rc, out = self.patch()
        self.assertEqual(rc, 0, out)


class ToolErrors(Fixture):
    def test_release_dir(self):
        empty = os.path.join(self.t.name, "empty")
        os.makedirs(empty)
        rc, out = self.patch(release=empty)
        self.assertEqual(rc, 2, out)
        self.assertIn("no kktls-java-4.4.4-armeabi-v7a-<release>.zip", out)
        # sha256 not in SHA256SUMS
        rel = os.path.join(self.t.name, "rel2")
        shutil.copytree(self.rel, rel)
        with open(os.path.join(rel, "SHA256SUMS"), "w") as f:
            f.write("%s  %s\n" % ("0" * 64, DONOR))
        shutil.rmtree(self.out)
        rc, out = self.patch(release=rel)
        self.assertEqual(rc, 2, out)
        self.assertIn("sha256 differs from SHA256SUMS", out)
        # two releases
        shutil.copyfile(os.path.join(rel, DONOR), os.path.join(rel, DONOR.replace(REL, "vU")))
        shutil.rmtree(self.out)
        rc, out = self.patch(release=rel)
        self.assertEqual(rc, 2, out)
        self.assertIn("keep one release", out)

    def test_donor_not_matching_set(self):
        # a donor whose DefaultHostnameVerifier is not the set's ours class (another release than the set)
        other = os.path.join(self.t.name, "other")
        shutil.copytree(os.path.join(self.base, "ours"), other)
        cls, ent = OURS["core"]
        self.make_jar(os.path.join(other, "system", "framework", "core.jar"),
                      [(c[0], c[1], "0x6") + c[3:] if c[0] == DHV else c for c in cls], ent)
        rel = os.path.join(self.t.name, "rel3")
        self.make_release(rel, other)
        rc, out = self.patch(release=rel)
        self.assertEqual(rc, 2, out)
        self.assertIn("donor core.jar does not give the set's ours aggregate", out)

    def test_donor_class_outside_set(self):
        # a donor that also changes a class the set does not list (a newer series than the set): the aggregate sees it
        other = os.path.join(self.t.name, "other")
        shutil.copytree(os.path.join(self.base, "ours"), other)
        cls, ent = OURS["conscrypt"]
        self.make_jar(os.path.join(other, "system", "framework", "conscrypt.jar"),
                      cls + [("Lcom/android/org/conscrypt/Unlisted;", 1, "0x1")], ent)
        rel = os.path.join(self.t.name, "rel5")
        self.make_release(rel, other)
        rc, out = self.patch(release=rel)
        self.assertEqual(rc, 2, out)
        self.assertIn("donor conscrypt.jar does not give the set's ours aggregate", out)

    def test_installer_too_old(self):
        # release zips from before the jar patcher: the device would refuse the zips, so nothing is written
        rel = os.path.join(self.t.name, "rel6")
        self.make_release(rel, os.path.join(self.base, "ours"), installer=None)
        rc, out = self.patch(release=rel)
        self.assertEqual(rc, 2, out)
        self.assertIn("%s: its installer predates this tool (no java-patched in kktls/checks.sh)" % DONOR, out)
        self.assertFalse(os.path.exists(os.path.join(self.out, "work")))
        rel = os.path.join(self.t.name, "rel7")
        self.make_release(rel, os.path.join(self.base, "ours"), installer="# java-patched)\n")
        shutil.rmtree(self.out)
        rc, out = self.patch("--accept-oem", release=rel)
        self.assertEqual(rc, 2, out)
        self.assertIn("%s: its installer predates this tool (no oem_ack in kktls/checks.sh)" % OPENSSL, out)

    def test_zip_conf(self):
        rel = os.path.join(self.t.name, "rel4")
        self.make_release(rel, os.path.join(self.base, "ours"), {"kind": "openssl"})
        rc, out = self.patch(release=rel)
        self.assertEqual(rc, 2, out)
        self.assertIn("zip.conf kind=openssl, expected java", out)

    def test_bootclasspath(self):
        rc, out = self.patch("--bootclasspath", "/system/framework/core.jar:/data/x.jar")
        self.assertEqual(rc, 2, out)   # repeated option: usage
        args = ["--system", self.dev, "--build-prop", os.path.join(self.sysdir, "build.prop"),
                "--release-dir", self.rel, "--set", self.set]
        for bcp, needle in (("/system/framework/core.jar:/data/x.jar", "is not a /system/framework jar"),
                            ("/system/framework/core.jar:/system/framework/nope.jar", "not in")):
            out = os.path.join(self.t.name, "o-" + needle.split()[-1])
            r = subprocess.run([sys.executable, "-I", SCRIPT] + args + ["--bootclasspath", bcp, "--out", out],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            self.assertEqual(r.returncode, 2, r.stdout)
            self.assertIn(needle, r.stdout)


class Logic(unittest.TestCase):
    """Without Java: CLI usage, dex header ids, verdict resolution."""

    def run_cli(self, *a):
        return subprocess.run([sys.executable, "-I", SCRIPT] + list(a), stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, universal_newlines=True)

    def test_usage(self):
        base = ["--release-dir", "r", "--out", "o"]
        for a in ([], base, ["--adb", "s"], ["--adb", "s", "--system", "d"] + base,
                  ["--adb", "s", "--build-prop", "b"] + base, ["--system", "d", "--build-prop", "b"] + base,
                  ["--adb", "s", "--bogus", "x"] + base, ["--adb"]):
            self.assertEqual(self.run_cli(*a).returncode, 2, a)
        self.assertEqual(self.run_cli("--help").returncode, 0)

    def test_out_not_empty(self):
        with tempfile.TemporaryDirectory() as t:
            open(os.path.join(t, "x"), "w").close()
            r = self.run_cli("--adb", "s", "--release-dir", t, "--out", t)
            self.assertEqual(r.returncode, 2)
            self.assertIn("not an empty directory", r.stdout)

    def test_dex_id_counts(self):
        h = bytearray(0x70)
        h[0:8] = b"dex\n035\0"
        for (k, off), n in zip(jp.DEX_IDS, (1, 2, 3, 65536)):
            h[off:off + 4] = n.to_bytes(4, "little")
        self.assertEqual(jp.dex_id_counts(bytes(h)), {"type": 1, "proto": 2, "field": 3, "method": 65536})
        with self.assertRaises(jp.ToolError):
            jp.dex_id_counts(b"PK\3\4" + bytes(0x70))

    def test_oem(self):
        # the markers equal installer/checks.sh KK_OEM_MARKERS (skipped in the release asset, which has no installer/)
        checks = os.path.join(TOOL, "..", "..", "installer", "checks.sh")
        if os.path.isfile(checks):
            with open(checks) as f:
                text = f.read()
            self.assertEqual(jp.OEM_MARKERS, text.split('KK_OEM_MARKERS="', 1)[1].split('"', 1)[0].split())
        with tempfile.TemporaryDirectory() as t:
            bp = os.path.join(t, "build.prop")
            with open(bp, "w") as f:
                f.write("# ro.cm.version=1\nro.build.id=KK\n ro.miui.x=1\nro.cm.version=11\nro.cm.device=x\n")
            self.assertEqual(jp.oem_markers(bp), ["ro.cm.device", "ro.cm.version"])   # awk's $1: unstripped key
        fp = "f" * 64
        self.assertEqual(jp.oem_conf("kind=openssl\nrelease=v9", fp), "kind=openssl\nrelease=v9\noem_ack=%s\n" % fp)
        with self.assertRaises(jp.ToolError):
            jp.oem_conf("kind=openssl\noem_ack=%s\n" % fp, fp)
        self.assertEqual(self.run_cli("--accept-oem", "--accept-oem", "--adb", "s", "--release-dir", "r",
                                      "--out", "o").returncode, 2)

    def test_ls_files(self):
        toolbox = ("\n/system/lib:\ndrwxr-xr-x root root 2014-01-01 00:00 hw\n"
                   "-rw-r--r-- root root 5 2014-01-01 00:00 libssl.so\n"
                   "lrwxrwxrwx root root 2014-01-01 00:00 libx.so -> libssl.so\n\n/system/lib/hw:\n"
                   "-rw-r--r-- root root 7 2014-01-01 00:00 keystore.default.so\n")
        busybox = ("/system/bin:\n-rwxr-xr-x    1 0        2000        5 Jan  1  2014 netd\n"
                   "lrwxrwxrwx    1 0        2000        7 Jan  1  2014 ls -> toolbox\n")
        self.assertEqual(jp.ls_files(toolbox, "/system/lib"), (["/system/lib/hw/keystore.default.so",
                                                                "/system/lib/libssl.so"], []))
        self.assertEqual(jp.ls_files(busybox, "/system/bin"), (["/system/bin/netd"], []))
        self.assertEqual(jp.ls_files(busybox, "/system/lib"), ([], []))
        # the shell's stderr in the stream: toolbox names no path (the header before it does), busybox does; a missing
        # directory is no error line
        toolbox_err = toolbox + "\n/system/lib/drm:\nopendir failed, Permission denied\n"
        self.assertEqual(jp.ls_files(toolbox_err, "/system/lib")[1],
                         [("/system/lib/drm", "opendir failed, Permission denied")])
        busybox_err = busybox + "ls: /system/bin/secret: Permission denied\n/system/bin/x: Permission denied\n"
        self.assertEqual(jp.ls_files(busybox_err, "/system/bin"), (["/system/bin/netd"], [
            ("/system/bin/secret", "Permission denied"), ("/system/bin/x", "Permission denied")]))
        self.assertEqual(jp.ls_files("ls: /system/vendor: No such file or directory\n", "/system/vendor"), ([], []))

    def test_lines_map(self):
        self.assertEqual(dict(jp.LINES), {"4.4.1": "4.4.2", "4.4.2": "4.4.2", "4.4.3": "4.4.4", "4.4.4": "4.4.4"})

    def test_unexpected_error(self):
        # an exception nobody foresaw is a tool error (exit 2), never the "refused" exit 1
        with tempfile.TemporaryDirectory() as t, contextlib.redirect_stderr(io.StringIO()) as err:
            orig = jp.from_system
            jp.from_system = lambda *a: b"\xff".decode("utf-8")
            try:
                rc = jp.main(["--system", t, "--bootclasspath", "/system/framework/core.jar", "--build-prop",
                              os.path.join(t, "b"), "--release-dir", t, "--out", os.path.join(t, "out")])
            finally:
                jp.from_system = orig
        self.assertEqual(rc, 2)
        self.assertIn("kktls-jarpatch: unexpected error: UnicodeDecodeError", err.getvalue())

    def test_patched_notice(self):
        n = jp.patched_notice("donor text\n", "kktls-java-4.4.2-x86-v9.zip", ["core", "okhttp"], "android-4.4.2_r2")
        self.assertIn("from kktls-java-4.4.2-x86-v9.zip", n)
        self.assertIn("system/framework/{core,okhttp}.jar are that system's own jars", n)
        self.assertIn("AOSP android-4.4.2_r2 libcore", n)
        self.assertTrue(n.endswith("\ndonor text\n"))

    def test_verdicts(self):
        A, B, C = "a" * 64, "b" * 64, "c" * 64
        st = mkset.SetFile()
        st.classes = [("core", DHV, A, B), ("core", KK, None, C), ("core", GONE, A, None)]
        st.checks = [("core", INT, A)]
        st.entries = [("core", PROPS, A, B)]

        class S(object):
            java_marker = None

        def run(dev, ent, jars=("core",)):
            v, already = jp.verdicts(st, list(jars), {"core": {c: ("p", d) for c, d in dev.items()}},
                                     {"core": ent}, S())
            return {(r[1], r[3]): r[0] for r in v}, already
        v, al = run({DHV: A, GONE: A, INT: A}, {PROPS: A})
        self.assertEqual(set(v.values()), {"match"})
        self.assertFalse(al)
        v, al = run({DHV: B, GONE: A, INT: A}, {PROPS: A})
        self.assertEqual(v[("class", DHV)], "vendor-modified")
        self.assertFalse(al)
        v, al = run({DHV: B, KK: C, INT: A}, {PROPS: B})
        self.assertTrue(al)
        self.assertEqual((v[("class", DHV)], v[("class", KK)], v[("entry", PROPS)], v[("class", GONE)]),
                         ("already-kktls", "already-kktls", "already-kktls", "missing"))
        # an older kktls class (other digest) and an extra kktls class are kktls too
        other = "Lio/github/hsw/kktls/Old;"
        v, al = run({DHV: A, KK: A, other: A, GONE: A, INT: A}, {PROPS: A})
        self.assertTrue(al)
        self.assertEqual((v[("class", KK)], v[("class", other)]), ("already-kktls", "already-kktls"))
        v, al = run({}, {}, jars=())
        self.assertEqual(v, {})


class Assemble(unittest.TestCase):
    def test_reproducible(self):
        """The same smali tree assembles to the same bytes every time (smali -j N does not: thread order)."""
        smali = smali_or_skip(self)[1]
        with tempfile.TemporaryDirectory() as d:
            tree = os.path.join(d, "t")
            os.makedirs(tree)
            for i in range(600):
                meth = "".join(".method public static m%d()Ljava/lang/String;\n    .registers 2\n"
                               "    const-string v0, \"s%d_%d\"\n    const v1, 0x%x\n    return-object v0\n"
                               ".end method\n" % (k, i, k, i * 7 + k) for k in range(4))
                with open(os.path.join(tree, "C%03d.smali" % i), "w") as f:
                    f.write(".class public Lp/C%03d;\n.super Ljava/lang/Object;\n"
                            ".field public static f:I = 0x%x\n%s" % (i, i, meth))
            got = set()
            for n in range(3):
                out = os.path.join(d, "%d.dex" % n)
                jp.assemble(tree, out, smali)
                with open(out, "rb") as f:
                    got.add(hashlib.sha256(f.read()).hexdigest())
            self.assertEqual(len(got), 1, "smali gave %d different dex files for one tree" % len(got))


@unittest.skipUnless(os.environ.get("KKTLS_JARPATCH_ORACLE_SYSTEM") and os.environ.get("KKTLS_JARPATCH_ORACLE_RELEASE"),
                     "local oracle: set KKTLS_JARPATCH_ORACLE_SYSTEM and KKTLS_JARPATCH_ORACLE_RELEASE")
class Oracle(unittest.TestCase):
    """Patching stock AOSP 4.4 jars gives, per class, the release java zip's classes (the classes outside the set
    keep the device's own bytecode, so a device built by another toolchain may differ there: counted, not failed,
    unless KKTLS_JARPATCH_ORACLE_EXACT=1)."""

    def test_oracle(self):
        jars = smali_or_skip(self)
        sysdir, rel = os.environ["KKTLS_JARPATCH_ORACLE_SYSTEM"], os.environ["KKTLS_JARPATCH_ORACLE_RELEASE"]
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "out")
            bcp = os.environ.get("KKTLS_JARPATCH_ORACLE_BOOTCLASSPATH") or \
                ":".join("/system/framework/%s.jar" % j for j in ("core", "conscrypt", "okhttp"))
            r = subprocess.run([sys.executable, "-I", SCRIPT, "--system", sysdir, "--bootclasspath", bcp,
                                "--build-prop", os.path.join(sysdir, "build.prop"), "--release-dir", rel,
                                "--out", out], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True)
            self.assertEqual(r.returncode, 0, r.stdout)
            with open(os.path.join(out, "stage", "manifest.json")) as f:
                m = json.load(f)
            for rt, v in m["linkcheck"].items():
                print("oracle link check %s: %s" % (rt, " ".join("%s=%d" % kv for kv in sorted(v.items()))),
                      file=sys.stderr)
            st = mkset.read_set(m["set"])
            with zipfile.ZipFile(m["donor"]) as z:
                for j in m["jars"]:
                    donor = os.path.join(t, j + ".jar")
                    with open(donor, "wb") as f:
                        f.write(z.read("system/framework/%s.jar" % j))
                    got = jp.disassemble(os.path.join(out, "stage", j, "classes.dex"), os.path.join(t, "g", j),
                                         jars[0])
                    want = jp.disassemble(donor, os.path.join(t, "w", j), jars[0])
                    for jj, c, _, ours in st.classes:
                        if jj == j:
                            self.assertEqual(got[c][1] if c in got else None, ours, (j, c))
                    diff = sorted(c for c in set(got) | set(want)
                                  if (got.get(c) or (0, None))[1] != (want.get(c) or (0, None))[1])
                    print("oracle %s.jar: %d classes, %d differ from the release jar %s" %
                          (j, len(got), len(diff), " ".join(diff[:20])), file=sys.stderr)
                    if os.environ.get("KKTLS_JARPATCH_ORACLE_EXACT") == "1":
                        self.assertEqual(diff, [], j)


if __name__ == "__main__":
    unittest.main()
