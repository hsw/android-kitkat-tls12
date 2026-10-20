# SPDX-License-Identifier: Apache-2.0
"""Unit tests of kktls-jarpatch.py on fixture systems assembled from smali sources: the staged classes equal the
donor's (the oracle in fixture form), the round-trip invariant, and each refusal with its reason (vendor-modified
class, vendor-modified check class, missing class, unexpected class, stripped jar, already patched, a vendor backport
equal to the kktls class). Skipped without Java and the smali jars of fetch-smali.sh, except the pure-logic tests.

    python3 -I -m unittest discover tools/jarpatch/tests

Local only: with KKTLS_JARPATCH_ORACLE_SYSTEM (a /system copy holding framework/ and build.prop of a stock AOSP 4.4
build) and KKTLS_JARPATCH_ORACLE_RELEASE (the release dir with SHA256SUMS and the java zips) set, Oracle patches the
stock jars and compares every class with the release java zip of that line.
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
PROPS = "java/security/security.properties"
REPLACED = {DHV, KK, NAT, ADDR, OKP}
JNI = [INT, NAT, BIO]
LINE, ABI, REL = "4.4.4", "armeabi-v7a", "vT"
DONOR = "kktls-java-%s-%s-%s.zip" % (LINE, ABI, REL)
BCP = "/system/framework/core.jar:/system/framework/conscrypt.jar:/system/framework/okhttp.jar"
FINGERPRINT = "fixture/fixture/fixture:4.4.4/FIX/1:user/test-keys"

FIXTURE = """\
.class public %(desc)s
.super Ljava/lang/Object;
.source "Fixture.java"


# direct methods
.method public static value()I
    .registers 1

    .prologue
    .line %(line)d
    const/4 v0, %(const)s

    return v0
.end method
"""

# {jar: ([(desc, line, const)], {entry: bytes})}
STOCK = {
    "core": ([(INT, 3, "0x1"), (DHV, 3, "0x1"), (GONE, 3, "0x1")], {PROPS: b"a=1\n"}),
    "conscrypt": ([(NAT, 3, "0x1"), (BIO, 3, "0x1")], {}),
    "okhttp": ([(OKP, 3, "0x1")], {}),
}
STOCK["core-libart"] = STOCK["core"]
OURS = {
    "core": ([(INT, 3, "0x1"), (DHV, 3, "0x2"), (KK, 3, "0x1")], {PROPS: b"a=1\nkktls=1\n"}),
    "conscrypt": ([(NAT, 3, "0x3"), (BIO, 3, "0x1"), (ADDR, 3, "0x1")], {}),
    "okhttp": ([(OKP, 3, "0x2")], {}),
}
OURS["core-libart"] = OURS["core"]


def device_jars():
    """The stock jars with other line numbers (debug info only) and a vendor class in each."""
    return {j: ([(d, l + 10, c) for d, l, c in cls] + [(VEN, 5, "0x7")], dict(ent)) for j, (cls, ent) in STOCK.items()}


def smali_or_skip(test):
    if not shutil.which("java"):
        test.skipTest("no java on PATH")
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
    if not os.path.isfile(dev(a[1])):
        sys.stderr.write("remote object '%s' does not exist\n" % a[1])
        sys.exit(1)
    shutil.copyfile(dev(a[1]), a[2])
elif a[:1] == ["shell"]:
    c = a[1]
    if c == "echo $BOOTCLASSPATH":
        sys.stdout.write(os.environ["FAKE_ADB_BCP"] + "\r\n")
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
        if not shutil.which("java"):
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
            for desc, line, const in classes:
                p = os.path.join(src, desc[1:-1] + ".smali")
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f:
                    f.write(FIXTURE % {"desc": desc, "line": line, "const": const})
            d = src + ".dex"
            r = subprocess.run(["java", "-jar", cls.jars[1], "a", "-a", "19", "-o", d, src],
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
    def make_release(cls, rel, ours, conf=None):
        os.makedirs(rel, exist_ok=True)
        z = os.path.join(rel, DONOR)
        c = {"kind": "java", "release": REL, "abi": ABI, "android": LINE, "tag": "android-4.4.4_r2"}
        c.update(conf or {})
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("kktls/zip.conf", "".join("%s=%s\n" % kv for kv in c.items()))
            for j in mkset.JARS:
                zf.write(os.path.join(ours, "system", "framework", j + ".jar"), "system/framework/%s.jar" % j)
            zf.writestr("system/lib/libjavacrypto.so", b"\x7fELF fixture")
        with open(z, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        with open(os.path.join(rel, "SHA256SUMS"), "w") as f:
            f.write("%s  %s\n" % (sha, DONOR))

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
            self.assertEqual(v["sha256"], hashlib.sha256(open(os.path.join(self.sysdir, "framework", j + ".jar"),
                                                               "rb").read()).hexdigest())
            if j in ("core", "core-libart"):
                with open(os.path.join(stage, j, PROPS), "rb") as f:
                    self.assertEqual(f.read(), b"a=1\nkktls=1\n")
                self.assertEqual((v["replaced"], v["removed"], v["entries"]), (2, 1, {PROPS: "%s/%s" % (j, PROPS)}))
        self.assertIn("result staged", self.read_report())
        return m

    def test_system(self):
        rc, out = self.patch()
        m = self.check_staged(rc, out)
        self.assertEqual((m["source"], m["bootclasspath"], m["dalvik_only"]), ("system", BCP.split(":"), False))
        self.assertFalse(os.path.exists(os.path.join(self.out, "work")))
        rep = self.read_report()
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
        self.assertTrue(m["dalvik_only"])

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
        self.device_jar("core", [(INT, 3, "0x1"), (DHV, 3, "0x2"), (GONE, 3, "0x1")])
        rc, out = self.patch()
        self.assertRefused(rc, out, "REFUSED core %s: equals the kktls version, but the system carries no kktls" % DHV)
        self.assertNotIn("restore", out)

    def test_gates(self):
        for over, needle in (({"ro.build.version.release": "4.3"}, "Android 4.3: only 4.4"),
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
                      [(c, l, "0x6" if c == DHV else k) for c, l, k in cls], ent)
        rel = os.path.join(self.t.name, "rel3")
        self.make_release(rel, other)
        rc, out = self.patch(release=rel)
        self.assertEqual(rc, 2, out)
        self.assertIn("donor core.jar class %s does not match the set's ours digest" % DHV, out)

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

    def test_lines_map(self):
        self.assertEqual(dict(jp.LINES),
                         {"4.4": "4.4.2", "4.4.1": "4.4.2", "4.4.2": "4.4.2", "4.4.3": "4.4.4", "4.4.4": "4.4.4"})

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
            bcp = ":".join("/system/framework/%s.jar" % j for j in ("core", "conscrypt", "okhttp"))
            r = subprocess.run([sys.executable, "-I", SCRIPT, "--system", sysdir, "--bootclasspath", bcp,
                                "--build-prop", os.path.join(sysdir, "build.prop"), "--release-dir", rel,
                                "--out", out], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True)
            self.assertEqual(r.returncode, 0, r.stdout)
            with open(os.path.join(out, "stage", "manifest.json")) as f:
                m = json.load(f)
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
