# SPDX-License-Identifier: Apache-2.0
"""Unit tests of mkset.py: the set logic on digest tables, the set file reader, the shipped sets, and (when Java and
the smali jars of fetch-smali.sh are available) mkset end to end on fixture jars assembled from smali sources.

    python3 -I -m unittest discover tools/jarpatch/tests
"""
import hashlib
import os
import shutil
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

A, B, C = "a" * 64, "b" * 64, "c" * 64
NAT = "Lcom/android/org/conscrypt/NativeCrypto;"
BIO = "Lcom/android/org/conscrypt/OpenSSLBIOInputStream;"
DHV = "Ljavax/net/ssl/DefaultHostnameVerifier;"
ADDED = "Lio/github/hsw/kktls/Added;"
GONE = "Lcom/example/Gone;"
INT = "Ljava/lang/Integer;"
CAL = "Ljava/util/Calendar;"
PROPS = "java/security/security.properties"
JNI = [INT, CAL, NAT, BIO]


def tables():
    core_s = ({INT: A, CAL: B, DHV: A, GONE: C}, {PROPS: A})
    core_o = ({INT: A, CAL: B, DHV: B, ADDED: C}, {PROPS: B})
    stock = {"core": core_s, "core-libart": core_s, "conscrypt": ({NAT: A, BIO: B}, {}), "okhttp": ({GONE: A}, {})}
    ours = {"core": core_o, "core-libart": core_o, "conscrypt": ({NAT: C, BIO: B}, {}), "okhttp": ({GONE: A}, {})}
    return stock, ours


def body(text):
    return [l for l in text.split("\n") if l.startswith(("class ", "check ", "entry "))]


EXPECTED = [
    "class core %s - %s" % (ADDED, C), "class core %s %s -" % (GONE, C), "class core %s %s %s" % (DHV, A, B),
    "class core-libart %s - %s" % (ADDED, C), "class core-libart %s %s -" % (GONE, C),
    "class core-libart %s %s %s" % (DHV, A, B),
    "class conscrypt %s %s %s" % (NAT, A, C),
    "check core %s %s" % (INT, A), "check core %s %s" % (CAL, B),
    "check core-libart %s %s" % (INT, A), "check core-libart %s %s" % (CAL, B),
    "check conscrypt %s %s" % (BIO, B),
    "entry core %s %s %s" % (PROPS, A, B), "entry core-libart %s %s %s" % (PROPS, A, B),
]


class MakeSet(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_lines(self):
        stock, ours = tables()
        text = mkset.make_set(stock, ours, JNI, "android-4.4.2_r2", ["a note"])
        # classes, then checks, then entries; within each by jar (JARS order), then by name
        order = lambda l: (("class", "check", "entry").index(l.split()[0]), mkset.JARS.index(l.split()[1]), l.split()[2])
        self.assertEqual(body(text), sorted(EXPECTED, key=order))
        self.assertIn("# a note\n", text)
        self.assertEqual([l for l in text.split("\n") if l.startswith("ours ")],
                         ["ours %s %s" % (j, mkset.aggregate(*ours[j])) for j in mkset.JARS])
        for k, v in (("tag", "android-4.4.2_r2"), ("model", normalize.MODEL),
                     ("normalizer", str(normalize.NORMALIZER_VERSION)), ("smali", normalize.SMALI_VERSION)):
            self.assertIn("\n%s %s\n" % (k, v), text)

    def test_jni_name_in_no_jar(self):
        stock, ours = tables()
        with self.assertRaisesRegex(mkset.SetError, "Ljava/lang/Typo;"):
            mkset.make_set(stock, ours, JNI + ["Ljava/lang/Typo;"], "android-4.4.2_r2")

    def test_jni_name_added_by_series(self):
        stock, ours = tables()
        text = mkset.make_set(stock, ours, JNI + [ADDED], "android-4.4.2_r2")
        self.assertFalse([l for l in body(text) if l.startswith("check") and ADDED in l])

    def test_round_trip(self):
        stock, ours = tables()
        p = os.path.join(self.tmp.name, "set.txt")
        with open(p, "w") as f:
            f.write(mkset.make_set(stock, ours, JNI, "android-4.4.4_r2"))
        s = mkset.read_set(p)
        self.assertEqual(s.header, {"tag": "android-4.4.4_r2", "model": "H", "normalizer": str(normalize.NORMALIZER_VERSION), "smali": "2.5.2"})
        self.assertIn(("core", ADDED, None, C), s.classes)
        self.assertIn(("core", GONE, C, None), s.classes)
        self.assertIn(("conscrypt", BIO, B), s.checks)
        self.assertIn(("core", PROPS, A, B), s.entries)
        self.assertEqual((len(s.classes), len(s.checks), len(s.entries)), (7, 5, 2))
        self.assertEqual(s.ours, {j: mkset.aggregate(*ours[j]) for j in mkset.JARS})

    def test_aggregate(self):
        # the whole jar: a class or entry no line names changes it too; the order of the tables does not
        cls, ent = {INT: A, CAL: B}, {PROPS: A}
        agg = mkset.aggregate(cls, ent)
        self.assertEqual(agg, mkset.aggregate(dict(reversed(list(cls.items()))), ent))
        self.assertNotEqual(agg, mkset.aggregate(dict(cls, **{"Lcom/example/Unlisted;": C}), ent))
        self.assertNotEqual(agg, mkset.aggregate(dict(cls, **{CAL: C}), ent))
        self.assertNotEqual(agg, mkset.aggregate(cls, dict(ent, **{"x.txt": C})))
        self.assertNotEqual(agg, mkset.aggregate(cls, {}))

    def test_reader_refuses(self):
        ours = ["ours %s %s" % (j, C) for j in mkset.JARS]
        good = ["tag android-4.4.2_r2", "model H", "normalizer %d" % normalize.NORMALIZER_VERSION, "smali 2.5.2", "class core %s %s %s" % (DHV, A, B)]
        good += ours
        bad = {
            "unknown jar": good + ["class framework %s %s %s" % (INT, A, B)],
            "both absent": good + ["class core %s - -" % INT],
            "short digest": good + ["class core %s %s abc" % (INT, A)],
            "check without stock": good + ["check core %s -" % INT],
            "field count": good + ["check core %s %s %s" % (INT, A, B)],
            "bad descriptor": good + ["class core java/lang/Integer %s %s" % (A, B)],
            "duplicate": good + ["check core %s %s" % (DHV, A)],
            "unknown kind": good + ["remove core %s %s %s" % (INT, A, B)],
            "repeated header": good + ["model S"],
            "missing header": good[1:],
            "foreign tag": ["tag android-5.0.0_r1"] + good[1:],
            "other normalizer": [l.replace("normalizer %d" % normalize.NORMALIZER_VERSION, "normalizer 9") for l in good],
            "other model": [l.replace("model H", "model S") for l in good],
            "no ours line": good[:-1],
            "repeated ours": good + [ours[0]],
            "short ours": good[:-1] + ["ours okhttp abc"],
            "ours of an unknown jar": good + ["ours framework %s" % C],
        }
        p = os.path.join(self.tmp.name, "s.txt")
        with open(p, "w") as f:
            f.write("\n".join(good) + "\n")
        mkset.read_set(p)
        mkset.read_set(p, "android-4.4.2_r2")
        with self.assertRaisesRegex(mkset.SetError, "tag android-4.4.2_r2, expected android-4.4.4_r2"):
            mkset.read_set(p, "android-4.4.4_r2")
        for why, lines in bad.items():
            with open(p, "w") as f:
                f.write("\n".join(lines) + "\n")
            with self.assertRaises(mkset.SetError, msg=why):
                mkset.read_set(p)

    def test_entry_digests(self):
        jar = os.path.join(self.tmp.name, "x.jar")
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("META-INF/MANIFEST.MF", "Created-By: x\n")
            z.writestr("classes.dex", b"dex\n035\0")
            z.writestr("java/", b"")
            z.writestr(PROPS, b"a=1\n")
        self.assertEqual(mkset.entry_digests(jar), {PROPS: hashlib.sha256(b"a=1\n").hexdigest()})

    def test_missing_jar(self):
        os.makedirs(os.path.join(self.tmp.name, "empty"))
        jni = os.path.join(self.tmp.name, "jni.txt")
        with open(jni, "w") as f:
            f.write(INT + "\n")
        r = subprocess.run([sys.executable, "-I", os.path.join(TOOL, "mkset.py"), os.path.join(self.tmp.name, "empty"),
                            os.path.join(self.tmp.name, "empty"), "--tag", "android-4.4.2_r2", "--jni", jni],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("no core.jar", r.stdout)

    def test_cli_usage(self):
        def run(*a):
            return subprocess.run([sys.executable, "-I", os.path.join(TOOL, "mkset.py")] + list(a),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode
        self.assertEqual(run(), 2)
        self.assertEqual(run("a", "b", "--jni", "j"), 2)
        self.assertEqual(run("a", "b", "--jni", "j", "--tag", "android-5.0_r1"), 2)
        self.assertEqual(run("a", "b", "--jni", "j", "--tag", "android-4.4.2_r2", "--bogus"), 2)


class ShippedSets(unittest.TestCase):
    """sets/4.4.2.txt and sets/4.4.4.txt: format, header against this normalizer, the measured shape."""

    def test_sets(self):
        jni = mkset.read_jni(os.path.join(TOOL, "sets", "jni-classes.txt"))
        self.assertEqual(len(jni), 25)
        bodies = []
        for line, tag in (("4.4.2", "android-4.4.2_r2"), ("4.4.4", "android-4.4.4_r2")):
            p = os.path.join(TOOL, "sets", line + ".txt")
            s = mkset.read_set(p)
            self.assertEqual(s.header, {"tag": tag, "model": normalize.MODEL,
                                        "normalizer": str(normalize.NORMALIZER_VERSION),
                                        "smali": normalize.SMALI_VERSION})
            self.assertEqual((len(s.classes), len(s.checks), len(s.entries), len(s.ours)), (19, 46, 2, 4))
            self.assertEqual({e[1] for e in s.entries}, {"java/security/security.properties"})
            named = {c[1] for c in s.classes} | {c[1] for c in s.checks}
            self.assertEqual(set(jni) - named, set())
            with open(p) as f:
                bodies.append(body(f.read()))
        # measured: the listed lines are equal (the ours aggregates are not: the 4.4.2 and 4.4.4 jars differ outside
        # the set, in AOSP code the series does not touch)
        self.assertEqual(bodies[0], bodies[1])


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


def smali_or_skip(test):
    if not shutil.which(normalize.JAVA):
        test.skipTest("no %s on PATH" % normalize.JAVA)
    try:
        return normalize.smali_jars()
    except normalize.NormalizeError as e:
        test.skipTest("smali/baksmali not available: %s" % e)


class EndToEnd(unittest.TestCase):
    """mkset.py on fixture jars: changed, added and removed class, changed security.properties, check classes, a
    debug-only change (no line), a differing manifest (no line)."""

    def setUp(self):
        self.jars = smali_or_skip(self)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def jar(self, side, name, classes, entries):
        src = os.path.join(self.root, "src", side, name)
        for desc, line, const in classes:
            p = os.path.join(src, desc[1:-1] + ".smali")
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(FIXTURE % {"desc": desc, "line": line, "const": const})
        dex = os.path.join(self.root, "dex-%s-%s" % (side, name))
        r = subprocess.run([normalize.JAVA, "-jar", self.jars[1], "a", "-a", "19", "-o", dex, src],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        out = os.path.join(self.root, side, "system", "framework", name + ".jar")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nCreated-By: %s\n" % side)
            z.write(dex, "classes.dex")
            for n, data in entries.items():
                z.writestr(n, data)

    def test_mkset(self):
        for name in ("core", "core-libart"):
            self.jar("stock", name, [(INT, 3, "0x1"), (CAL, 3, "0x1"), (DHV, 3, "0x1"), (GONE, 3, "0x1")],
                     {PROPS: "a=1\n"})
            self.jar("ours", name, [(INT, 30, "0x1"), (CAL, 3, "0x1"), (DHV, 3, "0x2"), (ADDED, 3, "0x1")],
                     {PROPS: "a=1\nb=2\n"})
        self.jar("stock", "conscrypt", [(NAT, 3, "0x1"), (BIO, 3, "0x1")], {})
        self.jar("ours", "conscrypt", [(NAT, 3, "0x3"), (BIO, 3, "0x1")], {})
        for side in ("stock", "ours"):
            self.jar(side, "okhttp", [(GONE, 3, "0x1")], {})
        jni = os.path.join(self.root, "jni.txt")
        with open(jni, "w") as f:
            f.write("# fixture\n" + "\n".join(JNI) + "\n")
        out = os.path.join(self.root, "set.txt")
        r = subprocess.run([sys.executable, "-I", os.path.join(TOOL, "mkset.py"), os.path.join(self.root, "stock"),
                            os.path.join(self.root, "ours"), "--tag", "android-4.4.2_r2", "--jni", jni, "--out", out],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        s = mkset.read_set(out)
        shape = sorted((j, c, st is not None, o is not None) for j, c, st, o in s.classes)
        self.assertEqual(shape, sorted([
            ("core", ADDED, False, True), ("core", GONE, True, False), ("core", DHV, True, True),
            ("core-libart", ADDED, False, True), ("core-libart", GONE, True, False), ("core-libart", DHV, True, True),
            ("conscrypt", NAT, True, True)]))
        self.assertEqual(sorted((j, c) for j, c, _ in s.checks), sorted([
            ("core", INT), ("core", CAL), ("core-libart", INT), ("core-libart", CAL), ("conscrypt", BIO)]))
        self.assertEqual(sorted(e[:2] for e in s.entries), [("core", PROPS), ("core-libart", PROPS)])
        self.assertIn(("core", PROPS, hashlib.sha256(b"a=1\n").hexdigest(), hashlib.sha256(b"a=1\nb=2\n").hexdigest()),
                      s.entries)
        # the same class source gives the same digest in another jar (core/core-libart, okhttp's unchanged GONE)
        dig = {(j, c): (st, o) for j, c, st, o in s.classes}
        self.assertEqual(dig[("core", DHV)], dig[("core-libart", DHV)])
        self.assertNotEqual(*dig[("core", DHV)])


if __name__ == "__main__":
    unittest.main()
