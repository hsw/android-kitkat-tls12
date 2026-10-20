# SPDX-License-Identifier: Apache-2.0
"""Unit tests of checkset.py (the release build's drift check of the set files): the comparison on digest tables, the
set lookup by tag, the header checks, and (when Java and the smali jars of fetch-smali.sh are available) the command
on mkset's fixture jars: the jars the set was made from pass, the stock jars and a changed class fail.

    python3 -I -m unittest discover tools/jarpatch/tests
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
sys.path.insert(0, TOOL)
sys.path.insert(0, HERE)
import checkset  # noqa: E402
import mkset  # noqa: E402
import test_mkset as tm  # noqa: E402  (module import: its TestCase classes are not collected twice)

SCRIPT = os.path.join(TOOL, "checkset.py")


def run(*args):
    r = subprocess.run([sys.executable, "-I", SCRIPT] + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True)
    return r.returncode, r.stdout


class Logic(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        stock, ours = tm.tables()
        self.ours = ours
        self.text = mkset.make_set(stock, ours, tm.JNI, "android-4.4.2_r2")
        self.path = self.write("a.txt", self.text)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_ours_tables_match(self):
        self.assertEqual(checkset.compare(checkset.load(self.path, "android-4.4.2_r2"), self.ours), [])

    def test_drift(self):
        st = checkset.load(self.path)
        ours = {j: (dict(c), dict(e)) for j, (c, e) in self.ours.items()}
        ours["conscrypt"][0][tm.NAT] = tm.A                          # a replaced class changed
        ours["core"][0][tm.GONE] = tm.C                              # a class the series removes is back
        del ours["core-libart"][0][tm.ADDED]                         # an added class is gone
        ours["core"][0][tm.INT] = tm.C                               # a check class changed by the series
        ours["core-libart"][1][tm.PROPS] = tm.C                      # the entry changed
        got = sorted(checkset.compare(st, ours))
        whole = [(j, "ours (whole jar)", mkset.aggregate(*ours[j]), st.ours[j]) for j in ("conscrypt", "core",
                                                                                          "core-libart")]
        self.assertEqual(got, sorted([
            ("conscrypt", "class " + tm.NAT, tm.A, tm.C), ("core", "class " + tm.GONE, tm.C, "-"),
            ("core-libart", "class " + tm.ADDED, "-", tm.C), ("core", "check " + tm.INT, tm.C, tm.A),
            ("core-libart", "entry " + tm.PROPS, tm.C, tm.B)] + whole))

    def test_drift_outside_the_set(self):
        # the series starts to change a class no line names (or adds one): only the whole-jar aggregate sees it
        st = checkset.load(self.path)
        ours = {j: (dict(c), dict(e)) for j, (c, e) in self.ours.items()}
        ours["okhttp"][0]["Lcom/android/okhttp/Unlisted;"] = tm.B
        ours["conscrypt"][1]["x.properties"] = tm.A
        self.assertEqual(sorted(checkset.compare(st, ours)), sorted(
            (j, "ours (whole jar)", mkset.aggregate(*ours[j]), st.ours[j]) for j in ("okhttp", "conscrypt")))

    def test_set_for_tag(self):
        self.write("b.txt", self.text.replace("tag android-4.4.2_r2", "tag android-4.4.4_r2"))
        self.assertEqual(checkset.set_for_tag("android-4.4.4_r2", self.tmp.name), os.path.join(self.tmp.name, "b.txt"))
        with self.assertRaisesRegex(checkset.CheckError, r"0 set files .* \(none\)"):
            checkset.set_for_tag("android-4.4.3_r1", self.tmp.name)
        self.write("c.txt", self.text)
        with self.assertRaisesRegex(checkset.CheckError, "2 set files .*a.txt, c.txt"):
            checkset.set_for_tag("android-4.4.2_r2", self.tmp.name)

    def test_shipped_sets(self):
        for tag, name in (("android-4.4.2_r2", "4.4.2.txt"), ("android-4.4.4_r2", "4.4.4.txt")):
            p = checkset.set_for_tag(tag)
            self.assertEqual(os.path.basename(p), name)
            checkset.load(p, tag)

    def test_header_mismatch(self):
        with self.assertRaisesRegex(checkset.CheckError, "tag android-4.4.2_r2, expected android-4.4.4_r2"):
            checkset.load(self.path, "android-4.4.4_r2")
        p = self.write("n.txt", self.text.replace("normalizer 1", "normalizer 9"))
        with self.assertRaisesRegex(checkset.CheckError, "normalizer 9, expected 1"):
            checkset.load(p)

    def test_usage(self):
        self.assertEqual(run()[0], 2)
        self.assertEqual(run("--tag", "android-4.4.2_r2")[0], 2)
        self.assertEqual(run("--tag", "x", "--tag", "y", "d")[0], 2)
        rc, out = run("--tag", "android-4.4.2_r2", "--set", self.path, os.path.join(self.tmp.name, "nothing"))
        self.assertEqual(rc, 2, out)
        self.assertIn("no core.jar", out)


class Command(tm.EndToEnd):
    """checkset.py on the jars of mkset's end-to-end fixture."""
    test_mkset = None     # inherited from EndToEnd: runs in test_mkset.py

    def make(self):
        for name in ("core", "core-libart"):
            self.jar("stock", name, [(tm.INT, 3, "0x1"), (tm.CAL, 3, "0x1"), (tm.DHV, 3, "0x1"), (tm.GONE, 3, "0x1")],
                     {tm.PROPS: "a=1\n"})
            self.jar("ours", name, [(tm.INT, 30, "0x1"), (tm.CAL, 3, "0x1"), (tm.DHV, 3, "0x2"), (tm.ADDED, 3, "0x1")],
                     {tm.PROPS: "a=1\nb=2\n"})
        self.jar("stock", "conscrypt", [(tm.NAT, 3, "0x1"), (tm.BIO, 3, "0x1")], {})
        self.jar("ours", "conscrypt", [(tm.NAT, 3, "0x3"), (tm.BIO, 3, "0x1")], {})
        for side in ("stock", "ours"):
            self.jar(side, "okhttp", [(tm.GONE, 3, "0x1")], {})
        bak = self.jars[0]
        text = mkset.make_set(mkset.collect(os.path.join(self.root, "stock"), bak),
                              mkset.collect(os.path.join(self.root, "ours"), bak), tm.JNI, "android-4.4.2_r2")
        self.set = os.path.join(self.root, "set.txt")
        with open(self.set, "w") as f:
            f.write(text)

    def test_checkset(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            self.make()
        ours = os.path.join(self.root, "ours")
        rc, out = run("--tag", "android-4.4.2_r2", "--set", self.set, ours, ours)
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.count(": 18/18 lines of set.txt match"), 2, out)
        rc, out = run("--tag", "android-4.4.2_r2", "--set", self.set, ours, os.path.join(self.root, "stock"))
        self.assertEqual(rc, 1, out)
        self.assertIn("checkset: ok %s:" % ours, out)
        self.assertIn("DRIFT %s conscrypt.jar class %s: built " % (os.path.join(self.root, "stock"), tm.NAT), out)
        self.assertIn("core.jar entry %s" % tm.PROPS, out)
        # the series changes a class the set lists as a check: drift
        shutil.rmtree(os.path.join(self.root, "src", "ours", "conscrypt"))
        self.jar("ours", "conscrypt", [(tm.NAT, 3, "0x3"), (tm.BIO, 3, "0x4")], {})
        rc, out = run("--tag", "android-4.4.2_r2", "--set", self.set, ours)
        self.assertEqual(rc, 1, out)
        self.assertIn("conscrypt.jar check %s" % tm.BIO, out)
        self.assertIn("conscrypt.jar ours (whole jar)", out)
        self.assertIn("16/18 lines", out)
        # a class outside the set: only the aggregate line fails
        shutil.rmtree(os.path.join(self.root, "src", "ours", "conscrypt"))
        self.jar("ours", "conscrypt", [(tm.NAT, 3, "0x3"), (tm.BIO, 3, "0x1"), ("Lcom/example/New;", 3, "0x1")], {})
        rc, out = run("--tag", "android-4.4.2_r2", "--set", self.set, ours)
        self.assertEqual(rc, 1, out)
        self.assertEqual(out.count("DRIFT"), 1, out)
        self.assertIn("conscrypt.jar ours (whole jar)", out)


if __name__ == "__main__":
    unittest.main()
