# SPDX-License-Identifier: Apache-2.0
"""Unit tests of normalize.py (model H): what must not and what must change a class digest.

    python3 -I -m unittest discover tools/jarpatch/tests
"""
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import normalize  # noqa: E402

# baksmali 2.5.2 style text of a class built with debug info
BASE = """\
.class public Lcom/example/Foo;
.super Ljava/lang/Object;
.source "Foo.java"


# instance fields
.field private count:I


# direct methods
.method public constructor <init>()V
    .registers 1

    .prologue
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public check(Ljava/lang/String;I)Z
    .registers 5
    .param p1, "host"    # Ljava/lang/String;
    .param p2, "port"    # I
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .prologue
    const/4 v0, 0x1

    .line 10
    .local v0, "ok":Z
    if-eqz p1, :cond_0

    .line 11
    const-string v1, "a :cond_9 label in a string"

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1

    .line 12
    :cond_0
    const/4 v0, 0x0

    .end local v0    # "ok":Z
    :cond_1
    .line 14
    return v0
.end method
"""

# the same class from a dex without debug info: no .source/.line/.local/.prologue and no .param lines at all
STRIPPED = """\
.class public Lcom/example/Foo;
.super Ljava/lang/Object;

.field private count:I

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public check(Ljava/lang/String;I)Z
    .registers 5
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation
    const/4 v0, 0x1
    if-eqz p1, :cond_0
    const-string v1, "a :cond_9 label in a string"
    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1
    if-nez v1, :cond_1
    :cond_0
    const/4 v0, 0x0
    :cond_1
    return v0
.end method
"""

PARAM_ANN = """\
.class public Lcom/example/Bar;
.super Ljava/lang/Object;

.method public run(Ljava/lang/String;)V
    .registers 2
    .param p1, "%s"    # Ljava/lang/String;
    .annotation runtime Lcom/example/NonNull;
    .end annotation
    .end param

    .prologue
    .line 5
    return-void
.end method
"""


def d(text):
    return normalize.digest_text(text)


def sub(text, old, new, count=1):
    assert text.count(old) >= count, old
    return text.replace(old, new, count)


class DigestUnchanged(unittest.TestCase):
    def test_debug_lines_and_comments(self):
        t = re.sub(r"^\s*(\.line \d+|\.prologue|\.source .*|\.local .*|\.end local.*|#.*)\n", "", BASE, flags=re.M)
        self.assertNotEqual(t, BASE)
        self.assertEqual(d(t), d(BASE))

    def test_other_line_numbers_and_restart_local(self):
        t = sub(BASE, ".line 10", ".line 110")
        t = sub(t, ":cond_1\n", ":cond_1\n    .restart local v0    # \"ok\":Z\n    .epilogue\n")
        self.assertEqual(d(t), d(BASE))

    def test_param_names(self):
        t = sub(BASE, '"host"', '"h"')
        t = sub(t, '.param p2, "port"    # I', '.param p2    # I')
        self.assertEqual(d(t), d(BASE))

    def test_no_debug_info_at_all(self):
        # a parameter without annotations before a method annotation is not a .param block
        self.assertEqual(d(STRIPPED), d(BASE))

    def test_labels_renamed(self):
        t = BASE.replace(":cond_0", ":cond_a").replace(":cond_1", ":goto_7")
        self.assertEqual(d(t), d(BASE))

    def test_whitespace_and_blank_lines(self):
        t = "\n".join("  " + l.strip() + "  " for l in BASE.split("\n") if l.strip())
        self.assertEqual(d(t), d(BASE))

    def test_annotated_param_name(self):
        self.assertEqual(d(PARAM_ANN % "s"), d(PARAM_ANN % "other"))
        stripped = PARAM_ANN.replace('.param p1, "%s"    # Ljava/lang/String;', ".param p1    # Ljava/lang/String;")
        self.assertEqual(d(stripped), d(PARAM_ANN % "s"))


FLOATS = """\
.class public Lp/F;
.super Ljava/lang/Object;

.field public static final A:F = %s
.field public static final B:D = %s
.field public static final S:Ljava/lang/String; = "1.5f # not a comment"

.method public static f()F
    .registers 1
    const/high16 v0, 0x40000000    %s
    return v0
.end method
"""


class JvmIndependent(unittest.TestCase):
    """baksmali prints float and double literals with the JVM's Float/Double.toString (other digits since Java 19)
    and adds comments: neither may change a digest; another value must."""

    def test_float_double_spellings(self):
        base = d(FLOATS % ("1.1754944E-38f", "1.0E23", "# 2.0f"))
        self.assertEqual(d(FLOATS % ("1.17549435E-38f", "9.999999999999999E22", "# 2.0f")), base)   # Java 17
        self.assertEqual(d(FLOATS % ("1.1754944E-38f", "1.0E23", "# 2.00000f")), base)            # a comment
        self.assertEqual(d(FLOATS % ("1.1754944E-38f", "1.0E23", "")), base)
        self.assertNotEqual(d(FLOATS % ("1.1754945E-38f", "1.0E23", "")), base)
        self.assertNotEqual(d(FLOATS % ("1.1754944E-38f", "1.0E22", "")), base)
        self.assertNotEqual(d(FLOATS % ("-Infinityf", "1.0E23", "")), d(FLOATS % ("Infinityf", "1.0E23", "")))
        self.assertNotEqual(d(FLOATS % ("NaNf", "NaN", "")), d(FLOATS % ("NaNf", "Infinity", "")))
        self.assertNotEqual(d(FLOATS.replace("1.5f # not", "2.5f # not") % ("NaNf", "NaN", "")),
                            d(FLOATS % ("NaNf", "NaN", "")))     # string literals are never rewritten

    def test_literal_forms(self):
        self.assertEqual(normalize.normalize_text(FLOATS % ("1.1754944E-38f", "4.9E-324", "# 2.0f")).split("\n")[2:6], [
            ".field public static final A:F = float:0x00800000", ".field public static final B:D = double:0x0000000000000001",
            '.field public static final S:Ljava/lang/String; = "1.5f # not a comment"', ".method public static f()F"])
        self.assertEqual(normalize._literals("value = {1.5f, \"a = 2.0\", -2.5, '#'}", True),
                         "value = {float:0x3fc00000, \"a = 2.0\", double:0xc004000000000000, '#'}")
        self.assertEqual(normalize._literals("NaN = 1.5f", True), "NaN = float:0x3fc00000")     # names stay
        self.assertEqual(normalize._literals("'\"', 1.5f, '\\''", True), "'\"', float:0x3fc00000, '\\''")
        self.assertEqual(normalize._literals("value = 1.5f"), "value = 1.5f")    # outside an annotation: as it is
        self.assertEqual(normalize.segments('a "x\\"y" \'b\'"open'),
                         [(False, "a "), (True, '"x\\"y"'), (False, " "), (True, "'b'"), (True, '"open')])
        self.assertEqual(normalize.segments(""), [])
        self.assertEqual(normalize.strip_comment("value = '#'    # c"), "value = '#'")
        self.assertEqual(normalize.strip_comment("x # 'y"), "x")
        self.assertEqual(normalize.strip_comment("x '#"), "x '#")
        self.assertEqual(normalize.strip_comment('const-string v0, "a\\"#b"    # c'), 'const-string v0, "a\\"#b"')

    def test_strings_and_instructions_kept(self):
        """Only values are rewritten: a const-string whose text holds ` = ` and a decimal stays as it is."""
        text = '.class public Lp/S;\n.super Ljava/lang/Object;\n.method public static f()V\n    .registers 1\n' \
               '    const-string v0, "%s"\n    return-void\n.end method\n'
        self.assertIn('const-string v0, "k = 1.5"', normalize.normalize_text(text % "k = 1.5"))
        self.assertNotEqual(d(text % "k = 1.5"), d(text % "k = 1.50"))
        self.assertNotEqual(d(text % "k = 1.5f"), d(text % "k = 1.50f"))
        self.assertIn('const-string v0, "x = 1.0E40f"', normalize.normalize_text(text % "x = 1.0E40f"))  # no overflow

    def test_annotation_values_and_arrays(self):
        """baksmali 2.5.2 text of an annotation with multi-line arrays and a sub-annotation (one element per line),
        on a class, a field, a method and a parameter: every float/double element is written as bits."""
        ann = ANN_FLOATS % (("1.17549435E-38f", "9.999999999999999E22") * 5)            # Java 17 spellings
        base = ANN_FLOATS % (("1.1754944E-38f", "1.0E23") * 5)                           # Java 19+
        self.assertEqual(d(ann), d(base))
        n = normalize.normalize_text(base)
        self.assertNotIn("E-38", n)
        self.assertNotIn("E23", n)
        self.assertIn('"x = 1.5",\n"1.5f"\n', n)
        self.assertIn("d = {\nfloat:0x00800000,\nfloat:0x3fc00000\n}", n)
        for i in range(10):                     # each literal counts
            vals = [("1.1754944E-38f", "1.0E23")[j % 2] for j in range(10)]
            vals[i] = "2.5f" if i % 2 == 0 else "2.5"
            self.assertNotEqual(d(ANN_FLOATS % tuple(vals)), d(base), i)


ANN_FLOATS = """\
.class public Lp/A;
.super Ljava/lang/Object;

# annotations
.annotation runtime Lp/Ann;
    d = {
        %s,
        1.5f
    }
    s = {
        "x = 1.5",
        "1.5f"
    }
    sub = .subannotation Lp/B;
        g = {
            %s
        }
    .end subannotation
.end annotation

.field public static F:F
    .annotation runtime Lp/Ann;
        f = %s
        d = %s
    .end annotation
.end field

.method public static f(F)V
    .registers 1
    .annotation runtime Lp/Ann;
        value = {
            %s
        }
        d = {
            %s
        }
    .end annotation
    .param p0    # F
        .annotation runtime Lp/Ann;
            f = %s
            d = {
                .subannotation Lp/B;
                    g = %s
                .end subannotation
            }
        .end annotation
    .end param
    .array-data 4
        0x3fc00000    # 1.5f
    .end array-data
    return-void
.end method

.method public static g()V
    .registers 1
    .annotation runtime Lp/Ann;
        f = %s
        d = %s
    .end annotation
    return-void
.end method
"""


class DigestChanged(unittest.TestCase):
    def assertChanges(self, old, new, text=BASE):
        self.assertNotEqual(d(sub(text, old, new)), d(text), "%r -> %r" % (old, new))

    def test_opcode(self):
        self.assertChanges("if-nez v1", "if-eqz v1")

    def test_constant(self):
        self.assertChanges("const/4 v0, 0x1", "const/4 v0, 0x2")

    def test_string(self):
        self.assertChanges('"a :cond_9 label in a string"', '"a :cond_8 label in a string"')

    def test_member_reference(self):
        self.assertChanges("Ljava/lang/String;->equals(", "Ljava/lang/String;->contentEquals(")
        self.assertChanges("Ljava/lang/Object;)Z", "Ljava/lang/CharSequence;)Z")
        self.assertChanges("Ljava/lang/Object;-><init>", "Ljava/lang/Number;-><init>")

    def test_register(self):
        self.assertChanges("move-result v1", "move-result v0")

    def test_branch_target(self):
        self.assertChanges("if-eqz p1, :cond_0", "if-eqz p1, :cond_1")

    def test_field_access_signature_super_annotation(self):
        self.assertChanges(".field private count:I", ".field private count:J")
        self.assertChanges(".field private count:I", ".field public count:I")
        self.assertChanges(".method public check", ".method public final check")
        self.assertChanges(".super Ljava/lang/Object;", ".super Ljava/lang/Number;")
        self.assertChanges("Ljava/io/IOException;\n", "Ljava/io/EOFException;\n")

    def test_parameter_annotation(self):
        t = PARAM_ANN % "s"
        self.assertChanges("Lcom/example/NonNull;", "Lcom/example/Nullable;", t)
        no_ann = sub(t, "    .annotation runtime Lcom/example/NonNull;\n    .end annotation\n    .end param\n", "")
        self.assertNotEqual(d(no_ann), d(t))

    def test_member_type_is_not_a_label(self):
        a = sub(BASE, "move-result v1\n", "move-result v1\n    sget-object v2, Lcom/example/Foo;->f:La_1;\n")
        b = sub(BASE, "move-result v1\n", "move-result v1\n    sget-object v2, Lcom/example/Foo;->f:Lb_2;\n")
        self.assertNotEqual(d(a), d(b))


class Tree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)

    def test_dir_and_dump(self):
        self.write("smali/com/example/Foo.smali", BASE)
        self.write("smali/com/example/Bar.smali", PARAM_ANN % "s")
        dump = os.path.join(self.root, "dump")
        res = normalize.normalize_dir(os.path.join(self.root, "smali"), dump)
        self.assertEqual(res, {"Lcom/example/Foo;": d(BASE), "Lcom/example/Bar;": d(PARAM_ANN % "s")})
        with open(os.path.join(dump, "com/example/Foo.nsmali"), encoding="utf-8") as f:
            self.assertEqual(f.read(), normalize.normalize_text(STRIPPED))

    def test_duplicate_class(self):
        self.write("smali/a/Foo.smali", BASE)
        self.write("smali/b/Foo.smali", BASE)
        with self.assertRaises(normalize.NormalizeError):
            normalize.normalize_dir(os.path.join(self.root, "smali"))

    def test_no_class_line(self):
        self.write("smali/x.smali", ".super Ljava/lang/Object;\n")
        with self.assertRaises(normalize.NormalizeError):
            normalize.normalize_dir(os.path.join(self.root, "smali"))

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(HERE), "normalize.py")] + list(args),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    def test_cli(self):
        self.write("smali/com/example/Foo.smali", BASE)
        r = self.run_cli("--dir", os.path.join(self.root, "smali"))
        self.assertEqual((r.returncode, r.stdout), (0, "Lcom/example/Foo;\t%s\n" % d(BASE)))
        self.assertEqual(self.run_cli().returncode, 2)
        self.assertEqual(self.run_cli("--dir", "a", "--jar", "b").returncode, 2)
        self.assertEqual(self.run_cli("--bogus").returncode, 2)
        r = self.run_cli("--dir", os.path.join(self.root, "missing"))
        self.assertEqual((r.returncode, r.stderr.split(": ")[-1]), (2, "not a directory\n"))
        # a --dump that cannot be written: tool error (exit 2), no traceback
        self.write("file", "x")
        r = self.run_cli("--dir", os.path.join(self.root, "smali"), "--dump", os.path.join(self.root, "file", "d"))
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertTrue(r.stderr.startswith("normalize: error: "), r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_jar_without_classes_dex(self):
        jar = os.path.join(self.root, "odexed.jar")
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        r = self.run_cli("--jar", jar)
        self.assertEqual(r.returncode, 2)
        self.assertIn("no dex", r.stderr)
        with zipfile.ZipFile(jar, "a") as z:
            z.writestr("classes.dex", b"dex\n035\0")
            z.writestr("classes2.dex", b"dex\n035\0")
        with self.assertRaises(normalize.NormalizeError):
            normalize.check_dex_jar(jar)


class Pins(unittest.TestCase):
    def test_smali_version_matches_fetch_script(self):
        with io.open(os.path.join(os.path.dirname(HERE), "fetch-smali.sh"), encoding="utf-8") as f:
            m = re.search(r"^SMALI_VERSION=(\S+)$", f.read(), re.M)
        self.assertEqual(m.group(1), normalize.SMALI_VERSION)


if __name__ == "__main__":
    unittest.main()
