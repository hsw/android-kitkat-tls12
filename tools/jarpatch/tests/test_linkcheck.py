# SPDX-License-Identifier: Apache-2.0
"""Unit tests of linkcheck.py: the dex table reader, smali references, resolution through superclasses, interfaces
and arrays, and run() on a fixture /system assembled from smali sources (a member the series removes, called from a
boot jar, a framework jar and an apk; an inherited member; a reference that never resolved; a replacement class
calling a member the boot class path lacks). The dex fixtures are skipped without Java and the smali jars of
fetch-smali.sh; the rest runs anywhere.

    python3 -I -m unittest discover tools/jarpatch/tests
"""
import contextlib
import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import linkcheck as lc  # noqa: E402
import normalize  # noqa: E402

ADDR = "Lcom/android/org/conscrypt/AddressUtils;"
ISLIT = "isLiteralIpAddress(Ljava/lang/String;)Z"

OBJECT = """\
.class public Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    return-void
.end method

.method public hashCode()I
    .registers 2
    const/4 v0, 0x0
    return v0
.end method

.method protected clone()Ljava/lang/Object;
    .registers 1
    return-object p0
.end method
"""
STRING = """\
.class public final Ljava/lang/String;
.super Ljava/lang/Object;
.implements Ljava/lang/CharSequence;

.field private count:I
.field public static final EMPTY:Ljava/lang/String;
"""
CHARSEQ = """\
.class public interface abstract Ljava/lang/CharSequence;
.super Ljava/lang/Object;

.method public abstract length()I
.end method
"""
CALLER = """\
.class public %s
.super Ljava/lang/Object;

.method public static check()Z
    .registers 2
    const-string v0, "1.2.3.4"
    invoke-static {v0}, Lcom/android/org/conscrypt/AddressUtils;->isLiteralIpAddress(Ljava/lang/String;)Z
    move-result v0
    return v0
.end method
"""
ADDR_HEAD = """\
.class public Lcom/android/org/conscrypt/AddressUtils;
.super Ljava/lang/Object;

.method public static value()I
    .registers 1
    const/4 v0, 0x1
    return v0
.end method
"""
ADDR_STOCK = ADDR_HEAD + """
.method public static isLiteralIpAddress(Ljava/lang/String;)Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method
"""
SUB = """\
.class public Lcom/vendor/Sub;
.super Lcom/android/org/conscrypt/AddressUtils;
"""
USER = """\
.class public Lcom/vendor/User;
.super Ljava/lang/Object;

.method public static use([Ljava/lang/String;)I
    .registers 3
    invoke-static {}, Lcom/vendor/Sub;->value()I
    move-result v0
    invoke-virtual {p0}, [Ljava/lang/String;->clone()Ljava/lang/Object;
    invoke-static {}, Lcom/android/org/conscrypt/AddressUtils;->notThere()V
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    return v0
.end method
"""
# the replacement class: inherited hashCode() links, the other two references do not
ADDR_BAD = ADDR_HEAD + """
.method public static bad()V
    .registers 2
    invoke-static {}, Lcom/android/org/conscrypt/AddressUtils;->hashCode()I
    invoke-static {}, Lcom/vendor/Helper;->gone()V
    sget-object v0, Ljava/lang/String;->EMPTY:Ljava/lang/String;
    sget-object v0, Ljava/lang/String;->NONE:Ljava/lang/String;
    return-void
.end method
"""

SMALI_SAMPLE = """\
.class public final Lp/A;
.super Lp/Base;
.implements Lp/I;
.source "A.java"

# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lp/Base<",
        "Lp/Gen;",
        ">;"
    }
.end annotation

.annotation runtime Lp/Ann;
    e = .enum Lp/E;->ONE:Lp/E;
.end annotation

.annotation system Ldalvik/annotation/Throws;
    value = {
        Ljava/io/IOException;,
        Lp/X;
    }
.end annotation

# instance fields
.field private f:[Lp/F;

.method public m(I[Lp/P;)Lp/R;
    .registers 4
    .param p1, "x"    # Lp/Comment;
    .prologue
    .line 3
    const-string v0, "Lp/InString;->s()V \\" Lp/Q;"
    .local v0, "s":Lp/Local;
    :try_start_0
    new-instance v1, Lp/N;
    invoke-direct {v1}, Lp/N;->init(Lp/Arg;)V
    check-cast v1, [[Lp/C;
    iget-object v2, p0, Lp/A;->f:[Lp/F;
    invoke-virtual {v2}, [Lp/F;->clone()Ljava/lang/Object;
    :try_end_0
    .catch Lp/Ex; {:try_start_0 .. :try_end_0} :catch_0
    sparse-switch v0, :sswitch_data_0
    :catch_0
    return-object v1
    :sswitch_data_0
    .sparse-switch
        0x1 -> :catch_0
    .end sparse-switch
.end method
"""


def cls(sup, ifs=(), fields=(), methods=()):
    return (sup, tuple(ifs), frozenset(fields), frozenset(methods))


class Pure(unittest.TestCase):
    def test_parse_types(self):
        self.assertEqual(lc.parse_types("I[Lp/A;[[JLp/B;"), ["Lp/A;", "Lp/B;"])
        self.assertEqual(lc.parse_proto("(I[Lp/A;)[Lp/R;"), ["Lp/A;", "Lp/R;"])
        for bad in ("Lp/A", "Q", "I,"):
            self.assertRaises(lc.LinkError, lc.parse_types, bad)
        self.assertRaises(lc.LinkError, lc.parse_proto, "I)V")

    def test_smali_refs(self):
        types, fields, methods = lc.smali_refs(SMALI_SAMPLE)
        self.assertEqual(types, {"Lp/A;", "Lp/Base;", "Lp/I;", "Lp/Ann;", "Lp/E;", "Ljava/io/IOException;", "Lp/X;",
                                 "Lp/F;", "Lp/P;", "Lp/R;", "Lp/N;", "Lp/Arg;", "Lp/C;", "Ljava/lang/Object;",
                                 "Lp/Ex;"})
        self.assertEqual(fields, {("Lp/E;", "ONE:Lp/E;"), ("Lp/A;", "f:[Lp/F;")})
        self.assertEqual(methods, {("Lp/N;", "init(Lp/Arg;)V"), ("[Lp/F;", "clone()Ljava/lang/Object;")})
        # literals and comments are never references, a quote inside a char literal included (normalize.segments)
        types, fields, methods = lc.smali_refs("    value = {'\"', \"Lp/S;->x:I\", 'L', Lp/T;}    # Lp/C; '\n"
                                               "    const-string v0, \"#\"    # Lp/D;->y:I\n")
        self.assertEqual((types, fields, methods), ({"Lp/T;"}, set(), set()))

    def test_resolve(self):
        boot = {"Ljava/lang/Object;": cls(None, methods=["hashCode()I", "clone()Ljava/lang/Object;"]),
                "Lp/I;": cls("Ljava/lang/Object;", methods=["run()V"], fields=["K:I"]),
                "Lp/J;": cls("Ljava/lang/Object;", ifs=["Lp/I;"]),
                "Lp/Base;": cls("Ljava/lang/Object;", ifs=["Lp/J;"], fields=["b:I"]),
                "Lp/A;": cls("Lp/Base;")}
        own = {"Lq/Sub;": cls("Lp/A;"), "Lp/A;": cls("Ljava/lang/Object;", fields=["own:I"])}
        w = lc.World(boot, own)
        self.assertEqual(w.resolve("Lp/A;", "b:I", lc.FIELD), "Lp/Base;")              # superclass
        self.assertEqual(w.resolve("Lp/A;", "run()V", lc.METHOD), "Lp/I;")              # interface of an interface
        self.assertEqual(w.resolve("Lp/A;", "K:I", lc.FIELD), "Lp/I;")
        self.assertEqual(w.resolve("Lq/Sub;", "hashCode()I", lc.METHOD), "Ljava/lang/Object;")
        self.assertEqual(w.resolve("Lp/I;", "hashCode()I", lc.METHOD), "Ljava/lang/Object;")
        self.assertEqual(w.resolve("[[Lp/A;", "clone()Ljava/lang/Object;", lc.METHOD), "Ljava/lang/Object;")
        self.assertEqual(w.resolve("[I", "hashCode()I", lc.METHOD), "Ljava/lang/Object;")
        self.assertIsNone(w.resolve("[Lp/Missing;", "hashCode()I", lc.METHOD))
        self.assertIsNone(w.resolve("Lp/A;", "own:I", lc.FIELD))      # the boot class path wins over the jar's own copy
        self.assertIsNone(w.resolve("Lp/A;", "run(I)V", lc.METHOD))
        self.assertIsNone(w.resolve("Lp/Missing;", "run()V", lc.METHOD))
        for changed, desc, want in (({"Lp/I;"}, "Lq/Sub;", True), ({"Lp/Base;"}, "[Lq/Sub;", True),
                                    ({"Lp/Gone;"}, "Lp/Gone;", True), ({"Lp/Other;"}, "Lq/Sub;", False),
                                    ({"Lp/I;"}, "[I", False), ({"Lp/I;"}, "Lp/Missing;", False)):
            self.assertEqual(lc.World(boot, own, changed).touches(desc), want, (changed, desc))

    def test_constructors(self):
        # constructors are not inherited: <init> resolves in the named class only (the donor's
        # `new IllegalStateException(String)` needs that class's own constructor, RuntimeException's does not do)
        boot = {"Ljava/lang/Object;": cls(None, methods=["<init>()V", "hashCode()I"]),
                "Lp/Base;": cls("Ljava/lang/Object;", methods=["<init>(Ljava/lang/String;)V", "<init>()V"]),
                "Lp/A;": cls("Lp/Base;", methods=["<init>()V"])}
        w = lc.World(boot)
        self.assertEqual(w.resolve("Lp/A;", "<init>()V", lc.METHOD), "Lp/A;")
        self.assertIsNone(w.resolve("Lp/A;", "<init>(Ljava/lang/String;)V", lc.METHOD))
        self.assertEqual(w.resolve("Lp/Base;", "<init>(Ljava/lang/String;)V", lc.METHOD), "Lp/Base;")
        self.assertIsNone(w.resolve("Lp/A;", "<clinit>()V", lc.METHOD))
        self.assertIsNone(w.resolve("[Lp/A;", "<init>()V", lc.METHOD))
        self.assertIsNone(w.resolve("Lp/Missing;", "<init>()V", lc.METHOD))
        self.assertEqual(w.resolve("Lp/A;", "hashCode()I", lc.METHOD), "Ljava/lang/Object;")
        text = (".class public Lq/R;\n.super Ljava/lang/Object;\n.method public static f()V\n    .registers 2\n"
                "    new-instance v0, Lp/A;\n    const-string v1, \"x\"\n"
                "    invoke-direct {v0, v1}, Lp/A;-><init>(Ljava/lang/String;)V\n    return-void\n.end method\n")
        w = lc.World(dict(boot, **{"Ljava/lang/String;": cls("Ljava/lang/Object;")}),
                     {"Lq/R;": cls("Ljava/lang/Object;")})
        self.assertEqual(lc.outbound(text, w)[0], ["Lp/A;-><init>(Ljava/lang/String;)V"])

    def test_duplicates(self):
        class D(object):
            def __init__(self, *names):
                self.classes = {n: cls(OBJ) for n in names}
        OBJ = "Ljava/lang/Object;"
        names = ["core.jar", "ext.jar", "okhttp.jar", "vendor.jar"]
        dexes = [D(OBJ, "Lp/V;"), D("Lp/E;"), D("Lp/V;", "Lp/E;", "Lp/L;", "Lp/O;"), D("Lp/L;")]
        self.assertEqual(lc.duplicates(names, dexes, {"okhttp": {"Lp/V;": "p", "Lp/E;": "p", "Lp/L;": "p",
                                                                 "Lp/O;": "p"}}),
                         [("okhttp", "Lp/E;", "earlier", "ext.jar"), ("okhttp", "Lp/L;", "later", "vendor.jar"),
                          ("okhttp", "Lp/V;", "earlier", "core.jar")])
        self.assertEqual(lc.duplicates(names, dexes, {"okhttp": {"Lp/O;": "p"}, "gone": {"Lp/V;": "p"}}), [])

    def test_runtimes(self):
        bcp = ["/system/framework/core.jar", "/system/framework/ext.jar"]
        self.assertEqual(lc.runtimes(bcp, False), [("dalvik", ["core.jar", "ext.jar"]),
                                                   ("art", ["core-libart.jar", "ext.jar"])])
        self.assertEqual(lc.runtimes(bcp, True), [("dalvik", ["core.jar", "ext.jar"])])
        self.assertRaises(lc.LinkError, lc.runtimes, ["/system/framework/ext.jar"], False)

    def test_bad_dex(self):
        self.assertRaises(lc.LinkError, lc.Dex, b"not a dex" * 20)
        head = bytearray(b"dex\n035\0" + b"\0" * 0x68)
        struct.pack_into("<2I", head, 0x38, 1000, 0x70)              # 1000 strings past the end
        self.assertRaises(lc.LinkError, lc.Dex, bytes(head))


class Fixture(unittest.TestCase):
    """A /system with core.jar (+ the same as core-libart.jar), conscrypt.jar (AddressUtils with
    isLiteralIpAddress), the staged conscrypt dex without it, framework/caller.jar and app/Caller.apk calling it, an
    apk with a subclass using the kept member, and a resource-only apk."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = cls.tmp.name
        cls.ok = False
        if not shutil.which(normalize.JAVA):
            return
        try:
            jars = normalize.smali_jars()
        except normalize.NormalizeError:
            return
        specs = {"core": {"Object": OBJECT, "String": STRING, "CharSequence": CHARSEQ,
                          "BootCaller": CALLER % "Lcom/android/BootCaller;"},
                 "conscrypt": {"AddressUtils": ADDR_STOCK},
                 "staged": {"AddressUtils": ADDR_HEAD},
                 "caller": {"Caller": CALLER % "Lcom/vendor/Caller;"},
                 "inherit": {"Sub": SUB, "User": USER}}
        procs = []
        for name, files in specs.items():
            src = os.path.join(cls.base, "src", name)
            os.makedirs(src)
            for n, text in files.items():
                with open(os.path.join(src, n + ".smali"), "w") as f:
                    f.write(text)
            dex = os.path.join(cls.base, name + ".dex")
            procs.append((dex, subprocess.Popen([normalize.JAVA, "-jar", jars[1], "a", "-a", "19", "-o", dex, src],
                                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)))
        for dex, p in procs:
            out = p.communicate()[0]
            assert p.returncode == 0 and os.path.isfile(dex), out
        cls.root = os.path.join(cls.base, "system")
        for p, dex in (("framework/core.jar", "core"), ("framework/core-libart.jar", "core"),
                       ("framework/conscrypt.jar", "conscrypt"), ("framework/caller.jar", "caller"),
                       ("app/Caller.apk", "caller"), ("priv-app/Inherit.apk", "inherit"), ("app/Res.apk", None)):
            p = os.path.join(cls.root, p)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("resources.arsc", b"\0")
                if dex:
                    z.write(os.path.join(cls.base, dex + ".dex"), "classes.dex")
        cls.staged = {"conscrypt": os.path.join(cls.base, "staged.dex")}
        cls.addr_smali = os.path.join(cls.base, "src", "staged", "AddressUtils.smali")
        cls.bcp = ["/system/framework/core.jar", "/system/framework/conscrypt.jar"]
        cls.ok = True

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        if not self.ok:
            self.skipTest("no java or no smali/baksmali (fetch-smali.sh)")

    def test_dex_reader(self):
        dx = lc.read_dex(os.path.join(self.root, "framework", "core.jar"))
        self.assertEqual(sorted(dx.classes), ["Lcom/android/BootCaller;", "Ljava/lang/CharSequence;",
                                              "Ljava/lang/Object;", "Ljava/lang/String;"])
        self.assertEqual(dx.classes["Ljava/lang/Object;"],
                         cls(None, methods=["<init>()V", "hashCode()I", "clone()Ljava/lang/Object;"]))
        self.assertEqual(dx.classes["Ljava/lang/String;"],
                         cls("Ljava/lang/Object;", ["Ljava/lang/CharSequence;"],
                             ["count:I", "EMPTY:Ljava/lang/String;"]))
        self.assertIn((ADDR, ISLIT), dx.methods)
        self.assertIn(ADDR, dx.types)
        self.assertIsNone(lc.read_dex(os.path.join(self.root, "app", "Res.apk")))
        self.assertEqual(lc.read_dex(self.staged["conscrypt"]).classes[ADDR][3], frozenset(["value()I"]))

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(lc.main(["--dex", os.path.join(self.root, "framework", "core.jar"),
                                      os.path.join(self.root, "app", "Res.apk")]), 0)
        text = out.getvalue()
        for needle in ("class Ljava/lang/Object; super -\n", "  method hashCode()I\n",
                       "class Ljava/lang/String; super Ljava/lang/Object; implements Ljava/lang/CharSequence;\n",
                       "ref method %s->%s\n" % (ADDR, ISLIT), "Res.apk: no classes.dex"):
            self.assertIn(needle, text)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(lc.main([]), 2)

        class Closed(io.StringIO):
            def write(self, s):
                raise BrokenPipeError(32, "Broken pipe")
        with contextlib.redirect_stdout(Closed()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(lc.main(["--dex", os.path.join(self.root, "framework", "core.jar")]), 2)
        self.assertEqual(err.getvalue(), "linkcheck: error: [Errno 32] Broken pipe\n")

    def run_check(self, replaced_text=None, dalvik_only=False):
        rep = {}
        if replaced_text is not None:
            p = os.path.join(tempfile.mkdtemp(dir=self.base), "AddressUtils.smali")
            with open(p, "w") as f:
                f.write(replaced_text)
            rep = {"conscrypt": {ADDR: p}}
        return lc.run(self.root, self.bcp, self.staged, rep, {"conscrypt": {ADDR}}, dalvik_only)

    def test_removed_member(self):
        # the series removes AddressUtils.isLiteralIpAddress (0030): every caller is refused, in both runtimes;
        # Sub.value() (inherited, kept) links, AddressUtils.notThere() never resolved (counted, not refused)
        stats, misses = self.run_check(ADDR_HEAD)
        why = "resolved before the patch, not after (%s)"
        ref = ADDR + "->" + ISLIT
        self.assertEqual(misses, [("/system/app/Caller.apk", ref, why % "dalvik, art"),
                                  ("/system/framework/caller.jar", ref, why % "dalvik, art"),
                                  ("/system/framework/core-libart.jar", ref, why % "art"),
                                  ("/system/framework/core.jar", ref, why % "dalvik")])
        d, a = stats["dalvik"], stats["art"]
        self.assertEqual((d["bootclasspath"], d["dex"], d["no_dex"], d["regressions"], d["outbound_misses"]),
                         (2, 5, 1, 3, 0))
        self.assertEqual(a["regressions"], 3)       # core-libart.jar carries the boot caller there
        self.assertEqual(d["unresolved_before"], 1)
        self.assertEqual(d["outbound_classes"], 1)
        # type + member of the three callers and of the staged dex, Inherit.apk: the supertype, Sub.value(),
        # AddressUtils.notThere() (String.length() and the array clone() do not reach AddressUtils)
        self.assertEqual(d["refs_checked"], 4 * 2 + 3)

    def test_dalvik_only(self):
        stats, misses = self.run_check(dalvik_only=True)
        self.assertEqual(sorted(stats), ["dalvik"])
        # the same callers as test_removed_member, minus core-libart.jar (no art runtime), dalvik only
        why = "resolved before the patch, not after (dalvik)"
        ref = ADDR + "->" + ISLIT
        self.assertEqual(misses, [("/system/app/Caller.apk", ref, why), ("/system/framework/caller.jar", ref, why),
                                  ("/system/framework/core.jar", ref, why)])

    def test_unchanged_links(self):
        # the device's own conscrypt as the "patched" dex: nothing changes, nothing breaks
        stats, misses = lc.run(self.root, self.bcp, {"conscrypt": os.path.join(self.root, "framework",
                                                                               "conscrypt.jar")},
                               {}, {"conscrypt": {ADDR}}, False)
        self.assertEqual(misses, [])
        self.assertEqual(stats["dalvik"]["regressions"], 0)

    def test_off_bootclasspath(self):
        # a patched jar that the runtime's BOOTCLASSPATH does not name would never be loaded: refused per runtime;
        # core.jar is dalvik's, core-libart.jar art's (each the other runtime's core jar, not refused there)
        why = "/system/framework/conscrypt.jar is patched, but BOOTCLASSPATH does not name it (%s): the runtime " \
              "would not load the patched classes"
        stats, misses = lc.run(self.root, ["/system/framework/core.jar"], self.staged, {}, {"conscrypt": {ADDR}},
                               False)
        self.assertEqual([m for m in misses if m[0] == "conscrypt"], [("conscrypt", "-", why % "dalvik, art")])
        stats, misses = lc.run(self.root, ["/system/framework/core.jar"], self.staged, {}, {"conscrypt": {ADDR}},
                               True)
        self.assertEqual([m for m in misses if m[0] == "conscrypt"], [("conscrypt", "-", why % "dalvik")])
        core = os.path.join(self.root, "framework", "core.jar")
        stats, misses = lc.run(self.root, self.bcp, {"core": core, "core-libart": core}, {}, {}, False)
        self.assertEqual(misses, [])

    def test_outbound(self):
        # the replacement class calls a member the boot class path lacks: refused with the class named
        stats, misses = self.run_check(ADDR_BAD)
        out = [m for m in misses if m[0] == "conscrypt"]
        tail = ", which does not resolve on the patched boot class path (dalvik, art)"
        self.assertEqual(out, [("conscrypt", ADDR, "references %s%s" % (r, tail)) for r in
                               ("Lcom/vendor/Helper;", "Lcom/vendor/Helper;->gone()V",
                                "Ljava/lang/String;->NONE:Ljava/lang/String;")])
        self.assertEqual(stats["dalvik"]["outbound_misses"], 3)

    def test_shadowed(self):
        # another boot jar defines the replaced AddressUtils too: before conscrypt.jar on BOOTCLASSPATH its copy is
        # the one the runtime loads (the patched one never runs), after it a second copy; both refuse, per runtime
        root = os.path.join(tempfile.mkdtemp(dir=self.base), "system")
        os.makedirs(os.path.join(root, "framework"))
        for n in ("core.jar", "core-libart.jar", "conscrypt.jar"):
            shutil.copyfile(os.path.join(self.root, "framework", n), os.path.join(root, "framework", n))
        shutil.copyfile(os.path.join(self.root, "framework", "conscrypt.jar"), os.path.join(root, "framework",
                                                                                            "vendor.jar"))
        p = os.path.join(tempfile.mkdtemp(dir=self.base), "AddressUtils.smali")
        shutil.copyfile(self.addr_smali, p)
        for bcp, where, why in ((["core.jar", "vendor.jar", "conscrypt.jar"], "earlier",
                                 "the runtime would load that copy, not the patched one"),
                                (["core.jar", "conscrypt.jar", "vendor.jar"], "later",
                                 "a second copy the series does not cover")):
            stats, misses = lc.run(root, ["/system/framework/" + n for n in bcp], self.staged,
                                   {"conscrypt": {ADDR: p}}, {"conscrypt": {ADDR}}, False)
            self.assertIn(("conscrypt", ADDR, "also defined in /system/framework/vendor.jar, %s on BOOTCLASSPATH "
                           "(dalvik, art): %s" % (where, why)), misses)
            self.assertEqual([m for m in misses if m[0] == "conscrypt"], [m for m in misses if "also defined" in m[2]])
        # a check class (the native library's, not replaced) is covered the same way, in its own words
        for bcp, where, why in ((["core.jar", "vendor.jar", "conscrypt.jar"], "earlier",
                                 "the runtime would load that copy, not the checked one"),
                                (["core.jar", "conscrypt.jar", "vendor.jar"], "later",
                                 "a second copy the check does not cover")):
            stats, misses = lc.run(root, ["/system/framework/" + n for n in bcp], self.staged, {},
                                   {"conscrypt": {ADDR}}, False, checked={"conscrypt": {ADDR}})
            self.assertEqual([m for m in misses if m[0] == "conscrypt"], [
                ("conscrypt", ADDR, "also defined in /system/framework/vendor.jar, %s on BOOTCLASSPATH (dalvik, art): "
                 "%s" % (where, why))])
        # the vendor jar off BOOTCLASSPATH (an ordinary framework jar) shadows nothing
        stats, misses = lc.run(root, ["/system/framework/core.jar", "/system/framework/conscrypt.jar"], self.staged,
                               {"conscrypt": {ADDR: p}}, {"conscrypt": {ADDR}}, False)
        self.assertFalse([m for m in misses if "also defined" in m[2]], misses)
