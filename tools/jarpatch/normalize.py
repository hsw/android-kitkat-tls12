#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""normalize.py: per-class normalized baksmali text and its sha256 (the jar patcher's reference model H).

    python3 -I normalize.py --jar JAR [--dump DIR]         baksmali JAR's classes.dex, then normalize
    python3 -I normalize.py --dir SMALI_DIR [--dump DIR]   normalize an existing `baksmali d` output tree

Prints `<class descriptor>\t<sha256>` lines sorted by descriptor; --dump also writes each normalized text to
DIR/<class path>.nsmali. Exit 0 ok, 1 tool error (no classes.dex, baksmali failed, bad smali), 2 usage.

A class's digest is the sha256 of its baksmali text (2.5.2, `d -a 19`, debug info kept) with everything removed that
only debug info or the disassembler's naming decides, so that two dex builds of the same source compare equal while any
change in what the class does compares different:
  - dropped: comment lines and trailing comments (`    # 2.0f`: baksmali's notes, never code), `.source`, `.line`,
    `.local`/`.end local`/`.restart local`, `.prologue`/`.epilogue`;
  - `.param pN, "name"`: dropped when the parameter has no annotations; when it opens a `.param` ... `.end param` block
    (parameter annotations) only `.param pN` stays;
  - labels (`:cond_0`, `:try_start_1`, `:pswitch_data_0`, ...) renamed per method in order of first appearance;
  - decimal float and double literals (field initial values and annotation elements, after ` = `) written as their
    bits (`float:0x00800000`, `double:0x...`): baksmali prints them with the JVM's Float/Double.toString, whose digits
    changed in Java 19 (`1.17549435E-38f` before, `1.1754944E-38f` after, the same float).
Kept as they are: class, super, interfaces, access flags, annotations, fields with their initial values, method
signatures and flags, `.registers`, every instruction with its operands (registers, constants, strings, type, field
and method references), try/catch ranges, switch and array payloads. Text inside string literals is never rewritten.
Measured on the four 4.4 jars (`core`, `core-libart`, `conscrypt`, `okhttp`): Google's SDK 4.4.2 builds and an AOSP
android-4.4.2_r2 build agree on every class the series touches or libjavacrypto.so names, and a baksmali -> smali ->
baksmali round trip keeps every digest.

Imported by mkset.py and the patcher: NORMALIZER_VERSION and MODEL go into the set files (a set made with another
version must not be compared with this one). Stdlib only (Java 8+ and the jars of fetch-smali.sh for --jar; the
java binary is $KKTLS_JAVA when set, else `java` on PATH; the patcher and checkset.py use the same).
"""
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

NORMALIZER_VERSION = 2       # 2: trailing comments dropped, float/double literals as bits (digests JVM-independent)
MODEL = "H"
SMALI_VERSION = "2.5.2"     # must equal fetch-smali.sh's SMALI_VERSION (tests check it)
BAKSMALI_API = "19"
HERE = os.path.dirname(os.path.abspath(__file__))
JAVA = os.environ.get("KKTLS_JAVA") or "java"   # Java 8+ for smali/baksmali 2.5.2
JOBS = str(min(8, os.cpu_count() or 1))         # baksmali threads (its output does not depend on them)

DEBUG_PREFIX = (".source ", ".line ", ".local ", ".end local", ".restart local")
DEBUG_EXACT = (".prologue", ".epilogue")
# A label is an operand or a label line: never preceded by anything but white space or `{` (`.catch ... {:a .. :b}`),
# which keeps `->field:Lpkg_1;`-like member types out.
LABEL = re.compile(r"(?<![^\s{]):[A-Za-z]+(?:_[A-Za-z]+)*_[0-9a-f]+\b")
PARAM = re.compile(r"\.param ([vp]\d+)\b")
# a decimal float (suffix f) or double literal as baksmali prints it; ints and longs are hex, names hold no `.`
FLOAT = re.compile(r"(?<![\w$/;>.-])(-?)(Infinity|NaN|\d+\.\d+(?:E-?\d+)?)([fF]?)(?![\w$.])")
# sub-annotations (`value = .subannotation ...`) only occur inside an annotation: depth > 0 skips them anyway
ANN_OPEN = ".annotation "
ANN_CLOSE = ".end annotation"


class NormalizeError(Exception):
    pass


def _is_debug(s):
    return s.startswith(DEBUG_PREFIX) or s in DEBUG_EXACT


def _opens_param_block(lines, i):
    """True when the `.param` line lines[i] is followed by its annotations and `.end param` (a method annotation
    after a parameter without annotations is not part of the parameter)."""
    depth = 0
    for s in lines[i + 1:]:
        if s.startswith(ANN_OPEN):
            depth += 1
        elif s == ANN_CLOSE:
            depth -= 1
        elif depth == 0:
            return s == ".end param"
    return False


def _split_string(line):
    """(code, tail): the part before the first double quote and the rest (string literals are left untouched)."""
    i = line.find('"')
    return (line, "") if i < 0 else (line[:i], line[i:])


def _strip_comment(line):
    """line without a trailing `# ...` comment; a `#` inside a string or char literal is kept."""
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "#":
            return line[:i].rstrip()
        i += 1
    return line


def _float_bits(m):
    sign, num, suffix = m.groups()
    if num == "NaN":
        bits = "NaN"
    elif suffix:
        bits = "0x%08x" % struct.unpack(">I", struct.pack(">f", float(sign + num)))[0]
    else:
        bits = "0x%016x" % struct.unpack(">Q", struct.pack(">d", float(sign + num)))[0]
    return ("float:" if suffix else "double:") + bits


def _literals(s):
    """The value part (after ` = `) of a field or annotation element line with its float/double literals as bits;
    string literals are left untouched."""
    i = s.find(" = ")
    if i < 0:
        return s
    out, rest = [s[:i + 3]], s[i + 3:]
    while rest:
        code, tail = _split_string(rest)
        out.append(FLOAT.sub(_float_bits, code))
        if not tail:
            break
        j = 1                                   # the end of the string literal that starts tail
        while j < len(tail) and tail[j] != '"':
            j += 2 if tail[j] == "\\" else 1
        out.append(tail[:j + 1])
        rest = tail[j + 1:]
    return "".join(out)


def normalize_text(text):
    """Normalized form (model H) of one class's baksmali text."""
    lines = [l.strip() for l in text.split("\n")]
    lines = [l for l in lines if l and not l.startswith("#") and not _is_debug(l)]
    lines = [_literals(_strip_comment(l)) for l in lines]
    out, labels, in_method = [], {}, False
    for i, s in enumerate(lines):
        if s.startswith(".method "):
            in_method, labels = True, {}
        elif s == ".end method":
            in_method = False
        if s.startswith(".param "):
            m = PARAM.match(s)
            if not m:
                raise NormalizeError("unparsable line: " + s)
            if not _opens_param_block(lines, i):
                continue
            s = ".param " + m.group(1)
        elif in_method:
            code, tail = _split_string(s)
            s = LABEL.sub(lambda m: labels.setdefault(m.group(0), ":L%d" % len(labels)), code) + tail
        out.append(s)
    return "\n".join(out) + "\n"


def class_descriptor(text):
    for l in text.split("\n"):
        if l.startswith(".class "):
            d = l.split()[-1]
            if d.startswith("L") and d.endswith(";"):
                return d
            break
    raise NormalizeError("no .class line")


def digest_text(text):
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def index_dir(root, dump=None):
    """{descriptor: (smali path, digest)} over the .smali files under root."""
    res = {}
    for d, _, files in os.walk(root):
        for f in sorted(files):
            if not f.endswith(".smali"):
                continue
            p = os.path.join(d, f)
            with open(p, encoding="utf-8") as fh:
                t = fh.read()
            try:
                c, n = class_descriptor(t), normalize_text(t)
            except NormalizeError as e:
                raise NormalizeError("%s: %s" % (p, e))
            if c in res:
                raise NormalizeError("class %s defined twice under %s" % (c, root))
            res[c] = (p, hashlib.sha256(n.encode("utf-8")).hexdigest())
            if dump:
                q = os.path.join(dump, c[1:-1] + ".nsmali")
                os.makedirs(os.path.dirname(q), exist_ok=True)
                with open(q, "w", encoding="utf-8") as fh:
                    fh.write(n)
    return res


def normalize_dir(root, dump=None):
    """{descriptor: digest} over the .smali files under root."""
    return {c: dg for c, (_, dg) in index_dir(root, dump).items()}


def smali_jars():
    """(baksmali.jar, smali.jar) from fetch-smali.sh (cache first, download with the pinned sha256 otherwise)."""
    r = subprocess.run(["bash", os.path.join(HERE, "fetch-smali.sh")], stdout=subprocess.PIPE, universal_newlines=True)
    paths = r.stdout.split("\n")[:2]
    if r.returncode != 0 or not all(p and os.path.isfile(p) for p in paths):
        raise NormalizeError("fetch-smali.sh failed (exit %d)" % r.returncode)
    return paths[0], paths[1]


def check_dex_jar(jar):
    """The jar must carry exactly one dex, classes.dex (odexed-and-stripped jars and multidex are not supported)."""
    try:
        with zipfile.ZipFile(jar) as z:
            names = z.namelist()
    except (OSError, zipfile.BadZipFile) as e:
        raise NormalizeError("%s: not a readable zip: %s" % (jar, e))
    dex = [n for n in names if n.endswith(".dex")]
    if dex != ["classes.dex"]:
        raise NormalizeError("%s: expected exactly classes.dex, found %s" % (jar, ", ".join(dex) or "no dex"))


def baksmali(src, out_dir, baksmali_jar):
    """baksmali d -a 19 (debug info kept) of a jar (check_dex_jar it first) or a dex into out_dir."""
    cmd = [JAVA, "-jar", baksmali_jar, "d", "-a", BAKSMALI_API, "-j", JOBS, src, "-o", out_dir]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    if r.returncode != 0:
        raise NormalizeError("baksmali of %s failed (exit %d): %s" % (src, r.returncode, r.stdout.strip()[-500:]))


def jar_digests(jar, baksmali_jar=None, dump=None):
    """{descriptor: digest} of the classes in jar's classes.dex."""
    check_dex_jar(jar)
    if baksmali_jar is None:
        baksmali_jar = smali_jars()[0]
    tmp = tempfile.mkdtemp(prefix="kktls-bak-")
    try:
        baksmali(jar, os.path.join(tmp, "out"), baksmali_jar)
        return normalize_dir(os.path.join(tmp, "out"), dump)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    usage = "usage: normalize.py (--jar JAR | --dir SMALI_DIR) [--dump DIR]"
    mode = src = dump = None
    while argv:
        a = argv.pop(0)
        if a in ("--jar", "--dir", "--dump") and argv:
            v = argv.pop(0)
            if a == "--dump":
                dump = v
            elif mode is None:
                mode, src = a, v
            else:
                print(usage, file=sys.stderr)
                return 2
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            print(usage, file=sys.stderr)
            return 2
    if mode is None:
        print(usage, file=sys.stderr)
        return 2
    try:
        if mode == "--dir":
            if not os.path.isdir(src):
                raise NormalizeError("%s: not a directory" % src)
            res = normalize_dir(src, dump)
        else:
            res = jar_digests(src, dump=dump)
    except NormalizeError as e:
        print("normalize: " + str(e), file=sys.stderr)
        return 1
    for c in sorted(res):
        print("%s\t%s" % (c, res[c]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
