#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""mkset.py: the jar patcher's set file for one donor line, from a stock and a series build of the four 4.4 jars.

    python3 -I mkset.py STOCK_DIR OURS_DIR --tag AOSP_TAG --jni FILE [--note TEXT]... [--out FILE]

STOCK_DIR and OURS_DIR hold core.jar, core-libart.jar, conscrypt.jar and okhttp.jar (directly, or in framework/ or
system/framework/): STOCK_DIR from an AOSP build of AOSP_TAG without the series, OURS_DIR the same jars with the series
(the release java zip's system/framework/). Each jar's classes.dex is disassembled (baksmali 2.5.2 from
fetch-smali.sh) and normalized (normalize.py, model H); the set is the dex diff, not a reading of the patches:

  class <jar> <descriptor> <stock-digest|-> <ours-digest|->   every class whose digest differs, added (stock `-`) or
                                                               removed (ours `-`) by the series: replaced by the patcher
  check <jar> <descriptor> <stock-digest>                      a class named in the --jni FILE (classes the donor
                                                               libjavacrypto.so looks up) that the jar has and the
                                                               series does not change: must equal stock, not replaced
  entry <jar> <path> <stock-sha256|-> <ours-sha256|->          a non-dex jar entry whose bytes differ (sha256 of the
                                                               uncompressed bytes); META-INF/ is ignored (the manifest
                                                               carries the build tool, not content)
  ours <jar> <sha256>                                          one per jar: aggregate() of the whole ours jar (every
                                                               class digest and entry sha256, listed or not), so that
                                                               any change of the series outside the listed lines, or a
                                                               donor of another release, is seen (checkset.py, the
                                                               patcher)

The header names the stock AOSP tag, the reference model, the normalizer version and the smali version; lines starting
with `#` are comments (--note adds some). A --jni name that no stock jar defines is an error (a typo would silently drop
a check). Exit 0 written, 2 usage or error.

read_set(path, tag) parses and validates a set file (used by the patcher, checkset.py and the tests): its header must
name this normalizer's model and versions (and tag, when given). Stdlib only.
"""
import hashlib
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # `python3 -I` leaves the script dir out
import normalize  # noqa: E402
import rawzip  # noqa: E402

JARS = ("core", "core-libart", "conscrypt", "okhttp")
HEADER_KEYS = ("tag", "model", "normalizer", "smali")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
DESC = re.compile(r"L[^;\s]+;\Z")
TAG = re.compile(r"android-4\.4(\.[1-4])?_r[0-9.]+\Z")


class SetError(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def aggregate(classes, entries):
    """sha256 of one jar as the set sees it: `class <desc> <digest>` for every class, then `entry <path> <sha256>`
    for every non-dex entry (META-INF/ excluded), each sorted, one line each."""
    h = hashlib.sha256()
    for k in sorted(classes):
        h.update(("class %s %s\n" % (k, classes[k])).encode("utf-8"))
    for k in sorted(entries):
        h.update(("entry %s %s\n" % (k, entries[k])).encode("utf-8"))
    return h.hexdigest()


def find_jar(root, name):
    for sub in ("", "framework", os.path.join("system", "framework")):
        p = os.path.join(root, sub, name + ".jar")
        if os.path.isfile(p):
            return p
    raise SetError("%s: no %s.jar (looked in ., framework/, system/framework/)" % (root, name))


def entry_digests(jar):
    """{path: sha256} of the jar's non-dex file entries, META-INF/ excluded."""
    res = {}
    with zipfile.ZipFile(jar) as z:
        for i in z.infolist():
            n = i.filename
            if n.endswith("/") or n == "classes.dex" or n.startswith("META-INF/"):
                continue
            if n in res:
                raise SetError("%s: duplicate entry %s" % (jar, n))
            res[n] = hashlib.sha256(z.read(i)).hexdigest()
    return res


def read_jni(path):
    names = []
    with open(path, encoding="utf-8") as f:
        for n, l in enumerate(f, 1):
            l = l.split("#", 1)[0].strip()
            if not l:
                continue
            if not DESC.match(l):
                raise SetError("%s:%d: not a class descriptor: %s" % (path, n, l))
            names.append(l)
    return names


def diff(a, b):
    """[(key, a-value|-, b-value|-)] for the keys whose values differ, sorted."""
    return [(k, a.get(k, "-"), b.get(k, "-")) for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]


def make_set(stock, ours, jni, tag, notes=()):
    """Set file text. stock/ours: {jar: (class digests, entry digests)}."""
    classes, checks, entries = [], [], []
    found = set()
    for j in JARS:
        (sc, se), (oc, oe) = stock[j], ours[j]
        changed = diff(sc, oc)
        classes += [("class", j) + d for d in changed]
        entries += [("entry", j) + d for d in diff(se, oe)]
        repl = {d[0] for d in changed}
        for c in jni:
            if c in sc:
                found.add(c)
                if c not in repl:
                    checks.append(("check", j, c, sc[c]))
            elif c in repl:
                found.add(c)       # added by the series: nothing on the stock side to check
    missing = [c for c in jni if c not in found]
    if missing:
        raise SetError("--jni names in no stock jar: " + " ".join(missing))
    out = ["# kktls jar patcher set file (tools/jarpatch/mkset.py; format in its help)"]
    out += ["# " + n for n in notes]
    out += ["tag " + tag, "model " + normalize.MODEL, "normalizer %d" % normalize.NORMALIZER_VERSION,
            "smali " + normalize.SMALI_VERSION]
    out += [" ".join(t) for t in classes + sorted(checks, key=lambda t: (JARS.index(t[1]), t[2])) + entries]
    out += ["ours %s %s" % (j, aggregate(*ours[j])) for j in JARS]
    return "\n".join(out) + "\n"


class SetFile(object):
    def __init__(self):
        self.header = {}
        self.classes = []   # (jar, descriptor, stock|None, ours|None)
        self.checks = []    # (jar, descriptor, stock)
        self.entries = []   # (jar, path, stock|None, ours|None)
        self.ours = {}      # {jar: aggregate of the ours jar}


def read_set(path, tag=None):
    """SetFile from path; SetError on any malformed line, a missing or repeated header key, a header that is not this
    normalizer's (or not tag, when given), a duplicate line key, a class or entry line that is `-` on both sides, or
    an ours line missing or repeated for a jar."""
    s = SetFile()
    seen = set()
    with open(path, encoding="utf-8") as f:
        for n, l in enumerate(f, 1):
            l = l.rstrip("\n")
            if not l.strip() or l.startswith("#"):
                continue
            p = l.split()
            where = "%s:%d" % (path, n)
            if p[0] in HEADER_KEYS:
                if len(p) != 2 or p[0] in s.header:
                    raise SetError("%s: bad or repeated header line" % where)
                s.header[p[0]] = p[1]
                continue
            if p[0] == "ours":
                if len(p) != 3 or p[1] not in JARS or not HEX64.match(p[2]) or p[1] in s.ours:
                    raise SetError("%s: bad or repeated ours line" % where)
                s.ours[p[1]] = p[2]
                continue
            if p[0] not in ("class", "check", "entry") or len(p) != (4 if p[0] == "check" else 5):
                raise SetError("%s: unknown line or wrong field count" % where)
            if p[1] not in JARS:
                raise SetError("%s: unknown jar %s" % (where, p[1]))
            if p[0] != "entry" and not DESC.match(p[2]):
                raise SetError("%s: bad class descriptor %s" % (where, p[2]))
            vals = p[3:]
            if any(v != "-" and not HEX64.match(v) for v in vals) or (p[0] == "check" and vals[0] == "-"):
                raise SetError("%s: bad digest" % where)
            if vals == ["-", "-"]:
                raise SetError("%s: absent on both sides" % where)
            key = ("entry" if p[0] == "entry" else "class", p[1], p[2])
            if key in seen:
                raise SetError("%s: %s %s listed twice" % (where, p[1], p[2]))
            seen.add(key)
            vals = [None if v == "-" else v for v in vals]
            if p[0] == "class":
                s.classes.append((p[1], p[2], vals[0], vals[1]))
            elif p[0] == "check":
                s.checks.append((p[1], p[2], vals[0]))
            else:
                s.entries.append((p[1], p[2], vals[0], vals[1]))
    missing = [k for k in HEADER_KEYS if k not in s.header]
    if missing:
        raise SetError("%s: header lacks %s" % (path, ", ".join(missing)))
    if not TAG.match(s.header["tag"]):
        raise SetError("%s: tag %s is not a 4.4 AOSP tag" % (path, s.header["tag"]))
    want = {"model": normalize.MODEL, "normalizer": str(normalize.NORMALIZER_VERSION),
            "smali": normalize.SMALI_VERSION}
    if tag is not None:
        want["tag"] = tag
    for k in HEADER_KEYS:
        if k in want and s.header[k] != want[k]:
            raise SetError("%s: %s %s, expected %s" % (path, k, s.header[k], want[k]))
    missing = [j for j in JARS if j not in s.ours]
    if missing:
        raise SetError("%s: no ours line for %s (regenerate the set with this mkset.py)" % (path, ", ".join(missing)))
    return s


def collect(root, baksmali_jar):
    res = {}
    for j in JARS:
        jar = find_jar(root, j)
        print("mkset: %s" % jar, file=sys.stderr)
        res[j] = (normalize.jar_digests(jar, baksmali_jar), entry_digests(jar))
    return res


def main(argv):
    return rawzip.cli("mkset", _main, argv)


def _main(argv):
    usage = "usage: mkset.py STOCK_DIR OURS_DIR --tag AOSP_TAG --jni FILE [--note TEXT]... [--out FILE]"
    pos, opt, notes = [], {}, []
    while argv:
        a = argv.pop(0)
        if a in ("-h", "--help"):
            print(__doc__)
            return 0
        if a in ("--tag", "--jni", "--out", "--note"):
            if not argv:
                print(usage, file=sys.stderr)
                return 2
            v = argv.pop(0)
            if a == "--note":
                notes.append(v)
            else:
                opt[a] = v
        elif a.startswith("-"):
            print(usage, file=sys.stderr)
            return 2
        else:
            pos.append(a)
    if len(pos) != 2 or "--tag" not in opt or "--jni" not in opt:
        print(usage, file=sys.stderr)
        return 2
    if not TAG.match(opt["--tag"]):
        print("mkset: --tag %s is not a 4.4 AOSP tag (android-4.4.N_rM)" % opt["--tag"], file=sys.stderr)
        return 2
    try:
        jni = read_jni(opt["--jni"])
        for root in pos:
            for j in JARS:
                find_jar(root, j)
        bak = normalize.smali_jars()[0]
        text = make_set(collect(pos[0], bak), collect(pos[1], bak), jni, opt["--tag"], notes)
        if "--out" in opt:
            rawzip.atomic_write(opt["--out"], text)
        else:
            sys.stdout.write(text)
    except (SetError, normalize.NormalizeError, OSError, zipfile.BadZipFile) as e:
        print("mkset: " + str(e), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
