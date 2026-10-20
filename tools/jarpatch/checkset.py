#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""checkset.py: the release build's drift check of the jar patcher's set files against the jars it built.

    python3 -I checkset.py --tag AOSP_TAG [--set FILE] JAR_DIR...

Each JAR_DIR holds core.jar, core-libart.jar, conscrypt.jar and okhttp.jar (directly, or in framework/ or
system/framework/), e.g. a release build output WORK/out/kktls/<tag>/<abi>/. The set file is the one in sets/ whose
header names AOSP_TAG (exactly one must), or --set FILE. Only the "ours" side is checked (the stock side comes from a
stock build made once per tag, see mkset.py):

  class <jar> <desc> <stock> <ours>   ours `-`: the class must be absent; else its normalized digest must equal ours
  check <jar> <desc> <stock>          the class must be present with the stock digest (the series does not change the
                                      classes the donor libjavacrypto.so names; a change must become a class line)
  entry <jar> <path> <stock> <ours>   ours `-`: the entry must be absent; else its sha256 must equal ours
  ours <jar> <sha256>                 the aggregate of the whole built jar (mkset.aggregate: every class and entry,
                                      listed or not) must equal it: a class the series starts to change that the set
                                      does not list fails here, and only here

A difference means the series and the committed set file no longer belong together: the patcher would refuse every
device with this release's donor zips (tool error), or keep the device's stock copy of a class the series now
changes, so the release must not ship. Regenerate the set (mkset.py) from a stock build of the tag and this build's
jars.

Exit 0 every line matches, 1 drift (each differing line listed; for a whole-jar drift also the jar's table, `TABLE`
lines, to compare with the set's source jars), 2 usage or tool error. Stdlib only (Java 8+ and the
jars of fetch-smali.sh, see normalize.py).
"""
import glob
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # `python3 -I` leaves the script dir out
import mkset  # noqa: E402
import normalize  # noqa: E402
import rawzip  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


class CheckError(Exception):
    pass


def set_for_tag(tag, sets_dir=None):
    """Path of the one set file in sets_dir (default sets/) whose header tag is tag."""
    sets_dir = sets_dir or os.path.join(HERE, "sets")
    found = []
    for p in sorted(glob.glob(os.path.join(sets_dir, "*.txt"))):
        with open(p, encoding="utf-8") as f:
            if any(l.split() == ["tag", tag] for l in f):
                found.append(p)
    if len(found) != 1:
        raise CheckError("%d set files in %s name tag %s (%s), want exactly one" %
                         (len(found), sets_dir, tag, ", ".join(os.path.basename(p) for p in found) or "none"))
    return found[0]


def load(path, tag=None):
    try:
        return mkset.read_set(path, tag)
    except (OSError, mkset.SetError) as e:
        raise CheckError("set file: %s" % e)


def compare(st, jars):
    """Differences of jars {jar: ({desc: digest}, {entry: sha256})} against the set: [(jar, what, got, want)]."""
    bad = []
    for j, c, _, ours in st.classes:
        got = jars[j][0].get(c)
        if got != ours:
            bad.append((j, "class " + c, got or "-", ours or "-"))
    for j, c, stock in st.checks:
        got = jars[j][0].get(c)
        if got != stock:
            bad.append((j, "check " + c, got or "-", stock))
    for j, p, _, ours in st.entries:
        got = jars[j][1].get(p)
        if got != ours:
            bad.append((j, "entry " + p, got or "-", ours or "-"))
    for j in mkset.JARS:
        got = mkset.aggregate(*jars[j])
        if got != st.ours[j]:
            bad.append((j, "ours (whole jar)", got, st.ours[j]))
    return bad


def main(argv):
    return rawzip.cli("checkset", _main, argv)


def _main(argv):
    usage = "usage: checkset.py --tag AOSP_TAG [--set FILE] JAR_DIR..."
    opt, dirs = {}, []
    while argv:
        a = argv.pop(0)
        if a in ("-h", "--help"):
            print(__doc__)
            return 0
        if a in ("--tag", "--set") and argv and a not in opt:
            opt[a] = argv.pop(0)
        elif a.startswith("-"):
            print(usage, file=sys.stderr)
            return 2
        else:
            dirs.append(a)
    if "--tag" not in opt or not dirs:
        print(usage, file=sys.stderr)
        return 2
    try:
        path = opt.get("--set") or set_for_tag(opt["--tag"])
        st = load(path, opt["--tag"])
        jar_paths = {d: {j: mkset.find_jar(d, j) for j in mkset.JARS} for d in dirs}
        bak = normalize.smali_jars()[0]
        rc = 0
        for d in dirs:
            jars = {j: (normalize.jar_digests(p, bak), mkset.entry_digests(p)) for j, p in jar_paths[d].items()}
            bad = compare(st, jars)
            for j, what, got, want in bad:
                print("checkset: DRIFT %s %s.jar %s: built %s, set %s" % (d, j, what, got, want))
            for j in sorted({b[0] for b in bad if b[1] == "ours (whole jar)"}):
                # the table the aggregate was made of, to find the class or entry against the set's source jars
                cls, ent = jars[j]
                print("".join("checkset: TABLE %s.jar class %s %s\n" % (j, c, cls[c]) for c in sorted(cls)) +
                      "".join("checkset: TABLE %s.jar entry %s %s\n" % (j, e, ent[e]) for e in sorted(ent)), end="")
            n = len(st.classes) + len(st.checks) + len(st.entries) + len(st.ours)
            print("checkset: %s %s: %d/%d lines of %s match" % ("FAIL" if bad else "ok", d, n - len(bad), n,
                                                               os.path.basename(path)))
            rc = rc or (1 if bad else 0)
    except (CheckError, mkset.SetError, normalize.NormalizeError, OSError, zipfile.BadZipFile) as e:
        print("checkset: error: %s" % e, file=sys.stderr)
        return 2
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
