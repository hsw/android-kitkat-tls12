#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""check_44_payload.py: the Android 4.4 recovery zips install the same /system files as a released baseline.

    python3 -I tools/check_44_payload.py ZIPDIR [--baseline FILE]   compare (exit 0 = same, apart from ALLOWED)
    python3 -I tools/check_44_payload.py ZIPDIR --write              print a baseline of ZIPDIR
    python3 -I tools/check_44_payload.py --selftest

Every kktls-*.zip of ZIPDIR except the Jelly Bean ones (names with -4.1-, -4.2-, -4.3-) is read: its release name from
kktls/zip.conf, and the sha256 of each system/ entry. The baseline (default tools/fixtures/v4-44-payload.sha256, made
with --write from the published v4 zips) has one line per file: "<sha256>  <zip name without -<release>.zip>/<entry>".
A zip or file missing on either side, or another sha256, fails; only the files in ALLOWED may differ (they are listed
as "allowed"). Installer scripts, notices and BUILD-INFO are not compared: they name the release and the build.

ALLOWED: framework/core.jar and core-libart.jar of the java-4.4.x zips (the default SSLSocketFactory hook in libcore,
patch 0025: the NEON guard, 2026-10-18). Every other 4.4 file must stay byte-identical. Stdlib only.
"""
import hashlib
import io
import os
import re
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BASELINE = os.path.join(HERE, "fixtures", "v4-44-payload.sha256")
JB = re.compile(r"-4\.[0-3]-")
ALLOWED = {
    (re.compile(r"kktls-java-4\.4\.[0-9]+-(armeabi-v7a|x86)$"), "system/framework/core.jar"),
    (re.compile(r"kktls-java-4\.4\.[0-9]+-(armeabi-v7a|x86)$"), "system/framework/core-libart.jar"),
}


def allowed(zipkey, entry):
    return any(z.match(zipkey) and entry == e for z, e in ALLOWED)


def payload(zipdir):
    """{"<zip key>/<entry>": sha256} of the system/ entries of every 4.4 zip in zipdir."""
    out = {}
    for name in sorted(os.listdir(zipdir)):
        if not (name.startswith("kktls-") and name.endswith(".zip")) or JB.search(name):
            continue
        with zipfile.ZipFile(os.path.join(zipdir, name)) as z:
            conf = z.read("kktls/zip.conf").decode()
            rel = [l[len("release="):] for l in conf.splitlines() if l.startswith("release=")]
            if len(rel) != 1 or not name.endswith("-%s.zip" % rel[0]):
                raise ValueError("%s: release %s in kktls/zip.conf does not end the name" % (name, rel))
            key = name[:-len("-%s.zip" % rel[0])]
            out[key + "/"] = ""  # the zip itself (a zip without system/ entries, e.g. restore, still counts)
            for e in z.namelist():
                if e.startswith("system/") and not e.endswith("/"):
                    out["%s/%s" % (key, e)] = hashlib.sha256(z.read(e)).hexdigest()
    return out


def read_baseline(path):
    base = {}
    with open(path) as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            h, k = line.split(None, 1)
            base[k.strip()] = "" if h == "-" else h
    return base


def compare(base, cur, log=print):
    bad = 0
    for k in sorted(set(base) | set(cur)):
        zipkey, _, entry = k.partition("/")
        if k not in cur:
            log("FAIL missing %s" % k)
            bad += 1
        elif k not in base:
            log("FAIL new     %s" % k)
            bad += 1
        elif base[k] != cur[k]:
            if allowed(zipkey, entry):
                log("allowed      %s (%s -> %s)" % (k, base[k][:12], cur[k][:12]))
            else:
                log("FAIL differs %s (%s -> %s)" % (k, base[k][:12], cur[k][:12]))
                bad += 1
    zips = len([k for k in cur if k.endswith("/")])
    files = len(cur) - zips
    log("%s: %d 4.4 zips, %d system files, %d failures" % ("PASS" if not bad else "FAIL", zips, files, bad))
    return bad == 0


def write(cur, out=sys.stdout):
    out.write("# sha256  <zip without -<release>.zip>/<system/ entry> (\"-\" = the zip itself), tools/check_44_payload.py\n")
    for k in sorted(cur):
        out.write("%s  %s\n" % (cur[k] or "-", k))


def selftest():
    td = tempfile.mkdtemp(prefix="check-44-payload-")
    ok = True

    def mk(d, rel, files):
        os.makedirs(d, exist_ok=True)
        for zname, entries in files.items():
            with zipfile.ZipFile(os.path.join(d, "%s-%s.zip" % (zname, rel)), "w") as z:
                z.writestr("kktls/zip.conf", "kind=x\nrelease=%s\n" % rel)
                z.writestr("NOTICE", "notice of %s" % rel)
                for e, data in entries.items():
                    z.writestr(e, data)

    v4 = {"kktls-java-4.4.2-x86": {"system/framework/core.jar": "a", "system/framework/okhttp.jar": "b"},
          "kktls-conscrypt-x86": {"system/lib/libkktls_conscrypt_jni.so": "c"}, "kktls-restore": {},
          "kktls-java-4.3-x86": {"system/framework/core.jar": "jb"}}
    try:
        mk(os.path.join(td, "v4"), "v4", v4)
        buf = io.StringIO()
        write(payload(os.path.join(td, "v4")), buf)
        bpath = os.path.join(td, "base.sha256")
        with open(bpath, "w") as f:
            f.write(buf.getvalue())
        base = read_baseline(bpath)
        cases = []

        def case(label, files, want):
            d = os.path.join(td, label.replace(" ", "_"))
            mk(d, "v5", files)
            got = compare(base, payload(d), log=lambda s: None)
            cases.append((label, got == want))

        case("same files, other release", v4, True)
        case("allowed core.jar change", dict(v4, **{"kktls-java-4.4.2-x86": {"system/framework/core.jar": "A",
                                                                           "system/framework/okhttp.jar": "b"}}), True)
        case("JB zip change ignored", dict(v4, **{"kktls-java-4.3-x86": {"system/framework/core.jar": "JB"}}), True)
        case("okhttp.jar change", dict(v4, **{"kktls-java-4.4.2-x86": {"system/framework/core.jar": "a",
                                                                     "system/framework/okhttp.jar": "B"}}), False)
        case("conscrypt .so change", dict(v4, **{"kktls-conscrypt-x86": {"system/lib/libkktls_conscrypt_jni.so": "C"}}), False)
        case("a file less", dict(v4, **{"kktls-conscrypt-x86": {}}), False)
        case("a file more", dict(v4, **{"kktls-restore": {"system/x": "x"}}), False)
        case("a zip less", {k: v for k, v in v4.items() if k != "kktls-restore"}, False)
        case("a zip more", dict(v4, **{"kktls-openssl-4.4-x86": {}}), False)
        for label, good in cases:
            print("selftest %s %s" % ("ok  " if good else "FAIL", label))
            ok &= good
    finally:
        for root, dirs, files in os.walk(td, topdown=False):
            for n in files:
                os.remove(os.path.join(root, n))
            for n in dirs:
                os.rmdir(os.path.join(root, n))
        os.rmdir(td)
    print("SELFTEST %s (%d cases)" % ("PASS" if ok else "FAIL", len(cases)))
    return ok


def main(argv):
    args = argv[1:]
    if args == ["--selftest"]:
        return 0 if selftest() else 1
    baseline, do_write = DEFAULT_BASELINE, False
    if "--write" in args:
        args.remove("--write")
        do_write = True
    if "--baseline" in args:
        i = args.index("--baseline")
        baseline = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1 or not os.path.isdir(args[0]):
        sys.stderr.write("usage: check_44_payload.py ZIPDIR [--baseline FILE] | ZIPDIR --write | --selftest\n")
        return 2
    try:
        cur = payload(args[0])
    except (ValueError, KeyError, zipfile.BadZipFile) as e:
        sys.stderr.write("check_44_payload.py: %s\n" % e)
        return 1
    if do_write:
        write(cur)
        return 0
    return 0 if compare(read_baseline(baseline), cur) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
