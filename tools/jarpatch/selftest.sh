#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# selftest.sh: the jar patcher end to end on fixture systems, one run of kktls-jarpatch.py per mutation, each with its
# expected exit code and reason. No AOSP binaries: every jar is assembled here from the smali sources in
# tests/fixtures/ (smali 2.5.2 of fetch-smali.sh), the set file is made by mkset.py, the release dir holds a donor java
# zip (the fixture's series jars and this repository's installer) and the openssl and conscrypt zips --accept-oem
# copies, listed in SHA256SUMS.
#
#   tools/jarpatch/selftest.sh [-v]        -v prints each run's output
#
# Fixtures (tests/fixtures/, `<side>/<jar>/smali/` class sources and `<side>/<jar>/res/` other jar entries; core-libart
# is built from the core sources):
#   stock/        the AOSP jars the series is applied to: core, conscrypt, okhttp
#   ours/         the same jars with the series (the donor): a changed class calling the boot class path, an added kktls
#                 class, a removed class, a changed and an added conscrypt class, a changed okhttp class, a changed
#                 security.properties
#   ext/          the device's ext.jar on the boot class path (java.lang.Object and a helper the series calls)
#   vendor/       the vendor's own class, added to every device jar
#   device/       the device's build of a stock class with other debug info (line numbers, source name)
#   mut/<name>/   the overlays of the mutations below (a whole jar when the device has none of that name)
#   jni-classes.txt  the fixture's class names of the donor libjavacrypto.so (the set's check lines)
# Device = stock + vendor + device overlays, build.prop of 4.4.4 armeabi-v7a, BOOTCLASSPATH core:conscrypt:okhttp:ext.
#
# Cases (expected exit, text in the output):
#   unchanged      0  the java-patched zip is written (zip.conf kind=java-patched), report "result staged"
#   body           1  a changed method body of a class the series replaces: vendor-modified
#   const          1  a changed constant in a check class (named by libjavacrypto.so): vendor-modified
#   missing        1  a class the series changes is not on the device: missing
#   member         1  an extra method in a class the series replaces: vendor-modified
#   stripped       1  core.jar without classes.dex next to core.odex: odexed without classes.dex
#   release        1  ro.build.version.release 4.3: not a 4.4 release
#   release44      1  ro.build.version.release 4.4 (android-4.4_r1): refused, 4.4.1 or later only
#   line           2  a 4.4.2 device with only the 4.4.4 donor in the release dir: no java zip of its line (tool error)
#   dangling       1  a vendor framework jar calls a class the series removes: link check
#   already        1  a kktls class already in core.jar: restore first
#   natives        1  a vendor class in conscrypt.jar declares a native method (the donor libjavacrypto.so lacks it)
#   oem            1  an OEM/CM build.prop marker (ro.cm.version) without --accept-oem: rerun with --accept-oem
#   oem-accepted   0  the same with --accept-oem: java-patched and the two device-bound oem zips are written
# Every refused run must leave no zip. The cases run in parallel. Exit 0 all pass, 1 a case failed, 2 a missing tool.
set -euo pipefail
export LC_ALL=C
HERE=$(cd "$(dirname "$0")" && pwd)
FX=$HERE/tests/fixtures
INST=$HERE/../../installer
VERBOSE=0
case ${1:-} in -v) VERBOSE=1 ;; '') ;; *) echo "usage: selftest.sh [-v]" >&2; exit 2 ;; esac
JAVA=${KKTLS_JAVA:-java}
for c in "$JAVA" python3 unzip; do command -v "$c" > /dev/null || { echo "selftest: $c not found" >&2; exit 2; }; done
[ -f "$INST/checks.sh" ] || { echo "selftest: $INST/checks.sh missing" >&2; exit 2; }
mapfile -t SM < <(bash "$HERE/fetch-smali.sh") || true
[ ${#SM[@]} = 2 ] && [ -f "${SM[1]}" ] || { echo "selftest: fetch-smali.sh failed" >&2; exit 2; }
SMALI=${SM[1]}
T=$(mktemp -d "${TMPDIR:-/tmp}/kktls-jarpatch-selftest.XXXXXX"); trap 'rm -rf "$T"' EXIT
REL=v0 TAG=android-4.4.4_r2 ABI=armeabi-v7a
# the smali API level and the set's jars are the patcher's own (normalize.BAKSMALI_API, mkset.JARS)
read -r API JARS < <(python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); import mkset, normalize
print(normalize.BAKSMALI_API, " ".join(mkset.JARS))' "$HERE") || true
[ -n "${JARS:-}" ] || { echo "selftest: cannot read normalize.BAKSMALI_API and mkset.JARS" >&2; exit 2; }
BCP=/system/framework/core.jar:/system/framework/conscrypt.jar:/system/framework/okhttp.jar:/system/framework/ext.jar

# mkjar OUT.jar SRC_JAR LAYER... : the smali/ and res/ trees of LAYER/SRC_JAR (or LAYER itself when it has smali/
# directly), later layers over earlier ones, assembled into OUT.jar (classes.dex + res files + a manifest)
mkjar() {
  local out=$1 sj=$2 w l d; shift 2
  w=$(mktemp -d "$T/src.XXXXXX"); mkdir -p "$w/smali" "$w/res"
  for l in "$@"; do
    d=$l/$sj; [ -d "$d" ] || d=$l
    [ ! -d "$d/smali" ] || cp -r "$d/smali/." "$w/smali/"
    [ ! -d "$d/res" ] || cp -r "$d/res/." "$w/res/"
  done
  "$JAVA" -jar "$SMALI" a -a "$API" -o "$w/classes.dex" "$w/smali" > "$w/log" 2>&1 && [ -f "$w/classes.dex" ] ||
    { echo "selftest: smali of $out failed:"; cat "$w/log"; return 1; } >&2
  mkdir -p "$(dirname "$out")"
  python3 -I - "$out" "$w" <<'EOF'
import os, sys, zipfile
out, w = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    z.write(os.path.join(w, "classes.dex"), "classes.dex")
    res = os.path.join(w, "res")
    for root, dirs, files in sorted(os.walk(res)):
        for f in sorted(files):
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, res))
EOF
  rm -rf "$w"
}
src_jar() { case $1 in core-libart) echo core ;; *) echo "$1" ;; esac; }

# ---- stock, ours, the device's base system, the set file, the release dir
pids=()
for j in $JARS; do
  mkjar "$T/stock/framework/$j.jar" "$(src_jar "$j")" "$FX/stock" & pids+=($!)
  mkjar "$T/ours/framework/$j.jar" "$(src_jar "$j")" "$FX/ours" & pids+=($!)
done
mkjar "$T/ext.jar" - "$FX/ext" & pids+=($!)
for p in "${pids[@]}"; do wait "$p"; done
python3 -I "$HERE/mkset.py" "$T/stock" "$T/ours" --tag "$TAG" --jni "$FX/jni-classes.txt" --out "$T/set.txt" \
  2> "$T/mkset.log" || { cat "$T/mkset.log"; echo "selftest: mkset.py failed" >&2; exit 1; }

python3 -I - "$T/release" "$T/ours/framework" "$INST" "$REL" "$ABI" "$TAG" <<'EOF'
import hashlib, os, sys, zipfile
rel, ours, inst, name, abi, tag = sys.argv[1:7]
os.makedirs(rel)
def mk(zname, conf, payload):
    with zipfile.ZipFile(os.path.join(rel, zname), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/com/google/android/update-binary", open(os.path.join(inst, "update-binary"), "rb").read())
        for f in ("checks.sh", "install.sh"):
            z.writestr("kktls/" + f, open(os.path.join(inst, f), "rb").read())
        z.writestr("kktls/zip.conf", "".join("%s=%s\n" % kv for kv in conf))
        z.writestr("NOTICE", "selftest fixture\n")
        for n, data in payload:
            z.writestr(n, data)
    return zname
zips = [mk("kktls-java-4.4.4-%s-%s.zip" % (abi, name),
           [("kind", "java"), ("release", name), ("abi", abi), ("android", "4.4.4"), ("tag", tag)],
           [("system/framework/%s.jar" % j, open(os.path.join(ours, j + ".jar"), "rb").read())
            for j in ("core", "core-libart", "conscrypt", "okhttp")] +
           [("system/lib/libjavacrypto.so", b"\x7fELF selftest placeholder")]),
        mk("kktls-openssl-4.4-%s-%s.zip" % (abi, name),
           [("kind", "openssl"), ("release", name), ("abi", abi), ("android", "4.4"), ("tag", tag)],
           [("system/lib/libssl.so", b"\x7fELF selftest placeholder")]),
        mk("kktls-conscrypt-%s-%s.zip" % (abi, name),
           [("kind", "conscrypt"), ("release", name), ("abi", abi), ("android", "4.4"), ("tag", tag)],
           [("system/framework/kktls-conscrypt.jar", b"PK selftest placeholder")])]
with open(os.path.join(rel, "SHA256SUMS"), "w") as f:
    for z in zips:
        f.write("%s  %s\n" % (hashlib.sha256(open(os.path.join(rel, z), "rb").read()).hexdigest(), z))
EOF

# device DIR [OVERLAY...]: the device's /system in DIR/system (stock + vendor + device overlay + OVERLAYs)
device() {
  local d=$1/system j ps=() rc=0; shift
  mkdir -p "$d/framework" "$d/lib" "$d/app"
  for j in $JARS; do mkjar "$d/framework/$j.jar" "$(src_jar "$j")" "$FX/stock" "$FX/vendor" "$FX/device" "$@" & ps+=($!); done
  cp "$T/ext.jar" "$d/framework/ext.jar"
  printf '%s\n' '# selftest' ro.build.version.release=4.4.4 ro.product.cpu.abi=$ABI \
    ro.build.fingerprint=selftest/fixture/fixture:4.4.4/SELFTEST/1:user/test-keys > "$d/build.prop"
  for j in "${ps[@]}"; do wait "$j" || rc=1; done   # every jar job, not only the last one, decides
  return $rc
}
setprop() { sed -i "s|^$2=.*|$2=$3|" "$1/system/build.prop"; }

# ---- the cases: NAME EXIT TEXT (setup in case_setup, extra patcher arguments in case_args)
CASES=(
  "unchanged|0|/out/kktls-java-patched-4.4.4-$ABI-$REL-"
  "body|1|REFUSED core Ljavax/net/ssl/DefaultHostnameVerifier;: differs from stock $TAG (vendor change)"
  "const|1|REFUSED core Ljava/lang/Integer;: differs from stock $TAG (vendor change)"
  "missing|1|REFUSED conscrypt Lcom/android/org/conscrypt/NativeCrypto;: stock $TAG has it, the device does not"
  "member|1|REFUSED okhttp Lcom/android/okhttp/internal/Platform;: differs from stock $TAG (vendor change)"
  "stripped|1|REFUSED core -: odexed without classes.dex"
  "release|1|REFUSED - ro.build.version.release: Android 4.3: only 4.4.1 to 4.4.4 are supported"
  "release44|1|REFUSED - ro.build.version.release: Android 4.4 (android-4.4_r1/r1.2) lacks upstream"
  "line|2|no kktls-java-4.4.2-$ABI-<release>.zip"
  "dangling|1|REFUSED /system/framework/vendor.jar Lcom/example/Gone;: link check: resolved before the patch, not after"
  "already|1|the system already carries kktls: restore it first"
  "natives|1|REFUSED conscrypt Lcom/vendor/NativeHelper;: declares 1 native method(s)"
  "oem|1|OEM/CM build: rerun with --accept-oem"
  "oem-accepted|0|/out/kktls-openssl-oem-4.4-$ABI-$REL-"
)
case_setup() { # NAME DIR
  local n=$1 d=$2
  case $n in
    body|const|member|already|natives) device "$d" "$FX/mut/$n" ;;
    missing) device "$d"   # then conscrypt.jar again, without NativeCrypto
      local w; w=$(mktemp -d "$T/miss.XXXXXX"); cp -r "$FX/stock/conscrypt" "$w/conscrypt"
      rm "$w/conscrypt/smali/com/android/org/conscrypt/NativeCrypto.smali"
      mkjar "$d/system/framework/conscrypt.jar" conscrypt "$w" "$FX/vendor" ;;
    stripped) device "$d"
      python3 -I - "$d/system/framework/core.jar" <<'EOF'
import os, sys, zipfile
p = sys.argv[1]
with zipfile.ZipFile(p) as z:
    keep = [(i, z.read(i)) for i in z.infolist() if i.filename != "classes.dex"]
with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
    for i, data in keep:
        z.writestr(i, data)
EOF
      echo "odex placeholder" > "$d/system/framework/core.odex" ;;
    release) device "$d"; setprop "$d" ro.build.version.release 4.3 ;;
    release44) device "$d"; setprop "$d" ro.build.version.release 4.4 ;;
    line) device "$d"; setprop "$d" ro.build.version.release 4.4.2 ;;
    dangling) device "$d"; mkjar "$d/system/framework/vendor.jar" - "$FX/mut/dangling/vendor" ;;
    oem|oem-accepted) device "$d"; echo ro.cm.version=11-selftest >> "$d/system/build.prop" ;;
    *) device "$d" ;;
  esac
}
case_args() { case $1 in oem-accepted) echo --accept-oem ;; esac; }

run_case() { # NAME EXIT TEXT -> $T/case/NAME/{result,out.log}
  local n=$1 want=$2 text=$3 d=$T/case/$1 rc=0 why=''
  mkdir -p "$d"
  case_setup "$n" "$d/dev" > "$d/setup.log" 2>&1 || { echo "FAIL setup" > "$d/result"; return 0; }
  # shellcheck disable=SC2046
  python3 -I "$HERE/kktls-jarpatch.py" --system "$d/dev" --bootclasspath "$BCP" --build-prop "$d/dev/system/build.prop" \
    --release-dir "$T/release" --out "$d/out" --set "$T/set.txt" --report "$d/report.txt" $(case_args "$n") \
    > "$d/out.log" 2>&1 || rc=$?
  [ "$rc" = "$want" ] || why="exit $rc, want $want"
  grep -qF -- "$text" "$d/out.log" || why="${why:+$why; }no '$text'"
  local zips; zips=$(find "$d/out" -maxdepth 1 -name '*.zip' -printf '%f ' 2> /dev/null) || true
  if [ "$want" = 0 ]; then
    grep -qx 'result staged' "$d/report.txt" 2> /dev/null || why="${why:+$why; }report lacks 'result staged'"
    z=$(cd "$d/out" && ls kktls-java-patched-*.zip 2> /dev/null) || true
    [ -n "$z" ] && unzip -p "$d/out/$z" kktls/zip.conf | grep -qx kind=java-patched ||
      why="${why:+$why; }no java-patched zip"
    if [ "$n" = oem-accepted ]; then
      for k in openssl-oem-4.4 conscrypt-oem; do
        z=$(cd "$d/out" && ls "kktls-$k-$ABI-$REL"-*.zip 2> /dev/null) || true
        [ -n "$z" ] && unzip -p "$d/out/$z" kktls/zip.conf | grep -q '^oem_ack=[0-9a-f]\{64\}$' ||
          why="${why:+$why; }no kktls-$k zip with oem_ack"
      done
    fi
  elif [ -n "$zips" ]; then
    why="${why:+$why; }refused but wrote $zips"
  fi
  if [ -z "$why" ]; then echo ok > "$d/result"; else echo "FAIL $why" > "$d/result"; fi
}

pids=()
for c in "${CASES[@]}"; do
  IFS='|' read -r n want text <<< "$c"
  run_case "$n" "$want" "$text" & pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done
fail=0
for c in "${CASES[@]}"; do
  IFS='|' read -r n want text <<< "$c"
  r=$(cat "$T/case/$n/result" 2> /dev/null || echo "FAIL no result")
  if [ "$r" = ok ]; then printf 'ok   %-13s exit %s: %s\n' "$n" "$want" "$text"; else
    printf 'FAIL %-13s %s\n' "$n" "${r#FAIL }"; fail=1
    [ "$VERBOSE" = 1 ] || { sed 's/^/       /' "$T/case/$n/setup.log" "$T/case/$n/out.log" | tail -n 20; }
  fi
  [ "$VERBOSE" = 0 ] || sed 's/^/       /' "$T/case/$n/out.log"
done
echo "selftest: $([ $fail = 0 ] && echo PASS || echo FAIL) (${#CASES[@]} cases)"
exit $fail
