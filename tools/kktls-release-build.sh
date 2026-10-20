#!/usr/bin/env bash
# Generic kktls release build: the TLS series on plain AOSP 4.4
# tags, a partial make of the release modules for aosp_<arch>-user, the Conscrypt 2.6-alpha2 stage for layer D, and the
# release files with their sha256 in WORK/out/kktls/<tag>/<abi>/. No device tree: nothing of a vendor BSP is synced or
# built; layer D's makefile and the SSLv3 filter module are copied into the tree as device/kktls/conscrypt/.
#
#   tools/kktls-release-build.sh [options] [all|sync|stock|apply|build|stage|build-d|collect|symcheck|check]...
#   tools/kktls-release-build.sh --dry-run [options]     print the selected targets, projects, modules, files; exit 0
#
# Steps per tag (all = every step in this order; each step leaves WORK/<tag>/<step>.done and is skipped next time):
#   sync     repo init --depth=1 + repo sync of the `project` lines of the targets file (sync image); every project must
#            then be at its `rev` line's commit (a moved tag fails); the repo tool tag is verified by the launcher; the
#            compilers (prebuilts/gcc projects, prebuilts/tools/gcc-sdk/) get their commit's time as mtime (the
#            prebuilt ccache 2.4 hashes the compiler's size and mtime: a checkout's mtime would miss a ccache kept from
#            an earlier tree, as in CI)
#   stock    pristine tree: `make clang`, then libcrypto/libssl (+ libc/libdl/libm/liblog) per ABI; the OpenSSL libraries,
#            include/ and the bionic export list go to WORK/<tag>/stock-openssl/<abi>/ (the old side of the ABI check, the
#            bionic of the Conscrypt .so check); out/target is removed afterwards. WORK/<tag>/stock-openssl.manifest
#            records the inputs (target rows, project revs, this script, the JDK patch, check_prebuilt.py) and the sha256
#            of every file; with --reuse-stock a stock-openssl/ that matches its manifest and this run's inputs is kept
#            and the makes are skipped (else it is removed and built)
#   apply    kktls-apply-series.sh (the committed series, `git archive HEAD`); device/kktls/conscrypt/sslfilter/ (the
#            SSLv3 filter module, built with layer A)
#   build    per ABI: every `module` except the two Conscrypt stage modules (core and conscrypt are needed by `stage`)
#   stage    host: mkstage.py (aar -> dex jar via d8, the armeabi-v7a and x86 .so) into WORK/<tag>/stock/conscrypt/2.6-alpha2/,
#            then check_prebuilt.py --stage (pins, dex, ELF, bionic symbols of both ABIs, NOTICE)
#   build-d  device/kktls/conscrypt/ <- the layer D Android.mk + SHA256SUMS; per ABI: kktls-conscrypt libkktls_conscrypt_jni
#            (the makefile installs the stage byte-identical, sha256-checked)
#   collect  per target: the `file` lines from PRODUCT_OUT/system into WORK/out/kktls/<tag>/<abi>/ (the AOSP-built jars
#            rewritten by tools/zipnorm.py: sorted entries, fixed time, so two builds give identical jars) + SHA256SUMS + BUILD-INFO.txt;
#            per tag: the OpenSSL, libcore, okhttp and bionic libc licence texts into WORK/out/kktls/<tag>/notice/ (+ SHA256SUMS)
#   symcheck device/kktls/symcheck/ <- release/symcheck/{Android.mk,kktls-symcheck.c,kktls-util.c}; per ABI
#            `make kktls-symcheck kktls-util` (static binaries, the recovery zips' symbol, label and zip-entry helpers)
#            into WORK/out/kktls/<tag>/helpers/<abi>/, with
#            allow-missing-libssl.txt and SHA256SUMS (helpers/ is not a release file dir: nothing of it goes to /system)
#   check    per target: check_artifacts.py --layer release, openssl-abi-check.py symbols against stock-openssl (0 removed
#            public exports), kktls-symcheck of our libssl/libcrypto against stock-openssl (SKIP when this host cannot
#            run the helper's ABI), jarpatch/checkset.py: the built core, core-libart, conscrypt and okhttp jars
#            against the "ours" column of the jar patcher's committed set file of the tag (a drift fails: the patcher
#            of this release would not accept its own donor zips); summary in WORK/out/kktls/checks.tsv
#
# Options:
#   --work DIR        scratch root (default ./kktls-release-work)
#   --targets FILE    default tools/targets.txt from HEAD (see "Inputs"); another file
#                     is for trials only (it is not checked for being committed)
#   --tags "T..."     only these tags (each must have a target line; default: all tags of the file)
#   --abis "A..."     only these ABIs (armeabi-v7a, x86; each must have a target line)
#   --cpus N --jobs N docker --cpus and make -j (default 4 / 4: a GitHub standard runner)
#   --image NAME      build image (default: tools/docker-image.sh aosp-build = kktls-aosp-build);
#                     --sync-image NAME (default: the same script's aosp-sync = kktls-aosp-sync)
#   --runner docker|direct   direct = already inside the build image (CI container, docker/Dockerfile.build): no
#                     docker; repo, make, python3, d8 and the checks run here
#   --aar FILE        Conscrypt 2.6-alpha2 aar (default: downloaded from Maven Central into WORK/dl/, sha256-pinned)
#   --d8 FILE --dexdump FILE  Android build-tools 37.0.0 (default $D8/$DEXDUMP, else $ANDROID_HOME/build-tools/37.0.0/)
#   --reuse-stock     keep a complete stock-openssl/ of the same inputs (e.g. restored from a CI cache), see `stock`
# Environment: KKTLS_CCACHE_MAX  ccache -M of WORK/<tag>/ccache (default 30G)
#   KKTLS_JAVA   Java 8+ for smali/baksmali in the check step (default: the build image's Java 17 runtime
#                /opt/kktls/jre17/bin/java, else `java` on PATH; Java 6 does not do)
#   KKTLS_CACHE  where jarpatch/fetch-smali.sh keeps the pinned smali/baksmali jars (default WORK/dl/smali)
#
# Inputs: everything from this repository comes from `git archive HEAD` into WORK/inputs/ (the series, the layer D
# files, the checkers, the targets file); the inputs must be committed (exit 4 if any is modified or untracked), and a
# tree is only built further while the series paths at HEAD equal those it was patched with (WORK/<tag>/series-head.txt).
# Synced sources are untrusted: with --runner docker they run only in the containers (repo/git in the sync image).
# Exit codes: 0 ok, 1 a failed step or check, 2 usage / unknown tag, ABI or target, 3 missing image or tool,
# 4 uncommitted inputs or a series change since apply.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ME=$(readlink -f "$0"); HERE=$(dirname "$ME"); REPO_ROOT=$(dirname "$HERE")
MIRROR=https://android.googlesource.com/platform/manifest
REPO_REV=v2.69   # the repo tool tag (signed; checked by the launcher)
AAR_URL=https://repo1.maven.org/maven2/org/conscrypt/conscrypt-android/2.6-alpha2/conscrypt-android-2.6-alpha2.aar
STAGE_MODULES="kktls-conscrypt libkktls_conscrypt_jni"
# paths of this repository the release depends on; SERIES_PATHS = what `apply` puts into the tree
SERIES_PATHS="tools/kktls-apply-series.sh patches/build/0001-allow-openjdk6.patch
patches/external_openssl patches/libcore patches/external_okhttp
conscrypt/sslfilter"
INPUT_PATHS="tools/kktls-release-build.sh tools tools/targets.txt
symcheck docker conscrypt $SERIES_PATHS"
STEPS_ALL="sync stock apply build stage build-d collect symcheck check"
SYMCHECK=symcheck
HELPERS="kktls-symcheck kktls-util"
# licence texts of the AOSP projects the release files and the static helpers (bionic libc) come from (tree path -> name in out/kktls/<tag>/notice/)
NOTICES="external/openssl/NOTICE:openssl.NOTICE libcore/NOTICE:libcore.NOTICE external/okhttp/LICENSE.txt:okhttp.LICENSE
bionic/libc/NOTICE:bionic-libc.NOTICE"

die() { echo "kktls-release-build: $1" >&2; exit "${2:-1}"; }

# ---------------------------------------------------------------- inside the build image
if [ "${1:-}" = --inner-make ]; then
  # --inner-make TREE LUNCH JOBS LABEL GOALS...   (TREE/{src,ccache,logs}); prints "INNER rc=N wall=S"
  set +euo pipefail   # envsetup.sh/lunch are not -u/-e clean
  shift; tree=$1 combo=$2 jobs=$3 label=$4; shift 4
  cd "$tree/src" || exit 1
  source build/envsetup.sh >/dev/null
  lunch "$combo" > "$tree/logs/$label.lunch" 2>&1 || { echo "INNER rc=90 wall=0 (lunch $combo failed)"; exit 0; }
  export ALLOW_OPENJDK=1 USE_CCACHE=1 CCACHE_DIR=$tree/ccache
  prebuilts/misc/linux-x86/ccache/ccache -M "${KKTLS_CCACHE_MAX:-30G}" >/dev/null
  t0=$(date +%s)
  make -j"$jobs" WITH_DEXPREOPT=false "$@" > "$tree/logs/$label.log" 2>&1
  rc=$?
  echo "INNER rc=$rc wall=$(( $(date +%s) - t0 ))"
  exit 0
fi
. "$HERE/lib/retry.sh" || die "tools/lib/retry.sh missing" 3   # retry (the sync step)

# ---------------------------------------------------------------- options
WORK=./kktls-release-work; TARGETS=""; SEL_TAGS=""; SEL_ABIS=""; CPUS=4; JOBS=4; IMAGE=""; SYNC_IMAGE=""
RUNNER=docker; AAR=""; REUSE_STOCK=0; D8=${D8:-${ANDROID_HOME:-$HOME/Android/sdk}/build-tools/37.0.0/d8}; DEXDUMP=${DEXDUMP:-}; DRY=0; CMDS=()
while [ $# -gt 0 ]; do
  case $1 in
    --work) WORK=${2:?}; shift 2 ;;
    --targets) TARGETS=${2:?}; shift 2 ;;
    --tags) SEL_TAGS=${2:?}; shift 2 ;;
    --abis) SEL_ABIS=${2:?}; shift 2 ;;
    --cpus) CPUS=${2:?}; shift 2 ;;
    --jobs) JOBS=${2:?}; shift 2 ;;
    --image) IMAGE=${2:?}; shift 2 ;;
    --sync-image) SYNC_IMAGE=${2:?}; shift 2 ;;
    --runner) RUNNER=${2:?}; shift 2 ;;
    --aar) AAR=${2:?}; shift 2 ;;
    --d8) D8=${2:?}; shift 2 ;;
    --dexdump) DEXDUMP=${2:?}; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --reuse-stock) REUSE_STOCK=1; shift ;;
    all|sync|stock|apply|build|stage|build-d|collect|symcheck|check) CMDS+=("$1"); shift ;;
    -h|--help) sed -n '2,66p' "$ME"; exit 0 ;;
    *) die "unknown argument: $1" 2 ;;
  esac
done
[ ${#CMDS[@]} -gt 0 ] || CMDS=(all)
[ "${CMDS[*]}" = all ] && read -r -a CMDS <<< "$STEPS_ALL"
case $RUNNER in docker|direct) ;; *) die "unknown --runner $RUNNER (docker|direct)" 2 ;; esac
[ -n "$DEXDUMP" ] || DEXDUMP=$(dirname "$D8")/dexdump
WORK=$(readlink -m "$WORK")

# ---------------------------------------------------------------- inputs (committed only)
dirty=$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all -- $INPUT_PATHS |
        grep -v '/__pycache__/' || true)
[ -z "$dirty" ] || die "uncommitted inputs (the release builds only from HEAD):
$dirty" 4
HEAD_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD)
INPUTS=$WORK/inputs
if [ $DRY = 1 ]; then INPUTS=$(mktemp -d); trap 'rm -rf "$INPUTS"' EXIT; else mkdir -p "$WORK"; rm -rf "$INPUTS"; mkdir -p "$INPUTS"; fi
# shellcheck disable=SC2086
git -C "$REPO_ROOT" archive HEAD $INPUT_PATHS | tar -x -C "$INPUTS"
if [ -n "$TARGETS" ]; then
  [ -f "$TARGETS" ] || die "targets file $TARGETS not found" 2
  TFILE=$TARGETS
else
  TFILE=$INPUTS/tools/targets.txt
fi
[ -f "$TFILE" ] || die "targets file missing at HEAD: $TFILE" 2

kw() { awk -v k="$1" '$1 == k { $1 = ""; sub(/^ +/, ""); print }' "$TFILE"; }
PROJECTS=$(kw project); MODULES=$(kw module); FILES=$(kw file); REVS=$(kw rev)
mapfile -t ALL_TARGETS < <(kw target)
[ ${#ALL_TARGETS[@]} -gt 0 ] && [ -n "$PROJECTS" ] && [ -n "$MODULES" ] && [ -n "$FILES" ] ||
  die "targets file $TFILE needs target, project, module and file lines" 2
for tl in "${ALL_TARGETS[@]}"; do
  read -r t l a x <<< "$tl"
  [ -n "$a" ] && [ -z "${x:-}" ] || die "bad target line: $tl" 2
  case $t in android-4.4.2_r2|android-4.4.4_r2) ;; *) die "unknown tag $t in $TFILE (kktls-apply-series.sh knows android-4.4.2_r2, android-4.4.4_r2)" 2 ;; esac
  case "$l:$a" in aosp_arm-*:armeabi-v7a|aosp_x86-*:x86) ;; *) die "lunch $l does not build ABI $a" 2 ;; esac
done
# selection: every selected tag and ABI must name at least one target line
TARGET_ROWS=()
for tl in "${ALL_TARGETS[@]}"; do
  read -r t l a <<< "$tl"
  [ -z "$SEL_TAGS" ] || case " $SEL_TAGS " in *" $t "*) ;; *) continue ;; esac
  [ -z "$SEL_ABIS" ] || case " $SEL_ABIS " in *" $a "*) ;; *) continue ;; esac
  TARGET_ROWS+=("$t $l $a")
done
for t in $SEL_TAGS; do printf '%s\n' "${TARGET_ROWS[@]}" | grep -q "^$t " || die "no target for tag $t in $TFILE" 2; done
for a in $SEL_ABIS; do printf '%s\n' "${TARGET_ROWS[@]}" | grep -q " $a\$" || die "no target for ABI $a in $TFILE" 2; done
[ ${#TARGET_ROWS[@]} -gt 0 ] || die "no target selected" 2
rev_of() { awk -v t="$1" -v p="$2" '$1 == t && $2 == p { print $3 }' <<<"$REVS"; }   # tag path -> pinned commit
for tl in "${TARGET_ROWS[@]}"; do
  read -r t _ <<< "$tl"
  for p in $PROJECTS; do
    [[ $(rev_of "$t" "$p") =~ ^[0-9a-f]{40}$ ]] || die "no rev line (40-hex commit) for $t $p in $TFILE" 2
  done
done
TAGS=$(printf '%s\n' "${TARGET_ROWS[@]}" | awk '!s[$1]++ {print $1}')
rows_of() { printf '%s\n' "${TARGET_ROWS[@]}" | awk -v t="$1" '$1 == t {print $2, $3}'; }   # tag -> "lunch abi" lines

if [ $DRY = 1 ]; then
  echo "head: $HEAD_SHA"; echo "work: $WORK"; echo "runner: $RUNNER cpus/jobs: $CPUS/$JOBS"; echo "steps: ${CMDS[*]}"
  echo "targets (${#TARGET_ROWS[@]}):"; printf '  %s\n' "${TARGET_ROWS[@]}"
  echo "modules: $(echo $MODULES)"; echo "files ($(echo $FILES | wc -w)): $(echo $FILES)"
  echo "projects ($(echo $PROJECTS | wc -w)): $(echo $PROJECTS)"
  exit 0
fi

# ---------------------------------------------------------------- tools and images
for f in "$D8" "$DEXDUMP"; do [ -x "$f" ] || die "missing tool $f (--d8/--dexdump)" 3; done
command -v readelf >/dev/null && command -v strip >/dev/null || die "missing tool readelf or strip (GNU binutils)" 3
if [ $RUNNER = docker ]; then
  if [ -n "$IMAGE" ]; then docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image '$IMAGE' not found" 3
  else IMAGE=$(sh "$REPO_ROOT/tools/docker-image.sh" aosp-build) || die "docker-image.sh aosp-build failed" 3; fi
  if [ -n "$SYNC_IMAGE" ]; then docker image inspect "$SYNC_IMAGE" >/dev/null 2>&1 || die "image '$SYNC_IMAGE' not found" 3
  else SYNC_IMAGE=$(sh "$REPO_ROOT/tools/docker-image.sh" aosp-sync) || die "docker-image.sh aosp-sync failed" 3; fi
else
  need="git make python3"; case " ${CMDS[*]} " in *" sync "*) need="repo $need" ;; esac
  for c in $need; do command -v $c >/dev/null || die "--runner direct: $c not found" 3; done
fi
# a Java 8+ binary for smali/baksmali (the check step's set check): $KKTLS_JAVA, the image's Java 17 runtime (kept off
# PATH: the 4.4 build needs Java 6 there), or java on PATH
jp_java() {
  local j v a b
  for j in ${KKTLS_JAVA:-} /opt/kktls/jre17/bin/java java; do
    command -v "$j" > /dev/null 2>&1 || continue
    v=$("$j" -version 2>&1 | sed -n 's/.* version "\([0-9][0-9.]*\).*/\1/p' | head -n 1)
    IFS=. read -r a b _ <<< "$v.0"
    [ "$a" != 1 ] || a=$b   # 1.6, 1.8: the second number
    if [ -n "$a" ] && [ "$a" -ge 8 ] 2> /dev/null; then command -v "$j"; return 0; fi
  done
  return 1
}
JP_JAVA=''
case " ${CMDS[*]} " in
  *" check "*) JP_JAVA=$(jp_java) ||
    die "missing Java 8+ for the jar patcher's set check (KKTLS_JAVA, /opt/kktls/jre17/bin/java or java on PATH)" 3 ;;
esac
PY="python3 -I"
CONS=$INPUTS/conscrypt
TOOLS=$INPUTS/tools

# run_sync TREE CMD: a shell command in TREE/src with the sync tools (sync image or here), under `bash -e` (a failing
# line fails the step); CMD names the tree as $TREE and the extracted inputs as $P (escaped: expanded by that shell)
run_sync() {
  local tree=$1; shift
  if [ $RUNNER = docker ]; then
    docker run --rm --cpus="$CPUS" -v "$tree:/aosp" -v "$INPUTS:/p:ro" -e TREE=/aosp -e P=/p \
      "$SYNC_IMAGE" bash -ec "cd /aosp/src; $1"
  else
    (cd "$tree/src" && TREE=$tree P=$INPUTS bash -ec "$1")
  fi
}
# run_make TREE LUNCH LABEL GOALS...: one make in the build image (log TREE/logs/LABEL.log); returns make's rc
run_make() {
  local tree=$1 combo=$2 label=$3; shift 3
  local out
  if [ $RUNNER = docker ]; then
    out=$(docker run --rm --name "kktls-rel-$(basename "$tree")-$label" --cpus="$CPUS" --ulimit nofile=1024:524288 \
          -e KKTLS_CCACHE_MAX -v "$tree:/aosp" -v "$ME:/scripts/r.sh:ro" "$IMAGE" \
          bash /scripts/r.sh --inner-make /aosp "$combo" "$JOBS" "$label" "$@" | tail -n1)
  else
    out=$(bash "$ME" --inner-make "$tree" "$combo" "$JOBS" "$label" "$@" | tail -n1)
  fi
  echo "  $label: $out"
  local rc
  rc=$(sed -n 's/.*INNER rc=\([0-9]*\).*/\1/p' <<<"$out")
  if [ "${rc:-1}" != 0 ]; then
    grep -m5 -E 'error:|Error [0-9]|No rule to make' "$tree/logs/$label.log" >&2 || true
    return 1
  fi
}

series_guard() { # tag: the tree must have been patched with the series of HEAD
  local d=$WORK/$1
  [ -f "$d/series-head.txt" ] || return 0
  local applied; applied=$(cat "$d/series-head.txt")
  # shellcheck disable=SC2086
  git -C "$REPO_ROOT" diff --quiet "$applied" HEAD -- $SERIES_PATHS ||
    die "[$1] the tree was patched at $applied; the series changed since (git diff $applied HEAD). Start over: rm -rf $d" 4
}

# ---------------------------------------------------------------- steps
do_sync() {
  local t=$1 d=$WORK/$1
  mkdir -p "$d/src" "$d/logs" "$d/ccache"
  echo "[$t] sync"
  # up to 3 tries with backoff (tools/lib/retry.sh: googlesource answers HTTP 503 at times); a later try runs repo
  # init again only while the tree has no manifest (an init that failed half-way), repo sync resumes
  # shellcheck disable=SC2086
  retry 3 run_sync "$d" "[ -f .repo/manifest.xml ] || repo init -u $MIRROR -b $t --depth=1 --repo-rev=$REPO_REV </dev/null
    repo sync -c -j8 --no-tags --no-clone-bundle --retry-fetches=3 $(echo $PROJECTS) </dev/null" \
    > "$d/logs/sync.log" 2>&1 || { tail -n 20 "$d/logs/sync.log" >&2; return 1; }
  # every project at its pinned commit (git runs where the synced trees may be touched: the sync image or here)
  local got bad=0 p want have
  got=$(run_sync "$d" "for p in $(echo $PROJECTS); do printf '%s %s\\n' \$p \$(git -C \$p -c core.hooksPath=/dev/null rev-parse -q --verify 'HEAD^{commit}' || echo none); done") ||
    { echo "[$t] reading the synced revisions failed" >&2; return 1; }
  for p in $PROJECTS; do
    want=$(rev_of "$t" "$p"); have=$(awk -v p="$p" '$1 == p { print $2 }' <<<"$got")
    [ "$have" = "$want" ] || { echo "[$t] $p is at ${have:-?}, the targets file pins $want" >&2; bad=1; }
  done
  [ $bad = 0 ] || return 1
  echo "  $(wc -w <<<"$PROJECTS") projects at their pinned commits"
  # shellcheck disable=SC2086
  run_sync "$d" "$(pin_mtimes_cmd $PROJECTS)" >> "$d/logs/sync.log" 2>&1 ||
    { echo "[$t] setting the toolchain mtimes failed" >&2; tail -n 5 "$d/logs/sync.log" >&2; return 1; }
}

# pin_mtimes_cmd PROJECT...: the run_sync command that sets every file of the compilers (the prebuilts/gcc projects,
# prebuilts/tools/gcc-sdk/: the host gcc wrappers) to its project's commit time (ccache 2.4 hashes the compiler's size
# and mtime; a new toolchain commit still changes the hash)
pin_mtimes_cmd() {
  local p dir
  for p in "$@"; do
    case $p in prebuilts/gcc/*) dir=$p ;; prebuilts/tools) dir=$p/gcc-sdk ;; *) continue ;; esac
    printf '[ ! -d %s ] || find %s -name .git -prune -o -type f -exec touch -d @$(git -C %s -c core.hooksPath=/dev/null log -1 --format=%%ct HEAD) {} +\n' \
      "$dir" "$dir" "$p"
  done
  echo true
}

sha_of() { sha256sum < "$1" | cut -c1-64; }
stock_inputs() { # tag: the MANIFEST header, everything besides the synced tree that the stock libraries depend on
  local t=$1 p
  echo "kktls-stock 1 $t"
  rows_of "$t" | sed 's/^/target /'
  for p in $PROJECTS; do echo "rev $p $(rev_of "$t" "$p")"; done
  echo "script $(sha_of "$INPUTS/tools/kktls-release-build.sh")"
  echo "jdk-patch $(sha_of "$INPUTS/patches/build/0001-allow-openjdk6.patch")"
  echo "check_prebuilt $(sha_of "$CONS/check_prebuilt.py")"
  echo --
}
stock_files() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum); }
# stock_reusable TAG: 0 when stock-openssl/ holds exactly the files of its manifest, each with its sha256, every
# target's libraries, bionic exports and headers, and the manifest was written for this run's inputs
stock_reusable() {
  local t=$1 d=$WORK/$1 m=$WORK/$1/stock-openssl.manifest abi f
  [ -f "$m" ] && [ -d "$d/stock-openssl" ] || return 1
  [ "$(sed -n '1,/^--$/p' "$m")" = "$(stock_inputs "$t")" ] || { echo "  stock-openssl: manifest of other inputs"; return 1; }
  while read -r _ abi; do
    for f in libcrypto.so libssl.so bionic-exports.txt include/openssl/ssl.h; do
      [ -s "$d/stock-openssl/$abi/$f" ] || { echo "  stock-openssl: $abi/$f missing"; return 1; }
    done
  done < <(rows_of "$t")
  [ "$(sed '1,/^--$/d' "$m")" = "$(stock_files "$d/stock-openssl")" ] || { echo "  stock-openssl: files differ from the manifest"; return 1; }
}

do_stock() {
  local t=$1 d=$WORK/$1 combo abi m=$WORK/$1/stock-openssl.manifest
  [ -f "$d/apply.done" ] && die "[$t] stock after apply: the tree is no longer pristine (rm -rf $d to start over)" 1
  # the 4.4 build insists on Oracle JDK 6; the build image has OpenJDK 6 (the series' plain build/ diff, kept by apply)
  run_sync "$d" "git -C build -c core.hooksPath=/dev/null apply -R --check \$P/patches/build/0001-allow-openjdk6.patch 2>/dev/null ||
    git -C build -c core.hooksPath=/dev/null apply \$P/patches/build/0001-allow-openjdk6.patch" > "$d/logs/stock-jdk.log" 2>&1 ||
    { cat "$d/logs/stock-jdk.log" >&2; return 1; }
  if [ $REUSE_STOCK = 1 ]; then
    if stock_reusable "$t"; then
      echo "  stock-openssl: reused ($(sed '1,/^--$/d' "$m" | wc -l) files match $m)"; return 0
    fi
    echo "  stock-openssl: nothing to reuse, building"; rm -rf "$d/stock-openssl"
  fi
  rm -f "$m"
  run_make "$d" "$(rows_of "$t" | head -n1 | cut -d' ' -f1)" stock-clang clang || return 1
  while read -r combo abi; do
    run_make "$d" "$combo" "stock-$abi" libcrypto libssl libc libdl libm liblog || return 1
    local o=$d/stock-openssl/$abi po; po=$(product_out "$d" "$combo"); rm -rf "$o"; mkdir -p "$o"
    cp "$po/system/lib/libcrypto.so" "$po/system/lib/libssl.so" "$o/"
    cp -r "$d/src/external/openssl/include" "$o/include"
    # the exports of this tag's bionic for the ABI (the series does not touch bionic): the Conscrypt .so check uses them
    $PY "$CONS/check_prebuilt.py" --bionic-exports "$po/system/lib" > "$o/bionic-exports.txt" || return 1
  done < <(rows_of "$t")
  { stock_inputs "$t"; stock_files "$d/stock-openssl"; } > "$m.new" && mv "$m.new" "$m"
  rm -rf "$d/src/out/target"   # the release modules are built from scratch on the patched tree (host tools stay)
}

do_apply() {
  local t=$1 d=$WORK/$1
  [ -f "$d/sync.done" ] || die "[$t] apply before sync" 1
  echo "$HEAD_SHA" > "$d/series-head.txt.new"
  run_sync "$d" "bash \$P/tools/kktls-apply-series.sh $t \$TREE/src \$P
    rm -rf device/kktls && mkdir -p device/kktls/conscrypt
    cp -r \$P/conscrypt/sslfilter device/kktls/conscrypt/" > "$d/logs/apply.log" 2>&1 ||
    { tail -n 20 "$d/logs/apply.log" >&2; return 1; }
  mv "$d/series-head.txt.new" "$d/series-head.txt"
  tail -n 4 "$d/logs/apply.log"
}

a_modules() { local m; for m in $MODULES; do case " $STAGE_MODULES " in *" $m "*) ;; *) printf '%s ' "$m" ;; esac; done; }

do_build() {
  local t=$1 d=$WORK/$1 combo abi
  [ -f "$d/apply.done" ] || die "[$t] build before apply" 1
  run_make "$d" "$(rows_of "$t" | head -n1 | cut -d' ' -f1)" clang clang || return 1
  while read -r combo abi; do
    # shellcheck disable=SC2046
    run_make "$d" "$combo" "build-$abi" $(a_modules) || return 1
  done < <(rows_of "$t")
}

get_aar() {
  if [ -n "$AAR" ]; then [ -f "$AAR" ] || die "--aar $AAR not found" 3; echo "$AAR"; return; fi
  local f=$WORK/dl/conscrypt-android-2.6-alpha2.aar
  if [ ! -f "$f" ]; then
    mkdir -p "$WORK/dl"
    curl -fsSL --retry 3 -o "$f.part" "$AAR_URL" || die "download of $AAR_URL failed" 3
    mv "$f.part" "$f"
  fi
  echo "$f"   # mkstage.py checks it against the 2.6-alpha2 pin
}

do_stage() {
  local t=$1 d=$WORK/$1
  [ -f "$d/build.done" ] || die "[$t] stage before build" 1
  local aar; aar=$(get_aar)
  local st=$d/stock/conscrypt/2.6-alpha2
  rm -rf "$st"
  $PY "$CONS/mkstage.py" "$aar" "$st" --java-libs "$d/src/out/target/common/obj/JAVA_LIBRARIES" --d8 "$D8" \
    --sums "$CONS/SHA256SUMS" > "$d/logs/stage.log" 2>&1 || { cat "$d/logs/stage.log" >&2; return 1; }
  local bargs=()
  [ -f "$d/stock-openssl/armeabi-v7a/bionic-exports.txt" ] && bargs+=(--bionic "$d/stock-openssl/armeabi-v7a/bionic-exports.txt")
  [ -f "$d/stock-openssl/x86/bionic-exports.txt" ] && bargs+=(--bionic-x86 "$d/stock-openssl/x86/bionic-exports.txt")
  $PY "$CONS/check_prebuilt.py" --stage "$st" --sums "$CONS/SHA256SUMS" --notice "$CONS/NOTICE" "${bargs[@]}" \
    > "$d/logs/stage-check.log" 2>&1 || { tail -n 20 "$d/logs/stage-check.log" >&2; return 1; }
  tail -n1 "$d/logs/stage-check.log"
  # informational: do the export lists in git equal this tag's bionic (the check above used this tag's own lists)
  for lib in armeabi-v7a:bionic44-exports.txt x86:bionic44-exports-x86.txt; do
    local abi=${lib%%:*} want=$CONS/${lib#*:}
    [ -f "$d/stock-openssl/$abi/bionic-exports.txt" ] || continue
    if diff -q <(grep -v '^#' "$want") <(grep -v '^#' "$d/stock-openssl/$abi/bionic-exports.txt") >/dev/null; then
      echo "  bionic exports $abi = $(basename "$want")"
    else
      echo "  bionic exports $abi differ from $(basename "$want") (+ this tag, - git): $(diff <(grep -v '^#' "$want") \
        <(grep -v '^#' "$d/stock-openssl/$abi/bionic-exports.txt") | grep -c '^[<>]') lines"
    fi
  done
}

do_build-d() {
  local t=$1 d=$WORK/$1 combo abi
  [ -f "$d/stage.done" ] || die "[$t] build-d before stage" 1
  # the layer D makefile (it includes sslfilter/ below it) and the pins its copy recipe checks, from HEAD
  cp "$CONS/Android.mk" "$CONS/SHA256SUMS" "$d/src/device/kktls/conscrypt/"
  while read -r combo abi; do
    # shellcheck disable=SC2086
    run_make "$d" "$combo" "build-d-$abi" $STAGE_MODULES || return 1
  done < <(rows_of "$t")
}

product_out() { # tree combo -> PRODUCT_OUT on the host
  case $2 in aosp_arm-*) echo "$1/src/out/target/product/generic" ;; aosp_x86-*) echo "$1/src/out/target/product/generic_x86" ;; esac
}

do_collect() {
  local t=$1 d=$WORK/$1 combo abi f
  [ -f "$d/build-d.done" ] || die "[$t] collect before build-d" 1
  while read -r combo abi; do
    local po; po=$(product_out "$d" "$combo") o=$WORK/out/kktls/$t/$abi
    rm -rf "$o"; mkdir -p "$o"
    for f in $FILES; do
      [ -f "$po/system/$f" ] || { echo "[$t] $abi: $f missing in $po/system" >&2; return 1; }
      install -D -m 0644 "$po/system/$f" "$o/$f"
      # AOSP-built jars carry the build time (entry times, extended-timestamp extras): sorted entries, fixed time,
      # compressed data copied raw. Not kktls-conscrypt.jar: the d8 stage, already normal and pinned in $CONS/SHA256SUMS
      case $f in
        framework/kktls-conscrypt.jar) ;;
        *.jar) $PY "$TOOLS/zipnorm.py" "$o/$f" > /dev/null || { echo "[$t] $abi: zipnorm $f failed" >&2; return 1; } ;;
      esac
    done
    (cd "$o" && find . -type f ! -name SHA256SUMS ! -name BUILD-INFO.txt | sed 's#^\./##' | LC_ALL=C sort |
       xargs sha256sum > SHA256SUMS)
    {
      echo "tag $t"; echo "lunch $combo"; echo "abi $abi"; echo "make WITH_DEXPREOPT=false"
      echo "series $(cat "$d/series-head.txt")"; echo "inputs $HEAD_SHA"
      for p in build external/openssl libcore external/okhttp; do
        echo "base $p $(git -C "$d/src/$p" rev-parse -q --verify "refs/remotes/m/$t^{commit}")"
      done
      echo "conscrypt-aar $(sha256sum "$(get_aar)" | cut -d' ' -f1)"
      echo "d8 $("$D8" --version 2>/dev/null | head -n1)"
    } > "$o/BUILD-INFO.txt"
    echo "  $t/$abi: $(wc -l < "$o/SHA256SUMS") files"
  done < <(rows_of "$t")
  local nd=$WORK/out/kktls/$t/notice e
  rm -rf "$nd"; mkdir -p "$nd"
  for e in $NOTICES; do
    [ -f "$d/src/${e%%:*}" ] || { echo "[$t] ${e%%:*} missing" >&2; return 1; }
    install -m 0644 "$d/src/${e%%:*}" "$nd/${e#*:}"
  done
  (cd "$nd" && find . -type f ! -name SHA256SUMS | sed 's#^\./##' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
}

do_symcheck() {
  local t=$1 d=$WORK/$1 combo abi
  [ -f "$d/collect.done" ] || die "[$t] symcheck before collect" 1
  local h=$WORK/out/kktls/$t/helpers
  rm -rf "$d/src/device/kktls/symcheck" "$h"; mkdir -p "$d/src/device/kktls/symcheck" "$h"
  cp "$INPUTS/$SYMCHECK/Android.mk" "$INPUTS/$SYMCHECK/kktls-symcheck.c" "$INPUTS/$SYMCHECK/kktls-util.c" \
    "$d/src/device/kktls/symcheck/"
  cp "$INPUTS/$SYMCHECK/allow-missing-libssl.txt" "$h/"
  while read -r combo abi; do
    # shellcheck disable=SC2086
    run_make "$d" "$combo" "symcheck-$abi" $HELPERS || return 1
    local m want n; case $abi in armeabi-v7a) want=ARM ;; x86) want="Intel 80386" ;; esac
    for n in $HELPERS; do
      local b; b=$(product_out "$d" "$combo")/system/bin/$n
      [ -f "$b" ] || { echo "[$t] $abi: $b missing" >&2; return 1; }
      m=$(LC_ALL=C readelf -h "$b" | awk -F: '/Machine:/ {gsub(/^ +/, "", $2); print $2}')
      [ "$m" = "$want" ] || { echo "[$t] $abi: $n machine '$m', want '$want'" >&2; return 1; }
      ! LC_ALL=C readelf -lW "$b" | grep -qE 'INTERP|DYNAMIC' || { echo "[$t] $abi: $n is not static" >&2; return 1; }
      install -D -m 0755 "$b" "$h/$abi/$n"
      # the x86 binary leaves the AOSP build with its symbol table (ARM is stripped): halve it with the host strip
      # (GNU binutils knows elf32-i386; the synced prebuilt toolchain is not run on the host)
      if LC_ALL=C readelf -SW "$h/$abi/$n" | grep -q '\.symtab'; then
        strip --strip-all "$h/$abi/$n" || { echo "[$t] $abi: strip $n failed" >&2; return 1; }
      fi
    done
  done < <(rows_of "$t")
  (cd "$h" && find . -type f ! -name SHA256SUMS | sed 's#^\./##' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
  sed 's/^/  /' "$h/SHA256SUMS"
}

do_check() {
  local t=$1 d=$WORK/$1 combo abi rc=0
  [ -f "$d/collect.done" ] || die "[$t] check before collect" 1
  [ -f "$d/symcheck.done" ] || die "[$t] check before symcheck" 1
  local sum=$WORK/out/kktls/checks.tsv
  [ -f "$sum" ] || printf 'tag\tabi\tcheck\tresult\tlog\n' > "$sum"
  while read -r combo abi; do
    local o=$WORK/out/kktls/$t/$abi l=$d/logs
    (cd "$o" && sha256sum -c --quiet SHA256SUMS) || { echo "[$t] $abi: SHA256SUMS mismatch" >&2; rc=1; }
    local r=PASS
    $PY "$TOOLS/check_artifacts.py" "$o" --layer release --abi "$abi" --dexdump "$DEXDUMP" --sums "$CONS/SHA256SUMS" \
      > "$l/check-artifacts-$abi.log" 2>&1 || { r=FAIL; rc=1; }
    printf '%s\t%s\tcheck_artifacts\t%s\t%s\n' "$t" "$abi" "$r" "$l/check-artifacts-$abi.log" >> "$sum"
    echo "  $abi check_artifacts: $r ($(tail -n1 "$l/check-artifacts-$abi.log"))"
    r=PASS
    READELF=$(command -v readelf) $PY "$TOOLS/openssl-abi-check.py" symbols --old "$d/stock-openssl/$abi" \
      --new "$o/lib" --old-headers "$d/stock-openssl/$abi/include" --allow "$TOOLS/openssl-abi-allow.txt" \
      > "$l/abi-symbols-$abi.log" 2>&1 || { r=FAIL; rc=1; }
    printf '%s\t%s\topenssl-abi-symbols\t%s\t%s\n' "$t" "$abi" "$r" "$l/abi-symbols-$abi.log" >> "$sum"
    echo "  $abi openssl-abi-check symbols: $r ($(tail -n1 "$l/abi-symbols-$abi.log"))"
    # the helper itself on the real libraries; exit 2 without arguments proves it runs here (ARM: qemu-user binfmt)
    local h=$WORK/out/kktls/$t/helpers sc=$WORK/out/kktls/$t/helpers/$abi/kktls-symcheck n=0
    (cd "$h" && sha256sum -c --quiet SHA256SUMS) || { echo "[$t] helpers SHA256SUMS mismatch" >&2; rc=1; }
    "$sc" > /dev/null 2>&1 || n=$?
    if [ "$n" != 2 ]; then
      r=SKIP; echo "cannot run $sc on this host (rc $n)" > "$l/symcheck-$abi.log"
    else
      r=PASS
      { "$sc" --allow-missing "$h/allow-missing-libssl.txt" "$o/lib/libssl.so" "$d/stock-openssl/$abi/libssl.so" &&
        "$sc" "$o/lib/libcrypto.so" "$d/stock-openssl/$abi/libcrypto.so" && echo "libssl, libcrypto: superset"; } \
        > "$l/symcheck-$abi.log" 2>&1 || { r=FAIL; rc=1; }
    fi
    printf '%s\t%s\tkktls-symcheck\t%s\t%s\n' "$t" "$abi" "$r" "$l/symcheck-$abi.log" >> "$sum"
    echo "  $abi kktls-symcheck: $r ($(tail -n1 "$l/symcheck-$abi.log"))"
    # the jar patcher's set file of this tag (the ours column) against the jars just built
    r=PASS
    KKTLS_JAVA=$JP_JAVA KKTLS_CACHE=${KKTLS_CACHE:-$WORK/dl/smali} $PY "$TOOLS/jarpatch/checkset.py" --tag "$t" "$o" \
      > "$l/jarpatch-set-$abi.log" 2>&1 || { r=FAIL; rc=1; }
    printf '%s\t%s\tjarpatch-set\t%s\t%s\n' "$t" "$abi" "$r" "$l/jarpatch-set-$abi.log" >> "$sum"
    echo "  $abi jarpatch-set: $r ($(tail -n1 "$l/jarpatch-set-$abi.log"))"
  done < <(rows_of "$t")
  return $rc
}

rc=0
for t in $TAGS; do
  series_guard "$t"
  for c in "${CMDS[@]}"; do
    d=$WORK/$t
    if [ -f "$d/$c.done" ] && [ "$c" != check ]; then echo "[$t] $c: done before"; continue; fi
    echo "[$t] $c $(date -u +%T)"
    t0=$(date +%s)
    if "do_$c" "$t"; then
      [ "$c" = check ] || touch "$d/$c.done"
      echo "[$t] $c ok $(( $(date +%s) - t0 ))s"
    else
      echo "[$t] $c FAILED after $(( $(date +%s) - t0 ))s" >&2; rc=1; break
    fi
  done
done
[ -f "$WORK/out/kktls/checks.tsv" ] && column -t -s $'\t' "$WORK/out/kktls/checks.tsv" | sed 's/^/  /'
exit $rc
