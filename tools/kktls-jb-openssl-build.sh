#!/usr/bin/env bash
# OpenSSL 1.0.1u (layer A, native libraries) for Android 4.1-4.3 (Jelly Bean): the per-base series of patches/jb/
# on a partial AOSP tree of the base's tag, the stock libraries of the same tree for the ABI check, the release files in
# WORK/out/kktls-jb/<base>/<abi>/. A base with `java` lines in patches/jb/targets.txt also gets its libcore-side release
# files (framework/core.jar, lib/libjavacore.so), built in the same tree against that OpenSSL. The 4.4 release build
# (tools/kktls-release-build.sh) is not involved.
#
#   tools/kktls-jb-openssl-build.sh [options] [all|sync|stock|apply|build|collect|check]...
#   tools/kktls-jb-openssl-build.sh --dry-run [options]   print the selected bases, targets, projects, java files; exit 0
#
# Steps per base (all = every step in this order; each step leaves WORK/<tag>/<step>.done and is skipped next time):
#   sync     repo init --depth=1 + repo sync of the base's `project` lines; every project must then be at its `rev`;
#            the compilers (prebuilts/gcc projects, prebuilts/tools/gcc-sdk/) get their commit's time as mtime
#            (ccache 2.4 hashes the compiler's size and mtime: a checkout's mtime would miss a ccache kept from an
#            earlier tree, as in CI)
#   stock    pristine tree (+ the base's build/ OpenJDK 6 diff): libcrypto libssl (+ the base's java lib/*.so modules)
#            per ABI; the libraries and include/ go to WORK/<tag>/stock-openssl/<abi>/ (the old side of the ABI and
#            export checks); out/target is removed afterwards.
#            WORK/<tag>/stock-openssl.manifest records the inputs (target rows, project revs, this script, the JDK
#            patch) and the sha256 of every file; with --reuse-stock a stock-openssl/ that matches its manifest and this
#            run's inputs is kept and the makes are skipped (else it is removed and built)
#   apply    git am patches/jb/<base>/external_openssl/*.patch in external/openssl and, when the base has one, the
#            libcore series patches/jb/<base>/libcore/*.patch in libcore (both projects must be pristine)
#   build    per ABI: libcrypto libssl openssl (the command-line tool is a test client, not a release file) and the
#            base's java modules; every make runs with WITH_DEXPREOPT=false (jars keep classes.dex, no .odex)
#   collect  lib/libssl.so lib/libcrypto.so and the java files into WORK/out/kktls-jb/<base>/<abi>/ (jars rewritten by
#            tools/zipnorm.py: sorted entries, fixed time) + SHA256SUMS + BUILD-INFO.txt (with the java modules and the
#            gate line of the base); bin/openssl into WORK/out/kktls-jb/<base>/test-bin/<abi>/; external/openssl/NOTICE
#            (+ libcore/NOTICE and external/fdlibm/NOTICE for a java base: libjavacore.so links libfdlibm statically)
#            into .../notice/; patches/jb/<base>/allow-missing-lib{ssl,crypto}.txt (the
#            zip's kktls-symcheck lists) into .../allow/
#   check    per ABI: openssl-abi-check.py symbols against stock-openssl (0 removed public exports; the 4.4 allow
#            list plus patches/jb/<base>/openssl-abi-allow.txt when present), and kktls-symcheck (built for this host
#            with $CC, default cc) with the allow/ lists, as the installer runs it on a device; for a java base every jar
#            carries classes.dex, and every java lib/*.so keeps the stock-tree build's dynamic exports (none removed)
#            and its NEEDED list (identical); for a base with a libcore series, once per base on the patched tree:
#            check_tls_lists.py --base <base> (groups openssl, libcore and libcore.net.http) and check_jni_signatures.py
#            (Java natives vs the JNI table and C functions, with patches/jb/<base>/jni-signature-allow.txt); summary in
#            WORK/out/kktls-jb/checks.tsv
#
# Options:
#   --work DIR        scratch root (default ./kktls-jb-work)
#   --bases "B..."    only these bases (default: every `base` line of patches/jb/targets.txt)
#   --abis "A..."     only these ABIs (armeabi-v7a, x86)
#   --cpus N --jobs N docker --cpus and make -j (default 4 / 4)
#   --image NAME      build image (default: tools/docker-image.sh aosp-build); --sync-image NAME (default aosp-sync)
#   --runner docker|direct   direct = already inside the build image: no docker
#   --reuse-stock     keep a complete stock-openssl/ of the same inputs (e.g. restored from a CI cache), see `stock`
#   --dry-run         validate the targets file of HEAD and print what would be built; nothing is written to --work
# Environment: KKTLS_CCACHE_MAX  ccache -M of WORK/<tag>/ccache (default 10G)
#
# Inputs come from `git archive HEAD` (patches/jb, patches/build, tools) and must be committed (exit 4); a tree is only built further
# while patches/jb at HEAD equals what it was patched with. Exit codes: 0 ok, 1 a failed step or check, 2 usage,
# 3 missing image or tool, 4 uncommitted inputs or a series change since apply.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ME=$(readlink -f "$0"); HERE=$(dirname "$ME"); REPO_ROOT=$(dirname "$HERE")
MIRROR=https://android.googlesource.com/platform/manifest
REPO_REV=v2.69
INPUT_PATHS="patches/jb patches/build tools symcheck"
STEPS_ALL="sync stock apply build collect check"
FILES="lib/libssl.so lib/libcrypto.so"

die() { echo "kktls-jb-openssl-build: $1" >&2; exit "${2:-1}"; }

if [ "${1:-}" = --inner-make ]; then
  # --inner-make TREE LUNCH JOBS LABEL GOALS...   (TREE/{src,ccache,logs}); prints "INNER rc=N wall=S"
  set +euo pipefail
  shift; tree=$1 combo=$2 jobs=$3 label=$4; shift 4
  cd "$tree/src" || exit 1
  source build/envsetup.sh >/dev/null
  lunch "$combo" > "$tree/logs/$label.lunch" 2>&1 || { echo "INNER rc=90 wall=0 (lunch $combo failed)"; exit 0; }
  export ALLOW_OPENJDK=1 USE_CCACHE=1 CCACHE_DIR=$tree/ccache
  prebuilts/misc/linux-x86/ccache/ccache -M "${KKTLS_CCACHE_MAX:-10G}" >/dev/null
  t0=$(date +%s)
  make -j"$jobs" WITH_DEXPREOPT=false "$@" > "$tree/logs/$label.log" 2>&1
  rc=$?
  echo "INNER rc=$rc wall=$(( $(date +%s) - t0 ))"
  exit 0
fi

WORK=./kktls-jb-work; SEL_BASES=""; SEL_ABIS=""; CPUS=4; JOBS=4; IMAGE=""; SYNC_IMAGE=""; RUNNER=docker; REUSE_STOCK=0; DRY=0; CMDS=()
while [ $# -gt 0 ]; do
  case $1 in
    --work) WORK=${2:?}; shift 2 ;;
    --bases) SEL_BASES=${2:?}; shift 2 ;;
    --abis) SEL_ABIS=${2:?}; shift 2 ;;
    --cpus) CPUS=${2:?}; shift 2 ;;
    --jobs) JOBS=${2:?}; shift 2 ;;
    --image) IMAGE=${2:?}; shift 2 ;;
    --sync-image) SYNC_IMAGE=${2:?}; shift 2 ;;
    --runner) RUNNER=${2:?}; shift 2 ;;
    --reuse-stock) REUSE_STOCK=1; shift ;;
    --dry-run) DRY=1; shift ;;
    all|sync|stock|apply|build|collect|check) CMDS+=("$1"); shift ;;
    -h|--help) sed -n '2,51p' "$ME"; exit 0 ;;
    *) die "unknown argument: $1" 2 ;;
  esac
done
[ ${#CMDS[@]} -gt 0 ] || CMDS=(all)
[ "${CMDS[*]}" = all ] && read -r -a CMDS <<< "$STEPS_ALL"
case $RUNNER in docker|direct) ;; *) die "unknown --runner $RUNNER (docker|direct)" 2 ;; esac
WORK=$(readlink -m "$WORK")

# shellcheck disable=SC2086
dirty=$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all -- $INPUT_PATHS | grep -v '/__pycache__/' || true)
[ -z "$dirty" ] || die "uncommitted inputs (the build uses HEAD only):
$dirty" 4
HEAD_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD)
INPUTS=$WORK/inputs
if [ $DRY = 1 ]; then INPUTS=$(mktemp -d); trap 'rm -rf "$INPUTS"' EXIT; else mkdir -p "$WORK"; rm -rf "$INPUTS"; mkdir -p "$INPUTS"; fi
# shellcheck disable=SC2086
git -C "$REPO_ROOT" archive HEAD $INPUT_PATHS | tar -x -C "$INPUTS"
TFILE=$INPUTS/patches/jb/targets.txt
[ -f "$TFILE" ] || die "patches/jb/targets.txt missing at HEAD" 2
kw() { awk -v k="$1" '$1 == k { $1 = ""; sub(/^ +/, ""); print }' "$TFILE"; }
tag_of() { kw base | awk -v b="$1" '$1 == b { print $2 }'; }
projects_of() { kw project | awk -v b="$1" '$1 == b { print $2 }'; }
rev_of() { kw rev | awk -v t="$1" -v p="$2" '$1 == t && $2 == p { print $3 }'; }
rows_of() { kw target | awk -v b="$1" '$1 == b { print $2, $3 }' |
  while read -r l a; do [ -z "$SEL_ABIS" ] || case " $SEL_ABIS " in *" $a "*) ;; *) continue ;; esac; echo "$l $a"; done; }
java_rows() { kw java | awk -v b="$1" '$1 == b { print $2, $3 }'; }        # base -> "module file" lines
java_modules() { java_rows "$1" | awk '{ print $1 }'; }
java_files() { java_rows "$1" | awk '{ print $2 }'; }
java_libs() { java_rows "$1" | awk '$2 ~ /^lib\/[^\/]+\.so$/ { print $2 }'; }  # base -> the java lib/*.so files
gate_of() { kw gate | awk -v b="$1" '$1 == b { $1 = ""; sub(/^ +/, ""); print }'; }
libcore_series() { compgen -G "$INPUTS/patches/jb/$1/libcore/*.patch" > /dev/null; }  # base has a libcore series

BASES=${SEL_BASES:-$(kw base | awk '{print $1}')}
for b in $BASES; do
  t=$(tag_of "$b"); [ -n "$t" ] || die "no base line for $b" 2
  [ -d "$INPUTS/patches/jb/$b/external_openssl" ] || die "no series patches/jb/$b/external_openssl" 2
  [ -n "$(rows_of "$b")" ] || die "no target selected for base $b" 2
  rows_of "$b" | while read -r l a; do
    case "$l:$a" in full-*:armeabi-v7a|aosp_arm-*:armeabi-v7a|full_x86-*:x86|aosp_x86-*:x86) ;;
      *) die "lunch $l does not build ABI $a" 2 ;; esac
  done
  for p in $(projects_of "$b"); do [[ $(rev_of "$t" "$p") =~ ^[0-9a-f]{40}$ ]] || die "no rev line for $t $p" 2; done
  while read -r m f; do
    [ -n "$m" ] || continue
    [[ $f =~ ^(framework/[A-Za-z0-9_.-]+\.jar|lib/[A-Za-z0-9_.+-]+\.so)$ ]] || die "java $b $m: $f is not framework/*.jar or lib/*.so" 2
  done < <(java_rows "$b")
  if [ -n "$(java_rows "$b")" ]; then
    case " $(projects_of "$b" | tr '\n' ' ') " in *" libcore "*) ;; *) die "base $b has java lines but no libcore project" 2 ;; esac
    [ -n "$(gate_of "$b")" ] || die "base $b has java lines but no gate line" 2
    ! libcore_series "$b" || [ -f "$INPUTS/patches/jb/$b/jni-signature-allow.txt" ] ||
      die "base $b has a libcore series but no patches/jb/$b/jni-signature-allow.txt" 2
    for v in $(gate_of "$b"); do
      case $v in "$b"|"$b".[0-9]|"$b".[0-9][0-9]) ;; *) die "gate $b: $v is not an Android $b release" 2 ;; esac
    done
  fi
done

if [ $DRY = 1 ]; then
  echo "head: $HEAD_SHA"; echo "work: $WORK"; echo "runner: $RUNNER cpus/jobs: $CPUS/$JOBS"; echo "steps: ${CMDS[*]}"
  for b in $BASES; do
    echo "base $b ($(tag_of "$b")):"
    rows_of "$b" | sed 's/^/  target /'
    echo "  files: $FILES $(java_files "$b" | tr '\n' ' ')"
    [ -z "$(java_rows "$b")" ] || echo "  java modules: $(java_modules "$b" | tr '\n' ' ')gate: $(gate_of "$b")"
    ! libcore_series "$b" || echo "  libcore series: $(ls "$INPUTS/patches/jb/$b/libcore/"*.patch | wc -l) patches"
    echo "  projects ($(projects_of "$b" | wc -l)): $(projects_of "$b" | tr '\n' ' ')"
  done
  exit 0
fi

if [ $RUNNER = docker ]; then
  if [ -n "$IMAGE" ]; then docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image '$IMAGE' not found" 3
  else IMAGE=$(sh "$REPO_ROOT/tools/docker-image.sh" aosp-build) || die "docker-image.sh aosp-build failed" 3; fi
  case " ${CMDS[*]} " in *" sync "*|*" stock "*|*" apply "*)
    if [ -n "$SYNC_IMAGE" ]; then docker image inspect "$SYNC_IMAGE" >/dev/null 2>&1 || die "image '$SYNC_IMAGE' not found" 3
    else SYNC_IMAGE=$(sh "$REPO_ROOT/tools/docker-image.sh" aosp-sync) || die "docker-image.sh aosp-sync failed" 3; fi ;;
  esac
fi
PY="python3 -I"

run_sync() {
  local tree=$1; shift
  if [ $RUNNER = docker ]; then
    docker run --rm --cpus="$CPUS" -v "$tree:/aosp" -v "$INPUTS:/p:ro" -e TREE=/aosp -e P=/p \
      "$SYNC_IMAGE" bash -ec "cd /aosp/src; $1"
  else
    (cd "$tree/src" && TREE=$tree P=$INPUTS bash -ec "$1")
  fi
}
run_make() {
  local tree=$1 combo=$2 label=$3; shift 3
  local out rc
  if [ $RUNNER = docker ]; then
    out=$(docker run --rm --name "kktls-jb-$(basename "$tree")-$label" --cpus="$CPUS" --ulimit nofile=1024:524288 \
          -e KKTLS_CCACHE_MAX -v "$tree:/aosp" -v "$ME:/scripts/r.sh:ro" "$IMAGE" \
          bash /scripts/r.sh --inner-make /aosp "$combo" "$JOBS" "$label" "$@" | tail -n1)
  else
    out=$(bash "$ME" --inner-make "$tree" "$combo" "$JOBS" "$label" "$@" | tail -n1)
  fi
  echo "  $label: $out"
  rc=$(sed -n 's/.*INNER rc=\([0-9]*\).*/\1/p' <<<"$out")
  if [ "${rc:-1}" != 0 ]; then
    grep -m5 -E 'error:|Error [0-9]|No rule to make' "$tree/logs/$label.log" >&2 || true
    return 1
  fi
}
product_out() {
  case $2 in full-*|aosp_arm-*) echo "$1/src/out/target/product/generic" ;; *) echo "$1/src/out/target/product/generic_x86" ;; esac
}
series_guard() {
  local d=$WORK/$1
  [ -f "$d/series-head.txt" ] || return 0
  git -C "$REPO_ROOT" diff --quiet "$(cat "$d/series-head.txt")" HEAD -- "patches/jb/$2" ||
    die "[$1] the tree was patched at $(cat "$d/series-head.txt"); patches/jb/$2 changed since. Start over: rm -rf $d" 4
}

do_sync() {
  local b=$1 t=$2 d=$WORK/$2 p want have bad=0 got projects
  projects=$(projects_of "$b" | tr '\n' ' ')
  mkdir -p "$d/src" "$d/logs" "$d/ccache"
  run_sync "$d" "[ -d .repo ] || repo init -u $MIRROR -b $t --depth=1 --repo-rev=$REPO_REV </dev/null
    repo sync -c -j8 --no-tags --no-clone-bundle --retry-fetches=3 $projects </dev/null" \
    > "$d/logs/sync.log" 2>&1 || { tail -n 20 "$d/logs/sync.log" >&2; return 1; }
  got=$(run_sync "$d" "for p in $projects; do printf '%s %s\\n' \$p \$(git -C \$p -c core.hooksPath=/dev/null rev-parse -q --verify 'HEAD^{commit}' || echo none); done")
  for p in $projects; do
    want=$(rev_of "$t" "$p"); have=$(awk -v p="$p" '$1 == p { print $2 }' <<<"$got")
    [ "$have" = "$want" ] || { echo "[$t] $p is at ${have:-?}, the targets file pins $want" >&2; bad=1; }
  done
  [ $bad = 0 ] || return 1
  echo "  $(wc -w <<<"$projects") projects at their pinned commits"
  # shellcheck disable=SC2086
  run_sync "$d" "$(pin_mtimes_cmd $projects)" >> "$d/logs/sync.log" 2>&1 ||
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
jdk_patch() { local j=patches/jb/$1/build/0001-allow-openjdk6.patch; [ -f "$INPUTS/$j" ] || j=patches/build/0001-allow-openjdk6.patch; echo "$j"; }
stock_inputs() { # base tag: the manifest header, everything besides the synced tree that the stock libraries depend on
  local b=$1 t=$2 p
  echo "kktls-jb-stock 2 $b $t"
  rows_of "$b" | sed 's/^/target /'
  java_libs "$b" | sed 's/^/java-lib /'
  for p in $(projects_of "$b"); do echo "rev $p $(rev_of "$t" "$p")"; done
  echo "script $(sha_of "$INPUTS/tools/kktls-jb-openssl-build.sh")"
  echo "jdk-patch $(jdk_patch "$b") $(sha_of "$INPUTS/$(jdk_patch "$b")")"
  echo --
}
stock_files() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum); }
# stock_reusable BASE TAG: 0 when stock-openssl/ holds exactly the files of its manifest, each with its sha256, every
# target's libraries and headers, and the manifest was written for this run's inputs
stock_reusable() {
  local b=$1 t=$2 d=$WORK/$2 m=$WORK/$2/stock-openssl.manifest abi f
  [ -f "$m" ] && [ -d "$d/stock-openssl" ] || return 1
  [ "$(sed -n '1,/^--$/p' "$m")" = "$(stock_inputs "$b" "$t")" ] || { echo "  stock-openssl: manifest of other inputs"; return 1; }
  while read -r _ abi; do
    for f in libcrypto.so libssl.so include/openssl/ssl.h $(java_libs "$b" | sed 's#^lib/##'); do
      [ -s "$d/stock-openssl/$abi/$f" ] || { echo "  stock-openssl: $abi/$f missing"; return 1; }
    done
  done < <(rows_of "$b")
  [ "$(sed '1,/^--$/d' "$m")" = "$(stock_files "$d/stock-openssl")" ] || { echo "  stock-openssl: files differ from the manifest"; return 1; }
}

do_stock() {
  local b=$1 t=$2 d=$WORK/$2 combo abi m=$WORK/$2/stock-openssl.manifest
  [ -f "$d/apply.done" ] && die "[$t] stock after apply: the tree is no longer pristine (rm -rf $d)" 1
  local jdk; jdk=$(jdk_patch "$b")
  run_sync "$d" "git -C build -c core.hooksPath=/dev/null apply -R --check \$P/$jdk 2>/dev/null ||
    git -C build -c core.hooksPath=/dev/null apply \$P/$jdk" > "$d/logs/stock-jdk.log" 2>&1 ||
    { cat "$d/logs/stock-jdk.log" >&2; return 1; }
  if [ $REUSE_STOCK = 1 ]; then
    if stock_reusable "$b" "$t"; then
      echo "  stock-openssl: reused ($(sed '1,/^--$/d' "$m" | wc -l) files match $m)"; return 0
    fi
    echo "  stock-openssl: nothing to reuse, building"; rm -rf "$d/stock-openssl"
  fi
  rm -f "$m"
  local jl jm; jl=$(java_libs "$b"); jm=$(java_rows "$b" | awk '$2 ~ /^lib\// { print $1 }')
  while read -r combo abi; do
    # shellcheck disable=SC2086
    run_make "$d" "$combo" "stock-$abi" libcrypto libssl $jm || return 1
    local o=$d/stock-openssl/$abi po f; po=$(product_out "$d" "$combo"); rm -rf "$o"; mkdir -p "$o"
    cp "$po/system/lib/libcrypto.so" "$po/system/lib/libssl.so" "$o/"
    for f in $jl; do cp "$po/system/$f" "$o/" || return 1; done
    cp -r "$d/src/external/openssl/include" "$o/include"
  done < <(rows_of "$b")
  { stock_inputs "$b" "$t"; stock_files "$d/stock-openssl"; } > "$m.new" && mv "$m.new" "$m"
  rm -rf "$d/src/out/target"
}

do_apply() {
  local b=$1 t=$2 d=$WORK/$2
  [ -f "$d/sync.done" ] || die "[$t] apply before sync" 1
  echo "$HEAD_SHA" > "$d/series-head.txt.new"
  run_sync "$d" "g() { git -C external/openssl -c core.hooksPath=/dev/null \"\$@\"; }
    [ -z \"\$(g status --porcelain --untracked-files=normal)\" ] || { echo 'external/openssl has local changes'; exit 3; }
    [ \"\$(g rev-parse HEAD)\" = \"\$(g rev-parse -q --verify refs/remotes/m/$t^{commit})\" ] ||
      { echo 'external/openssl is not at the synced $t revision (series applied before?)'; exit 3; }
    g -c user.name=kktls -c user.email=kktls@localhost am --keep-cr \$P/patches/jb/$b/external_openssl/*.patch
    echo \"external/openssl HEAD \$(g rev-parse --short HEAD), \$(g log --oneline refs/remotes/m/$t..HEAD | wc -l) commits\"" \
    > "$d/logs/apply.log" 2>&1 || { tail -n 20 "$d/logs/apply.log" >&2; return 1; }
  if libcore_series "$b"; then
    run_sync "$d" "g() { git -C libcore -c core.hooksPath=/dev/null \"\$@\"; }
      [ -z \"\$(g status --porcelain --untracked-files=normal)\" ] || { echo 'libcore has local changes'; exit 3; }
      [ \"\$(g rev-parse HEAD)\" = \"\$(g rev-parse -q --verify refs/remotes/m/$t^{commit})\" ] ||
        { echo 'libcore is not at the synced $t revision (series applied before?)'; exit 3; }
      g -c user.name=kktls -c user.email=kktls@localhost am --keep-cr \$P/patches/jb/$b/libcore/*.patch
      echo \"libcore HEAD \$(g rev-parse --short HEAD), \$(g log --oneline refs/remotes/m/$t..HEAD | wc -l) commits\"" \
      >> "$d/logs/apply.log" 2>&1 || { tail -n 20 "$d/logs/apply.log" >&2; return 1; }
  fi
  mv "$d/series-head.txt.new" "$d/series-head.txt"
  grep -E '^(external/openssl|libcore) HEAD ' "$d/logs/apply.log"
}

do_build() {
  local b=$1 t=$2 d=$WORK/$2 combo abi
  [ -f "$d/apply.done" ] || die "[$t] build before apply" 1
  while read -r combo abi; do
    # shellcheck disable=SC2046
    run_make "$d" "$combo" "build-$abi" libcrypto libssl openssl $(java_modules "$b") || return 1
  done < <(rows_of "$b")
}

do_collect() {
  local b=$1 t=$2 d=$WORK/$2 combo abi f
  [ -f "$d/build.done" ] || die "[$t] collect before build" 1
  while read -r combo abi; do
    local po; po=$(product_out "$d" "$combo") o=$WORK/out/kktls-jb/$b/$abi
    rm -rf "$o"; mkdir -p "$o"
    for f in $FILES $(java_files "$b"); do
      [ -f "$po/system/$f" ] || { echo "[$t] $abi: $f missing in $po/system" >&2; return 1; }
      install -D -m 0644 "$po/system/$f" "$o/$f"
      case $f in *.jar) $PY "$INPUTS/tools/zipnorm.py" "$o/$f" > /dev/null || { echo "[$t] $abi: zipnorm $f failed" >&2; return 1; } ;; esac
    done
    install -D -m 0755 "$po/system/bin/openssl" "$WORK/out/kktls-jb/$b/test-bin/$abi/openssl"
    (cd "$o" && find . -type f ! -name SHA256SUMS ! -name BUILD-INFO.txt | sed 's#^\./##' | LC_ALL=C sort |
       xargs sha256sum > SHA256SUMS)
    {
      echo "base $b"; echo "tag $t"; echo "lunch $combo"; echo "abi $abi"
      echo "series $(cat "$d/series-head.txt")"; echo "inputs $HEAD_SHA"
      for p in build external/openssl; do
        echo "base $p $(git -C "$d/src/$p" rev-parse -q --verify "refs/remotes/m/$t^{commit}")"
      done
      if [ -n "$(java_rows "$b")" ]; then
        echo "base libcore $(git -C "$d/src/libcore" rev-parse -q --verify "refs/remotes/m/$t^{commit}")"
        ! libcore_series "$b" || echo "libcore series $(ls "$INPUTS/patches/jb/$b/libcore/"*.patch | wc -l) patches"
        java_rows "$b" | sed 's/^/java /'
        echo "make WITH_DEXPREOPT=false"
        echo "gate $(gate_of "$b")"
      fi
    } > "$o/BUILD-INFO.txt"
    echo "  $b/$abi: $(wc -l < "$o/SHA256SUMS") files"
  done < <(rows_of "$b")
  local nd=$WORK/out/kktls-jb/$b/notice
  rm -rf "$nd"; mkdir -p "$nd"
  install -m 0644 "$d/src/external/openssl/NOTICE" "$nd/openssl.NOTICE"
  if [ -n "$(java_rows "$b")" ]; then
    install -m 0644 "$d/src/libcore/NOTICE" "$nd/libcore.NOTICE"
    install -m 0644 "$d/src/external/fdlibm/NOTICE" "$nd/fdlibm.NOTICE"
  fi
  (cd "$nd" && sha256sum -- *.NOTICE > SHA256SUMS)
  local ad=$WORK/out/kktls-jb/$b/allow l
  rm -rf "$ad"; mkdir -p "$ad"
  [ -f "$INPUTS/patches/jb/$b/allow-missing-libssl.txt" ] || { echo "[$t] patches/jb/$b/allow-missing-libssl.txt missing" >&2; return 1; }
  for l in libssl libcrypto; do
    [ ! -f "$INPUTS/patches/jb/$b/allow-missing-$l.txt" ] || install -m 0644 "$INPUTS/patches/jb/$b/allow-missing-$l.txt" "$ad/"
  done
  (cd "$ad" && sha256sum allow-missing-*.txt > SHA256SUMS)
}

# elf_exports FILE / elf_needed FILE: the defined global/weak dynamic symbols (sorted names) / the NEEDED entries in order
elf_exports() {
  readelf --dyn-syms -W "$1" | awk '$1 ~ /^[0-9]+:$/ && $7 != "UND" && ($5 == "GLOBAL" || $5 == "WEAK") && NF >= 8 { print $8 }' |
    LC_ALL=C sort -u
}
elf_needed() { readelf -d -W "$1" | sed -n 's/.*(NEEDED).*\[\(.*\)\]$/\1/p'; }

# java_check BASE ABI OUT STOCK: every java jar has classes.dex; every java lib/*.so exports at least what the stock-tree
# build of the same module exports and has its NEEDED list; prints the findings, returns 1 on a failure
java_check() {
  local b=$1 abi=$2 o=$3 st=$4 f rc=0 old new removed added
  for f in $(java_files "$b"); do
    case $f in
      *.jar)
        if $PY -c 'import sys, zipfile; sys.exit(0 if "classes.dex" in zipfile.ZipFile(sys.argv[1]).namelist() else 1)' "$o/$f"; then
          echo "$f: classes.dex present"
        else echo "FAIL $f: no classes.dex (dexpreopt?)"; rc=1; fi ;;
      *.so)
        old=$(elf_exports "$st/${f##*/}"); new=$(elf_exports "$o/$f")
        [ -n "$old" ] && [ -n "$new" ] || { echo "FAIL $f: no dynamic exports read (stock $(wc -w <<<"$old"), new $(wc -w <<<"$new"))"; rc=1; continue; }
        removed=$(LC_ALL=C comm -23 <(echo "$old") <(echo "$new")); added=$(LC_ALL=C comm -13 <(echo "$old") <(echo "$new"))
        echo "$f: $(wc -l <<<"$old") stock exports, $(wc -l <<<"$new") new, $(grep -c . <<<"$removed") removed, $(grep -c . <<<"$added") added"
        [ -z "$added" ] || echo "$added" | sed 's/^/  added /'
        [ -z "$removed" ] || { echo "$removed" | sed 's/^/  FAIL removed /'; rc=1; }
        if [ "$(elf_needed "$st/${f##*/}")" = "$(elf_needed "$o/$f")" ]; then
          echo "$f: NEEDED as stock: $(elf_needed "$o/$f" | tr '\n' ' ')"
        else
          echo "FAIL $f: NEEDED differs: stock [$(elf_needed "$st/${f##*/}" | tr '\n' ' ')] new [$(elf_needed "$o/$f" | tr '\n' ' ')]"; rc=1
        fi ;;
    esac
  done
  return $rc
}

do_check() {
  local b=$1 t=$2 d=$WORK/$2 combo abi rc=0
  [ -f "$d/collect.done" ] || die "[$t] check before collect" 1
  local sum=$WORK/out/kktls-jb/checks.tsv allow=$d/abi-allow.txt
  [ -f "$sum" ] || printf 'base\tabi\tcheck\tresult\tlog\n' > "$sum"
  cat "$INPUTS/tools/openssl-abi-allow.txt" > "$allow"
  local sc=$d/kktls-symcheck-host ad=$WORK/out/kktls-jb/$b/allow
  (cd "$ad" && sha256sum -c --quiet SHA256SUMS) || { echo "[$t] allow/ SHA256SUMS mismatch" >&2; rc=1; }
  ${CC:-cc} -O1 -std=gnu99 -o "$sc" "$INPUTS/symcheck/kktls-symcheck.c" > "$d/logs/symcheck-cc.log" 2>&1 ||
    { cat "$d/logs/symcheck-cc.log" >&2; return 1; }
  [ -f "$INPUTS/patches/jb/$b/openssl-abi-allow.txt" ] && cat "$INPUTS/patches/jb/$b/openssl-abi-allow.txt" >> "$allow"
  while read -r combo abi; do
    local o=$WORK/out/kktls-jb/$b/$abi l=$d/logs r=PASS
    (cd "$o" && sha256sum -c --quiet SHA256SUMS) || { echo "[$t] $abi: SHA256SUMS mismatch" >&2; rc=1; }
    READELF=$(command -v readelf) $PY "$INPUTS/tools/openssl-abi-check.py" symbols --old "$d/stock-openssl/$abi" \
      --new "$o/lib" --old-headers "$d/stock-openssl/$abi/include" --allow "$allow" \
      > "$l/abi-symbols-$abi.log" 2>&1 || { r=FAIL; rc=1; }
    printf '%s\t%s\topenssl-abi-symbols\t%s\t%s\n' "$b" "$abi" "$r" "$l/abi-symbols-$abi.log" >> "$sum"
    echo "  $abi openssl-abi-check symbols: $r ($(tail -n1 "$l/abi-symbols-$abi.log"))"
    r=PASS
    local lib args
    for lib in libssl libcrypto; do
      args=(); [ ! -f "$ad/allow-missing-$lib.txt" ] || args=(--allow-missing "$ad/allow-missing-$lib.txt")
      "$sc" ${args[@]+"${args[@]}"} "$o/lib/$lib.so" "$d/stock-openssl/$abi/$lib.so" || r=FAIL
    done > "$l/symcheck-$abi.log" 2>&1
    [ "$r" = PASS ] && echo "libssl, libcrypto: superset (with the allow/ lists)" >> "$l/symcheck-$abi.log" || rc=1
    printf '%s\t%s\tkktls-symcheck\t%s\t%s\n' "$b" "$abi" "$r" "$l/symcheck-$abi.log" >> "$sum"
    echo "  $abi kktls-symcheck: $r ($(tail -n1 "$l/symcheck-$abi.log"))"
    if [ -n "$(java_rows "$b")" ]; then
      r=PASS
      java_check "$b" "$abi" "$o" "$d/stock-openssl/$abi" > "$l/java-$abi.log" 2>&1 || { r=FAIL; rc=1; }
      printf '%s\t%s\tjava-dex-exports\t%s\t%s\n' "$b" "$abi" "$r" "$l/java-$abi.log" >> "$sum"
      echo "  $abi java dex/exports/NEEDED: $r ($(grep -c '^FAIL\|  FAIL' "$l/java-$abi.log") failures)"
    fi
  done < <(rows_of "$b")
  if libcore_series "$b"; then
    # the source checks of the libcore series, once per base on the patched tree (groups openssl, libcore and
    # libcore.net.http: a series must carry the HttpsURLConnection TLSv1 + SCSV fallback, check http-fallback)
    local l=$d/logs r=PASS
    $PY "$INPUTS/tools/check_tls_lists.py" "$d/src" --base "$b" --group openssl --group libcore --group libcore.net.http \
      > "$l/tls-lists.log" 2>&1 || { r=FAIL; rc=1; }
    printf '%s\t%s\tcheck-tls-lists\t%s\t%s\n' "$b" all "$r" "$l/tls-lists.log" >> "$sum"
    echo "  check_tls_lists.py --base $b: $r ($(tail -n1 "$l/tls-lists.log"))"
    r=PASS
    $PY "$INPUTS/tools/check_jni_signatures.py" "$d/src/libcore" --allow "$INPUTS/patches/jb/$b/jni-signature-allow.txt" \
      > "$l/jni-signatures.log" 2>&1 || { r=FAIL; rc=1; }
    printf '%s\t%s\tjni-signatures\t%s\t%s\n' "$b" all "$r" "$l/jni-signatures.log" >> "$sum"
    echo "  check_jni_signatures.py: $r ($(tail -n1 "$l/jni-signatures.log" | cut -c1-120))"
  fi
  return $rc
}

rc=0
for b in $BASES; do
  t=$(tag_of "$b")
  series_guard "$t" "$b"
  for c in "${CMDS[@]}"; do
    d=$WORK/$t
    if [ -f "$d/$c.done" ] && [ "$c" != check ]; then echo "[$t] $c: done before"; continue; fi
    echo "[$t] $c $(date -u +%T)"
    t0=$(date +%s)
    if "do_$c" "$b" "$t"; then
      [ "$c" = check ] || touch "$d/$c.done"
      echo "[$t] $c ok $(( $(date +%s) - t0 ))s"
    else
      echo "[$t] $c FAILED after $(( $(date +%s) - t0 ))s" >&2; rc=1; break
    fi
  done
done
[ -f "$WORK/out/kktls-jb/checks.tsv" ] && column -t -s $'\t' "$WORK/out/kktls-jb/checks.tsv" | sed 's/^/  /'
exit $rc
