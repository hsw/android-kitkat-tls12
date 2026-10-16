#!/usr/bin/env bash
# OpenSSL 1.0.1u (layer A, native libraries only) for Android 4.1-4.3 (Jelly Bean): the per-base series of patches/jb/
# on a partial AOSP tree of the base's tag, the stock libraries of the same tree for the ABI check, the release files in
# WORK/out/kktls-jb/<base>/<abi>/. The 4.4 release build (tools/kktls-release-build.sh) is not involved.
#
#   tools/kktls-jb-openssl-build.sh [options] [all|sync|stock|apply|build|collect|check]...
#
# Steps per base (all = every step in this order; each step leaves WORK/<tag>/<step>.done and is skipped next time):
#   sync     repo init --depth=1 + repo sync of the base's `project` lines; every project must then be at its `rev`
#   stock    pristine tree (+ the base's build/ OpenJDK 6 diff): libcrypto libssl per ABI; the libraries and include/ go
#            to WORK/<tag>/stock-openssl/<abi>/ (the old side of the ABI check); out/target is removed afterwards
#   apply    git am patches/jb/<base>/external_openssl/*.patch in external/openssl
#   build    per ABI: libcrypto libssl openssl (the command-line tool is a test client, not a release file)
#   collect  lib/libssl.so lib/libcrypto.so into WORK/out/kktls-jb/<base>/<abi>/ + SHA256SUMS + BUILD-INFO.txt;
#            bin/openssl into WORK/out/kktls-jb/<base>/test-bin/<abi>/; external/openssl/NOTICE into .../notice/
#   check    per ABI: openssl-abi-check.py symbols against stock-openssl (0 removed public exports; the 4.4 allow
#            list plus patches/jb/<base>/openssl-abi-allow.txt when present); summary in WORK/out/kktls-jb/checks.tsv
#
# Options:
#   --work DIR        scratch root (default ./kktls-jb-work)
#   --bases "B..."    only these bases (default: every `base` line of patches/jb/targets.txt)
#   --abis "A..."     only these ABIs (armeabi-v7a, x86)
#   --cpus N --jobs N docker --cpus and make -j (default 4 / 4)
#   --image NAME      build image (default: tools/docker-image.sh aosp-build); --sync-image NAME (default aosp-sync)
#   --runner docker|direct   direct = already inside the build image: no docker
#
# Inputs come from `git archive HEAD` (patches/jb, patches/build, tools) and must be committed (exit 4); a tree is only built further
# while patches/jb at HEAD equals what it was patched with. Exit codes: 0 ok, 1 a failed step or check, 2 usage,
# 3 missing image or tool, 4 uncommitted inputs or a series change since apply.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ME=$(readlink -f "$0"); HERE=$(dirname "$ME"); REPO_ROOT=$(dirname "$HERE")
MIRROR=https://android.googlesource.com/platform/manifest
REPO_REV=v2.69
INPUT_PATHS="patches/jb patches/build tools"
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
  prebuilts/misc/linux-x86/ccache/ccache -M 10G >/dev/null
  t0=$(date +%s)
  make -j"$jobs" "$@" > "$tree/logs/$label.log" 2>&1
  rc=$?
  echo "INNER rc=$rc wall=$(( $(date +%s) - t0 ))"
  exit 0
fi

WORK=./kktls-jb-work; SEL_BASES=""; SEL_ABIS=""; CPUS=4; JOBS=4; IMAGE=""; SYNC_IMAGE=""; RUNNER=docker; CMDS=()
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
    all|sync|stock|apply|build|collect|check) CMDS+=("$1"); shift ;;
    -h|--help) sed -n '2,32p' "$ME"; exit 0 ;;
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
mkdir -p "$WORK"; rm -rf "$INPUTS"; mkdir -p "$INPUTS"
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
done

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
          -v "$tree:/aosp" -v "$ME:/scripts/r.sh:ro" "$IMAGE" \
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
}

do_stock() {
  local b=$1 t=$2 d=$WORK/$2 combo abi
  [ -f "$d/apply.done" ] && die "[$t] stock after apply: the tree is no longer pristine (rm -rf $d)" 1
  local jdk=patches/jb/$b/build/0001-allow-openjdk6.patch
  [ -f "$INPUTS/$jdk" ] || jdk=patches/build/0001-allow-openjdk6.patch
  run_sync "$d" "git -C build -c core.hooksPath=/dev/null apply -R --check \$P/$jdk 2>/dev/null ||
    git -C build -c core.hooksPath=/dev/null apply \$P/$jdk" > "$d/logs/stock-jdk.log" 2>&1 ||
    { cat "$d/logs/stock-jdk.log" >&2; return 1; }
  while read -r combo abi; do
    run_make "$d" "$combo" "stock-$abi" libcrypto libssl || return 1
    local o=$d/stock-openssl/$abi po; po=$(product_out "$d" "$combo"); rm -rf "$o"; mkdir -p "$o"
    cp "$po/system/lib/libcrypto.so" "$po/system/lib/libssl.so" "$o/"
    cp -r "$d/src/external/openssl/include" "$o/include"
  done < <(rows_of "$b")
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
  mv "$d/series-head.txt.new" "$d/series-head.txt"
  tail -n 1 "$d/logs/apply.log"
}

do_build() {
  local b=$1 t=$2 d=$WORK/$2 combo abi
  [ -f "$d/apply.done" ] || die "[$t] build before apply" 1
  while read -r combo abi; do
    run_make "$d" "$combo" "build-$abi" libcrypto libssl openssl || return 1
  done < <(rows_of "$b")
}

do_collect() {
  local b=$1 t=$2 d=$WORK/$2 combo abi f
  [ -f "$d/build.done" ] || die "[$t] collect before build" 1
  while read -r combo abi; do
    local po; po=$(product_out "$d" "$combo") o=$WORK/out/kktls-jb/$b/$abi
    rm -rf "$o"; mkdir -p "$o"
    for f in $FILES; do
      [ -f "$po/system/$f" ] || { echo "[$t] $abi: $f missing in $po/system" >&2; return 1; }
      install -D -m 0644 "$po/system/$f" "$o/$f"
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
    } > "$o/BUILD-INFO.txt"
    echo "  $b/$abi: $(wc -l < "$o/SHA256SUMS") files"
  done < <(rows_of "$b")
  local nd=$WORK/out/kktls-jb/$b/notice
  rm -rf "$nd"; mkdir -p "$nd"
  install -m 0644 "$d/src/external/openssl/NOTICE" "$nd/openssl.NOTICE"
  (cd "$nd" && sha256sum openssl.NOTICE > SHA256SUMS)
}

do_check() {
  local b=$1 t=$2 d=$WORK/$2 combo abi rc=0
  [ -f "$d/collect.done" ] || die "[$t] check before collect" 1
  local sum=$WORK/out/kktls-jb/checks.tsv allow=$d/abi-allow.txt
  [ -f "$sum" ] || printf 'base\tabi\tcheck\tresult\tlog\n' > "$sum"
  cat "$INPUTS/tools/openssl-abi-allow.txt" > "$allow"
  [ -f "$INPUTS/patches/jb/$b/openssl-abi-allow.txt" ] && cat "$INPUTS/patches/jb/$b/openssl-abi-allow.txt" >> "$allow"
  while read -r combo abi; do
    local o=$WORK/out/kktls-jb/$b/$abi l=$d/logs r=PASS
    (cd "$o" && sha256sum -c --quiet SHA256SUMS) || { echo "[$t] $abi: SHA256SUMS mismatch" >&2; rc=1; }
    READELF=$(command -v readelf) $PY "$INPUTS/tools/openssl-abi-check.py" symbols --old "$d/stock-openssl/$abi" \
      --new "$o/lib" --old-headers "$d/stock-openssl/$abi/include" --allow "$allow" \
      > "$l/abi-symbols-$abi.log" 2>&1 || { r=FAIL; rc=1; }
    printf '%s\t%s\topenssl-abi-symbols\t%s\t%s\n' "$b" "$abi" "$r" "$l/abi-symbols-$abi.log" >> "$sum"
    echo "  $abi openssl-abi-check symbols: $r ($(tail -n1 "$l/abi-symbols-$abi.log"))"
  done < <(rows_of "$b")
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
