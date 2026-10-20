#!/bin/bash
# fetch-smali.sh: download smali/baksmali 2.5.2 (BSD-3-Clause; fat jars that bundle Guava, JCommander, ANTLR and
# StringTemplate) for the jar patcher and check them against the pinned sha256. Not vendored: fetched at run time.
#
#   fetch-smali.sh                prints the paths of the checked jars on stdout (baksmali, then smali), exit 0
#   fetch-smali.sh --selftest     offline checks of the download/cache logic (file:// URLs, synthetic files)
#   . fetch-smali.sh              defines the pin (SMALI_VERSION, SMALI_URL_BASE, *_SHA256), the cache dir and
#                                 fetch_pinned
#
# Cache dir: $KKTLS_CACHE, default ${XDG_CACHE_HOME:-$HOME/.cache}/kktls. A cached jar with the pinned sha256 is reused
# without network access; one with another sha256 is deleted and downloaded again. A download goes to a per-process
# .part file and is renamed only after its sha256 matched; a failed or mismatching download is deleted.
# Source: the upstream author's Bitbucket downloads (a GET redirects to a presigned S3 URL; HEAD requests get 403).
# SMALI_URL_BASE may be overridden from the environment (a mirror with the same file names, or file:// in tests); the
# sha256 cannot. Maven Central org.smali:{baksmali,smali}:2.5.2 are thin jars with other hashes that need their
# dependencies on the class path: a manual alternative only, not reachable through SMALI_URL_BASE.
# Exit 1 = download failed or sha256 mismatch, 2 = usage.
# SPDX-License-Identifier: Apache-2.0
SMALI_VERSION=2.5.2
SMALI_URL_BASE=${SMALI_URL_BASE:-https://bitbucket.org/JesusFreke/smali/downloads}
BAKSMALI_SHA256=d3116248cce4f82ec5a31eb7f95ee75daff42ddf6eed0ab573973dc53fbad2e5
SMALI_SHA256=9544299578b16f771d8aa8eaefe0d3718ca03478c16f3c356f2fcf1366bfb116
SMALI_CACHE=${KKTLS_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/kktls}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# fetch_pinned URL SHA256 DIR NAME: prints DIR/NAME once it holds a file with SHA256; rc 1 (message on stderr) otherwise.
fetch_pinned() {
  local url=$1 sha=$2 dir=$3 name=$4 f part got
  f=$dir/$name; part=$f.part.$$
  mkdir -p "$dir" || { echo "fetch-smali: cannot create $dir" >&2; return 1; }
  if [ -f "$f" ]; then
    got=$(sha256_of "$f")
    if [ "$got" = "$sha" ]; then printf '%s\n' "$f"; return 0; fi
    echo "fetch-smali: cached $f has sha256 $got, not $sha: deleting it" >&2
    rm -f "$f"
  fi
  rm -f "$part"
  echo "fetch-smali: downloading $url" >&2
  if ! curl --fail --location --silent --show-error --proto '=https,file' --output "$part" "$url"; then
    rm -f "$part"; echo "fetch-smali: download of $url failed" >&2; return 1
  fi
  got=$(sha256_of "$part")
  if [ "$got" != "$sha" ]; then
    rm -f "$part"; echo "fetch-smali: sha256 of the download is $got, not $sha: deleted" >&2; return 1
  fi
  mv -f "$part" "$f" || { rm -f "$part"; return 1; }
  printf '%s\n' "$f"
}

# Sourced: only the pin and the functions.
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
set -uo pipefail

selftest() {
  local t pass=0 fail=0 out rc good goodsha bad
  t=$(mktemp -d) || exit 1
  trap "rm -rf '$t'" EXIT
  mkdir "$t/src"
  printf 'good jar\n' > "$t/src/good.jar"; goodsha=$(sha256_of "$t/src/good.jar")
  printf 'tampered jar\n' > "$t/src/bad.jar"; bad=file://$t/src/bad.jar; good=file://$t/src/good.jar
  check() { if [ "$1" = 0 ]; then pass=$((pass + 1)); echo "ok   $2"; else fail=$((fail + 1)); echo "FAIL $2"; fi; }
  # 1. fresh good download: rc 0, file in place, path printed, no .part
  out=$(fetch_pinned "$good" "$goodsha" "$t/d1" x.jar 2>/dev/null); rc=$?
  [ $rc = 0 ] && [ "$out" = "$t/d1/x.jar" ] && cmp -s "$t/d1/x.jar" "$t/src/good.jar" && [ "$(ls -A "$t/d1")" = x.jar ]
  check $? "good download is kept and its path printed"
  # 2. bad sha256: rc 1, nothing left in the directory
  fetch_pinned "$bad" "$goodsha" "$t/d2" x.jar >/dev/null 2>&1; rc=$?
  [ $rc = 1 ] && [ -z "$(ls -A "$t/d2")" ]
  check $? "download with a wrong sha256 aborts and leaves no file"
  # 3. cached good file, URL unreachable: rc 0 without download
  mkdir "$t/d3"; cp "$t/src/good.jar" "$t/d3/x.jar"
  out=$(fetch_pinned "file://$t/src/missing" "$goodsha" "$t/d3" x.jar 2>&1 >/dev/null); rc=$?
  [ $rc = 0 ] && ! grep -q downloading <<<"$out" && cmp -s "$t/d3/x.jar" "$t/src/good.jar"
  check $? "a cached good file is not downloaded again"
  # 4. cached bad file: deleted and downloaded again
  mkdir "$t/d4"; cp "$t/src/bad.jar" "$t/d4/x.jar"
  fetch_pinned "$good" "$goodsha" "$t/d4" x.jar >/dev/null 2>&1; rc=$?
  [ $rc = 0 ] && cmp -s "$t/d4/x.jar" "$t/src/good.jar"
  check $? "a cached file with a wrong sha256 is replaced"
  # 5. cached bad file and a bad download: both gone
  mkdir "$t/d5"; cp "$t/src/bad.jar" "$t/d5/x.jar"
  fetch_pinned "$bad" "$goodsha" "$t/d5" x.jar >/dev/null 2>&1; rc=$?
  [ $rc = 1 ] && [ -z "$(ls -A "$t/d5")" ]
  check $? "a bad cached file and a bad download leave no file"
  # 6. download failure (curl --fail on a missing file): rc 1, no .part
  fetch_pinned "file://$t/src/missing" "$goodsha" "$t/d6" x.jar >/dev/null 2>&1; rc=$?
  [ $rc = 1 ] && [ -z "$(ls -A "$t/d6")" ]
  check $? "a failed download leaves no file"
  # 7. a stale .part from an interrupted run is not taken as the jar
  mkdir "$t/d7"; cp "$t/src/good.jar" "$t/d7/x.jar.part"
  fetch_pinned "file://$t/src/missing" "$goodsha" "$t/d7" x.jar >/dev/null 2>&1; rc=$?
  [ $rc = 1 ] && [ ! -e "$t/d7/x.jar" ]
  check $? "a stale .part is not reused"
  # 8. the CLI honours KKTLS_CACHE and SMALI_URL_BASE, and fails (exit 1) on a mirror without the jars
  KKTLS_CACHE=$t/cache SMALI_URL_BASE=file://$t/nomirror bash "$0" >/dev/null 2>&1; rc=$?
  [ $rc = 1 ] && [ -d "$t/cache" ] && [ -z "$(ls -A "$t/cache")" ]
  check $? "CLI: KKTLS_CACHE used, a failed mirror exits 1 and leaves no file"
  # 9. the CLI refuses an unknown option (exit 2)
  bash "$0" --bogus >/dev/null 2>&1; rc=$?
  [ $rc = 2 ]
  check $? "unknown option exits 2"
  echo "RESULT $([ $fail = 0 ] && echo PASS || echo FAIL) ($pass of $((pass + fail)))"
  [ $fail = 0 ]
}

while [ $# -gt 0 ]; do
  case $1 in
    --selftest) selftest; exit ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "fetch-smali: unknown argument $1 (usage: fetch-smali.sh [--selftest])" >&2; exit 2 ;;
  esac
done
fetch_pinned "$SMALI_URL_BASE/baksmali-$SMALI_VERSION.jar" "$BAKSMALI_SHA256" "$SMALI_CACHE" "baksmali-$SMALI_VERSION.jar" &&
  fetch_pinned "$SMALI_URL_BASE/smali-$SMALI_VERSION.jar" "$SMALI_SHA256" "$SMALI_CACHE" "smali-$SMALI_VERSION.jar"
