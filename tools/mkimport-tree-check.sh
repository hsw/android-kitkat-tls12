#!/bin/bash
# mkimport-tree-check.sh: prove that mkimport.sh regenerates exactly the committed import. Compares
# trees, not .patch bytes:
#   reference = AOSP external/openssl dd1da36 + series 0001 (recipe) + 0002 (committed import), applied with git am;
#   candidate = mkimport.sh RECIPE (dd1da36 + 0001) in a fresh KKTLS_WORK (fresh dd1da36 fetch; tarball fetched by
#               fetch-openssl.sh unless TARBALL is set).
# Equal = the same git tree hash of both worktrees (content, exec bit, symlinks; `git add -A -f` with a scratch index)
# and `diff -r --exclude=.git` empty except for empty directories, which git and patches cannot hold (listed apart).
# 0003 (Ssl.mk) is not applied.
#
#   mkimport-tree-check.sh [--series DIR] WORK
#
# --series DIR  the external_openssl patch directory (default: ../external_openssl, else ../patches/external_openssl)
# WORK          a new or empty scratch directory (holds recipe/, ref/, mk/ and the logs); it must not exist or be empty
# Env: TARBALL, BUILD_IMAGE, AOSP_OPENSSL_URL as for mkimport.sh.
# Exit 0 = import rc 0 and trees equal; 1 = trees differ or the import failed; 2 = usage or setup error.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
TOOLS=$(cd "$(dirname "$0")" && pwd -P)
SERIES=$TOOLS/../external_openssl; [ -d "$SERIES" ] || SERIES=$TOOLS/../patches/external_openssl
BASE=dd1da36b0baa39942f0aef42c4712ef0ad628a83
AOSP_OPENSSL_URL=${AOSP_OPENSSL_URL:-https://android.googlesource.com/platform/external/openssl}
die() { echo "mkimport-tree-check: $*" >&2; exit 2; }
[ "${1:-}" = --series ] && { [ $# -ge 2 ] || die "--series needs a directory"; SERIES=$2; shift 2; }
[ $# = 1 ] || die "usage: mkimport-tree-check.sh [--series DIR] WORK"
case $1 in -*) die "unknown option $1" ;; esac
SERIES=$(cd "$SERIES" 2>/dev/null && pwd -P) || die "no series directory"
p1=$(ls "$SERIES"/0001-*.patch 2>/dev/null) && [ "$(echo "$p1" | wc -l)" = 1 ] || die "no single 0001-*.patch in $SERIES"
p2=$(ls "$SERIES"/0002-*.patch 2>/dev/null) && [ "$(echo "$p2" | wc -l)" = 1 ] || die "no single 0002-*.patch in $SERIES"
mkdir -p "$1"; WORK=$(cd "$1" && pwd -P)
[ -z "$(ls -A "$WORK")" ] || die "WORK $WORK is not empty"
gitc() { git -c user.name=mkimport-tree-check -c user.email=mkimport-tree-check@localhost -c core.hooksPath=/dev/null \
  -c advice.detachedHead=false "$@"; }

echo "== series $SERIES"; sha256sum "$p1" "$p2"
gitc init -q "$WORK/recipe"
gitc -C "$WORK/recipe" fetch -q --depth=1 "$AOSP_OPENSSL_URL" "$BASE" || die "cannot fetch $BASE"
gitc -C "$WORK/recipe" checkout -q FETCH_HEAD
gitc -C "$WORK/recipe" am -q "$p1" || die "0001 does not apply on $BASE"
cp -a "$WORK/recipe" "$WORK/ref"
gitc -C "$WORK/ref" am -q "$p2" || die "0002 does not apply on $BASE + 0001"
echo "== reference: $(git -C "$WORK/ref" log --oneline | head -3 | tr '\n' ';')"

echo "== mkimport.sh $WORK/recipe"
KKTLS_WORK="$WORK/mk" "$TOOLS/mkimport.sh" "$WORK/recipe" > "$WORK/mkimport.out" 2>&1 && rc=0 || rc=$?
tail -n 20 "$WORK/mkimport.out"
[ "$rc" = 0 ] || { echo "RESULT FAIL (mkimport rc=$rc)"; exit 1; }

C=$WORK/mk/openssl-import
# 1. git tree of each worktree (content, exec bit, symlinks; what a patch can carry), ignored files included
wtree() { GIT_INDEX_FILE=$WORK/index.$2 gitc -C "$1" add -A -f . && GIT_INDEX_FILE=$WORK/index.$2 gitc -C "$1" write-tree; }
t_ref=$(wtree "$WORK/ref" ref) && t_mk=$(wtree "$C" mk) || die "git write-tree failed"
# 2. diff -r as a second view; empty directories (no git, no patch can hold them) are listed but do not count
diff -r --exclude=.git "$WORK/ref" "$C" > "$WORK/tree.diff" 2>&1 || true
: > "$WORK/tree.diff.counted"; : > "$WORK/empty-dirs.txt"
while IFS= read -r l; do
  if [[ $l =~ ^Only\ in\ (.*):\ (.*)$ ]] && [ -d "${BASH_REMATCH[1]}/${BASH_REMATCH[2]}" ] &&
     [ -z "$(find "${BASH_REMATCH[1]}/${BASH_REMATCH[2]}" -mindepth 1 ! -type d -print -quit)" ]; then
    echo "$l" >> "$WORK/empty-dirs.txt"
  else echo "$l" >> "$WORK/tree.diff.counted"; fi
done < "$WORK/tree.diff"
echo "== git tree: reference $t_ref, mkimport $t_mk"
echo "== diff -r: $(wc -l < "$WORK/tree.diff.counted") counted lines ($WORK/tree.diff.counted), $(wc -l < "$WORK/empty-dirs.txt") empty-directory lines ($WORK/empty-dirs.txt)"
cat "$WORK/empty-dirs.txt"
echo "== files: $(cd "$C" && find . -path ./.git -prune -o -type f -print | wc -l)"
if [ "$t_ref" = "$t_mk" ] && [ ! -s "$WORK/tree.diff.counted" ]; then echo "RESULT PASS (trees equal)"; exit 0; fi
head -n 20 "$WORK/tree.diff.counted"
echo "RESULT FAIL (trees differ)"; exit 1
