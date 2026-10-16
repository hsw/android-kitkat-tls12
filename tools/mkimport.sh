#!/bin/bash
# mkimport.sh: regenerate the external/openssl import (series external_openssl/0002) from the recipe (0001) with KitKat's
# own `import_openssl.sh import openssl-1.0.1u.tar.gz`, in the build container. For OpenSSL backports: amend 0001 in a
# git checkout of the recipe, rerun this, amend 0002 with the result, regenerate the series.
#
#   mkimport.sh RECIPE_DIR        nothing but this directory, fetch-openssl.sh, git, curl and docker are needed
#
# RECIPE_DIR   holds openssl.config, openssl.version, patches/*.patch and patches/README, i.e. an external/openssl tree at
#              dd1da36 with series 0001 applied. Only these files are read from it.
# KKTLS_WORK   the scratch root (default ./kktls-openssl-work); the container sees only this root as /aosp, so
#              IMPORT_DIR, TARBALL and IMPORT_LOG must be under it.
# IMPORT_DIR   a scratch git checkout of AOSP external/openssl at dd1da36 (default $KKTLS_WORK/openssl-import), created
#              when it does not exist (shallow fetch of dd1da36 from AOSP_OPENSSL_URL, default android.googlesource.com).
#              It is reset to dd1da36 and cleaned (git reset --hard, git clean -fdx), its patches/*.patch are replaced by
#              the recipe's, then import_openssl.sh rewrites it. Never point it at the recipe checkout or a build tree.
# TARBALL      default: fetched by fetch-openssl.sh into $KKTLS_WORK/dl (reused when cached). Its sha256 must be the
#              published one (pinned once, in fetch-openssl.sh).
# IMPORT_LOG   default $KKTLS_WORK/import-u.log (import_openssl.sh output).
# BUILD_IMAGE  the docker image import_openssl.sh runs in (default: tools/docker-image.sh aosp-build, the AOSP 4.4 build
#              image kktls-aosp-build).
#
# Exit 0 = import rc 0; the summary lists any patch fuzz/failure lines of the log, the patches applied and the diff size
# against dd1da36; exit 2 = bad input. To reuse the result: `diff -rq --exclude=.git --exclude=Ssl.mk IMPORT_DIR <recipe
# checkout>` (empty when the recipe is unchanged; Ssl.mk differs by series 0003), then `rsync -a --checksum --delete
# --exclude=/.git IMPORT_DIR/ <checkout>/` on the import commit (0002) and keep 0003's Ssl.mk. Nothing from the tarball
# runs outside the container.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
TOOLS=$(cd "$(dirname "$0")" && pwd -P)
. "$TOOLS/fetch-openssl.sh"                             # OPENSSL_TAR_NAME, TAR_SHA256, fetch_tarball
BASE=dd1da36b0baa39942f0aef42c4712ef0ad628a83          # android-4.4.4_r2.0.1 external/openssl (AOSP-TREE)
AOSP_OPENSSL_URL=${AOSP_OPENSSL_URL:-https://android.googlesource.com/platform/external/openssl}
IMAGE=${BUILD_IMAGE:-}
die() { echo "mkimport: $*" >&2; exit 2; }
case ${1:-} in -h|--help) sed -n '2,26p' "$0"; exit 0 ;; -*) die "unknown option $1" ;; esac
[ $# = 1 ] || die "usage: mkimport.sh RECIPE_DIR"
mkdir -p "${KKTLS_WORK:-./kktls-openssl-work}" || die "cannot create KKTLS_WORK ${KKTLS_WORK:-./kktls-openssl-work}"
W=$(cd "${KKTLS_WORK:-./kktls-openssl-work}" && pwd -P)
RECIPE=$1
I=${IMPORT_DIR:-$W/openssl-import}
TARBALL=${TARBALL:-}
LOG=${IMPORT_LOG:-$W/import-u.log}
under_w() { case $(realpath -m "$1") in "$W"/*) ;; *) die "$1 is not under $W (the container sees only $W as /aosp)" ;; esac; }

under_w "$I"; under_w "$LOG"
I=$(realpath -m "$I"); LOG=$(realpath -m "$LOG")
[ -d "$RECIPE" ] || die "RECIPE_DIR $RECIPE is not a directory"
RECIPE=$(cd "$RECIPE" && pwd -P)                      # absolute: the copy below runs in IMPORT_DIR
if [ -z "$TARBALL" ]; then TARBALL=$(fetch_tarball "$OPENSSL_TAR_URL" "$TAR_SHA256" "$W/dl" "$OPENSSL_TAR_NAME") || die "no tarball"; fi
if [ ! -e "$I" ]; then                                 # shallow checkout of dd1da36 (googlesource serves a sha want)
  git init -q "$I"
  git -C "$I" fetch -q --depth=1 "$AOSP_OPENSSL_URL" "$BASE" || { rm -rf "$I"; die "cannot fetch $BASE from $AOSP_OPENSSL_URL"; }
  git -C "$I" -c advice.detachedHead=false checkout -q FETCH_HEAD
fi
under_w "$TARBALL"; TARBALL=$(realpath -m "$TARBALL")
mkdir -p "$(dirname "$LOG")"
[ -d "$I/.git" ] || die "IMPORT_DIR $I is not a git checkout of external/openssl"
[ "$(git -C "$I" rev-parse HEAD)" = "$BASE" ] || die "IMPORT_DIR $I is not at $BASE"
[ "$(realpath "$I")" != "$(realpath "$RECIPE")" ] || die "IMPORT_DIR and RECIPE_DIR are the same directory"
for f in openssl.config openssl.version patches/README; do [ -f "$RECIPE/$f" ] || die "no $f in $RECIPE"; done
patches=$(bash -c '. "$1/openssl.config"; echo $OPENSSL_PATCHES' _ "$RECIPE")
[ -n "$patches" ] || die "OPENSSL_PATCHES is empty in $RECIPE/openssl.config"
for p in $patches; do [ -f "$RECIPE/patches/$p" ] || die "OPENSSL_PATCHES names $p, missing in $RECIPE/patches"; done
echo "$TAR_SHA256  $TARBALL" | sha256sum -c --quiet - || die "sha256 of $TARBALL is not the published one"

[ -n "$IMAGE" ] || IMAGE=$(sh "$TOOLS/docker-image.sh" aosp-build) || die "docker-image.sh aosp-build failed"
cd "$I"
chmod -R u+w . 2>/dev/null || true
git reset -q --hard && git clean -fdxq
rm -f patches/*.patch
cp "$RECIPE/openssl.config" "$RECIPE/openssl.version" .
cp "$RECIPE"/patches/*.patch "$RECIPE/patches/README" patches/
docker run --rm -u "$(id -u):$(id -g)" -v "$W:/aosp" -w "/aosp/${I#"$W"/}" "$IMAGE" \
  bash -c "./import_openssl.sh import '/aosp/${TARBALL#"$W"/}' > '/aosp/${LOG#"$W"/}' 2>&1" && rc=0 || rc=$?
echo "import rc=$rc (log $LOG)"
grep -n 'Hunk\|FAIL\|rej\|WARNING\|rm:\|No such' "$LOG" || true
grep '^Applying' "$LOG" || true
git status --short | grep -v '^ [MD] ' || true
git diff --shortstat
exit "$rc"
