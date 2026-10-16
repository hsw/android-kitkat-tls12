#!/bin/sh
# docker-image.sh: build the project's Docker images and print the image ID. POSIX sh; also sourced by bash scripts.
#
#   tools/docker-image.sh aosp-build | aosp-sync        -> kktls-aosp-build / kktls-aosp-sync, prints the image ID
#   tools/docker-image.sh [--pull] TAG DOCKERFILE CONTEXT [docker build args...]
#   . tools/docker-image.sh; id=$(kktls_image [--pull] TAG DOCKERFILE CONTEXT [args...])
#
# Every caller runs `docker build -q` (BuildKit; a full cache hit takes < 1 s) and uses the printed image ID; the tag is
# a name for humans. A changed Dockerfile or base misses the cache and rebuilds.
# --pull is for rolling bases (debian:trixie, ubuntu:24.04): at most once a day (a stamp per base and platform in
# $KKTLS_IMAGE_STAMPS, default ~/.cache/kktls-docker) a plain `docker pull` of every FROM base runs before the build, so
# a base update rebuilds the image. KKTLS_IMAGE_PULL=1 pulls now, =0 never; a failed pull (offline) keeps the local base.
# Never `build --pull`: with the docker driver a --pull build and a plain build of one base get different cache keys.
# Without --pull (the frozen EOL ubuntu:14.04 of aosp-build, digest-pinned FROMs) nothing is pulled: a fresh local copy
# of the base would change BuildKit's cache key and re-run the apt layers. FROMs pinned by @sha256 and kktls-* images
# are never pulled.
# SPDX-License-Identifier: Apache-2.0

kktls_image_note() { printf '%s\n' "$*" >&2; }

# kktls_image_bases DOCKERFILE: "platform base" per FROM line (platform may be "-")
kktls_image_bases() {
    awk 'toupper($1) == "FROM" {
        plat = "-"; img = ""
        for (i = 2; i <= NF; i++) {
            if ($i ~ /^--platform=/) { plat = substr($i, 12); continue }
            if ($i ~ /^--/) continue
            img = $i; break
        }
        if (img != "") print plat, img
    }' "$1"
}

# kktls_image_pull PLATFORM BASE: the daily pull; prints ", pulled BASE" / ", pull failed" for the log line
kktls_image_pull() {
    _p=${KKTLS_IMAGE_PULL:-}
    [ "$_p" != 0 ] || return 0
    case $2 in *@sha256:*|kktls-*|scratch) return 0 ;; esac
    _d=${KKTLS_IMAGE_STAMPS:-${XDG_CACHE_HOME:-$HOME/.cache}/kktls-docker}
    mkdir -p "$_d" || return 0
    _s="$_d/pull-$(printf '%s_%s' "$2" "$1" | tr -c 'A-Za-z0-9_.-' _).stamp"
    (
        if command -v flock >/dev/null 2>&1; then flock -w 600 8 || exit 0; fi
        if [ "$_p" != 1 ] && [ -n "$(find "$_s" -mmin -1440 2>/dev/null)" ]; then exit 0; fi
        _to=; command -v timeout >/dev/null 2>&1 && _to="timeout 300"
        if [ "$1" = - ]; then set -- "$2"; else set -- --platform "$1" "$2"; fi
        if $_to docker pull -q "$@" >/dev/null 2>&1; then
            touch "$_s"; printf ', pulled %s' "$*"
        else
            kktls_image_note "docker-image: docker pull $* failed (offline?); building on the local base"
            printf ', pull failed'
        fi
    ) 8>"$_s.lock"
}

# kktls_image [--pull] TAG DOCKERFILE CONTEXT [docker build args...]: build, print the image ID on stdout and one line
# "image TAG = <id12> (N s[, pulled ...])" on stderr (prefix $KKTLS_IMAGE_INDENT)
kktls_image() {
    _pull=0
    [ "$1" = --pull ] && { _pull=1; shift; }
    _tag=$1 _df=$2 _ctx=$3; shift 3
    [ -f "$_df" ] || { kktls_image_note "docker-image: no Dockerfile $_df"; return 2; }
    _t0=$(date +%s) _note=
    if [ "$_pull" = 1 ]; then
        _note=$(kktls_image_bases "$_df" | while read -r _pl _b; do kktls_image_pull "$_pl" "$_b"; done)
    fi
    _err=$(mktemp "${TMPDIR:-/tmp}/kktls-image.XXXXXX") || return 2
    _id=$(DOCKER_BUILDKIT=1 docker build -q -t "$_tag" -f "$_df" "$@" "$_ctx" 2>"$_err") || _id=
    case $_id in
        sha256:*)
            rm -f "$_err"
            kktls_image_note "${KKTLS_IMAGE_INDENT:-}image $_tag = $(printf '%s' "$_id" | cut -c8-19) ($(( $(date +%s) - _t0 )) s$_note)"
            printf '%s\n' "$_id" ;;
        *)
            kktls_image_note "${KKTLS_IMAGE_INDENT:-}docker build of $_tag failed; tail of the build log:"
            tail -n 20 "$_err" >&2; rm -f "$_err"
            return 1 ;;
    esac
}

# the named images: the AOSP 4.4 toolchain and the repo client (UID: owner of the trees; KKTLS_IMAGE_UID overrides).
# Dockerfiles: KKTLS_DOCKER_DIR, else docker/ at the repository top (release/docker/ next to tools/ in the series dir).
kktls_image_named() {
    _tools=${KKTLS_IMAGE_TOOLS:-$(cd "$(dirname "$0")" && pwd)}
    _dd=${KKTLS_DOCKER_DIR:-}
    if [ -z "$_dd" ]; then
        if [ -d "$_tools/../release/docker" ]; then _dd=$_tools/../release/docker; else _dd=$_tools/../docker; fi
    fi
    _uid=${KKTLS_IMAGE_UID:-$(id -u)}
    case $1 in
        aosp-build) kktls_image kktls-aosp-build "$_dd/Dockerfile.build" "$_dd" --platform linux/amd64 --build-arg UID="$_uid" ;;
        aosp-sync)  kktls_image --pull kktls-aosp-sync "$_dd/Dockerfile.sync" "$_dd" --build-arg UID="$_uid" ;;
        *) kktls_image_note "docker-image: unknown image $1 (aosp-build | aosp-sync)"; return 2 ;;
    esac
}

# executed (not sourced): $0 is this file
case ${0##*/} in
    docker-image.sh)
        case ${1:-} in
            aosp-build|aosp-sync) kktls_image_named "$1" ;;
            ''|-h|--help) sed -n '2,6p' "$0"; exit 2 ;;
            *) kktls_image "$@" ;;
        esac ;;
esac
