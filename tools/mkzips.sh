#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# mkzips.sh: pack the kktls release recovery zips (+ SHA256SUMS) from the release build output.
#
#   mkzips.sh --in DIR --release NAME --cacerts DIR --conscrypt-notice FILE --out DIR [--base-tag TAG] [--mtime EPOCH]
#
#   --in DIR       release build output: DIR/<tag>/<abi>/{lib,framework}/... + SHA256SUMS + BUILD-INFO.txt,
#                  DIR/<tag>/helpers/<abi>/{kktls-symcheck,kktls-util} + allow-missing-libssl.txt + SHA256SUMS,
#                  DIR/<tag>/notice/{openssl,libcore,bionic-libc}.NOTICE okhttp.LICENSE + SHA256SUMS
#   --release NAME release name written into the markers and zip names (e.g. v1; [A-Za-z0-9._-] only)
#   --cacerts DIR  the CA store: <hash>.<n> files in the Android 4.x format (installed as /system/etc/security/cacerts)
#   --conscrypt-notice FILE  the NOTICE of the Conscrypt/BoringSSL build in the layer D files
#   --out DIR      output directory (created; existing kktls-*.zip and SHA256SUMS in it are replaced)
#   --base-tag TAG the tag whose openssl, layer D and helper files go into the ABI-independent zips and the
#                  openssl/conscrypt zips (default: the first tag in sort order; those files are the same for every tag)
#   --mtime EPOCH  timestamp of every zip entry (default 1230768000 = 2009-01-01 UTC)
#
# Zips (Android version from the tag name android-<ver>_rN):
#   kktls-openssl-<abi>-<rel>.zip           system/lib/{libssl,libcrypto}.so
#   kktls-cacerts-<rel>.zip                 system/etc/security/cacerts/* (replaces the directory)
#   kktls-java-<ver>-<abi>-<rel>.zip        system/framework/{core,core-libart,conscrypt,okhttp}.jar, system/lib/libjavacrypto.so
#   kktls-conscrypt-<abi>-<rel>.zip         system/framework/kktls-{conscrypt,sslfilter}.jar, system/lib/libkktls_conscrypt_jni.so
#   kktls-restore-<rel>.zip                 no payload
# Each holds META-INF/com/google/android/{update-binary,updater-script}, kktls/{zip.conf,checks.sh,install.sh},
# kktls/bin/<abi>/ helpers, NOTICE, and the payload under system/. Entries are sorted, with fixed timestamps and modes,
# so the same inputs give byte-identical zips. Exit 0 ok, 1 bad input, 2 usage.
set -euo pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
die() { echo "mkzips: $*" >&2; exit "${2:-1}"; }
IN='' REL='' CACERTS='' CNOTICE='' OUT='' BASE='' MTIME=1230768000
while [ $# -gt 0 ]; do
  case $1 in
    --in|--release|--cacerts|--conscrypt-notice|--out|--base-tag|--mtime)
      [ $# -ge 2 ] || die "$1 needs a value" 2
      case $1 in
        --in) IN=$2 ;; --release) REL=$2 ;; --cacerts) CACERTS=$2 ;; --conscrypt-notice) CNOTICE=$2 ;;
        --out) OUT=$2 ;; --base-tag) BASE=$2 ;; --mtime) MTIME=$2 ;;
      esac; shift 2 ;;
    -h|--help) sed -n '3,27p' "$0"; exit 0 ;;
    *) die "unknown argument $1" 2 ;;
  esac
done
[ -n "$IN" ] && [ -n "$REL" ] && [ -n "$CACERTS" ] && [ -n "$CNOTICE" ] && [ -n "$OUT" ] ||
  die "usage: mkzips.sh --in DIR --release NAME --cacerts DIR --conscrypt-notice FILE --out DIR" 2
case $REL in ''|*[!A-Za-z0-9._-]*) die "--release '$REL': only [A-Za-z0-9._-]" 2 ;; esac
case $MTIME in ''|*[!0-9]*) die "--mtime '$MTIME' is not a number" 2 ;; esac
[ -d "$IN" ] || die "--in $IN: no such directory"
[ -f "$CNOTICE" ] || die "--conscrypt-notice $CNOTICE: no such file"
ls "$CACERTS"/*.[0-9] > /dev/null 2>&1 || die "--cacerts $CACERTS: no <hash>.<n> files"
find "$CACERTS" -mindepth 1 ! -name '*.[0-9]' | grep -q . && die "--cacerts $CACERTS: holds other entries than <hash>.<n> files"
INST=$HERE/installer LIC=$HERE/licenses   # next to this script, or one level up (the published layout)
[ -d "$INST" ] || INST=$HERE/../installer
[ -d "$LIC" ] || LIC=$HERE/../licenses
ABIS="armeabi-v7a x86"

TAGS=$(cd "$IN" && ls -d android-4.4* 2> /dev/null | sort) || true
[ -n "$TAGS" ] || die "--in $IN: no android-4.4* tag directories"
[ -n "$BASE" ] || BASE=$(echo "$TAGS" | head -n 1)
echo "$TAGS" | grep -qx "$BASE" || die "--base-tag $BASE is not in $IN"

# every input directory is checked against its SHA256SUMS first
for t in $TAGS; do
  for d in $ABIS helpers notice; do
    [ -f "$IN/$t/$d/SHA256SUMS" ] || die "$IN/$t/$d/SHA256SUMS missing"
    (cd "$IN/$t/$d" && sha256sum -c --quiet SHA256SUMS) || die "$IN/$t/$d: SHA256SUMS mismatch"
  done
done

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
ST=$(mktemp -d); trap 'rm -rf "$ST"' EXIT
rm -f "$OUT"/kktls-*.zip "$OUT/SHA256SUMS"

rule() { printf '%s\n' "============================================================================="; }
section() { echo; rule; echo "$1"; rule; echo; cat "$2"; }

notice() { # kind tag -> NOTICE text
  local kind=$1 t=$2 n=$IN/$2/notice
  echo "Notices for the kktls $kind zip ($REL)"
  echo
  echo "The installer scripts (META-INF/, kktls/*.sh) and the helpers kktls-symcheck and kktls-util are licensed under"
  echo "the Apache License 2.0. The helpers are linked statically with the Android bionic C library (notice below)."
  case $kind in
    openssl) echo "lib/libssl.so and lib/libcrypto.so are OpenSSL 1.0.1u with backported fixes, built from AOSP $t"
             echo "external/openssl; they are under the OpenSSL and SSLeay licences below." ;;
    java) echo "framework/core.jar, core-libart.jar, conscrypt.jar and lib/libjavacrypto.so are built from AOSP $t libcore"
          echo "(Apache License 2.0; Apache Harmony, Bouncy Castle and other notices below), framework/okhttp.jar from"
          echo "AOSP $t external/okhttp (Apache License 2.0)." ;;
    conscrypt) echo "framework/kktls-sslfilter.jar is own code under the Apache License 2.0; framework/kktls-conscrypt.jar"
               echo "and lib/libkktls_conscrypt_jni.so are Conscrypt with BoringSSL (notice below)." ;;
    cacerts) echo "etc/security/cacerts/* hold the certificates of the Mozilla CA root store (as published by curl,"
             echo "https://curl.se/ca/cacert.pem), made available under the Mozilla Public License 2.0 (text below)." ;;
    restore) ;;
  esac
  case $kind in
    openssl) section "OpenSSL (AOSP $t external/openssl/NOTICE)" "$n/openssl.NOTICE" ;;
    java) section "libcore (AOSP $t libcore/NOTICE)" "$n/libcore.NOTICE" ;;
    conscrypt) section "Conscrypt and BoringSSL" "$CNOTICE" ;;
    cacerts) section "Mozilla Public License 2.0" "$LIC/MPL-2.0.txt" ;;
  esac
  section "Android bionic C library (AOSP $t bionic/libc/NOTICE)" "$n/bionic-libc.NOTICE"
  section "Apache License 2.0" "$LIC/Apache-2.0.txt"
}

stage() { # name kind abi android tag helper-abis... -> $ST/name/ with everything but the payload
  local kind=$2 abi=$3 android=$4 t=$5 s=$ST/$1 a; shift 5
  mkdir -p "$s/META-INF/com/google/android" "$s/kktls"
  cp "$INST/update-binary" "$s/META-INF/com/google/android/update-binary"
  echo "# kktls: the installer is META-INF/com/google/android/update-binary (a shell script)" \
    > "$s/META-INF/com/google/android/updater-script"
  cp "$INST/checks.sh" "$INST/install.sh" "$s/kktls/"
  printf 'kind=%s\nrelease=%s\nabi=%s\nandroid=%s\ntag=%s\n' "$kind" "$REL" "$abi" "$android" "$t" > "$s/kktls/zip.conf"
  for a in "$@"; do
    mkdir -p "$s/kktls/bin/$a"
    cp "$IN/$t/helpers/$a/kktls-symcheck" "$IN/$t/helpers/$a/kktls-util" "$s/kktls/bin/$a/"
  done
  notice "$kind" "$t" > "$s/NOTICE"
}

payload() { # name tag abi files... (paths below <tag>/<abi>/)
  local s=$ST/$1 src=$IN/$2/$3 f; shift 3
  for f in "$@"; do install -D -m 0644 "$src/$f" "$s/system/$f"; done
  cp "$src/BUILD-INFO.txt" "$s/kktls/BUILD-INFO.txt"
}

pack() { # name: $ST/name -> $OUT/name.zip (sorted entries, fixed time, 0755 for update-binary and helpers)
  python3 -I - "$ST/$1" "$OUT/$1.zip" "$MTIME" <<'EOF'
import os, sys, time, zipfile
src, out, epoch = sys.argv[1], sys.argv[2], int(sys.argv[3])
dt = max(time.gmtime(epoch)[:6], (1980, 1, 1, 0, 0, 0))
names = []
for root, dirs, files in os.walk(src):
    for f in files:
        names.append(os.path.relpath(os.path.join(root, f), src).replace(os.sep, "/"))
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for n in sorted(names):
        zi = zipfile.ZipInfo(n, dt)
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.create_system = 3
        exe = n == "META-INF/com/google/android/update-binary" or n.startswith("kktls/bin/")
        zi.external_attr = (0o100000 | (0o755 if exe else 0o644)) << 16
        with open(os.path.join(src, n), "rb") as fh:
            z.writestr(zi, fh.read())
EOF
  echo "  $1.zip"
}

ver_of() { local v=${1#android-}; echo "${v%%_*}"; }

for a in $ABIS; do
  n=kktls-openssl-$a-$REL
  stage "$n" openssl "$a" 4.4 "$BASE" "$a"
  payload "$n" "$BASE" "$a" lib/libssl.so lib/libcrypto.so
  cp "$IN/$BASE/helpers/allow-missing-libssl.txt" "$ST/$n/kktls/"
  pack "$n"
  for t in $TAGS; do
    n=kktls-java-$(ver_of "$t")-$a-$REL
    stage "$n" java "$a" "$(ver_of "$t")" "$t" "$a"
    payload "$n" "$t" "$a" framework/core.jar framework/core-libart.jar framework/conscrypt.jar framework/okhttp.jar \
      lib/libjavacrypto.so
    pack "$n"
  done
  n=kktls-conscrypt-$a-$REL
  stage "$n" conscrypt "$a" 4.4 "$BASE" "$a"
  payload "$n" "$BASE" "$a" framework/kktls-conscrypt.jar framework/kktls-sslfilter.jar lib/libkktls_conscrypt_jni.so
  pack "$n"
done
n=kktls-cacerts-$REL
# shellcheck disable=SC2086
stage "$n" cacerts any 4.1-4.4 "$BASE" $ABIS
mkdir -p "$ST/$n/system/etc/security/cacerts"
for f in "$CACERTS"/*.[0-9]; do install -m 0644 "$f" "$ST/$n/system/etc/security/cacerts/"; done
pack "$n"
n=kktls-restore-$REL
# shellcheck disable=SC2086
stage "$n" restore any 4.1-4.4 "$BASE" $ABIS
pack "$n"

(cd "$OUT" && sha256sum kktls-*.zip > SHA256SUMS)
echo "mkzips: $(wc -l < "$OUT/SHA256SUMS") zips in $OUT (SHA256SUMS)"
