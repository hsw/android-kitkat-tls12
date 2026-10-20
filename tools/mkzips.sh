#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# mkzips.sh: pack the kktls release recovery zips (+ SHA256SUMS) from the release build output.
#
#   mkzips.sh --in DIR --release NAME --cacerts DIR --conscrypt-notice FILE --out DIR [--jb DIR] [--base-tag TAG]
#             [--mtime EPOCH]
#
#   --in DIR       release build output: DIR/<tag>/<abi>/{lib,framework}/... + SHA256SUMS + BUILD-INFO.txt,
#                  DIR/<tag>/helpers/<abi>/{kktls-symcheck,kktls-util} + allow-missing-libssl.txt + SHA256SUMS,
#                  DIR/<tag>/notice/{openssl,libcore,bionic-libc}.NOTICE okhttp.LICENSE + SHA256SUMS
#   --release NAME release name written into the markers and zip names (e.g. v1; [A-Za-z0-9._-] only)
#   --cacerts DIR  the CA store: <hash>.<n> files in the Android 4.x format (installed as /system/etc/security/cacerts)
#   --conscrypt-notice FILE  the NOTICE of the Conscrypt/BoringSSL build in the layer D files
#   --out DIR      output directory (created; existing kktls-*.zip and SHA256SUMS in it are replaced)
#   --jb DIR       Jelly Bean openssl build output (tools/kktls-jb-openssl-build.sh WORK/out/kktls-jb): DIR/<base>/<abi>/
#                  {lib/libssl.so,lib/libcrypto.so,SHA256SUMS,BUILD-INFO.txt}, DIR/<base>/notice/openssl.NOTICE,
#                  DIR/<base>/allow/allow-missing-lib{ssl,crypto}.txt (each with SHA256SUMS), base = 4.1|4.2|4.3: one
#                  openssl zip per base and ABI (helpers and the bionic notice from the 4.4 base tag). A base built with
#                  java lines (BUILD-INFO `java <module> <path>` and `gate <release>...`, equal for every ABI) also has
#                  those files in <abi>/ and notice/{libcore,fdlibm}.NOTICE: one java zip per base and ABI. A java base
#                  with layer D (BUILD-INFO `conscrypt <path>` lines: the three layer D files, in <abi>/, and on an ABI
#                  whose bionic needs it lib/libkktls_compat.so as a fourth) also gets one conscrypt zip per ABI
#   --base-tag TAG the tag whose openssl, layer D and helper files go into the ABI-independent zips and the
#                  openssl/conscrypt zips (default: the first tag in sort order; those files are the same for every tag)
#   --mtime EPOCH  timestamp of every zip entry (default 1230768000 = 2009-01-01 UTC)
#
# Zips (Android version from the tag name android-<ver>_rN; the openssl zips name the Android version they install on):
#   kktls-openssl-4.4-<abi>-<rel>.zip       system/lib/{libssl,libcrypto}.so (any 4.4.x)
#   kktls-openssl-<base>-<abi>-<rel>.zip    the same for Android <base>.x, with --jb (4.1, 4.2, 4.3)
#   kktls-cacerts-<rel>.zip                 system/etc/security/cacerts/* (replaces the directory)
#   kktls-java-<ver>-<abi>-<rel>.zip        system/framework/{core,core-libart,conscrypt,okhttp}.jar, system/lib/libjavacrypto.so
#   kktls-java-<base>-<abi>-<rel>.zip       system/framework/core.jar, system/lib/libjavacore.so (the base's java lines),
#                                           with --jb; installs on the releases of its gate line (zip.conf android: one
#                                           release, or <base> = every AOSP <base>.x) over that base's openssl zip
#   kktls-conscrypt-<abi>-<rel>.zip         system/framework/kktls-{conscrypt,sslfilter}.jar, system/lib/libkktls_conscrypt_jni.so
#   kktls-conscrypt-<base>-<abi>-<rel>.zip  the same files of a Jelly Bean base (+ system/lib/libkktls_compat.so where
#                                           the base and ABI need it), with --jb; gate as that base's java zip, needs
#                                           the java zip of the same release (its marker)
#   kktls-restore-<rel>.zip                 no payload
# Each holds META-INF/com/google/android/{update-binary,updater-script}, kktls/{zip.conf,checks.sh,install.sh},
# kktls/bin/<abi>/ helpers, NOTICE, and the payload under system/. Not a recovery zip:
#   kktls-jarpatch-<rel>.zip                kktls-jarpatch-<rel>/: the jar patcher (tools/jarpatch/ without its tests:
#                                           driver, normalizer, set files, link check, zip writer, native scan,
#                                           fetch-smali.sh, README.md) and LICENSE; a host tool that makes a
#                                           device-specific java zip from the 4.4 java zips of the same release. Every
#                                           4.4 tag of --in needs a set file (sets/*.txt naming the tag); the release
#                                           build's check step compares its jars with that set (jarpatch/checkset.py)
# Entries are sorted, with fixed timestamps and modes, so the same inputs give byte-identical zips. Exit 0 ok, 1 bad
# input, 2 usage.
set -euo pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
die() { echo "mkzips: $*" >&2; exit "${2:-1}"; }
IN='' REL='' CACERTS='' CNOTICE='' OUT='' BASE='' MTIME=1230768000 JB=''
while [ $# -gt 0 ]; do
  case $1 in
    --in|--release|--cacerts|--conscrypt-notice|--out|--base-tag|--mtime|--jb)
      [ $# -ge 2 ] || die "$1 needs a value" 2
      case $1 in
        --in) IN=$2 ;; --release) REL=$2 ;; --cacerts) CACERTS=$2 ;; --conscrypt-notice) CNOTICE=$2 ;;
        --out) OUT=$2 ;; --base-tag) BASE=$2 ;; --mtime) MTIME=$2 ;; --jb) JB=$2 ;;
      esac; shift 2 ;;
    -h|--help) sed -n '3,49p' "$0"; exit 0 ;;
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
JP=$HERE/jarpatch   # the jar patcher: tools/jarpatch/ next to this script
[ -d "$JP" ] || JP=$HERE/tools/jarpatch
# its files in the kktls-jarpatch zip (tests, selftest.sh and caches stay out)
JP_FILES="README.md kktls-jarpatch.py normalize.py mkset.py checkset.py linkcheck.py rawzip.py nativescan.py
fetch-smali.sh aosp44-ssl-consumers.txt"
ABIS="armeabi-v7a x86"

TAGS=$(cd "$IN" && ls -d android-4.4* 2> /dev/null | sort) || true
[ -n "$TAGS" ] || die "--in $IN: no android-4.4* tag directories"
[ -n "$BASE" ] || BASE=$(echo "$TAGS" | head -n 1)
echo "$TAGS" | grep -qx "$BASE" || die "--base-tag $BASE is not in $IN"

JBASES=''
if [ -n "$JB" ]; then
  [ -d "$JB" ] || die "--jb $JB: no such directory"
  JBASES=$(cd "$JB" && ls -d 4.[0-3] 2> /dev/null | sort -r) || true
  [ -n "$JBASES" ] || die "--jb $JB: no 4.1-4.3 base directories"
fi
jb_tag() { # base -> the AOSP tag its libraries were built from (BUILD-INFO.txt of every ABI, which must agree)
  local t; t=$(cat "$JB/$1"/*/BUILD-INFO.txt | sed -n 's/^tag //p' | sort -u)
  case $t in android-"$1"*) echo "$t" ;; *) die "$JB/$1: BUILD-INFO tag '$t' is not one android-$1 tag" ;; esac
}
jb_info() { # base key -> the values of the BUILD-INFO lines "key ...", one per line; every ABI must have the same
  local a v x='' first=1
  for a in $ABIS; do
    v=$(sed -n "s/^$2 //p" "$JB/$1/$a/BUILD-INFO.txt")
    if [ $first = 1 ]; then x=$v first=0; elif [ "$v" != "$x" ]; then die "$JB/$1: BUILD-INFO '$2' lines differ between ABIs"; fi
  done
  [ -z "$x" ] || printf '%s\n' "$x"
}
jb_java_files() { # base -> the java payload (paths below <abi>/), nothing for an openssl-only base
  jb_info "$1" java | awk '{ print $2 }'
}
jb_conscrypt_files() { # base abi -> the layer D payload of that ABI (paths below <abi>/), nothing without layer D; the
  # ABIs may differ (the compat library)
  sed -n 's/^conscrypt //p' "$JB/$1/$2/BUILD-INFO.txt"
}
D_FILES="framework/kktls-conscrypt.jar framework/kktls-sslfilter.jar lib/libkktls_conscrypt_jni.so"  # installer KK_D_FILES
D_COMPAT=lib/libkktls_compat.so  # the fourth layer D file where a JB base and ABI need it (also in KK_D_FILES)
jb_android() { # base -> zip.conf android of its java zip, from the gate line. checks.sh compares one release exactly
  # and takes 4.N as any 4.N.x, so a gate is either one point release or every AOSP release string of the base
  local g all
  g=$(jb_info "$1" gate | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' '); g=${g% }
  case $1 in 4.1) all='4.1 4.1.1 4.1.2' ;; 4.2) all='4.2 4.2.1 4.2.2' ;; 4.3) all='4.3 4.3.1' ;; *) all='' ;; esac
  case $g in
    '') die "$JB/$1: java lines without a gate line" ;;
    "$all") echo "$1" ;;
    "$1".[0-9]|"$1".[0-9][0-9]) echo "$g" ;;
    *) die "$JB/$1: gate '$g' cannot be expressed by the installer (one $1.x release, or all of '$all')" ;;
  esac
}

# the jar patcher ships with a set file for every 4.4 tag of the release
for f in $JP_FILES; do [ -f "$JP/$f" ] || die "$JP/$f missing (the kktls-jarpatch zip)"; done
for t in $TAGS; do
  n=$(grep -lx "tag $t" "$JP"/sets/*.txt 2> /dev/null | wc -l) || true
  [ "$n" = 1 ] || die "$JP/sets: $n set files name tag $t, want exactly one (the kktls-jarpatch zip)"
done

# every input directory is checked against its SHA256SUMS first
for t in $TAGS; do
  for d in $ABIS helpers notice; do
    [ -f "$IN/$t/$d/SHA256SUMS" ] || die "$IN/$t/$d/SHA256SUMS missing"
    (cd "$IN/$t/$d" && sha256sum -c --quiet SHA256SUMS) || die "$IN/$t/$d: SHA256SUMS mismatch"
  done
done
for b in $JBASES; do
  for d in $ABIS notice allow; do
    [ -f "$JB/$b/$d/SHA256SUMS" ] || die "$JB/$b/$d/SHA256SUMS missing"
    (cd "$JB/$b/$d" && sha256sum -c --quiet SHA256SUMS) || die "$JB/$b/$d: SHA256SUMS mismatch"
  done
  [ -f "$JB/$b/allow/allow-missing-libssl.txt" ] || die "$JB/$b/allow/allow-missing-libssl.txt missing"
  jb_tag "$b" > /dev/null
  jf=$(jb_java_files "$b") cf=''
  for a in $ABIS; do cf=$cf${cf:+ }$(jb_conscrypt_files "$b" "$a"); done
  [ -n "$jf" ] || [ -z "$cf" ] || die "$JB/$b: conscrypt lines without java lines (layer D needs the base's java zip)"
  [ -n "$jf" ] || continue
  jb_android "$b" > /dev/null
  for f in $jf; do
    case $f in framework/*.jar|lib/*.so) ;; *) die "$JB/$b: java file '$f' is not framework/*.jar or lib/*.so" ;; esac
    for a in $ABIS; do
      awk -v f="$f" '$2 == f { ok = 1 } END { exit !ok }' "$JB/$b/$a/SHA256SUMS" || die "$JB/$b/$a/SHA256SUMS does not list $f"
    done
  done
  for f in libcore fdlibm; do
    grep -q " $f.NOTICE\$" "$JB/$b/notice/SHA256SUMS" || die "$JB/$b/notice/SHA256SUMS does not list $f.NOTICE"
  done
  [ -n "$cf" ] || continue
  # on every ABI exactly the files the installer's restore removes (KK_D_FILES): the three, or the three and the compat
  # library; each listed in that ABI's SHA256SUMS
  for a in $ABIS; do
    cf=$(jb_conscrypt_files "$b" "$a")
    [ "$(echo $cf)" = "$D_FILES" ] || [ "$(echo $cf)" = "$D_FILES $D_COMPAT" ] ||
      die "$JB/$b/$a: conscrypt files '$(echo $cf)' are not '$D_FILES' [+ $D_COMPAT]"
    for f in $cf; do
      awk -v f="$f" '$2 == f { ok = 1 } END { exit !ok }' "$JB/$b/$a/SHA256SUMS" || die "$JB/$b/$a/SHA256SUMS does not list $f"
    done
  done
done

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
ST=$(mktemp -d); trap 'rm -rf "$ST"' EXIT
rm -f "$OUT"/kktls-*.zip "$OUT/SHA256SUMS"

rule() { printf '%s\n' "============================================================================="; }
section() { echo; rule; echo "$1"; rule; echo; cat "$2"; }

notice() { # kind tag [openssl-tag openssl-notice-dir] -> NOTICE text (the JB openssl zips: OpenSSL from their own tag)
  local kind=$1 t=$2 n=$IN/$2/notice ot=${3:-$2} on=${4:-$IN/$2/notice}
  echo "Notices for the kktls $kind zip ($REL)"
  echo
  echo "The installer scripts (META-INF/, kktls/*.sh) and the helpers kktls-symcheck and kktls-util are licensed under"
  echo "the Apache License 2.0. The helpers are linked statically with the Android bionic C library (notice below)."
  case $kind in
    openssl) echo "lib/libssl.so and lib/libcrypto.so are OpenSSL 1.0.1u with backported fixes, built from AOSP $ot"
             echo "external/openssl; they are under the OpenSSL and SSLeay licences below." ;;
    java) if [ -n "${3:-}" ]; then # Jelly Bean: libcore of the base's tag, libfdlibm linked into libjavacore.so
            echo "framework/core.jar and lib/libjavacore.so are built from AOSP $ot libcore (Apache License 2.0; Apache"
            echo "Harmony, ICU and other notices below); lib/libjavacore.so contains AOSP $ot external/fdlibm (notice below)."
          else
            echo "framework/core.jar, core-libart.jar, conscrypt.jar and lib/libjavacrypto.so are built from AOSP $t libcore"
            echo "(Apache License 2.0; Apache Harmony, Bouncy Castle and other notices below), framework/okhttp.jar from"
            echo "AOSP $t external/okhttp (Apache License 2.0)."
          fi ;;
    conscrypt) echo "framework/kktls-sslfilter.jar is own code under the Apache License 2.0; framework/kktls-conscrypt.jar"
               echo "and lib/libkktls_conscrypt_jni.so are Conscrypt with BoringSSL (notice below)."
               [ -z "${COMPAT_NOTICE:-}" ] || {
                 echo "lib/libkktls_compat.so is own code under the Apache License 2.0, built against the AOSP $ot"
                 echo "bionic headers; lib/libkktls_conscrypt_jni.so is the Conscrypt library with one .dynamic entry"
                 echo "changed to load it (DT_SONAME retagged DT_NEEDED)."; } ;;
    cacerts) echo "etc/security/cacerts/* hold the certificates of the Mozilla CA root store (as published by curl,"
             echo "https://curl.se/ca/cacert.pem), made available under the Mozilla Public License 2.0 (text below)." ;;
    restore) ;;
  esac
  case $kind in
    openssl) section "OpenSSL (AOSP $ot external/openssl/NOTICE)" "$on/openssl.NOTICE" ;;
    java) if [ -n "${3:-}" ]; then
            section "libcore (AOSP $ot libcore/NOTICE)" "$on/libcore.NOTICE"
            section "fdlibm (AOSP $ot external/fdlibm/NOTICE)" "$on/fdlibm.NOTICE"
          else
            section "libcore (AOSP $t libcore/NOTICE)" "$n/libcore.NOTICE"
          fi ;;
    conscrypt) section "Conscrypt and BoringSSL" "$CNOTICE" ;;
    cacerts) section "Mozilla Public License 2.0" "$LIC/MPL-2.0.txt" ;;
  esac
  section "Android bionic C library (AOSP $t bionic/libc/NOTICE)" "$n/bionic-libc.NOTICE"
  section "Apache License 2.0" "$LIC/Apache-2.0.txt"
}

stage() { # name kind abi android tag helper-abis... -> $ST/name/ with everything but the payload
  # (helpers and notices from tag; HTAG=<4.4 tag> NOTICE_ARGS="<tag> <dir>": a JB zip, helpers from the 4.4 base tag)
  local kind=$2 abi=$3 android=$4 t=$5 s=$ST/$1 a ht=${HTAG:-$5}; shift 5
  mkdir -p "$s/META-INF/com/google/android" "$s/kktls"
  cp "$INST/update-binary" "$s/META-INF/com/google/android/update-binary"
  echo "# kktls: the installer is META-INF/com/google/android/update-binary (a shell script)" \
    > "$s/META-INF/com/google/android/updater-script"
  cp "$INST/checks.sh" "$INST/install.sh" "$s/kktls/"
  printf 'kind=%s\nrelease=%s\nabi=%s\nandroid=%s\ntag=%s\n' "$kind" "$REL" "$abi" "$android" "$t" > "$s/kktls/zip.conf"
  for a in "$@"; do
    mkdir -p "$s/kktls/bin/$a"
    cp "$IN/$ht/helpers/$a/kktls-symcheck" "$IN/$ht/helpers/$a/kktls-util" "$s/kktls/bin/$a/"
  done
  # shellcheck disable=SC2086
  notice "$kind" "$ht" ${NOTICE_ARGS:-} > "$s/NOTICE"
}

payload() { # name dir files... (paths below dir, the <tag>/<abi>/ of a build output)
  local s=$ST/$1 src=$2 f; shift 2
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
  n=kktls-openssl-4.4-$a-$REL
  stage "$n" openssl "$a" 4.4 "$BASE" "$a"
  payload "$n" "$IN/$BASE/$a" lib/libssl.so lib/libcrypto.so
  cp "$IN/$BASE/helpers/allow-missing-libssl.txt" "$ST/$n/kktls/"
  pack "$n"
  for b in $JBASES; do
    n=kktls-openssl-$b-$a-$REL jt=$(jb_tag "$b")
    HTAG=$BASE NOTICE_ARGS="$jt $JB/$b/notice" stage "$n" openssl "$a" "$b" "$jt" "$a"
    payload "$n" "$JB/$b/$a" lib/libssl.so lib/libcrypto.so
    for l in libssl libcrypto; do
      [ ! -f "$JB/$b/allow/allow-missing-$l.txt" ] || cp "$JB/$b/allow/allow-missing-$l.txt" "$ST/$n/kktls/"
    done
    pack "$n"
    jf=$(jb_java_files "$b")
    [ -n "$jf" ] || continue
    n=kktls-java-$b-$a-$REL
    HTAG=$BASE NOTICE_ARGS="$jt $JB/$b/notice" stage "$n" java "$a" "$(jb_android "$b")" "$jt" "$a"
    # shellcheck disable=SC2086
    payload "$n" "$JB/$b/$a" $jf
    pack "$n"
    cf=$(jb_conscrypt_files "$b" "$a")
    [ -n "$cf" ] || continue
    n=kktls-conscrypt-$b-$a-$REL
    cn=''; case " $(echo $cf) " in *" $D_COMPAT "*) cn=1 ;; esac
    COMPAT_NOTICE=$cn HTAG=$BASE NOTICE_ARGS="$jt $JB/$b/notice" stage "$n" conscrypt "$a" "$(jb_android "$b")" "$jt" "$a"
    # shellcheck disable=SC2086
    payload "$n" "$JB/$b/$a" $cf
    pack "$n"
  done
  for t in $TAGS; do
    n=kktls-java-$(ver_of "$t")-$a-$REL
    stage "$n" java "$a" "$(ver_of "$t")" "$t" "$a"
    payload "$n" "$IN/$t/$a" framework/core.jar framework/core-libart.jar framework/conscrypt.jar framework/okhttp.jar \
      lib/libjavacrypto.so
    pack "$n"
  done
  n=kktls-conscrypt-$a-$REL
  stage "$n" conscrypt "$a" 4.4 "$BASE" "$a"
  payload "$n" "$IN/$BASE/$a" framework/kktls-conscrypt.jar framework/kktls-sslfilter.jar lib/libkktls_conscrypt_jni.so
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
n=kktls-jarpatch-$REL
mkdir -p "$ST/$n/$n/sets"
for f in $JP_FILES; do install -m 0644 "$JP/$f" "$ST/$n/$n/$f"; done
install -m 0644 "$JP"/sets/*.txt "$ST/$n/$n/sets/"
install -m 0644 "$LIC/Apache-2.0.txt" "$ST/$n/$n/LICENSE"
pack "$n"

(cd "$OUT" && sha256sum kktls-*.zip > SHA256SUMS)
echo "mkzips: $(wc -l < "$OUT/SHA256SUMS") zips in $OUT (SHA256SUMS)"
