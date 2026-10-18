#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests of the kktls recovery zips: mkzips.sh on a synthetic release output, then update-binary from each zip run by
# busybox sh against fake device roots (KKTLS_ROOT), inside `unshare -r` so chown 0:0 works without privileges.
#
#   run-tests.sh [--real IN CACERTS CONSCRYPT_NOTICE STOCK_LIB_DIR [--sdk-system DIR] [--jb JB JB_STOCK]]
#
# Synthetic input: ELF fixtures for the libraries (symcheck/mkfixtures.py), zip jars with or without classes.dex, and
# helper wrappers: kktls-symcheck and kktls-util built for this host, with `setcon` replaced by a logger (a label write
# needs privileges the test does not have). busybox runs its own applets first, so the scripts see busybox tools only
# (except a fake chcon on PATH in the chcon case).
# install-adb.sh runs against a stub adb whose device is a fake root entered with `unshare -r chroot` (the host's static
# busybox stands in for the downloaded one; zips with statically linked helpers).
# --real also packs the real release output IN (a mkzips.sh --in directory) and installs and restores its x86 openssl,
# java and conscrypt zips on a fake root whose libssl/libcrypto come from STOCK_LIB_DIR (the stock AOSP x86 libraries;
# the zips' own static helpers run, labels through the fake chcon).
# --sdk-system DIR (with --real): DIR is the /system of an emulator system image (build.prop, lib, framework, app,
# priv-app, etc), e.g. extracted from the SDK 4.4.2 ARM image with debugfs rdump; its ARM zips are installed on a copy
# (openssl, cacerts, java-<its release>, conscrypt) and restored: the AOSP gate, the dex check and the symbol check
# against a real AOSP system. The ARM helpers run through qemu-user binfmt_misc.
# --jb JB JB_STOCK (with --real): JB is the Jelly Bean openssl output (mkzips.sh --jb), JB_STOCK/<base>/x86/ the stock
# AOSP x86 libssl/libcrypto of each base: per base its x86 openssl zip installs and restores on a fake <base>.x root with
# those libraries (the real allow lists against the real stock exports), and the 4.4 zip is refused there; a base with
# java files also installs its x86 java zip over that openssl zip before the restore, and a base with layer D its x86
# conscrypt zip over that (the 4.4 conscrypt zip is refused there).
# Exit 0 all pass, 1 a failure, 2 usage or a missing tool.
set -euo pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
REL_DIR=$(cd "$HERE/../.." && pwd)
SYM=$REL_DIR/symcheck
REAL=() SDK='' RJB=() RJB_STOCK=''
while [ $# -gt 0 ]; do
  case $1 in
    --real) [ $# -ge 5 ] || { echo "run-tests.sh: --real needs IN CACERTS CONSCRYPT_NOTICE STOCK_LIB_DIR" >&2; exit 2; }
            REAL=("$2" "$3" "$4" "$5"); shift 5 ;;
    --sdk-system) [ $# -ge 2 ] && [ -f "$2/build.prop" ] || { echo "run-tests.sh: --sdk-system needs a /system copy" >&2; exit 2; }
                  SDK=$(cd "$2" && pwd); shift 2 ;;
    --jb) [ $# -ge 3 ] && [ -d "$2" ] && [ -d "$3" ] || { echo "run-tests.sh: --jb needs JB JB_STOCK directories" >&2; exit 2; }
          RJB=("$2"); RJB_STOCK=$3; shift 3 ;;
    -h|--help) sed -n '3,25p' "$0"; exit 0 ;;
    *) echo "run-tests.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
BB=$(command -v busybox) || { echo "run-tests.sh: busybox not found" >&2; exit 2; }
command -v unshare > /dev/null || { echo "run-tests.sh: unshare not found" >&2; exit 2; }

T=$(mktemp -d); [ -n "${KKTLS_TEST_KEEP:-}" ] && echo "keeping $T" || trap 'rm -rf "$T"' EXIT
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL $*"; }
check() { # label cmd...
  local l=$1; shift
  if "$@"; then ok; else bad "$l"; fi
}
none() { # paths (unmatched globs stay literal): true when none of them exists
  local p
  for p; do [ ! -e "$p" ] || return 1; done
}

# ---- host helpers and fixtures -----------------------------------------------------------------------------------
mkdir -p "$T/hbin" "$T/fx" "$T/chcon"
cc -O1 -std=gnu99 -Wall -Wextra -Werror -o "$T/hbin/kktls-util" "$SYM/kktls-util.c"
cc -O1 -std=gnu99 -Wall -Wextra -Werror -o "$T/hbin/kktls-symcheck" "$SYM/kktls-symcheck.c"
cat > "$T/hbin/util-wrapper" <<EOF
#!/bin/sh
if [ "\$1" = setcon ]; then
  shift; ctx=\$1; shift
  for p; do
    case \$p in *"\${KKTLS_TEST_FAIL:-//none//}"*) echo "setcon: injected failure \$p" >&2; exit 1 ;; esac
    if [ -n "\${KKTLS_TEST_FAIL_AFTER:-}" ]; then  # every label write after the first N fails
      n=0; [ -f "\$KKTLS_TEST_LOG.n" ] && read -r n < "\$KKTLS_TEST_LOG.n"  # builtins only: PATH is empty here
      n=\$((n + 1)); echo \$n > "\$KKTLS_TEST_LOG.n"
      [ \$n -le \$KKTLS_TEST_FAIL_AFTER ] || { echo "setcon: injected failure \$p" >&2; exit 1; }
    fi
    echo "util \$ctx \$p" >> "\$KKTLS_TEST_LOG"
  done
  exit 0
fi
exec "$T/hbin/kktls-util" "\$@"
EOF
cat > "$T/chcon/chcon" <<'EOF'
#!/bin/sh
ctx=$1; shift
for p; do echo "chcon $ctx $p" >> "$KKTLS_TEST_LOG"; done
EOF
chmod 0755 "$T/hbin/util-wrapper" "$T/chcon/chcon"

python3 -I - "$SYM" "$T/fx" <<'EOF'
import os, sys, zipfile
sys.path.insert(0, sys.argv[1])
import mkfixtures as m
out = sys.argv[2]
extra = lambda n: (n, m.GLOBAL, m.FUNC, m.DEFAULT, m.BSS)
libs = {
    "ours.so": m.elf(m.FULL, machine=m.EM_386),
    "dev-subset.so": m.elf(m.without("kk_fb"), machine=m.EM_386),
    "dev-ssl2.so": m.elf(m.FULL + [extra("ssl2_accept")], machine=m.EM_386),   # allow-listed internal export
    "dev-extra.so": m.elf(m.FULL + [extra("kk_oem_only")], machine=m.EM_386),  # an export ours lacks
    "dev-zlib.so": m.elf(m.FULL + [extra("BIO_f_zlib")], machine=m.EM_386),    # libcrypto export a JB allow list names
}
for n, b in libs.items():
    open(os.path.join(out, n), "wb").write(b)
def jar(name, dex, tag):
    with zipfile.ZipFile(os.path.join(out, name), "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        if dex:
            z.writestr("classes.dex", "dex\n035\0" + tag)
jar("dex.jar", True, "device")
jar("nodex.jar", False, "device")
jar("ours.jar", True, "ours")
EOF

# ---- synthetic release output -------------------------------------------------------------------------------------
IN=$T/in
jb_needs_compat() { # base abi: the Conscrypt .so of layer D needs libkktls_compat.so (check_prebuilt.py JB_MISSING:
  # 4.2 ARM getauxval; 4.1 the fortify functions on both ABIs, and getauxval on ARM)
  case $1/$2 in 4.2/armeabi-v7a|4.1/*) return 0 ;; *) return 1 ;; esac
}
mkin() {
  local t a d
  for t in android-4.4.2_r2 android-4.4.4_r2; do
    for a in armeabi-v7a x86; do
      d=$IN/$t/$a
      mkdir -p "$d/lib" "$d/framework"
      cp "$T/fx/ours.so" "$d/lib/libssl.so"; cp "$T/fx/ours.so" "$d/lib/libcrypto.so"
      printf 'javacrypto %s %s\n' "$t" "$a" > "$d/lib/libjavacrypto.so"
      printf 'conscrypt jni %s\n' "$a" > "$d/lib/libkktls_conscrypt_jni.so"
      for j in core core-libart conscrypt okhttp kktls-conscrypt kktls-sslfilter; do cp "$T/fx/ours.jar" "$d/framework/$j.jar"; done
      printf 'tag %s\nabi %s\n' "$t" "$a" > "$d/BUILD-INFO.txt"
      (cd "$d" && find . -type f ! -name SHA256SUMS ! -name BUILD-INFO.txt | sed 's#^\./##' | sort | xargs sha256sum > SHA256SUMS)
      mkdir -p "$IN/$t/helpers/$a"
      cp "$T/hbin/kktls-symcheck" "$IN/$t/helpers/$a/kktls-symcheck"
      cp "$T/hbin/util-wrapper" "$IN/$t/helpers/$a/kktls-util"
    done
    cp "$SYM/allow-missing-libssl.txt" "$IN/$t/helpers/"
    (cd "$IN/$t/helpers" && find . -type f ! -name SHA256SUMS | sed 's#^\./##' | sort | xargs sha256sum > SHA256SUMS)
    mkdir -p "$IN/$t/notice"
    for n in openssl.NOTICE libcore.NOTICE okhttp.LICENSE bionic-libc.NOTICE; do echo "fake $n of $t" > "$IN/$t/notice/$n"; done
    (cd "$IN/$t/notice" && sha256sum ./*.NOTICE ./*.LICENSE | sed 's# \./# #' > SHA256SUMS)
  done
  local b
  for b in 4.3 4.2 4.1; do
    for a in armeabi-v7a x86; do
      d=$T/jb/$b/$a
      mkdir -p "$d/lib"
      cp "$T/fx/ours.so" "$d/lib/libssl.so"; cp "$T/fx/ours.so" "$d/lib/libcrypto.so"
      printf 'base %s\ntag android-%s_r9\nabi %s\n' "$b" "$b" "$a" > "$d/BUILD-INFO.txt"
      # every JB base is a java base (as tools/kktls-jb-openssl-build.sh writes it)
      mkdir -p "$d/framework"; cp "$T/fx/ours.jar" "$d/framework/core.jar"
      printf 'javacore %s %s\n' "$b" "$a" > "$d/lib/libjavacore.so"
      printf 'java core framework/core.jar\njava libjavacore lib/libjavacore.so\n' >> "$d/BUILD-INFO.txt"
      case $b in 4.3) echo 'gate 4.3 4.3.1' ;; 4.2) echo 'gate 4.2 4.2.1 4.2.2' ;; 4.1) echo 'gate 4.1.2' ;; esac >> "$d/BUILD-INFO.txt"
      # layer D (a `conscrypt` line of patches/jb/targets.txt): every JB base
      printf 'jb conscrypt jni %s %s\n' "$b" "$a" > "$d/lib/libkktls_conscrypt_jni.so"
      for j in kktls-conscrypt kktls-sslfilter; do cp "$T/fx/ours.jar" "$d/framework/$j.jar"; done
      printf 'conscrypt %s\n' framework/kktls-conscrypt.jar framework/kktls-sslfilter.jar lib/libkktls_conscrypt_jni.so \
        >> "$d/BUILD-INFO.txt"
      if jb_needs_compat "$b" "$a"; then # the compat library (a `compat` line)
        printf 'jb compat %s %s\n' "$b" "$a" > "$d/lib/libkktls_compat.so"
        echo 'conscrypt lib/libkktls_compat.so' >> "$d/BUILD-INFO.txt"
      fi
      (cd "$d" && find . -type f ! -name SHA256SUMS ! -name BUILD-INFO.txt | sed 's#^\./##' | sort | xargs sha256sum > SHA256SUMS)
    done
    mkdir -p "$T/jb/$b/notice" "$T/jb/$b/allow"
    echo "fake openssl.NOTICE of android-${b}_r9" > "$T/jb/$b/notice/openssl.NOTICE"
    for n in libcore fdlibm; do echo "fake $n.NOTICE of android-${b}_r9" > "$T/jb/$b/notice/$n.NOTICE"; done
    (cd "$T/jb/$b/notice" && sha256sum ./*.NOTICE | sed 's# \./# #' > SHA256SUMS)
    cp "$SYM/allow-missing-libssl.txt" "$T/jb/$b/allow/"
    [ "$b" != 4.1 ] || echo BIO_f_zlib > "$T/jb/$b/allow/allow-missing-libcrypto.txt"
    (cd "$T/jb/$b/allow" && sha256sum allow-missing-*.txt > SHA256SUMS)
  done
  mkdir -p "$T/cacerts"
  for c in 00000001.0 00000002.0 keepme00.0; do echo "new cert $c" > "$T/cacerts/$c"; done
  echo "fake conscrypt notice" > "$T/cnotice"
}
mkin

MK=$REL_DIR/mkzips.sh; [ -f "$MK" ] || MK=$REL_DIR/tools/mkzips.sh   # published layout: tools/
MKA=(--in "$IN" --release v9 --cacerts "$T/cacerts" --conscrypt-notice "$T/cnotice")
"$MK" "${MKA[@]}" --out "$T/z1" --jb "$T/jb" > "$T/mk1.log"
"$MK" "${MKA[@]}" --out "$T/z2" --jb "$T/jb" > "$T/mk2.log"
"$MK" "${MKA[@]}" --out "$T/z44" > "$T/mk44.log"
Z=$T/z1
check "mkzips writes 28 zips (10 + 3 JB bases x 2 ABIs x openssl, java and conscrypt)" [ "$(wc -l < "$Z/SHA256SUMS")" = 28 ]
check "mkzips without --jb writes the 10 4.4 zips" [ "$(wc -l < "$T/z44/SHA256SUMS")" = 10 ]
check "the 4.4 zips do not depend on --jb" sh -c "grep -v -- '-4\.[123]-' '$Z/SHA256SUMS' | cmp -s - '$T/z44/SHA256SUMS'"
check "zips are byte-identical across two runs" cmp -s "$T/z1/SHA256SUMS" "$T/z2/SHA256SUMS"
check "the release set has the java zips of 4.1, 4.2 and 4.3 for both ABIs" sh -c "[ \"\$(ls '$Z' | grep 'java-4\.[123]-' | tr '\n' ' ')\" = 'kktls-java-4.1-armeabi-v7a-v9.zip kktls-java-4.1-x86-v9.zip kktls-java-4.2-armeabi-v7a-v9.zip kktls-java-4.2-x86-v9.zip kktls-java-4.3-armeabi-v7a-v9.zip kktls-java-4.3-x86-v9.zip ' ]"
if "$MK" "${MKA[@]}" --out "$T/zu" --jb "$T/jb" --out-unreleased "$T/u" > "$T/mku.log" 2>&1; then
  bad "mkzips accepts the dropped --out-unreleased option"
else
  check "mkzips refuses the dropped --out-unreleased option" sh -c "grep -q '^mkzips: unknown argument --out-unreleased' '$T/mku.log' && [ ! -e '$T/u' ]"
fi
for z in "$Z"/kktls-*.zip; do
  l=$(unzip -Z1 "$z")
  check "$(basename "$z") has NOTICE" sh -c "echo '$l' | grep -qx NOTICE"
  check "$(basename "$z") has update-binary" sh -c "echo '$l' | grep -qx META-INF/com/google/android/update-binary"
  check "$(basename "$z") entries sorted" sh -c "echo '$l' | sort -c"
  check "$(basename "$z") update-binary is 0755" sh -c "unzip -Z '$z' META-INF/com/google/android/update-binary | grep -q '^-rwxr-xr-x'"
done
check "openssl zip carries the allow list" sh -c "unzip -Z1 '$Z/kktls-openssl-4.4-x86-v9.zip' | grep -qx kktls/allow-missing-libssl.txt"
for b in 4.3 4.2 4.1; do
  for a in armeabi-v7a x86; do
    zb=$Z/kktls-openssl-$b-$a-v9.zip
    check "openssl $b $a: zip.conf android=$b tag=android-${b}_r9" sh -c "unzip -p '$zb' kktls/zip.conf | tr '\n' ' ' | grep -qx 'kind=openssl release=v9 abi=$a android=$b tag=android-${b}_r9 '"
    check "openssl $b $a: the base's libs and BUILD-INFO" sh -c "unzip -p '$zb' kktls/BUILD-INFO.txt | grep -qx 'base $b'"
    check "openssl $b $a: helpers of the 4.4 base tag" sh -c "unzip -p '$zb' kktls/bin/$a/kktls-symcheck | cmp -s - '$IN/android-4.4.2_r2/helpers/$a/kktls-symcheck'"
    check "openssl $b $a: NOTICE has the base's OpenSSL and the 4.4 bionic" sh -c "unzip -p '$zb' NOTICE > '$T/n' && grep -q 'fake openssl.NOTICE of android-${b}_r9' '$T/n' && grep -q 'built from AOSP android-${b}_r9' '$T/n' && grep -q 'fake bionic-libc.NOTICE of android-4.4.2_r2' '$T/n'"
  done
done
for jg in "4.3|4.3 4.3.1|4.3" "4.2|4.2 4.2.1 4.2.2|4.2" "4.1|4.1.2|4.1.2"; do  # base|gate|zip.conf android
  IFS='|' read -r b g an <<< "$jg"
  for a in armeabi-v7a x86; do
    zj=$Z/kktls-java-$b-$a-v9.zip
    check "java $b $a: zip.conf android=$an (gate $g) tag=android-${b}_r9" sh -c "unzip -p '$zj' kktls/zip.conf | tr '\n' ' ' | grep -qx 'kind=java release=v9 abi=$a android=$an tag=android-${b}_r9 '"
    check "java $b $a: payload is core.jar and libjavacore.so of the base" sh -c "[ \"\$(unzip -Z1 '$zj' | grep ^system/ | tr '\n' ' ')\" = 'system/framework/core.jar system/lib/libjavacore.so ' ] && unzip -p '$zj' system/lib/libjavacore.so | grep -qx 'javacore $b $a' && unzip -p '$zj' system/framework/core.jar | cmp -s - '$T/fx/ours.jar'"
    check "java $b $a: BUILD-INFO of the base" sh -c "unzip -p '$zj' kktls/BUILD-INFO.txt | grep -qx 'gate $g'"
    check "java $b $a: helpers of the 4.4 base tag" sh -c "unzip -p '$zj' kktls/bin/$a/kktls-util | cmp -s - '$IN/android-4.4.2_r2/helpers/$a/kktls-util' && [ \"\$(unzip -Z1 '$zj' | grep -c ^kktls/bin/)\" = 2 ]"
    check "java $b $a: NOTICE has libcore and fdlibm of the base, the 4.4 bionic, no okhttp" sh -c "unzip -p '$zj' NOTICE > '$T/n' && grep -q 'fake libcore.NOTICE of android-${b}_r9' '$T/n' && grep -q 'fake fdlibm.NOTICE of android-${b}_r9' '$T/n' && grep -q 'built from AOSP android-${b}_r9 libcore' '$T/n' && grep -q 'fake bionic-libc.NOTICE of android-4.4.2_r2' '$T/n' && ! grep -qi okhttp '$T/n'"
  done
done
for jg in "4.3|4.3|4.3 4.3.1" "4.2|4.2|4.2 4.2.1 4.2.2" "4.1|4.1.2|4.1.2"; do  # base|zip.conf android|gate
  IFS='|' read -r b an g <<< "$jg"
  for a in armeabi-v7a x86; do
    zd=$Z/kktls-conscrypt-$b-$a-v9.zip
    want='system/framework/kktls-conscrypt.jar system/framework/kktls-sslfilter.jar system/lib/libkktls_conscrypt_jni.so '
    what="the three layer D files of the base"
    if jb_needs_compat "$b" "$a"; then  # unzip lists the entries sorted: compat before conscrypt
      want='system/framework/kktls-conscrypt.jar system/framework/kktls-sslfilter.jar system/lib/libkktls_compat.so system/lib/libkktls_conscrypt_jni.so '
      what="the three layer D files and libkktls_compat.so of the base"
    fi
    check "conscrypt $b $a: zip.conf android=$an (the java gate $g) tag=android-${b}_r9" sh -c "unzip -p '$zd' kktls/zip.conf | tr '\n' ' ' | grep -qx 'kind=conscrypt release=v9 abi=$a android=$an tag=android-${b}_r9 '"
    check "conscrypt $b $a: payload is $what" sh -c "[ \"\$(unzip -Z1 '$zd' | grep ^system/ | tr '\n' ' ')\" = '$want' ] && unzip -p '$zd' system/lib/libkktls_conscrypt_jni.so | grep -qx 'jb conscrypt jni $b $a'"
    check "conscrypt $b $a: BUILD-INFO of the base, helpers of the 4.4 base tag" sh -c "unzip -p '$zd' kktls/BUILD-INFO.txt | grep -qx 'conscrypt lib/libkktls_conscrypt_jni.so' && unzip -p '$zd' kktls/bin/$a/kktls-util | cmp -s - '$IN/android-4.4.2_r2/helpers/$a/kktls-util'"
    check "conscrypt $b $a: NOTICE has Conscrypt and the 4.4 bionic" sh -c "unzip -p '$zd' NOTICE > '$T/n' && grep -q 'fake conscrypt notice' '$T/n' && grep -q 'fake bionic-libc.NOTICE of android-4.4.2_r2' '$T/n'"
    if jb_needs_compat "$b" "$a"; then
      check "conscrypt $b $a: the compat library is the base's, NOTICE names it" sh -c "unzip -p '$zd' system/lib/libkktls_compat.so | grep -qx 'jb compat $b $a' && unzip -p '$zd' NOTICE | grep -q 'lib/libkktls_compat.so is own code under the Apache License 2.0, built against the AOSP android-${b}_r9'"
    else
      check "conscrypt $b $a: NOTICE does not name the compat library" sh -c "! unzip -p '$zd' NOTICE | grep -q libkktls_compat"
    fi
  done
done
check "a conscrypt zip for every JB base and ABI" sh -c "[ \"\$(ls '$Z' | grep 'conscrypt-4\.[123]-' | tr '\n' ' ')\" = 'kktls-conscrypt-4.1-armeabi-v7a-v9.zip kktls-conscrypt-4.1-x86-v9.zip kktls-conscrypt-4.2-armeabi-v7a-v9.zip kktls-conscrypt-4.2-x86-v9.zip kktls-conscrypt-4.3-armeabi-v7a-v9.zip kktls-conscrypt-4.3-x86-v9.zip ' ]"
check "the 4.4 conscrypt zips keep their names" sh -c "ls '$Z' | grep -qx kktls-conscrypt-x86-v9.zip && ls '$Z' | grep -qx kktls-conscrypt-armeabi-v7a-v9.zip"
check "java 4.4.2 zip NOTICE unchanged by the JB branch (okhttp, the 4.4 libcore)" sh -c "unzip -p '$Z/kktls-java-4.4.2-x86-v9.zip' NOTICE | grep -q 'framework/okhttp.jar from' && unzip -p '$Z/kktls-java-4.4.2-x86-v9.zip' NOTICE | grep -q 'fake libcore.NOTICE of android-4.4.2_r2'"
# the gate line maps to zip.conf android: one point release exactly, the full AOSP set of a base as 4.N, else refused
rm -rf "$T/jbx"; cp -r "$T/jb" "$T/jbx"
jbx_java() { # base gate-arm [gate-x86]: give jbx/<base> java files and gate lines
  local b=$1 a g
  for a in armeabi-v7a x86; do
    g=$2; [ "$a" = armeabi-v7a ] || g=${3:-$2}
    sed -i '/^java \|^gate /d' "$T/jbx/$b/$a/BUILD-INFO.txt"
    mkdir -p "$T/jbx/$b/$a/framework"; cp "$T/fx/ours.jar" "$T/jbx/$b/$a/framework/core.jar"
    echo "javacore $b $a" > "$T/jbx/$b/$a/lib/libjavacore.so"
    printf 'java core framework/core.jar\njava libjavacore lib/libjavacore.so\n' >> "$T/jbx/$b/$a/BUILD-INFO.txt"
    [ -z "$g" ] || echo "gate $g" >> "$T/jbx/$b/$a/BUILD-INFO.txt"
    (cd "$T/jbx/$b/$a" && find . -type f ! -name SHA256SUMS ! -name BUILD-INFO.txt | sed 's#^\./##' | sort | xargs sha256sum > SHA256SUMS)
  done
  for n in libcore fdlibm; do echo "fake $n.NOTICE" > "$T/jbx/$b/notice/$n.NOTICE"; done
  (cd "$T/jbx/$b/notice" && sha256sum ./*.NOTICE | sed 's# \./# #' > SHA256SUMS)
}
mkx() { "$MK" "${MKA[@]}" --out "$T/zx" --jb "$T/jbx" > "$T/mkx.log" 2>&1; }
jbx_java 4.2 4.2.2; jbx_java 4.1 "4.1.2 4.1 4.1.1"
check "mkzips: gate 4.2.2 -> android=4.2.2, gate of all 4.1 releases -> android=4.1" sh -c "'$MK' --in '$IN' --release v9 --cacerts '$T/cacerts' --conscrypt-notice '$T/cnotice' --out '$T/zx' --jb '$T/jbx' > /dev/null && unzip -p '$T/zx/kktls-java-4.2-armeabi-v7a-v9.zip' kktls/zip.conf | grep -qx android=4.2.2 && unzip -p '$T/zx/kktls-java-4.1-armeabi-v7a-v9.zip' kktls/zip.conf | grep -qx android=4.1 && [ \"\$(wc -l < '$T/zx/SHA256SUMS')\" = 28 ]"
for g in "4.2" "4.2.1 4.2.2" "4.2.2 4.3" "4.2.x" ""; do
  jbx_java 4.2 "$g"
  if mkx; then bad "mkzips accepts the 4.2 gate '$g'"; else ok; fi
done
check "mkzips: an empty gate says so" grep -q 'java lines without a gate line' "$T/mkx.log"
jbx_java 4.2 4.2.2 "4.2 4.2.1 4.2.2"
if mkx; then bad "mkzips accepts gate lines that differ between ABIs"; else ok; fi
jbx_java 4.2 4.2.2; rm "$T/jbx/4.2/notice/fdlibm.NOTICE"; (cd "$T/jbx/4.2/notice" && sha256sum ./*.NOTICE | sed 's# \./# #' > SHA256SUMS)
if mkx; then bad "mkzips accepts a java base without the fdlibm notice"; else ok; fi
jbx_java 4.2 4.2.2; sed -i '/libjavacore/d' "$T/jbx/4.2/x86/SHA256SUMS"
if mkx; then bad "mkzips accepts a java file missing from SHA256SUMS"; else ok; fi
jbx_java 4.2 4.2.2
rm -rf "$T/jbx/4.3"; cp -r "$T/jb/4.3" "$T/jbx/4.3"; sed -i '/^conscrypt framework\/kktls-sslfilter.jar/d' "$T/jbx/4.3/"*/BUILD-INFO.txt
if mkx; then bad "mkzips accepts conscrypt lines without kktls-sslfilter.jar"; else ok; fi
rm -rf "$T/jbx/4.3"; cp -r "$T/jb/4.3" "$T/jbx/4.3"; sed -i '/kktls-sslfilter/d' "$T/jbx/4.3/x86/SHA256SUMS"
if mkx; then bad "mkzips accepts a layer D file missing from SHA256SUMS"; else ok; fi
rm -rf "$T/jbx/4.3"; cp -r "$T/jb/4.3" "$T/jbx/4.3"; rm -rf "$T/jbx/4.2"; cp -r "$T/jb/4.2" "$T/jbx/4.2"
check "mkzips: the unchanged JB inputs pass" mkx
sed -i '/libkktls_compat/d' "$T/jbx/4.2/armeabi-v7a/SHA256SUMS"
if mkx; then bad "mkzips accepts a compat library missing from SHA256SUMS"; else ok; fi
rm -rf "$T/jbx/4.2"; cp -r "$T/jb/4.2" "$T/jbx/4.2"; echo 'conscrypt lib/libjavacore.so' >> "$T/jbx/4.2/armeabi-v7a/BUILD-INFO.txt"
if mkx; then bad "mkzips accepts a fifth layer D file"; else check "mkzips: other layer D files say so" grep -q 'are not .*\[+ lib/libkktls_compat.so\]' "$T/mkx.log"; fi
rm -rf "$T/jbx/4.2"; cp -r "$T/jb/4.2" "$T/jbx/4.2"; sed -i '/^conscrypt lib\/libkktls_conscrypt_jni.so/d' "$T/jbx/4.2/armeabi-v7a/BUILD-INFO.txt"
if mkx; then bad "mkzips accepts the compat library without the Conscrypt library"; else ok; fi
rm -rf "$T/jbx/4.2"; cp -r "$T/jb/4.2" "$T/jbx/4.2"
rm -rf "$T/jbx/4.3"; cp -r "$T/jb/4.3" "$T/jbx/4.3"; sed -i '/^java \|^gate /d' "$T/jbx/4.3/"*/BUILD-INFO.txt
if mkx; then bad "mkzips accepts conscrypt lines without java lines"; else check "mkzips: conscrypt lines without java lines say so" grep -q 'conscrypt lines without java lines' "$T/mkx.log"; fi
rm -rf "$T/jbx/4.3"; cp -r "$T/jb/4.3" "$T/jbx/4.3"
check "openssl 4.1 zip carries a libcrypto allow list" sh -c "unzip -Z1 '$Z/kktls-openssl-4.1-x86-v9.zip' | grep -qx kktls/allow-missing-libcrypto.txt"
check "openssl 4.3 and 4.4 zips carry none" sh -c "! unzip -Z1 '$Z/kktls-openssl-4.3-x86-v9.zip' | grep -q libcrypto.txt && ! unzip -Z1 '$Z/kktls-openssl-4.4-x86-v9.zip' | grep -q libcrypto.txt"
check "mkzips refuses a tampered JB input" sh -c "echo x >> '$T/jb/4.2/allow/allow-missing-libssl.txt'; ! '$MK' --in '$IN' --release v9 --cacerts '$T/cacerts' --conscrypt-notice '$T/cnotice' --out '$T/z3' --jb '$T/jb' > /dev/null 2>&1"
cp "$SYM/allow-missing-libssl.txt" "$T/jb/4.2/allow/"
check "cacerts NOTICE has the MPL" sh -c "unzip -p '$Z/kktls-cacerts-v9.zip' NOTICE | grep -q 'Mozilla Public License Version 2.0'"
check "java 4.4.4 zip says android=4.4.4" sh -c "unzip -p '$Z/kktls-java-4.4.4-x86-v9.zip' kktls/zip.conf | grep -qx android=4.4.4"
check "mkzips refuses a tampered input" sh -c "echo x >> '$IN/android-4.4.2_r2/x86/lib/libssl.so'; ! '$MK' --in '$IN' --release v9 --cacerts '$T/cacerts' --conscrypt-notice '$T/cnotice' --out '$T/z3' > /dev/null 2>&1"
cp "$T/fx/ours.so" "$IN/android-4.4.2_r2/x86/lib/libssl.so"
check "mkzips refuses a bad release name" sh -c "! '$MK' --in '$IN' --release 'v 1' --cacerts '$T/cacerts' --conscrypt-notice '$T/cnotice' --out '$T/z3' > /dev/null 2>&1"

# ---- fake device roots ----------------------------------------------------------------------------------------------
mkroot() { # dir [key=value...] (build.prop overrides; special: libssl=FIXTURE, libcrypto=FIXTURE, nosdcard=1, media=1, selinuxfs=1|sysfs,
  # jb=1: a Jelly Bean /system: core.jar but no core-libart/conscrypt/okhttp jars, libjavacore.so but no libjavacrypto.so)
  local r=$1 kv; shift
  rm -rf "$r"; mkdir -p "$r/system/lib" "$r/system/framework" "$r/system/app" "$r/system/priv-app" \
    "$r/system/etc/security/cacerts" "$r/data/dalvik-cache" "$r/sdcard"
  {
    echo "ro.build.id=KK"; echo "ro.build.version.release=4.4.2"; echo "ro.product.cpu.abi=x86"
    echo "ro.build.type=user"; echo "ro.build.fingerprint=generic/sdk/generic:4.4.2/KK/1:user/test-keys"
  } > "$r/system/build.prop"
  cp "$T/fx/dev-ssl2.so" "$r/system/lib/libssl.so"; cp "$T/fx/dev-subset.so" "$r/system/lib/libcrypto.so"
  echo "stock javacrypto" > "$r/system/lib/libjavacrypto.so"
  for j in core core-libart conscrypt okhttp framework ext services; do
    cp "$T/fx/nodex.jar" "$r/system/framework/$j.jar"; echo "odex $j" > "$r/system/framework/$j.odex"
  done
  for j in framework ext services; do cp "$T/fx/dex.jar" "$r/system/framework/$j.jar"; done
  cp "$T/fx/dex.jar" "$r/system/framework/android.test.runner.jar"   # not odexed
  cp "$T/fx/dex.jar" "$r/system/app/Browser.apk"; echo odex > "$r/system/app/Browser.odex"
  cp "$T/fx/dex.jar" "$r/system/priv-app/Settings.apk"; echo odex > "$r/system/priv-app/Settings.odex"
  for c in old00001.0 old00002.0 keepme00.0; do echo "stock cert $c" > "$r/system/etc/security/cacerts/$c"; done
  echo cache > "$r/data/dalvik-cache/system@framework@core.jar@classes.dex"
  for kv; do
    case $kv in
      libssl=*) cp "$T/fx/${kv#libssl=}" "$r/system/lib/libssl.so" ;;
      libcrypto=*) cp "$T/fx/${kv#libcrypto=}" "$r/system/lib/libcrypto.so" ;;
      nosdcard=1) rm -rf "$r/sdcard" ;;
      media=1) mkdir -p "$r/data/media/0" ;;
      selinuxfs=1) mkdir -p "$r/proc"; printf 'nodev\tsysfs\nnodev\tselinuxfs\n\text4\n' > "$r/proc/filesystems" ;;
      selinuxfs=sysfs) mkdir -p "$r/sys/fs/selinux" ;;
      jb=1) for j in core-libart conscrypt okhttp; do rm -f "$r/system/framework/$j.jar" "$r/system/framework/$j.odex"; done
            rm -f "$r/system/lib/libjavacrypto.so"; echo "stock javacore" > "$r/system/lib/libjavacore.so" ;;
      *) sed -i "/^${kv%%=*}=/d" "$r/system/build.prop"; echo "$kv" >> "$r/system/build.prop" ;;
    esac
  done
  chmod -R u+rwX,go+rX "$r"; find "$r" -type f -exec chmod 0644 {} +
}

snap() { # dir [subdir] -> listing of types, modes, sizes and content hashes
  (cd "$1/${2:-.}" && find . -printf '%y %m %s %p\n' | sort && find . -type f -exec sha256sum {} + | sort -k2)
}

LOG=$T/log
run() { # root zip [extra env...] -> exit status of update-binary; output in $T/out
  # KK_PRE: shell commands run first as root in a private mount namespace (e.g. a small tmpfs over a directory); there
  # /proc/self/fd/N of the output file cannot be reopened, so the messages go to stdout (OUTFD "-")
  # KK_SH: the shell for update-binary instead of busybox sh (e.g. dash, which runs PATH tools, not busybox applets)
  local r=$1 z=$2 rc=0 pre=(unshare -r) fd=1 sh=("$BB" sh); shift 2
  [ -z "${KK_SH:-}" ] || read -r -a sh <<< "$KK_SH"
  [ -z "${KK_PRE:-}" ] || pre=(unshare -rm sh -c "$KK_PRE"' && exec "$@"' sh) fd=-
  rm -rf "$T/ub"; mkdir -p "$T/ub"
  unzip -p "$z" META-INF/com/google/android/update-binary > "$T/ub/update-binary"
  "${pre[@]}" env -i PATH="${KK_PATH:-/nonexistent}" KKTLS_ROOT="$r" KKTLS_TMP="$T/unpacked" KKTLS_TEST_LOG="$LOG" "$@" \
    "${sh[@]}" "$T/ub/update-binary" 3 "$fd" "$z" > "$T/out" 2>&1 || rc=$?
  return $rc
}

refused() { # label root zip [env...]: must exit non-zero, say REFUSED and leave the whole root unchanged
  local l=$1 r=$2 z=$3 before; shift 3
  before=$(snap "$r")
  if run "$r" "$z" "$@"; then bad "$l: exit 0"; sed 's/^/  /' "$T/out"; return; fi
  grep -q REFUSED "$T/out" || { bad "$l: no REFUSED line"; sed 's/^/  /' "$T/out"; return; }
  [ "$before" = "$(snap "$r")" ] || { bad "$l: the root changed"; return; }
  ok
}
installs() { # label root zip [env...]
  local l=$1 r=$2 z=$3; shift 3
  if run "$r" "$z" "$@"; then ok; else bad "$l: exit $?"; sed 's/^/  /' "$T/out"; fi
}

O=$Z/kktls-openssl-4.4-x86-v9.zip C=$Z/kktls-cacerts-v9.zip J=$Z/kktls-java-4.4.2-x86-v9.zip
J4=$Z/kktls-java-4.4.4-x86-v9.zip D=$Z/kktls-conscrypt-x86-v9.zip R=$Z/kktls-restore-v9.zip
R0=$T/root

# ---- refusals: nothing is written -------------------------------------------------------------------------------
mkroot "$R0" ro.cm.version=11-20140804-NIGHTLY-hammerhead
refused "openssl on a CM build" "$R0" "$O"
mkroot "$R0" ro.cm.version=11-20140804-NIGHTLY-hammerhead; mkdir -p "$R0/system/etc/kktls"; echo v9 > "$R0/system/etc/kktls/openssl.version"
refused "java on a CM build" "$R0" "$J"
mkroot "$R0" ro.miui.ui.version.name=V5
refused "openssl on MIUI" "$R0" "$O"
mkroot "$R0" ro.build.version.release=4.3
refused "openssl on 4.3" "$R0" "$O"
refused "java 4.4.2 zip on 4.3" "$R0" "$J"
mkroot "$R0" ro.build.version.release=4.0.4
refused "cacerts on 4.0.4" "$R0" "$C"
mkroot "$R0" ro.build.version.release=5.0
refused "cacerts on 5.0" "$R0" "$C"
mkroot "$R0" ro.build.version.release=4.10
refused "cacerts on 4.10" "$R0" "$C"
mkroot "$R0" ro.build.version.release=4.1-rc
refused "cacerts on a non-numeric 4.1-rc" "$R0" "$C"
mkroot "$R0" ro.build.version.release=4.1.2 ro.product.cpu.abi=armeabi-v7a
refused "openssl on 4.1.2" "$R0" "$Z/kktls-openssl-4.4-armeabi-v7a-v9.zip"
mkroot "$R0" ro.product.cpu.abi=armeabi-v7a
refused "x86 openssl on an ARM device" "$R0" "$O"
# Jelly Bean openssl zips: each installs only on its own 4.N.x; the 4.4 zip only on 4.4.x
O43=$Z/kktls-openssl-4.3-x86-v9.zip O41=$Z/kktls-openssl-4.1-x86-v9.zip
mkroot "$R0" ro.build.version.release=4.4.2
refused "openssl 4.3 zip on 4.4.2" "$R0" "$O43"
mkroot "$R0" ro.build.version.release=4.2.2
refused "openssl 4.3 zip on 4.2.2" "$R0" "$O43"
refused "openssl 4.1 zip on 4.2.2" "$R0" "$O41"
mkroot "$R0" ro.build.version.release=4.10
refused "openssl 4.1 zip on 4.10" "$R0" "$O41"
mkroot "$R0" ro.build.version.release=4.3.1 ro.product.cpu.abi=armeabi-v7a
refused "x86 openssl 4.3 zip on an ARM device" "$R0" "$O43"
mkroot "$R0" ro.build.version.release=4.3.1 ro.cm.version=10.2
refused "openssl 4.3 zip on a CM build" "$R0" "$O43"
mkroot "$R0" ro.build.version.release=4.1.2 libcrypto=dev-zlib.so
refused "openssl 4.2 zip on 4.1.2" "$R0" "$Z/kktls-openssl-4.2-x86-v9.zip"
mkroot "$R0" libcrypto=dev-zlib.so
refused "openssl 4.4 zip: device libcrypto exports more (no libcrypto allow list)" "$R0" "$O"
mkroot "$R0" ro.build.version.release=4.3 libcrypto=dev-zlib.so
refused "openssl 4.3 zip: BIO_f_zlib is allowed for 4.1 only" "$R0" "$O43"
mkroot "$R0" libssl=dev-extra.so
refused "device libssl exports more" "$R0" "$O"
mkroot "$R0"; echo "not an elf" > "$R0/system/lib/libssl.so"
refused "device libssl is not ELF" "$R0" "$O"
mkroot "$R0"
refused "java without the openssl marker" "$R0" "$J"
refused "conscrypt without the java marker" "$R0" "$D"
refused "restore without a backup" "$R0" "$R"
mkdir -p "$R0/system/etc/kktls"; echo v9 > "$R0/system/etc/kktls/openssl.version"
cp "$T/fx/nodex.jar" "$R0/system/framework/framework.jar"
refused "java with a stripped odexed framework.jar" "$R0" "$J"
cp "$T/fx/dex.jar" "$R0/system/framework/framework.jar"; cp "$T/fx/nodex.jar" "$R0/system/app/Browser.apk"
refused "java with a stripped odexed apk" "$R0" "$J"
cp "$T/fx/dex.jar" "$R0/system/app/Browser.apk"; echo "junk" > "$R0/system/priv-app/Settings.apk"
refused "java with an unreadable odexed apk" "$R0" "$J"
cp "$T/fx/dex.jar" "$R0/system/priv-app/Settings.apk"
refused "java 4.4.4 zip on 4.4.2" "$R0" "$J4"
echo v9 > "$R0/system/etc/kktls/java.version"; echo v8 > "$R0/system/etc/kktls/java.version"
refused "conscrypt with another release's java marker" "$R0" "$D"

# a read-only /system or /data refuses, although busybox `test -w` says yes to root there
mkroot "$R0"
KK_PRE="mount --bind '$R0/system' '$R0/system' && mount -o remount,bind,ro '$R0/system'" \
  refused "openssl on a read-only /system" "$R0" "$O"
check "read-only /system: the refusal says so" grep -q '/system is not writable' "$T/out"
KK_PRE="mount --bind '$R0/data' '$R0/data' && mount -o remount,bind,ro '$R0/data'" \
  refused "cacerts on a read-only /data" "$R0" "$C"
check "read-only /data: the refusal says so" grep -q '/data is not mounted read-write' "$T/out"
KK_PRE="mount --bind '$R0/system/app' '$R0/system/app' && mount -o remount,bind,ro '$R0/system/app'" \
  installs "openssl with only /system/app read-only (the mount of /system itself decides)" "$R0" "$O"
mkroot "$R0"
KK_PRE="mount --bind '$R0' '$R0' && mount --bind '$R0/system' '$R0/system' && mount --bind '$R0/data' '$R0/data' && mount --bind '$R0/sdcard' '$R0/sdcard' && mount -o remount,bind,ro '$R0'" \
  installs "openssl: read-write /system and /data mounts below a read-only root" "$R0" "$O"

# Jelly Bean openssl zips install on their base (4.1: stock libcrypto with BIO_f_zlib, allowed by its list) and restore
for kv in "4.3 4.3.1" "4.2 4.2.2" "4.1 4.1.2 libcrypto=dev-zlib.so" "4.1 4.1"; do
  read -r b v opt <<< "$kv"
  mkroot "$R0" ro.build.version.release="$v" ${opt:+"$opt"}; ORIG=$(snap "$R0" system)
  installs "openssl $b zip on $v" "$R0" "$Z/kktls-openssl-$b-x86-v9.zip"
  check "openssl $b on $v: libssl and libcrypto replaced" sh -c "cmp -s '$R0/system/lib/libssl.so' '$T/fx/ours.so' && cmp -s '$R0/system/lib/libcrypto.so' '$T/fx/ours.so'"
  check "openssl $b on $v: marker" [ "$(cat "$R0/system/etc/kktls/openssl.version")" = v9 ]
  installs "restore after openssl $b on $v" "$R0" "$R"
  check "openssl $b on $v: /system identical after restore" [ "$ORIG" = "$(snap "$R0" system)" ]
done

# Jelly Bean java zips (4.3, 4.2, 4.1): core.jar + libjavacore.so over the openssl zip of the same base, on the
# releases of its gate only (4.3.x, 4.2.x; 4.1.2 alone: 4.1.1 has another libcore JNI)
jbroot() { # release [key=value...]: an ARM JB root with the kktls openssl marker
  local v=$1; shift
  mkroot "$R0" ro.build.version.release="$v" ro.product.cpu.abi=armeabi-v7a jb=1 "$@"
  mkdir -p "$R0/system/etc/kktls"; echo v9 > "$R0/system/etc/kktls/openssl.version"; chmod 0644 "$R0/system/etc/kktls/openssl.version"
}
jb_java_cases() { # base "refused releases (last: 5.0)" "releases of the gate" CM-version [refusal text]
  local b=$1 v v1=${3%% *} vl=${3##* } JA JX OA MJ rt=${5:-"is not $1.x"}
  JA=$Z/kktls-java-$b-armeabi-v7a-v9.zip JX=$Z/kktls-java-$b-x86-v9.zip OA=$Z/kktls-openssl-$b-armeabi-v7a-v9.zip
  for v in $2; do
    jbroot "$v"; refused "java $b zip on $v" "$R0" "$JA"
  done
  check "java $b zip on 5.0: the refusal says '$rt'" grep -qF "$rt" "$T/out"
  jbroot "$v1"; refused "java 4.4.2 zip on a JB $v1" "$R0" "$Z/kktls-java-4.4.2-armeabi-v7a-v9.zip"
  jbroot "$vl"; refused "java 4.4.4 zip on a JB $vl" "$R0" "$Z/kktls-java-4.4.4-armeabi-v7a-v9.zip"
  jbroot "$v1"; rm -r "$R0/system/etc/kktls"
  refused "java $b zip without the openssl marker" "$R0" "$JA"
  check "java $b zip without openssl: the refusal names the openssl zip" grep -q 'install the kktls openssl zip first' "$T/out"
  jbroot "$vl" ro.cm.version="$4"
  refused "java $b zip on a CM $vl build" "$R0" "$JA"
  jbroot "$vl"; refused "x86 java $b zip on an ARM $vl" "$R0" "$JX"
  jbroot "$v1"; cp "$T/fx/nodex.jar" "$R0/system/framework/framework.jar"
  refused "java $b zip on an odexed and stripped $v1 (the SDK images)" "$R0" "$JA"
  check "java $b zip on a stripped system: the refusal names classes.dex" grep -q 'framework.jar is odexed without classes.dex' "$T/out"
  for v in $3; do
    mkroot "$R0" ro.build.version.release="$v" ro.product.cpu.abi=armeabi-v7a jb=1; ORIG=$(snap "$R0" system)
    : > "$LOG"
    installs "openssl $b zip on JB $v" "$R0" "$OA"
    installs "java $b zip on JB $v" "$R0" "$JA"
    check "java $b on $v: dex check ran" grep -q 'dex check: 5 odexed jar/apk files carry classes.dex' "$T/out"
    check "java $b on $v: core.jar and libjavacore.so replaced" sh -c "cmp -s '$R0/system/framework/core.jar' '$T/fx/ours.jar' && grep -qx 'javacore $b armeabi-v7a' '$R0/system/lib/libjavacore.so'"
    check "java $b on $v: core.odex removed, framework.odex kept" sh -c "[ ! -e '$R0/system/framework/core.odex' ] && [ -f '$R0/system/framework/framework.odex' ]"
    check "java $b on $v: dalvik-cache wiped" [ -z "$(ls -A "$R0/data/dalvik-cache")" ]
    check "java $b on $v: marker" [ "$(cat "$R0/system/etc/kktls/java.version")" = v9 ]
    if [ "$b" != 4.3 ]; then  # an AOSP 4.1/4.2 kernel without SELinux: nothing labelled (with SELinux: below)
      check "java $b on $v: no SELinux, nothing labelled" sh -c "grep -q 'files are not labelled' '$T/out' && [ \"\$(grep -c 'kktls-new\$' '$LOG')\" = 0 ]"
    else
      check "java $b on $v: 2 files + marker labelled" [ "$(grep -c "java.version.kktls-new\$\|core.jar.kktls-new\$\|libjavacore.so.kktls-new\$" "$LOG")" = 3 ]
    fi
    MJ=$(grep -l '^kind java' "$R0"/data/kktls-backup/0*/manifest)
    check "java $b on $v: the backup holds core.jar, libjavacore.so and core.odex" sh -c "grep -q ' system/framework/core.jar\$' '$MJ' && grep -q ' system/lib/libjavacore.so\$' '$MJ' && grep -q '^F .* system/framework/core.odex\$' '$MJ' && grep -qx 'A system/etc/kktls/java.version' '$MJ'"
    installs "java $b zip rerun on $v (core.odex already gone)" "$R0" "$JA"
    installs "restore after java $b on $v" "$R0" "$R"
    check "java $b on $v: /system identical after restore (core.jar, libjavacore.so, core.odex back)" [ "$ORIG" = "$(snap "$R0" system)" ]
    check "java $b on $v: stock core.odex content back" grep -qx 'odex core' "$R0/system/framework/core.odex"
  done
  if [ "$b" != 4.3 ]; then  # SELinux in the kernel: labels are written when the kernel takes them
    mkroot "$R0" ro.build.version.release="$vl" ro.product.cpu.abi=armeabi-v7a jb=1 selinuxfs=1; ORIG=$(snap "$R0" system)
    installs "openssl $b zip on JB $vl with selinuxfs" "$R0" "$OA"
    : > "$LOG"; installs "java $b zip on JB $vl with selinuxfs" "$R0" "$JA"
    check "java $b on $vl with selinuxfs: 2 files + marker labelled" [ "$(grep -c "java.version.kktls-new\$\|core.jar.kktls-new\$\|libjavacore.so.kktls-new\$" "$LOG")" = 3 ]
    installs "restore after java $b on $vl with selinuxfs" "$R0" "$R"
    check "java $b on $vl with selinuxfs: /system identical after restore" [ "$ORIG" = "$(snap "$R0" system)" ]
  fi
  mkroot "$R0" ro.build.version.release="$vl" jb=1; ORIG=$(snap "$R0" system)
  installs "x86 openssl $b zip on x86 JB $vl" "$R0" "$Z/kktls-openssl-$b-x86-v9.zip"
  installs "x86 java $b zip on x86 JB $vl" "$R0" "$JX"
  check "x86 java $b: libjavacore.so replaced" grep -qx "javacore $b x86" "$R0/system/lib/libjavacore.so"
  installs "restore after x86 java $b" "$R0" "$R"
  check "x86 java $b: /system identical after restore" [ "$ORIG" = "$(snap "$R0" system)" ]
}
jb_java_cases 4.3 "4.4.2 4.2.2 4.2 4.1.2 4.30 5.0" "4.3 4.3.1" 10.2
jb_java_cases 4.2 "4.4.2 4.3 4.3.1 4.1.2 4.20 4.21 5.0" "4.2 4.2.1 4.2.2" 10.1
jb_java_cases 4.1 "4.4.2 4.3.1 4.2.2 4.2 4.1 4.1.1 4.1.3 4.1.20 4.10 5.0" "4.1.2" 10.0 \
  "is not 4.1.2 (this zip is built from AOSP 4.1.2)"
jbroot 4.1.1; refused "java 4.1 zip on 4.1.1 (another libcore JNI)" "$R0" "$Z/kktls-java-4.1-armeabi-v7a-v9.zip"
check "java 4.1 zip on 4.1.1: the refusal names 4.1.2" grep -qF "Android '4.1.1' is not 4.1.2" "$T/out"

# Jelly Bean conscrypt zips (4.3, 4.2, 4.1): layer D over the java zip of the same release, on the releases of the java
# gate only; the 4.2 ARM zip and both 4.1 zips have libkktls_compat.so as a fourth file
jbjava() { # release [key=value...]: jbroot + the kktls java marker of release v9
  jbroot "$@"; echo v9 > "$R0/system/etc/kktls/java.version"; chmod 0644 "$R0/system/etc/kktls/java.version"
}
jb_conscrypt_cases() { # base "refused releases (last: 5.0)" "gate releases" cm-version [refusal text]
  local b=$1 v n DA DX MD files rt=${5:-"is not $1.x"}
  DA=$Z/kktls-conscrypt-$b-armeabi-v7a-v9.zip DX=$Z/kktls-conscrypt-$b-x86-v9.zip
  files="system/framework/kktls-conscrypt.jar system/framework/kktls-sslfilter.jar system/lib/libkktls_conscrypt_jni.so"
  ! jb_needs_compat "$b" armeabi-v7a || files="$files system/lib/libkktls_compat.so"
  n=$(echo $files | wc -w)
  for v in $2; do jbjava "$v"; refused "conscrypt $b zip on $v" "$R0" "$DA"; done
  check "conscrypt $b zip on 5.0: the refusal says '$rt'" grep -qF "Android '5.0' $rt" "$T/out"
  jbjava "${3%% *}"; refused "4.4 conscrypt zip on a JB $b (wrong base)" "$R0" "$Z/kktls-conscrypt-armeabi-v7a-v9.zip"
  check "4.4 conscrypt zip on $b: the refusal says 'is not 4.4.x'" grep -qF "Android '${3%% *}' is not 4.4.x" "$T/out"
  jbroot "${3%% *}"; refused "conscrypt $b zip without the java marker (no java zip)" "$R0" "$DA"
  check "conscrypt $b zip without java: the refusal names the java zip" grep -q 'install the kktls java zip first' "$T/out"
  jbjava "${3##* }"; echo v8 > "$R0/system/etc/kktls/java.version"
  refused "conscrypt $b zip over the java zip of another release" "$R0" "$DA"
  check "conscrypt $b zip over java v8: the refusal names both releases" grep -qF "java.version is 'v8', this zip needs 'v9'" "$T/out"
  jbjava "${3##* }" ro.cm.version="$4"; refused "conscrypt $b zip on a CM ${3##* } build" "$R0" "$DA"
  jbjava "${3%% *}"; refused "x86 conscrypt $b zip on an ARM $b" "$R0" "$DX"
  for v in $3; do
    mkroot "$R0" ro.build.version.release="$v" ro.product.cpu.abi=armeabi-v7a jb=1; ORIG=$(snap "$R0" system)
    installs "openssl $b zip on JB $v (layer D chain)" "$R0" "$Z/kktls-openssl-$b-armeabi-v7a-v9.zip"
    installs "java $b zip on JB $v (layer D chain)" "$R0" "$Z/kktls-java-$b-armeabi-v7a-v9.zip"
    : > "$LOG"
    installs "conscrypt $b zip on JB $v" "$R0" "$DA"
    check "conscrypt $b on $v: the $n layer D files of the base" sh -c "grep -qx 'jb conscrypt jni $b armeabi-v7a' '$R0/system/lib/libkktls_conscrypt_jni.so' && cmp -s '$R0/system/framework/kktls-conscrypt.jar' '$T/fx/ours.jar' && cmp -s '$R0/system/framework/kktls-sslfilter.jar' '$T/fx/ours.jar'"
    if jb_needs_compat "$b" armeabi-v7a; then
      check "conscrypt $b on $v: libkktls_compat.so of the base" grep -qx "jb compat $b armeabi-v7a" "$R0/system/lib/libkktls_compat.so"
    else
      check "conscrypt $b on $v: no libkktls_compat.so" [ ! -e "$R0/system/lib/libkktls_compat.so" ]
    fi
    check "conscrypt $b on $v: marker" [ "$(cat "$R0/system/etc/kktls/conscrypt.version")" = v9 ]
    if [ "$b" != 4.3 ]; then  # an AOSP 4.1/4.2 kernel without SELinux: nothing labelled
      check "conscrypt $b on $v: no SELinux, nothing labelled" sh -c "grep -q 'files are not labelled' '$T/out' && [ \"\$(grep -c 'kktls-new\$' '$LOG')\" = 0 ]"
    else
      check "conscrypt $b on $v: $n files + marker labelled" [ "$(grep -c "conscrypt.version.kktls-new\$\|kktls-conscrypt.jar.kktls-new\$\|kktls-sslfilter.jar.kktls-new\$\|libkktls_conscrypt_jni.so.kktls-new\$\|libkktls_compat.so.kktls-new\$" "$LOG")" = $((n + 1)) ]
    fi
    MD=$(grep -l '^kind conscrypt' "$R0"/data/kktls-backup/0*/manifest)
    check "conscrypt $b on $v: the backup records the $n files as added" sh -c "for f in $files; do grep -qx \"A \$f\" '$MD' || exit 1; done"
    installs "restore after conscrypt $b on $v" "$R0" "$R"
    check "conscrypt $b on $v: /system identical after restore (layer D files and markers gone)" [ "$ORIG" = "$(snap "$R0" system)" ]
  done
  mkroot "$R0" ro.build.version.release="${3%% *}" jb=1; ORIG=$(snap "$R0" system)
  installs "x86 openssl $b zip on x86 JB ${3%% *} (layer D chain)" "$R0" "$Z/kktls-openssl-$b-x86-v9.zip"
  installs "x86 java $b zip on x86 JB ${3%% *} (layer D chain)" "$R0" "$Z/kktls-java-$b-x86-v9.zip"
  installs "x86 conscrypt $b zip on x86 JB ${3%% *}" "$R0" "$DX"
  if jb_needs_compat "$b" x86; then
    check "x86 conscrypt $b: the x86 .so and the x86 compat library" sh -c "grep -qx 'jb conscrypt jni $b x86' '$R0/system/lib/libkktls_conscrypt_jni.so' && grep -qx 'jb compat $b x86' '$R0/system/lib/libkktls_compat.so'"
  else
    check "x86 conscrypt $b: the x86 .so, no compat library" sh -c "grep -qx 'jb conscrypt jni $b x86' '$R0/system/lib/libkktls_conscrypt_jni.so' && [ ! -e '$R0/system/lib/libkktls_compat.so' ]"
  fi
  installs "restore after x86 conscrypt $b" "$R0" "$R"
  check "x86 conscrypt $b: /system identical after restore" [ "$ORIG" = "$(snap "$R0" system)" ]
}
jb_conscrypt_cases 4.3 "4.4.2 4.2.2 4.2 4.1.2 4.30 5.0" "4.3 4.3.1" 10.2
jb_conscrypt_cases 4.2 "4.4.2 4.3 4.3.1 4.1.2 4.20 4.21 5.0" "4.2 4.2.1 4.2.2" 10.1
jb_conscrypt_cases 4.1 "4.4.2 4.3.1 4.2.2 4.2 4.1 4.1.1 4.1.3 4.1.20 4.10 5.0" "4.1.2" 10.0 \
  "is not 4.1.2 (this zip is built from AOSP 4.1.2)"
jbjava 4.1.1; refused "conscrypt 4.1 zip on 4.1.1 (with a java marker)" "$R0" "$Z/kktls-conscrypt-4.1-armeabi-v7a-v9.zip"
check "conscrypt 4.1 zip on 4.1.1: the refusal names 4.1.2" grep -qF "Android '4.1.1' is not 4.1.2" "$T/out"
# restore when the backups are gone: the layer D files (KK_D_FILES, with the compat library) go all the same
mkroot "$R0" ro.build.version.release=4.2.2 ro.product.cpu.abi=armeabi-v7a jb=1; ORIG=$(snap "$R0" system)
installs "openssl 4.2 zip on JB 4.2.2 (lost backups)" "$R0" "$Z/kktls-openssl-4.2-armeabi-v7a-v9.zip"
installs "java 4.2 zip on JB 4.2.2 (lost backups)" "$R0" "$Z/kktls-java-4.2-armeabi-v7a-v9.zip"
installs "conscrypt 4.2 zip on JB 4.2.2 (lost backups)" "$R0" "$Z/kktls-conscrypt-4.2-armeabi-v7a-v9.zip"
MD=$(grep -l '^kind conscrypt' "$R0"/data/kktls-backup/0*/manifest); rm -rf "${MD%/manifest}"
rm -rf "$R0"/sdcard/kktls-backup/"$(basename "${MD%/manifest}")"
installs "restore without the conscrypt backup" "$R0" "$R"
check "restore without the conscrypt backup: no layer D file left, compat library included" sh -c "for f in framework/kktls-conscrypt.jar framework/kktls-sslfilter.jar lib/libkktls_conscrypt_jni.so lib/libkktls_compat.so; do [ ! -e '$R0/system/'\$f ] || exit 1; done"

# ---- install chain and restore -------------------------------------------------------------------------------------
mkroot "$R0"; ORIG=$(snap "$R0" system)
: > "$LOG"
installs "openssl on the SDK id KK" "$R0" "$O"
check "openssl: libssl replaced" cmp -s "$R0/system/lib/libssl.so" "$T/fx/ours.so"
check "openssl: marker" [ "$(cat "$R0/system/etc/kktls/openssl.version")" = v9 ]
for p in system/lib/libssl.so system/lib/libcrypto.so system/etc/kktls system/etc/kktls/openssl.version; do
  check "openssl: label call for $p" grep -q "^util u:object_r:system_file:s0 $R0/$p\(.kktls-new\)\?$" "$LOG"
done
check "openssl: backup in /data and /sdcard" sh -c "ls -d '$R0'/data/kktls-backup/0001-*/manifest '$R0'/sdcard/kktls-backup/0001-*/manifest > /dev/null"
M1=$(ls "$R0"/data/kktls-backup/0001-*/manifest)
check "openssl: manifest has the fingerprint" grep -qx 'fingerprint generic/sdk/generic:4.4.2/KK/1:user/test-keys' "$M1"
check "openssl: manifest names the digest tool" grep -qx 'hash sha256' "$M1"
check "openssl: manifest has the libssl digest" grep -qx "F $(sha256sum < "$T/fx/dev-ssl2.so" | cut -d' ' -f1) system/lib/libssl.so" "$M1"
check "openssl: no unfinished second copy" sh -c "! ls -d '$R0'/sdcard/kktls-backup/.tmp-* 2> /dev/null"
installs "openssl rerun" "$R0" "$O"
installs "cacerts" "$R0" "$C"
check "cacerts: plan removes before it places" sh -c "head -n 1 '$T/unpacked/kktls/plan' | grep -q '^R ' && awk '/^P /{p=1} /^R /&&p{b=1} END{exit b}' '$T/unpacked/kktls/plan'"
check "cacerts: directory replaced wholesale" sh -c "[ \"\$(ls '$R0/system/etc/security/cacerts' | tr '\n' ' ')\" = '00000001.0 00000002.0 keepme00.0 ' ]"
: > "$LOG"
installs "java" "$R0" "$J"
check "java: core.odex removed" [ ! -e "$R0/system/framework/core.odex" ]
check "java: framework.odex kept" [ -f "$R0/system/framework/framework.odex" ]
check "java: dalvik-cache wiped" [ -z "$(ls -A "$R0/data/dalvik-cache")" ]
check "java: core.jar replaced" cmp -s "$R0/system/framework/core.jar" "$T/fx/ours.jar"
check "java: label calls for 5 files + marker" [ "$(grep -c '\.kktls-new$' "$LOG")" = 6 ]
installs "java rerun (odex already gone)" "$R0" "$J"
installs "conscrypt" "$R0" "$D"
check "conscrypt: jni lib" [ -f "$R0/system/lib/libkktls_conscrypt_jni.so" ]
echo cache > "$R0/data/dalvik-cache/x"
installs "restore" "$R0" "$R"
check "restore: /system identical to the original" [ "$ORIG" = "$(snap "$R0" system)" ]
check "restore: dalvik-cache wiped" [ -z "$(ls -A "$R0/data/dalvik-cache")" ]
check "restore: backups marked done" none "$R0"/data/kktls-backup/[0-9]* "$R0"/sdcard/kktls-backup/[0-9]*
refused "restore twice" "$R0" "$R"

# cacerts and restore on Android 4.1-4.3: no SELinux in an AOSP 4.1/4.2 kernel (no label writes), labels on 4.3 and
# on a 4.1/4.2 kernel that has SELinux
check "cacerts zip says android=4.1-4.4" sh -c "unzip -p '$C' kktls/zip.conf | grep -qx android=4.1-4.4"
check "restore zip says android=4.1-4.4" sh -c "unzip -p '$R' kktls/zip.conf | grep -qx android=4.1-4.4"
for v in 4.1 4.1.2 4.2.2; do
  mkroot "$R0" ro.build.version.release=$v ro.product.cpu.abi=armeabi-v7a; ORIG=$(snap "$R0" system)
  : > "$LOG"
  installs "cacerts on $v without SELinux" "$R0" "$C"
  check "cacerts $v: says it does not label" grep -q 'no SELinux in this kernel' "$T/out"
  check "cacerts $v: directory replaced wholesale" sh -c "[ \"\$(ls '$R0/system/etc/security/cacerts' | tr '\n' ' ')\" = '00000001.0 00000002.0 keepme00.0 ' ]"
  check "cacerts $v: files 0644, marker dir 0755" sh -c "[ \"\$(stat -c %a '$R0'/system/etc/security/cacerts/* '$R0/system/etc/kktls' | sort -u | tr '\n' ' ')\" = '644 755 ' ]"
  check "cacerts $v: marker" [ "$(cat "$R0/system/etc/kktls/cacerts.version")" = v9 ]
  check "cacerts $v: no label calls" [ ! -s "$LOG" ]
  installs "restore on $v without SELinux" "$R0" "$R"
  check "restore $v: /system identical" [ "$ORIG" = "$(snap "$R0" system)" ]
  check "restore $v: no label calls" [ ! -s "$LOG" ]
done
for kv in "4.2.2 selinuxfs=1" "4.2.2 selinuxfs=sysfs" "4.3" "4.3.1"; do
  read -r v opt <<< "$kv"
  mkroot "$R0" ro.build.version.release="$v" ${opt:+"$opt"}; ORIG=$(snap "$R0" system)
  : > "$LOG"
  installs "cacerts on $kv" "$R0" "$C"
  check "cacerts $kv: labels each CA file and the marker" [ "$(grep -c '^util u:object_r:system_file:s0 .*\.kktls-new$' "$LOG")" = 4 ]
  check "cacerts $kv: labels the marker dir" grep -qx "util u:object_r:system_file:s0 $R0/system/etc/kktls" "$LOG"
  check "cacerts $kv: no 'not labelled' line" sh -c "! grep -q 'no SELinux' '$T/out'"
  : > "$LOG"
  installs "restore on $kv" "$R0" "$R"
  check "restore $kv: /system identical" [ "$ORIG" = "$(snap "$R0" system)" ]
  check "restore $kv: labels the restored files" grep -q '^util u:object_r:system_file:s0 ' "$LOG"
done
mkroot "$R0" ro.build.version.release=4.4.2 selinuxfs=1
: > "$LOG"
installs "cacerts on 4.4.2 (selinuxfs listed)" "$R0" "$C"
check "cacerts 4.4.2: labelled" [ "$(grep -c '\.kktls-new$' "$LOG")" = 4 ]
# 4.2.2 kernel with SELinux but no policy loaded (the SDK 4.1/4.2 emulator kernels): every label write fails with
# EOPNOTSUPP; the install and the restore go on without labels and say so once
mkroot "$R0" ro.build.version.release=4.2.2 selinuxfs=1; ORIG=$(snap "$R0" system)
rm -f "$LOG.n"
installs "cacerts on 4.2.2, SELinux without a policy (label writes fail)" "$R0" "$C" KKTLS_TEST_FAIL_AFTER=0
check "cacerts 4.2.2 no policy: one 'takes no labels' line" [ "$(grep -c 'takes no labels' "$T/out")" = 1 ]
check "cacerts 4.2.2 no policy: directory replaced" sh -c "[ \"\$(ls '$R0/system/etc/security/cacerts' | tr '\n' ' ')\" = '00000001.0 00000002.0 keepme00.0 ' ]"
rm -f "$LOG.n"
installs "restore on 4.2.2, SELinux without a policy" "$R0" "$R" KKTLS_TEST_FAIL_AFTER=0
check "restore 4.2.2 no policy: /system identical" [ "$ORIG" = "$(snap "$R0" system)" ]
rm -f "$LOG.n"
mkroot "$R0" ro.build.version.release=4.1.2
installs "cacerts on 4.1.2: an injected label failure is never reached" "$R0" "$C" KKTLS_TEST_FAIL=keepme00.0.kktls-new
mkroot "$R0" ro.build.version.release=4.3; ORIG=$(snap "$R0" system)
if run "$R0" "$C" KKTLS_TEST_FAIL=keepme00.0.kktls-new; then bad "4.3: a label failure must fail the install"; else ok; fi
check "4.3 label failure: rolled back" [ "$ORIG" = "$(snap "$R0" system)" ]

# restore from /sdcard after /data is wiped
mkroot "$R0"; ORIG=$(snap "$R0" system)
installs "openssl (sdcard case)" "$R0" "$O"
installs "java (sdcard case)" "$R0" "$J"
rm -rf "$R0/data"; mkdir -p "$R0/data"
installs "restore from /sdcard" "$R0" "$R"
check "restore from /sdcard: /system identical" [ "$ORIG" = "$(snap "$R0" system)" ]

# no /sdcard: the second copy goes to /data/media/0
mkroot "$R0" nosdcard=1 media=1; ORIG=$(snap "$R0" system)
installs "openssl (media case)" "$R0" "$O"
check "media: copy in /data/media/0" sh -c "ls -d '$R0'/data/media/0/kktls-backup/0001-* > /dev/null"
rm -rf "$R0/data/kktls-backup"
installs "restore from /data/media/0" "$R0" "$R"
check "restore from /data/media/0: /system identical" [ "$ORIG" = "$(snap "$R0" system)" ]

# a failure during the copy rolls back
mkroot "$R0"; ORIG=$(snap "$R0" system)
if run "$R0" "$O" KKTLS_TEST_FAIL=libssl.so.kktls-new; then bad "injected failure: exit 0"; else ok; fi
check "rollback: /system identical" [ "$ORIG" = "$(snap "$R0" system)" ]
check "rollback: backup marked failed" sh -c "ls -d '$R0'/data/kktls-backup/failed-0001-* '$R0'/sdcard/kktls-backup/failed-0001-* > /dev/null"
refused "restore after a rolled-back install" "$R0" "$R"

# a failure that also breaks the rollback (label writes stop working) keeps the backup active for the restore zip
mkroot "$R0"; ORIG=$(snap "$R0" system)
if run "$R0" "$O" KKTLS_TEST_FAIL=libssl.so.kktls-new; then :; fi
check "failed rollback setup: first install refused by the injected failure" grep -q 'install failed' "$T/out"
installs "openssl (before a systemic failure)" "$R0" "$O"
rm -f "$LOG.n"  # cacerts: 3 CA files labelled, then the marker and the rollback of a changed CA file fail
if run "$R0" "$C" KKTLS_TEST_FAIL_AFTER=3; then bad "systemic failure: exit 0"; else ok; fi
check "systemic failure: rollback reported incomplete" grep -q 'rollback incomplete' "$T/out"
check "systemic failure: backup kept active" sh -c "ls -d '$R0'/data/kktls-backup/0003-*/manifest > /dev/null"
installs "restore after a failed rollback" "$R0" "$R"
check "restore after a failed rollback: /system identical" [ "$ORIG" = "$(snap "$R0" system)" ]

# leftovers of an interrupted run are removed first: *.kktls-new in /system, an unfinished second backup copy
mkroot "$R0"; echo junk > "$R0/system/lib/libssl.so.kktls-new"; mkdir -p "$R0/sdcard/kktls-backup/.tmp-0007-x/files"
installs "openssl over leftovers" "$R0" "$O"
check "leftovers removed" sh -c "[ ! -e '$R0/system/lib/libssl.so.kktls-new' ] && [ ! -e '$R0/sdcard/kktls-backup/.tmp-0007-x' ]"

# backups of every location take part: a factory reset wipes /data (and its backups), /sdcard keeps 0001; the
# re-install after it backs up the kktls state as 0002; restore needs 0002 from /data and 0001 from /sdcard
mkroot "$R0"; ORIG=$(snap "$R0" system)
installs "openssl (reset case)" "$R0" "$O"
rm -rf "$R0/data"; mkdir -p "$R0/data/dalvik-cache"
installs "openssl again after a factory reset" "$R0" "$O"
check "reset: the new backup is 0002" sh -c "ls -d '$R0'/data/kktls-backup/0002-*/manifest > /dev/null"
installs "restore after reset and re-install" "$R0" "$R"
check "restore after reset and re-install: /system identical" [ "$ORIG" = "$(snap "$R0" system)" ]
check "reset: both backups marked done" sh -c "ls -d '$R0'/sdcard/kktls-backup/done-0001-* '$R0'/sdcard/kktls-backup/done-0002-* > /dev/null"

# digests: a damaged copy in /data is skipped for the intact one on /sdcard; damage in every copy refuses the restore
mkroot "$R0"; ORIG=$(snap "$R0" system)
installs "openssl (digest case)" "$R0" "$O"
echo damaged >> "$(ls -d "$R0"/data/kktls-backup/0001-*)/files/system/lib/libssl.so"
installs "restore with a damaged /data copy" "$R0" "$R"
check "damaged /data copy: /system identical from the /sdcard copy" [ "$ORIG" = "$(snap "$R0" system)" ]
mkroot "$R0"
installs "openssl (damage everywhere)" "$R0" "$O"
for d in "$R0"/data/kktls-backup/0001-* "$R0"/sdcard/kktls-backup/0001-*; do echo damaged >> "$d/files/system/lib/libcrypto.so"; done
refused "restore with every copy damaged" "$R0" "$R"
check "damaged everywhere: the refusal says why" grep -q 'no copy whose files match' "$T/out"
rm -f "$(ls -d "$R0"/sdcard/kktls-backup/0001-*)/files/system/lib/libcrypto.so"
refused "restore with a file missing in one copy and damaged in the other" "$R0" "$R"

# another ROM: a ROM update replaces /system (new fingerprint, new stock files, no markers); the old backups must not
# be restored over it, and the next install retires them as stale
mkroot "$R0"
installs "openssl (ROM update case)" "$R0" "$O"
rm -rf "$R0/system/etc/kktls"; cp "$T/fx/dev-ssl2.so" "$R0/system/lib/libssl.so"; echo "new ROM" > "$R0/system/lib/libjavacrypto.so"
sed -i 's#^ro.build.fingerprint=.*#ro.build.fingerprint=generic/sdk/generic:4.4.2/KK/2:user/test-keys#' "$R0/system/build.prop"
refused "restore after a ROM update" "$R0" "$R"
check "ROM update: the refusal names the ROM change" grep -q 'the ROM was replaced' "$T/out"
NEWROM=$(snap "$R0" system)
installs "openssl on the new ROM" "$R0" "$O"
check "ROM update: old backup retired as stale" sh -c "ls -d '$R0'/data/kktls-backup/stale-0001-* '$R0'/sdcard/kktls-backup/stale-0001-* > /dev/null"
check "ROM update: the new backup is 0002" sh -c "ls -d '$R0'/data/kktls-backup/0002-*/manifest > /dev/null"
installs "restore on the new ROM" "$R0" "$R"
check "ROM update: restore gives back the new ROM" [ "$NEWROM" = "$(snap "$R0" system)" ]

# same ROM, no marker, an active backup: the first install failed and its rollback too; a second install must keep that
# backup (the only copy of the stock files), and the restore returns to the original
mkroot "$R0"; ORIG=$(snap "$R0" system)
rm -f "$LOG.n"
if run "$R0" "$O" KKTLS_TEST_FAIL_AFTER=1; then bad "first install, broken rollback: exit 0"; else ok; fi
check "broken first rollback: reported" grep -q 'rollback incomplete' "$T/out"
check "broken first rollback: no marker" [ ! -e "$R0/system/etc/kktls/openssl.version" ]
installs "openssl after a broken first rollback" "$R0" "$O"
check "broken first rollback: backup 0001 still active" sh -c "ls -d '$R0'/data/kktls-backup/0001-*/manifest > /dev/null"
installs "restore after a broken first rollback" "$R0" "$R"
check "broken first rollback: /system identical after restore" [ "$ORIG" = "$(snap "$R0" system)" ]

# free space: a /system or /data too small refuses before anything is written; a full /sdcard only loses the second copy
# full_pre DIR: KK_PRE that mounts a tmpfs over $R0/DIR, copies DIR back and fills it up to 8 KiB free. The tmpfs is
# filled rather than sized from `du`: du of the copy depends on the host filesystem (ext4 counts 4 KiB per directory,
# tmpfs none), so a size derived from it left the tmpfs with room to spare when TMPDIR is not a tmpfs.
full_pre() {
  echo "mount -t tmpfs -o size=$(( $(du -sk "$R0/$1" | cut -f1) * 2 + 1024 ))k tmpfs '$R0/$1' && cp -a '$T/cp/$1/.' '$R0/$1/'" \
    "&& f=\$(df -Pk '$R0/$1' | awk 'NR == 2 { print \$4 }') && dd if=/dev/zero of='$R0/$1/.kktls-test-fill' bs=1024" \
    "count=\$((f - 8)) 2> /dev/null && [ \"\$(df -Pk '$R0/$1' | awk 'NR == 2 { print \$4 }')\" -le 8 ]"
}
mkroot "$R0"; rm -rf "$T/cp"; cp -a "$R0" "$T/cp"
KK_PRE=$(full_pre system) refused "openssl with a full /system" "$R0" "$O"
check "full /system: the refusal says so" grep -q 'not enough space on /system' "$T/out"
KK_PRE=$(full_pre data) refused "openssl with a full /data" "$R0" "$O"
check "full /data: the refusal says so" grep -q 'not enough space on /data' "$T/out"
KK_PRE="mount -t tmpfs -o size=4k tmpfs '$R0/sdcard'" installs "openssl with a full /sdcard" "$R0" "$O"
check "full /sdcard: warned, no second copy" grep -q 'not enough space for the second backup copy' "$T/out"

# ---- a recovery without digest tools --------------------------------------------------------------------------------
# busybox sh runs its own applets first, so a missing applet cannot be simulated with it: these cases run update-binary
# under dash with PATH = every busybox applet except the digest ones (sha*sum, md5sum, cksum), i.e. a recovery busybox
# built without them. The backup digests come from the zip's helper (kktls-util sha256).
command -v dash > /dev/null || { echo "run-tests.sh: dash not found" >&2; exit 2; }
DASH=$(command -v dash) ND=$T/nodigest
mkdir -p "$ND"
for a in $("$BB" --list); do
  case $a in *sum|sh|ash|hush) ;; *) ln -s "$BB" "$ND/$a" ;; esac
done
check "no digest tool on the reduced PATH" sh -c "! PATH='$ND' '$DASH' -c 'command -v sha256sum || command -v md5sum || command -v cksum'"
mkroot "$R0"; ORIG=$(snap "$R0" system)
KK_SH=$DASH KK_PATH=$ND installs "no digest tools: openssl" "$R0" "$O"
KK_SH=$DASH KK_PATH=$ND installs "no digest tools: java" "$R0" "$J"
M1=$(ls "$R0"/data/kktls-backup/0001-*/manifest)
check "no digest tools: manifest says sha256" grep -qx 'hash sha256' "$M1"
check "no digest tools: the helper's libssl digest" grep -qx "F $(sha256sum < "$T/fx/dev-ssl2.so" | cut -d' ' -f1) system/lib/libssl.so" "$M1"
check "no digest tools: second copies" sh -c "ls -d '$R0'/sdcard/kktls-backup/0001-*/manifest '$R0'/sdcard/kktls-backup/0002-*/manifest > /dev/null"
KK_SH=$DASH KK_PATH=$ND installs "no digest tools: restore" "$R0" "$R"
check "no digest tools: /system identical after restore" [ "$ORIG" = "$(snap "$R0" system)" ]

# backups of rc1-rc3 may record md5 or cksum digests (the first of sha256sum/md5sum/cksum that ran): they restore where
# that tool exists; where it does not, the refusal names the tool (not "damaged")
legacy() { # tool: rewrite every copy of the active backups to that tool's digests, as an old release wrote them
  local m t h p
  for m in "$R0"/data/kktls-backup/[0-9]*/manifest "$R0"/sdcard/kktls-backup/[0-9]*/manifest; do
    while read -r t h p; do
      case $t in
        hash) echo "hash $1" ;;
        F) case $1 in
             md5) echo "F $(md5sum < "${m%/manifest}/files/$p" | cut -d' ' -f1) $p" ;;
             cksum) echo "F $(cksum < "${m%/manifest}/files/$p" | awk '{ print $1 "-" $2 }') $p" ;;
             *) echo "F $h $p" ;;
           esac ;;
        *) echo "$t${h:+ $h}${p:+ $p}" ;;
      esac
    done < "$m" > "$m.new" && mv "$m.new" "$m"
  done
}
mkdir -p "$T/digest"; ln -s "$(command -v md5sum)" "$(command -v cksum)" "$T/digest/"
for tool in md5 cksum; do
  mkroot "$R0"; ORIG=$(snap "$R0" system)
  installs "$tool backup: openssl" "$R0" "$O"
  legacy $tool
  check "$tool backup: manifest rewritten" grep -qx "hash $tool" "$(ls "$R0"/data/kktls-backup/0001-*/manifest)"
  want="cksum"; [ $tool = md5 ] && want="md5sum"
  KK_SH=$DASH KK_PATH=$ND refused "$tool backup: restore without $want" "$R0" "$R"
  check "$tool backup: the refusal names $want" grep -q "has $tool digests and this shell has no $want" "$T/out"
  check "$tool backup: not called damaged" sh -c "! grep -q 'no copy whose files match' '$T/out'"
  # busybox sh with the host's tool on PATH (the host busybox has md5sum but no cksum applet)
  KK_PATH=$T/digest installs "$tool backup: restore where $want exists" "$R0" "$R"
  check "$tool backup: /system identical after restore" [ "$ORIG" = "$(snap "$R0" system)" ]
done
mkroot "$R0"
installs "unknown digest: openssl" "$R0" "$O"
legacy sha1
refused "unknown digest: restore" "$R0" "$R"
check "unknown digest: the refusal says so" grep -q "names no known digest ('hash sha1')" "$T/out"

# the second copy is renamed only when its manifest equals the original: a cp that leaves the copy's manifest short
# (header only: every remaining F line still verifies) loses the second copy with a warning
mkdir -p "$T/shortcp"
cat > "$T/shortcp/cp" <<EOF
#!$DASH
"$BB" cp "\$@" || exit \$?
for last; do :; done
case \$last in */.tmp-*) "$BB" head -n 5 "\$last/manifest" > "\$last/m" && "$BB" mv "\$last/m" "\$last/manifest" ;; esac
EOF
chmod 0755 "$T/shortcp/cp"
mkroot "$R0"
KK_SH=$DASH KK_PATH=$T/shortcp:$ND installs "short manifest copy: openssl" "$R0" "$O"
check "short manifest copy: warned" grep -q 'WARNING: no second backup copy in /sdcard/kktls-backup' "$T/out"
check "short manifest copy: no second copy, no leftover" none "$R0"/sdcard/kktls-backup/0001-* "$R0"/sdcard/kktls-backup/.tmp-*
check "short manifest copy: /data backup intact" sh -c "ls -d '$R0'/data/kktls-backup/0001-*/manifest > /dev/null"

# chcon on PATH is preferred over the helper
mkroot "$R0"; : > "$LOG"
KK_PATH=$T/chcon installs "openssl with chcon" "$R0" "$O"
check "chcon used, helper not" sh -c "grep -q '^chcon ' '$LOG' && ! grep -q '^util ' '$LOG'"

# ---- install-adb.sh against a stub adb ------------------------------------------------------------------------------
# The "device" is a fake root entered with `unshare -r chroot` (root = uid 0 there, absolute device paths), with the
# host's static busybox as /bin and as the pushed busybox, getprop/chcon stand-ins in /system/bin, and /sdcard a
# symlink to /data/media/0 as on a 4.4 emulator. The zips carry statically linked host helpers (no host paths inside).
ADB_SH=$REL_DIR/install-adb.sh; [ -f "$ADB_SH" ] || ADB_SH=$REL_DIR/tools/install-adb.sh
if file -L "$BB" | grep -q 'statically linked'; then
  mkdir -p "$T/sbin" "$T/adbbin"
  cc -O1 -std=gnu99 -static -o "$T/sbin/kktls-util" "$SYM/kktls-util.c"
  cc -O1 -std=gnu99 -static -o "$T/sbin/kktls-symcheck" "$SYM/kktls-symcheck.c"
  rm -rf "$T/in-adb"; cp -r "$IN" "$T/in-adb"
  for t in android-4.4.2_r2 android-4.4.4_r2; do
    for a in armeabi-v7a x86; do cp "$T/sbin/kktls-util" "$T/sbin/kktls-symcheck" "$T/in-adb/$t/helpers/$a/"; done
    (cd "$T/in-adb/$t/helpers" && find . -type f ! -name SHA256SUMS | sed 's#^\./##' | sort | xargs sha256sum > SHA256SUMS)
  done
  "$MK" --in "$T/in-adb" --release v9 --cacerts "$T/cacerts" --conscrypt-notice "$T/cnotice" --out "$T/za" > "$T/mka.log"
  cat > "$T/adbbin/adb" <<'EOF'
#!/usr/bin/env bash
# stub adb: the device is the fake root $KKTLS_ADB_ROOT; every call is logged to $KKTLS_ADB_LOG
R=$KKTLS_ADB_ROOT
[ "${1:-}" = -s ] && shift 2
c=${1:-}; shift || true
echo "$c $*" >> "$KKTLS_ADB_LOG"
[ ! -e "$R/gone" ] || { echo "error: device 'fake' not found" >&2; exit 1; }  # the device was unplugged
case $c in
  root|remount|wait-for-device|reboot) exit 0 ;;
  push) case $2 in */zip[0-9]*) [ ! -e "$R/pushfail" ] || exit 1 ;; esac
        if [ -d "$R$2" ]; then cp -r "$1" "$R$2/"; else cp -r "$1" "$R$2"; fi ;;
  shell) case "$*" in stop|start) exit 0 ;; *kk_main*) [ ! -e "$R/vanish" ] || { : > "$R/gone"; exit 1; } ;; esac
         cmd=$*  # /jbrm: rm refuses -f like the Android 4.1 toolbox (a function: busybox sh prefers its own applets)
         [ ! -e "$R/jbrm" ] || cmd='rm() { case $1 in -*f*) echo "rm: invalid option -- f" >&2; return 1 ;; esac; command rm "$@"; }; '$cmd
         exec unshare -rm sh -c 'mount --bind /dev/null "$1/dev/null" && exec chroot "$1" /bin/busybox env -i \
           PATH=/bin:/system/bin /bin/sh -c "$2"' sh "$R" "$cmd" ;;
  *) exit 1 ;;
esac
EOF
  chmod 0755 "$T/adbbin/adb"
  mkdev() { # fake device root for the stub
    mkroot "$@"
    local r=$1
    mkdir -p "$r/bin" "$r/dev" "$r/system/bin" "$r/data/local/tmp" "$r/data/media/0"; : > "$r/dev/null"
    cp "$BB" "$r/bin/busybox"; unshare -r chroot "$r" /bin/busybox --install -s /bin
    rm -rf "$r/sdcard"; ln -s data/media/0 "$r/sdcard"; ln -s /bin/busybox "$r/system/bin/sh"
    printf '#!/bin/sh\nawk -F= -v k="$1" '"'"'$1 == k { sub(/^[^=]*=/, ""); v = $0 } END { print v }'"'"' /system/build.prop\n' \
      > "$r/system/bin/getprop"
    printf '#!/bin/sh\nctx=$1; shift\nfor p; do echo "chcon $ctx $p" >> /chcon.log; done\n' > "$r/system/bin/chcon"
    chmod 0755 "$r/system/bin/getprop" "$r/system/bin/chcon"
  }
  ZA=$T/za RA=$T/adbroot ALOG=$T/adb.log
  adbrun() { # install-adb.sh args... -> exit status; output in $T/aout
    local rc=0
    : > "$ALOG"
    PATH=$T/adbbin:$PATH KKTLS_ADB_ROOT=$RA KKTLS_ADB_LOG=$ALOG "$ADB_SH" -s fake --busybox "$BB" "$@" > "$T/aout" 2>&1 || rc=$?
    return $rc
  }
  aexit() { # label expected-rc args...
    local l=$1 want=$2 rc=0; shift 2
    adbrun "$@" || rc=$?
    if [ "$rc" = "$want" ]; then ok; else bad "$l: exit $rc, want $want"; sed 's/^/  /' "$T/aout"; fi
  }

  mkdev "$RA"; ORIG=$(snap "$RA" system)
  aexit "adb: openssl, cacerts, java, conscrypt in one run" 0 --no-reboot \
    "$ZA/kktls-openssl-4.4-x86-v9.zip" "$ZA/kktls-cacerts-v9.zip" "$ZA/kktls-java-4.4.2-x86-v9.zip" "$ZA/kktls-conscrypt-x86-v9.zip"
  check "adb: our libssl installed" cmp -s "$RA/system/lib/libssl.so" "$T/fx/ours.so"
  check "adb: markers written" sh -c "[ \"\$(cat '$RA/system/etc/kktls/java.version')\" = v9 ] && [ -f '$RA/system/etc/kktls/openssl.version' ]"
  check "adb: D files installed" [ -f "$RA/system/framework/kktls-conscrypt.jar" ]
  check "adb: core.odex removed" [ ! -e "$RA/system/framework/core.odex" ]
  check "adb: dalvik-cache wiped" [ -z "$(ls "$RA/data/dalvik-cache")" ]
  check "adb: four backups in /data" [ "$(ls -d "$RA"/data/kktls-backup/[0-9]*/manifest | wc -l)" = 4 ]
  check "adb: second copies on /sdcard (data/media/0)" [ "$(ls -d "$RA"/data/media/0/kktls-backup/[0-9]*/manifest | wc -l)" = 4 ]
  check "adb: chcon labels every payload file" grep -q "chcon u:object_r:system_file:s0 /system/lib/libssl.so.kktls-new" "$RA/chcon.log"
  check "adb: framework stopped, no reboot" sh -c "grep -qx 'shell stop' '$ALOG' && ! grep -q '^reboot' '$ALOG'"
  check "adb: device work dir removed" [ ! -e "$RA/data/local/tmp/kktls-adb" ]
  check "adb: installer output shown" grep -q 'installed: ' "$T/aout"
  aexit "adb: restore" 0 --restore "$ZA/kktls-restore-v9.zip"
  check "adb: /system identical after restore" [ "$ORIG" = "$(snap "$RA" system)" ]
  check "adb: reboot by default" grep -qx 'reboot ' "$ALOG"

  # Android 4.1: toolbox rm has no -f (rm -rf fails); a stale work dir from an interrupted run is on the device. Two
  # zips in one run must each run their own scripts (a push into a stale dir nests and would run the old ones).
  jbrm() { : > "$1/jbrm"; }  # stub adb: rm of the device shell refuses -f like the 4.1 toolbox
  mkdev "$RA" ro.build.version.release=4.1.2; jbrm "$RA"; ORIG=$(snap "$RA" system)
  mkdir -p "$RA/data/local/tmp/kktls-adb/zip1/kktls" "$RA/data/local/tmp/kktls-adb/zip/kktls"
  echo 'kk_main() { echo STALE; }' > "$RA/data/local/tmp/kktls-adb/zip1/kktls/install.sh"
  aexit "adb 4.1: cacerts over a stale work dir" 0 --no-reboot "$ZA/kktls-cacerts-v9.zip"
  check "adb 4.1: the zip's own scripts ran" sh -c "grep -q 'installed: 3 files' '$T/aout' && ! grep -q STALE '$T/aout'"
  check "adb 4.1: not labelled (no SELinux)" sh -c "grep -q 'files are not labelled' '$T/aout' && [ ! -s '$RA/chcon.log' ]"
  check "adb 4.1: work dir removed" [ ! -e "$RA/data/local/tmp/kktls-adb" ]
  aexit "adb 4.1: restore" 0 --no-reboot --restore "$ZA/kktls-restore-v9.zip"
  check "adb 4.1: /system identical after restore" [ "$ORIG" = "$(snap "$RA" system)" ]
  mkdev "$RA"; jbrm "$RA"
  aexit "adb: two zips in one run with a toolbox rm without -f" 0 --no-reboot "$ZA/kktls-openssl-4.4-x86-v9.zip" "$ZA/kktls-cacerts-v9.zip"
  check "adb: both markers" sh -c "[ -f '$RA/system/etc/kktls/openssl.version' ] && [ -f '$RA/system/etc/kktls/cacerts.version' ]"

  # SELinux enforcing: setenforce 0 for the run, 1 after it (also after a refusal); a refused setenforce stops the run
  selinux() { # root: getenforce/setenforce stand-ins; /enforce holds the mode, /setenforce.fail refuses setenforce
    local r=$1
    echo Enforcing > "$r/enforce"
    printf '#!/bin/sh\ncat /enforce\n' > "$r/system/bin/getenforce"
    printf '#!/bin/sh\n[ -e /setenforce.fail ] && exit 1\necho "setenforce $1" >> /selinux.log\n[ "$1" = 0 ] && echo Permissive > /enforce || echo Enforcing > /enforce\n' \
      > "$r/system/bin/setenforce"
    chmod 0755 "$r"/system/bin/getenforce "$r"/system/bin/setenforce
  }
  mkdev "$RA"; selinux "$RA"
  aexit "adb: enforcing device" 0 --no-reboot "$ZA/kktls-openssl-4.4-x86-v9.zip"
  check "adb: permissive for the run, enforcing after" sh -c "[ \"\$(tr '\n' ' ' < '$RA/selinux.log')\" = 'setenforce 0 setenforce 1 ' ] && grep -qx Enforcing '$RA/enforce'"
  check "adb: openssl installed on the enforcing device" [ -f "$RA/system/etc/kktls/openssl.version" ]
  mkdev "$RA"; selinux "$RA"
  aexit "adb: enforcing, refusal" 1 --no-reboot "$ZA/kktls-conscrypt-x86-v9.zip"
  check "adb: enforcing again after a refusal" grep -qx Enforcing "$RA/enforce"
  mkdev "$RA"; selinux "$RA"; : > "$RA/setenforce.fail"
  aexit "adb: enforcing, setenforce refused" 2 --no-reboot "$ZA/kktls-openssl-4.4-x86-v9.zip"
  check "adb: nothing installed without setenforce" [ ! -e "$RA/system/etc/kktls" ]

  # the EXIT trap cleans up after a die, and copes with a device that is gone
  mkdev "$RA"; selinux "$RA"; : > "$RA/pushfail"
  aexit "adb: zip push fails" 2 --no-reboot "$ZA/kktls-openssl-4.4-x86-v9.zip"
  check "adb: push failure: enforcing again, work dir removed" sh -c "grep -qx Enforcing '$RA/enforce' && [ ! -e '$RA/data/local/tmp/kktls-adb' ]"
  check "adb: push failure: says why" grep -q 'cannot push' "$T/aout"
  mkdev "$RA"; selinux "$RA"; : > "$RA/vanish"
  aexit "adb: device gone during the install" 1 --no-reboot "$ZA/kktls-openssl-4.4-x86-v9.zip"
  check "adb: device gone: trap warns and ends cleanly" sh -c "grep -q 'could not set SELinux enforcing again' '$T/aout' && ! grep -Eq 'unbound|command not found|syntax error' '$T/aout'"
  check "adb: device gone: one cleanup only" [ "$(grep -c '^shell rm -r /data/local/tmp/kktls-adb$' "$ALOG")" = 1 ]

  mkdev "$RA"; before=$(snap "$RA")
  aexit "adb: conscrypt without java refused" 1 --no-reboot "$ZA/kktls-conscrypt-x86-v9.zip"
  check "adb: refusal says REFUSED" grep -q 'REFUSED: install the kktls java zip first' "$T/aout"
  check "adb: refusal starts the framework again" sh -c "grep -qx 'shell start' '$ALOG' && grep -q 'nothing was installed' '$T/aout'"
  rm -f "$RA/chcon.log"
  check "adb: refusal leaves the device unchanged" [ "$before" = "$(snap "$RA")" ]
  aexit "adb: java without openssl refused" 1 --no-reboot "$ZA/kktls-java-4.4.2-x86-v9.zip"
  check "adb: java refusal names the openssl zip" grep -q 'install the kktls openssl zip first' "$T/aout"
  aexit "adb: second zip refused after the first installed" 1 --no-reboot \
    "$ZA/kktls-openssl-4.4-x86-v9.zip" "$ZA/kktls-java-4.4.4-x86-v9.zip"
  check "adb: partial run says reboot" grep -q '1 zip(s) of this run are installed' "$T/aout"
  check "adb: first zip of the partial run is installed" [ -f "$RA/system/etc/kktls/openssl.version" ]

  mkdev "$RA" ro.cm.version=11-20140804-NIGHTLY-hammerhead; before=$(snap "$RA")
  aexit "adb: openssl on a CM build refused" 1 --no-reboot "$ZA/kktls-openssl-4.4-x86-v9.zip"
  rm -f "$RA/chcon.log"
  check "adb: CM refusal leaves the device unchanged" [ "$before" = "$(snap "$RA")" ]

  aexit "adb: restore zip without --restore" 2 "$ZA/kktls-restore-v9.zip"
  aexit "adb: --restore with an install zip" 2 --restore "$ZA/kktls-openssl-4.4-x86-v9.zip"
  echo "not a zip" > "$T/bad.zip"
  aexit "adb: not a zip" 2 "$T/bad.zip"
  (cd "$T/fx" && zip -q "$T/other.zip" dex.jar)
  aexit "adb: a zip without kktls/zip.conf" 2 "$T/other.zip"
  check "adb: usage errors never reach the device" [ ! -s "$ALOG" ]
  aexit "adb: missing --busybox file" 2 --busybox "$T/nonexistent" "$ZA/kktls-openssl-4.4-x86-v9.zip"
  aexit "adb: no zip" 2 --no-reboot
else
  echo "run-tests.sh: $BB is not static, install-adb.sh tests skipped"; bad "install-adb.sh tests need a static busybox"
fi

# ---- real release output --------------------------------------------------------------------------------------------
if [ ${#REAL[@]} = 4 ]; then
  jbargs=() nz=10 nj=0 nd=0
  if [ ${#RJB[@]} != 0 ]; then
    # per JB base 2 openssl zips; a base with java lines also 2 java zips (ARM and x86), one with layer D 2 conscrypt zips
    nj=$(cat "${RJB[0]}"/4.[1-3]/armeabi-v7a/BUILD-INFO.txt | grep -c '^gate ') || true
    nd=$(cat "${RJB[0]}"/4.[1-3]/armeabi-v7a/BUILD-INFO.txt | grep -c '^conscrypt lib/libkktls_conscrypt_jni.so$') || true
    jbargs=(--jb "${RJB[0]}"); nz=$((10 + 2 * $(ls -d "${RJB[0]}"/4.[1-3] | wc -l) + 2 * nj + 2 * nd))
  fi
  "$MK" --in "${REAL[0]}" --release t1 --cacerts "${REAL[1]}" --conscrypt-notice "${REAL[2]}" --out "$T/r1" "${jbargs[@]}" \
    > "$T/r1.log"
  "$MK" --in "${REAL[0]}" --release t1 --cacerts "${REAL[1]}" --conscrypt-notice "${REAL[2]}" --out "$T/r2" "${jbargs[@]}" \
    > /dev/null
  check "real: $nz zips" [ "$(wc -l < "$T/r1/SHA256SUMS")" = "$nz" ]
  check "real: $nj java zips per JB ABI" sh -c "[ \"\$(grep -c 'kktls-java-4\.[123]-armeabi-v7a-t1' '$T/r1/SHA256SUMS')\" = $nj ] && [ \"\$(grep -c 'kktls-java-4\.[123]-x86-t1' '$T/r1/SHA256SUMS')\" = $nj ]"
  check "real: $nd conscrypt zips per JB ABI" sh -c "[ \"\$(grep -c 'kktls-conscrypt-4\.[123]-armeabi-v7a-t1' '$T/r1/SHA256SUMS')\" = $nd ] && [ \"\$(grep -c 'kktls-conscrypt-4\.[123]-x86-t1' '$T/r1/SHA256SUMS')\" = $nd ]"
  check "real: byte-identical across two runs" cmp -s "$T/r1/SHA256SUMS" "$T/r2/SHA256SUMS"
  mkroot "$R0"
  cp "${REAL[3]}/libssl.so" "${REAL[3]}/libcrypto.so" "$R0/system/lib/"; chmod 0644 "$R0"/system/lib/*.so
  ORIG=$(snap "$R0" system); : > "$LOG"
  for z in kktls-openssl-4.4-x86-t1 kktls-java-4.4.2-x86-t1 kktls-conscrypt-x86-t1 kktls-cacerts-t1; do
    KK_PATH=$T/chcon installs "real: $z" "$R0" "$T/r1/$z.zip"
  done
  check "real: every installed file labelled" [ "$(grep -c '\.kktls-new$' "$LOG")" -ge 14 ]
  KK_PATH=$T/chcon installs "real: restore" "$R0" "$T/r1/kktls-restore-t1.zip"
  check "real: /system identical after restore" [ "$ORIG" = "$(snap "$R0" system)" ]
  cp "$T/r1/SHA256SUMS" "$T/real-SHA256SUMS"; sed 's/^/  real zip: /' "$T/real-SHA256SUMS"
  if [ -n "$SDK" ]; then
    rm -rf "$R0"; mkdir -p "$R0/data/dalvik-cache" "$R0/sdcard"; cp -r "$SDK" "$R0/system"; chmod -R u+w "$R0/system"
    sv=$(sed -n 's/^ro.build.version.release=//p' "$R0/system/build.prop")
    sa=$(sed -n 's/^ro.product.cpu.abi=//p' "$R0/system/build.prop")
    echo "  sdk system: release $sv, abi $sa, id $(sed -n 's/^ro.build.id=//p' "$R0/system/build.prop"),"\
      "$(ls "$R0"/system/framework/*.odex "$R0"/system/app/*.odex "$R0"/system/priv-app/*.odex 2> /dev/null | wc -l) .odex"
    ORIG=$(snap "$R0" system); : > "$LOG"
    for z in kktls-openssl-4.4-$sa-t1 kktls-cacerts-t1 kktls-java-$sv-$sa-t1 kktls-conscrypt-$sa-t1; do
      KK_PATH=$T/chcon installs "sdk: $z" "$R0" "$T/r1/$z.zip"
      grep -E 'dex check|backup:|installed:' "$T/out" | sed 's/^ui_print /    /'
    done
    check "sdk: core.odex removed" [ ! -e "$R0/system/framework/core.odex" ]
    check "sdk: CA store replaced" cmp -s "$R0/system/etc/security/cacerts/$(ls "${REAL[1]}" | head -n 1)" "${REAL[1]}/$(ls "${REAL[1]}" | head -n 1)"
    KK_PATH=$T/chcon installs "sdk: restore" "$R0" "$T/r1/kktls-restore-t1.zip"
    check "sdk: /system identical after restore" [ "$ORIG" = "$(snap "$R0" system)" ]
  fi
  for jd in ${RJB[0]:+"${RJB[0]}"/4.[1-3]}; do
    b=${jd##*/} st=$RJB_STOCK/${jd##*/}/x86 jz=$T/r1/kktls-java-${jd##*/}-x86-t1.zip rv=${jd##*/}.9
    dz=$T/r1/kktls-conscrypt-${jd##*/}-x86-t1.zip
    [ -f "$st/libssl.so" ] && [ -f "$st/libcrypto.so" ] || { bad "real jb $b: no stock x86 libs in $st"; continue; }
    if [ -f "$jz" ]; then  # the java zip's release (a point-release gate) or any <base>.x
      rv=$(unzip -p "$jz" kktls/zip.conf | sed -n 's/^android=//p'); [ "$rv" != "$b" ] || rv=$b.9
      mkroot "$R0" ro.build.version.release="$rv" jb=1
    else
      mkroot "$R0" ro.build.version.release="$rv"
    fi
    cp "$st/libssl.so" "$st/libcrypto.so" "$R0/system/lib/"; chmod 0644 "$R0"/system/lib/*.so
    ORIG=$(snap "$R0" system); : > "$LOG"
    refused "real jb $b: the 4.4 openssl zip" "$R0" "$T/r1/kktls-openssl-4.4-x86-t1.zip"
    for z in "kktls-openssl-$b-x86-t1" kktls-cacerts-t1; do
      KK_PATH=$T/chcon installs "real jb $b: $z" "$R0" "$T/r1/$z.zip"
    done
    check "real jb $b: libssl is the base's build" cmp -s "$R0/system/lib/libssl.so" "$jd/x86/lib/libssl.so"
    if [ -f "$jz" ]; then
      KK_PATH=$T/chcon installs "real jb $b: ${jz##*/}" "$R0" "$jz"
      check "real jb $b: core.jar, libjavacore.so are the base's build, core.odex removed" sh -c "cmp -s '$R0/system/framework/core.jar' '$jd/x86/framework/core.jar' && cmp -s '$R0/system/lib/libjavacore.so' '$jd/x86/lib/libjavacore.so' && [ ! -e '$R0/system/framework/core.odex' ]"
    fi
    for a in armeabi-v7a x86; do  # each conscrypt zip installs exactly the base's layer D files of its ABI
      z=$T/r1/kktls-conscrypt-$b-$a-t1.zip
      [ -f "$z" ] || continue
      check "real jb $b $a: the conscrypt zip's payload is the BUILD-INFO conscrypt files, byte for byte" sh -c "[ \"\$(unzip -Z1 '$z' | sed -n 's#^system/##p' | sort)\" = \"\$(sed -n 's/^conscrypt //p' '$jd/$a/BUILD-INFO.txt' | sort)\" ] && for f in \$(sed -n 's/^conscrypt //p' '$jd/$a/BUILD-INFO.txt'); do unzip -p '$z' system/\$f | cmp -s - '$jd/$a/'\$f || exit 1; done"
    done
    if [ -f "$dz" ]; then  # layer D over the java zip of the same release
      refused "real jb $b: the 4.4 conscrypt zip" "$R0" "$T/r1/kktls-conscrypt-x86-t1.zip"
      KK_PATH=$T/chcon installs "real jb $b: ${dz##*/}" "$R0" "$dz"
      check "real jb $b: the three layer D files are the base's build" sh -c "cmp -s '$R0/system/framework/kktls-conscrypt.jar' '$jd/x86/framework/kktls-conscrypt.jar' && cmp -s '$R0/system/framework/kktls-sslfilter.jar' '$jd/x86/framework/kktls-sslfilter.jar' && cmp -s '$R0/system/lib/libkktls_conscrypt_jni.so' '$jd/x86/lib/libkktls_conscrypt_jni.so'"
    fi
    KK_PATH=$T/chcon installs "real jb $b: restore" "$R0" "$T/r1/kktls-restore-t1.zip"
    check "real jb $b: /system identical after restore" [ "$ORIG" = "$(snap "$R0" system)" ]
  done
elif [ -n "$SDK" ] || [ ${#RJB[@]} != 0 ]; then
  echo "run-tests.sh: --sdk-system and --jb need --real" >&2; exit 2
fi

[ -z "${KKTLS_TEST_SHOW:-}" ] || cat "$T/out"
echo "installer tests: $pass passed, $fail failed"
[ $fail = 0 ]
