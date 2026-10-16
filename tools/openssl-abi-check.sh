#!/bin/bash
# Host-side driver of openssl-abi-check.py: the ABI of a patched external/openssl against the stock one. Every path must
# lie under $KKTLS_AOSP_DIR, which the build container (tools/docker-image.sh aosp-build, or $KKTLS_BUILD_IMAGE) sees as
# /aosp; the AOSP 4.4 source tree is $KKTLS_AOSP_DIR/src. The ARM compiler of that tree runs only in the container.
#
#   KKTLS_AOSP_DIR=... openssl-abi-check.sh probe OPENSSL_TREE OUT.o
#       compile the struct probe (openssl-abi-check.py probe-source) against OPENSSL_TREE/include with the -D flags of
#       OPENSSL_TREE/build-config.mk, for ARM (the tree's arm-linux-androideabi-4.7, NDK android-9 sysroot)
#   KKTLS_AOSP_DIR=... openssl-abi-check.sh all OLD_LIBDIR NEW_LIBDIR OLD_TREE NEW_TREE OUTDIR [SCAN_ROOT ...]
#       symbols (old headers = OLD_TREE/include) + users (SCAN_ROOTs, default the product's system/ of
#       $KKTLS_TARGET_PRODUCT (default generic), prebuilt marks from symbols/system) + structs; allow list
#       tools/openssl-abi-allow.txt (symbols, structs); exit 1 if any part fails
#   KKTLS_AOSP_DIR=... openssl-abi-check.sh selftest [OPENSSL_TREE] [OUTDIR]
#       the ARM probe compile path: compiles the probe against OPENSSL_TREE (default $KKTLS_AOSP_DIR/src/external/openssl)
#       into OUTDIR (default $KKTLS_AOSP_DIR/abi/selftest), checks that the object holds every probe symbol and compares
#       with itself (PASS), then a mutant whose SSL3_STATE.client_random offset moved (FAIL expected) and a tree without
#       include/ (compile failure expected)
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[ -n "${KKTLS_AOSP_DIR:-}" ] && [ -d "$KKTLS_AOSP_DIR/src" ] || { echo "KKTLS_AOSP_DIR must hold the AOSP 4.4 tree in src/" >&2; exit 2; }
W=$(realpath "$KKTLS_AOSP_DIR")
PRODUCT=${KKTLS_TARGET_PRODUCT:-generic}
TOOLS=$(cd "$(dirname "$0")" && pwd)
PY="python3 -I $TOOLS/openssl-abi-check.py"
ALLOW=$TOOLS/openssl-abi-allow.txt
IMAGE=${KKTLS_BUILD_IMAGE:-}

under_w() { case $(realpath -m "$1") in "$W"/*) ;; *) echo "$1 is not under $W" >&2; exit 2 ;; esac; }

probe() {
  local tree out src cflags
  tree=$(realpath "$1"); out=$(realpath -m "$2")
  under_w "$tree"; under_w "$out"
  mkdir -p "$(dirname "$out")"
  src=${out%.o}.c
  rm -f "$out"
  # KKTLS_PROBE_ABSENT="Type.member ...": members the old base lacks (Jelly Bean: no ALPN, Channel ID or tls12 digests)
  local absent=() k
  for k in ${KKTLS_PROBE_ABSENT:-}; do absent+=(--absent "$k"); done
  $PY probe-source "${absent[@]}" > "$src"
  cflags=$(sed -n 's/^ *\(-D[A-Za-z0-9_]*\) *\\$/\1/p' "$tree/build-config.mk" | grep -v -x -- -DTERMIO | tr '\n' ' ')
  [ -n "$IMAGE" ] || IMAGE=$(sh "$TOOLS/docker-image.sh" aosp-build) || { echo "docker-image.sh aosp-build failed" >&2; return 1; }
  docker run --rm -u "$(id -u):$(id -g)" -v "$W:/aosp" "$IMAGE" \
    /aosp/src/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.7/bin/arm-linux-androideabi-gcc \
    --sysroot=/aosp/src/prebuilts/ndk/current/platforms/android-9/arch-arm -march=armv7-a -mfloat-abi=softfp \
    -fno-common -O0 $cflags -I "/aosp/${tree#$W/}/include" -c "/aosp/${src#$W/}" -o "/aosp/${out#$W/}" \
    2>&1 | sed "s#/aosp/#$W/#g" >&2 || true
  [ -s "$out" ] || { echo "probe compile failed for $tree" >&2; return 1; }
}

case ${1:-} in
  probe) shift; probe "$@" ;;
  all)
    shift
    old_lib=$1 new_lib=$2 old_tree=$3 new_tree=$4 out=$5; shift 5
    scans=("$@"); [ ${#scans[@]} -gt 0 ] || scans=("$W/src/out/target/product/$PRODUCT/system")
    rc=0
    echo "== symbols"; $PY symbols --old "$old_lib" --new "$new_lib" --old-headers "$old_tree/include" --allow "$ALLOW" || rc=1
    echo "== users";  args=(); for s in "${scans[@]}"; do args+=(--scan "$s"); done
    $PY users --old "$old_lib" --new "$new_lib" "${args[@]}" --symbols-root "$W/src/out/target/product/$PRODUCT/symbols/system" \
      || rc=1
    echo "== structs"; probe "$old_tree" "$out/old.o" && probe "$new_tree" "$out/new.o" &&
      $PY structs --old "$out/old.o" --new "$out/new.o" --allow "$ALLOW" || rc=1
    exit $rc ;;
  selftest)
    shift
    tree=${1:-$W/src/external/openssl}; out=${2:-$W/abi/selftest}
    under_w "$out"; mkdir -p "$out"; rm -f "$out"/*.o "$out"/*.c
    fail=0
    ok() { echo "  ok   $*"; }
    bad() { echo "  FAIL $*"; fail=1; }
    if probe "$tree" "$out/probe.o"; then
      ok "probe compiled for ARM against $tree"
      n_want=$($PY probe-source | grep -c '^char kktls_')
      n_have=$(${READELF:-readelf} -W -s "$out/probe.o" | grep -c ' OBJECT .* kktls_\(sz\|off\)__')
      [ "$n_want" = "$n_have" ] && ok "probe object holds all $n_want probe symbols" || bad "probe symbols: want $n_want, have $n_have"
      ${READELF:-readelf} -h "$out/probe.o" | grep -q 'Machine: *ARM' && ok "probe object is ARM" || bad "probe object is not ARM"
      $PY structs --old "$out/probe.o" --new "$out/probe.o" >/dev/null && ok "structs: probe vs itself PASS" ||
        bad "structs: probe vs itself"
      # mutant: the probe source with one member offset moved by 4 (rebuilt through the same compile path)
      mtree=$out/mutant-tree; rm -rf "$mtree"; mkdir -p "$mtree"
      cp "$tree/build-config.mk" "$mtree/"; cp -rL "$tree/include" "$mtree/include"
      sed -i 's/^\(\s*unsigned char client_random\[SSL3_RANDOM_SIZE\];\)/    int kktls_selftest_pad;\n\1/' "$mtree/include/openssl/ssl3.h"
      if ! grep -q kktls_selftest_pad "$mtree/include/openssl/ssl3.h"; then
        bad "mutant: client_random not found in $mtree/include/openssl/ssl3.h"
      elif probe "$mtree" "$out/mutant.o"; then
        mres=$($PY structs --old "$out/probe.o" --new "$out/mutant.o") && mrc=0 || mrc=$?
        [ "$mrc" = 1 ] && grep -q 'FAIL SSL3_STATE.client_random: offset' <<<"$mres" &&
          ok "structs: moved SSL3_STATE.client_random FAILs (rc=1)" || bad "structs: moved member not reported (rc=$mrc)"
      else bad "mutant probe did not compile"; fi
      rm -rf "$mtree"
    else bad "probe did not compile against $tree"; fi
    etree=$out/empty-tree; rm -rf "$etree"; mkdir -p "$etree"; cp "$tree/build-config.mk" "$etree/"
    if probe "$etree" "$out/empty.o" 2>/dev/null; then bad "probe compiled without include/"; else ok "probe without include/ fails"; fi
    rm -rf "$etree"
    echo "SELFTEST $([ $fail = 0 ] && echo PASS || echo FAIL) (openssl-abi-check.sh probe path)"
    exit $fail ;;
  *) sed -n '2,17p' "$0"; exit 2 ;;
esac
