#!/usr/bin/env bash
# Tests of kktls-symcheck (plan 20261015-android-kitkat-tls12-publish, Task 8).
#
#   test.sh [--bin PATH]... [--real OURS_LIB_DIR STOCK_LIB_DIR]...
#
# Always builds kktls-symcheck.c for the host with $CC (default cc; ASan+UBSan when the compiler has them) and runs
# the case table on it, plus a truncation sweep and a mutation fuzz of a fixture. Each --bin (a release build of the
# helper, e.g. out/kktls/<tag>/helpers/<abi>/kktls-symcheck) runs the case table and the truncation sweep too: an ARM
# binary through ${QEMU_ARM:-qemu-arm} (or binfmt_misc when that is not in PATH), an x86 one directly.
# --real compares the libssl.so/libcrypto.so of two directories (ours, stock AOSP) with allow-missing-libssl.txt.
# Fixtures are written by mkfixtures.py (no cross toolchain needed). Exit 0 all pass, 1 a failure, 2 usage.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ALLOW=$HERE/allow-missing-libssl.txt
BINS=() REAL=()
while [ $# -gt 0 ]; do
  case $1 in
    --bin) [ $# -ge 2 ] || { echo "test.sh: --bin needs a path" >&2; exit 2; }
           [ -f "$2" ] || { echo "test.sh: --bin $2: no such file" >&2; exit 2; }
           BINS+=("$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"); shift 2 ;;
    --real) [ $# -ge 3 ] || { echo "test.sh: --real needs two directories" >&2; exit 2; }
            REAL+=("$2" "$3"); shift 3 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "test.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
F=$T/fx
python3 -I "$HERE/mkfixtures.py" "$F"

CC=${CC:-cc}
SAN="-fsanitize=address,undefined -fno-sanitize-recover=all"
# shellcheck disable=SC2086  # $SAN is a flag list
if ! echo 'int main(void){return 0;}' | $CC $SAN -x c -o "$T/san-probe" - 2>/dev/null; then
  echo "note: $CC has no ASan/UBSan, host build without sanitizers"; SAN=
fi
# shellcheck disable=SC2086
$CC -O1 -g -std=c99 -Wall -Wextra -Werror $SAN -o "$T/kktls-symcheck-host" "$HERE/kktls-symcheck.c"
export ASAN_OPTIONS=detect_leaks=0:exitcode=99 UBSAN_OPTIONS=halt_on_error=1:exitcode=98:print_stacktrace=1

PASS=0 FAILS=0 RUN=()
fail() { echo "FAIL [$LABEL] $*"; FAILS=$((FAILS + 1)); }
# x WANT_RC ARGS...: run the binary under test; stdout/stderr in $T/out, $T/err
x() {
  local want=$1 rc=0; shift
  "${RUN[@]}" "$@" > "$T/out" 2> "$T/err" || rc=$?
  if [ "$rc" = "$want" ]; then PASS=$((PASS + 1)); else fail "rc $rc, want $want: $* ($(head -c 300 "$T/err"))"; fi
}
err_is() { if [ "$(cat "$T/err")" = "$1" ]; then PASS=$((PASS + 1)); else fail "stderr: $(head -c 300 "$T/err") want: $1"; fi; }
err_has() { if grep -qx -- "$1" "$T/err"; then PASS=$((PASS + 1)); else fail "stderr lacks line '$1': $(head -c 300 "$T/err")"; fi; }
err_lines() { local n; n=$(wc -l < "$T/err"); if [ "$n" = "$1" ]; then PASS=$((PASS + 1)); else fail "stderr has $n lines, want $1"; fi; }
out_is() { if [ "$(cat "$T/out")" = "$1" ]; then PASS=$((PASS + 1)); else fail "stdout: $(head -c 300 "$T/out") want: $1"; fi; }

LIST_FULL='kk_abs object
kk_fa function
kk_fb function
kk_fc function
kk_ifunc function
kk_obj object
kk_tls tls
kk_weak function'

cases() {
  local a=$F/full-arm.so
  # superset or not
  x 0 "$a" "$a"; err_is ""; out_is ""
  x 1 "$F/minus-arm.so" "$a"; err_has kk_fb; err_lines 2
  err_has "kktls-symcheck: 1 export(s) of $a missing in $F/minus-arm.so"
  x 0 "$a" "$F/minus-arm.so"
  x 1 "$F/minus2-arm.so" "$a"; err_has kk_fb; err_has kk_obj; err_lines 3
  x 1 "$F/kind-arm.so" "$a"; err_has "kk_obj (object in $a, another kind in $F/kind-arm.so)"; err_lines 2
  x 1 "$a" "$F/kind-arm.so"; err_has "kk_obj (function in $F/kind-arm.so, another kind in $a)"
  x 0 "$F/ifunc-arm.so" "$a"; x 0 "$a" "$F/ifunc-arm.so"
  x 0 "$F/strong-arm.so" "$a"; x 0 "$a" "$F/strong-arm.so"
  x 1 "$F/hiddenfb-arm.so" "$a"; err_has kk_fb; err_lines 2
  x 1 "$F/undeffb-arm.so" "$a"; err_has kk_fb; err_lines 2
  x 0 "$a" "$F/hiddenfb-arm.so"; x 0 "$a" "$F/undeffb-arm.so"
  x 0 "$F/dup-arm.so" "$a"
  x 1 "$a" "$F/dup-arm.so"; err_has "kk_obj (function in $F/dup-arm.so, another kind in $a)"; err_lines 2
  x 2 "$F/empty-arm.so" "$a"; err_has "kktls-symcheck: $F/empty-arm.so exports nothing"   # zero exports: refused, not compared
  x 2 "$a" "$F/empty-arm.so"; err_has "kktls-symcheck: $F/empty-arm.so exports nothing"; x 2 "$F/empty-arm.so" "$F/empty-arm.so"
  x 0 "$F/full-x86.so" "$F/full-x86.so"
  # --allow-missing
  printf 'kk_fb\n' > "$T/allow1"
  printf '# comment\r\n\r\n  \nkk_obj \r\nkk_fb' > "$T/allow2"   # CRLF, blanks, trailing blank, no final newline
  printf 'kk_\0fb\n' > "$T/allow-nul"; : > "$T/allow-empty"
  x 0 --allow-missing "$T/allow1" "$F/minus-arm.so" "$a"; err_is ""
  x 0 --allow-missing "$T/allow2" "$F/minus2-arm.so" "$a"
  x 1 --allow-missing "$T/allow1" "$F/minus2-arm.so" "$a"; err_has kk_obj; err_lines 2
  x 1 --allow-missing "$T/allow-empty" "$F/minus-arm.so" "$a"; err_has kk_fb
  x 2 --allow-missing "$T/allow-nul" "$F/minus-arm.so" "$a"
  x 2 --allow-missing "$T/nope" "$a" "$a"
  x 2 --allow-missing "$T/allow1" "$a" "$F/empty-arm.so"; err_has "kktls-symcheck: $F/empty-arm.so exports nothing"
  # --list
  x 0 --list "$a"; out_is "$LIST_FULL"; err_is ""
  x 0 --list "$F/dup-arm.so"; out_is "$(printf '%s\n' "$LIST_FULL" | sed 's/^kk_obj object$/kk_obj object\nkk_obj function/')"
  x 0 --list "$F/empty-arm.so"; out_is ""
  # usage
  x 2; x 2 "$a"; x 2 "$a" "$a" "$a"; x 2 --list; x 2 --bogus "$a" "$a"; x 2 --allow-missing "$T/allow1" "$a"
  x 2 --list "$a" "$a"
  # bad input, as either library
  local b
  for b in "$F"/bad-*.so; do x 2 "$a" "$b"; x 2 "$b" "$a"; x 2 --list "$b"; done
  printf 'not an ELF file\n' > "$T/text"; : > "$T/zero"
  x 2 "$a" "$T/text"; x 2 "$a" "$T/zero"; x 2 "$a" "$T/missing"; x 2 "$a" "$T"
  x 2 "$a" "$F/full-x86.so"; x 2 "$F/full-x86.so" "$a"
  # every truncated prefix of a fixture is bad input (the section headers are at the end)
  local n i size; size=$(wc -c < "$a")
  for i in $(seq 0 $((size - 1))); do
    head -c "$i" "$a" > "$T/trunc"
    n=0; "${RUN[@]}" "$a" "$T/trunc" > /dev/null 2>&1 || n=$?
    [ "$n" = 2 ] || { fail "truncated to $i bytes: rc $n, want 2"; break; }
  done
  [ "$n" = 2 ] && PASS=$((PASS + 1))
  if [ ${#REAL[@]} -gt 0 ]; then
    for i in $(seq 0 2 $((${#REAL[@]} - 1))); do
      local o=${REAL[$i]} s=${REAL[$((i + 1))]}
      x 0 --allow-missing "$ALLOW" "$o/libssl.so" "$s/libssl.so"
      x 1 "$o/libssl.so" "$s/libssl.so"; err_lines $(( $(grep -cv '^#' "$ALLOW") + 1 ))
      x 0 "$o/libcrypto.so" "$s/libcrypto.so"
      x 1 "$o/libssl.so" "$o/libcrypto.so"   # the libcrypto exports are not in libssl
    done
  fi
}

# mutation fuzz on the sanitizer build: random byte changes in the header/section-header area and anywhere else
fuzz() {
  python3 -I - "$F/full-arm.so" "$T/fuzz" <<'EOF'
import os, random, sys
src, out = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
os.makedirs(out, exist_ok=True)
rng = random.Random(20261015)
for i in range(1500):
    b = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        pos = rng.choice([rng.randrange(52), rng.randrange(len(b) - 200, len(b)), rng.randrange(len(b))])
        b[pos] = rng.choice([0, 0xFF, 0x7F, 0x80, rng.randrange(256)])
    open(os.path.join(out, "m%04d.so" % i), "wb").write(b)
EOF
  local m n bad=0
  for m in "$T"/fuzz/*.so; do
    n=0; "${RUN[@]}" "$F/full-arm.so" "$m" > /dev/null 2> "$T/ferr" || n=$?
    case $n in 0|1|2) ;; *) fail "fuzz $(basename "$m"): rc $n $(head -c 300 "$T/ferr")"; bad=1; break ;; esac
    n=0; "${RUN[@]}" --list "$m" > /dev/null 2> "$T/ferr" || n=$?
    case $n in 0|2) ;; *) fail "fuzz --list $(basename "$m"): rc $n $(head -c 300 "$T/ferr")"; bad=1; break ;; esac
  done
  [ $bad = 0 ] && PASS=$((PASS + 1))
}

machine() { python3 -I -c 'import sys; d=open(sys.argv[1],"rb").read(20); print(d[18] | d[19] << 8)' "$1"; }

total_fail=0
LABEL=host RUN=("$T/kktls-symcheck-host")
cases; fuzz
echo "host ($CC${SAN:+, sanitizers}): $PASS passed, $FAILS failed"
total_fail=$((total_fail + FAILS))
for b in ${BINS[@]+"${BINS[@]}"}; do
  PASS=0 FAILS=0 LABEL=$b
  case $(machine "$b") in
    40) if command -v "${QEMU_ARM:-qemu-arm}" > /dev/null; then RUN=("${QEMU_ARM:-qemu-arm}" "$b"); else RUN=("$b"); fi ;;
    *) RUN=("$b") ;;
  esac
  cases
  echo "$b (${RUN[0]##*/}): $PASS passed, $FAILS failed"
  total_fail=$((total_fail + FAILS))
done
[ $total_fail = 0 ] && echo "PASS kktls-symcheck tests" || echo "FAIL kktls-symcheck tests ($total_fail failure(s))"
[ $total_fail = 0 ]
