#!/usr/bin/env bash
# Tests of kktls-util (has-entry, setcon, sha256).
#
#   test-util.sh [--bin PATH]...
#
# Builds kktls-util.c for the host with $CC (default cc; ASan+UBSan when available) and runs the case table on it;
# each --bin (a release build, out/kktls/<tag>/helpers/<abi>/kktls-util) runs the same table (ARM through
# ${QEMU_ARM:-qemu-arm} when present, else binfmt_misc). Zip fixtures come from python3 zipfile.
# setcon is checked for its exit codes only (a label write needs CAP_SYS_ADMIN; when the run has it, the label is
# read back). sha256: FIPS 180-2 known answers (empty, "abc", the 56-byte two-block message, one million 'a') and every
# length 0..200 (padding edges 55/56/63/64/119/120) against python3 hashlib. Exit 0 all pass, 1 a failure, 2 usage.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BINS=()
while [ $# -gt 0 ]; do
  case $1 in
    --bin) [ $# -ge 2 ] && [ -f "$2" ] || { echo "test-util.sh: --bin needs an existing file" >&2; exit 2; }
           BINS+=("$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"); shift 2 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "test-util.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
python3 -I - "$T" <<'EOF'
import sys, zipfile, os
d = sys.argv[1]
def mk(name, entries, comment=b""):
    with zipfile.ZipFile(os.path.join(d, name), "w") as z:
        for e in entries:
            z.writestr(e, b"x" * 10)
        z.comment = comment
mk("dex.jar", ["META-INF/MANIFEST.MF", "classes.dex"])
mk("nodex.jar", ["META-INF/MANIFEST.MF", "res/classes.dex", "classes.dex.txt"])
mk("comment.jar", ["classes.dex"], b"classes.dex PK\x05\x06 fake")
mk("empty.zip", [])
data = open(os.path.join(d, "dex.jar"), "rb").read()
open(os.path.join(d, "trunc.jar"), "wb").write(data[:-5])
open(os.path.join(d, "notzip.jar"), "wb").write(b"\x7fELF" + b"\0" * 100)
open(os.path.join(d, "zero.jar"), "wb").write(b"")
# a central directory offset pointing past the end-of-central-directory record
bad = bytearray(data); i = bad.rfind(b"PK\x05\x06"); bad[i+16:i+20] = (len(bad) + 100).to_bytes(4, "little")
open(os.path.join(d, "badoff.jar"), "wb").write(bytes(bad))
# sha256 inputs: known answers, then lengths 0..200 of a byte pattern with hashlib's digest for each
import hashlib
kat = {"empty": b"", "abc": b"abc", "two-block": b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "million-a": b"a" * 1000000}
for n, b in kat.items():
    open(os.path.join(d, "kat-" + n), "wb").write(b)
os.mkdir(os.path.join(d, "len"))
with open(os.path.join(d, "len", "want"), "w") as w:
    for n in range(201):
        b = bytes((i * 7 + n) & 0xff for i in range(n))
        open(os.path.join(d, "len", str(n)), "wb").write(b)
        w.write("%d %s\n" % (n, hashlib.sha256(b).hexdigest()))
EOF

CC=${CC:-cc}
SAN="-fsanitize=address,undefined -fno-sanitize-recover=all"
# shellcheck disable=SC2086
echo 'int main(void){return 0;}' | $CC $SAN -x c -o "$T/san-probe" - 2>/dev/null || SAN=
# shellcheck disable=SC2086
$CC -O1 -g -std=gnu99 -Wall -Wextra -Werror $SAN -o "$T/kktls-util-host" "$HERE/kktls-util.c"
export ASAN_OPTIONS=detect_leaks=0:exitcode=99 UBSAN_OPTIONS=halt_on_error=1:exitcode=98:print_stacktrace=1

pass=0 fail=0
expect_out() { # want-stdout label cmd...: exit 0, exactly that one line on stdout, nothing on stderr
  local want=$1 label=$2 got=0; shift 2
  "$@" > "$T/out" 2> "$T/err" || got=$?
  if [ "$got" = 0 ] && [ "$(cat "$T/out")" = "$want" ] && [ "$(wc -l < "$T/out")" = 1 ] && [ ! -s "$T/err" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1)); echo "FAIL $label: exit $got, output '$(cat "$T/out")', want '$want'"; sed 's/^/  /' "$T/err"
  fi
}
expect() { # want label cmd...
  local want=$1 label=$2 got=0; shift 2
  "$@" > "$T/out" 2>&1 || got=$?
  if [ "$got" = "$want" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL $label: exit $got, want $want"; sed 's/^/  /' "$T/out"; fi
}

run_table() { # runner...
  local r=("$@") Z=$T
  expect 0 "has classes.dex" "${r[@]}" has-entry "$Z/dex.jar" classes.dex
  expect 1 "only similar names" "${r[@]}" has-entry "$Z/nodex.jar" classes.dex
  expect 0 "manifest present" "${r[@]}" has-entry "$Z/nodex.jar" META-INF/MANIFEST.MF
  expect 0 "zip comment with a fake signature" "${r[@]}" has-entry "$Z/comment.jar" classes.dex
  expect 1 "empty zip" "${r[@]}" has-entry "$Z/empty.zip" classes.dex
  expect 2 "truncated" "${r[@]}" has-entry "$Z/trunc.jar" classes.dex
  expect 2 "not a zip" "${r[@]}" has-entry "$Z/notzip.jar" classes.dex
  expect 2 "empty file" "${r[@]}" has-entry "$Z/zero.jar" classes.dex
  expect 2 "directory offset out of range" "${r[@]}" has-entry "$Z/badoff.jar" classes.dex
  expect 2 "missing file" "${r[@]}" has-entry "$Z/nope.jar" classes.dex
  expect 2 "has-entry without a name" "${r[@]}" has-entry "$Z/dex.jar"
  expect 2 "no subcommand" "${r[@]}"
  expect 2 "unknown subcommand" "${r[@]}" frob
  expect 2 "setcon without a path" "${r[@]}" setcon u:object_r:system_file:s0
  expect 1 "setcon on a missing path" "${r[@]}" setcon u:object_r:system_file:s0 "$Z/nope"
  expect_out e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "sha256 empty" "${r[@]}" sha256 "$Z/kat-empty"
  expect_out ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad "sha256 abc" "${r[@]}" sha256 "$Z/kat-abc"
  expect_out 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1 "sha256 two blocks" \
    "${r[@]}" sha256 "$Z/kat-two-block"
  expect_out cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0 "sha256 one million a" \
    "${r[@]}" sha256 "$Z/kat-million-a"
  local n h bad=0
  while read -r n h; do
    [ "$("${r[@]}" sha256 "$Z/len/$n" 2>&1)" = "$h" ] || { bad=$((bad + 1)); echo "FAIL sha256 of $n bytes"; }
  done < "$Z/len/want"
  if [ $bad = 0 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
  expect 2 "sha256 of a missing file" "${r[@]}" sha256 "$Z/nope"
  expect 2 "sha256 of a directory" "${r[@]}" sha256 "$Z/len"
  expect 2 "sha256 without a file" "${r[@]}" sha256
  expect 2 "sha256 with two files" "${r[@]}" sha256 "$Z/kat-abc" "$Z/kat-abc"
  : > "$Z/f"
  local rc=0; "${r[@]}" setcon u:object_r:system_file:s0 "$Z/f" > /dev/null 2>&1 || rc=$?
  if [ $rc = 0 ] && command -v getfattr > /dev/null; then
    expect 0 "setcon label read back" sh -c "getfattr -n security.selinux --only-values '$Z/f' | grep -qx 'u:object_r:system_file:s0'"
  elif [ $rc = 1 ]; then
    pass=$((pass + 1))  # no privilege for security.* here: a clean exit 1 is the expected failure
  else
    fail=$((fail + 1)); echo "FAIL setcon on an existing file: exit $rc"
  fi
}

run_table "$T/kktls-util-host"
for b in "${BINS[@]}"; do
  case $(LC_ALL=C readelf -h "$b" | awk -F: '/Machine:/ {gsub(/^ +/, "", $2); print $2}') in
    ARM) if command -v "${QEMU_ARM:-qemu-arm}" > /dev/null; then run_table "${QEMU_ARM:-qemu-arm}" "$b"; else run_table "$b"; fi ;;
    *) run_table "$b" ;;
  esac
done
echo "kktls-util tests: $pass passed, $fail failed"
[ $fail = 0 ]
