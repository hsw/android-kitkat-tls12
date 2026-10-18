#!/bin/sh
# Host tests of conscrypt/compat/kktls_compat.c (libkktls_compat.so): fake 32-bit auxv files and the fortify aborts
# (-DKK_FAKE), then the host's own /proc/self/auxv against the C library's getauxval. Needs cc (gcc or clang).
# SPDX-License-Identifier: Apache-2.0
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cc=${CC:-cc}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/kktls-compat-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
rc=0
for mode in fake native; do
  flags=-U_FORTIFY_SOURCE
  [ $mode = fake ] && flags="$flags -DKK_FAKE"
  # shellcheck disable=SC2086
  "$cc" -std=gnu99 -O1 -Wall -Wextra -Werror $flags -o "$tmp/t-$mode" "$here/test_compat.c"
  echo "== $mode"
  # the stub log lines (stderr) go to a file; the abort cases read the child's stderr themselves
  TMPDIR=$tmp "$tmp/t-$mode" > "$tmp/out" 2> "$tmp/log" || rc=1
  sed 's/^/  /' "$tmp/out"
done
[ $rc = 0 ] && echo "compat host tests: PASS" || echo "compat host tests: FAIL"
exit $rc
