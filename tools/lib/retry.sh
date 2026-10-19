#!/bin/bash
# retry.sh: run a command again after a failure, with exponential backoff; for the network fetches of the build and
# test scripts (android.googlesource.com answers HTTP 503 now and then, and one such answer failed a whole CI job).
#
#   . tools/lib/retry.sh            defines retry
#   tools/lib/retry.sh --selftest   offline checks of retry (stub commands, KKTLS_RETRY_SLEEP=0)
#
# retry TRIES CMD...: runs CMD (a command or a shell function) up to TRIES times, until it exits 0. After failed try n
# (n < TRIES) it logs the try and its rc on stderr and sleeps KKTLS_RETRY_SLEEP * 3^(n-1) seconds (KKTLS_RETRY_SLEEP
# default 60: 60 s, then 180 s). Returns 0, or the rc of the last try. A wrong TRIES or KKTLS_RETRY_SLEEP is rc 2.
# CMD runs as an `if` condition, so `set -e` does not stop the script on a failed try, and errexit is off inside CMD
# (as for any command before `||`). A CMD that is not safe to run twice must not be wrapped.
# Twin: tools/kktls-apply-series.sh has an inline copy (it runs in the sync container); keep both in step (--selftest
# runs the twin too).
# SPDX-License-Identifier: Apache-2.0

retry() {
  local tries=${1:-} n=1 rc delay=${KKTLS_RETRY_SLEEP:-60}
  [[ $tries =~ ^[1-9][0-9]*$ ]] || { echo "retry: TRIES must be a positive integer, not '$tries'" >&2; return 2; }
  [[ $delay =~ ^[0-9]+$ ]] || { echo "retry: KKTLS_RETRY_SLEEP must be a whole number of seconds, not '$delay'" >&2; return 2; }
  shift
  [ $# -gt 0 ] || { echo "retry: no command" >&2; return 2; }
  while :; do
    if "$@"; then return 0; else rc=$?; fi
    if [ $n -ge "$tries" ]; then
      echo "retry: try $n/$tries of '$*' failed (rc $rc); giving up" >&2
      return $rc
    fi
    echo "retry: try $n/$tries of '$*' failed (rc $rc); next try in ${delay} s" >&2
    sleep "$delay"
    delay=$((delay * 3)); n=$((n + 1))
  done
}

# Sourced: only the function.
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
set -uo pipefail

# shellcheck disable=SC2064,SC2319  # the trap names this run's dir; check takes the rc of the test chain before it
selftest() {
  local t pass=0 fail=0 out rc me
  me=$(readlink -f "$0")
  t=$(mktemp -d) || exit 1
  trap "rm -rf '$t'" EXIT
  export KKTLS_RETRY_SLEEP=0
  check() { if [ "$1" = 0 ]; then pass=$((pass + 1)); echo "ok   $2"; else fail=$((fail + 1)); echo "FAIL $2"; fi; }
  # stub COUNTFILE FAILS RC: counts its calls in COUNTFILE; the first FAILS calls exit RC, later ones exit 0
  cat > "$t/stub" <<'EOF'
#!/bin/sh
n=$(( $(cat "$1" 2>/dev/null || echo 0) + 1 )); echo $n > "$1"
[ $n -gt "$2" ] || exit "$3"
exit 0
EOF
  chmod +x "$t/stub"
  calls() { cat "$t/$1" 2>/dev/null || echo 0; }
  # 1. fails twice, then succeeds: rc 0 after 3 calls, two failed tries logged
  out=$(retry 3 "$t/stub" "$t/c1" 2 5 2>&1); rc=$?
  [ $rc = 0 ] && [ "$(calls c1)" = 3 ] && [ "$(grep -c '^retry: try [12]/3 .* failed (rc 5); next try in 0 s$' <<<"$out")" = 2 ]
  check $? "fails twice, then succeeds: rc 0, 3 calls, 2 tries logged"
  # 2. always fails: the last rc after N calls, the last try logged as giving up
  out=$(retry 4 "$t/stub" "$t/c2" 99 7 2>&1); rc=$?
  [ $rc = 7 ] && [ "$(calls c2)" = 4 ] && grep -q '^retry: try 4/4 .* failed (rc 7); giving up$' <<<"$out"
  check $? "always fails: rc 7 after 4 calls"
  # 3. success at once: one call, nothing logged
  out=$(retry 3 "$t/stub" "$t/c3" 0 1 2>&1); rc=$?
  [ $rc = 0 ] && [ "$(calls c3)" = 1 ] && [ -z "$out" ]
  check $? "first try succeeds: 1 call, no log"
  # 4. one try: no retry, rc passed through
  retry 1 "$t/stub" "$t/c4" 99 3 2>/dev/null; rc=$?
  [ $rc = 3 ] && [ "$(calls c4)" = 1 ]
  check $? "TRIES 1: one call, rc 3"
  # 5. a shell function as CMD, in a `set -e` script without `||`: the failed tries do not end the script
  out=$(bash -ec ". '$me'; f() { '$t/stub' '$t/c5' 2 4; }; retry 3 f; echo after rc=\$?" 2>/dev/null); rc=$?
  [ $rc = 0 ] && [ "$out" = "after rc=0" ] && [ "$(calls c5)" = 3 ]
  check $? "set -e caller, shell function CMD: 3 calls, script goes on"
  # 6. set -e caller, always failing: the script stops at retry with the last rc
  out=$(bash -ec ". '$me'; retry 2 '$t/stub' '$t/c6' 99 6; echo after" 2>/dev/null); rc=$?
  [ $rc = 6 ] && [ -z "$out" ] && [ "$(calls c6)" = 2 ]
  check $? "set -e caller, always fails: script stops with rc 6 after 2 calls"
  # 7. the backoff: base 1 s, 3 tries -> 1 s + 3 s of sleep (a stub sleep records its arguments)
  out=$(KKTLS_RETRY_SLEEP=1 bash -c "sleep() { echo \"sleep \$1\"; }; . '$me'; retry 3 false" 2>/dev/null); rc=$?
  [ $rc = 1 ] && [ "$out" = "sleep 1
sleep 3" ]
  check $? "backoff: base 1 gives sleeps 1 s, then 3 s, none after the last try"
  # 8. bad arguments: rc 2, CMD not run
  retry 0 "$t/stub" "$t/c8" 0 0 2>/dev/null; rc=$?
  [ $rc = 2 ] && [ "$(calls c8)" = 0 ]
  check $? "TRIES 0: rc 2, no call"
  KKTLS_RETRY_SLEEP=x retry 3 "$t/stub" "$t/c9" 0 0 2>/dev/null; rc=$?
  [ $rc = 2 ] && [ "$(calls c9)" = 0 ]
  check $? "KKTLS_RETRY_SLEEP=x: rc 2, no call"
  retry 3 2>/dev/null; rc=$?
  [ $rc = 2 ]
  check $? "no command: rc 2"
  # 9. the inline twin of tools/kktls-apply-series.sh behaves the same (cases 1, 2 and the backoff)
  sed -n '/^retry() {$/,/^}$/p' "$(dirname "$me")/../kktls-apply-series.sh" > "$t/twin.sh"
  out=$(bash -ec ". '$t/twin.sh'; retry 3 '$t/stub' '$t/c10' 2 5; echo after" 2>/dev/null); rc=$?
  [ $rc = 0 ] && [ "$out" = after ] && [ "$(calls c10)" = 3 ]
  check $? "twin: fails twice, then succeeds: rc 0, 3 calls"
  retry_twin() { bash -c ". '$t/twin.sh'; retry \"\$@\"" retry "$@"; }
  retry_twin 4 "$t/stub" "$t/c11" 99 7 2>/dev/null; rc=$?
  [ $rc = 7 ] && [ "$(calls c11)" = 4 ]
  check $? "twin: always fails: rc 7 after 4 calls"
  out=$(KKTLS_RETRY_SLEEP=1 bash -c "sleep() { echo \"sleep \$1\"; }; . '$t/twin.sh'; retry 3 false" 2>/dev/null); rc=$?
  [ $rc = 1 ] && [ "$out" = "sleep 1
sleep 3" ]
  check $? "twin: backoff 1 s, then 3 s"
  echo "retry selftest: $pass passed, $fail failed"
  [ $fail = 0 ]
}

case ${1:-} in
  --selftest) selftest ;;
  *) echo "usage: retry.sh --selftest   (or source it: . retry.sh; retry TRIES CMD...)" >&2; exit 2 ;;
esac
