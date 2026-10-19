#!/bin/bash
# Runtime checks of the TLS series on a running Android 4.4 (emulator or device) over adb: the layer-A matrix, layer D
# and its gate (PROBE_LAYER=d matrix, both, fallback, shadow, mem, intolerant, local, gate) and the app-mix and SNI
# property cases (appmix, sniprop). Subcommands below.
#
#   tls-probe.sh prep SERIAL CACERTS_DIR HOSTNAME IP
#       emulator started with --writable-system: replace /system/etc/security/cacerts with CACERTS_DIR (e.g. the
#       release store, cacerts/files) and add "IP HOSTNAME" to /system/etc/hosts
#   tls-probe.sh cts SERIAL APKDIR [libcore|conscrypt:CLASS[#method] ...]
#       route (b): install android.core.tests.{runner,libcore.package.libcore,libcore.package.conscrypt}.apk from
#       APKDIR and run each class (default: the route (a) Task 7 set, conscrypt classes as com.android.org.conscrypt.*)
#       with am instrument; one RESULT PASS|FAIL line per class with the failing test names, then TOTAL and the
#       comparison with the known-failure list (CTS_KNOWN, default tools/cts-known-failures.txt, only the entries of the
#       classes, or single methods, that ran): exit 1 on any failure not on the list, on a crash or missing summary, on
#       a summary that is not exactly "OK (N tests)" / "Tests run: N,  Failures: F,  Errors: E", on N = 0 (no test
#       ran), on a summary whose failure count differs from the per-test records, on output the parser cannot read,
#       and on a listed failure that passed (update the list); a "? Class#glob EXCEPTION" entry may pass or fail with
#       exactly that exception (the root cause of the test's stack), any other failure of such a test is unexpected.
#       An argument without its libcore:/conscrypt: prefix is a tool error (exit 2), as is a run in which no class ran,
#       a results file that cannot be written, or a class that ran without its records in that file (review 3, codex 5:
#       a lost append dropped the class from the comparison, and an empty results file was a PASS), and so is an adb
#       that fails while a class runs (transport, device gone: its output is no evidence; review 3, codex 6). The class
#       goes to the device shell in single quotes (a "$" in CLASS or #method stays literal)
#   tls-probe.sh build CLASSES_DIR OUT.jar
#       compile probe/Tls12Probe.java (javac --release 8 against CLASSES_DIR/{framework,ext}.jar, the classes.jar of
#       out/target/common/obj/JAVA_LIBRARIES/{framework,ext}_intermediates) and dex it with d8 --min-api 19
#   tls-probe.sh dump SERIAL JAR
#       enabled/supported protocols and suites of every default factory, incl. android.net.SSLCertificateSocketFactory
#   tls-probe.sh matrix SERIAL JAR
#       internet rows (howsmyssl, badssl, ISRG Root X1) with the expected outcome; prints MATCH/MISMATCH/NONE per row.
#       A refusal row names the failure class it expects (FAIL:handshake, FAIL:cert, FAIL:hostname; Tls12Probe
#       classify()); a network failure (DNS, connect, timeout) is NONE on every row, never MATCH
#   tls-probe.sh rows SERIAL JAR ROWSFILE
#       the same for the rows in ROWSFILE (MATRIX format below), e.g. a subset or a negative control; a missing,
#       unreadable or empty ROWSFILE is a tool error (exit 2), never "0 mismatches"
#   tls-probe.sh hello SERIAL JAR HOSTNAME DEVICE_IP [PORT]
#       local rows: clienthello_probe.py serves on the Mac (127.0.0.1:PORT, default 8443); the device must resolve
#       HOSTNAME to the Mac (emulator: /system/etc/hosts "10.0.2.2 HOSTNAME"); DEVICE_IP is the Mac's address as the
#       device sees it (emulator: 10.0.2.2), used for the IP-literal row. Prints each captured ClientHello as JSON.
#       HELLO_BIND=0.0.0.0 for a device on the LAN (over Wi-Fi; HOSTNAME e.g. <host-ip-with-dashes>.nip.io).
#   tls-probe.sh selftest [CLASSES_DIR]
#       no device: the verdict logic (matrix rows, probe rows of local/intolerant, the rows file, the CTS parser and
#       known-failure comparison, the fallback runs, the setters verdict) against a stub adb and canned output; with
#       CLASSES_DIR (as for build) also `Tls12Probe selftest` (classify() on synthetic exception chains, the both
#       verdict, the setters cases per stack) on the host JVM.
#       SELFTEST PASS|FAIL
#
# Layer D (Conscrypt 2.6-alpha2 behind the default factory). The default factory io.github.hsw.kktls.KktlsDefaultSSLSocketFactory is part of layer A (core.jar,
# libcore/0025) and layer D is three /system files (kktls-conscrypt.jar, kktls-sslfilter.jar, libkktls_conscrypt_jni.so),
# none a boot jar. The factory uses Conscrypt when /system/framework/kktls-conscrypt.jar exists, unless the kill switch
# persist.kktls.conscrypt is exactly "0" (read once per process; root: `adb -s SERIAL shell setprop
# persist.kktls.conscrypt 0`; an image may set 0 in build.prop). Without the jar it is layer A ([absent: ...]) and logs
# nothing; with the switch at 0 likewise ([gate-off: ...]). "Layer D on" below = the jar installed and the switch not 0;
# the commands marked [D on] stop otherwise; with D off, run the layer-A commands (dump, plain matrix, ...).
# kktls-conscrypt.jar is NOT on BOOTCLASSPATH: the factory loads it with its own
# PathClassLoader(/system/framework/kktls-conscrypt.jar:kktls-sslfilter.jar, /system/lib, boot), so with D off no
# process maps the jar, its dalvik-cache file or libkktls_conscrypt_jni.so, and an app's own org.conscrypt is never shadowed.
# Since review 1b the system copy's JNI library is libkktls_conscrypt_jni.so (the build rewrites the aar's
# loadLibrary("conscrypt_jni")), so an app's own libconscrypt_jni.so never shares a basename with it in the 4.4 linker.
#   tls-probe.sh gate SERIAL JAR HOST PORT
#       the kill switch (root; needs kktls-conscrypt.jar installed): the current value, then 0, true, 01, the empty
#       string and 1, each in a new process: 0 must give `[gate-off: ...]`, no Conscrypt library mapped, no
#       KktlsSslFactory log line and no kktls-conscrypt dex mapped and a handshake to HOST:PORT through getDefault()
#       (layer A); every other value must give `[conscrypt: ...]` with the library and the kktls-conscrypt dex mapped
#       (no handshake: X25519 crashes on the emulator) and neither in zygote; a setprop after the first read changes
#       nothing in that process (both directions). The property is set back to its old value (an unset one ends as "")
#   [D on] PROBE_LAYER=d tls-probe.sh matrix SERIAL JAR
#       the same rows plus howsmyssl-socket (SSLSocketFactory.getDefault()); the howsmyssl rows must also show
#       TLS 1.3 and a ChaCha20 suite (MISMATCH otherwise)
#   [D on] tls-probe.sh both SERIAL JAR PHOST PPORT CHOST CPORT CPROTOCOLS|-
#       both TLS stacks in one process (platform handshake to PHOST, Conscrypt default-factory handshake to CHOST,
#       optionally restricted to CPROTOCOLS), in both orders; each RESULT OK needs the default factory to be the wrapper
#       over Conscrypt, the default step's socket an org.conscrypt class from kktls-conscrypt.jar, the platform step's a
#       com.android.org.conscrypt class of the boot class path, and both libraries mapped (review 3, codex 5)
#   [D on] tls-probe.sh fallback SERIAL JAR HOST PORT    three blocked runs, each with one file bind-mounted away (root):
#       libkktls_conscrypt_jni.so and kktls-conscrypt.jar masked with /dev/null, then the .so masked with a copy of its
#       first 4096 bytes (a truncated library: valid ELF header, PT_LOAD past EOF); the wrapper must fall back to layer A
#       with exactly ONE "Conscrypt is not usable" logcat line (tag KktlsSslFactory) in a process that creates four
#       wrappers, and handshake TLSv1.2 to HOST; the truncated run must also log the factory's ELF check ("PT_LOAD ...
#       truncated"), so the factory refused the file before the linker saw it (an image without that check dies of SIGBUS
#       there: no RESULT). Then the mounts are undone and a control run (no handshake) must show the Conscrypt delegate,
#       log nothing and end with RESULT fallback-control OK (each run also needs its PID line)
#   tls-probe.sh shadow SERIAL JAR HOST PORT      either D state: an app that bundles org.conscrypt (stub class in the
#       probe jar); the app's own copy must be the one its class loader returns and the boot class loader must have none;
#       PORT 0 = no handshake. MAPS shows what the default factory loaded (D on: libkktls_conscrypt_jni.so and the
#       kktls-conscrypt dex via the factory's loader; D off: nothing). The probe does not load a Conscrypt library of
#       its own (JNI_OnLoad needs a real NativeCrypto; the stub has none); `appmix` is the check with a real app copy
#   [D on] tls-probe.sh appmix SERIAL JAR APPJAR APPSO HOSTNAME [PORT]
#       review 1b: an app that bundles a real Conscrypt (APPJAR: its classes as a dex jar, e.g. the review-1 build's
#       kktls-conscrypt.jar, which still loads "conscrypt_jni"; APPSO: its libconscrypt_jni.so, e.g. the aar's) next to the
#       default factory in ONE process, in both orders (app-first, default-first), against the P-256 TLS 1.2 local
#       server of `local` (no X25519). The app's loader is PathClassLoader(APPJAR, <dir of APPSO>, boot), as an app's.
#       PASS: each order gives four OK handshakes (first, second, first, second) from the expected classes, the default
#       factory is Conscrypt, two distinct libraries are mapped (/system/lib/libkktls_conscrypt_jni.so and the app's
#       libconscrypt_jni.so), no tombstone appears, and logcat of the pid has no Fatal signal/JNI ERROR/RegisterNatives
#       line. A process abort (the review-1 hazard: the linker hands the second loader the first copy) shows as a
#       missing RESULT line.
#   [D on] tls-probe.sh sniprop SERIAL JAR HOSTNAME [PORT]
#       review 1b: jsse.enableSNIExtension set before the first getDefault(): "yes" (Conscrypt rejects it) must give
#       `[platform-sni: ...]`, no libkktls_conscrypt_jni.so mapped, exactly one KktlsSslFactory line naming the property and a
#       TLS 1.2 handshake to the local server; "TRUE" (valid, any case) must give Conscrypt and no line. The "yes"
#       handshake needs layer A at or after 87d593c (libcore/0027 in conscrypt.jar: SNI stays on instead of a
#       RuntimeException); the emulator pair of emu_layer_d.py has the Task 8 conscrypt.jar, so push the D build's
#       conscrypt.jar there first (emu.sh push-system, `sync`, restart the emulator)
#   tls-probe.sh setters SERIAL JAR HOST PORT [local]
#       either D state: app-set suites and protocols (Tls12Probe setters: {RC4}, {RC4, GCM},
#       {TLS 1.3 name, GCM}, {SSLv3}, {SSLv3, TLSv1.2}, {SSLv3, TLSv1, TLSv1.1, TLSv1.2}, the protocol cases with a
#       handshake to HOST:PORT, PORT 0: none) on
#       sockets of the default factory and of SSLContext.getDefault() (platform in both D states), each outcome
#       checked against its socket's stack. PASS: the default factory's sockets are Conscrypt with D on and the
#       platform otherwise, SSLContext's are the platform, both runs end RESULT ... OK, no new tombstone. "local": HOST must resolve to
#       the Mac; a TLS 1.0-1.2 P-256-only server with the throwaway CA serves PORT (the emulator: no X25519 under QEMU)
#   tls-probe.sh mem SERIAL JAR url:URL|load|local:HOST:PORT:PROTOS
#       PSS of a TLS process (/proc/self/smaps) + system_server/zygote PSS, dumpsys meminfo, /data/dalvik-cache size;
#       exit 1 when the TLS use itself was not OK
#   tls-probe.sh intolerant SERIAL JAR HOSTNAME [PORT]
#       a TLS-1.3-intolerant server on the Mac (clienthello_probe.py intolerant: drops every ClientHello that offers
#       TLS 1.3 in supported_versions, hands the others to a local TLS server with a throwaway CA, which is pushed to
#       the device store for the run and removed afterwards); two servers: max TLS 1.2, then max TLS 1.0. Every row
#       must print its RESULT line (none = the process died); D off (layer A, no TLS 1.3 offered) every row must be
#       OK; D on only certsock (the platform) must be, the Conscrypt rows are recorded (INFO). intolerant: PASS|FAIL
#   [D on] tls-probe.sh local SERIAL JAR HOSTNAME [PORT]
#       Conscrypt without X25519 (the emulator crashes in BoringSSL's X25519 NEON code, see the series README): a
#       local TLS 1.2 server with ECDHE P-256 only and the throwaway CA; default-factory (the wrapper's Conscrypt)
#       handshake restricted to TLSv1.2, the platform path, both stacks in one process, PSS; every row must be OK
#       (local: PASS|FAIL). (No Conscrypt.newProvider() row: org.conscrypt is not on the boot class path, so
#       reflection from the probe finds only its stub)
#
# The probe runs under app_process (framework natives registered, as for `am`), so SSLCertificateSocketFactory works.
# Always targets one device: adb -s SERIAL (never a bare adb: another device may be on USB too). Exit 1 on any MISMATCH or
# failed case; exit 2 on a tool error (die: usage, a missing file, a push/setprop/remount/build step failing, the gate
# not in the state a subcommand needs) and for an unknown subcommand: the run never reached a verdict on the image.
# 4.4 adbd has no shell protocol (`adb shell` exits 0 whatever the command did), so remote commands that matter go through
# ash(), which returns the remote status. Every device change (test CA, bind mount, gate value) and the Mac-side key
# directory is undone by an EXIT/INT/TERM trap if the run stops early.
# SPDX-License-Identifier: Apache-2.0
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ADB=${ADB:-adb}
BT=${BUILD_TOOLS:-/opt/homebrew/share/android-commandlinetools/build-tools/37.0.0}
DEV_JAR=/data/local/tmp/tls12probe.jar

die() { echo "tls-probe.sh: $*" >&2; exit 2; }

# cleanup actions: add_cleanup CMD pushes one command (eval'd later), run_cleanups runs them newest first and empties the
# list; the EXIT trap runs whatever is left, so Ctrl-C never leaves a trusted test CA, a bind mount, a flipped gate or the
# test CA's private key behind
CLEANUPS=
add_cleanup() { CLEANUPS="$1
$CLEANUPS"; }
run_cleanups() {
  local c todo=$CLEANUPS
  CLEANUPS=
  while IFS= read -r c; do [ -z "$c" ] || eval "$c"; done <<< "$todo"
  return 0
}
trap run_cleanups EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ash() {  # SERIAL CMD: adb shell CMD (output CR-stripped); returns CMD's own exit status, which 4.4 adb does not
  local s=$1 out rc; shift
  out=$("$ADB" -s "$s" shell "$*; echo \"KKTLSRC=\$?\"" < /dev/null | tr -d '\r')
  rc=$(printf '%s\n' "$out" | sed -n 's/.*KKTLSRC=\([0-9]*\)$/\1/p' | tail -1)
  printf '%s\n' "$out" | sed 's/KKTLSRC=[0-9]*$//' | grep -v '^$'
  [ "$rc" = 0 ]
}

probe() {  # SERIAL ARGS...: one probe invocation, CR stripped
  local s=$1; shift
  "$ADB" -s "$s" shell "CLASSPATH=$DEV_JAR app_process /system/bin Tls12Probe $*" < /dev/null | tr -d '\r'
}

push_jar() { "$ADB" -s "$1" push "$2" "$DEV_JAR" >/dev/null 2>&1 || die "push to $1 failed"; }

pid_of() {  # SERIAL NAME: the pid of the first process whose ps NAME is exactly NAME, from one `adb shell ps` (the
  # toolbox of the SDK 4.4.2 image has no pidof). The PID column comes from the header; toolbox rows carry a state
  # column the header lacks before NAME, so NAME is the last field. No such process is 1 with a message: callers use
  # `pid=$(pid_of ...) || exit 2` (a tool error, not a FAIL) and put the pid into the device command
  local p
  p=$("$ADB" -s "$1" shell ps < /dev/null | tr -d '\r' | awk -v n="$2" '
    !c { for (i = 1; i <= NF; i++) if ($i == "PID") c = i; next }
    $NF == n { print $c; exit }')
  case $p in
    '' | *[!0-9]*) echo "tls-probe.sh: no process '$2' in 'adb shell ps' of $1" >&2; return 1 ;;
  esac
  printf '%s\n' "$p"
}

pack_dex() {  # DIR OUT: DIR/classes.dex as the only member of the jar OUT; any failing step is a tool error (exit 2), so
  # "built" is never printed over a missing or stale OUT (review 3, codex 3)
  [ -s "$1/classes.dex" ] || die "d8 wrote no classes.dex in $1"
  (cd "$1" && rm -f out.jar && zip -q out.jar classes.dex) || die "zip of classes.dex failed"
  unzip -l "$1/out.jar" 2>/dev/null | grep -q ' classes\.dex$' || die "$1/out.jar has no classes.dex"
  mv -f "$1/out.jar" "$2" || die "could not move the jar to $2"
}

cmd_build() {
  local cls=$1 out=$2 tmp
  for j in framework ext; do [ -f "$cls/$j.jar" ] || die "$cls/$j.jar missing"; done
  tmp=$(mktemp -d)
  # the org.conscrypt stub is the "app-bundled" copy of the shadow check (the one the probe's loader must return)
  javac -nowarn --release 8 -cp "$cls/framework.jar:$cls/ext.jar" -d "$tmp/classes" "$HERE/probe/Tls12Probe.java" \
    "$HERE/probe/shadow/org/conscrypt/Conscrypt.java" || die "javac failed"
  JAVA_HOME=${JAVA_HOME:-/opt/homebrew/opt/openjdk} "$BT/d8" --min-api 19 --output "$tmp" \
    $(find "$tmp/classes" -name '*.class') || die "d8 failed"
  pack_dex "$tmp" "$out"
  rm -rf "$tmp"
  echo "built $out"
}

# name | command line | expected | why | with PROBE_LAYER=d: strings (separated by ";") that the row's output must also contain
#   expected: PASS = handshake/GET succeeds; FAIL:<class> = refused with that Tls12Probe failure class (handshake: TLS
#   alert/protocol/cipher refusal, cert: path/trust/validity, hostname: name check), optionally ~ERE: the RESULT line must
#   also match that case-insensitive extended regex; INFO = recorded only. A row whose
#   probe failed with class=network (or printed no RESULT) is NONE whatever it expects: no evidence, the run fails.
MATRIX='howsmyssl|url howsmyssl https://www.howsmyssl.com/a/check|PASS|TLS 1.2, rating, no insecure suites|tls_version=TLS 1.3;CHACHA20
howsmyssl-apache|apache howsmyssl-apache https://www.howsmyssl.com/a/check|PASS|Apache HTTP client, same defaults|tls_version=TLS 1.3;CHACHA20
tls-v1-2|socket tls-v1-2 tls-v1-2.badssl.com 1012|PASS|TLSv1.2-only server
tls-v1-2-url|url tls-v1-2-url https://tls-v1-2.badssl.com:1012/|PASS|same through okhttp
sha256|url sha256 https://sha256.badssl.com/|PASS|SHA-256 certificate
ecc256|url ecc256 https://ecc256.badssl.com/|PASS|P-256 ECDSA certificate
ecc384|url ecc384 https://ecc384.badssl.com/|PASS|P-384 ECDSA certificate
rsa4096|url rsa4096 https://rsa4096.badssl.com/|PASS|RSA 4096 certificate
extended-validation|url extended-validation https://extended-validation.badssl.com/|INFO|EV row of README §7 (the badssl EV certificate may be gone)
tls-v1-1|socket tls-v1-1 tls-v1-1.badssl.com 1011|PASS|TLSv1.1 stays enabled
tls-v1-0|socket tls-v1-0 tls-v1-0.badssl.com 1010|PASS|TLSv1 stays enabled (A7)
ssl3|socket ssl3 ssl-v3.badssl.com 443|INFO|badssl ssl-v3 host now speaks TLS 1.2 (not an SSLv3 test)
rc4|socket rc4 rc4.badssl.com 443|FAIL:handshake|RC4-only server, RC4 not in the defaults
rc4-md5|socket rc4-md5 rc4-md5.badssl.com 443|FAIL:handshake|RC4-MD5-only server
3des|socket 3des 3des.badssl.com 443|FAIL:handshake|3DES-only server, 3DES not in the defaults
dh480|socket dh480 dh480.badssl.com 443|FAIL:handshake|480-bit DH (DHE not in the defaults; Logjam limit)
dh512|socket dh512 dh512.badssl.com 443|FAIL:handshake|512-bit DH
null|socket null null.badssl.com 443|FAIL:handshake|NULL cipher server
expired|url expired https://expired.badssl.com/|FAIL:cert|expired certificate
wrong.host|url wrong.host https://wrong.host.badssl.com/|FAIL:handshake~inappropriate.fallback|name mismatch: the first okhttp try fails the hostname check, the TLSv1 + SCSV retry then gets inappropriate_fallback, which okhttp reports (certsock-wrong.host shows the name check alone)
self-signed|url self-signed https://self-signed.badssl.com/|FAIL:cert|self-signed
untrusted-root|url untrusted-root https://untrusted-root.badssl.com/|FAIL:cert|unknown root
isrg|url isrg https://valid-isrgrootx1.letsencrypt.org/|PASS|ISRG Root X1 chain through Java (needs it in the CA store)
certsock-sha256|certsock certsock-sha256 sha256.badssl.com 443|PASS|SSLCertificateSocketFactory, verifies the host
certsock-wrong.host|certsock certsock-wrong.host wrong.host.badssl.com 443|FAIL:hostname|SSLCertificateSocketFactory name check'
MATRIX_D_EXTRA='howsmyssl-socket|socket howsmyssl-socket www.howsmyssl.com 443|PASS|SSLSocketFactory.getDefault() = the wrapper|protocol=TLSv1.3'

summarize_body() {  # howsmyssl JSON -> one line; other bodies -> first 200 characters
  python3 -I -c '
import json, sys
for line in sys.stdin:
    name, body = line.split(" ", 2)[1:]
    try:
        j = json.loads(body)
    except ValueError:
        print("   body: " + body.strip()[:200]); continue
    print("   howsmyssl %s: tls_version=%s rating=%s given_suites=%d insecure=%s ephemeral_keys=%s session_ticket=%s"
          " tls_compression=%s unknown_cipher_suite=%s beast_vuln=%s" % (name, j.get("tls_version"), j.get("rating"),
          len(j.get("given_cipher_suites") or []), sorted((j.get("insecure_cipher_suites") or {}).keys()),
          j.get("ephemeral_keys_supported"), j.get("session_ticket_supported"), j.get("tls_compression_supported"),
          j.get("unknown_cipher_suite_supported"), j.get("beast_vuln")))
    print("   given_cipher_suites " + ",".join(j.get("given_cipher_suites") or []))'
}

run_rows() {  # SERIAL ROWS: run each row, print the result and MATCH/MISMATCH; 1 on a MISMATCH/NONE, 2 if no row ran
  local s=$1 rows=$2 bad=0 n=0 name cmdline want why dwant out res got summary missing need
  while IFS='|' read -r name cmdline want why dwant; do
    [ -n "$name" ] || continue
    n=$((n + 1))
    out=$(probe "$s" "$cmdline")
    res=$(printf '%s\n' "$out" | grep "^RESULT $name " | tail -1)
    summary=$(printf '%s\n' "$out" | grep "^BODY $name " | summarize_body)
    [ -z "$summary" ] || printf '%s\n' "$summary"
    got=$(echo "$res" | awk '{print $3}')
    case $got in
      OK) got=PASS ;;
      FAIL) got=FAIL:$(echo "$res" | awk '$4 ~ /^class=/ {sub(/^class=/, "", $4); print $4}'); [ "$got" != FAIL: ] || got=FAIL:other ;;
      *) got=NONE; res="RESULT $name NONE $(printf '%s' "$out" | tail -3 | tr '\n' ' ')" ;;
    esac
    missing=
    if [ "${PROBE_LAYER:-a}" = d ] && [ -n "$dwant" ]; then
      while IFS= read -r w; do
        [ -n "$w" ] && ! printf '%s\n%s\n' "$summary" "$res" | grep -qF -- "$w" && missing="$missing [$w]"
      done <<< "$(printf '%s\n' "$dwant" | tr ';' '\n')"
    fi
    need=; case $want in *~*) need=${want#*~} ;; esac
    if [ "$got" = NONE ] || [ "$got" = FAIL:network ]; then v=NONE; bad=$((bad + 1))  # no TLS evidence either way
    elif { [ "$want" = INFO ] || [ "$got" = "${want%%~*}" ]; } && [ -z "$missing" ] &&
         { [ -z "$need" ] || printf '%s\n' "$res" | grep -qiE -- "$need"; }; then v=MATCH
    else v=MISMATCH; bad=$((bad + 1)); fi
    printf '%-9s want=%-14s %s   (%s)%s\n' "$v" "$want" "$res" "$why" "${missing:+   layer D wants:$missing}"
  done <<< "$rows"
  [ $n -gt 0 ] || { echo "matrix: no rows to run (empty ROWSFILE?): no verdict"; return 2; }
  echo "matrix: $bad mismatch(es) or row(s) without evidence"
  [ $bad -eq 0 ]
}

cmd_hello() {
  local s=$1 jar=$2 host=$3 ip=$4 port=${5:-8443} log pid rows
  push_jar "$s" "$jar"
  log=$(mktemp)
  python3 -I "$HERE/clienthello_probe.py" serve --bind "${HELLO_BIND:-127.0.0.1}" --port "$port" --timeout 60 > "$log" 2>&1 &
  pid=$!
  add_cleanup "kill $pid 2>/dev/null; rm -f $(printf %q "$log")"
  for _ in $(seq 50); do grep -q listening "$log" && break; sleep 0.1; done
  rows="probe-okhttp|url probe-okhttp https://$host:$port/|FAIL|okhttp: first try, then the TLSv1 + SCSV retry
probe-apache|apache probe-apache https://$host:$port/|FAIL|Apache HTTP: SNI
probe-default|socket probe-default $host $port|FAIL|SSLSocketFactory.getDefault(): SNI
probe-certsock|certsock probe-certsock $host $port|FAIL|SSLCertificateSocketFactory: SNI
probe-ip|socket probe-ip $ip $port|FAIL|IP literal: no SNI"
  local before
  while IFS='|' read -r name cmdline want why; do
    before=$(grep -c '"conn"' "$log")
    echo "== $name ($why): $(probe "$s" "$cmdline" | grep '^RESULT')"
    sleep 1
    # the ClientHellos this row produced
    grep '"conn"' "$log" | tail -n +$((before + 1)) | python3 -I -c '
import json, sys
for line in sys.stdin:
    h = json.loads(line)
    if "error" in h:
        print("   conn %s: %s" % (h["conn"], h["error"])); continue
    print("   conn %d: record %s client_version %s, %d suites, fallback_scsv=%s, sni=%s, padding=%s, hello %d B, record bytes %d, supported_versions %s, ext %s"
          % (h["conn"], h["record_version"], h["client_version"], h["n_ciphers"], h["fallback_scsv"], h["sni"],
             h["padding_len"], h["hello_len"], h["record_bytes"], ",".join(h.get("supported_versions") or []) or "-",
             ",".join(h["extensions"])))'
  done <<< "$rows"
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  echo "== raw capture (clienthello_probe.py JSON, in connection order)"
  cat "$log"
  run_cleanups
}

# route (b): the CTS libcore packages, one class per `am instrument` (conscrypt classes are jarjar'd on a device)
CTS_CLASSES='libcore libcore.javax.net.ssl.SSLSocketTest libcore.javax.net.ssl.SSLContextTest
libcore libcore.javax.net.ssl.SSLSocketFactoryTest libcore.javax.net.ssl.SSLServerSocketTest
libcore libcore.javax.net.ssl.SSLServerSocketFactoryTest libcore.javax.net.ssl.SSLEngineTest
libcore libcore.javax.net.ssl.SSLSessionTest libcore.javax.net.ssl.SSLParametersTest
libcore libcore.javax.net.ssl.DefaultHostnameVerifierTest libcore.javax.net.ssl.SSLSessionContextTest
conscrypt com.android.org.conscrypt.NativeCryptoTest com.android.org.conscrypt.CipherSuiteTest
conscrypt com.android.org.conscrypt.TrustManagerImplTest com.android.org.conscrypt.TrustedCertificateIndexTest
conscrypt com.android.org.conscrypt.ClientSessionContextTest com.android.org.conscrypt.OpenSSLSocketImplTest
conscrypt com.android.org.conscrypt.AddressUtilsTest
libcore libcore.java.net.URLConnectionTest
libcore tests.api.javax.net.ssl.SSLSessionTest tests.api.javax.net.ssl.SSLSessionContextTest
libcore tests.api.javax.net.ssl.SSLServerSocketTest tests.api.javax.net.ssl.SSLServerSocketFactoryTest
libcore tests.api.javax.net.ssl.SSLSocketTest tests.api.javax.net.ssl.SSLSocketFactoryTest
libcore tests.api.javax.net.ssl.SSLContext1Test tests.api.javax.net.ssl.SSLContext2Test
libcore tests.api.javax.net.ssl.HandshakeCompletedEventTest tests.api.javax.net.ssl.HttpsURLConnectionTest
libcore tests.api.javax.net.ssl.SSLEngineTest
libcore org.apache.harmony.luni.tests.internal.net.www.protocol.https.HttpsURLConnectionTest'

cmd_cts() {  # SERIAL APKDIR [pkg:CLASS ...]: install the three APKs, run each class, compare with the known failures
  local s=$1 dir=$2 list pkg cls total=0 bad=0 results ps known=${CTS_KNOWN:-$HERE/cts-known-failures.txt}; shift 2
  [ -f "$known" ] || die "known-failure list $known missing"
  cts_args "$@"
  for a in runner libcore.package.libcore libcore.package.conscrypt; do
    "$ADB" -s "$s" install -r "$dir/android.core.tests.$a.apk" < /dev/null | tr -d '\r' | grep -q '^Success' ||
      die "install of android.core.tests.$a.apk failed"
  done
  if [ $# -gt 0 ]; then list=$(printf '%s\n' "$@" | sed 's/:/ /')
  else list=$(printf '%s\n' "$CTS_CLASSES" | awk '{for (i = 2; i <= NF; i++) print $1, $i}'); fi
  results=$(mktemp "${TMPDIR:-/tmp}/tls-probe-cts.XXXXXX") || die "mktemp failed"; add_cleanup "rm -f $(printf %q "$results")"
  while read -r pkg cls; do
    [ -n "$cls" ] || continue
    total=$((total + 1))
    # adb joins its arguments into one command line that the device shell parses again: the class goes in single
    # quotes there, or "p.Outer$Inner" runs p.Outer (review 3, codex 6). cts_args allows no quote in a class name.
    "$ADB" -s "$s" shell am instrument -r -w -e class "'$cls'" \
      "android.core.tests.libcore.package.$pkg/android.test.InstrumentationCtsTestRunner" < /dev/null | tr -d '\r' |
      cts_class "$cls" "$results"
    ps=("${PIPESTATUS[@]}")
    [ "${ps[2]}" != 2 ] || die "cts: cannot write the results file $results: no verdict"
    # 4.4 adbd never passes am's status back, so a failing adb (or tr) is the host side or the transport: the output
    # it delivered proves nothing, even with an OK summary before the device went away (review 3, codex 6: that ran
    # into cts_compare and exited 0 next to "TOTAL ... fail=1")
    [ "${ps[0]}${ps[1]}" = 00 ] || die "cts: adb failed (exit ${ps[0]}, tr ${ps[1]}) while running $cls: no verdict"
    [ "${ps[2]}" = 0 ] || bad=$((bad + 1))
  done <<< "$list"
  echo "TOTAL pass=$((total - bad)) fail=$bad"
  [ "$total" -gt 0 ] || die "cts: no class ran: no verdict"
  # every class that ran must have its records (RAN is appended after them): a lost append is no verdict, never a PASS
  while read -r pkg cls; do
    [ -z "$cls" ] || grep -qxF "RAN $cls" "$results" || die "cts: no records of $cls in the results file: no verdict"
  done <<< "$list"
  cts_compare "$known" "$results"
}

cts_args() {  # PKG:CLASS[#method]...: every argument must have that form, or exit 2 (review 4b: a bare class name gave an
  # empty class, which the loop skipped, and a run of nothing passed)
  local a
  for a in "$@"; do
    printf '%s\n' "$a" | grep -Eqx '(libcore|conscrypt):[A-Za-z_][A-Za-z0-9_.$]*(#[A-Za-z0-9_$]+)?' ||
      die "cts: '$a' is not libcore:CLASS[#method] or conscrypt:CLASS[#method]"
  done
}

cts_class() {  # CLASS RESULTS < `am instrument -r -w` output: print the class's RESULT line and append its FAILED
  # records, then "RAN CLASS", to RESULTS; 1 unless RESULT PASS, 2 when RESULTS cannot be written (review 3, codex 5:
  # an ignored append failure lost the class, and its failures, from the comparison). Output the parser could not read
  # (python died, no RAN line) becomes "FAILED CLASS#<parser-error>", so cts_compare never passes a class whose
  # failures nobody recorded
  local cls=$1 res=$2 out rc recs
  out=$(cts_parse "$cls"); rc=$?
  if [ $rc -ne 0 ] || ! printf '%s\n' "$out" | grep -qxF "RAN $cls"; then
    echo "RESULT FAIL $cls: parser error (rc $rc)"
    printf 'FAILED %s#<parser-error>\nRAN %s\n' "$cls" "$cls" >> "$res" ||
      { echo "RESULT FAIL $cls: cannot write $res"; return 2; }
    return 1
  fi
  printf '%s\n' "$out" | grep '^RESULT '
  recs=$(printf '%s\n' "$out" | grep '^FAILED ')
  # RAN goes last and only after the records were written: a class with a RAN line has all its records
  { { [ -z "$recs" ] || printf '%s\n' "$recs"; } && printf 'RAN %s\n' "$cls"; } >> "$res" ||
    { echo "RESULT FAIL $cls: cannot write $res"; return 2; }
  case $out in "RESULT PASS"*) return 0;; esac
  return 1
}

cts_parse() {  # CLASS < `am instrument -r -w` output: "RESULT PASS|FAIL CLASS: ..." line, then RAN CLASS and one
  # "FAILED Class#test EXCEPTION" line per failing test (EXCEPTION: the root cause of the status' stack=, i.e. its last
  # "Caused by: " line, else its first line, the throwable's toString(); empty when there is none: ForEachRunner wraps
  # every ClientHello test's failure in "java.lang.Exception: Failed for SSLContext(...)", the cause is what failed)
  # and FAILED CLASS#<crashed>|<no-summary> (record names have no blank). The summary must be exactly "OK (N test[s])"
  # or "Tests run: N,  Failures: F,  Errors: E" (else FAILED CLASS#<bad-summary>), N must be at least 1 (else
  # FAILED CLASS#<no-tests>: an empty or unloadable suite is no evidence; review 3 codex 3 / review 4b), and its count
  # must equal the failure records: F + E records, none after OK; otherwise FAILED CLASS#<summary-mismatch>. A FAIL
  # never comes without a FAILED record
  python3 -I -c '
import re, sys
cls = sys.argv[1]; st = {}; fails = []; summary = ""; crashed = False; instack = False
for ln in sys.stdin:
    ln = ln.rstrip("\n")
    if instack and not ln.startswith("INSTRUMENTATION_"):
        if ln.strip().startswith("Caused by: "):
            st["cause"] = ln.strip()[len("Caused by: "):]
        continue
    instack = False
    if ln.startswith("INSTRUMENTATION_STATUS: "):
        k, _, v = ln[len("INSTRUMENTATION_STATUS: "):].partition("=")
        st[k] = v
        instack = k == "stack"
    elif ln.startswith("INSTRUMENTATION_STATUS_CODE: "):
        code = int(ln.split(": ")[1])
        if code in (-1, -2):
            fails.append((st.get("class", cls), st.get("test", "?"), code,
                          st.get("cause", st.get("stack", "")).strip()))
        st = {}
    elif ln.startswith("OK (") or ln.startswith("Tests run:"):
        summary = ln.strip()
    elif "INSTRUMENTATION_RESULT: shortMsg" in ln or "Process crashed" in ln:
        crashed = True
m_ok = re.match(r"OK \((\d+) tests?\)$", summary)
m_run = re.match(r"Tests run: *(\d+), *Failures: *(\d+), *Errors: *(\d+)$", summary)
n_run = int(m_ok.group(1)) if m_ok else int(m_run.group(1)) if m_run else None
counted = 0 if m_ok else int(m_run.group(2)) + int(m_run.group(3)) if m_run else None
ok = bool(m_ok) and n_run > 0 and not fails and not crashed
records = []
for c, t, _, e in fails:
    records.append(("FAILED %s#%s %s" % (c, t, e)).rstrip())
if crashed or not summary:
    records.append("FAILED %s#<%s>" % (cls, "crashed" if crashed else "no-summary"))
elif n_run is None:
    records.append("FAILED %s#<bad-summary> %s" % (cls, summary))
elif n_run == 0:
    records.append("FAILED %s#<no-tests> %s" % (cls, summary))
elif counted != len(fails):
    records.append("FAILED %s#<summary-mismatch> %s: %d failure(s), %d record(s)" % (cls, summary, counted,
                                                                                    len(fails)))
if not ok and not records:
    records.append("FAILED %s#<no-failure-record> %s" % (cls, summary))
print("RESULT %s %s: %s%s%s" % ("PASS" if ok and not records else "FAIL", cls, summary or "no summary",
      " crashed" if crashed else "",
      (" failing: " + ",".join(t + ("(error)" if c == -1 else "") for _, t, c, _ in fails)) if fails else ""))
print("RAN %s" % cls)
for r in records:
    print(r)
' "$1"
}

cts_compare() {  # KNOWN RESULTS: the failing set of the classes that ran must equal the known list (exit 1 otherwise;
  # 2 for a malformed list or RESULTS without a RAN line: no class recorded is no verdict). "? Class#glob EXCEPTION": a
  # matching test may fail, but only with that exception (the first line of its stack must be EXCEPTION or start with
  # "EXCEPTION:"), or pass
  python3 -I - "$1" "$2" <<'PY'
import fnmatch, sys
known_path, res_path = sys.argv[1], sys.argv[2]
required, optional = set(), []
for n, raw in enumerate(open(known_path), 1):
    ln = raw.split("#", 1)[0].strip() if raw.lstrip().startswith("#") else raw.strip()
    if not ln:
        continue
    if ln.startswith("?"):
        w = ln[1:].split()
        if len(w) != 2:
            print("%s:%d: want '? Class#glob EXCEPTION' (an optional failure names the exception it may fail with)"
                  % (known_path, n))
            sys.exit(2)
        optional.append((w[0], w[1]))
    else:
        required.add(ln)
ran, failed, exc = set(), set(), {}
for ln in open(res_path):
    kind, _, rest = ln.strip().partition(" ")
    if kind == "RAN":
        ran.add(rest)
    elif kind == "FAILED":
        name, _, e = rest.partition(" ")
        failed.add(name)
        exc[name] = e.strip()
if not ran:
    print("CTS: no class recorded in %s: no verdict" % res_path)
    sys.exit(2)


def optional_ok(f):
    e = exc.get(f, "")
    return any(fnmatch.fnmatchcase(f, g) and (e == x or e.startswith(x + ":")) for g, x in optional)


required = {k for k in required if k.split("#", 1)[0] in ran or k in ran}  # a class, or one method (CLASS#method)
unexpected = sorted(f for f in failed - required if not optional_ok(f))
passed = sorted(required - failed)
flaky = sorted(f for f in failed - required if f not in unexpected)
for f in flaky:
    print("CTS known-flaky failure (allowed): %s (%s)" % (f, exc.get(f)))
for f in unexpected:
    print("CTS UNEXPECTED failure: %s%s" % (f, " (%s)" % exc[f] if exc.get(f) else ""))
for f in passed:
    print("CTS known failure that PASSED (remove it from %s): %s" % (known_path, f))
print("CTS: %d class(es), %d failure(s) known, %d unexpected, %d known passed -> %s"
      % (len(ran), len(failed & required), len(unexpected), len(passed), "PASS" if not unexpected and not passed else "FAIL"))
sys.exit(1 if unexpected or passed else 0)
PY
}

cmd_prep() {  # SERIAL CACERTS_DIR HOSTNAME IP: emulator with --writable-system only
  local s=$1 dir=$2 host=$3 ip=$4 n
  n=$(ls "$dir" | grep -c '\.0$')
  [ "$n" -gt 0 ] || die "$dir has no <hash>.0 files"
  "$ADB" -s "$s" remount >/dev/null || die "remount failed (start the emulator with --writable-system)"
  # the device store becomes exactly CACERTS_DIR: replace, not add
  ash "$s" "rm -f /system/etc/security/cacerts/*" || die "could not empty the device CA store"
  "$ADB" -s "$s" push "$dir/." /system/etc/security/cacerts/ >/dev/null || die "cacerts push failed"
  ash "$s" "chown root:root /system/etc/security/cacerts/* && chmod 644 /system/etc/security/cacerts/* &&
    { grep -q ' $host\$' /system/etc/hosts || echo '$ip $host' >> /system/etc/hosts; } && cat /system/etc/hosts" ||
    die "CA store permissions or the hosts entry failed"
  echo "device store: $("$ADB" -s "$s" shell ls /system/etc/security/cacerts < /dev/null | grep -c '\.0')" files
  echo "prepared $s: $n CA files from $dir, hosts entry $ip $host"
}

# ---- layer D (Task 11) ------------------------------------------------------------------------------------------------

GATE=persist.kktls.conscrypt
# the layer-A client defaults as the probe prints them (A7 protocols, the 13 A6 suites; the exact list is pinned by
# check_tls_lists.py default-suites-order and check_artifacts.py, not here)
LAYER_A_ENABLED='protocols=\[TLSv1, TLSv1.1, TLSv1.2\] suites(13)'
get_gate() { "$ADB" -s "$1" shell getprop "$GATE" < /dev/null | tr -d '\r'; }

set_gate() {  # SERIAL VALUE: setprop and check the effect (setprop exits 0 even when a non-root shell is refused)
  "$ADB" -s "$1" shell "setprop $GATE '$2'" < /dev/null
  [ "$(get_gate "$1")" = "$2" ] || die "setprop $GATE '$2' had no effect on $1 (root needed: adb -s $1 root)"
}

restore_gate() {  # SERIAL VALUE: set the gate back after cmd_gate (also from the EXIT trap)
  "$ADB" -s "$1" shell "setprop $GATE '$2'" < /dev/null
  echo "== $GATE after the run: '$(get_gate "$1")' (set back to '$2')"
}

D_JAR=/system/framework/kktls-conscrypt.jar
d_installed() {  # SERIAL: 0 when kktls-conscrypt.jar exists (the factory's "installed" test, File.exists)
  [ "$("$ADB" -s "$1" shell "ls $D_JAR >/dev/null 2>&1 && echo yes" < /dev/null | tr -d '\r')" = yes ]
}

d_state() {  # SERIAL: on (jar installed, kill switch not 0), off (switch 0) or absent (no jar)
  d_installed "$1" || { echo absent; return; }
  [ "$(get_gate "$1")" = 0 ] && echo off || echo on
}

need_gate_on() {  # SERIAL: the Conscrypt checks need layer D on (Task 4: the jar installed, the kill switch not 0)
  local v; v=$(get_gate "$1")
  d_installed "$1" || die "$D_JAR is not installed on $1, so layer D is absent (layer A); install the D files first"
  [ "$v" != 0 ] || die "$GATE is 0 on $1, so layer D is off (layer A); this check needs: adb -s $1 shell setprop $GATE 1 (root)"
}

kktls_lines() {  # SERIAL PID: every KktlsSslFactory logcat line of that pid
  "$ADB" -s "$1" logcat -d -v threadtime -s KktlsSslFactory:V < /dev/null | tr -d '\r' | awk -v p="$2" '$3 == p'
}

cmd_gate() {  # SERIAL JAR HOST PORT: the gate persist.kktls.conscrypt (Task 11b), each value in a new process
  local s=$1 host=$3 port=$4 orig row v want flip out pid n bad=0 zy zpid
  d_installed "$s" || die "gate: $D_JAR is not installed on $s (the kill switch acts only on an installed layer D)"
  zpid=$(pid_of "$s" zygote) || exit 2
  push_jar "$s" "$2"
  orig=$(get_gate "$s")
  echo "== $GATE before the run: '$orig'"
  add_cleanup "restore_gate $(printf %q "$s") $(printf %q "$orig")"
  # row|value to set ("=" keeps the current one)|off or on|flip value
  while IFS='|' read -r row v want flip; do
    [ "$v" = "=" ] || set_gate "$s" "$v"
    if [ "$want" = on ]; then
      out=$(probe "$s" "gate gate-$row $host 0 $flip")
    else
      out=$(probe "$s" "gate gate-$row $host $port $flip")
    fi
    printf '%s\n' "$out"
    pid=$(printf '%s\n' "$out" | awk '/^PID /{print $3}')
    n=$(kktls_lines "$s" "$pid" | grep -c .)
    echo "gate-$row: pid $pid logged $n KktlsSslFactory line(s) (want 0)"
    [ "$n" = 0 ] || { kktls_lines "$s" "$pid"; bad=1; }
    printf '%s\n' "$out" | grep -q "^RESULT gate-$row OK" || { echo "gate-$row: no OK result"; bad=1; }
    if [ "$want" = on ]; then
      printf '%s\n' "$out" | grep -q '^DEFAULT .*\[conscrypt: ' || { echo "gate-$row: not Conscrypt"; bad=1; }
      printf '%s\n' "$out" | grep -q '^ENABLED .*TLSv1.3' || { echo "gate-$row: no TLSv1.3 enabled"; bad=1; }
      printf '%s\n' "$out" | grep -q '^MAPS .*/libkktls_conscrypt_jni\.so' || { echo "gate-$row: libkktls_conscrypt_jni.so not mapped"; bad=1; }
      printf '%s\n' "$out" | grep -q '^MAPS .*/libconscrypt_jni\.so' && { echo "gate-$row: a libconscrypt_jni.so is mapped"; bad=1; }
      printf '%s\n' "$out" | grep -q '^DEX .*kktls-conscrypt' || { echo "gate-$row: no kktls-conscrypt dex mapped"; bad=1; }
      [ -z "$flip" ] || printf '%s\n' "$out" | grep -q '^AFTER-SETPROP .*new-instance KktlsDefaultSSLSocketFactory\[conscrypt: ' ||
        { echo "gate-$row: a setprop $flip changed this process's gate"; bad=1; }
      zy=$("$ADB" -s "$s" shell "grep -c -e conscrypt_jni -e kktls-conscrypt /proc/$zpid/maps" < /dev/null | tr -d '\r')
      echo "gate-$row: zygote (pid $zpid) maps a Conscrypt library or kktls-conscrypt $zy time(s) (want 0)"
      [ "$zy" = 0 ] || bad=1
    else
      printf '%s\n' "$out" | grep -q '^DEFAULT .*\[gate-off: com.android.org.conscrypt.OpenSSLSocketFactoryImpl\]' ||
        { echo "gate-$row: not the gate-off platform factory"; bad=1; }
      printf '%s\n' "$out" | grep -q "^ENABLED .* $LAYER_A_ENABLED" ||
        { echo "gate-$row: not the layer-A defaults"; bad=1; }
      printf '%s\n' "$out" | grep -q '^MAPS .* \[\]$' || { echo "gate-$row: a Conscrypt library mapped with the gate off"; bad=1; }
      printf '%s\n' "$out" | grep -q '^DEX .* \[\]$' ||
        { echo "gate-$row: kktls-conscrypt dex mapped with the gate off (is kktls-conscrypt.jar on BOOTCLASSPATH?)"; bad=1; }
      printf '%s\n' "$out" | grep -q "^RESULT gate-$row OK protocol=TLSv1.2" || { echo "gate-$row: no TLSv1.2 handshake"; bad=1; }
      [ -z "$flip" ] || printf '%s\n' "$out" | grep -q '^AFTER-SETPROP .*new-instance KktlsDefaultSSLSocketFactory\[gate-off: ' ||
        { echo "gate-$row: a setprop $flip changed this process's gate"; bad=1; }
    fi
  done <<EOT
current|=|$( [ "$orig" = 0 ] && echo off || echo on )|
zero|0|off|1
true|true|on|
01|01|on|
empty||on|
one|1|on|0
EOT
  run_cleanups
  [ $bad -eq 0 ] && echo "gate: PASS" || { echo "gate: FAIL"; return 1; }
}

cmd_both() {  # SERIAL JAR PHOST PPORT CHOST CPORT CPROTOS
  local s=$1 bad=0 o out
  need_gate_on "$s"
  push_jar "$s" "$2"
  for o in conscrypt-first platform-first; do
    out=$(probe "$s" "both both-$o $3 $4 $5 $6 $7 $o"); printf '%s\n' "$out" | grep -E '^(STEP|DEFAULT|MAPS|RESULT) '
    printf '%s\n' "$out" | grep -q "^RESULT both-$o OK" || { bad=1; printf '%s\n' "$out" | tail -2; }
  done
  [ $bad -eq 0 ] && echo "both: PASS" || { echo "both: FAIL"; return 1; }
}

logcat_pid_lines() {  # SERIAL PID: every KktlsSslFactory line of that pid (the message and the attached failure)
  "$ADB" -s "$1" logcat -d -v threadtime -s KktlsSslFactory:W < /dev/null | tr -d '\r' | awk -v p="$2" '$3 == p'
}

elf_check_verdict() {  # LINES: 1 unless the factory's own ELF check refused the truncated library (not the linker)
  printf '%s\n' "$1" | grep -q 'ELF check of /system/lib/libkktls_conscrypt_jni.so: PT_LOAD segment .* truncated' ||
    { echo "truncated: no 'ELF check ... PT_LOAD segment ... truncated' in the pid's KktlsSslFactory lines"; return 1; }
}

logcat_lines() {  # SERIAL PID: the "Conscrypt is not usable" lines (tag KktlsSslFactory) of that pid
  "$ADB" -s "$1" logcat -d -v threadtime -s KktlsSslFactory:W < /dev/null | tr -d '\r' |
    awk -v p="$2" '$3 == p && /Conscrypt is not usable/'
}

cmd_fallback() {  # SERIAL JAR HOST PORT: blocked runs handshake (layer A); the control run only builds the factory
  local s=$1 out pid n lines bad=0 f src run
  local so=/system/lib/libkktls_conscrypt_jni.so tr=/data/local/tmp/kktls-truncated.so
  need_gate_on "$s"
  push_jar "$s" "$2"
  for run in "$so /dev/null" "/system/framework/kktls-conscrypt.jar /dev/null" "$so $tr"; do
    f=${run%% *} src=${run#* }
    if [ "$src" = "$tr" ]; then  # the first 4096 bytes: ELF header and program headers intact, PT_LOAD past EOF
      ash "$s" "dd if=$f of=$tr bs=4096 count=1 && chmod 644 $tr" || die "cannot make the truncated copy $tr"
      add_cleanup "ash $(printf %q "$s") 'rm $tr'"
    fi
    ash "$s" "mount -o bind $src $f && ls -l $f" || die "bind mount of $src over $f failed (root needed)"
    add_cleanup "ash $(printf %q "$s") 'umount $f; ls -l $f'"
    out=$(probe "$s" "fallback fallback-blocked $3 $4"); printf '%s\n' "$out"
    run_cleanups  # the umount (and the truncated copy)
    pid=$(printf '%s\n' "$out" | awk '/^PID /{print $3}')
    lines=$(logcat_lines "$s" "$pid"); n=$(printf '%s' "$lines" | grep -c .)
    echo "fallback-blocked ($f masked with $src): pid $pid logged $n 'Conscrypt is not usable' line(s) (want exactly 1):"
    printf '%s\n' "$lines"
    fallback_verdict blocked "$out" "$n" || bad=1
    if [ "$src" = "$tr" ]; then
      lines=$(logcat_pid_lines "$s" "$pid"); printf '%s\n' "$lines" | grep 'ELF check' || true
      elf_check_verdict "$lines" || bad=1
    fi
  done
  out=$(probe "$s" "fallback fallback-control $3 0"); printf '%s\n' "$out"
  pid=$(printf '%s\n' "$out" | awk '/^PID /{print $3}')
  n=$(logcat_lines "$s" "$pid" | grep -c .)
  echo "fallback-control (library and jar back): pid $pid logged $n line(s) (want 0)"
  fallback_verdict control "$out" "$n" || bad=1
  [ $bad -eq 0 ] && echo "fallback: PASS" || { echo "fallback: FAIL"; return 1; }
}

fallback_verdict() {  # blocked|control PROBE_OUTPUT N_LOGCAT_LINES: 1 (with the reasons) unless the run is what that
  # kind must show. Both: a PID line (no pid: the logcat count means nothing) and the run's own RESULT ... OK line (an
  # explicit FAIL or a process that died after printing DEFAULT/ENABLED is no pass). blocked: exactly one "not usable"
  # line, the platform factory with the layer-A defaults, a TLSv1.2 handshake; control: no line, Conscrypt's defaults
  local kind=$1 out=$2 n=$3 bad=0
  printf '%s\n' "$out" | grep -q '^PID fallback-'"$kind"' [0-9][0-9]*$' || { echo "$kind: no PID line"; bad=1; }
  if [ "$kind" = blocked ]; then
    [ "$n" = 1 ] || { echo "blocked: $n 'not usable' line(s), want exactly 1"; bad=1; }
    printf '%s\n' "$out" | grep -q '^DEFAULT .*\[platform: ' || { echo "default factory is not the platform fallback"; bad=1; }
    printf '%s\n' "$out" | grep -q "^ENABLED .* $LAYER_A_ENABLED=" ||
      { echo "fallback is not the layer-A defaults (A7 protocols, the 13 A6 suites)"; bad=1; }
    printf '%s\n' "$out" | grep -q '^RESULT fallback-blocked OK protocol=TLSv1.2' || { echo "no TLSv1.2 handshake"; bad=1; }
  else
    [ "$n" = 0 ] || { echo "control: $n 'not usable' line(s), want 0"; bad=1; }
    printf '%s\n' "$out" | grep -q '^DEFAULT .*\[conscrypt: ' || { echo "control: default factory is not Conscrypt"; bad=1; }
    printf '%s\n' "$out" | grep -q '^ENABLED .* protocols=\[TLSv1, TLSv1.1, TLSv1.2, TLSv1.3\]' ||
      { echo "control: not Conscrypt's defaults"; bad=1; }
    printf '%s\n' "$out" | grep -q '^RESULT fallback-control OK' ||
      { echo "control: no RESULT fallback-control OK line (FAIL, or the process died)"; bad=1; }
  fi
  [ $bad -eq 0 ]
}

cmd_shadow() {  # SERIAL JAR HOST PORT (PORT 0: no handshake); either gate state
  local s=$1 out
  push_jar "$s" "$2"
  echo "== $GATE is '$(get_gate "$s")', layer D $(d_state "$s")"
  out=$(probe "$s" "shadow shadow $3 $4"); printf '%s\n' "$out"
  printf '%s\n' "$out" | grep -q '^RESULT shadow OK .*app-copy-used=true boot-visible=false' &&
    echo "shadow: PASS (the app's own org.conscrypt wins; none on the boot class path)" || { echo "shadow: FAIL"; return 1; }
}
cmd_mem() {  # SERIAL JAR MODE (url:URL | load | local:HOST:PORT:PROTOS); 1 if the TLS use was not OK (its PSS means nothing)
  local s=$1 out sspid zpid
  sspid=$(pid_of "$s" system_server) || exit 2
  zpid=$(pid_of "$s" zygote) || exit 2
  push_jar "$s" "$2"
  out=$(probe "$s" "mem mem $3"); printf '%s\n' "$out" | grep -E '^(PID|PSS|RESULT) '
  "$ADB" -s "$s" shell "for p in $sspid $zpid; do"'
      echo "pid $p $(cat /proc/$p/cmdline | tr "\0" " "): Pss $(awk "/^Pss:/{s+=\$2} END{print s}" /proc/$p/smaps) kB"; done
    dumpsys meminfo | grep -E "Total PSS|Total RAM|Free RAM|Used RAM|Lost RAM|system \(pid|system_server|com.android.phone \("
    du -s /data/dalvik-cache; ls -l /data/dalvik-cache | grep -E "kktls-|@core.jar|@conscrypt.jar"
    df /data' < /dev/null | tr -d '\r'
  printf '%s\n' "$out" | grep -q '^RESULT mem OK' || { echo "mem: FAIL (no OK RESULT for the TLS use)"; return 1; }
}

with_test_ca() {  # SERIAL HOSTNAME DIR: throwaway CA + leaf for HOSTNAME in DIR, CA pushed to the device store
  local s=$1 host=$2 tmp=$3
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 -subj "/CN=kktls tls-probe test CA" \
    -keyout "$tmp/ca.key" -out "$tmp/ca.pem" -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1 || die "CA failed"
  openssl req -newkey rsa:2048 -nodes -sha256 -subj "/CN=$host" -keyout "$tmp/leaf.key" -out "$tmp/leaf.csr" \
    >/dev/null 2>&1 && printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host" > "$tmp/ext" &&
    openssl x509 -req -in "$tmp/leaf.csr" -CA "$tmp/ca.pem" -CAkey "$tmp/ca.key" -CAcreateserial -days 2 -sha256 \
      -extfile "$tmp/ext" -out "$tmp/leaf.pem" >/dev/null 2>&1 || die "leaf certificate failed"
  CA_HASH=$(openssl x509 -subject_hash_old -noout -in "$tmp/ca.pem")
  "$ADB" -s "$s" remount >/dev/null || die "remount failed (start the emulator with --writable-system)"
  ash "$s" "[ ! -e /system/etc/security/cacerts/$CA_HASH.0 ]" || die "$CA_HASH.0 already in the device store"
  add_cleanup "drop_test_ca $(printf %q "$s")"
  "$ADB" -s "$s" push "$tmp/ca.pem" "/system/etc/security/cacerts/$CA_HASH.0" >/dev/null || die "CA push failed"
  ash "$s" "chmod 644 /system/etc/security/cacerts/$CA_HASH.0" || die "chmod of the test CA failed"
  echo "test CA $CA_HASH.0 pushed"
}

drop_test_ca() {  # SERIAL: remove the test CA (also from the EXIT trap)
  ash "$1" "rm /system/etc/security/cacerts/$CA_HASH.0" && echo "test CA removed" ||
    echo "WARNING: test CA $CA_HASH.0 still in the store of $1" >&2
}

test_dir() {  # make the Mac-side directory for the throwaway CA and key; removed by the EXIT trap; sets TMPD
  TMPD=$(mktemp -d) || die "mktemp failed"
  add_cleanup "rm -rf $(printf %q "$TMPD")"
}

local_server() {  # LOG PORT SERVER_MAX CURVE TMP: start clienthello_probe.py intolerant in the background, set SRV_PID
  python3 -I "$HERE/clienthello_probe.py" intolerant --bind "${HELLO_BIND:-127.0.0.1}" --port "$2" --timeout 120 \
    --cert "$5/leaf.pem" --key "$5/leaf.key" --server-max "$3" ${4:+--curve "$4"} > "$1" 2>&1 &
  SRV_PID=$!
  for _ in $(seq 50); do grep -q listening "$1" && break; sleep 0.1; done
}

run_probe_rows() {  # SERIAL ROWS (name|probe args|OK or INFO): one line per row with its verdict; returns 1 when a
  # row printed no RESULT line for its probe name (the second word of the probe args: the process died, e.g. a native
  # crash) or an OK row's RESULT is not OK; INFO rows only record the outcome. 2 if no row ran
  local name cmdline want pname out res v bad=0 n=0
  while IFS='|' read -r name cmdline want; do
    [ -n "$name" ] || continue
    n=$((n + 1))
    pname=$(printf '%s\n' "$cmdline" | awk '{print $2}')
    out=$(probe "$1" "$cmdline")
    res=$(printf '%s\n' "$out" | grep "^RESULT $pname " | tail -1)
    if [ -z "$res" ]; then v=NONE; bad=$((bad + 1))
    elif [ "$want" = INFO ]; then v=INFO
    elif [ "$want" = OK ] && printf '%s\n' "$res" | grep -q "^RESULT $pname OK"; then v=MATCH
    else v=MISMATCH; bad=$((bad + 1)); fi
    echo "-- $name [$v want=$want]: $(printf '%s\n' "$out" | grep -E '^(RESULT|STEP|MAPS|PSS) ' | tr '\n' ' ')"
    [ -n "$res" ] || echo "   no RESULT $pname line (the process died?): $(printf '%s\n' "$out" | tail -3 | tr '\n' ' ')"
  done <<< "$2"
  [ $n -gt 0 ] || { echo "no rows to run"; return 2; }
  [ $bad -eq 0 ]
}

cmd_intolerant() {  # SERIAL JAR HOSTNAME [PORT]: the four Java client paths against a TLS-1.3-intolerant server
  local s=$1 host=$3 port=${4:-8444} tmp smax log bad=0 d=OK
  push_jar "$s" "$2"
  # D off or absent (layer A offers no TLS 1.3): every path must be served. D on: only certsock (the platform) must be;
  # the default factory, Apache and okhttp go through Conscrypt and are recorded (INFO): their outcome is the
  # documented D risk (device item tls13-layer-d-conscrypt-device-test.md), never seen on the emulator (X25519 crash)
  [ "$(d_state "$s")" = on ] && d=INFO
  echo "== $GATE is '$(get_gate "$s")', layer D $(d_state "$s"): default/apache/okhttp rows want $d, certsock OK"
  test_dir; tmp=$TMPD; with_test_ca "$s" "$host" "$tmp"
  for smax in TLSv1.2 TLSv1; do
    log=$tmp/intolerant-$smax.log
    local_server "$log" "$port" "$smax" "" "$tmp"
    add_cleanup "kill $SRV_PID 2>/dev/null"
    echo "== server max $smax (drops ClientHellos that offer TLS 1.3)"
    run_probe_rows "$s" "okhttp|url intol-okhttp https://$host:$port/|$d
apache|apache intol-apache https://$host:$port/|$d
default|socket intol-default $host $port|$d
certsock|certsock intol-certsock $host $port|OK" || bad=1
    kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
    echo "-- server log (one JSON line per connection)"; grep '"conn"' "$log"
  done
  run_cleanups  # the test CA and the key directory
  if [ $bad -eq 0 ]; then echo "intolerant: PASS"; else echo "intolerant: FAIL"; return 1; fi
}

cmd_local() {  # SERIAL JAR HOSTNAME [PORT]: Conscrypt over TLS 1.2 with a P-256-only local server (no X25519)
  local s=$1 host=$3 port=${4:-8445} tmp log bad=0
  need_gate_on "$s"
  push_jar "$s" "$2"
  test_dir; tmp=$TMPD; with_test_ca "$s" "$host" "$tmp"
  log=$tmp/local.log
  local_server "$log" "$port" TLSv1.2 prime256v1 "$tmp"
  add_cleanup "kill $SRV_PID 2>/dev/null"
  echo "== local server: TLS 1.0-1.2, ECDHE P-256 only, test CA"
  run_probe_rows "$s" "conscrypt-tls12|csock local-conscrypt-tls12 $host $port default TLSv1.2|OK
platform|csock local-platform $host $port platform -|OK
both-conscrypt-first|both both-conscrypt-first $host $port $host $port TLSv1.2 conscrypt-first|OK
both-platform-first|both both-platform-first $host $port $host $port TLSv1.2 platform-first|OK
mem|mem mem-local local:$host:$port:TLSv1.2|OK" || bad=1
  kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
  echo "-- server log (one JSON line per connection)"; grep '"conn"' "$log"
  run_cleanups  # the server, the test CA and the key directory
  if [ $bad -eq 0 ]; then echo "local: PASS"; else echo "local: FAIL"; return 1; fi
}

tombstones() { "$ADB" -s "$1" shell 'ls -l /data/tombstones 2>/dev/null' < /dev/null | tr -d '\r'; }

fatal_lines() {  # SERIAL PID: logcat lines of that pid that mean a native abort or a JNI failure
  "$ADB" -s "$1" logcat -d -v threadtime < /dev/null | tr -d '\r' |
    awk -v p="$2" '$3 == p' | grep -E 'Fatal signal|JNI ERROR|RegisterNatives|JNI WARNING|Shared lib .* already opened' || true
}

cmd_appmix() {  # SERIAL JAR APPJAR APPSO HOSTNAME [PORT]: an app's own Conscrypt next to the default factory (review 1b)
  local s=$1 appjar=$3 appso=$4 host=$5 port=${6:-8446} tmp log o out pid tb0 tb1 fl bad=0 dir=/data/local/tmp/kktlsapp
  need_gate_on "$s"
  [ -f "$appjar" ] && [ -f "$appso" ] || die "APPJAR $appjar or APPSO $appso missing"
  push_jar "$s" "$2"
  ash "$s" "rm -rf $dir; mkdir -p $dir/lib" >/dev/null || die "mkdir $dir failed"
  add_cleanup "ash $(printf %q "$s") 'rm -rf $dir' >/dev/null"
  "$ADB" -s "$s" push "$appjar" "$dir/app.jar" >/dev/null 2>&1 || die "push $appjar failed"
  "$ADB" -s "$s" push "$appso" "$dir/lib/libconscrypt_jni.so" >/dev/null 2>&1 || die "push $appso failed"
  ash "$s" "chmod 644 $dir/app.jar $dir/lib/libconscrypt_jni.so; ls -l $dir/app.jar $dir/lib/"
  test_dir; tmp=$TMPD; with_test_ca "$s" "$host" "$tmp"
  log=$tmp/appmix.log
  local_server "$log" "$port" TLSv1.2 prime256v1 "$tmp"
  add_cleanup "kill $SRV_PID 2>/dev/null"
  echo "== local server: TLS 1.0-1.2, ECDHE P-256 only, test CA; app jar $(shasum -a 256 "$appjar" | cut -c1-12)…, app .so $(shasum -a 256 "$appso" | cut -c1-12)…"
  for o in app-first default-first; do
    tb0=$(tombstones "$s")
    out=$(probe "$s" "appmix appmix-$o $host $port $dir/app.jar $dir/lib TLSv1.2 $o"); printf '%s\n' "$out"
    pid=$(printf '%s\n' "$out" | awk '/^PID /{print $3}')
    tb1=$(tombstones "$s")
    fl=$(fatal_lines "$s" "$pid")
    [ -z "$fl" ] || { echo "appmix-$o: logcat of pid $pid:"; printf '%s\n' "$fl"; bad=1; }
    [ "$tb0" = "$tb1" ] || { echo "appmix-$o: new tombstone:"; printf '%s\n' "$tb1"; bad=1; }
    printf '%s\n' "$out" | grep -q "^RESULT appmix-$o OK" || { echo "appmix-$o: no OK result (an abort prints none)"; bad=1; }
  done
  kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
  run_cleanups  # the server, the test CA, the key directory and $dir
  [ $bad -eq 0 ] && echo "appmix: PASS" || { echo "appmix: FAIL"; return 1; }
}

cmd_sniprop() {  # SERIAL JAR HOSTNAME [PORT]: jsse.enableSNIExtension before the first getDefault() (review 1b)
  local s=$1 host=$3 port=${4:-8447} tmp log v out pid lines n bad=0
  need_gate_on "$s"
  push_jar "$s" "$2"
  test_dir; tmp=$TMPD; with_test_ca "$s" "$host" "$tmp"
  log=$tmp/sniprop.log
  local_server "$log" "$port" TLSv1.2 prime256v1 "$tmp"
  add_cleanup "kill $SRV_PID 2>/dev/null"
  for v in yes TRUE; do
    out=$(probe "$s" "sniprop sniprop-$v $v $host $port TLSv1.2"); printf '%s\n' "$out"
    pid=$(printf '%s\n' "$out" | awk '/^PID /{print $3}')
    lines=$(kktls_lines "$s" "$pid"); n=$(printf '%s' "$lines" | grep -c .)
    printf '%s\n' "$lines"
    printf '%s\n' "$out" | grep -q "^RESULT sniprop-$v OK protocol=TLSv1.2" || { echo "sniprop-$v: no TLSv1.2 handshake"; bad=1; }
    if [ "$v" = yes ]; then
      printf '%s\n' "$out" | grep -q '^DEFAULT .*\[platform-sni: com.android.org.conscrypt.OpenSSLSocketFactoryImpl\]' ||
        { echo "sniprop-$v: not the platform-sni delegate"; bad=1; }
      printf '%s\n' "$out" | grep -q '^MAPS .* \[\]$' || { echo "sniprop-$v: Conscrypt loaded"; bad=1; }
      [ "$n" = 1 ] && printf '%s\n' "$lines" | grep -q 'jsse.enableSNIExtension is "yes"' ||
        { echo "sniprop-$v: $n KktlsSslFactory line(s), want exactly 1 naming the property"; bad=1; }
    else
      printf '%s\n' "$out" | grep -q '^DEFAULT .*\[conscrypt: ' || { echo "sniprop-$v: not Conscrypt"; bad=1; }
      [ "$n" = 0 ] || { echo "sniprop-$v: $n KktlsSslFactory line(s), want 0"; bad=1; }
    fi
  done
  kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
  run_cleanups
  [ $bad -eq 0 ] && echo "sniprop: PASS" || { echo "sniprop: FAIL"; return 1; }
}

cmd_setters() {  # SERIAL JAR HOST PORT [local]: app-set suites/protocols on the default and the SSLContext factory
  local s=$1 host=$3 port=$4 mode=${5:-} gate want tmp log od op tb0 tb1 bad=0
  [ -z "$mode" ] || [ "$mode" = local ] || die "setters: the fifth argument can only be 'local'"
  push_jar "$s" "$2"
  gate=$(get_gate "$s"); want=platform; [ "$(d_state "$s")" = on ] && want=conscrypt
  echo "== $GATE is '$gate', layer D $(d_state "$s"): default-factory sockets must be $want, SSLContext.getDefault()'s platform"
  if [ "$mode" = local ]; then
    test_dir; tmp=$TMPD; with_test_ca "$s" "$host" "$tmp"
    log=$tmp/setters.log
    local_server "$log" "$port" TLSv1.2 prime256v1 "$tmp"
    add_cleanup "kill $SRV_PID 2>/dev/null"
    echo "== local server $host:$port: TLS 1.0-1.2, ECDHE P-256 only, test CA"
  fi
  tb0=$(tombstones "$s")
  od=$(probe "$s" "setters setters-default $host $port default"); printf '%s\n' "$od"
  op=$(probe "$s" "setters setters-context $host $port context"); printf '%s\n' "$op"
  tb1=$(tombstones "$s")
  if [ "$mode" = local ]; then
    kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
    echo "-- server log (one JSON line per connection)"; grep '"conn"' "$log"
  fi
  run_cleanups  # the server, the test CA and the key directory
  [ "$tb0" = "$tb1" ] || { echo "new tombstone(s): $tb1"; bad=1; }
  setters_verdict "$want" "$od" "$op" || bad=1
  [ $bad -eq 0 ] && echo "setters: PASS" || { echo "setters: FAIL"; return 1; }
}

setters_verdict() {  # WANT_DEFAULT_STACK DEFAULT_OUT CONTEXT_OUT: 1 (with the reasons) unless the default factory's
  # run is OK on WANT_DEFAULT_STACK and the SSLContext factory's run is OK on the platform (a missing RESULT = died)
  local bad=0
  printf '%s\n' "$2" | grep -q "^RESULT setters-default OK stack=$1 " ||
    { echo "default factory: no 'RESULT setters-default OK stack=$1'"; bad=1; }
  printf '%s\n' "$3" | grep -q '^RESULT setters-context OK stack=platform ' ||
    { echo "SSLContext factory: no 'RESULT setters-context OK stack=platform'"; bad=1; }
  [ $bad -eq 0 ]
}

# ---- selftest (no device) -----------------------------------------------------------------------------------------

# shellcheck disable=SC2016  # the stub's own script: its $ expand when the stub runs, not here
STUB_ADB='#!/bin/bash
# stub adb of tls-probe.sh selftest: -s SERIAL push|install|shell ...; a probe prints what its row name (second word)
# asks for; ps prints the file STUB_PS; am instrument prints one passing test of the class it was given (parsed as the
# device shell parses the command line adb joins: quotes removed, $NAME expanded), logs "RAN-CLASS <class>" to STUB_LOG
# and exits STUB_RC
shift 2
case $1 in
  install) echo Success ;;
  shell)
    shift
    case "$*" in
      *"am instrument"*)
        # STUB_RO=DIR: make the files in DIR (the caller'"'"'s TMPDIR: its results file) read-only, as a full disk would
        [ -z "${STUB_RO:-}" ] || chmod a-w "$STUB_RO"/*
        eval "set -- $*"
        c=; while [ $# -gt 2 ]; do [ "$1 $2" = "-e class" ] && { c=$3; break; }; shift; done
        [ -z "${STUB_LOG:-}" ] || printf "RAN-CLASS %s\n" "$c" >> "$STUB_LOG"
        printf "%s\n" "INSTRUMENTATION_STATUS: class=${c%%#*}" "INSTRUMENTATION_STATUS: test=test_x" \
          "INSTRUMENTATION_STATUS_CODE: 1" "INSTRUMENTATION_STATUS: class=${c%%#*}" "INSTRUMENTATION_STATUS: test=test_x" \
          "INSTRUMENTATION_STATUS_CODE: 0" "INSTRUMENTATION_RESULT: stream=" "OK (1 test)" "INSTRUMENTATION_CODE: -1"
        exit "${STUB_RC:-0}" ;;
      *"Tls12Probe "*)
        set -- ${*#*Tls12Probe }
        case $2 in
          ok-*) echo "RESULT $2 OK protocol=TLSv1.2 suite=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" ;;
          alert-*) echo "RESULT $2 FAIL class=handshake javax.net.ssl.SSLHandshakeException: alert handshake failure" ;;
          reset-*) echo "RESULT $2 FAIL class=network javax.net.ssl.SSLHandshakeException <- java.net.SocketException" ;;
          dead-*) echo "PID $2 4242"; echo "Segmentation fault" ;;
          other-*) echo "RESULT someone-else OK" ;;
        esac ;;
      getprop*) echo "${STUB_GATE:-}" ;;
      ps) [ -z "${STUB_PS:-}" ] || cat "$STUB_PS" ;;
      "ls /system/framework/kktls-conscrypt.jar"*) [ -z "${STUB_D:-}" ] || echo yes ;;
    esac ;;
esac
exit 0'

# `am instrument -r -w` of SSLSocketTest as 4.4 prints it: an error (stack = the throwable's toString, then "at" lines),
# a failure and a pass, then the summary
CTS_CANNED='INSTRUMENTATION_STATUS: class=libcore.javax.net.ssl.SSLSocketTest
INSTRUMENTATION_STATUS: test=test_SSLSocket_SNI_ipLiteral
INSTRUMENTATION_STATUS_CODE: 1
INSTRUMENTATION_STATUS: class=libcore.javax.net.ssl.SSLSocketTest
INSTRUMENTATION_STATUS: stack=java.util.concurrent.CancellationException
	at java.util.concurrent.FutureTask.report(FutureTask.java:94)
	at libcore.javax.net.ssl.SSLSocketTest.captureTlsHandshakeFirstTransmittedChunkBytes(SSLSocketTest.java:1)
INSTRUMENTATION_STATUS: test=test_SSLSocket_SNI_ipLiteral
INSTRUMENTATION_STATUS_CODE: -1
INSTRUMENTATION_STATUS: class=libcore.javax.net.ssl.SSLSocketTest
INSTRUMENTATION_STATUS: test=test_SSLSocket_SNI_setHostname
INSTRUMENTATION_STATUS_CODE: 1
INSTRUMENTATION_STATUS: class=libcore.javax.net.ssl.SSLSocketTest
INSTRUMENTATION_STATUS: stack=junit.framework.AssertionFailedError: expected:<[sni-explicit.tls.test]> but was:<null>
	at libcore.javax.net.ssl.SSLSocketTest.test_SSLSocket_SNI_setHostname(SSLSocketTest.java:2)
INSTRUMENTATION_STATUS: test=test_SSLSocket_SNI_setHostname
INSTRUMENTATION_STATUS_CODE: -2
INSTRUMENTATION_STATUS: class=libcore.javax.net.ssl.SSLSocketTest
INSTRUMENTATION_STATUS: test=test_SSLSocket_ClientHello_padding
INSTRUMENTATION_STATUS_CODE: 1
INSTRUMENTATION_STATUS: class=libcore.javax.net.ssl.SSLSocketTest
INSTRUMENTATION_STATUS: test=test_SSLSocket_ClientHello_padding
INSTRUMENTATION_STATUS_CODE: 0
INSTRUMENTATION_RESULT: stream=
Test results for InstrumentationCtsTestRunner=.E.F.
FAILURES!!!
Tests run: 3,  Failures: 1,  Errors: 1
INSTRUMENTATION_CODE: -1'

# `adb shell ps` of the SDK 4.4.2 ARM image (rows cut; the selftest adds the CRs that adb gives), plus a made-up app
# whose name ends in zygote; toolbox prints the state column (S) without a header
PS_FIXTURE='USER     PID   PPID  VSIZE  RSS     WCHAN    PC         NAME
root      1     0     644    500   c00df1fc 0001a098 S /init
root      2     0     0      0     c003c4d8 00000000 S kthreadd
root      472   1     576    260   c00df1fc 0001a098 S /sbin/ueventd
system    667   1     1000   176   c027e9dc b6f5a41c S /system/bin/servicemanager
root      673   1     494756 39940 ffffffff b6edb568 S zygote
system    1070  673   565472 41412 ffffffff b6edc5cc S system_server
u0_a7     1161  673   531660 54376 ffffffff b6edc5cc S com.android.systemui
u0_a99    1300  673   508444 22424 ffffffff b6edc5cc S com.example.zygote'

cts_wrapped() {  # ROOT [MIDDLE]: canned `am instrument` output of one ClientHello test that failed inside
  # ForEachRunner.runNamed (4.4's stack= is the printStackTrace text: wrapper, its "at" lines, then each cause)
  local c=libcore.javax.net.ssl.SSLSocketTest t=test_SSLSocket_ClientHello_compressionMethods
  printf '%s\n' "INSTRUMENTATION_STATUS: class=$c" "INSTRUMENTATION_STATUS: test=$t" "INSTRUMENTATION_STATUS_CODE: 1" \
    "INSTRUMENTATION_STATUS: class=$c" \
    'INSTRUMENTATION_STATUS: stack=java.lang.Exception: Failed for SSLContext("TLSv1.1"): null' \
    '	at tests.util.ForEachRunner.runNamed(ForEachRunner.java:50)' \
    "	at $c.$t(SSLSocketTest.java:1734)"
  [ -z "${2:-}" ] || printf '%s\n' "Caused by: $2" '	at java.util.concurrent.FutureTask.report(FutureTask.java:94)' \
    '	... 3 more'
  printf '%s\n' "Caused by: $1" '	at java.util.concurrent.FutureTask.report(FutureTask.java:94)' '	... 12 more' \
    "INSTRUMENTATION_STATUS: test=$t" "INSTRUMENTATION_STATUS_CODE: -1" "INSTRUMENTATION_RESULT: stream=" \
    "Test results for InstrumentationCtsTestRunner=.E" "FAILURES!!!" "Tests run: 1,  Failures: 0,  Errors: 1" \
    "INSTRUMENTATION_CODE: -1"
}

cmd_selftest() {  # [CLASSES_DIR]: the verdict logic without a device (a stub adb); with CLASSES_DIR (as for build) also
  # Tls12Probe selftest (classify() on synthetic exception chains, the both verdict) on the host JVM. Exit 1 on a
  # failing case
  local t n=0 fail=0 sse=libcore.javax.net.ssl.SSLSocketTest
  test_dir; t=$TMPD
  printf '%s\n' "$STUB_ADB" > "$t/adb"; chmod +x "$t/adb"
  ADB=$t/adb
  : > "$t/jar"; : > "$t/empty-rows"
  case_rc() {  # LABEL WANT_RC CMD...: CMD's exit status must be WANT_RC (its output is shown on a failure)
    local label=$1 want=$2 rc; shift 2
    "$@" > "$t/out" 2>&1; rc=$?
    n=$((n + 1))
    if [ "$rc" = "$want" ]; then echo "selftest ok   $label (rc $rc)"
    else echo "selftest FAIL $label: rc $rc, want $want"; sed 's/^/    | /' "$t/out"; fail=1; fi
  }
  # layer D state (Task 4): installed = kktls-conscrypt.jar exists; only the kill switch value 0 turns it off
  dstate() { (export STUB_D=$1 STUB_GATE=$2; [ "$(d_state S)" = "$3" ]); }
  case_rc "d_state: jar, switch unset -> on" 0 dstate 1 "" on
  case_rc "d_state: jar, switch 1 -> on" 0 dstate 1 1 on
  case_rc "d_state: jar, switch true -> on (only 0 is off)" 0 dstate 1 true on
  case_rc "d_state: jar, switch 0 -> off" 0 dstate 1 0 off
  case_rc "d_state: no jar, switch 1 -> absent" 0 dstate "" 1 absent
  gateon() { (export STUB_D=$1 STUB_GATE=$2; need_gate_on S); }
  case_rc "need_gate_on: jar, switch unset" 0 gateon 1 ""
  case_rc "need_gate_on: jar, switch 0 is a tool error" 2 gateon 1 0
  case_rc "need_gate_on: no jar is a tool error" 2 gateon "" 1
  # matrix rows
  case_rc "run_rows: no rows is no verdict" 2 run_rows S ""
  case_rc "run_rows: a refusal of the expected class matches" 0 run_rows S "alert-r|socket alert-r h 443|FAIL:handshake|x"
  case_rc "run_rows: a reset is no evidence for FAIL:handshake" 1 run_rows S "reset-r|socket reset-r h 443|FAIL:handshake|x"
  case_rc "rows: a missing ROWSFILE is a tool error" 2 env ADB="$t/adb" bash "$0" rows S "$t/jar" "$t/missing-rows"
  case_rc "rows: an empty ROWSFILE is no verdict" 2 env ADB="$t/adb" bash "$0" rows S "$t/jar" "$t/empty-rows"
  # probe rows of local/intolerant
  case_rc "probe rows: OK row, OK result" 0 run_probe_rows S "a|csock ok-a h 1 default -|OK"
  case_rc "probe rows: OK row, FAIL result" 1 run_probe_rows S "a|csock ok-a h 1 default -|OK
b|csock alert-b h 1 default -|OK"
  case_rc "probe rows: no RESULT line (process died)" 1 run_probe_rows S "a|csock dead-a h 1 default -|INFO"
  case_rc "probe rows: only another row's RESULT" 1 run_probe_rows S "a|csock other-a h 1 default -|OK"
  case_rc "probe rows: INFO row records a FAIL" 0 run_probe_rows S "a|csock alert-a h 1 default -|INFO"
  case_rc "probe rows: no rows" 2 run_probe_rows S ""
  # cts: the stack's first line goes with each failure; '?' entries allow only their exception
  printf '%s\n' "$CTS_CANNED" | cts_parse "$sse" > "$t/parsed"
  case_rc "cts_parse: error with its exception" 0 grep -qx "FAILED $sse#test_SSLSocket_SNI_ipLiteral java.util.concurrent.CancellationException" "$t/parsed"
  case_rc "cts_parse: failure with its exception" 0 grep -qx "FAILED $sse#test_SSLSocket_SNI_setHostname junit.framework.AssertionFailedError: expected:<\[sni-explicit.tls.test\]> but was:<null>" "$t/parsed"
  case_rc "cts_parse: RESULT FAIL line" 0 grep -q "^RESULT FAIL $sse: Tests run: 3" "$t/parsed"
  printf '%s\n' "? $sse#test_SSLSocket_SNI_* java.util.concurrent.CancellationException" > "$t/known"
  grep -v setHostname "$t/parsed" > "$t/race-only"
  case_rc "cts_compare: the capture race (CancellationException) is allowed" 0 cts_compare "$t/known" "$t/race-only"
  case_rc "cts_compare: an assertion failure under a '?' glob is UNEXPECTED" 1 cts_compare "$t/known" "$t/parsed"
  printf 'RAN %s\nFAILED %s#test_SSLSocket_SNI_x java.util.concurrent.CancellationExceptionX\n' "$sse" "$sse" > "$t/other-exc"
  case_rc "cts_compare: another exception with the same prefix is UNEXPECTED" 1 cts_compare "$t/known" "$t/other-exc"
  printf 'RAN %s\nFAILED %s#<crashed>\n' "$sse" "$sse" > "$t/crashed"
  case_rc "cts_compare: a crash is UNEXPECTED" 1 cts_compare "$t/known" "$t/crashed"
  printf '%s\n' "? $sse#test_SSLSocket_SNI_*" > "$t/known-old"
  case_rc "cts_compare: a '?' entry without its exception is a malformed list" 2 cts_compare "$t/known-old" "$t/race-only"
  printf 'RAN %s\n' "$sse" > "$t/ran-only"
  case_rc "cts_compare: the shipped cts-known-failures.txt parses" 0 cts_compare "$HERE/cts-known-failures.txt" "$t/ran-only"
  # cts: a class's output -> records -> verdict (cts_class + cts_compare, as cmd_cts runs them); every failure the
  # summary counts must have a record, and output the parser cannot read must not vanish
  cts_one() {  # KNOWN CANNED: cts_class on CANNED, then cts_compare with KNOWN
    : > "$t/res"
    printf '%s\n' "$2" | cts_class "$sse" "$t/res"
    cts_compare "$1" "$t/res"
  }
  : > "$t/known-none"
  printf '%s\n' "$sse#test_SSLSocket_SNI_ipLiteral" "$sse#test_SSLSocket_SNI_setHostname" > "$t/known-both"
  case_rc "cts: records match the summary, both failures known" 0 cts_one "$t/known-both" "$CTS_CANNED"
  case_rc "cts: summary counts a failure that has no record" 1 cts_one "$t/known-none" "$(printf '%s\n' "$CTS_CANNED" |
    grep -v -e '^INSTRUMENTATION_STATUS_CODE: -' -e '^INSTRUMENTATION_STATUS: stack=' -e '^	at ')"
  case_rc "cts: summary counts more failures than records" 1 cts_one "$t/known-both" \
    "$(printf '%s\n' "$CTS_CANNED" | sed 's/Failures: 1,  Errors: 1/Failures: 2,  Errors: 1/')"
  case_rc "cts: output the parser cannot read" 1 cts_one "$t/known-none" \
    "$(printf '%s\n' "$CTS_CANNED" | sed 's/^INSTRUMENTATION_STATUS_CODE: 0$/INSTRUMENTATION_STATUS_CODE: garbled/')"
  # cts: ForEachRunner wraps a ClientHello test's failure; the record names the root cause (the last "Caused by: ")
  printf '%s\n' "? $sse#test_SSLSocket_ClientHello_* java.util.concurrent.CancellationException" > "$t/known-q"
  case_rc "cts: a '?' entry allows its root cause inside ForEachRunner's wrapper" 0 cts_one "$t/known-q" \
    "$(cts_wrapped java.util.concurrent.CancellationException)"
  case_rc "cts: a wrapped assertion failure (root cause) is UNEXPECTED" 1 cts_one "$t/known-q" \
    "$(cts_wrapped 'junit.framework.AssertionFailedError: expected:<[0]> but was:<[1]>' \
      java.util.concurrent.CancellationException)"
  # the shipped list (review 3 iteration 3): libcore/0031 fixed the capture race, so a CancellationException in a
  # ClientHello test is UNEXPECTED; testConnectTimeouts may pass or fail with its ErrnoException root cause only
  case_rc "cts: shipped list, a CancellationException in a ClientHello test is UNEXPECTED" 1 cts_one \
    "$HERE/cts-known-failures.txt" "$(cts_wrapped java.util.concurrent.CancellationException)"
  local uct=libcore.java.net.URLConnectionTest
  printf 'RAN %s\nFAILED %s#testConnectTimeouts libcore.io.ErrnoException: connect failed: ETIMEDOUT (Connection timed out)\n' \
    "$uct" "$uct" > "$t/ct-errno"
  printf 'RAN %s\nFAILED %s#testConnectTimeouts junit.framework.AssertionFailedError\n' "$uct" "$uct" > "$t/ct-assert"
  printf 'RAN %s\n' "$uct" > "$t/ct-pass"
  case_rc "cts: shipped list, testConnectTimeouts with its ErrnoException" 0 cts_compare "$HERE/cts-known-failures.txt" "$t/ct-errno"
  case_rc "cts: shipped list, testConnectTimeouts passing" 0 cts_compare "$HERE/cts-known-failures.txt" "$t/ct-pass"
  case_rc "cts: shipped list, testConnectTimeouts with an assertion is UNEXPECTED" 1 cts_compare \
    "$HERE/cts-known-failures.txt" "$t/ct-assert"
  # cts: the summary must be complete and count at least one test (review 3 codex 3, review 4b)
  cts_sum() {  # SUMMARY: canned output of one passing test followed by SUMMARY
    printf '%s\n' "INSTRUMENTATION_STATUS: class=$sse" "INSTRUMENTATION_STATUS: test=test_x" "INSTRUMENTATION_STATUS_CODE: 1" \
      "INSTRUMENTATION_STATUS: class=$sse" "INSTRUMENTATION_STATUS: test=test_x" "INSTRUMENTATION_STATUS_CODE: 0" \
      "INSTRUMENTATION_RESULT: stream=" "Test results for InstrumentationCtsTestRunner=." "$1" "INSTRUMENTATION_CODE: -1"
  }
  case_rc "cts: OK (1 test) passes" 0 cts_one "$t/known-none" "$(cts_sum 'OK (1 test)')"
  case_rc "cts: OK (0 tests) is no evidence" 1 cts_one "$t/known-none" "$(cts_sum 'OK (0 tests)')"
  case_rc "cts: a cut summary 'OK (' fails" 1 cts_one "$t/known-none" "$(cts_sum 'OK (')"
  case_rc "cts: 'OK (2 tests) garbage' fails" 1 cts_one "$t/known-none" "$(cts_sum 'OK (2 tests) garbage')"
  case_rc "cts: Tests run: 0 fails" 1 cts_one "$t/known-none" "$(cts_sum 'Tests run: 0,  Failures: 0,  Errors: 0')"
  # cts: arguments must be PKG:CLASS[#method]; a bare class name used to run nothing and pass
  case_rc "cts: a class without its libcore: prefix is a tool error" 2 env ADB="$t/adb" bash "$0" cts S "$t" \
    libcore.javax.net.ssl.SSLSocketTest
  case_rc "cts: an empty argument is a tool error" 2 env ADB="$t/adb" bash "$0" cts S "$t" ""
  case_rc "cts: libcore:CLASS runs (stub: one passing test)" 0 env ADB="$t/adb" bash "$0" cts S "$t" libcore:$sse
  # cts: a results file that cannot be written is no verdict (review 3, codex 5: a lost append passed)
  mkdir -p "$t/res-dir" "$t/rotmp"
  cts_into() { printf '%s\n' "$2" | cts_class "$sse" "$1"; }  # RESULTS CANNED
  case_rc "cts_class: an unwritable results file is exit 2" 2 cts_into "$t/res-dir" "$(cts_sum 'OK (1 test)')"
  : > "$t/res-empty"
  case_rc "cts_compare: a results file without a RAN line is no verdict" 2 cts_compare "$t/known-none" "$t/res-empty"
  if [ "$(id -u)" = 0 ]; then echo "selftest SKIP cts: read-only results file (root ignores the mode)"
  else
    case_rc "cts: the results file turns read-only during the run" 2 env ADB="$t/adb" TMPDIR="$t/rotmp" \
      STUB_RO="$t/rotmp" bash "$0" cts S "$t" libcore:$sse
  fi
  # cts: adb failing after an OK summary is no verdict; a "$" in a class or method name reaches the device shell
  # literally (review 3, codex 6: exit 0 next to "fail=1"; Outer$Inner ran Outer)
  case_rc "cts: adb exits 1 after an OK summary (device gone) is no verdict" 2 env ADB="$t/adb" STUB_RC=1 \
    bash "$0" cts S "$t" libcore:$sse
  cts_dollar() {  # PKG:CLASS[#method]: cts runs, and the stub's device shell got CLASS[#method] unchanged
    : > "$t/stub-log"
    env ADB="$t/adb" STUB_LOG="$t/stub-log" bash "$0" cts S "$t" "$1" && grep -qxF "RAN-CLASS ${1#*:}" "$t/stub-log"
  }
  # shellcheck disable=SC2016  # a literal "$" in the class and method names is the point of these two cases
  case_rc "cts: a nested class p.Outer\$Inner reaches the device shell as written" 0 cts_dollar 'libcore:p.Outer$Inner'
  # shellcheck disable=SC2016
  case_rc "cts: p.Outer\$Inner#test_\$x reaches the device shell as written" 0 cts_dollar 'conscrypt:p.Outer$Inner#test_$x'
  case_rc "cts: a plain class reaches the device shell as written" 0 cts_dollar libcore:$sse
  # cts: a run of one method compares that method's entry (CLASS#method in RAN)
  printf 'RAN %s#test_k\nFAILED %s#test_k java.lang.AssertionError\n' "$sse" "$sse" > "$t/one-method"
  printf '%s\n' "$sse#test_k" > "$t/known-k"
  case_rc "cts_compare: a single-method run with its known entry" 0 cts_compare "$t/known-k" "$t/one-method"
  # build: the jar step checks each step (review 3 codex 3: a failed zip or move still printed "built")
  sub() { ( "$@" ); }
  mkdir -p "$t/dex" "$t/nodex" "$t/badzip"; printf 'dex\n' > "$t/dex/classes.dex"
  printf '#!/bin/sh\nexit 1\n' > "$t/badzip/zip"; chmod +x "$t/badzip/zip"
  case_rc "build: no classes.dex is a tool error" 2 sub pack_dex "$t/nodex" "$t/p1.jar"
  case_rc "build: a failing zip is a tool error" 2 env PATH="$t/badzip:$PATH" bash -c \
    ". \"\$1\" pack-only; pack_dex \"\$2\" \"\$3\"" _ "$0" "$t/dex" "$t/p2.jar"
  case_rc "build: an unwritable output is a tool error" 2 sub pack_dex "$t/dex" "$t/no/such/dir/p3.jar"
  case_rc "build: a good dex makes a jar with classes.dex" 0 sub pack_dex "$t/dex" "$t/p4.jar"
  case_rc "build: the jar holds classes.dex" 0 sh -c "unzip -l '$t/p4.jar' | grep -q ' classes.dex\$'"
  # fallback: the probe output of each run against its verdict (logcat count given)
  local fb_ok fb_ctl
  fb_ok='PID fallback-blocked 4242
DEFAULT fallback-blocked io.github.hsw.kktls.KktlsDefaultSSLSocketFactory [platform: x]
ENABLED fallback-blocked protocols=[TLSv1, TLSv1.1, TLSv1.2] suites(13)=[x]
RESULT fallback-blocked OK protocol=TLSv1.2 suite=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
  fb_ctl='PID fallback-control 4243
DEFAULT fallback-control io.github.hsw.kktls.KktlsDefaultSSLSocketFactory [conscrypt: x]
ENABLED fallback-control protocols=[TLSv1, TLSv1.1, TLSv1.2, TLSv1.3] suites(16)=[x]'
  case_rc "fallback: blocked run with its one line and a TLSv1.2 handshake" 0 fallback_verdict blocked "$fb_ok" 1
  case_rc "fallback: control run OK" 0 fallback_verdict control "$fb_ctl
DEX fallback-control [x]
RESULT fallback-control OK no handshake" 0
  case_rc "fallback: control RESULT FAIL after DEFAULT and ENABLED" 1 fallback_verdict control "$fb_ctl
RESULT fallback-control FAIL class=other java.lang.IllegalStateException: x" 0
  case_rc "fallback: control process died after ENABLED (no RESULT)" 1 fallback_verdict control "$fb_ctl
Segmentation fault" 0
  case_rc "fallback: control without a PID line (logcat count unbound)" 1 fallback_verdict control \
    "$(printf '%s\n' "$fb_ctl" | grep -v '^PID')
RESULT fallback-control OK no handshake" 0
  case_rc "fallback: truncated run refused by the ELF check" 0 elf_check_verdict \
    "10-15 20:00:00.000  4242  4242 W KktlsSslFactory: java.io.IOException: ELF check of /system/lib/libkktls_conscrypt_jni.so: PT_LOAD segment 3 ends at byte 1300000, past the end of the file (4096 bytes): truncated"
  case_rc "fallback: truncated run refused by something else" 1 elf_check_verdict \
    "10-15 20:00:00.000  4242  4242 W KktlsSslFactory: java.lang.UnsatisfiedLinkError: dlopen failed"
  case_rc "fallback: truncated run without lines" 1 elf_check_verdict ""
  # setters: the stack of each factory's sockets must follow the gate, and every case must be OK
  local st_c='RESULT setters-default OK stack=conscrypt cases=6' st_p='RESULT setters-context OK stack=platform cases=6'
  case_rc "setters: gate on, Conscrypt default and platform" 0 setters_verdict conscrypt "$st_c" "$st_p"
  case_rc "setters: gate off, platform on both" 0 setters_verdict platform \
    "RESULT setters-default OK stack=platform cases=6" "$st_p"
  case_rc "setters: gate on but the default factory gave platform sockets" 1 setters_verdict conscrypt \
    "RESULT setters-default OK stack=platform cases=6" "$st_p"
  case_rc "setters: gate off but the default factory gave Conscrypt sockets" 1 setters_verdict platform "$st_c" "$st_p"
  case_rc "setters: a BAD case (RESULT FAIL)" 1 setters_verdict conscrypt \
    "RESULT setters-default FAIL class=other bad=rc4 stack=conscrypt cases=6" "$st_p"
  case_rc "setters: the SSLContext run died (no RESULT)" 1 setters_verdict conscrypt "$st_c" "SETTER setters-context rc4 ok x"
  case_rc "setters: the fifth argument must be 'local'" 2 env ADB="$t/adb" bash "$0" setters S "$t/jar" h 443 remote
  # pid_of (no pidof on the SDK 4.4.2 image): exact NAME match; ps-nozygote = the fixture without the zygote row
  printf '%s\n' "$PS_FIXTURE" | sed 's/$/\r/' > "$t/ps"
  grep -v ' zygote.$' "$t/ps" > "$t/ps-nozygote"
  pidis() { [ "$(STUB_PS=$1 pid_of S "$2")" = "$3" ]; }
  case_rc "pid_of: zygote" 0 pidis "$t/ps" zygote 673
  case_rc "pid_of: system_server" 0 pidis "$t/ps" system_server 1070
  case_rc "pid_of: com.example.zygote is not zygote" 0 pidis "$t/ps-nozygote" zygote ""
  pidcaller() { (pid=$(STUB_PS=$1 pid_of S "$2") || exit 2; echo "$pid"); }
  case_rc "pid_of: a missing process is a tool error" 2 pidcaller "$t/ps-nozygote" zygote
  case_rc "pid_of: no ps output is a tool error" 2 pidcaller /dev/null zygote
  gate_nozygote() {  # exit 2, the message, and no gate read or set before it
    env ADB="$t/adb" STUB_D=1 STUB_PS="$t/ps-nozygote" bash "$0" gate S "$t/jar" h 443 > "$t/gate-out" 2>&1
    [ $? = 2 ] && grep -q "no process 'zygote'" "$t/gate-out" && ! grep -q 'before the run' "$t/gate-out"
  }
  case_rc "gate: no zygote is a tool error before the gate is touched" 0 gate_nozygote
  case_rc "mem: no zygote is a tool error" 2 env ADB="$t/adb" STUB_PS="$t/ps-nozygote" bash "$0" mem S "$t/jar" load
  if [ -n "${1:-}" ]; then
    for j in framework ext; do [ -f "$1/$j.jar" ] || die "$1/$j.jar missing"; done
    mkdir -p "$t/classes"
    javac -nowarn --release 8 -cp "$1/framework.jar:$1/ext.jar" -d "$t/classes" "$HERE/probe/Tls12Probe.java" \
      "$HERE/probe/shadow/org/conscrypt/Conscrypt.java" || die "javac failed"
    case_rc "Tls12Probe selftest (classify, both verdict, setters) on the host JVM" 0 java -cp "$t/classes:$1/framework.jar:$1/ext.jar" Tls12Probe selftest
    sed 's/^/    /' "$t/out"
  else
    echo "selftest SKIP Tls12Probe selftest (give CLASSES_DIR with framework.jar and ext.jar)"
  fi
  run_cleanups
  echo "SELFTEST $([ $fail = 0 ] && echo PASS || echo FAIL) ($n cases)"
  [ $fail = 0 ]
}

[ "${1:-}" = pack-only ] && return 0 2>/dev/null  # sourced by the selftest's stub-zip case: functions only
case ${1:-} in
  cts) [ $# -ge 3 ] || die "usage: cts SERIAL APKDIR [libcore|conscrypt:CLASS ...]"; cmd_cts "${@:2}" ;;
  prep) [ $# -eq 5 ] || die "usage: prep SERIAL CACERTS_DIR HOSTNAME IP"; cmd_prep "${@:2}" ;;
  build) [ $# -eq 3 ] || die "usage: build CLASSES_DIR OUT.jar"; cmd_build "$2" "$3" ;;
  dump) [ $# -eq 3 ] || die "usage: dump SERIAL JAR"; push_jar "$2" "$3"; probe "$2" dump ;;
  matrix) [ $# -eq 3 ] || die "usage: [PROBE_LAYER=d] matrix SERIAL JAR"; push_jar "$2" "$3"
    if [ "${PROBE_LAYER:-a}" = d ]; then need_gate_on "$2"; run_rows "$2" "$MATRIX
$MATRIX_D_EXTRA"; else run_rows "$2" "$MATRIX"; fi ;;
  rows) [ $# -eq 4 ] || die "usage: [PROBE_LAYER=d] rows SERIAL JAR ROWSFILE"
    [ -f "$4" ] && [ -r "$4" ] || die "ROWSFILE $4 missing or unreadable"; push_jar "$2" "$3"
    [ "${PROBE_LAYER:-a}" = d ] && need_gate_on "$2"; run_rows "$2" "$(cat "$4")" ;;
  both) [ $# -eq 8 ] || die "usage: both SERIAL JAR PHOST PPORT CHOST CPORT CPROTOCOLS|-"; cmd_both "${@:2}" ;;
  local) [ $# -ge 4 ] || die "usage: local SERIAL JAR HOSTNAME [PORT]"; cmd_local "${@:2}" ;;
  fallback) [ $# -eq 5 ] || die "usage: fallback SERIAL JAR HOST PORT"; cmd_fallback "${@:2}" ;;
  shadow) [ $# -eq 5 ] || die "usage: shadow SERIAL JAR HOST PORT"; cmd_shadow "${@:2}" ;;
  appmix) [ $# -ge 6 ] || die "usage: appmix SERIAL JAR APPJAR APPSO HOSTNAME [PORT]"; cmd_appmix "${@:2}" ;;
  sniprop) [ $# -ge 4 ] || die "usage: sniprop SERIAL JAR HOSTNAME [PORT]"; cmd_sniprop "${@:2}" ;;
  mem) [ $# -eq 4 ] || die "usage: mem SERIAL JAR url:URL|load|local:HOST:PORT:PROTOS"; cmd_mem "${@:2}" ;;
  intolerant) [ $# -ge 4 ] || die "usage: intolerant SERIAL JAR HOSTNAME [PORT]"; cmd_intolerant "${@:2}" ;;
  hello) [ $# -ge 5 ] || die "usage: hello SERIAL JAR HOSTNAME DEVICE_IP [PORT]"; cmd_hello "${@:2}" ;;
  gate) [ $# -eq 5 ] || die "usage: gate SERIAL JAR HOST PORT"; cmd_gate "${@:2}" ;;
  setters) [ $# -eq 5 ] || [ $# -eq 6 ] || die "usage: setters SERIAL JAR HOST PORT [local]"; cmd_setters "${@:2}" ;;
  selftest) [ $# -le 2 ] || die "usage: selftest [CLASSES_DIR]"; cmd_selftest "${@:2}" ;;
  *) awk 'NR > 1 && !/^#/ {exit} NR > 1' "$0"; exit 2 ;;
esac
