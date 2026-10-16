#!/bin/bash
# run-host-tests.sh: host tests of io.github.hsw.kktls.KktlsDefaultSSLSocketFactory (the default SSLSocketFactory that
# libcore/0025 adds to libcore) and of org.conscrypt.KktlsFilteringSSLSocket (kktls-sslfilter) on a host JDK with
# JUnit 3.8.2 and stub classes. Never part of the image.
#
#   conscrypt/sslfactory/test/run-host-tests.sh [--keep]
#     JAVA_HOME=<jdk> (default: java/javac on PATH, >= 8); JUNIT_JAR=<junit-3.8.2.jar>
#     (default ~/.m2/repository/junit/junit/3.8.2/junit-3.8.2.jar)
#
# Compiles into a temp dir with --release 8 (the floor of current JDKs): kktlstest/ (the recording factory and the test),
# stub-platform/ (com.android.org.conscrypt.OpenSSLSocketFactoryImpl), stub-conscrypt/ (org.conscrypt.Conscrypt 2.6-alpha2,
# served only through the stub PathClassLoader as the "kktls-conscrypt.jar"), stub-conscrypt-253/ (the same class with the
# 2.5.3 API shape: a builder without the TLSv1 switches), stub-android/ (android.os.SystemProperties, the kill switch
# persist.kktls.conscrypt from -Dkktlstest.gate), stub-dalvik/ (dalvik.system.PathClassLoader, the wrapper's own
# loader for the jar, which is off the boot class path), and the wrapper from ../src against nothing but the JDK, so a
# compile-time reference to org.conscrypt, android.os, dalvik.system or the platform class would fail here. The test
# loads the wrapper with a different stub set per case (see the test's header).
# The wrapper is compiled from a copy whose only change is SYSTEM_ROOT = <temp>/system (checked: exactly one line), so
# "layer D installed" (<root>/framework/kktls-conscrypt.jar exists) is a real file the test creates and deletes.
# libcore/0025 must carry the same source byte for byte (checked first; the patch is what the image builds).
# The host JDK cannot prove Java 6 source compatibility; the KitKat build of libcore (javac 6) does.
# SPDX-License-Identifier: Apache-2.0
set -eu
here=$(cd "$(dirname "$0")" && pwd)
keep=0; [ "${1:-}" = --keep ] && keep=1
JUNIT_JAR=${JUNIT_JAR:-$HOME/.m2/repository/junit/junit/3.8.2/junit-3.8.2.jar}
[ -f "$JUNIT_JAR" ] || [ ! -f /usr/share/java/junit-3.8.2.jar ] || JUNIT_JAR=/usr/share/java/junit-3.8.2.jar   # Debian junit package
[ -f "$JUNIT_JAR" ] || { echo "run-host-tests: no JUnit 3.8.2 jar at $JUNIT_JAR (set JUNIT_JAR)" >&2; exit 2; }
if [ -n "${JAVA_HOME:-}" ]; then JAVA=$JAVA_HOME/bin/java JAVAC=$JAVA_HOME/bin/javac; else JAVA=java JAVAC=javac; fi
out=$(mktemp -d "${TMPDIR:-/tmp}/kktls-sslfactory-test.XXXXXX")
[ $keep = 1 ] && echo "build dir: $out" || trap 'rm -rf "$out"' EXIT
jc() { "$JAVAC" --release 8 -encoding UTF-8 -Xlint:-options -nowarn "$@"; }

mkdir -p "$out"/{test,stub-platform,stub-conscrypt,stub-conscrypt-253,stub-android,stub-dalvik,wrapper,filter}
# The SSLv3-filtering wrapper socket (kktls-sslfilter.jar): compiled into its own dir and reached ONLY through
# -Dkktlstest.filter (the stub PathClassLoader's kktls-sslfilter.jar, and the filter unit test's own loader), never on the
# test's own classpath -- so clearing -Dkktlstest.filter makes the class genuinely absent, as a missing jar would.
jc -d "$out/filter" $(find "$here/../../sslfilter/src" -name '*.java')
jc -cp "$JUNIT_JAR" -d "$out/test" "$here"/kktlstest/*.java
jc -cp "$out/test" -d "$out/stub-platform" $(find "$here/stub-platform" -name '*.java')
jc -cp "$out/test" -d "$out/stub-conscrypt" $(find "$here/stub-conscrypt" -name '*.java')
jc -cp "$out/test" -d "$out/stub-conscrypt-253" $(find "$here/stub-conscrypt-253" -name '*.java')
jc -cp "$out/test" -d "$out/stub-android" $(find "$here/stub-android" -name '*.java')
jc -cp "$out/test" -d "$out/stub-dalvik" $(find "$here/stub-dalvik" -name '*.java')
# libcore/0025 adds the wrapper as a new file: its "+" lines must be the source (KKTLS_LIBCORE_PATCH overrides the path)
# default: the series' libcore directory of the nearest ancestor that has it (the repository top)
patch=${KKTLS_LIBCORE_PATCH:-}
if [ -z "$patch" ]; then
  d=$here
  while [ "$d" != / ] && [ -z "$patch" ]; do
    patch=$(ls "$d"/patches/libcore/0025-*.patch 2>/dev/null | head -1) || true
    d=$(dirname "$d")
  done
fi
[ -f "$patch" ] || { echo "run-host-tests: no libcore/0025 patch (set KKTLS_LIBCORE_PATCH)" >&2; exit 2; }
awk '/^diff --git / { on = ($0 == "diff --git a/luni/src/main/java/io/github/hsw/kktls/KktlsDefaultSSLSocketFactory.java b/luni/src/main/java/io/github/hsw/kktls/KktlsDefaultSSLSocketFactory.java"); body = 0; next }
     on && /^@@ / { body = 1; next }
     on && body && /^\+/ { print substr($0, 2); next }
     on && body && /^-- $/ { on = 0 }' "$patch" > "$out/patch-wrapper.java"
cmp -s "$out/patch-wrapper.java" "$(find "$here/../src" -name 'KktlsDefaultSSLSocketFactory.java')" ||
  { echo "run-host-tests: $patch does not add ../src's KktlsDefaultSSLSocketFactory.java byte for byte" >&2; exit 1; }
echo "libcore patch carries the wrapper source: $(basename "$patch")"
# the copy with SYSTEM_ROOT = $out/system (one line, or the test would check another file than the wrapper's)
src=$(find "$here/../src" -name 'KktlsDefaultSSLSocketFactory.java')
[ "$(find "$here/../src" -name '*.java' | wc -l)" = 1 ] || { echo "run-host-tests: want exactly one source in ../src" >&2; exit 2; }
root_line='    static final String SYSTEM_ROOT = "/system";'
[ "$(grep -cxF "$root_line" "$src")" = 1 ] || { echo "run-host-tests: no single SYSTEM_ROOT line in $src" >&2; exit 2; }
mkdir -p "$out/wrapper-src/io/github/hsw/kktls" "$out/system"
awk -v want="$root_line" -v root="$out/system" '$0 == want { print "    static final String SYSTEM_ROOT = \"" root "\";"; next } { print }' \
  "$src" > "$out/wrapper-src/io/github/hsw/kktls/KktlsDefaultSSLSocketFactory.java"
[ "$(diff "$src" "$out/wrapper-src/io/github/hsw/kktls/KktlsDefaultSSLSocketFactory.java" | grep -c '^[<>]')" = 2 ] ||
  { echo "run-host-tests: the test copy differs from the wrapper in more than the SYSTEM_ROOT line" >&2; exit 2; }
jc -d "$out/wrapper" "$out/wrapper-src/io/github/hsw/kktls/KktlsDefaultSSLSocketFactory.java"

# junit.textui.TestRunner runs one class per invocation, so run each (both must pass).
for t in kktlstest.KktlsDefaultSSLSocketFactoryTest kktlstest.KktlsFilteringSSLSocketTest; do
  echo "== $t =="
  "$JAVA" -cp "$JUNIT_JAR:$out/test" \
    -Dkktlstest.wrapper="$out/wrapper" -Dkktlstest.stub.platform="$out/stub-platform" \
    -Dkktlstest.stub.conscrypt="$out/stub-conscrypt" -Dkktlstest.stub.conscrypt253="$out/stub-conscrypt-253" \
    -Dkktlstest.stub.android="$out/stub-android" -Dkktlstest.stub.dalvik="$out/stub-dalvik" \
    -Dkktlstest.filter="$out/filter" -Dkktlstest.system="$out/system" \
    junit.textui.TestRunner "$t"
done
