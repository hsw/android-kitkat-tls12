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
# stub-platform-jb/ (the Android 4.1-4.3 platform factory org.apache.harmony.xnet.provider.jsse.OpenSSLSocketFactoryImpl)
# and stub-kitkat/ (com.android.org.conscrypt.OpenSSLSocketImpl, whose presence keeps Conscrypt's KitKat adapter) are the
# Jelly Bean and 4.4 platform shapes of the same wrapper source.
# The wrapper is compiled from a copy whose only changes are SYSTEM_ROOT = <temp>/system and PROC_ROOT = <temp>/proc
# (checked: exactly these two lines), so "layer D installed" (<root>/framework/kktls-conscrypt.jar exists) is a real
# file the test creates and deletes, and so are the auxv and cpuinfo of the NEON check.
# libcore/0025 and the Jelly Bean libcore patch that adds the wrapper (patches/jb/<base>/libcore/, each base that has
# one) must carry the same source byte for byte (checked first; the patches are what the images build).
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

mkdir -p "$out"/{test,stub-platform,stub-platform-jb,stub-kitkat,stub-conscrypt,stub-conscrypt-253,stub-android,stub-dalvik,wrapper,filter}
# The SSLv3-filtering wrapper socket (kktls-sslfilter.jar): compiled into its own dir and reached ONLY through
# -Dkktlstest.filter (the stub PathClassLoader's kktls-sslfilter.jar, and the filter unit test's own loader), never on the
# test's own classpath -- so clearing -Dkktlstest.filter makes the class genuinely absent, as a missing jar would.
jc -d "$out/filter" $(find "$here/../../sslfilter/src" -name '*.java')
jc -cp "$JUNIT_JAR" -d "$out/test" "$here"/kktlstest/*.java
jc -cp "$out/test" -d "$out/stub-platform" $(find "$here/stub-platform" -name '*.java')
jc -cp "$out/test" -d "$out/stub-platform-jb" $(find "$here/stub-platform-jb" -name '*.java')
jc -cp "$out/test" -d "$out/stub-kitkat" $(find "$here/stub-kitkat" -name '*.java')
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
wrapper_diff="diff --git a/luni/src/main/java/io/github/hsw/kktls/KktlsDefaultSSLSocketFactory.java b/luni/src/main/java/io/github/hsw/kktls/KktlsDefaultSSLSocketFactory.java"
# the Jelly Bean series next to patches/libcore/ (none under a KKTLS_LIBCORE_PATCH outside a repository)
jb_patches=$(grep -lxF "$wrapper_diff" "$(dirname "$(dirname "$(dirname "$patch")")")"/patches/jb/*/libcore/*.patch 2>/dev/null) || true
for p in "$patch" $jb_patches; do
  awk -v want="$wrapper_diff" '/^diff --git / { on = ($0 == want); body = 0; next }
       on && /^@@ / { body = 1; next }
       on && body && /^\+/ { print substr($0, 2); next }
       on && body && /^-- $/ { on = 0 }' "$p" > "$out/patch-wrapper.java"
  cmp -s "$out/patch-wrapper.java" "$(find "$here/../src" -name 'KktlsDefaultSSLSocketFactory.java')" ||
    { echo "run-host-tests: $p does not add ../src's KktlsDefaultSSLSocketFactory.java byte for byte" >&2; exit 1; }
  echo "libcore patch carries the wrapper source: ${p#"$(dirname "$(dirname "$(dirname "$patch")")")"/}"
done
# the copy with SYSTEM_ROOT = $out/system (one line, or the test would check another file than the wrapper's)
src=$(find "$here/../src" -name 'KktlsDefaultSSLSocketFactory.java')
[ "$(find "$here/../src" -name '*.java' | wc -l)" = 1 ] || { echo "run-host-tests: want exactly one source in ../src" >&2; exit 2; }
root_line='    static final String SYSTEM_ROOT = "/system";'
proc_line='    static final String PROC_ROOT = "/proc";'
[ "$(grep -cxF "$root_line" "$src")" = 1 ] || { echo "run-host-tests: no single SYSTEM_ROOT line in $src" >&2; exit 2; }
[ "$(grep -cxF "$proc_line" "$src")" = 1 ] || { echo "run-host-tests: no single PROC_ROOT line in $src" >&2; exit 2; }
mkdir -p "$out/wrapper-src/io/github/hsw/kktls" "$out/system" "$out/proc"
awk -v want="$root_line" -v root="$out/system" -v pwant="$proc_line" -v proc="$out/proc" '
  $0 == want { print "    static final String SYSTEM_ROOT = \"" root "\";"; next }
  $0 == pwant { print "    static final String PROC_ROOT = \"" proc "\";"; next } { print }' \
  "$src" > "$out/wrapper-src/io/github/hsw/kktls/KktlsDefaultSSLSocketFactory.java"
[ "$(diff "$src" "$out/wrapper-src/io/github/hsw/kktls/KktlsDefaultSSLSocketFactory.java" | grep -c '^[<>]')" = 4 ] ||
  { echo "run-host-tests: the test copy differs from the wrapper in more than the SYSTEM_ROOT and PROC_ROOT lines" >&2; exit 2; }
jc -d "$out/wrapper" "$out/wrapper-src/io/github/hsw/kktls/KktlsDefaultSSLSocketFactory.java"

# junit.textui.TestRunner runs one class per invocation, so run each (both must pass).
for t in kktlstest.KktlsDefaultSSLSocketFactoryTest kktlstest.KktlsFilteringSSLSocketTest; do
  echo "== $t =="
  "$JAVA" -cp "$JUNIT_JAR:$out/test" \
    -Dkktlstest.wrapper="$out/wrapper" -Dkktlstest.stub.platform="$out/stub-platform" \
    -Dkktlstest.stub.platformjb="$out/stub-platform-jb" -Dkktlstest.stub.kitkat="$out/stub-kitkat" \
    -Dkktlstest.stub.conscrypt="$out/stub-conscrypt" -Dkktlstest.stub.conscrypt253="$out/stub-conscrypt-253" \
    -Dkktlstest.stub.android="$out/stub-android" -Dkktlstest.stub.dalvik="$out/stub-dalvik" \
    -Dkktlstest.filter="$out/filter" -Dkktlstest.system="$out/system" -Dkktlstest.proc="$out/proc" \
    junit.textui.TestRunner "$t"
done
