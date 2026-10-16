#!/usr/bin/env bash
# Apply the kktls TLS series (the external_openssl, libcore and external_okhttp patches) to a shallow AOSP 4.4 tree.
# Used by tools/kktls-release-build.sh (and the CI measurement script); meant to run inside the sync container
# (git only: the synced tree is untrusted data, so hooks are off for every git command).
#
#   kktls-apply-series.sh TAG SRC P
#     TAG  android-4.4.2_r2 | android-4.4.4_r2 (other tags exit 2: the per-tag fixups below are known only for these)
#     SRC  the synced tree (repo checkout of the release projects)
#     P    an extracted `git archive` holding patches/external_openssl,
#          patches/libcore, patches/external_okhttp and
#          patches/build/0001-allow-openjdk6.patch
#
# Refuses (exit 3) a tree whose patched projects are not clean at their synced revision: a second run, or a run on a tree
# with local edits, would stack patches or build something else than the release names. Exit 1 on a failed patch.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
TAG=${1:?TAG}; SRC=${2:?SRC}; P=${3:?P}
case $TAG in android-4.4.2_r2|android-4.4.4_r2) ;; *) echo "kktls-apply-series: unknown tag $TAG" >&2; exit 2 ;; esac
cd "$SRC"
g() { git -C "$1" -c core.hooksPath=/dev/null "${@:2}"; }
am() { g "$1" am --keep-cr "${@:2}"; }

# build/: the OpenJDK 6 patch is a plain diff (left uncommitted). A release build applies it before the series, for the
# pristine stock-library build; it counts as clean when exactly that patch is applied (reverse-applies cleanly).
JDK=$P/patches/build/0001-allow-openjdk6.patch
if g build apply -R --check "$JDK" 2>/dev/null; then jdk_done=1; else jdk_done=0; fi
for p in build external/openssl libcore external/okhttp; do
  [ -d "$p/.git" ] || [ -f "$p/.git" ] || { echo "kktls-apply-series: $p is not a git checkout" >&2; exit 3; }
  st=$(g "$p" status --porcelain --untracked-files=normal)
  [ "$p" = build ] && [ $jdk_done = 1 ] && st=$(grep -v -x ' M core/main.mk' <<< "$st" || true)
  if [ -n "$st" ]; then
    echo "kktls-apply-series: $p has local changes (series applied before?); re-sync the tree" >&2; exit 3
  fi
  # repo sync leaves a detached HEAD at the manifest revision (refs/remotes/m/<branch>); anything else is not pristine
  want=$(g "$p" rev-parse -q --verify "refs/remotes/m/$TAG^{commit}" || true)
  if [ -z "$want" ] || [ "$(g "$p" rev-parse HEAD)" != "$want" ]; then
    echo "kktls-apply-series: $p HEAD is not the synced $TAG revision (series applied before?); re-sync the tree" >&2
    exit 3
  fi
done

[ $jdk_done = 1 ] || g build apply "$JDK"
if [ "$TAG" != android-4.4.4_r2 ]; then
  # 4.4.0-4.4.3: external/openssl lacks dd1da36 (Early CCS fix), the only openssl change of KitKat
  g external/openssl fetch -q --depth=2 aosp refs/tags/android-4.4.4_r2
  g external/openssl format-patch -q -1 --stdout FETCH_HEAD > /tmp/dd1da36.patch
  am external/openssl /tmp/dd1da36.patch
fi
am external/openssl "$P"/patches/external_openssl/*.patch
L=$P/patches/libcore
if [ "$TAG" = android-4.4.4_r2 ]; then
  # 4.4.3+: SSLSocketTest.java already imports java.net.InetAddress, so 0012 hunk 1 (two imports) is rejected; a
  # shallow tree has no preimage blob for am -3. Apply the rest, add only the Field import
  # shellcheck disable=SC2046
  am libcore $(ls "$L"/*.patch | head -n 11)
  p12=$(ls "$L"/0012-*.patch); f=luni/src/test/java/libcore/javax/net/ssl/SSLSocketTest.java
  g libcore apply --reject "$p12" || true
  rej=$(cd libcore && find . -name "*.rej" | sort | tr "\n" " ")
  [ "$rej" = "./$f.rej " ] || { echo "0012: unexpected rejects: $rej" >&2; exit 1; }
  grep -q "^import java.net.InetAddress;" "libcore/$f" || { echo "0012: InetAddress import missing" >&2; exit 1; }
  sed -i "s/^import java.lang.reflect.Method;/import java.lang.reflect.Field;\n&/" "libcore/$f"
  rm "libcore/$f.rej"; g libcore add -A
  g libcore commit -q -m "$(sed -n "s/^Subject: \[PATCH[^]]*\] //p" "$p12" | head -n1) (4.4.4: Field import by hand)"
  # shellcheck disable=SC2046
  am libcore $(ls "$L"/*.patch | tail -n +13)
else
  am libcore "$L"/*.patch
fi
am external/okhttp "$P"/patches/external_okhttp/*.patch
for p in build external/openssl libcore external/okhttp; do
  echo "$p $(g "$p" log --oneline | wc -l) commits, HEAD $(g "$p" rev-parse --short HEAD)"
done
