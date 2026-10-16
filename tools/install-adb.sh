#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install kktls release zips over adb, without a custom recovery: emulators, eng/userdebug builds, CI tests.
#
#   install-adb.sh [-s SERIAL] [--busybox FILE] [--no-reboot] ZIP...
#   install-adb.sh [-s SERIAL] [--busybox FILE] [--no-reboot] --restore RESTORE_ZIP
#
# The device must allow `adb root` (eng/userdebug builds, the SDK emulator images). Each ZIP is unpacked on the host,
# pushed to /data/local/tmp/kktls-adb/ and installed by the zip's own kktls/checks.sh and kktls/install.sh, the code
# the recovery runs (update-binary): the same pre-checks (any failure aborts before anything is written), the same
# backups in /data/kktls-backup/ plus the copy on /sdcard, the same marker files. The zips are applied in the order
# given and the run stops at the first refusal or failure. --restore runs the kktls-restore zip (only with this flag).
# An enforcing SELinux device is set permissive (setenforce 0) for the run and enforcing again at the end: the 4.4
# policy denies the root shell the relabel to system_file. The Android framework is stopped (`stop`) before the first
# zip; the device reboots at the end (--no-reboot: it is left stopped and the caller reboots it; a refusal of the
# first zip starts the framework again).
#
# A stock Android 4.4 shell (toolbox) lacks sed, awk, find, sort, cmp and tail, which the installer scripts use, so a
# static busybox runs them. By default the script downloads the upstream static build of busybox 1.31.0 for the
# device's ABI from busybox.net (checked against the sha256 below) into ${KKTLS_CACHE:-~/.cache/kktls}; --busybox FILE
# pushes your own instead. busybox is GPL-2.0 (source: https://busybox.net/downloads/busybox-1.31.0.tar.bz2); it is
# only downloaded and pushed to the device for the run, then deleted. It is not part of this repository or the zips.
#
# Exit 0 all zips installed, 1 a zip was refused or failed, 2 usage or host-side error.
set -euo pipefail
export LC_ALL=C

BB_VERSION=1.31.0
BB_URL=https://busybox.net/downloads/binaries/$BB_VERSION-defconfig-multiarch-musl
BB_SHA256_armv7l=cd04052b8b6885f75f50b2a280bfcbf849d8710c8e61d369c533acf307eda064
BB_SHA256_i686=6c63a8623659aff24843d9b0720fa4aa216d44a5d60f29979a4073f3f80ce69c
DEV=/data/local/tmp/kktls-adb

die() { echo "install-adb.sh: $*" >&2; exit 2; }
usage() { sed -n '3,6p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

SERIAL='' BUSYBOX='' REBOOT=1 RESTORE=0 ZIPS=()
while [ $# -gt 0 ]; do
  case $1 in
    -s) [ $# -ge 2 ] || usage; SERIAL=$2; shift 2 ;;
    --busybox) [ $# -ge 2 ] || usage; BUSYBOX=$2; shift 2 ;;
    --no-reboot) REBOOT=0; shift ;;
    --restore) RESTORE=1; shift ;;
    -h|--help) sed -n '3,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $1" ;;
    *) ZIPS+=("$1"); shift ;;
  esac
done
[ ${#ZIPS[@]} -gt 0 ] || usage
for t in adb unzip; do command -v $t > /dev/null || die "$t not found"; done
[ -z "$BUSYBOX" ] || [ -f "$BUSYBOX" ] || die "--busybox: no such file: $BUSYBOX"

sha256() { if command -v sha256sum > /dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

# finish (the EXIT trap, also on die and on errors): the device work dir removed and SELinux enforcing again when this
# run changed it; once only, and harmless when the device is gone (every adb call may fail)
A=(adb); [ -z "$SERIAL" ] || A+=(-s "$SERIAL")
DEVDIR=0 SETENF=0 FINISHED=0
finish() {
  [ "$FINISHED" = 0 ] || return 0
  FINISHED=1
  if [ "$DEVDIR" = 1 ]; then "${A[@]}" shell "rm -r $DEV" > /dev/null 2>&1 || true; fi
  if [ "$SETENF" = 1 ]; then
    if [ "$("${A[@]}" shell 'setenforce 1; getenforce' 2> /dev/null | tr -d '\r' || true)" = Enforcing ]; then
      echo "install-adb.sh: SELinux enforcing again"
    else
      echo "install-adb.sh: WARNING: could not set SELinux enforcing again (device gone?)" >&2
    fi
  fi
  return 0
}
T=$(mktemp -d); trap 'finish; rm -rf "$T"' EXIT

# ---- the zips, unpacked and checked on the host before the device is touched --------------------------------------
KINDS=()
i=0
for z in "${ZIPS[@]}"; do
  [ -f "$z" ] || die "no such zip: $z"
  i=$((i + 1)); d=$T/z$i
  mkdir -p "$d"
  unzip -q "$z" -d "$d" || die "cannot unpack $z"
  for f in kktls/zip.conf kktls/checks.sh kktls/install.sh; do
    [ -f "$d/$f" ] || die "$z is not a kktls zip (no $f)"
  done
  k=$(sed -n 's/^kind=//p' "$d/kktls/zip.conf" | tail -n 1)
  KINDS+=("$k")
done
if [ $RESTORE = 1 ]; then
  [ ${#ZIPS[@]} = 1 ] && [ "${KINDS[0]}" = restore ] || die "--restore takes exactly one kktls-restore zip"
else
  for k in "${KINDS[@]}"; do [ "$k" != restore ] || die "a kktls-restore zip needs --restore"; done
fi

# ---- the device ---------------------------------------------------------------------------------------------------
dsh() { "${A[@]}" shell "$@" | tr -d '\r'; }

"${A[@]}" root > /dev/null 2>&1 || true
"${A[@]}" wait-for-device
n=0
until [ "$(dsh id 2> /dev/null | sed -n 's/^uid=\([0-9]*\).*/\1/p')" = 0 ]; do  # adbd restarts as root
  n=$((n + 1)); [ $n -le 30 ] || die "adb is not root on the device (adb root refused: a user build?)"
  sleep 1; "${A[@]}" wait-for-device
done
"${A[@]}" remount > "$T/remount.txt" 2>&1 || true

abi=$(dsh getprop ro.product.cpu.abi)
case $abi in
  x86*) bbarch=i686 ;;
  arm*) bbarch=armv7l ;;
  *) die "unsupported ro.product.cpu.abi '$abi'" ;;
esac
if [ -z "$BUSYBOX" ]; then
  cache=${KKTLS_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/kktls}
  BUSYBOX=$cache/busybox-$BB_VERSION-$bbarch
  case $bbarch in i686) want=$BB_SHA256_i686 ;; *) want=$BB_SHA256_armv7l ;; esac
  if [ ! -f "$BUSYBOX" ] || [ "$(sha256 "$BUSYBOX")" != "$want" ]; then
    command -v curl > /dev/null || die "curl not found (or pass --busybox FILE)"
    mkdir -p "$cache"
    curl -sSfL -o "$BUSYBOX.part" "$BB_URL/busybox-$bbarch" || die "cannot download $BB_URL/busybox-$bbarch"
    [ "$(sha256 "$BUSYBOX.part")" = "$want" ] || { rm -f "$BUSYBOX.part"; die "busybox-$bbarch: sha256 mismatch"; }
    mv -f "$BUSYBOX.part" "$BUSYBOX"
  fi
fi

# SELinux: an enforcing 4.4 policy denies the adb root shell (domain shell) the relabel to system_file that the
# installer needs (avc: denied { relabelto }); `runcon u:r:su:s0` does not help, the busybox and the tools it runs
# end up in domain shell again. So the device is permissive for the run and enforcing again at the end.
if [ "$(dsh getenforce 2> /dev/null)" = Enforcing ]; then
  [ "$(dsh 'setenforce 0 2> /dev/null; getenforce')" = Permissive ] ||
    die "SELinux is enforcing and setenforce 0 is refused: cannot label the installed files"
  SETENF=1; echo "install-adb.sh: SELinux permissive for the run"
fi
DEVDIR=1
# toolbox rm of Android 4.1 has no -f: rm -r; the run fails when an old work dir cannot be removed
dsh "rm -r $DEV 2> /dev/null; mkdir $DEV && mkdir $DEV/bb && echo DIROK" | grep -qx DIROK || die "cannot create a fresh $DEV"
"${A[@]}" push "$BUSYBOX" "$DEV/bb/busybox" > /dev/null 2>&1 || die "cannot push busybox"
dsh "chmod 0755 $DEV/bb/busybox && $DEV/bb/busybox --install -s $DEV/bb && echo BBOK" | grep -qx BBOK ||
  die "the busybox does not run on the device ($abi)"

echo "install-adb.sh: stopping the Android framework"
dsh stop > /dev/null
i=0 done_n=0
for z in "${ZIPS[@]}"; do
  i=$((i + 1))
  echo "== $(basename "$z")"
  # a new directory per zip: a push into an existing directory would nest (zip<i>/z<i>) and run the old scripts
  "${A[@]}" push "$T/z$i" "$DEV/zip$i" > /dev/null 2>&1 || die "cannot push $z"
  # the zip's scripts under busybox sh; busybox tools first on PATH, toolbox (chcon) after them
  dsh "cd / && export PATH=$DEV/bb:/system/bin:/system/xbin KK_ROOT= KK_DIR=$DEV/zip$i KK_OUTFD= && \
$DEV/bb/sh -c 'chmod 0755 \"\$KK_DIR\"/kktls/bin/*/* 2> /dev/null; . \"\$KK_DIR/kktls/checks.sh\" && \
. \"\$KK_DIR/kktls/install.sh\" && kk_main' 2>&1; echo KKTLS_RC=\$?" > "$T/out" || true
  grep -v '^KKTLS_RC=' "$T/out" || true
  rc=$(sed -n 's/^KKTLS_RC=//p' "$T/out" | tail -n 1)
  if [ "$rc" != 0 ]; then
    echo "install-adb.sh: $(basename "$z") FAILED (rc=${rc:-none})"
    finish
    if [ $done_n = 0 ]; then
      dsh start > /dev/null || true
      echo "install-adb.sh: nothing was installed in this run; framework started again"
    else
      echo "install-adb.sh: $done_n zip(s) of this run are installed; reboot the device"
    fi
    exit 1
  fi
  done_n=$((done_n + 1))
done
finish
if [ $REBOOT = 1 ]; then
  echo "install-adb.sh: $done_n zip(s) done, rebooting"
  "${A[@]}" reboot
else
  echo "install-adb.sh: $done_n zip(s) done; the framework is stopped: reboot the device now"
fi
