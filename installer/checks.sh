# shellcheck shell=dash disable=SC2034  # dash = POSIX + local; the KK_* settings are also read by install.sh
# kktls installer pre-checks (sourced; POSIX sh: recovery busybox ash, the device mksh over adb).
# SPDX-License-Identifier: Apache-2.0
#
# Shared by the recovery zips (update-binary) and install-adb.sh. Nothing here writes to the device (kk_precheck
# writes the plan and the restore list into KK_DIR only; the functions it calls from install.sh are read-only too).
#
# Inputs (set by the caller before kk_precheck):
#   KK_ROOT   prefix of the device tree ("" on a device; a fake root in the tests)
#   KK_DIR    the unpacked zip: KK_DIR/kktls/zip.conf, KK_DIR/kktls/bin/<abi>/, KK_DIR/system/... (the payload)
# zip.conf (written by mkzips.sh): kind=openssl|cacerts|java|conscrypt|restore, release=<tag>, abi=armeabi-v7a|x86|any,
#   android=4.4.2|4.4.4 (java: the exact ro.build.version.release it was built from) or 4.4 (any 4.4.x)
#
# Properties come from KK_ROOT/system/build.prop, never from getprop: in recovery getprop answers for the recovery's
# own default.prop, not for the system that is being changed.

KK_CTX=u:object_r:system_file:s0
# the java zip replaces these boot jars; their .odex files are removed (and backed up) instead of being dex-checked
KK_JAVA_JARS="core core-libart conscrypt okhttp"
# layer D files (the conscrypt zip); restore removes them together with the markers
KK_D_FILES="system/framework/kktls-conscrypt.jar system/framework/kktls-sslfilter.jar system/lib/libkktls_conscrypt_jni.so"
KK_MARKER_DIR=system/etc/kktls
# Build properties that only CyanogenMod-family and OEM firmwares set (prefix match on the key). Such firmwares ship
# their own libcore/framework/OpenSSL changes (cm-11 has two ssl.h), which an AOSP binary cannot be checked against.
KK_OEM_MARKERS="ro.cm. ro.modversion ro.cyanogen ro.miui. ro.build.version.emui ro.build.hw_emui ro.lewa. ro.aokp.
ro.pa. ro.pac. ro.slim. ro.omni. ro.mk. ro.mokee. ro.carbon. ro.rr. ro.dirtyunicorns. ro.liquid. ro.beanstalk.
ro.build.PDA ro.build.hidden_ver ro.build.sense. ro.htc. ro.lge. ro.semc. ro.sony. ro.yunos. ro.vivo.
ro.build.version.opporom ro.oppo. ro.mediatek. ro.flyme. ro.meizu. ro.coolpad. ro.zte. ro.lenovo. ro.asus."

kk_print() { # message lines go to the recovery screen when KK_OUTFD is set, else to stdout
  if [ -n "${KK_OUTFD:-}" ]; then
    echo "ui_print $*" >> "/proc/self/fd/$KK_OUTFD"; echo "ui_print" >> "/proc/self/fd/$KK_OUTFD"
  else
    echo "$*"
  fi
}

kk_conf() { # key -> value from zip.conf
  sed -n "s/^$1=//p" "$KK_DIR/kktls/zip.conf" | tail -n 1
}

kk_prop() { # key -> value from the device build.prop (last assignment wins, as in init)
  awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); v = $0 } END { print v }' "$KK_ROOT/system/build.prop" 2>/dev/null
}

kk_helper_abi() { # ABI directory of the static helpers for this device
  case $(kk_prop ro.product.cpu.abi) in
    x86*) echo x86 ;;
    arm*) echo armeabi-v7a ;;
    *) echo unknown ;;
  esac
}

kk_util() { # kktls-util from the zip for this device
  "$KK_DIR/kktls/bin/$(kk_helper_abi)/kktls-util" "$@"
}

KK_FAIL=0
kk_refuse() { kk_print "REFUSED: $*"; KK_FAIL=1; }

kk_check_version() { # $1 = zip.conf android (4.4 = any 4.4.x)
  local rel; rel=$(kk_prop ro.build.version.release)
  if [ "$1" = 4.4 ]; then
    case $rel in 4.4|4.4.[0-9]*) ;; *) kk_refuse "Android '$rel' is not 4.4.x" ;; esac
  elif [ "$rel" != "$1" ]; then
    kk_refuse "Android '$rel' is not $1 (this zip is built from AOSP $1)"
  fi
}

kk_check_aosp() { # AOSP-like gate: no CM/OEM marker property (ro.build.id is not checked: SDK images say KK)
  local m hit
  for m in $KK_OEM_MARKERS; do
    hit=$(awk -F= -v p="$m" 'index($1, p) == 1 { print $1; exit }' "$KK_ROOT/system/build.prop" 2>/dev/null)
    [ -z "$hit" ] || kk_refuse "not an AOSP-like build: build.prop sets $hit"
  done
}

kk_check_abi() { # $1 = zip.conf abi
  local abi; abi=$(kk_prop ro.product.cpu.abi)
  [ "$abi" = "$1" ] || kk_refuse "ro.product.cpu.abi '$abi' is not $1"
}

kk_check_helpers() {
  local a; a=$(kk_helper_abi)
  [ -x "$KK_DIR/kktls/bin/$a/kktls-util" ] || { kk_refuse "no helper for ABI '$a' in this zip"; return; }
  # exit 2 (usage) proves the binary runs on this CPU
  "$KK_DIR/kktls/bin/$a/kktls-util" > /dev/null 2>&1
  [ $? = 2 ] || kk_refuse "the zip's helper does not run on this device ($a)"
}

kk_check_dex() {
  # Replacing core.jar makes every other .odex stale; Dalvik then re-dexopts each jar/apk from its classes.dex into
  # /data/dalvik-cache. A firmware whose jar/apk next to an .odex has no classes.dex (odexed and stripped) would
  # bootloop. BOOTCLASSPATH is in the boot ramdisk (not readable from recovery): its jars are in /system/framework,
  # so the .odex scan of /system/framework covers them.
  local d o base f n=0
  for d in framework app priv-app; do
    for o in "$KK_ROOT/system/$d"/*.odex; do
      [ -f "$o" ] || continue
      base=${o%.odex}
      case " $KK_JAVA_JARS " in *" ${base##*/} "*) [ "$d" = framework ] && continue ;; esac
      f=
      [ -f "$base.jar" ] && f=$base.jar
      [ -f "$base.apk" ] && f=$base.apk
      if [ -z "$f" ]; then
        kk_refuse "/system/$d/${o##*/} has no jar/apk next to it"; continue
      fi
      n=$((n + 1))
      kk_util has-entry "$f" classes.dex
      case $? in
        0) ;;
        1) kk_refuse "/system/$d/${f##*/} is odexed without classes.dex (would bootloop after core.jar changes)" ;;
        *) kk_refuse "/system/$d/${f##*/} is not a readable zip" ;;
      esac
    done
  done
  kk_print "dex check: $n odexed jar/apk files carry classes.dex"
}

kk_check_symbols() { # our libssl/libcrypto must export everything the device's do
  local a l rc; a=$(kk_helper_abi)
  for l in libcrypto libssl; do
    if [ ! -f "$KK_ROOT/system/lib/$l.so" ]; then kk_refuse "/system/lib/$l.so is missing"; continue; fi
    if [ $l = libssl ]; then
      "$KK_DIR/kktls/bin/$a/kktls-symcheck" --allow-missing "$KK_DIR/kktls/allow-missing-libssl.txt" \
        "$KK_DIR/system/lib/$l.so" "$KK_ROOT/system/lib/$l.so"
    else
      "$KK_DIR/kktls/bin/$a/kktls-symcheck" "$KK_DIR/system/lib/$l.so" "$KK_ROOT/system/lib/$l.so"
    fi
    rc=$?
    case $rc in
      0) ;;
      1) kk_refuse "the device's $l.so exports symbols ours lacks (listed above)" ;;
      *) kk_refuse "kktls-symcheck cannot compare $l.so (exit $rc)" ;;
    esac
  done
}

kk_check_marker() { # name [required content]
  local m="$KK_ROOT/$KK_MARKER_DIR/$1.version"
  if [ ! -f "$m" ]; then kk_refuse "install the kktls $1 zip first ($KK_MARKER_DIR/$1.version missing)"; return; fi
  [ -z "${2:-}" ] || [ "$(cat "$m")" = "$2" ] || kk_refuse "$KK_MARKER_DIR/$1.version is '$(cat "$m")', this zip needs '$2'"
}

kk_check_writable() { # /system and /data must be mounted read-write
  [ -f "$KK_ROOT/system/build.prop" ] || { kk_refuse "/system is not mounted (no build.prop)"; return; }
  [ -w "$KK_ROOT/system" ] || kk_refuse "/system is not writable"
  [ -d "$KK_ROOT/data" ] && [ -w "$KK_ROOT/data" ] || kk_refuse "/data is not mounted read-write"
}

kk_precheck() { # all checks of zip.conf's kind; returns 1 (after listing every failure) or 0
  local kind rel abi android; KK_FAIL=0
  kind=$(kk_conf kind) rel=$(kk_conf release) abi=$(kk_conf abi) android=$(kk_conf android)
  kk_print "kktls $kind $rel ($abi, Android $android)"
  kk_check_writable
  [ $KK_FAIL = 0 ] || return 1
  kk_check_helpers
  case $kind in
    openssl) kk_check_version "$android"; kk_check_aosp; kk_check_abi "$abi"
             [ $KK_FAIL = 1 ] || kk_check_symbols ;;
    cacerts) kk_check_version "$android" ;;
    java) kk_check_version "$android"; kk_check_aosp; kk_check_abi "$abi"; kk_check_marker openssl
          [ $KK_FAIL = 1 ] || kk_check_dex ;;
    conscrypt) kk_check_version "$android"; kk_check_aosp; kk_check_abi "$abi"; kk_check_marker java "$rel" ;;
    restore) kk_restore_select ;;
    *) kk_refuse "unknown zip kind '$kind'" ;;
  esac
  case $kind in openssl|cacerts|java|conscrypt) # the plan (written to KK_DIR only) sizes the space check
    if [ $KK_FAIL = 0 ]; then
      kk_plan "$kind" || kk_refuse "cannot write the plan to $KK_DIR"
      [ $KK_FAIL = 1 ] || kk_check_space
    fi ;;
  esac
  [ $KK_FAIL = 0 ]
}
