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
# zip.conf (written by mkzips.sh; java-patched by tools/jarpatch/kktls-jarpatch.py):
#   kind=openssl|cacerts|java|java-patched|conscrypt|restore, release=<tag>, abi=armeabi-v7a|x86|any,
#   android= one exact ro.build.version.release (4.4.2, 4.4.4: the 4.4 java zips; 4.1.2: the 4.1 java and conscrypt
#   zips), 4.N (any 4.N.x: the openssl zips of 4.1 to 4.4, the 4.4 conscrypt zip, the 4.3 and 4.2 java and conscrypt
#   zips) or a range 4.1-4.4 (any 4.1.x to 4.4.x: cacerts and restore, which carry no code built against one release);
#   a conscrypt zip also needs the java marker of its own release;
#   java-patched (the device's own jars with the kktls classes, made for one system): jar.<name>=<sha256> of each
#   /system/framework/<name>.jar it was patched from and fingerprint=<sha256 of ro.build.fingerprint> instead of the
#   release and AOSP gates (android= is informational); it writes the java marker as the java zip does;
#   oem_ack=<sha256 of ro.build.fingerprint> (openssl and conscrypt only, the copies kktls-jarpatch.py --accept-oem
#   writes for one OEM/CM system): the AOSP gate is skipped on that system, any other system refuses
#
# Properties come from KK_ROOT/system/build.prop, never from getprop: in recovery getprop answers for the recovery's
# own default.prop, not for the system that is being changed.

KK_CTX=u:object_r:system_file:s0
# the java and java-patched zips replace these boot jars; their .odex files are removed (and backed up) instead of being
# dex-checked
KK_JAVA_JARS="core core-libart conscrypt okhttp"
# layer D files (the conscrypt zip; libkktls_compat.so only in the Jelly Bean zips whose base and ABI need it); restore
# removes them together with the markers
KK_D_FILES="system/framework/kktls-conscrypt.jar system/framework/kktls-sslfilter.jar system/lib/libkktls_conscrypt_jni.so
  system/lib/libkktls_compat.so"
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

kk_minor() { # ro.build.version.release -> its minor number when it is 4.N or 4.N.x, else nothing
  case $1 in 4.[0-9]|4.[0-9].*|4.[0-9][0-9]|4.[0-9][0-9].*) ;; *) return 0 ;; esac
  local m=${1#4.}; echo "${m%%.*}"
}

kk_check_version() { # $1 = zip.conf android (4.N = any 4.N.x, 4.A-4.B = any 4.A.x to 4.B.x)
  local rel lo hi m; rel=$(kk_prop ro.build.version.release)
  case $1 in
    4.[0-9]) case $rel in "$1"|"$1".[0-9]*) ;; *) kk_refuse "Android '$rel' is not $1.x" ;; esac ;;
    4.[0-9]-4.[0-9])
      lo=${1%-*} hi=${1#*-} lo=${lo#4.} hi=${hi#4.} m=$(kk_minor "$rel")
      [ -n "$m" ] && [ "$m" -ge "$lo" ] && [ "$m" -le "$hi" ] || kk_refuse "Android '$rel' is not 4.$lo.x to 4.$hi.x" ;;
    *) [ "$rel" = "$1" ] || kk_refuse "Android '$rel' is not $1 (this zip is built from AOSP $1)" ;;
  esac
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
  # so the .odex scan of /system/framework covers them. vendor/app: the package manager scans /vendor/app (on 4.4
  # /system/vendor/app) as system apps too; a missing directory, or a /system/vendor that is a symlink not resolving
  # in recovery, gives an empty glob.
  local d o base f n=0
  for d in framework app priv-app vendor/app; do
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
    # allow lists: libssl in every openssl zip; libcrypto only where that base needs one (the Jelly Bean zips)
    if [ -f "$KK_DIR/kktls/allow-missing-$l.txt" ]; then
      "$KK_DIR/kktls/bin/$a/kktls-symcheck" --allow-missing "$KK_DIR/kktls/allow-missing-$l.txt" \
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

kk_prop_first() { # key -> value of its first definition in build.prop, blanks trimmed: what init gives a ro.* property
  # (set once) and what kktls-jarpatch.py hashed; kk_prop (last definition) stays for the other gates
  awk -v k="$1" '{ sub(/\r$/, ""); i = index($0, "="); if (i == 0) next
      key = substr($0, 1, i - 1); gsub(/^[ \t]+|[ \t]+$/, "", key); if (key != k) next
      v = substr($0, i + 1); gsub(/^[ \t]+|[ \t]+$/, "", v); print v; exit }' "$KK_ROOT/system/build.prop" 2>/dev/null
}

kk_fp_sha() { # sha256 of ro.build.fingerprint (first definition, trimmed) as kktls-jarpatch.py writes it; empty on failure
  local fp=$KK_DIR/kktls/fingerprint.tmp h
  printf '%s' "$(kk_prop_first ro.build.fingerprint)" > "$fp" && h=$(kk_util sha256 "$fp") || h=
  rm -f "$fp"
  echo "$h"
}

kk_check_oem() { # openssl, conscrypt: the AOSP gate, unless zip.conf oem_ack= names this system's fingerprint
  local ack h
  if ! grep -q '^oem_ack=' "$KK_DIR/kktls/zip.conf"; then kk_check_aosp; return; fi
  ack=$(kk_conf oem_ack) h=$(kk_fp_sha)
  if [ -n "$h" ] && [ "$h" = "$ack" ]; then
    kk_print "OEM/CM gate skipped: this copy was made for this system (oem_ack)"
  else
    kk_refuse "oem_ack: this zip was made for another system (ro.build.fingerprint sha256 $h): run kktls-jarpatch.py --accept-oem on this system"
  fi
}

kk_check_patched() { # java-patched: this /system must be the one the zip was made from (zip.conf jar.<name>=, fingerprint=)
  local f j want h n=0
  for f in "$KK_DIR"/system/framework/*.jar; do  # every jar of the payload must have been checked
    [ -f "$f" ] || continue
    j=${f##*/}; j=${j%.jar}
    grep -q "^jar\.$j=" "$KK_DIR/kktls/zip.conf" || kk_refuse "zip.conf has no jar.$j= line for the payload's $j.jar"
  done
  while IFS='=' read -r j want; do
    [ -n "$j" ] || continue
    j=${j#jar.}
    case $j in ''|*[!a-z0-9-]*) kk_refuse "zip.conf: bad jar name '$j'"; continue ;; esac
    n=$((n + 1))
    if [ ! -f "$KK_ROOT/system/framework/$j.jar" ]; then
      kk_refuse "/system/framework/$j.jar is missing: this zip was made for another system"; continue
    fi
    h=$(kk_util sha256 "$KK_ROOT/system/framework/$j.jar")
    [ -n "$h" ] && [ "$h" = "$want" ] ||
      kk_refuse "/system/framework/$j.jar is not the jar this zip was made from (sha256 $h): run kktls-jarpatch.py on this system (after the kktls restore zip if kktls is installed)"
  done <<EOF
$(grep '^jar\.' "$KK_DIR/kktls/zip.conf")
EOF
  [ $n -gt 0 ] || kk_refuse "zip.conf names no jar (jar.<name>=)"
  h=$(kk_fp_sha)
  [ -n "$h" ] && [ "$h" = "$(kk_conf fingerprint)" ] ||
    kk_refuse "ro.build.fingerprint is not the one this zip was made for (sha256 $h)"
}

kk_check_marker() { # name [required content]
  local m="$KK_ROOT/$KK_MARKER_DIR/$1.version"
  if [ ! -f "$m" ]; then kk_refuse "install the kktls $1 zip first ($KK_MARKER_DIR/$1.version missing)"; return; fi
  [ -z "${2:-}" ] || [ "$(cat "$m")" = "$2" ] || kk_refuse "$KK_MARKER_DIR/$1.version is '$(cat "$m")', this zip needs '$2'"
}

kk_ro_mount() { # dir -> 0 when /proc/mounts shows the mount that holds dir (the longest mount point that is dir or
  # one of its parents; the last entry of an overmounted point) with the option ro; 1 otherwise or when unknown
  local p; p=$(cd "$1" 2> /dev/null && pwd -P) || return 1
  [ -r /proc/mounts ] || return 1
  awk -v p="$p" '{ m = $2; gsub(/\\040/, " ", m)
      if ((p == m || m == "/" || index(p, m "/") == 1) && length(m) >= best) { best = length(m); o = $4 } }
    END { exit (("," o ",") ~ /,ro,/) ? 0 : 1 }' /proc/mounts
}

kk_check_writable() { # /system and /data must be mounted read-write
  # `test -w` alone is not enough: busybox answers yes for root on a read-only mount (it does not call access())
  [ -f "$KK_ROOT/system/build.prop" ] || { kk_refuse "/system is not mounted (no build.prop)"; return; }
  if [ ! -w "$KK_ROOT/system" ] || kk_ro_mount "$KK_ROOT/system"; then kk_refuse "/system is not writable"; fi
  if [ ! -d "$KK_ROOT/data" ] || [ ! -w "$KK_ROOT/data" ] || kk_ro_mount "$KK_ROOT/data"; then
    kk_refuse "/data is not mounted read-write"
  fi
}

kk_precheck() { # all checks of zip.conf's kind; returns 1 (after listing every failure) or 0
  local kind rel abi android; KK_FAIL=0
  kind=$(kk_conf kind) rel=$(kk_conf release) abi=$(kk_conf abi) android=$(kk_conf android)
  kk_print "kktls $kind $rel ($abi, Android $android)"
  kk_check_writable
  [ $KK_FAIL = 0 ] || return 1
  kk_check_helpers
  case $kind in
    openssl) kk_check_version "$android"; kk_check_oem; kk_check_abi "$abi"
             [ $KK_FAIL = 1 ] || kk_check_symbols ;;
    cacerts) kk_check_version "$android" ;;
    java) kk_check_version "$android"; kk_check_aosp; kk_check_abi "$abi"; kk_check_marker openssl
          [ $KK_FAIL = 1 ] || kk_check_dex ;;
    java-patched) # no release or AOSP gate: the jar patcher checked the classes, these digests pin the system
          kk_check_abi "$abi"; kk_check_marker openssl; kk_check_patched
          [ $KK_FAIL = 1 ] || kk_check_dex ;;
    conscrypt) kk_check_version "$android"; kk_check_oem; kk_check_abi "$abi"; kk_check_marker java "$rel" ;;
    restore) kk_restore_select ;;
    *) kk_refuse "unknown zip kind '$kind'" ;;
  esac
  case $kind in openssl|cacerts|java|java-patched|conscrypt) # the plan (written to KK_DIR only) sizes the space check
    if [ $KK_FAIL = 0 ]; then
      kk_plan "$kind" || kk_refuse "cannot write the plan to $KK_DIR"
      [ $KK_FAIL = 1 ] || kk_check_space
    fi ;;
  esac
  [ $KK_FAIL = 0 ]
}
