# shellcheck shell=dash
# kktls installer: backup, install, restore (sourced after checks.sh; POSIX sh: recovery busybox ash, device mksh).
# SPDX-License-Identifier: Apache-2.0
#
#   kk_main        pre-checks of zip.conf's kind, then install (or restore); returns non-zero on refusal or failure
#
# Backups: KK_ROOT/data/kktls-backup/<NNNN>-<time>/ and a copy in the second location (KK_ROOT/sdcard/kktls-backup/
# when /sdcard is real storage, else KK_ROOT/data/media/0/kktls-backup/), because a factory reset wipes /data but
# leaves /system modified. NNNN is a sequence number over both locations (the recovery clock may say 1970), so name
# order is install order. Each backup holds files/<path> and a manifest written last:
#   kind <kind> / release <release> / seq <n>     header lines
#   fingerprint <ro.build.fingerprint>              the system the backup was taken from
#   hash sha256                                     the digest of the F lines (rc1-rc3 backups may say md5 or cksum)
#   F <digest> <path>   the file existed: saved as files/<path>, restored by copy
#   A <path>    the file did not exist: restore deletes it
#   D <path>    the directory did not exist: restore removes it when empty
# (paths are relative to the root, e.g. system/lib/libssl.so). Every file kktls touches (libraries, jars, .odex, CA
# files, markers) is a regular root:root 0644 system_file on AOSP 4.4, so the backup keeps content only and both install
# and restore set owner, mode and label explicitly (the second copy may sit on a FAT card without owners or modes).
# The digests come from the zip's helper (kktls-util sha256), never from the recovery's busybox, which may lack
# sha256sum and md5sum; only backups of rc1-rc3 that recorded md5 or cksum still need that system tool to be restored.
# The second copy is written to .tmp-<name>, checked against the digests and its manifest against the original's, and
# renamed at the end.
# Restore collects the active backups of every location, takes each from a copy whose files match the digests, refuses
# (writing nothing) when one has no intact copy or comes from another ROM (fingerprint), applies them newest -> oldest,
# so the oldest backup (the state before the first kktls zip) wins, then renames them to done-<name>. An install retires
# the active backups of another ROM (an update or reflash replaced /system) as stale-<name>.

KK_BACKUP_NAME=kktls-backup
KK_SECOND_SKIP=
KK_LABEL=  # set by kk_selinux

kk_backup_bases() { # every backup location that exists, primary first
  local b
  for b in "$KK_ROOT/data/$KK_BACKUP_NAME" "$KK_ROOT/sdcard/$KK_BACKUP_NAME" "$KK_ROOT/data/media/0/$KK_BACKUP_NAME"; do
    [ -d "$b" ] && echo "$b"
  done
}

kk_backup_names() { # names of the active backups (with a manifest) over all locations, newest first
  local b d
  for b in $(kk_backup_bases); do
    for d in "$b"/[0-9][0-9][0-9][0-9]-*; do
      [ -f "$d/manifest" ] && echo "${d##*/}"
    done
  done | sort -u -r
}

kk_second_base() { # the location of the second backup copy, or nothing
  if [ -z "$KK_ROOT" ]; then
    # in recovery /sdcard can be an unmounted ramdisk directory: only a mount point or a symlink is real storage
    if [ -L /sdcard ] || grep -q ' /sdcard ' /proc/mounts 2>/dev/null; then echo "/sdcard/$KK_BACKUP_NAME"; return; fi
  elif [ -d "$KK_ROOT/sdcard" ]; then
    echo "$KK_ROOT/sdcard/$KK_BACKUP_NAME"; return
  fi
  [ -d "$KK_ROOT/data/media/0" ] && echo "$KK_ROOT/data/media/0/$KK_BACKUP_NAME"
}

kk_next_seq() {
  local b d n max=0
  for b in $(kk_backup_bases); do
    for d in "$b"/*; do
      d=${d##*/}; d=${d#done-}; d=${d#failed-}; d=${d#stale-}; n=${d%%-*}
      case $n in [0-9][0-9][0-9][0-9]) n=$(echo "$n" | sed 's/^0*//'); [ "${n:-0}" -gt $max ] && max=${n:-0} ;; esac
    done
  done
  printf '%04d' $((max + 1))
}

kk_hash_missing() { # manifest hash tool -> nothing when it can be computed here, the system tool it needs, ? unknown
  case $1 in
    sha256) ;;  # the zip's helper
    md5) md5sum < /dev/null > /dev/null 2>&1 || echo md5sum ;;
    cksum) cksum < /dev/null > /dev/null 2>&1 || echo cksum ;;
    *) echo "?" ;;
  esac
}

kk_hash() { # tool file -> digest (one word)
  case $1 in
    sha256) kk_util sha256 "$2" ;;
    md5) md5sum < "$2" | awk '{ print $1 }' ;;  # backups of rc1-rc3 only
    cksum) cksum < "$2" | awk '{ print $1 "-" $2 }' ;;
    *) return 1 ;;
  esac
}

kk_backup_verify() { # backup dir: the manifest is there and every F file matches its digest
  local dir=$1 tool t h p
  [ -f "$dir/manifest" ] || return 1
  tool=$(sed -n 's/^hash //p' "$dir/manifest")
  while read -r t h p; do
    [ "$t" = F ] || continue
    [ -f "$dir/files/$p" ] && [ "$(kk_hash "$tool" "$dir/files/$p")" = "$h" ] || return 1
  done < "$dir/manifest"
}

kk_selinux() { # sets KK_LABEL once: 1 label (a failure fails the install), 2 label if the kernel lets us, 0 no SELinux
  # Android 4.3 and later: 1 (AOSP ships SELinux from 4.3 on; as on 4.4).
  # 4.1/4.2: 0 when the kernel has no SELinux (no selinuxfs in /proc/filesystems, no /sys/fs/selinux): the AOSP case,
  # nothing to label. With SELinux in the kernel, 2: an AOSP 4.1/4.2 userspace loads no policy, so the kernel refuses
  # the label write (EOPNOTSUPP) and nothing checks labels; a firmware that does load one gets its files labelled.
  [ -z "${KK_LABEL:-}" ] || return 0
  KK_LABEL=1
  case $(kk_prop ro.build.version.release) in
    4.[0-2]|4.[0-2].*)
      if grep -qw selinuxfs "$KK_ROOT/proc/filesystems" 2> /dev/null || [ -d "$KK_ROOT/sys/fs/selinux" ]; then
        KK_LABEL=2
      else
        KK_LABEL=0
        kk_print "no SELinux in this kernel (Android $(kk_prop ro.build.version.release)): files are not labelled"
      fi ;;
  esac
}

kk_setcon() { # label paths system_file: chcon when it works, else the zip's helper (see kk_selinux)
  kk_selinux
  [ "$KK_LABEL" != 0 ] || return 0
  if command -v chcon > /dev/null 2>&1 && chcon "$KK_CTX" "$@" 2> /dev/null; then return 0; fi
  [ "$KK_LABEL" = 2 ] || { kk_util setcon "$KK_CTX" "$@"; return; }
  kk_util setcon "$KK_CTX" "$@" 2> /dev/null && return 0
  # once per run (kk_setcon may run in a subshell, so the note is a file)
  [ -e "$KK_DIR/kktls/label-skipped" ] || { : > "$KK_DIR/kktls/label-skipped"
    kk_print "SELinux is in the kernel but takes no labels (no policy loaded, Android $(kk_prop ro.build.version.release)): files are not labelled"; }
  return 0
}

kk_place() { # src dst: copy one payload file into /system as root:root 0644 system_file
  cp "$1" "$2.kktls-new" && chown 0:0 "$2.kktls-new" && chmod 0644 "$2.kktls-new" && kk_setcon "$2.kktls-new" &&
    mv -f "$2.kktls-new" "$2" || { rm -f "$2.kktls-new"; return 1; }
}

kk_mkdir() { # path relative to the root: create it (and its parents) root:root 0755 system_file
  local p=$1 up
  [ -d "$KK_ROOT/$p" ] && return 0
  up=${p%/*}; [ "$up" = "$p" ] || kk_mkdir "$up" || return 1
  mkdir "$KK_ROOT/$p" && chown 0:0 "$KK_ROOT/$p" && chmod 0755 "$KK_ROOT/$p" && kk_setcon "$KK_ROOT/$p"
}

kk_cleanup() { # leftovers of an interrupted run: *.kktls-new in /system, unfinished second copies
  local f b
  find "$KK_ROOT/system" -name '*.kktls-new' -type f 2> /dev/null | while read -r f; do rm -f "$f"; done
  for b in $(kk_backup_bases); do
    for f in "$b"/.tmp-*; do [ -e "$f" ] && rm -rf "$f"; done
  done
}

kk_plan() { # the paths this zip touches -> KK_DIR/kktls/plan: "R path" (removed) first, then "P path" (payload), "M"
  local kind=$1 p f j plan=$KK_DIR/kktls/plan
  : > "$plan" || return 1
  case $kind in
    cacerts) # the CA directory is replaced wholesale: old roots must not survive next to the new set
      for f in "$KK_ROOT"/system/etc/security/cacerts/*; do
        [ -f "$f" ] || continue
        p=system/etc/security/cacerts/${f##*/}
        [ -f "$KK_DIR/$p" ] || echo "R $p" >> "$plan"
      done ;;
    java|java-patched) # stale .odex of the replaced jars would be used instead of the new classes.dex
      for j in $KK_JAVA_JARS; do
        [ -f "$KK_ROOT/system/framework/$j.odex" ] && echo "R system/framework/$j.odex" >> "$plan"
      done ;;
  esac
  # removals first: they free space before the payload is written (the backup is taken before either)
  (cd "$KK_DIR" && find system -type f | sort) | sed 's/^/P /' >> "$plan"
  echo "M $KK_MARKER_DIR/$(kk_marker "$kind").version" >> "$plan"
}

kk_marker() { # kind -> its marker name (java-patched installs layer A as the java zip does: the conscrypt zip needs java)
  case $1 in java-patched) echo java ;; *) echo "$1" ;; esac
}

kk_kb() { # file -> its size in KiB, rounded up to 4 KiB blocks (0 when missing)
  local s
  [ -f "$1" ] || { echo 0; return; }
  s=$(wc -c < "$1")
  echo $(( (s + 4095) / 4096 * 4 ))
}

kk_df() { # path -> "mountpoint free-KiB" of its filesystem, or nothing
  df -Pk "$1" 2> /dev/null | awk 'NR > 1 { a = $4; m = $6 } END { if (m != "" && a ~ /^[0-9]+$/) print m, a }'
}

kk_check_space() { # needs KK_DIR/kktls/plan; refuses when /system or /data lacks room, may skip the second copy
  local t p sys=16 bak=8 freed=0 s d c m a need second
  while read -r t p; do
    case $t in
      P) sys=$((sys + $(kk_kb "$KK_DIR/$p"))); bak=$((bak + $(kk_kb "$KK_ROOT/$p"))) ;;
      R) freed=$((freed + $(kk_kb "$KK_ROOT/$p"))); bak=$((bak + $(kk_kb "$KK_ROOT/$p"))) ;;
      M) sys=$((sys + 4)); bak=$((bak + $(kk_kb "$KK_ROOT/$p"))) ;;
    esac
  done < "$KK_DIR/kktls/plan"
  # R removals are credited; files replaced by P are not (over adb a running daemon can hold the old inode until reboot)
  sys=$((sys - freed)); [ $sys -gt 0 ] || sys=4
  s=$(kk_df "$KK_ROOT/system"); d=$(kk_df "$KK_ROOT/data")
  if [ -z "$s" ] || [ -z "$d" ]; then kk_print "WARNING: df gives no free space for /system or /data; not checked"; return 0; fi
  if [ "${s% *}" = "${d% *}" ]; then
    need=$((sys + bak))
    [ "${s#* }" -ge $need ] || kk_refuse "not enough space: /system and /data need $need KiB, ${s#* } KiB free"
  else
    [ "${s#* }" -ge $sys ] || kk_refuse "not enough space on /system: $sys KiB needed, ${s#* } KiB free"
    [ "${d#* }" -ge $bak ] || kk_refuse "not enough space on /data for the backup: $bak KiB needed, ${d#* } KiB free"
  fi
  [ $KK_FAIL = 0 ] || return 1
  second=$(kk_second_base); [ -n "$second" ] || return 0
  [ -d "$second" ] || second=${second%/*}
  c=$(kk_df "$second"); [ -n "$c" ] || return 0
  m=${c% *} a=${c#* } need=$bak
  [ "$m" = "${s% *}" ] && need=$((need + sys))
  [ "$m" = "${d% *}" ] && need=$((need + bak))
  if [ "$a" -lt "$need" ]; then
    KK_SECOND_SKIP=1
    kk_print "WARNING: not enough space for the second backup copy in ${m#"$KK_ROOT"} ($need KiB needed, $a KiB free)"
  fi
}

kk_backup() { # kind release -> the backup of everything in the plan; its dir goes to KK_DIR/kktls/backup-dir
  local seq name dir
  seq=$(kk_next_seq); name=$seq-$(date +%Y%m%d-%H%M%S)
  dir=$KK_ROOT/data/$KK_BACKUP_NAME/$name
  kk_backup_write "$1" "$2" "$seq" "$dir" || { rm -rf "$dir"; return 1; }
  kk_backup_copy "$dir"
  echo "$dir" > "$KK_DIR/kktls/backup-dir"
}

kk_backup_write() { # kind release seq dir
  local kind=$1 rel=$2 seq=$3 dir=$4 t p d dirs h
  mkdir -p "$dir/files" || return 1
  { echo "kind $kind"; echo "release $rel"; echo "seq $seq"; echo "fingerprint $(kk_prop ro.build.fingerprint)"
    echo "hash sha256"; } > "$dir/manifest.tmp" || return 1
  while read -r t p; do
    if [ -f "$KK_ROOT/$p" ]; then
      mkdir -p "$dir/files/${p%/*}" && cp "$KK_ROOT/$p" "$dir/files/$p" || return 1
      h=$(kk_hash sha256 "$dir/files/$p") && [ -n "$h" ] || return 1
      echo "F $h $p" >> "$dir/manifest.tmp" || return 1
    else
      echo "A $p" >> "$dir/manifest.tmp" || return 1
    fi
  done < "$KK_DIR/kktls/plan"
  # directories the install will create (deepest last here, restore removes them in reverse order)
  dirs=
  while read -r t p; do
    d=${p%/*}
    while [ "$d" != "$p" ] && [ -n "$d" ] && [ ! -d "$KK_ROOT/$d" ]; do
      case " $dirs " in *" $d "*) ;; *) dirs="$d $dirs" ;; esac
      p=$d; d=${d%/*}
    done
  done < "$KK_DIR/kktls/plan"
  for d in $dirs; do echo "D $d" >> "$dir/manifest.tmp" || return 1; done
  sync
  mv "$dir/manifest.tmp" "$dir/manifest" && kk_backup_verify "$dir"
}

kk_backup_copy() { # dir: the second copy, written to .tmp-<name> and renamed once it checks out (else a warning)
  # checked: its files against the digests and its manifest against the original (a short copy of the manifest would
  # pass the digest check with fewer F lines)
  local dir=$1 name=${1##*/} second
  second=$(kk_second_base)
  if [ -z "$second" ]; then
    kk_print "WARNING: no /sdcard for a second backup copy; a factory reset would lose ${dir#"$KK_ROOT"}"
  elif [ -n "$KK_SECOND_SKIP" ]; then
    kk_print "WARNING: no second backup copy; a factory reset would lose ${dir#"$KK_ROOT"}"
  elif mkdir -p "$second" && cp -r "$dir" "$second/.tmp-$name" 2> /dev/null && kk_backup_verify "$second/.tmp-$name" &&
      cmp -s "$dir/manifest" "$second/.tmp-$name/manifest" && sync && mv "$second/.tmp-$name" "$second/$name"; then
    kk_print "backup: ${dir#"$KK_ROOT"} and ${second#"$KK_ROOT"}/$name"
  else
    rm -rf "${second:?}/.tmp-$name" "${second:?}/$name"
    kk_print "WARNING: no second backup copy in ${second#"$KK_ROOT"}; a factory reset would lose the backup"
  fi
}

kk_backup_intact() { # name -> the first location's copy of that backup whose files match the digests, or nothing
  local b
  for b in $(kk_backup_bases); do
    kk_backup_verify "$b/$1" && { echo "$b/$1"; return 0; }
  done
  return 1
}

kk_retire_stale() { # active backups taken on another ROM can never be restored: rename them to stale-<name>
  local fp b d bfp
  fp=$(kk_prop ro.build.fingerprint)
  for b in $(kk_backup_bases); do
    for d in "$b"/[0-9][0-9][0-9][0-9]-*; do
      [ -f "$d/manifest" ] || continue
      bfp=$(sed -n 's/^fingerprint //p' "$d/manifest")
      [ "$bfp" = "$fp" ] && continue
      mv "$d" "$b/stale-${d##*/}" &&
        kk_print "backup ${d#"$KK_ROOT"} is from another ROM ('$bfp'): retired as stale-${d##*/}"
    done
  done
}

kk_restore_select() { # pre-check of the restore zip: KK_DIR/kktls/restore-list = the backup copies to apply
  local fp name b dir bfp tool miss n=0 list=$KK_DIR/kktls/restore-list
  fp=$(kk_prop ro.build.fingerprint)
  : > "$list"
  for name in $(kk_backup_names); do
    for b in $(kk_backup_bases); do
      [ -f "$b/$name/manifest" ] || continue
      bfp=$(sed -n 's/^fingerprint //p' "$b/$name/manifest")
      [ "$bfp" = "$fp" ] ||
        kk_refuse "backup $name was taken on '$bfp', this system is '$fp': the ROM was replaced, nothing to restore"
      tool=$(sed -n 's/^hash //p' "$b/$name/manifest")
      break
    done
    [ "$bfp" = "$fp" ] || continue
    miss=$(kk_hash_missing "$tool")
    if [ "$miss" = "?" ]; then
      kk_refuse "backup $name: its manifest names no known digest ('hash $tool')"; continue
    elif [ -n "$miss" ]; then
      kk_refuse "backup $name has $tool digests and this shell has no $miss to check them: restore from a recovery or a device shell (install-adb.sh --restore) that has $miss"
      continue
    fi
    if dir=$(kk_backup_intact "$name"); then
      echo "$dir" >> "$list"; n=$((n + 1))
    else
      kk_refuse "backup $name: no copy whose files match its manifest (damaged or incomplete)"
    fi
  done
  [ $n -gt 0 ] || [ $KK_FAIL = 1 ] || kk_refuse "no kktls backup in /data, /sdcard or /data/media/0"
}

kk_apply_manifest() { # backup dir: put the files of one backup back (F), delete the added ones (A), then empty dirs (D)
  local t h p rc=0
  while read -r t h p; do
    case $t in
      F) cmp -s "$1/files/$p" "$KK_ROOT/$p" 2> /dev/null && continue  # untouched (or already back)
         mkdir -p "$KK_ROOT/${p%/*}" && kk_place "$1/files/$p" "$KK_ROOT/$p" ||
           { kk_print "ERROR: cannot restore /$p"; rc=1; } ;;
      A) rm -f "$KK_ROOT/$h" || rc=1 ;;  # A and D lines carry the path in the second field
    esac
  done < "$1/manifest"
  # D lines were written shallowest first
  for p in $(sed -n 's/^D //p' "$1/manifest" | sort -r); do rmdir "$KK_ROOT/$p" 2> /dev/null; done
  return $rc
}

kk_wipe_dalvik() {
  rm -rf "$KK_ROOT"/data/dalvik-cache/* 2> /dev/null
  kk_print "dalvik-cache wiped: the first boot re-optimises every app and takes long (ART: boot.art too)"
}

kk_apply_plan() { # release: carry out KK_DIR/kktls/plan
  local t p
  while read -r t p; do
    case $t in
      R) rm -f "$KK_ROOT/$p" || return 1 ;;
      P) kk_mkdir "${p%/*}" && kk_place "$KK_DIR/$p" "$KK_ROOT/$p" || return 1 ;;
      M) kk_mkdir "${p%/*}" && echo "$1" > "$KK_DIR/kktls/marker" &&
           kk_place "$KK_DIR/kktls/marker" "$KK_ROOT/$p" || return 1 ;;
    esac
  done < "$KK_DIR/kktls/plan"
}

kk_install() { # after kk_precheck (which wrote KK_DIR/kktls/plan)
  local kind rel dir b rb
  kind=$(kk_conf kind) rel=$(kk_conf release)
  kk_cleanup
  kk_retire_stale
  if ! kk_backup "$kind" "$rel"; then
    kk_print "ERROR: backup failed; nothing installed"; return 1
  fi
  dir=$(cat "$KK_DIR/kktls/backup-dir")
  if ! kk_apply_plan "$rel"; then
    rb=$(kk_backup_intact "${dir##*/}") || rb=
    kk_print "ERROR: install failed; rolling back from ${rb#"$KK_ROOT"}"
    if [ -n "$rb" ] && kk_apply_manifest "$rb"; then
      # the system is as before: this backup must not take part in a later restore
      for b in $(kk_backup_bases); do
        [ -d "$b/${dir##*/}" ] && mv "$b/${dir##*/}" "$b/failed-${dir##*/}"
      done
    else
      kk_print "ERROR: rollback incomplete; the backup stays active: flash the kktls restore zip"
    fi
    return 1
  fi
  case $kind in java|java-patched) kk_wipe_dalvik ;; esac
  sync
  kk_print "installed: $(grep -c '^P ' "$KK_DIR/kktls/plan") files; marker /$KK_MARKER_DIR/$(kk_marker "$kind").version = $rel"
}

kk_restore() { # after kk_precheck (which wrote KK_DIR/kktls/restore-list, every copy in it verified)
  local b n=0 rc=0 f name
  kk_cleanup
  while read -r b; do
    kk_print "restore: ${b#"$KK_ROOT"} ($(sed -n 's/^kind //p' "$b/manifest"))"
    kk_apply_manifest "$b" || rc=1
    n=$((n + 1))
  done < "$KK_DIR/kktls/restore-list"
  # our files never belong to a stock system: drop what is left of them (e.g. when older backups were lost)
  for f in $KK_D_FILES; do rm -f "$KK_ROOT/$f"; done
  rm -f "$KK_ROOT/$KK_MARKER_DIR"/*.version
  rmdir "$KK_ROOT/$KK_MARKER_DIR" 2> /dev/null
  [ $rc = 0 ] || { kk_print "ERROR: restore incomplete; backups kept"; return 1; }
  while read -r b; do
    name=${b##*/}
    for f in $(kk_backup_bases); do
      [ -d "$f/$name" ] && mv "$f/$name" "$f/done-$name"
    done
  done < "$KK_DIR/kktls/restore-list"
  kk_wipe_dalvik
  sync
  kk_print "restored from $n backup(s)"
}

kk_main() {
  kk_precheck || { kk_print "nothing was changed"; return 1; }
  kk_selinux  # decided once, in this shell (kk_setcon may run in subshells)
  case $(kk_conf kind) in
    restore) kk_restore ;;
    *) kk_install ;;
  esac
}
