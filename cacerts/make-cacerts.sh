#!/usr/bin/env bash
# make-cacerts.sh — build an Android 4.x /system/etc/security/cacerts directory
# from the Mozilla CA bundle as published by curl (https://curl.se/ca/cacert.pem).
#
# Usage: make-cacerts.sh <cacert.pem> <cacert.pem.sha256> <outdir> [now-epoch]
#   outdir      is wiped and recreated (contains only <hash>.<n> files)
#   now-epoch   reference time for the expiry check (default: now); pass the
#               bundle date to reproduce a given output byte-for-byte.
# Also writes MANIFEST.tsv next to outdir (i.e. into its parent).
#
# File format (AOSP system/ca-certificates/files): PEM block, then the
# `openssl x509 -text` dump, then the "SHA1 Fingerprint=" line. Android only
# parses the leading PEM block; the rest is a comment. To keep the directory
# small the text dump omits the public key and signature hex
# (-certopt no_pubkey,no_sigdump).
# File name: `openssl x509 -subject_hash_old` (legacy MD5-based hash, what
# libcore TrustedCertificateStore 4.x uses) + ".0", ".1"… on collision;
# collisions are ordered by SHA-256 fingerprint so the result is deterministic.
# Filters: expired certs (notAfter < now) and certs without
# basicConstraints CA:TRUE are dropped (reported on stderr).
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
export LC_ALL=C
[ $# -ge 3 ] || { echo "usage: $0 cacert.pem cacert.pem.sha256 outdir [now-epoch]" >&2; exit 2; }
PEM=$1; SUM=$2; OUT=$3; NOW=${4:-$(date +%s)}
OPENSSL=${OPENSSL:-openssl}
NOWISO=$(date -u -r "$NOW" '+%Y-%m-%d %H:%M:%SZ' 2>/dev/null || date -u -d "@$NOW" '+%Y-%m-%d %H:%M:%SZ')

want=$(awk '{print $1}' "$SUM")
have=$(shasum -a 256 "$PEM" | awk '{print $1}')
[ "$want" = "$have" ] || { echo "sha256 mismatch: $have != $want" >&2; exit 1; }
echo "bundle: $(grep -m1 'Certificate data from Mozilla as of' "$PEM" | sed 's/^## *//')" >&2
echo "sha256: $have" >&2

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
awk -v d="$TMP" '/-----BEGIN CERTIFICATE-----/{n++; f=sprintf("%s/in-%04d.pem",d,n)} f{print > f} /-----END CERTIFICATE-----/{close(f); f=""}' "$PEM"

rm -rf "$OUT"; mkdir -p "$OUT"
: > "$TMP/list"
kept=0; expired=0; nonca=0
for c in "$TMP"/in-*.pem; do
  name=$("$OPENSSL" x509 -in "$c" -noout -subject -nameopt RFC2253,-esc_msb | sed 's/^subject=//')
  if ! "$OPENSSL" x509 -in "$c" -noout -ext basicConstraints 2>/dev/null | grep -q 'CA:TRUE'; then
    echo "drop (not CA): $name" >&2; nonca=$((nonca+1)); continue
  fi
  na=$("$OPENSSL" x509 -in "$c" -noout -enddate -dateopt iso_8601 | sed 's/^notAfter=//')
  if [[ ! "$na" > "$NOWISO" ]]; then
    echo "drop (expired $na): $name" >&2; expired=$((expired+1)); continue
  fi
  h=$("$OPENSSL" x509 -in "$c" -noout -subject_hash_old)
  s256=$("$OPENSSL" x509 -in "$c" -outform DER | shasum -a 256 | awk '{print $1}')
  printf '%s\t%s\t%s\n' "$h" "$s256" "$c" >> "$TMP/list"
  kept=$((kept+1))
done

MAN="$(dirname "$OUT")/MANIFEST.tsv"
printf 'file\tsubject\tnotBefore\tnotAfter\tsha256\n' > "$MAN"
sort -k1,1 -k2,2 "$TMP/list" | while IFS=$'\t' read -r h s256 c; do
  n=0; while [ -e "$OUT/$h.$n" ]; do n=$((n+1)); done
  f="$OUT/$h.$n"
  {
    "$OPENSSL" x509 -in "$c" -outform PEM
    "$OPENSSL" x509 -in "$c" -noout -text -certopt no_pubkey,no_sigdump
    "$OPENSSL" x509 -in "$c" -noout -fingerprint     # default SHA1, "SHA1 Fingerprint=..."
  } > "$f"
  chmod 0644 "$f"
  nb=$("$OPENSSL" x509 -in "$c" -noout -startdate -dateopt iso_8601 | sed 's/^notBefore=//')
  na=$("$OPENSSL" x509 -in "$c" -noout -enddate -dateopt iso_8601 | sed 's/^notAfter=//')
  subj=$("$OPENSSL" x509 -in "$c" -noout -subject -nameopt RFC2253,-esc_msb | sed 's/^subject=//')
  printf '%s\t%s\t%s\t%s\t%s\n' "$h.$n" "$subj" "$nb" "$na" "$s256" >> "$MAN"
done
echo "in: $(ls "$TMP"/in-*.pem | wc -l | tr -d ' ')  kept: $kept  expired: $expired  not-CA: $nonca  -> $OUT" >&2
