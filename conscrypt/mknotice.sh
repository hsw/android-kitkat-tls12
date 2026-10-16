#!/bin/bash
# mknotice.sh: write the NOTICE of the layer D modules for a Conscrypt tag and the BoringSSL commit its .so links.
#
#   conscrypt/mknotice.sh CONSCRYPT_GIT TAG BORINGSSL_DIR > NOTICE
#
# CONSCRYPT_GIT = a clone of google/conscrypt (https://github.com/google/conscrypt); its NOTICE and LICENSE are read
# with `git show TAG:…`. BORINGSSL_DIR = a checkout of the commit named in the aar's conscrypt.properties
# (git fetch --depth 1 https://boringssl.googlesource.com/boringssl <sha>); its LICENSE and third_party/fiat/LICENSE
# (fiat-crypto is compiled into libcrypto) are read as files. Output is deterministic; check_prebuilt.py --stage
# compares it with the sha256 pinned in SHA256SUMS (NOTICE) and requires the tag and commit in the text.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[ $# = 3 ] || { echo "usage: mknotice.sh CONSCRYPT_GIT TAG BORINGSSL_DIR" >&2; exit 2; }
git_dir=$1 tag=$2 bssl=$3
sha=$(git -C "$bssl" rev-parse HEAD)
git -C "$git_dir" rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "mknotice: no tag $tag in $git_dir" >&2; exit 1; }
[ -f "$bssl/LICENSE" ] && [ -f "$bssl/third_party/fiat/LICENSE" ] || { echo "mknotice: $bssl is not a BoringSSL checkout" >&2; exit 1; }
rule() { printf '%s\n' "============================================================================="; }
cat <<EOF
Notices for kktls-conscrypt.jar and libkktls_conscrypt_jni.so (Conscrypt $tag, org.conscrypt:conscrypt-android:$tag)

This product contains Conscrypt $tag (https://github.com/google/conscrypt, tag $tag), licensed under the
Apache License 2.0. Its NOTICE and LICENSE follow.

libkktls_conscrypt_jni.so (the aar's libconscrypt_jni.so under another file name) links BoringSSL statically
(https://boringssl.googlesource.com/boringssl, commit $sha), licensed under the
Apache License 2.0 (its LICENSE at that commit, with an appendix for Go test code that is not compiled in). That
LICENSE and the one of third_party/fiat (fiat-crypto, compiled into libcrypto) follow the Conscrypt texts.

EOF
rule; echo "Conscrypt NOTICE (google/conscrypt $tag:NOTICE)"; rule; echo
git -C "$git_dir" show "$tag:NOTICE"
echo; rule
echo "Conscrypt LICENSE (google/conscrypt $tag:LICENSE; licenses/LICENSE.netty.txt and"
echo "licenses/LICENSE.harmony.txt are the same Apache License 2.0 text, up to whitespace)"
rule; echo
git -C "$git_dir" show "$tag:LICENSE"
echo; rule; echo "BoringSSL LICENSE (boringssl $sha:LICENSE)"; rule; echo
cat "$bssl/LICENSE"
echo; rule; echo "fiat-crypto LICENSE (boringssl $sha:third_party/fiat/LICENSE)"; rule; echo
cat "$bssl/third_party/fiat/LICENSE"
