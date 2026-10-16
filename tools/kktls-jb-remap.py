#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Remap a patch of the 4.4 libcore series (patches/libcore/) to the Jelly Bean libcore layout.

Android 4.4 keeps the TLS provider in libcore/crypto (package org.conscrypt, JNI file org_conscrypt_NativeCrypto.cpp in
libjavacrypto.so); Android 4.1-4.3 keep the same classes in libcore/luni as org.apache.harmony.xnet.provider.jsse, JNI
file org_apache_harmony_xnet_provider_jsse_NativeCrypto.cpp in libjavacore.so. This tool rewrites the paths of every
`diff --git` section and the package names, JNI class paths and JNI function prefixes inside the hunks. The message
(everything before the first `diff --git` line) is copied unchanged: it keeps the 4.4 subject and the upstream
references. The output is a starting point for `git am --reject` on a JB libcore checkout, not a finished JB patch: the
hunks that do not apply are hand-ported there and the series is regenerated with `git format-patch`.

  kktls-jb-remap.py OUT_DIR PATCH...   write each remapped PATCH to OUT_DIR/<same name>
  kktls-jb-remap.py --selftest         check the substitutions on built-in cases

Stdlib only; run as `python3 -I`.
"""
import os
import re
import sys

JSSE_DIR = "org/apache/harmony/xnet/provider/jsse"
JSSE_PKG = "org.apache.harmony.xnet.provider.jsse"
JSSE_JNI = "org_apache_harmony_xnet_provider_jsse_"

# Order matters: longer, more specific paths first.
PATH_MAP = [
    ("crypto/src/main/native/org_conscrypt_NativeCrypto.cpp",
     "luni/src/main/native/" + JSSE_JNI + "NativeCrypto.cpp"),
    ("crypto/src/main/java/org/conscrypt/", "luni/src/main/java/%s/" % JSSE_DIR),
    ("crypto/src/test/java/org/conscrypt/", "luni/src/test/java/%s/" % JSSE_DIR),
]
TEXT_MAP = [
    (re.compile(r"\borg\.conscrypt\b"), JSSE_PKG),
    (re.compile(r"org/conscrypt/"), JSSE_DIR + "/"),  # also inside "Lorg/conscrypt/..;"
    (re.compile(r"org_conscrypt_"), JSSE_JNI),
]


def remap_text(s):
    for old, new in PATH_MAP:
        s = s.replace(old, new)
    for rx, new in TEXT_MAP:
        s = rx.sub(new, s)
    return s


def remap_patch(text):
    """Message unchanged up to the first `diff --git`; paths and names remapped from there on."""
    m = re.search(r"^diff --git ", text, re.M)
    if not m:
        raise ValueError("no diff --git section")
    return text[:m.start()] + remap_text(text[m.start():])


def selftest():
    cases = [
        ("diff --git a/crypto/src/main/java/org/conscrypt/NativeCrypto.java b/crypto/src/main/java/org/conscrypt/"
         "NativeCrypto.java\n",
         "diff --git a/luni/src/main/java/%s/NativeCrypto.java b/luni/src/main/java/%s/NativeCrypto.java\n"
         % (JSSE_DIR, JSSE_DIR)),
        ("+++ b/crypto/src/test/java/org/conscrypt/AddressUtilsTest.java\n",
         "+++ b/luni/src/test/java/%s/AddressUtilsTest.java\n" % JSSE_DIR),
        ("--- a/crypto/src/main/native/org_conscrypt_NativeCrypto.cpp\n",
         "--- a/luni/src/main/native/%sNativeCrypto.cpp\n" % JSSE_JNI),
        ("+package org.conscrypt;\n", "+package %s;\n" % JSSE_PKG),
        ('+    NATIVE_METHOD(NativeCrypto, x, "(L" SSL_CALLBACKS ")V"),\n'
         '+#define SSL_CALLBACKS "Lorg/conscrypt/NativeCrypto$SSLHandshakeCallbacks;"\n',
         '+    NATIVE_METHOD(NativeCrypto, x, "(L" SSL_CALLBACKS ")V"),\n'
         '+#define SSL_CALLBACKS "L%s/NativeCrypto$SSLHandshakeCallbacks;"\n' % JSSE_DIR),
        ("+static jint org_conscrypt_NativeCrypto_x(\n", "+static jint %sNativeCrypto_x(\n" % JSSE_JNI),
        ("+import org.conscryptx.Foo;\n", "+import org.conscryptx.Foo;\n"),
    ]
    bad = 0
    for src, want in cases:
        got = remap_text(src)
        if got != want:
            bad += 1
            print("FAIL: %r -> %r, want %r" % (src, got, want))
    msg = "Subject: x\n\nsee crypto/src/main/java/org/conscrypt/A.java\n---\n"
    body = "diff --git a/crypto/src/main/java/org/conscrypt/A.java b/crypto/src/main/java/org/conscrypt/A.java\n"
    out = remap_patch(msg + body)
    if not out.startswith(msg) or "org/conscrypt" in out[len(msg):]:
        bad += 1
        print("FAIL: message must stay, body must be remapped: %r" % out)
    print("selftest: %d cases, %d failed" % (len(cases) + 1, bad))
    return 1 if bad else 0


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) < 3 or argv[1].startswith("-"):
        sys.stderr.write(__doc__)
        return 2
    out = argv[1]
    os.makedirs(out, exist_ok=True)
    for p in argv[2:]:
        with open(p, encoding="utf-8", newline="") as f:
            text = f.read()
        with open(os.path.join(out, os.path.basename(p)), "w", encoding="utf-8", newline="") as f:
            f.write(remap_patch(text))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
