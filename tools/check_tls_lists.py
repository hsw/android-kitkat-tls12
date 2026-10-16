#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Static checker for the kktls TLS series (Java TLS 1.2+ by default on an Android 4.4 tree).

It pins what the runtime tests cannot observe or would only show on a device: constants and lists that must agree
across Java and C, the exact default lists, that the SNI host is computed without a reverse DNS lookup (the route (a)
tests cannot see a lookup on an InetAddress-created socket) and okhttp's "SCSV only when supported" guard (cheap static
pin of the branch next to libcore's runtime fallback tests). Input is a directory holding the patched source files at their tree-relative paths (copied from the
trial tree after apply-patches.sh). Stdlib only, plus kktlsfmt.py next to this script (the A6/A7/SSL_MODE values); run as
`python3 -I`.

  check_tls_lists.py DIR [--group G ...] [--check NAME ...]   run checks (exit 1 if any fails; 2 for an unknown
                                                              group/check or when nothing is selected); groups:
                                                              openssl, libcore, okhttp
  check_tls_lists.py --list-files                             tree-relative paths the checks read (for tar/rsync)
  check_tls_lists.py --list-checks                            check names and groups
  check_tls_lists.py --selftest                               run every check on fixtures/good (all must pass) and on
                                                              each mutation in fixtures/mutations.json (the named
                                                              check must fail with the expected message; a mutation
                                                              with "pass": true is a control that must still pass)

Fetch the inputs from a patched AOSP 4.4 tree:
  (cd <tree> && tar -cf - $(python3 -I check_tls_lists.py --list-files)) | tar -x -C DIR
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # python3 -I leaves the script directory off sys.path
# A6 order, A7 protocols and the SSL_MODE bits: one definition in kktlsfmt.py, which check_artifacts.py checks against the
# built dex; this script checks the same lists against the patched sources.
from kktlsfmt import A6_DEFAULT_SUITES, A7_CLIENT_PROTOCOLS, SSL_MODES, SSL_MODES_NOTE  # noqa: E402

F_NATIVE = "libcore/crypto/src/main/java/org/conscrypt/NativeCrypto.java"
F_SERVER = "libcore/crypto/src/main/java/org/conscrypt/OpenSSLServerSocketImpl.java"
F_SOCKET = "libcore/crypto/src/main/java/org/conscrypt/OpenSSLSocketImpl.java"
F_SSL_H = "external/openssl/ssl/ssl.h"
F_SSL_H_INC = "external/openssl/include/openssl/ssl.h"
F_TLS1_H = "external/openssl/ssl/tls1.h"
F_SSL_LOCL_H = "external/openssl/ssl/ssl_locl.h"
F_OKHTTP_PLATFORM = "external/okhttp/android/main/java/com/squareup/okhttp/internal/Platform.java"
F_ADDRESS_UTILS = "libcore/crypto/src/main/java/org/conscrypt/AddressUtils.java"
F_CONSCRYPT_PLATFORM = "libcore/crypto/src/main/java/org/conscrypt/Platform.java"
# OpenSSL keeps two copies of its public SSL headers: ssl/<h> (the source) and include/openssl/<h> (what libssl itself, via
# <openssl/ssl.h>, and every client such as libjavacrypto compile against). A1 (cm-11 a8c4a5f) edits both copies.
OPENSSL_HEADER_PAIRS = [("external/openssl/ssl/%s" % h, "external/openssl/include/openssl/%s" % h)
                        for h in ("ssl.h", "ssl3.h", "tls1.h", "dtls1.h")]
FILES = [F_NATIVE, F_SERVER, F_SOCKET, F_ADDRESS_UTILS, F_CONSCRYPT_PLATFORM, F_SSL_H, F_SSL_H_INC, F_SSL_LOCL_H,
         F_OKHTTP_PLATFORM] + \
    [f for pair in OPENSSL_HEADER_PAIRS for f in pair if f not in (F_SSL_H, F_SSL_H_INC)]

# Other NativeCrypto constants that mirror an ssl.h #define (SSL_OP_*, SSL_MODE_*, SSL_VERIFY_*): each must equal both
# ssl.h copies (Task 7d audit of the 1.0.1u headers; checked by ssl-cipher-constants).
# The whole initializer is evaluated (const_value): an expression it cannot evaluate fails, it is never skipped.
SSL_H_MIRROR = re.compile(r"\b(long|int)\s+(SSL_(?:OP|MODE|VERIFY)_\w+)\s*=\s*([^;]*);")
# A1 wire values: the SCSV cipher id (0x5600 in the ClientHello) and the inappropriate_fallback alert.
A1_WIRE = [("external/openssl/ssl/ssl3.h", "SSL3_CK_FALLBACK_SCSV", 0x03005600),
           ("external/openssl/ssl/tls1.h", "TLS1_AD_INAPPROPRIATE_FALLBACK", 86)]

# A5: the 33 TLS 1.2 rows of conscrypt 336e8eb (5.0 NativeCrypto), standard name -> OpenSSL name.
A5_TLS12_ROWS = [
    ("TLS_RSA_WITH_NULL_SHA256", "NULL-SHA256"),
    ("TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256"),
    ("TLS_RSA_WITH_AES_256_CBC_SHA256", "AES256-SHA256"),
    ("TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256"),
    ("TLS_RSA_WITH_AES_256_GCM_SHA384", "AES256-GCM-SHA384"),
    ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE-RSA-AES128-SHA256"),
    ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE-RSA-AES256-SHA256"),
    ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE-RSA-AES128-GCM-SHA256"),
    ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE-RSA-AES256-GCM-SHA384"),
    ("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "DHE-DSS-AES128-SHA256"),
    ("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "DHE-DSS-AES256-SHA256"),
    ("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "DHE-DSS-AES128-GCM-SHA256"),
    ("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "DHE-DSS-AES256-GCM-SHA384"),
    ("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "ECDH-RSA-AES128-SHA256"),
    ("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "ECDH-RSA-AES256-SHA384"),
    ("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "ECDH-RSA-AES128-GCM-SHA256"),
    ("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "ECDH-RSA-AES256-GCM-SHA384"),
    ("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "ECDH-ECDSA-AES128-SHA256"),
    ("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "ECDH-ECDSA-AES256-SHA384"),
    ("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "ECDH-ECDSA-AES128-GCM-SHA256"),
    ("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "ECDH-ECDSA-AES256-GCM-SHA384"),
    ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256"),
    ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE-RSA-AES256-SHA384"),
    ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"),
    ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256"),
    ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE-ECDSA-AES256-SHA384"),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"),
    ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384"),
    ("TLS_DH_anon_WITH_AES_128_CBC_SHA256", "ADH-AES128-SHA256"),
    ("TLS_DH_anon_WITH_AES_256_CBC_SHA256", "ADH-AES256-SHA256"),
    ("TLS_DH_anon_WITH_AES_128_GCM_SHA256", "ADH-AES128-GCM-SHA256"),
    ("TLS_DH_anon_WITH_AES_256_GCM_SHA384", "ADH-AES256-GCM-SHA384"),
]

# kktls port of conscrypt 2d089e18: the server key type comes from the SSL_CIPHER's algorithm_mkey/algorithm_auth bits, so
# the Java copies of these OpenSSL 1.0.1e constants must equal the headers in the tree (README §5.7 rule, extended).
# (Java name, header that defines it): SSL_k*/SSL_a* in ssl/ssl_locl.h, the ClientCertificateType bytes in ssl/tls1.h.
KEYTYPE_CONSTANTS = [("SSL_k%s" % n, F_SSL_LOCL_H) for n in
                     ("RSA", "DHr", "DHd", "EDH", "KRB5", "ECDHr", "ECDHe", "EECDH", "PSK", "GOST", "SRP")] + \
                    [("SSL_a%s" % n, F_SSL_LOCL_H) for n in
                     ("RSA", "DSS", "NULL", "DH", "ECDH", "KRB5", "ECDSA", "PSK", "GOST94", "GOST01")] + \
                    [("TLS_CT_%s" % n, F_TLS1_H) for n in
                     ("RSA_SIGN", "DSS_SIGN", "RSA_FIXED_DH", "DSS_FIXED_DH", "ECDSA_SIGN", "RSA_FIXED_ECDH",
                      "ECDSA_FIXED_ECDH")]

SUPPORTED_PROTOCOLS = ["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"]

# Families that must not be in the default suite list (A6): (label, regex on the standard name).
FORBIDDEN = [
    ("RC4", re.compile(r"_RC4_")),
    ("3DES", re.compile(r"_3DES_")),
    ("DES", re.compile(r"_DES(40)?_")),
    ("EXPORT", re.compile(r"EXPORT")),
    ("MD5", re.compile(r"_MD5$")),
    ("DHE", re.compile(r"^(TLS|SSL)_DHE_")),
    ("DSS", re.compile(r"_DSS_")),
    ("static ECDH", re.compile(r"^TLS_ECDH_(ECDSA|RSA)_")),
    ("NULL", re.compile(r"_NULL_")),
    ("anon", re.compile(r"_anon_")),
    ("fallback SCSV", re.compile(r"^TLS_FALLBACK_SCSV$")),
]


class CheckError(Exception):
    pass


# ---------------------------------------------------------------------------------------------------- source parsing

def strip_comments(text):
    """Remove // and /* */ comments (C and Java), keeping string and char literals and line structure."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * text.count("\n", i, j))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def read_raw(root, rel):
    try:
        with open(os.path.join(root, rel), "rb") as f:
            return f.read()
    except OSError as e:
        raise CheckError("cannot read %s: %s" % (rel, e.strerror))


def read(root, rel):
    return strip_comments(read_raw(root, rel).decode("utf-8", errors="replace"))


def matching_close(text, start, open_c="{", close_c="}"):
    """Offset of the bracket that closes the one at text[start] (string and char literals skipped)."""
    depth, i = 0, start
    while i < len(text):
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < len(text) and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            i = j
        elif c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise CheckError("unbalanced %s%s after offset %d" % (open_c, close_c, start))


def block_after(text, pos):
    """Text inside the brace block that starts at the first '{' at or after pos."""
    start = text.find("{", pos)
    if start < 0:
        raise CheckError("no block after offset %d" % pos)
    return text[start + 1:matching_close(text, start)]


def control_blocks(text, keyword):
    """[(header, start, end)] of every braced `keyword (header) { ... }` statement in text (if/for/while); start..end
    spans the block body. Statements without braces are not listed, so code under them counts as unguarded."""
    out = []
    for m in re.finditer(r"\b%s\s*\(" % keyword, text):
        close = matching_close(text, m.end() - 1, "(", ")")
        rest = text[close + 1:]
        brace = len(rest) - len(rest.lstrip())
        if rest[brace:brace + 1] != "{":
            continue
        start = close + 1 + brace
        out.append((text[m.end():close], start, matching_close(text, start)))
    return out


def enclosing(blocks, pos):
    """Headers of the blocks that contain offset pos, innermost first."""
    inside = [(start, header) for header, start, end in blocks if start < pos < end]
    return [header for start, header in sorted(inside, reverse=True)]


def method_body(text, name, rel):
    m = re.search(r"[\w\]>]\s+%s\s*\([^)]*\)\s*(throws [\w.,\s]+)?\{" % re.escape(name), text)
    if not m:
        raise CheckError("%s: method %s() not found" % (rel, name))
    return block_after(text, m.end() - 1)


def method_bodies(text):
    """{name: [body, ...]} of every method (and constructor) declared in a Java class; overloads share a name."""
    out = {}
    for m in re.finditer(r"(?<![\w.])(\w+)\s*\(([^()]*)\)\s*(?:throws\s+[\w.,\s]+)?\{", text):
        name = m.group(1)
        if name in ("if", "for", "while", "switch", "catch", "synchronized", "return", "new", "super", "this"):
            continue
        out.setdefault(name, []).append(block_after(text, m.end() - 1))
    return out


def reachable_bodies(text, start):
    """[(path, body)] of method `start` and every method of the same class it calls, transitively (calls through
    another object, `x.m(...)`, are not followed; `this.m(...)` and `super.m(...)` of a local method are)."""
    bodies = method_bodies(text)
    seen, out, todo = set(), [], [(start, start + "()")]
    while todo:
        name, path = todo.pop(0)
        if name in seen or name not in bodies:
            continue
        seen.add(name)
        for body in bodies[name]:
            out.append((path, body))
            for c in re.finditer(r"(?:(?<![\w.])|(?<=this\.)|(?<=super\.))(\w+)\s*\(", body):
                if c.group(1) in bodies and c.group(1) not in seen:
                    todo.append((c.group(1), "%s -> %s()" % (path, c.group(1))))
    return out


def string_constants(text):
    return dict(re.findall(r'\bString\s+(\w+)\s*=\s*"([^"]*)"\s*;', text))


def array_constants(text):
    out = {}
    for m in re.finditer(r"\bString\s*\[\s*\]\s+(\w+)\s*=\s*(?:new\s+String\s*\[\s*\]\s*)?(?=\{)", text):
        out[m.group(1)] = block_after(text, m.end())
    return out


def eval_elements(body, consts, rel):
    items = []
    for tok in [t.strip() for t in body.split(",")]:
        if not tok:
            continue
        m = re.fullmatch(r'"([^"]*)"', tok)
        if m:
            items.append(m.group(1))
            continue
        name = tok.split(".")[-1]
        if name in consts:
            items.append(consts[name])
            continue
        raise CheckError("%s: cannot resolve list element %r" % (rel, tok))
    return items


def eval_string_array(expr, text, rel):
    """Evaluate a String[] expression: new String[] {...}, CONST, CONST.clone(), Class.CONST."""
    consts, arrays = string_constants(text), array_constants(text)
    expr = expr.strip()
    m = re.match(r"new\s+String\s*\[\s*\]\s*\{", expr)
    if m:
        return eval_elements(block_after(expr, m.end() - 1), consts, rel)
    m = re.fullmatch(r"(?:\w+\.)*(\w+)(?:\.clone\(\))?", expr)
    if m and m.group(1) in arrays:
        return eval_elements(arrays[m.group(1)], consts, rel)
    raise CheckError("%s: cannot evaluate String[] expression %r" % (rel, expr[:80]))


def returned_array(text, method, rel):
    body = method_body(text, method, rel)
    m = re.search(r"\breturn\b", body)
    if not m:
        raise CheckError("%s: %s() has no return" % (rel, method))
    end = body.find(";", m.end())
    # a `new String[] {...}` literal contains no ';' so the first one ends the return statement
    return eval_string_array(body[m.end():end], text, rel)


# Constant expressions (review 3, codex 5: the parsers read only the leading literal, so `(0x00000080L << 1)` was 0x80).
# const_value evaluates the whole initializer or #define body, or raises CheckError; it never returns a prefix's value.
_CONST_TOKEN = re.compile(r"\s*(?:(0[xX][0-9a-fA-F]+|[0-9]+)(\w*)|(<<|[|()]))")
C_SUFFIX = r"(?:[uU](?:ll|LL|[lL])?|(?:ll|LL|[lL])[uU]?)?$"
# value widths: C unsigned long of the ARMv7 target, and Java long, int and byte as non-negative values
JAVA_TYPES = {"long": (r"[lL]?$", 63), "int": (r"$", 31), "byte": (r"$", 7)}


def const_value(expr, suffix, bits, what):
    """Exact value of the constant expression `expr`: integer literals (hex, decimal, octal; `suffix` is a regex of the
    suffixes the language allows), parentheses, << and |, the forms the OpenSSL headers and NativeCrypto use. Every
    literal, shift result and the value must be a non-negative number below 2**bits and every shift count below `bits`.
    Anything else (an identifier, another operator, a missing operand, text left over) raises CheckError naming `what`."""
    def bad(why):
        return CheckError("%s: cannot evaluate %r (%s)" % (what, expr.strip(), why))
    text, pos, toks = expr.strip(), 0, []
    while pos < len(text):
        m = _CONST_TOKEN.match(text, pos)
        if not m:
            raise bad("unexpected %r" % text[pos:pos + 12])
        pos = m.end()
        if m.group(3):
            toks.append(m.group(3))
            continue
        digits, suf = m.group(1), m.group(2)
        if not re.match(suffix, suf):
            raise bad("literal %s%s" % (digits, suf))
        if digits[:2] in ("0x", "0X"):
            v = int(digits, 16)
        elif digits == "0" or digits[0] != "0":
            v = int(digits)
        elif re.match(r"0[0-7]+$", digits):
            v = int(digits, 8)
        else:
            raise bad("literal %s" % digits)
        toks.append(v)
    limit, at = 1 << bits, [0]

    def peek():
        return toks[at[0]] if at[0] < len(toks) else None

    def take():
        t = peek()
        at[0] += 1
        return t

    def fits(v):
        if v >= limit:
            raise bad("0x%x does not fit %d bits" % (v, bits))
        return v

    def primary():
        t = take()
        if t == "(":
            v = alternation()
            if take() != ")":
                raise bad("unbalanced parentheses")
            return v
        if isinstance(t, int):
            return fits(t)
        raise bad("an operand expected, got %s" % ("the end" if t is None else repr(t)))

    def shift():
        v = primary()
        while peek() == "<<":
            take()
            n = primary()
            if n >= bits:
                raise bad("shift by %d" % n)
            v = fits(v << n)
        return v

    def alternation():
        v = shift()
        while peek() == "|":
            take()
            v |= shift()
        return v

    if not toks:
        raise bad("empty")
    value = alternation()
    if at[0] != len(toks):
        raise bad("text after the value")
    return value


def java_long(text, name, rel=F_NATIVE):
    """Value of a long constant; None when there is none; CheckError when its initializer cannot be evaluated."""
    m = re.search(r"\blong\s+%s\s*=\s*([^;]*);" % name, text)
    return const_value(m.group(1), JAVA_TYPES["long"][0], JAVA_TYPES["long"][1], "%s long %s" % (rel, name)) \
        if m else None


def java_int(text, name, rel=F_NATIVE):
    """Value of an int or byte constant (the kktls port of 2d089e18 adds SSL_k*/SSL_a* ints and TLS_CT_* bytes); None
    when there is none; CheckError when its initializer cannot be evaluated."""
    m = re.search(r"\b(int|byte)\s+%s\s*=\s*([^;]*);" % name, text)
    if not m:
        return None
    suffix, bits = JAVA_TYPES[m.group(1)]
    return const_value(m.group(2), suffix, bits, "%s %s %s" % (rel, m.group(1), name))


def c_define(text, name, rel="header"):
    """Value of an object-like #define (its whole body, continuation lines joined; comments are already stripped);
    None when there is none; CheckError when its body cannot be evaluated."""
    text = re.sub(r"\\\r?\n", " ", text)
    m = re.search(r"^[ \t]*#[ \t]*define[ \t]+%s(?![\w(])([^\n]*)$" % name, text, re.M)
    return const_value(m.group(1), C_SUFFIX, 32, "%s #define %s" % (rel, name)) if m else None


def c_txt_defines(text):
    """OpenSSL cipher names: #define TLS1_TXT_<X> "<name>" -> {X: name}."""
    return dict(re.findall(r'^\s*#\s*define\s+TLS1_TXT_(\w+)\s+"([^"]+)"', text, re.M))


def tls1_txt_key(std):
    """ssl/tls1.h names a TLS 1.2 suite without "TLS_" and "CBC_", and DH_anon as ADH:
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -> ECDHE_RSA_WITH_AES_128_SHA256, TLS_DH_anon_WITH_... -> ADH_WITH_..."""
    return std[len("TLS_"):].replace("_CBC_", "_").replace("DH_anon_WITH", "ADH_WITH")


def suite_table(text):
    return re.findall(r'\badd\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)\s*;', text)


# ---------------------------------------------------------------------------------------------------- checks
# Each check returns a list of failure messages (empty = pass). Task 3 added ssl-cipher-constants and
# server-keytype-native (kktls port of 2d089e18), Task 5 sni-host-helper (A8), Task 7 the okhttp "SCSV only when
# supported" refinement of okhttp-fallback (A11).

CHECKS = []


def check(name, group):
    def deco(fn):
        CHECKS.append((name, group, fn))
        return fn
    return deco


@check("scsv-java-matches-c", "libcore")
def c_scsv(root):
    """A4 TLS_FALLBACK_SCSV: the Java mode bits equal SSL_MODE_* in BOTH ssl.h copies (README §5.7) and are the 1.0.1u
    values (SCSV 0x80, cut-through 0x200, Task 7d); the pseudo-suite exists, is supported (appended to the supported
    list, accepted by checkEnabledCipherSuites) but never default, and turns into
    SSL_set_mode(SSL_MODE_SEND_FALLBACK_SCSV)."""
    nc = read(root, F_NATIVE)
    hdrs = [(F_SSL_H, read(root, F_SSL_H)), (F_SSL_H_INC, read(root, F_SSL_H_INC))]
    fails = []
    for name, label in (("SSL_MODE_SEND_FALLBACK_SCSV", "no SCSV"), ("SSL_MODE_HANDSHAKE_CUTTHROUGH", "cut-through")):
        try:
            jv = java_long(nc, name)
        except CheckError as e:
            fails.append(str(e))
            continue
        if jv is None:
            fails.append("%s: NativeCrypto has no long %s" % (label, name))
        for rel, h in hdrs:
            try:
                cv = c_define(h, name, rel)
            except CheckError as e:
                fails.append(str(e))
                continue
            if cv is None:
                fails.append("%s: %s has no #define %s" % (label, rel, name))
            elif jv is not None and cv != jv:
                fails.append("%s mismatch: NativeCrypto 0x%x, %s 0x%x" % (name, jv, rel, cv))
    for name, want in SSL_MODES:
        try:
            jv = java_long(nc, name)
        except CheckError:
            continue  # reported above (SSL_MODES are the two bits checked above)
        if jv is not None and jv != want:
            fails.append("%s is 0x%x in NativeCrypto, want 0x%x (%s)" % (name, jv, want, SSL_MODES_NOTE))
    if string_constants(nc).get("TLS_FALLBACK_SCSV") != "TLS_FALLBACK_SCSV":
        fails.append('no SCSV: NativeCrypto has no String TLS_FALLBACK_SCSV = "TLS_FALLBACK_SCSV"')
    if not re.search(r"SSL_set_mode\(\s*\w+\s*,\s*SSL_MODE_SEND_FALLBACK_SCSV\s*\)", nc):
        fails.append("no SCSV: NativeCrypto never calls SSL_set_mode(ssl, SSL_MODE_SEND_FALLBACK_SCSV)")
    if not re.search(r"SUPPORTED_CIPHER_SUITES\s*\[[^\]]*\]\s*=\s*TLS_FALLBACK_SCSV\s*;", nc):
        fails.append("no SCSV: TLS_FALLBACK_SCSV is not appended to SUPPORTED_CIPHER_SUITES")
    try:
        body = method_body(nc, "checkEnabledCipherSuites", F_NATIVE)
        if "TLS_FALLBACK_SCSV" not in body:
            fails.append("no SCSV: checkEnabledCipherSuites() does not skip TLS_FALLBACK_SCSV, so setEnabledCipherSuites "
                         "rejects it")
    except CheckError as e:
        fails.append(str(e))
    try:
        if "TLS_FALLBACK_SCSV" in default_suites(root):
            fails.append("TLS_FALLBACK_SCSV is in getDefaultCipherSuites(); it must be supported, never default")
    except CheckError as e:
        fails.append(str(e))
    return fails


@check("openssl-header-values", "openssl")
def c_openssl_headers(root):
    """SSL_MODE_SEND_FALLBACK_SCSV = 0x80 and SSL_MODE_HANDSHAKE_CUTTHROUGH = 0x200 in BOTH ssl.h copies, no two
    SSL_MODE bits collide, SCSV id 0x03005600 and alert 86 are defined, and the ssl/ and include/openssl/ copies of ssl.h,
    ssl3.h, tls1.h and dtls1.h are identical (reads only OpenSSL files)."""
    fails = []
    for rel in (F_SSL_H, F_SSL_H_INC):
        h = read(root, rel)
        for name, want in SSL_MODES:
            try:
                got = c_define(h, name, rel)
            except CheckError as e:
                fails.append(str(e))
                continue
            if got is None:
                fails.append("%s: %s has no #define %s" % ("no SCSV" if "SCSV" in name else "cut-through", rel, name))
            elif got != want:
                fails.append("%s is 0x%x in %s, want 0x%x (%s)" % (name, got, rel, want, SSL_MODES_NOTE))
        bits = {}
        names = []
        for name in re.findall(r"^[ \t]*#[ \t]*define[ \t]+(SSL_MODE_\w+)(?![\w(])", h, re.M):
            if name not in names:
                names.append(name)
        for name in names:
            try:
                bits.setdefault(c_define(h, name, rel), []).append(name)
            except CheckError as e:
                fails.append(str(e))
        for val, names in sorted(bits.items()):
            if len(names) > 1:
                fails.append("SSL_MODE bits collide in %s: %s are all 0x%x" % (rel, ", ".join(names), val))
    for rel, name, want in A1_WIRE:
        try:
            got = c_define(read(root, rel), name, rel)
        except CheckError as e:
            fails.append(str(e))
            continue
        if got is None:
            fails.append("no SCSV: %s has no #define %s" % (rel, name))
        elif got != want:
            fails.append("%s is 0x%x in %s, want 0x%x" % (name, got, rel, want))
    for src, inc in OPENSSL_HEADER_PAIRS:
        if read_raw(root, src) != read_raw(root, inc):
            fails.append("header copies differ: %s != %s" % (src, inc))
    return fails


@check("tls12-table", "libcore")
def c_table(root):
    """A5: the 33 TLS 1.2 rows of 336e8eb are in STANDARD_TO_OPENSSL_CIPHER_SUITES with the same OpenSSL names, and
    each OpenSSL name is the TLS1_TXT_* name of that suite in the tree's ssl/tls1.h."""
    rows = dict()
    fails = []
    for std, ossl in suite_table(read(root, F_NATIVE)):
        if std in rows and rows[std] != ossl:
            fails.append("%s mapped twice (%s, %s)" % (std, rows[std], ossl))
        rows[std] = ossl
    missing = [s for s, _ in A5_TLS12_ROWS if s not in rows]
    if len(missing) == len(A5_TLS12_ROWS):
        fails.append("no GCM rows: all %d TLS 1.2 rows missing from STANDARD_TO_OPENSSL_CIPHER_SUITES" % len(missing))
    elif missing:
        fails.append("TLS 1.2 rows missing: %s" % ", ".join(missing))
    for std, ossl in A5_TLS12_ROWS:
        if std in rows and rows[std] != ossl:
            fails.append("%s maps to %s, want %s" % (std, rows[std], ossl))
    txt = c_txt_defines(read(root, F_TLS1_H))
    for std, ossl in A5_TLS12_ROWS:
        key = tls1_txt_key(std)
        if key not in txt:
            fails.append("%s: %s has no TLS1_TXT_%s" % (std, F_TLS1_H, key))
        elif txt[key] != rows.get(std, ossl):
            fails.append("%s maps to %s, but %s TLS1_TXT_%s is %s" % (std, rows.get(std, ossl), F_TLS1_H, key, txt[key]))
    return fails


@check("ssl-cipher-constants", "libcore")
def c_keytype_constants(root):
    """kktls port of 2d089e18: NativeCrypto's SSL_k*/SSL_a* (server key type from SSL_CIPHER) equal ssl/ssl_locl.h and its
    TLS_CT_* (client certificate types) equal ssl/tls1.h; (Task 7d) every other SSL_OP_*/SSL_MODE_*/SSL_VERIFY_* long or
    int of NativeCrypto equals the #define in both ssl.h copies (the two SCSV/cut-through bits: scsv-java-matches-c)."""
    nc = read(root, F_NATIVE)
    hdrs = {}
    fails = []
    for name, rel in KEYTYPE_CONSTANTS:
        if rel not in hdrs:
            hdrs[rel] = read(root, rel)
        try:
            jv = java_int(nc, name)
            cv = c_define(hdrs[rel], name, rel)
        except CheckError as e:
            fails.append(str(e))
            continue
        if jv is None:
            fails.append("no native key type: NativeCrypto has no int/byte %s" % name)
        if cv is None:
            fails.append("%s has no #define %s" % (rel, name))
        if jv is not None and cv is not None and jv != cv:
            fails.append("%s mismatch: NativeCrypto 0x%x, %s 0x%x" % (name, jv, rel, cv))
    pinned = set(n for n, _ in SSL_MODES)
    for rel in (F_SSL_H, F_SSL_H_INC):
        h = read(root, rel)
        for typ, name, val in SSL_H_MIRROR.findall(nc):
            if name in pinned:
                continue
            try:
                jv = const_value(val, JAVA_TYPES[typ][0], JAVA_TYPES[typ][1], "%s %s %s" % (F_NATIVE, typ, name))
                cv = c_define(h, name, rel)
            except CheckError as e:
                fails.append(str(e))
                continue
            if cv is None:
                fails.append("%s has no #define %s (mirrored by NativeCrypto)" % (rel, name))
            elif jv != cv:
                fails.append("%s mismatch: NativeCrypto 0x%x, %s 0x%x" % (name, jv, rel, cv))
    return fails


@check("server-keytype-native", "libcore")
def c_server_keytype(root):
    """kktls port of 2d089e18: OpenSSL server sockets take the server key types from SSL_get_ciphers(), not from the Harmony
    CipherSuite table, which has no TLS 1.2 suites (CipherSuite.getByName() returns null -> NullPointerException)."""
    fails = []
    for rel in (F_SOCKET, F_SERVER):
        if re.search(r"\bCipherSuite\s*\.\s*getByName\s*\(", read(root, rel)):
            fails.append("NPE for TLS 1.2 suites: %s calls CipherSuite.getByName() (the Harmony table has no TLS 1.2 "
                         "suites)" % rel)
    sock = read(root, F_SOCKET)
    if not re.search(r"NativeCrypto\s*\.\s*SSL_get_ciphers\s*\(", sock):
        fails.append("%s never calls NativeCrypto.SSL_get_ciphers() for the server key types" % F_SOCKET)
    if not re.search(r"\bgetServerKeyType\s*\(\s*long\b", sock):
        fails.append("%s has no getServerKeyType(long sslCipher)" % F_SOCKET)
    return fails


# A8: calls that resolve a peer address and can block on (reverse) DNS; the SNI host must never come from them.
SNI_FORBIDDEN_CALLS = ["getPeerHostName", "getInetAddress", "getHostName", "getCanonicalHostName", "getByName",
                       "getAllByName"]


@check("sni-host-helper", "libcore")
def c_sni(root):
    """A8 (kktls port of conscrypt d745755, b221fc9, 342097d, 966ae8a, f67d784): the SNI host comes from
    OpenSSLSocketImpl.getSniHostname(), which (with every method it calls) never reaches getPeerHostName(),
    getInetAddress(), getHostName() or a DNS lookup; the (String host, ...) constructors keep their host;
    jsse.enableSNIExtension defaults to "true"; SSL_set_tlsext_host_name is only called with the helper's value and
    behind AddressUtils.isValidSniHostname, which wants a dot and rejects literal IPs via InetAddress.isNumeric."""
    sock = read(root, F_SOCKET)
    fails = []
    reach = reachable_bodies(sock, "getSniHostname")
    if not reach:
        fails.append("no SNI default: %s has no getSniHostname()" % F_SOCKET)
    for path, body in reach:
        for call in SNI_FORBIDDEN_CALLS:
            if re.search(r"\b%s\s*\(" % call, body):
                fails.append("reverse DNS: %s reaches %s()" % (path, call))
    text = "\n".join(b for _, b in reach)
    if reach and not re.search(r'System\s*\.\s*getProperty\(\s*"jsse\.enableSNIExtension"\s*,\s*"true"\s*\)', text):
        fails.append('SNI off by default: getSniHostname() does not read System.getProperty("jsse.enableSNIExtension", '
                     '"true")')
    for field in ("peerHostname", "wrappedHost"):
        if reach and not re.search(r"\b%s\b" % field, text):
            fails.append("getSniHostname() never uses %s" % field)
    for m in re.finditer(r"\bOpenSSLSocketImpl\s*\(\s*String\s+(\w+)\s*,[^)]*\)\s*(?:throws[\w.,\s]+)?\{", sock):
        if not re.search(r"\bpeerHostname\s*=\s*%s\s*;" % m.group(1), block_after(sock, m.end() - 1)):
            fails.append("the OpenSSLSocketImpl(String %s, ...) constructor drops its host (no peerHostname = %s)"
                         % (m.group(1), m.group(1)))
    calls = re.findall(r"SSL_set_tlsext_host_name\s*\(\s*\w+\s*,\s*([^)]*)\)", sock)
    guarded = re.findall(r"if\s*\(\s*AddressUtils\s*\.\s*isValidSniHostname\s*\(\s*(\w+)\s*\)\s*\)\s*\{\s*"
                         r"NativeCrypto\s*\.\s*SSL_set_tlsext_host_name\s*\(\s*\w+\s*,\s*(\w+)\s*\)", sock)
    if not calls:
        fails.append("%s never calls SSL_set_tlsext_host_name" % F_SOCKET)
    if len(guarded) != len(calls) or any(a != b for a, b in guarded):
        fails.append("SSL_set_tlsext_host_name(%s) is not guarded by AddressUtils.isValidSniHostname of the same value"
                     % ", ".join(c.strip() for c in calls))
    for _, var in guarded:
        if not re.search(r"\b%s\s*=\s*getSniHostname\s*\(\s*\)" % var, sock):
            fails.append("SSL_set_tlsext_host_name(%s) does not use getSniHostname()" % var)
    if not os.path.exists(os.path.join(root, F_ADDRESS_UTILS)):
        fails.append("no %s (342097d)" % F_ADDRESS_UTILS)
        return fails
    au = read(root, F_ADDRESS_UTILS)
    try:
        valid = method_body(au, "isValidSniHostname", F_ADDRESS_UTILS)
        if not re.search(r"indexOf\(\s*'\.'\s*\)", valid):
            fails.append("no FQDN check: AddressUtils.isValidSniHostname() does not look for a '.'")
        if not re.search(r"\bPlatform\s*\.\s*isLiteralIpAddress\s*\(", valid):
            fails.append("AddressUtils.isValidSniHostname() does not reject literal IPs via Platform.isLiteralIpAddress()")
    except CheckError as e:
        fails.append(str(e))
    try:
        lit = method_body(read(root, F_CONSCRYPT_PLATFORM), "isLiteralIpAddress", F_CONSCRYPT_PLATFORM)
        if not re.search(r"\bInetAddress\s*\.\s*isNumeric\s*\(", lit) or re.search(r"getByName|getAllByName", lit):
            fails.append("DNS lookup: Platform.isLiteralIpAddress() must use InetAddress.isNumeric() (no lookup)")
    except CheckError as e:
        fails.append(str(e))
    return fails


def default_suites(root):
    return returned_array(read(root, F_NATIVE), "getDefaultCipherSuites", F_NATIVE)


@check("default-suites-order", "libcore")
def c_order(root):
    """A6: getDefaultCipherSuites() is exactly the kktls list, in order."""
    got = default_suites(root)
    if got == A6_DEFAULT_SUITES:
        return []
    fails = []
    if got and got[0] != A6_DEFAULT_SUITES[0]:
        fam = [lab for lab, rx in FORBIDDEN if rx.search(got[0])]
        fails.append("first default suite is %s%s, want %s" % (got[0], " (%s first)" % fam[0] if fam else "",
                                                               A6_DEFAULT_SUITES[0]))
    for i, (g, w) in enumerate(zip(got, A6_DEFAULT_SUITES)):
        if g != w:
            fails.append("default suite #%d is %s, want %s" % (i + 1, g, w))
            break
    if len(got) != len(A6_DEFAULT_SUITES):
        fails.append("%d default suites, want %d" % (len(got), len(A6_DEFAULT_SUITES)))
    return fails


@check("default-suites-forbidden", "libcore")
def c_forbidden(root):
    """A6: no RC4, DES, 3DES, EXPORT, MD5, DHE, DSS, static ECDH, NULL, anon or the fallback SCSV in the defaults."""
    fails = []
    for s in default_suites(root):
        for lab, rx in FORBIDDEN:
            if rx.search(s):
                fails.append("%s suite in the defaults: %s" % (lab, s))
    return fails


@check("default-suites-supported", "libcore")
def c_supported(root):
    """Every default suite is in the table (or is the renegotiation SCSV), and the list has no duplicates."""
    nc = read(root, F_NATIVE)
    table = dict(suite_table(nc))
    got = default_suites(root)
    fails = ["default suite not in STANDARD_TO_OPENSSL_CIPHER_SUITES: %s" % s
             for s in got if s not in table and s != "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"]
    dups = sorted(set(s for s in got if got.count(s) > 1))
    if dups:
        fails.append("duplicate default suites: %s" % ", ".join(dups))
    return fails


@check("protocols-client", "libcore")
def c_proto_client(root):
    """A7: client defaults are TLSv1, TLSv1.1, TLSv1.2; SSLv3 stays supported (opt-in)."""
    nc = read(root, F_NATIVE)
    fails = []
    dflt = returned_array(nc, "getDefaultProtocols", F_NATIVE)
    if dflt != A7_CLIENT_PROTOCOLS:
        fails.append("getDefaultProtocols() = [%s], want [%s]" % (", ".join(dflt), ", ".join(A7_CLIENT_PROTOCOLS)))
    sup = returned_array(nc, "getSupportedProtocols", F_NATIVE)
    if sup != SUPPORTED_PROTOCOLS:
        fails.append("getSupportedProtocols() = [%s], want [%s] (SSLv3 stays opt-in)"
                     % (", ".join(sup), ", ".join(SUPPORTED_PROTOCOLS)))
    return fails


@check("protocols-server", "libcore")
def c_proto_server(root):
    """A7: OpenSSLServerSocketImpl enables the default protocols, not every supported one (SSLv3)."""
    src = read(root, F_SERVER)
    m = re.search(r"\bString\s*\[\s*\]\s+enabledProtocols\s*=\s*([^;]+);", src)
    if not m:
        return ["%s: no enabledProtocols field initializer" % F_SERVER]
    init = re.sub(r"\s+", "", m.group(1))
    if init != "NativeCrypto.getDefaultProtocols()":
        return ["server enabledProtocols = %s, want NativeCrypto.getDefaultProtocols()" % init]
    return []


@check("okhttp-fallback", "okhttp")
def c_okhttp(root):
    """A11: no "SSLv3" literal in okhttp's Android Platform; the TLS-intolerance retry is TLSv1 plus TLS_FALLBACK_SCSV,
    and the SCSV is appended only when getSupportedCipherSuites() lists it (Task 7)."""
    src = read(root, F_OKHTTP_PLATFORM)
    fails = []
    if '"SSLv3"' in src:
        fails.append('SSLv3 fallback: %s has an "SSLv3" literal' % F_OKHTTP_PLATFORM)
    body = method_body(src, "supportTlsIntolerantServer", F_OKHTTP_PLATFORM)
    protos = re.findall(r"setEnabledProtocols\(\s*new\s+String\s*\[\s*\]\s*\{([^}]*)\}\s*\)", body)
    if [re.sub(r"\s+", "", p) for p in protos] != ['"TLSv1"']:
        fails.append("supportTlsIntolerantServer sets protocols %s, want exactly {\"TLSv1\"}"
                     % (["{%s}" % p.strip() for p in protos] or "none"))
    if '"TLS_FALLBACK_SCSV"' not in body:
        fails.append("no SCSV: supportTlsIntolerantServer does not add TLS_FALLBACK_SCSV")
        return fails
    return fails + okhttp_scsv_guard(body)


def okhttp_scsv_guard(body):
    """Task 7 (c3f6560): TLS_FALLBACK_SCSV is appended only if the socket lists it in getSupportedCipherSuites(), so a
    socket factory that does not know the SCSV (an app's own provider, layer D before its adapter) gets no
    IllegalArgumentException from setEnabledCipherSuites. Accepted shape: a boolean flag declared false, set true inside
    a loop over the getSupportedCipherSuites() array under an equals() test against the SCSV name, and the
    setEnabledCipherSuites call inside `if (flag) { ... }`; or an if condition that tests the supported array directly.
    Negated tests (`!`, `== false`, `!= true`, `== -1`) are refused, and the flag may not be assigned anywhere except its
    `= false` declaration and the guarded `= true`."""
    fails = []
    supported = re.findall(r"(\w+)\s*=\s*[\w.]+\.getSupportedCipherSuites\(\s*\)", body)
    if not supported:
        return ["SCSV not checked against getSupportedCipherSuites(): no array assigned from "
                "socket.getSupportedCipherSuites() in supportTlsIntolerantServer"]
    scsv_names = ['"TLS_FALLBACK_SCSV"'] + re.findall(r'\bString\s+(\w+)\s*=\s*"TLS_FALLBACK_SCSV"\s*;', body)
    ifs, fors = control_blocks(body, "if"), control_blocks(body, "for")

    def mentions(expr, names):
        return any(re.search(r"(?<![\w\"])%s(?![\w\"])" % re.escape(n), expr) if not n.startswith('"') else n in expr
                   for n in names)

    def negated(expr):
        return bool(re.search(r"!(?!=)|==\s*false\b|\bfalse\s*==|!=\s*true\b|\btrue\s*!=|==\s*-\s*1\b", expr))

    def supported_test(expr):
        return mentions(expr, supported) and mentions(expr, scsv_names)

    def flag_from_supported_loop(flag):
        """flag is declared false and only ever set true under an SCSV equals() test inside a loop over the array."""
        decl = re.search(r"\bboolean\s+%s\s*=\s*(\w+)\s*;" % re.escape(flag), body)
        if not decl:
            return "flag %s is not a boolean declared in supportTlsIntolerantServer" % flag
        if decl.group(1) != "false":
            return "flag %s starts %s, want false (set only when getSupportedCipherSuites() lists the SCSV)" \
                % (flag, decl.group(1))
        sets = [m.start() for m in re.finditer(r"(?<![\w.])%s\s*=(?!=)\s*true\s*;" % re.escape(flag), body)]
        if not sets:
            return "flag %s is never set true" % flag
        assigns = [m for m in re.finditer(r"(?<![\w.])%s\s*(?:=(?!=)|[|&^]=)" % re.escape(flag), body)
                   if m.start() not in sets and not decl.start() <= m.start() < decl.end()]
        if assigns:
            a = assigns[0]
            return "flag %s is assigned outside the guarded `= true`: %s" \
                % (flag, body[a.start():body.find(";", a.start()) + 1].strip())
        for pos in sets:
            loop_ok = any(mentions(h, supported) for h in enclosing(fors, pos))
            tests = [h for h in enclosing(ifs, pos) if ".equals(" in h and mentions(h, scsv_names)]
            if tests and loop_ok and all(negated(h) for h in tests):
                return "flag %s is set true under a negated SCSV test (%s)" % (flag, tests[0].strip())
            test_ok = any(not negated(h) for h in tests)
            if not (loop_ok and test_ok):
                return "flag %s is set true outside an SCSV equals() test in a loop over %s" \
                    % (flag, "/".join(supported))
        return None

    calls = [m.start() for m in re.finditer(r"\.setEnabledCipherSuites\s*\(", body)]
    if not calls:
        return ["no SCSV: supportTlsIntolerantServer never calls setEnabledCipherSuites"]
    for pos in calls:
        conds = enclosing(ifs, pos)
        if not conds:
            fails.append("SCSV appended unconditionally: setEnabledCipherSuites is not inside an if that tests "
                         "getSupportedCipherSuites() for TLS_FALLBACK_SCSV")
            continue
        cond = conds[0].strip()
        if supported_test(cond) and negated(cond):
            fails.append("SCSV not only when supported: guard (%s) is negated" % cond)
            continue
        if supported_test(cond):
            continue
        flag = re.fullmatch(r"(\w+)", cond)
        why = flag_from_supported_loop(flag.group(1)) if flag else \
            "guard (%s) is neither a flag nor a test of getSupportedCipherSuites()" % cond
        if why:
            fails.append("SCSV not only when supported: %s" % why)
    return fails


# ---------------------------------------------------------------------------------------------------- driver

def run(root, groups=None, names=None, quiet=False):
    results = {}
    for name, group, fn in CHECKS:
        if groups and group not in groups:
            continue
        if names and name not in names:
            continue
        try:
            fails = fn(root)
        except CheckError as e:
            fails = ["ERROR %s" % e]
        results[name] = fails
        if not quiet:
            print("%s %s [%s]" % ("PASS" if not fails else "FAIL", name, group))
            for f in fails:
                print("     - %s" % f)
    return results


def selftest():
    import shutil
    import tempfile
    fx = os.path.join(HERE, "fixtures")
    good = os.path.join(fx, "good")
    ok = True
    res = run(good, quiet=True)
    bad = {k: v for k, v in res.items() if v}
    if bad or len(res) != len(CHECKS):
        print("SELFTEST FAIL fixtures/good: %s" % json.dumps(bad))
        ok = False
    else:
        print("selftest ok   fixtures/good: %d checks pass" % len(res))
    # const_value on its own (review 3, codex 5): the whole expression or an error, never a prefix's value
    for expr, lang, want in [("0x00000080L", "c", 0x80), ("(0x00000080L << 1)", "c", 0x100), ("86", "c", 86),
                             ("(0x10|0x20UL)", "c", 0x30), ("010", "c", 8), ("1 << 31", "c", 1 << 31),
                             ("0x80L", "long", 0x80), ("64", "byte", 64), ("(0x00000080L << 1", "c", None),
                             ("0x80L)", "c", None), ("0x80L 1", "c", None), ("1 <<", "c", None), ("()", "c", None),
                             ("", "c", None), ("08", "c", None), ("0x", "c", None), ("0x80Q", "c", None),
                             ("1 << 32", "c", None), ("0x100000000", "c", None), ("0x80 + 1", "c", None),
                             ("~0x80", "c", None), ("0x80U", "long", None), ("0x80L", "int", None), ("128", "byte", None),
                             ("X << 1", "c", None)]:
        suffix, bits = (C_SUFFIX, 32) if lang == "c" else JAVA_TYPES[lang]
        try:
            got = const_value(expr, suffix, bits, "selftest")
        except CheckError:
            got = None
        if got != want:
            print("SELFTEST FAIL const_value(%r, %s) = %r, want %r" % (expr, lang, got, want))
            ok = False
        else:
            print("selftest ok   const_value(%r, %s) = %r" % (expr, lang, got))
    with open(os.path.join(fx, "mutations.json"), encoding="utf-8") as f:
        mutations = json.load(f)
    seen = set()
    for mu in mutations:
        tmp = tempfile.mkdtemp(prefix="tls-selftest-")
        try:
            shutil.copytree(good, os.path.join(tmp, "t"))
            root = os.path.join(tmp, "t")
            for ed in mu["edits"]:
                p = os.path.join(root, ed["file"])
                with open(p, encoding="utf-8") as f:
                    s = f.read()
                if ed["old"] not in s:
                    print("SELFTEST FAIL %s: fixture text not found in %s: %r" % (mu["name"], ed["file"], ed["old"][:60]))
                    ok = False
                    continue
                with open(p, "w", encoding="utf-8") as f:
                    f.write(s.replace(ed["old"], ed["new"], -1 if ed.get("all") else 1))
            r = run(root, quiet=True)
            msgs = r.get(mu["check"], [])
            if mu.get("pass"):  # a control: the edit keeps the values, so the check must still pass
                if msgs:
                    print("SELFTEST FAIL %s: check %s gave %s, want a pass" % (mu["name"], mu["check"], msgs))
                    ok = False
                else:
                    print("selftest ok   %-34s -> %s: passes" % (mu["name"], mu["check"]))
            elif not any(mu["expect"] in m for m in msgs):
                print("SELFTEST FAIL %s: check %s gave %s, want a message containing %r"
                      % (mu["name"], mu["check"], msgs, mu["expect"]))
                ok = False
            else:
                seen.add(mu["check"])
                print("selftest ok   %-34s -> %s: %s" % (mu["name"], mu["check"], mu["expect"]))
        finally:
            shutil.rmtree(tmp)
    untested = [n for n, _, _ in CHECKS if n not in seen]
    if untested:
        print("SELFTEST FAIL no mutation exercises: %s" % ", ".join(untested))
        ok = False
    print("SELFTEST %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main(argv):
    args = argv[1:]
    if args == ["--selftest"]:
        return selftest()
    if args == ["--list-files"]:
        print(" ".join(FILES))
        return 0
    if args == ["--list-checks"]:
        for name, group, fn in CHECKS:
            print("%-28s %-8s %s" % (name, group, " ".join(fn.__doc__.split())))
        return 0
    if not args or args[0].startswith("-"):
        print(__doc__.strip())
        return 2
    root, groups, names = args[0], [], []
    rest = args[1:]
    while rest:
        opt = rest.pop(0)
        if opt in ("--group", "--check") and rest:
            (groups if opt == "--group" else names).append(rest.pop(0))
        else:
            print("unknown argument %s" % opt)
            return 2
    known = set(n for n, _, _ in CHECKS)
    if any(n not in known for n in names):
        print("unknown check in %s; --list-checks" % names)
        return 2
    known_groups = set(g for _, g, _ in CHECKS)
    if any(g not in known_groups for g in groups):
        print("unknown group in %s; groups: %s" % (groups, ", ".join(sorted(known_groups))))
        return 2
    if not os.path.isdir(root):
        print("no such directory: %s" % root)
        return 2
    res = run(root, groups or None, names or None)
    if not res:
        print("no check selected (--group %s --check %s)" % (groups, names))
        return 2
    nfail = sum(1 for v in res.values() if v)
    print("%d check(s), %d failed" % (len(res), nfail))
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
