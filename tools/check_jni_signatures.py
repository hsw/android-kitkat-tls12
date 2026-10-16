#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""JNI signature check of NativeCrypto: the Java `native` declarations against the registration table and the C
functions of the JNI file.

RegisterNatives fails for a method whose name or signature string is not declared in the class, and Dalvik then
aborts while loading the JNI library (at boot, for libjavacore.so on Android 4.1-4.3). A C function whose parameter
types do not match the registered signature is registered without complaint (NATIVE_METHOD casts it to void*) and
receives garbage: on 32-bit ARM a jlong takes an aligned register pair, so an `int` vs `long` slip moves every later
argument. The patches of the series add natives (and the Jelly Bean bases differ in their pointer type: 4.3 passes
long, 4.1/4.2 int), so this checks, from the sources:

  1. every NATIVE_METHOD(NativeCrypto, name, sig) of the method table names a Java native method with exactly that
     JNI signature (macros such as FILE_DESCRIPTOR and SSL_CALLBACKS expanded), and every Java native method is
     registered (an unregistered one throws UnsatisfiedLinkError on first use);
  2. every registered name has a C function NativeCrypto_<name>(JNIEnv*, jclass, ...) whose parameter and return
     types fit the signature (jlong = J, jint = I, jboolean = Z, jstring = Ljava/lang/String;, jbyteArray = [B,
     jobject = any reference, ...).

  check_jni_signatures.py ROOT              ROOT is a libcore checkout (or a directory with libcore/ in it): the 4.4
                                            layout (crypto/.../org/conscrypt) or the 4.1-4.3 one (luni/.../xnet/
                                            provider/jsse) is detected
  check_jni_signatures.py --java F --cpp F  explicit files (reference types are then resolved from the imports, the
                                            nested types, java.lang and the Java file's own directory)
  check_jni_signatures.py --selftest        built-in good and broken cases
  --allow FILE (with ROOT or --java/--cpp)  problems of the stock tree that the series does not touch, one message
                                            per line as printed after "FAIL " (# comments): reported as ALLOWED; an
                                            entry that no longer occurs fails (the list must be kept exact)

Exit 0 when all match, 1 on a mismatch, 2 on usage errors. Stdlib only; run as `python3 -I`.
"""
import os
import re
import sys

LAYOUTS = [  # (Java file, JNI file), relative to a libcore checkout
    ("crypto/src/main/java/org/conscrypt/NativeCrypto.java",
     "crypto/src/main/native/org_conscrypt_NativeCrypto.cpp"),
    ("luni/src/main/java/org/apache/harmony/xnet/provider/jsse/NativeCrypto.java",
     "luni/src/main/native/org_apache_harmony_xnet_provider_jsse_NativeCrypto.cpp"),
]
PRIM = {"void": "V", "boolean": "Z", "byte": "B", "char": "C", "short": "S", "int": "I", "long": "J",
        "float": "F", "double": "D"}
JAVA_LANG = {"Object", "String", "Class", "Throwable", "Exception", "RuntimeException", "Integer", "Long", "Boolean",
             "Byte", "Character", "Short", "Float", "Double", "Number", "CharSequence", "StringBuilder", "Runnable",
             "Thread", "Void", "Error"}
C_TYPES = {"void": "V", "jboolean": "Z", "jbyte": "B", "jchar": "C", "jshort": "S", "jint": "I", "jlong": "J",
           "jfloat": "F", "jdouble": "D", "jstring": "Ljava/lang/String;", "jclass": "Ljava/lang/Class;",
           "jthrowable": "L*", "jobject": "*", "jobjectArray": "[*", "jbooleanArray": "[Z", "jbyteArray": "[B",
           "jcharArray": "[C", "jshortArray": "[S", "jintArray": "[I", "jlongArray": "[J", "jfloatArray": "[F",
           "jdoubleArray": "[D", "jarray": "[*", "int": "I"}


def strip_comments(text):
    """Remove // and /* */ comments, keep string and char literals (replaced by nothing else)."""
    out = []
    i, n = 0, len(text)
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
            out.append(" ")
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


class Java:
    def __init__(self, text, own_dir=None):
        self.text = strip_comments(text)
        m = re.search(r"^\s*package\s+([\w.]+)\s*;", self.text, re.M)
        self.package = m.group(1) if m else ""
        self.imports = {}
        for m in re.finditer(r"^\s*import\s+([\w.]+)\s*;", self.text, re.M):
            self.imports[m.group(1).rsplit(".", 1)[1]] = m.group(1)
        m = re.search(r"\b(?:class|interface)\s+(\w+)", self.text)
        self.cls = m.group(1) if m else "NativeCrypto"
        self.nested = set(re.findall(r"\b(?:class|interface|enum)\s+(\w+)", self.text)) - {self.cls}
        self.own_dir = own_dir

    def binary_name(self, t):
        """JNI descriptor of the Java type t (no generics in native signatures)."""
        t = re.sub(r"<.*>", "", t).strip()
        dims = 0
        while t.endswith("[]"):
            dims += 1
            t = t[:-2].strip()
        if t.endswith("..."):
            dims += 1
            t = t[:-3].strip()
        if t in PRIM:
            d = PRIM[t]
        elif "." in t and t.split(".")[0][:1].islower():
            parts = t.split(".")
            pkg = [p for p in parts if p[:1].islower()]
            cls = [p for p in parts if not p[:1].islower()]
            d = "L%s/%s;" % ("/".join(pkg), "$".join(cls))
        else:
            first, _, rest = t.partition(".")
            tail = ("$" + rest.replace(".", "$")) if rest else ""
            if first in self.nested:
                d = "L%s/%s$%s%s;" % (self.package.replace(".", "/"), self.cls, first, tail)
            elif first in self.imports:
                d = "L%s%s;" % (self.imports[first].replace(".", "/"), tail)
            elif first in JAVA_LANG:
                d = "Ljava/lang/%s%s;" % (first, tail)
            elif self.own_dir and os.path.exists(os.path.join(self.own_dir, first + ".java")):
                d = "L%s/%s%s;" % (self.package.replace(".", "/"), first, tail)
            else:
                raise ValueError("cannot resolve Java type %r" % t)
        return "[" * dims + d

    def natives(self):
        """{name: [signature, ...]} of the native methods."""
        out = {}
        rx = re.compile(r"((?:\b(?:public|private|protected|static|final|synchronized)\s+)*)\bnative\s+"
                        r"((?:\b(?:public|private|protected|static|final|synchronized)\s+)*)"
                        r"([\w.<>?,\s\[\]]+?)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+)?;")
        for m in rx.finditer(self.text):
            ret, name, params = m.group(3), m.group(4), m.group(5).strip()
            sig = "("
            if params:
                for p in split_params(params):
                    p = re.sub(r"\b(final|@\w+)\s+", "", p).strip()
                    pm = re.match(r"(.+?)\s*\b(\w+)\s*((?:\[\s*\])*)$", p)
                    if not pm:
                        raise ValueError("%s: cannot parse parameter %r" % (name, p))
                    sig += self.binary_name(pm.group(1) + pm.group(3).replace(" ", ""))
            sig += ")" + self.binary_name(ret)
            out.setdefault(name, []).append(sig)
        return out


def split_params(s):
    out, depth, cur = [], 0, ""
    for c in s:
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        if c == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += c
    out.append(cur)
    return [p for p in out if p.strip()]


def c_string(expr, macros, what):
    """Value of a concatenation of string literals, string macros and TO_STRING(MACRO) (the 4.4 JNI_JARJAR_PREFIX
    idiom: the stringified value of MACRO, "" for an empty or undefined one); outer parentheses are dropped."""
    out = ""
    toks = re.findall(r'"(?:[^"\\]|\\.)*"|\w+|\S', expr)
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok.startswith('"'):
            out += tok[1:-1]
        elif tok in ("(", ")"):
            pass
        elif tok == "TO_STRING" and toks[i + 1:i + 2] == ["("] and toks[i + 3:i + 4] == [")"]:
            out += macros.get(toks[i + 2], "").strip()
            i += 3
        elif tok in macros:
            out += c_string(macros[tok], macros, what)
        else:
            raise ValueError("%s: cannot evaluate %r in %r" % (what, tok, expr))
        i += 1
    return out


def balanced_args(t, start):
    """Top-level comma-separated arguments of the call whose '(' is at t[start]; (args, end index)."""
    depth, cur, args, i = 0, "", [], start
    while i < len(t):
        c = t[i]
        if c == '"':
            j = i + 1
            while t[j] != '"':
                j += 2 if t[j] == "\\" else 1
            cur += t[i:j + 1]
            i = j + 1
            continue
        if c == "(":
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif c == ")":
            depth -= 1
            if depth == 0:
                args.append(cur.strip())
                return args, i
        if c == "," and depth == 1:
            args.append(cur.strip())
            cur = ""
        else:
            cur += c
        i += 1
    raise ValueError("unbalanced parentheses at offset %d" % start)


def c_table(text):
    """[(name, signature, line)] of NATIVE_METHOD(NativeCrypto, ...) rows; macro values expanded."""
    t = strip_comments(text)
    macros = {}
    for m in re.finditer(r"^[ \t]*#[ \t]*define[ \t]+(\w+)(?:[ \t]+(.*?))?[ \t]*$", t, re.M):
        macros.setdefault(m.group(1), m.group(2) or "")
    rows = []
    for m in re.finditer(r"\bNATIVE_METHOD\s*\(", t):
        line = t.count("\n", 0, m.start()) + 1
        if re.match(r"\s*#\s*define", t[t.rfind("\n", 0, m.start()) + 1:]):
            continue
        args, _ = balanced_args(t, m.end() - 1)
        if len(args) != 3 or args[0] != "NativeCrypto":
            continue
        rows.append((args[1], c_string(args[2], macros, "line %d" % line), line))
    return rows


def c_functions(text):
    """{name: (return type, [parameter types after JNIEnv*, jclass])} of static NativeCrypto_<name>(...) definitions."""
    t = strip_comments(text)
    out = {}
    for m in re.finditer(r"^\s*static\s+([\w*\s]+?)\s*\bNativeCrypto_(\w+)\s*\(([^)]*)\)\s*\{", t, re.M):
        params = [p.strip() for p in m.group(3).split(",") if p.strip()]
        types = []
        for p in params:
            p = re.sub(r"\bconst\b", "", p).strip()
            tm = re.match(r"(\w+\s*\**)", p)
            types.append(tm.group(1).replace(" ", "") if tm else p)
        out.setdefault(m.group(2), []).append((m.group(1).strip(), types))
    return out


def sig_parts(sig):
    m = re.match(r"\((.*)\)(.+)$", sig)
    if not m:
        raise ValueError("bad signature %r" % sig)
    args = re.findall(r"\[*(?:[ZBCSIJFD]|L[^;]+;)", m.group(1))
    if "".join(args) != m.group(1):
        raise ValueError("bad signature %r" % sig)
    return args, m.group(2)


def c_fits(ctype, desc):
    if ctype.endswith("*"):
        return desc == "I"  # Android 4.1/4.2 handles: a 32-bit pointer passed as Java int
    want = C_TYPES.get(ctype)
    if want is None:
        return False
    if want == "*":
        return desc.startswith("L") or desc.startswith("[")
    if want == "L*":
        return desc.startswith("L")
    if want == "[*":
        return desc.startswith("[") and (desc[1:2] in ("L", "["))
    return want == desc


def check(java_text, cpp_text, own_dir=None):
    fails = []
    try:
        natives = Java(java_text, own_dir).natives()
    except ValueError as e:
        return ["Java: %s" % e]
    try:
        table = c_table(cpp_text)
    except ValueError as e:
        return ["JNI table: %s" % e]
    funcs = c_functions(cpp_text)
    if not natives:
        fails.append("no native methods found in the Java file")
    if not table:
        fails.append("no NATIVE_METHOD(NativeCrypto, ...) rows found in the JNI file")
    registered = {}
    for name, sig, line in table:
        if sig in registered.get(name, []):
            fails.append("%s %s registered twice" % (name, sig))
        registered.setdefault(name, []).append(sig)
        if name not in natives:
            fails.append("%s %s is registered but NativeCrypto.java declares no native %s" % (name, sig, name))
        elif sig not in natives[name]:
            fails.append("%s registered as %s, Java declares %s" % (name, sig, " or ".join(natives[name])))
        try:
            args, ret = sig_parts(sig)
        except ValueError as e:
            fails.append("%s: %s" % (name, e))
            continue
        defs = funcs.get(name)
        if not defs:
            fails.append("no C definition static ... NativeCrypto_%s(JNIEnv*, jclass, ...)" % name)
            continue
        ok = False
        why = ""
        for cret, ctypes in defs:
            if len(ctypes) < 2 or not ctypes[0].startswith("JNIEnv") or ctypes[1] not in ("jclass", "jobject"):
                why = "C parameters do not start with (JNIEnv*, jclass)"
                continue
            rest = ctypes[2:]
            if len(rest) != len(args):
                why = "C function takes %d arguments, signature %s has %d" % (len(rest), sig, len(args))
                continue
            bad = ["argument %d: C %s vs %s" % (i + 1, c, a) for i, (c, a) in enumerate(zip(rest, args))
                   if not c_fits(c, a)]
            if not c_fits(cret, ret):
                bad.append("return: C %s vs %s" % (cret, ret))
            if bad:
                why = "; ".join(bad)
                continue
            ok = True
        if not ok:
            fails.append("NativeCrypto_%s does not fit %s: %s" % (name, sig, why))
    for name, sigs in sorted(natives.items()):
        for sig in sigs:
            if sig not in registered.get(name, []):
                fails.append("Java native %s %s is not registered in the JNI table" % (name, sig))
    return fails


def find_files(root):
    for base in (root, os.path.join(root, "libcore")):
        for j, c in LAYOUTS:
            if os.path.exists(os.path.join(base, j)) and os.path.exists(os.path.join(base, c)):
                return os.path.join(base, j), os.path.join(base, c)
    return None


GOOD_JAVA = """package a.b;
import java.io.FileDescriptor;
import java.net.SocketTimeoutException;
public final class NativeCrypto {
    public static native long SSL_new(long ctx) throws SSLException;
    // public static native int commented_out(int x);
    public static native int SSL_do(long ssl, FileDescriptor fd, SSLHandshakeCallbacks shc, int timeout,
            boolean client, byte[] npn, String[] names) throws SocketTimeoutException;
    private static native void clinit();
    public static native byte[][] get_chain(long ssl);
    public static native long[] SSL_get_ciphers(long ssl);
    public interface SSLHandshakeCallbacks { void x(); }
}
"""
GOOD_CPP = """#define FILE_DESCRIPTOR "Ljava/io/FileDescriptor;"
#define SSL_CALLBACKS "La/b/NativeCrypto$SSLHandshakeCallbacks;"
static jlong NativeCrypto_SSL_new(JNIEnv* env, jclass, jlong ctx) { return 0; }
static jint NativeCrypto_SSL_do(JNIEnv* env, jclass, jlong ssl, jobject fd, jobject shc, jint t,
        jboolean c, jbyteArray npn, jobjectArray names) { return 0; }
static void NativeCrypto_clinit(JNIEnv*, jclass) {}
static jobjectArray NativeCrypto_get_chain(JNIEnv* env, jclass, jlong ssl) { return NULL; }
static jlongArray NativeCrypto_SSL_get_ciphers(JNIEnv* env, jclass, jlong ssl) { return NULL; }
static JNINativeMethod sNativeCryptoMethods[] = {
    NATIVE_METHOD(NativeCrypto, SSL_new, "(J)J"),
    NATIVE_METHOD(NativeCrypto, SSL_do, "(J" FILE_DESCRIPTOR SSL_CALLBACKS "IZ[B[Ljava/lang/String;)I"),
    NATIVE_METHOD(NativeCrypto, clinit, "()V"),
    NATIVE_METHOD(NativeCrypto, get_chain, "(J)[[B"),
    NATIVE_METHOD(NativeCrypto, SSL_get_ciphers, "(J)[J"),
};
"""
MUTATIONS = [  # (description, file, old, new, expected message part)
    ("Java int vs registered J", "java", "long SSL_new(long ctx)", "long SSL_new(int ctx)", "registered as (J)J"),
    ("C jint for a J argument", "cpp", "NativeCrypto_SSL_new(JNIEnv* env, jclass, jlong ctx)",
     "NativeCrypto_SSL_new(JNIEnv* env, jclass, jint ctx)", "argument 1: C jint vs J"),
    ("unregistered Java native", "cpp", '    NATIVE_METHOD(NativeCrypto, SSL_get_ciphers, "(J)[J"),\n', "",
     "SSL_get_ciphers (J)[J is not registered"),
    ("registered without Java native", "java", "public static native long[] SSL_get_ciphers(long ssl);", "",
     "declares no native SSL_get_ciphers"),
    ("macro value wrong", "cpp", 'a/b/NativeCrypto$SSLHandshakeCallbacks', 'a/b/NativeCrypto$Other',
     "SSL_do registered as"),
    ("C argument count", "cpp", "jboolean c, jbyteArray npn, jobjectArray names)", "jboolean c, jbyteArray npn)",
     "takes 6 arguments"),
    ("C return type", "cpp", "static jlongArray NativeCrypto_SSL_get_ciphers", "static jintArray NativeCrypto_SSL_get_ciphers",
     "return: C jintArray vs [J"),
    ("missing C function", "cpp", "static void NativeCrypto_clinit(JNIEnv*, jclass) {}", "", "no C definition"),
    ("duplicate row", "cpp", '    NATIVE_METHOD(NativeCrypto, clinit, "()V"),\n',
     '    NATIVE_METHOD(NativeCrypto, clinit, "()V"),\n    NATIVE_METHOD(NativeCrypto, clinit, "()V"),\n',
     "registered twice"),
    ("unknown type", "java", "SSLHandshakeCallbacks shc", "Unknown shc", "cannot resolve Java type 'Unknown'"),
]


def selftest():
    bad = 0
    f = check(GOOD_JAVA, GOOD_CPP)
    if f:
        bad += 1
        print("FAIL good case: %s" % f)
    for desc, which, old, new, want in MUTATIONS:
        j, c = GOOD_JAVA, GOOD_CPP
        src = j if which == "java" else c
        if src.count(old) != 1:
            bad += 1
            print("FAIL %s: mutation anchor not unique" % desc)
            continue
        src = src.replace(old, new)
        f = check(src, c) if which == "java" else check(j, src)
        if not any(want in x for x in f):
            bad += 1
            print("FAIL %s: want %r in %s" % (desc, want, f))
    print("selftest: %d cases, %d failed" % (len(MUTATIONS) + 1, bad))
    return 1 if bad else 0


def read_allow(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.split("#", 1)[0].strip() if ln.lstrip().startswith("#") else ln.rstrip("\n").strip()
            if ln:
                out.append(ln)
    return out


def main(argv):
    args = argv[1:]
    if args == ["--selftest"]:
        return selftest()
    allow = None
    if len(args) >= 2 and args[-2] == "--allow":
        allow = read_allow(args[-1])
        args = args[:-2]
    if len(args) == 4 and args[0] == "--java" and args[2] == "--cpp":
        jf, cf = args[1], args[3]
    elif len(args) == 1 and not args[0].startswith("-"):
        found = find_files(args[0])
        if not found:
            sys.stderr.write("check_jni_signatures: no NativeCrypto.java + JNI file under %s\n" % args[0])
            return 2
        jf, cf = found
    else:
        sys.stderr.write(__doc__)
        return 2
    with open(jf, encoding="utf-8") as f:
        jt = f.read()
    with open(cf, encoding="utf-8") as f:
        ct = f.read()
    found = check(jt, ct, os.path.dirname(jf))
    allowed = [x for x in found if allow is not None and x in allow]
    fails = [x for x in found if x not in allowed]
    for x in allowed:
        print("ALLOWED %s" % x)
    for x in fails:
        print("FAIL %s" % x)
    for x in allow or []:
        if x not in found:
            print("FAIL stale allow entry (no longer occurs): %s" % x)
            fails.append(x)
    if fails:
        print("check_jni_signatures: %d problem(s) in %s vs %s" % (len(fails), jf, cf))
        return 1
    try:
        n = sum(len(v) for v in Java(jt, os.path.dirname(jf)).natives().values())
    except ValueError:
        n = "?"
    print("check_jni_signatures: PASS, %s native methods, %d table rows, signatures and C types match (%d allowed "
          "stock problems) (%s)" % (n, len(c_table(ct)), len(allowed), os.path.basename(cf)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
