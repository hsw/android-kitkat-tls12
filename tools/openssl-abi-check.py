#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ABI/compatibility checker for replacing the system libssl/libcrypto (OpenSSL 1.0.1e -> 1.0.1u).

The prebuilt users of /system/lib/libssl.so and libcrypto.so (Widevine, rtl_supplicant, libffmpeg, ...) were linked
against the old libraries and cannot be rebuilt. This tool answers three questions, each as its own subcommand, and
exits 1 when a question has a failing answer:

  symbols  Does every dynamic symbol that the old libssl.so/libcrypto.so export still exist in the new ones, and in the
           same library? A removed symbol whose name appears in the old public headers (include/openssl; --old-headers
           must be a readable directory with at least one .h file) fails; a removed internal symbol (ssl3_*, ssl2_*,
           ...) is only listed, because `users` decides whether anybody imports it. An exported data object whose size
           changed fails (copy relocations).
  users    Does every ELF file under the scanned roots that has NEEDED libssl.so or libcrypto.so find each symbol it
           imports from them (old exports) in the same library of the new pair, with the same symbol type (function vs
           data object)? A user of either library is checked against both (libssl.so NEEDs libcrypto.so; review 3,
           codex 3). Missing strong imports fail, missing weak ones are listed. ELF files inside APK/JAR/ZIP archives
           (lib/<abi>/*.so) are checked too and named ARCHIVE!MEMBER. A user without a copy under --symbols-root is
           marked "prebuilt", an archive member "apk". A --scan root (or --symbols-root) that is not a readable
           directory stops the run, as does a file, an archive or an archive member under it that cannot be read (or
           an .apk/.jar/.zip that is not a zip), and a --scan root without any libssl/libcrypto user fails. Imports are
           the undefined dynamic symbols plus the targets of copy relocations (R_ARM_COPY: a non-PIC executable's own
           .bss copy of a library data object, which readelf lists as defined).
  structs  Do the public structures keep their layout? Compares sizes and member offsets read from two probe objects
           (`probe-source` emits the probe; openssl-abi-check.sh compiles it with the tree's ARM compiler against the old
           and the new headers). A changed size of a type that callers allocate themselves (by value or as their own
           static method tables) fails, as does a moved member that callers may read directly (wpa_supplicant reads
           ssl->s3->client_random and ssl->session->master_key, for example). A grown library-allocated struct, or a
           moved member that only libssl itself uses (the Android channelid/alpn/tls12_digests fields), is listed.

  openssl-abi-check.py symbols --old DIR --new DIR [--old-headers DIR] [--allow FILE]
  openssl-abi-check.py users   --old DIR --new DIR --scan ROOT [--scan ROOT ...] [--symbols-root DIR]
  openssl-abi-check.py probe-source
  openssl-abi-check.py structs --old OLD.o --new NEW.o [--allow FILE]
  openssl-abi-check.py --selftest

DIR holds libssl.so and libcrypto.so; one without any exported dynamic symbol (no .dynsym, or readelf text with an entry
line that is not parsed or fewer entries than its table header declares) stops the run. --allow FILE lists justified exceptions, one per line, NAME an fnmatch pattern
(list exact names where you can; a glob also covers names nobody has looked at):
"symbol<TAB>NAME<TAB>reason" (removed public symbol), "objsize<TAB>NAME<TAB>reason" (exported data object whose size
changed) or "struct<TAB>TYPE[.member]<TAB>reason" (size or offset change; # starts a comment). `users` has no allow
list: a user that imports a removed symbol, a data object whose size changed or a symbol whose type changed always
fails. --readelf PATH (or $READELF)
selects readelf; GNU readelf reads ARM objects on any host (macOS: brew binutils' greadelf). Stdlib only, `python3 -I`.
"""
import argparse
import contextlib
import fnmatch
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
import zlib

LIBS = ("libssl.so", "libcrypto.so")

# ---------------------------------------------------------------------------------------------------------------------
# readelf parsing (pure functions on readelf's text, so --selftest can feed synthetic output)

_SYM_RE = re.compile(r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+|0x[0-9a-fA-F]+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)(?:\s+\[[^\]]*\])?\s*$")


def parse_symbols(text):
    """readelf -W --dyn-syms / -s text -> list of dicts (name, size, type, bind, ndx)."""
    out = []
    for line in text.splitlines():
        m = _SYM_RE.match(line)
        if not m:
            continue
        _value, size, typ, bind, _vis, ndx, name = m.groups()
        name = name.split("@")[0]
        if not name:
            continue
        out.append({"name": name, "size": int(size, 0), "type": typ, "bind": bind, "ndx": ndx})
    return out


_ENTRY_RE = re.compile(r"^\s*\d+:\s")
_NONAME_RE = re.compile(r"^\s*\d+:\s+[0-9a-fA-F]+\s+(\d+|0x[0-9a-fA-F]+)\s+\w+\s+\w+\s+\w+\s+\w+\s*$")  # entry 0
_TABLE_RE = re.compile(r"^Symbol table '([^']*)' contains (\d+) entr(?:y|ies)")


def symbol_text_problems(text):
    """Reasons why readelf symbol text was not read completely: an entry line that _SYM_RE does not parse, or a table
    whose entry count differs from its header (review 3, codex 4: dropped entries of the old libraries' tables went
    unchecked). Empty for a fully parsed text."""
    problems, declared, entries = [], 0, 0
    for line in text.splitlines():
        m = _TABLE_RE.match(line)
        if m:
            declared += int(m.group(2))
        elif _ENTRY_RE.match(line):
            entries += 1
            if not _SYM_RE.match(line) and not _NONAME_RE.match(line):
                problems.append("entry line not parsed: %r" % line.strip())
    if declared != entries:
        problems.append("%d entries declared by the table header(s), %d entry lines" % (declared, entries))
    return problems


def defined_exports(syms):
    """Defined, globally visible functions and data objects: name -> (type, size)."""
    res = {}
    for s in syms:
        if s["ndx"] == "UND" or s["bind"] not in ("GLOBAL", "WEAK"):
            continue
        if s["type"] not in ("FUNC", "OBJECT", "IFUNC", "TLS"):
            continue
        res[s["name"]] = (s["type"], s["size"])
    return res


def undefined_imports(syms, copied=()):
    """Imported symbols: name -> bind (GLOBAL or WEAK). Undefined symbols, plus the targets of copy relocations
    (copied: names from parse_copy_relocs): a non-PIC executable that reads a library's data object gets its own copy
    in .bss, and readelf lists that symbol as defined (Ndx = the .bss section), although the dynamic linker fills it
    from the library with the library's size."""
    copied = set(copied)
    return {s["name"]: s["bind"] for s in syms if s["bind"] in ("GLOBAL", "WEAK") and
            (s["ndx"] == "UND" or s["name"] in copied)}


_COPY_RE = re.compile(r"^\s*[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+R_\w+_COPY\s+[0-9a-fA-F]+\s+(\S+)")


def parse_copy_relocs(text):
    """readelf -W -r text -> names of the symbols of copy relocations (R_ARM_COPY and the other R_*_COPY)."""
    res = set()
    for line in text.splitlines():
        m = _COPY_RE.match(line)
        if m:
            res.add(m.group(1).split("@")[0])
    return res


def parse_needed(text):
    return re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", text)


class Readelf:
    def __init__(self, path):
        self.path = path or os.environ.get("READELF") or "readelf"

    def run(self, args, f):
        r = subprocess.run([self.path] + args + [f], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            raise RuntimeError("%s %s %s failed: %s" % (self.path, " ".join(args), f, r.stderr.decode(errors="replace")))
        return r.stdout.decode("utf-8", errors="replace")

    def dynsyms(self, f):
        """The dynamic symbols of f. An entry readelf printed that parse_symbols cannot read stops the run: a dropped
        import or export would go unchecked."""
        text = self.run(["-W", "--dyn-syms"], f)
        problems = symbol_text_problems(text)
        if problems:
            raise SystemExit("%s --dyn-syms %s: %s" % (self.path, f, "; ".join(problems[:3])))
        return parse_symbols(text)

    def syms(self, f):
        return parse_symbols(self.run(["-W", "-s"], f))

    def needed(self, f):
        return parse_needed(self.run(["-W", "-d"], f))

    def copy_relocs(self, f):
        return parse_copy_relocs(self.run(["-W", "-r"], f))


def load_allow(path):
    allow = {"symbol": {}, "objsize": {}, "struct": {}}
    if not path:
        return allow
    with open(path) as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3 or parts[0] not in allow or not parts[2].strip():
                raise SystemExit("%s:%d: want 'symbol|objsize|struct<TAB>name<TAB>reason'" % (path, n))
            allow[parts[0]][parts[1]] = parts[2].strip()
    return allow


def allowed(allow, kind, name):
    """Reason of the first allow entry of this kind whose name (an fnmatch pattern) matches, else None."""
    for pat, reason in allow[kind].items():
        if fnmatch.fnmatchcase(name, pat):
            return reason
    return None


def strip_c_comments(text):
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", " ", text, flags=re.S))


def _walk_error(err):
    """os.walk onerror: an unreadable directory stops the run instead of being skipped (os.walk's default)."""
    raise SystemExit("cannot read %s: %s" % (err.filename, err.strerror or err))


def header_identifiers(hdir):
    """Identifiers used in the code (not the comments) of the public headers. A missing or unreadable directory, or one
    without any .h file, stops the run: an empty set would turn every removed public symbol into an internal one."""
    if not os.path.isdir(hdir):
        raise SystemExit("--old-headers %s is not a directory" % hdir)
    ids, n = set(), 0
    for root, _dirs, files in os.walk(hdir, onerror=_walk_error):
        for f in files:
            if f.endswith(".h"):
                n += 1
                with open(os.path.join(root, f), encoding="latin-1") as fh:
                    ids.update(re.findall(r"\b[A-Za-z_]\w*\b", strip_c_comments(fh.read())))
    if not n:
        raise SystemExit("--old-headers %s holds no .h file" % hdir)
    return ids


# ---------------------------------------------------------------------------------------------------------------------
# symbols


def compare_symbols(old, new, public_ids, allow):
    """old/new: {lib: {name: (type, size)}}. Returns (failures, notes)."""
    fails, notes = [], []
    new_all = {}
    for lib in LIBS:
        for name in new.get(lib, {}):
            new_all.setdefault(name, lib)
    for lib in LIBS:
        o, n = old.get(lib, {}), new.get(lib, {})
        removed = sorted(set(o) - set(n))
        added = sorted(set(n) - set(o))
        for name in removed:
            where = new_all.get(name)
            msg = "%s: %s removed" % (lib, name) + (" (now in %s)" % where if where else "")
            why = allowed(allow, "symbol", name)
            if why:
                notes.append("allowed  " + msg + ": " + why)
            elif public_ids is not None and name in public_ids:
                fails.append("public   " + msg)
            elif public_ids is None:
                fails.append("removed  " + msg)
            else:
                notes.append("internal " + msg)
        for name in sorted(set(o) & set(n)):
            (ot, osz), (nt, nsz) = o[name], n[name]
            if ot == "OBJECT" and nt == "OBJECT" and osz != nsz:
                msg = "%s: data object %s size %d -> %d" % (lib, name, osz, nsz)
                why = allowed(allow, "objsize", name)
                (notes.append("allowed  " + msg + ": " + why) if why else fails.append(msg))
            elif ot != nt:
                fails.append("%s: %s type %s -> %s" % (lib, name, ot, nt))
        notes.append("%s: %d exported before, %d after, %d removed, %d added" % (lib, len(o), len(n), len(removed),
                                                                                  len(added)))
    return fails, notes


def load_pair(re_, d):
    """{lib: exports} of DIR's libssl.so and libcrypto.so. A library without any exported dynamic symbol stops the run
    (no .dynsym, not the library, or readelf output that was not parsed): an empty old map would let `symbols` find
    nothing removed and `users` find no OpenSSL import (review 3, codex 4)."""
    res = {}
    for lib in LIBS:
        p = os.path.join(d, lib)
        if not os.path.isfile(p):
            raise SystemExit("missing %s" % p)
        res[lib] = defined_exports(re_.dynsyms(p))
        if not res[lib]:
            raise SystemExit("%s: no exported dynamic symbol (no .dynsym, not the OpenSSL library, or readelf output "
                             "that was not parsed)" % p)
    return res


def cmd_symbols(a):
    re_ = Readelf(a.readelf)
    allow = load_allow(a.allow)
    old, new = load_pair(re_, a.old), load_pair(re_, a.new)
    ids = header_identifiers(a.old_headers) if a.old_headers else None
    fails, notes = compare_symbols(old, new, ids, allow)
    return report("symbols", fails, notes)


# ---------------------------------------------------------------------------------------------------------------------
# users


def check_user(needed, imports, old, new):
    """needed: NEEDED list; imports: {name: bind}; old/new: {lib: {name: (type, size)}}.
    Returns (n_imports, failures, missing_weak). A user that NEEDs libssl.so or libcrypto.so is checked against BOTH
    (review 3, codex 3: a user of libssl.so alone has libcrypto.so in its load closure, since libssl.so NEEDs it, and
    its libcrypto imports were skipped). A symbol is an OpenSSL import if the old pair exported it; it must still come
    from the library that exported it, and an imported data object must keep its size (a prebuilt executable gets a
    copy relocation of the old size) and every import its symbol type (a data object that became a function, or the
    reverse, is a different thing to the importer). This is conservative: the 4.4 linker resolves an import only in
    the executable, LD_PRELOAD and the importer's own DT_NEEDED (bionic linker.cpp soinfo_do_lookup), so checking
    the second library can only add failures. Files that reach OpenSSL only through a third library are not users:
    their own imports never resolve there. The allow list does not apply here: an importer of a removed symbol is a
    real break."""
    libs = list(LIBS) if any(l in needed for l in LIBS) else []
    n, strong, weak = 0, [], []
    for name, bind in sorted(imports.items()):
        src = [l for l in libs if name in old.get(l, {})]
        if not src:
            continue
        n += 1
        now = [l for l in src if name in new.get(l, {})]
        if now:
            (ot, osz), (nt, nsz) = old[now[0]][name], new[now[0]][name]
            if ot != nt:
                strong.append("%s (%s): type %s -> %s" % (name, now[0], ot, nt))
            elif ot == "OBJECT" and osz != nsz:
                strong.append("%s (%s): data object size %d -> %d (copy relocation)" % (name, now[0], osz, nsz))
            continue
        (weak if bind == "WEAK" else strong).append("%s (%s)" % (name, src[0]))
    return n, strong, weak


def is_elf(p):
    """True for an ELF file. A file that cannot be read stops the run: it may be an OpenSSL user nobody checked."""
    try:
        with open(p, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError as e:
        raise SystemExit("cannot read %s: %s" % (p, e.strerror or e))


ARCHIVE_SUFFIXES = (".apk", ".jar", ".zip")


def archive_elf_members(path):
    """Names of the ELF members of a zip archive (an APK's lib/<abi>/*.so). An archive that cannot be read, is not a
    zip or has a member that cannot be read stops the run: its libraries may be OpenSSL users nobody checked."""
    try:
        with zipfile.ZipFile(path) as z:
            res = []
            for info in z.infolist():
                if info.is_dir() or not info.filename.endswith(".so"):
                    continue
                with z.open(info) as fh:
                    if fh.read(4) == b"\x7fELF":
                        res.append(info.filename)
            return sorted(res)
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, zlib.error) as e:
        raise SystemExit("cannot read archive %s: %s" % (path, getattr(e, "strerror", None) or e))


def extract_member(path, member, out):
    """Copy one archive member to out; a read error (bad CRC, truncated data) stops the run like archive_elf_members."""
    try:
        with zipfile.ZipFile(path) as z, z.open(member) as src, open(out, "wb") as dst:
            shutil.copyfileobj(src, dst)
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, zlib.error) as e:
        raise SystemExit("cannot read %s!%s: %s" % (path, member, getattr(e, "strerror", None) or e))


def scan_users(root, tmpdir):
    """Yield (display name, path of an ELF file on disk, origin) for every ELF file under root, plain files first by
    path, archive members extracted into tmpdir. origin: "file" or "archive". A missing root, an unreadable directory
    (os.walk would skip it silently), an unreadable file or an unreadable archive stops the run."""
    if not os.path.isdir(root):
        raise SystemExit("--scan %s is not a directory" % root)
    for dirpath, dirs, files in os.walk(root, onerror=_walk_error):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(dirpath, f)
            if os.path.islink(p):
                continue
            rel = os.path.relpath(p, root)
            if is_elf(p):
                yield rel, p, "file"
            elif f.lower().endswith(ARCHIVE_SUFFIXES):
                members = archive_elf_members(p)
                for i, m in enumerate(members):
                    out = os.path.join(tmpdir, "%d-%s" % (i, os.path.basename(m)))
                    extract_member(p, m, out)
                    yield "%s!%s" % (rel, m), out, "archive"


def cmd_users(a, re_=None):
    re_ = re_ or Readelf(a.readelf)
    if a.symbols_root and not os.path.isdir(a.symbols_root):
        raise SystemExit("--symbols-root %s is not a directory" % a.symbols_root)
    old, new = load_pair(re_, a.old), load_pair(re_, a.new)
    fails, notes, n_users, n_archive = [], [], 0, 0
    for root in a.scan:
        n_root = 0
        with tempfile.TemporaryDirectory(prefix="abi-users-") as tmp:
            for rel, p, origin in scan_users(root, tmp):
                needed = re_.needed(p)
                if not any(l in needed for l in LIBS):
                    continue
                n_users += 1
                n_root += 1
                mark = ""
                if origin == "archive":
                    n_archive += 1
                    mark = " [apk]"
                elif a.symbols_root:
                    mark = "" if os.path.exists(os.path.join(a.symbols_root, rel)) else " [prebuilt]"
                n, strong, weak = check_user(needed, undefined_imports(re_.dynsyms(p), re_.copy_relocs(p)), old, new)
                line = "%s%s: NEEDED %s, %d OpenSSL imports" % (rel, mark, "+".join(l for l in LIBS if l in needed), n)
                if strong:
                    fails.append(line + ", MISSING: " + ", ".join(strong))
                else:
                    notes.append(line + (", missing weak: " + ", ".join(weak) if weak else ", all resolve"))
        if not n_root:
            fails.append("%s: no ELF file with NEEDED libssl.so or libcrypto.so (wrong --scan root?)" % root)
    notes.append("%d users of libssl/libcrypto under %s (%d inside APK/JAR/ZIP archives)" % (n_users, ", ".join(a.scan),
                                                                                         n_archive))
    return report("users", fails, notes)


# ---------------------------------------------------------------------------------------------------------------------
# structs
#
# (type, kind, members). kind "byval": callers allocate it themselves (stack/static/embedded) or define their own
# instances (method tables), so its size must not change. kind "lib": allocated by the library; its size may grow, but
# the listed members must not move. Members prefixed with "~" are only used inside libssl (Android patch fields); a
# move is listed, not failed.
STRUCTS = [
    ("SSL", "lib", ["version", "type", "method", "rbio", "wbio", "bbio", "rwstate", "in_handshake", "handshake_func",
                    "server", "new_session", "quiet_shutdown", "shutdown", "state", "rstate", "init_buf", "init_msg",
                    "init_num", "init_off", "packet", "packet_length", "s2", "s3", "d1", "read_ahead", "msg_callback",
                    "msg_callback_arg", "hit", "param", "cipher_list", "cipher_list_by_id", "mac_flags",
                    "enc_read_ctx", "read_hash", "expand", "enc_write_ctx", "write_hash", "compress", "cert",
                    "sid_ctx_length", "sid_ctx", "session", "~session_creation_enabled", "generate_session_id",
                    "verify_mode", "verify_callback", "info_callback", "error", "error_code", "ctx", "debug",
                    "verify_result", "ex_data", "client_CA", "references", "options", "mode", "max_cert_list",
                    "first_packet", "client_version", "max_send_fragment", "tlsext_debug_cb", "tlsext_debug_arg",
                    "tlsext_hostname", "servername_done", "tlsext_status_type", "tlsext_status_expected",
                    "tlsext_ocsp_ids", "tlsext_ocsp_exts", "tlsext_ocsp_resp", "tlsext_ocsp_resplen",
                    "tlsext_ticket_expected", "tlsext_session_ticket", "tls_session_ticket_ext_cb",
                    "tls_session_ticket_ext_cb_arg", "tls_session_secret_cb", "tls_session_secret_cb_arg",
                    "initial_ctx", "~tlsext_channel_id_enabled", "~tlsext_channel_id_private",
                    "~alpn_client_proto_list", "renegotiate"]),
    ("SSL3_STATE", "lib", ["flags", "delay_buf_pop_ret", "read_sequence", "read_mac_secret_size", "read_mac_secret",
                           "write_sequence", "write_mac_secret_size", "write_mac_secret", "server_random",
                           "client_random", "need_empty_fragments", "empty_fragment_done", "init_extra", "rbuf",
                           "wbuf", "rrec", "wrec", "alert_fragment", "alert_fragment_len", "handshake_fragment",
                           "handshake_fragment_len", "wnum", "wpend_tot", "wpend_type", "wpend_ret", "wpend_buf",
                           "handshake_buffer", "handshake_dgst", "change_cipher_spec", "warn_alert", "fatal_alert",
                           "alert_dispatch", "send_alert", "renegotiate", "total_renegotiations",
                           "num_renegotiations", "in_read_app_data", "tmp.finish_md", "tmp.finish_md_len",
                           "tmp.peer_finish_md", "tmp.message_size", "tmp.message_type", "tmp.new_cipher",
                           "tmp.next_state", "tmp.reuse_message", "tmp.new_sym_enc", "tmp.new_hash",
                           "tmp.key_block_length", "tmp.key_block", "previous_client_finished",
                           "previous_server_finished", "send_connection_binding", "next_proto_neg_seen",
                           "~tlsext_channel_id_valid", "~tlsext_channel_id", "~alpn_selected", "~digest_rsa"]),
    ("SSL_SESSION", "lib", ["ssl_version", "key_arg_length", "key_arg", "master_key_length", "master_key",
                            "session_id_length", "session_id", "sid_ctx_length", "sid_ctx", "not_resumable",
                            "sess_cert", "peer", "verify_result", "references", "timeout", "time", "compress_meth",
                            "cipher", "cipher_id", "ciphers", "ex_data", "prev", "next", "tlsext_hostname",
                            "tlsext_tick", "tlsext_ticklen", "tlsext_tick_lifetime_hint"]),
    ("SSL_CTX", "lib", ["method", "cipher_list", "cipher_list_by_id", "cert_store", "sessions", "session_cache_size",
                        "session_cache_head", "session_cache_tail", "session_cache_mode", "session_timeout",
                        "new_session_cb", "remove_session_cb", "get_session_cb", "stats", "references",
                        "app_verify_callback", "app_verify_arg", "default_passwd_callback",
                        "default_passwd_callback_userdata", "client_cert_cb", "app_gen_cookie_cb",
                        "app_verify_cookie_cb", "ex_data", "rsa_md5", "md5", "sha1", "extra_certs", "comp_methods",
                        "info_callback", "client_CA", "options", "mode", "max_cert_list", "cert", "read_ahead",
                        "msg_callback", "msg_callback_arg", "verify_mode", "sid_ctx_length", "sid_ctx",
                        "default_verify_callback", "generate_session_id", "param", "quiet_shutdown",
                        "max_send_fragment", "client_cert_engine", "tlsext_servername_callback",
                        "tlsext_servername_arg", "tlsext_tick_key_name", "tlsext_tick_hmac_key",
                        "tlsext_tick_aes_key", "tlsext_ticket_key_cb", "tlsext_status_cb", "tlsext_status_arg",
                        "~alpn_select_cb", "~tlsext_channel_id_enabled", "~tlsext_channel_id_private"]),
    ("SSL_CIPHER", "lib", ["valid", "name", "id", "algorithm_mkey", "algorithm_auth", "algorithm_enc",
                           "algorithm_mac", "algorithm_ssl", "algo_strength", "algorithm2", "strength_bits",
                           "alg_bits"]),
    ("EVP_MD_CTX", "byval", ["digest", "engine", "flags", "md_data", "pctx", "update"]),
    ("EVP_CIPHER_CTX", "byval", ["cipher", "engine", "encrypt", "buf_len", "oiv", "iv", "buf", "num", "app_data",
                                 "key_len", "flags", "cipher_data", "final_used", "block_mask", "final"]),
    ("HMAC_CTX", "byval", ["md", "md_ctx", "i_ctx", "o_ctx", "key_length", "key"]),
    ("EVP_MD", "byval", ["type", "pkey_type", "md_size", "flags", "init", "update", "final", "copy", "cleanup",
                         "sign", "verify", "required_pkey_type", "block_size", "ctx_size", "md_ctrl"]),
    ("EVP_CIPHER", "byval", ["nid", "block_size", "key_len", "iv_len", "flags", "init", "do_cipher", "cleanup",
                             "ctx_size", "set_asn1_parameters", "get_asn1_parameters", "ctrl", "app_data"]),
    ("EVP_ENCODE_CTX", "byval", ["num", "length", "enc_data", "line_num", "expect_nl"]),
    ("SHA_CTX", "byval", []),
    ("SHA256_CTX", "byval", []),
    ("SHA512_CTX", "byval", []),
    ("MD5_CTX", "byval", []),
    ("MD4_CTX", "byval", []),
    ("AES_KEY", "byval", ["rounds"]),
    ("DES_key_schedule", "byval", []),
    ("RC4_KEY", "byval", []),
    ("BIGNUM", "byval", ["d", "top", "dmax", "neg", "flags"]),
    ("CRYPTO_EX_DATA", "byval", ["sk", "dummy"]),
    ("X509_STORE_CTX", "byval", ["ctx", "current_method", "cert", "untrusted", "crls", "param", "other_ctx",
                                 "verify", "verify_cb", "get_issuer", "check_issued", "check_revocation", "get_crl",
                                 "check_crl", "cert_crl", "check_policy", "lookup_certs", "lookup_crls", "cleanup",
                                 "valid", "last_untrusted", "chain", "tree", "explicit_policy", "error_depth",
                                 "error", "current_cert", "current_issuer", "current_crl", "current_crl_score",
                                 "current_reasons", "parent", "ex_data"]),
    ("BIO_METHOD", "byval", ["type", "name", "bwrite", "bread", "bputs", "bgets", "ctrl", "create", "destroy",
                             "callback_ctrl"]),
    ("RSA_METHOD", "byval", ["name", "rsa_pub_enc", "rsa_pub_dec", "rsa_priv_enc", "rsa_priv_dec", "rsa_mod_exp",
                             "bn_mod_exp", "init", "finish", "flags", "app_data", "rsa_sign", "rsa_verify",
                             "rsa_keygen"]),
    ("BIO", "lib", ["method", "callback", "cb_arg", "init", "shutdown", "flags", "retry_reason", "num", "ptr",
                    "next_bio", "prev_bio", "references", "num_read", "num_write", "ex_data"]),
    ("EVP_PKEY", "lib", ["type", "save_type", "references", "ameth", "engine", "pkey", "save_parameters",
                         "attributes"]),
    ("RSA", "lib", ["pad", "version", "meth", "engine", "n", "e", "d", "p", "q", "dmp1", "dmq1", "iqmp", "ex_data",
                    "references", "flags", "_method_mod_n", "_method_mod_p", "_method_mod_q", "bignum_data",
                    "blinding", "mt_blinding"]),
    ("DSA", "lib", ["pad", "version", "write_params", "p", "q", "g", "pub_key", "priv_key", "kinv", "r", "flags",
                    "method_mont_p", "references", "ex_data", "meth", "engine"]),
    ("DH", "lib", ["pad", "version", "p", "g", "length", "pub_key", "priv_key", "flags", "method_mont_p", "q", "j",
                   "seed", "seedlen", "counter", "references", "ex_data", "meth", "engine"]),
    ("X509", "lib", ["cert_info", "sig_alg", "signature", "valid", "references", "name", "ex_data", "ex_pathlen",
                     "ex_pcpathlen", "ex_flags", "ex_kusage", "ex_xkusage", "ex_nscert", "skid", "akid",
                     "policy_cache", "crldp", "altname", "nc", "sha1_hash", "aux"]),
    ("X509_CINF", "lib", ["version", "serialNumber", "signature", "issuer", "validity", "subject", "key",
                          "issuerUID", "subjectUID", "extensions", "enc"]),
    ("X509_STORE", "lib", ["cache", "objs", "get_cert_methods", "param", "verify", "verify_cb", "get_issuer",
                           "check_issued", "check_revocation", "get_crl", "check_crl", "cert_crl", "lookup_certs",
                           "lookup_crls", "cleanup", "ex_data", "references"]),
    ("ASN1_STRING", "lib", ["length", "type", "data", "flags"]),
]

PROBE_HEADERS = ["ssl.h", "ssl3.h", "evp.h", "hmac.h", "sha.h", "md5.h", "md4.h", "aes.h", "des.h", "rc4.h", "bn.h",
                 "rsa.h", "dsa.h", "dh.h", "x509.h", "x509_vfy.h", "bio.h", "crypto.h", "asn1.h"]


def probe_key(typ, member=None):
    return typ if member is None else "%s.%s" % (typ, member)


def probe_symbol(typ, member=None):
    if member is None:
        return "kktls_sz__" + typ
    return "kktls_off__%s__%s" % (typ, member.replace(".", "__"))


def probe_source(absent=()):
    """absent: "Type.member" keys left out (members a Jelly Bean base does not have, e.g. SSL_CTX.alpn_select_cb)."""
    lines = ["/* generated by openssl-abi-check.py probe-source: sizes and member offsets of the public OpenSSL",
             " * structures, as the sizes of global char arrays (offset + 1, so no array has size 0). */",
             "#include <stddef.h>"]
    lines += ["#include <openssl/%s>" % h for h in PROBE_HEADERS]
    for typ, _kind, members in STRUCTS:
        lines.append("char %s[sizeof(%s)];" % (probe_symbol(typ), typ))
        for m in members:
            m = m.lstrip("~")
            if probe_key(typ, m) in absent:
                continue
            lines.append("char %s[offsetof(%s, %s) + 1];" % (probe_symbol(typ, m), typ, m))
    return "\n".join(lines) + "\n"


def probe_values(syms):
    """readelf -s of a probe object -> {key: value} (size, or offset for members)."""
    by_sym = {s["name"]: s["size"] for s in syms if s["type"] == "OBJECT"}
    res = {}
    for typ, _kind, members in STRUCTS:
        k = probe_symbol(typ)
        if k in by_sym:
            res[probe_key(typ)] = by_sym[k]
        for m in members:
            m = m.lstrip("~")
            k = probe_symbol(typ, m)
            if k in by_sym:
                res[probe_key(typ, m)] = by_sym[k] - 1
    return res


def compare_structs(old, new, allow, absent=()):
    fails, notes = [], []
    for typ, kind, members in STRUCTS:
        key = probe_key(typ)
        if key not in old or key not in new:
            fails.append("%s: missing from the %s probe" % (typ, "old" if key not in old else "new"))
            continue
        if old[key] != new[key]:
            msg = "%s (%s): size %d -> %d" % (typ, kind, old[key], new[key])
            why = allowed(allow, "struct", key)
            if why:
                notes.append("allowed  " + msg + ": " + why)
            elif kind == "byval":
                fails.append(msg)
            else:
                notes.append("grown    " + msg if new[key] > old[key] else "shrunk   " + msg)
        for m in members:
            internal = m.startswith("~")
            m = m.lstrip("~")
            k = probe_key(typ, m)
            if k in absent and k not in old:
                notes.append("absent   %s: left out of the probes (--absent)" % k)
                continue
            if k not in old or k not in new:
                fails.append("%s: missing from the %s probe" % (k, "old" if k not in old else "new"))
                continue
            if old[k] != new[k]:
                msg = "%s: offset %d -> %d" % (k, old[k], new[k])
                why = allowed(allow, "struct", k)
                if why:
                    notes.append("allowed  " + msg + ": " + why)
                elif internal:
                    notes.append("internal " + msg + " (only libssl uses it)")
                else:
                    fails.append(msg)
    notes.append("%d types, %d members compared" % (len(STRUCTS), sum(len(m) for _t, _k, m in STRUCTS)))
    return fails, notes


def cmd_structs(a):
    re_ = Readelf(a.readelf)
    allow = load_allow(a.allow)
    old, new = probe_values(re_.syms(a.old)), probe_values(re_.syms(a.new))
    fails, notes = compare_structs(old, new, allow, set(a.absent or ()))
    return report("structs", fails, notes)


# ---------------------------------------------------------------------------------------------------------------------


def report(what, fails, notes):
    for n in notes:
        print("  " + n)
    for f in fails:
        print("  FAIL " + f)
    print("%s %s (%d failure(s))" % ("PASS" if not fails else "FAIL", what, len(fails)))
    return 0 if not fails else 1


def _syms_text(entries):
    """Synthetic readelf -W --dyn-syms text: entries (name, type, bind, ndx, size)."""
    out = ["Symbol table '.dynsym' contains %d entries:" % len(entries),
           "   Num:    Value  Size Type    Bind   Vis      Ndx Name"]
    for i, (name, typ, bind, ndx, size) in enumerate(entries):
        out.append("%6d: %08x %5d %-7s %-6s DEFAULT  %3s %s" % (i, 0x1000 + i, size, typ, bind, ndx, name))
    return "\n".join(out)


def selftest():
    errors = []
    count = [0]

    def expect(cond, what):
        count[0] += 1
        if not cond:
            errors.append(what)

    noallow = {"symbol": {}, "objsize": {}, "struct": {}}
    # parsers
    text = _syms_text([("", "NOTYPE", "LOCAL", "UND", 0), ("SSL_new", "FUNC", "GLOBAL", "9", 40),
                       ("ssl3_undef_enc_method", "OBJECT", "GLOBAL", "18", 44), ("memcpy", "FUNC", "GLOBAL", "UND", 0),
                       ("__gmon_start__", "NOTYPE", "WEAK", "UND", 0), ("local_x", "FUNC", "LOCAL", "9", 4)])
    syms = parse_symbols(text)
    expect(defined_exports(syms) == {"SSL_new": ("FUNC", 40), "ssl3_undef_enc_method": ("OBJECT", 44)},
           "defined_exports: %r" % defined_exports(syms))
    expect(undefined_imports(syms) == {"memcpy": "GLOBAL", "__gmon_start__": "WEAK"},
           "undefined_imports: %r" % undefined_imports(syms))
    expect(parse_needed(" 0x00000001 (NEEDED)  Shared library: [libssl.so]\n 0x00000001 (NEEDED)  Shared library: "
                        "[libc.so]") == ["libssl.so", "libc.so"], "parse_needed")
    # copy relocations: GNU readelf 2.42 -W -r of a non-PIC ARM executable (arm-linux-androideabi-gcc 4.7 -fno-PIC)
    # that reads BN_version and ssl3_version_str; its --dyn-syms lists both as defined OBJECTs in .bss (Ndx 18)
    relocs = ("Relocation section '.rel.dyn' at offset 0x4a4 contains 4 entries:\n"
              " Offset     Info    Type                Sym. Value  Symbol's Name\n"
              "0000bff8  00000115 R_ARM_GLOB_DAT         00000000   __gmon_start__\n"
              "0000c010  00000314 R_ARM_COPY             0000c010   BN_version\n"
              "0000c03e  00000414 R_ARM_COPY             0000c03e   ssl3_version_str@OPENSSL_1.0.0\n"
              "0000c00c  00000216 R_ARM_JUMP_SLOT        00000000   __libc_init\n")
    copied = parse_copy_relocs(relocs)
    expect(copied == {"BN_version", "ssl3_version_str"}, "parse_copy_relocs: %r" % copied)
    exe = parse_symbols(_syms_text([("BN_version", "OBJECT", "GLOBAL", "18", 46), ("main", "FUNC", "GLOBAL", "10", 20),
                                    ("SSL_new", "FUNC", "GLOBAL", "UND", 0)]))
    expect(undefined_imports(exe, copied) == {"BN_version": "GLOBAL", "SSL_new": "GLOBAL"},
           "undefined_imports with copy relocations: %r" % undefined_imports(exe, copied))
    # symbols
    old = {"libssl.so": {"SSL_new": ("FUNC", 1), "SSLv2_method": ("FUNC", 1), "ssl2_accept": ("FUNC", 1),
                         "ssl3_undef_enc_method": ("OBJECT", 44)},
           "libcrypto.so": {"EVP_sha1": ("FUNC", 1), "OPENSSL_ia32cap_P": ("OBJECT", 8)}}
    good = {"libssl.so": {"SSL_new": ("FUNC", 1), "SSLv2_method": ("FUNC", 1), "ssl3_undef_enc_method": ("OBJECT", 44),
                          "SSL_set_alpn_protos": ("FUNC", 1)},
            "libcrypto.so": {"EVP_sha1": ("FUNC", 1), "OPENSSL_ia32cap_P": ("OBJECT", 8)}}
    ids = {"SSL_new", "SSLv2_method", "EVP_sha1", "OPENSSL_ia32cap_P"}
    f, n = compare_symbols(old, good, ids, noallow)
    expect(not f and any("internal libssl.so: ssl2_accept removed" in x for x in n), "symbols good: %r %r" % (f, n))
    bad = {k: dict(v) for k, v in good.items()}
    del bad["libssl.so"]["SSLv2_method"]
    f, _ = compare_symbols(old, bad, ids, noallow)
    expect(any("public   libssl.so: SSLv2_method removed" in x for x in f), "symbols: public removal: %r" % f)
    f, n = compare_symbols(old, bad, ids, {"symbol": {"SSLv2_method": "why"}, "objsize": {}, "struct": {}})
    expect(not f and any(x.startswith("allowed") for x in n), "symbols: allow list: %r" % f)
    bad = {k: dict(v) for k, v in good.items()}
    bad["libcrypto.so"]["OPENSSL_ia32cap_P"] = ("OBJECT", 16)
    f, _ = compare_symbols(old, bad, ids, noallow)
    expect(any("data object OPENSSL_ia32cap_P size 8 -> 16" in x for x in f), "symbols: object size: %r" % f)
    bad = {k: dict(v) for k, v in good.items()}
    bad["libcrypto.so"]["SSL_new"] = bad["libssl.so"].pop("SSL_new")
    f, _ = compare_symbols(old, bad, ids, noallow)
    expect(any("SSL_new removed (now in libcrypto.so)" in x for x in f), "symbols: moved between libs: %r" % f)
    # users
    imports = {"SSL_new": "GLOBAL", "ssl2_accept": "GLOBAL", "memcpy": "GLOBAL", "EVP_sha1": "GLOBAL"}
    n_, strong, weak = check_user(["libssl.so", "libcrypto.so", "libc.so"], imports, old, good)
    expect(n_ == 3 and strong == ["ssl2_accept (libssl.so)"] and not weak, "users: internal import: %r" % strong)
    n_, strong, _ = check_user(["libcrypto.so"], imports, old, good)
    expect(n_ == 3 and strong == ["ssl2_accept (libssl.so)"], "users: libcrypto user, both libs count: %d %r" % (n_, strong))
    n_, strong, _ = check_user(["libc.so"], imports, old, good)
    expect(n_ == 0 and not strong, "users: no OpenSSL NEEDED, no OpenSSL imports: %d %r" % (n_, strong))
    # review 3 codex 3: a user that NEEDs only libssl.so imports from libcrypto.so through libssl's own NEEDED
    gone = {k: dict(v) for k, v in good.items()}
    del gone["libcrypto.so"]["EVP_sha1"]
    n_, strong, _ = check_user(["libssl.so", "libc.so"], {"SSL_new": "GLOBAL", "EVP_sha1": "GLOBAL"}, old, gone)
    expect(n_ == 2 and strong == ["EVP_sha1 (libcrypto.so)"], "users: libssl user, removed libcrypto import: %d %r"
           % (n_, strong))
    resized = {k: dict(v) for k, v in good.items()}
    resized["libcrypto.so"]["OPENSSL_ia32cap_P"] = ("OBJECT", 12)
    _, strong, _ = check_user(["libssl.so"], {"OPENSSL_ia32cap_P": "GLOBAL"}, old, resized)
    expect(strong == ["OPENSSL_ia32cap_P (libcrypto.so): data object size 8 -> 12 (copy relocation)"],
           "users: libssl user, resized libcrypto object: %r" % strong)
    n_, strong, weak = check_user(["libssl.so"], {"ssl2_accept": "WEAK"}, old, good)
    expect(not strong and weak == ["ssl2_accept (libssl.so)"], "users: weak import: %r %r" % (strong, weak))
    grown = {k: dict(v) for k, v in good.items()}
    grown["libcrypto.so"]["OPENSSL_ia32cap_P"] = ("OBJECT", 9)
    _, strong, _ = check_user(["libcrypto.so"], {"OPENSSL_ia32cap_P": "GLOBAL"}, old, grown)
    expect(strong == ["OPENSSL_ia32cap_P (libcrypto.so): data object size 8 -> 9 (copy relocation)"],
           "users: copy relocation: %r" % strong)
    f, _ = compare_symbols(old, grown, ids, {"symbol": {"OPENSSL_*_P": "why"}, "objsize": {}, "struct": {}})
    expect(any("data object OPENSSL_ia32cap_P size 8 -> 9" in x for x in f), "symbols: symbol allow is no objsize: %r" % f)
    f, n = compare_symbols(old, grown, ids, {"symbol": {}, "objsize": {"OPENSSL_*_P": "why"}, "struct": {}})
    expect(not f and any("allowed  libcrypto.so: data object OPENSSL_ia32cap_P" in x for x in n),
           "symbols: allow pattern: %r" % f)
    _, strong, _ = check_user(["libssl.so"], {"ssl3_undef_enc_method": "GLOBAL"}, old,
                              {"libssl.so": {"ssl3_undef_enc_method": ("FUNC", 44)}, "libcrypto.so": {}})
    expect(strong == ["ssl3_undef_enc_method (libssl.so): type OBJECT -> FUNC"], "users: object -> function: %r" % strong)
    _, strong, _ = check_user(["libcrypto.so"], {"EVP_sha1": "GLOBAL"}, old,
                              {"libssl.so": {}, "libcrypto.so": {"EVP_sha1": ("OBJECT", 1)}})
    expect(strong == ["EVP_sha1 (libcrypto.so): type FUNC -> OBJECT"], "users: function -> object: %r" % strong)
    # users: ELF members of archives (an APK's lib/<abi>/*.so), extracted; non-ELF members ignored
    with tempfile.TemporaryDirectory(prefix="abi-selftest-") as tmp:
        root = os.path.join(tmp, "system")
        os.makedirs(os.path.join(root, "app"))
        os.makedirs(os.path.join(root, "lib"))
        with open(os.path.join(root, "lib", "libuser.so"), "wb") as fh:
            fh.write(b"\x7fELF-plain")
        with zipfile.ZipFile(os.path.join(root, "app", "App.apk"), "w") as z:
            z.writestr("lib/armeabi-v7a/libjni.so", b"\x7fELF-member")
            z.writestr("lib/armeabi-v7a/notes.so", b"not an ELF")
            z.writestr("classes.dex", b"dex\n035")
        out = os.path.join(tmp, "x")
        os.makedirs(out)
        got = [(rel, origin, open(p, "rb").read()) for rel, p, origin in scan_users(root, out)]
        expect(got == [("app/App.apk!lib/armeabi-v7a/libjni.so", "archive", b"\x7fELF-member"),
                       ("lib/libuser.so", "file", b"\x7fELF-plain")], "users: archive scan: %r" % got)
        # an archive that is not a zip, an archive member with a bad CRC, and (as non-root) a file or an archive
        # without read permission stop the run: each may hold an OpenSSL user nobody checked
        bad_cases = [("not a zip", "Broken.apk", None), ("member with a bad CRC", "BadCrc.apk", None)]
        if hasattr(os, "geteuid") and os.geteuid() != 0:  # root reads mode-000 files anyway
            bad_cases += [("unreadable ELF file", "libsecret.so", 0), ("unreadable archive", "Locked.apk", 0)]
        for what, name, mode in bad_cases:
            broot = os.path.join(tmp, "bad-" + name)
            os.makedirs(os.path.join(broot, "lib"))
            shutil.copy(os.path.join(root, "lib", "libuser.so"), os.path.join(broot, "lib", "libuser.so"))
            bp = os.path.join(broot, "lib", name)
            if name == "Broken.apk":
                with open(bp, "wb") as fh:
                    fh.write(b"PK not a zip")
            elif name == "BadCrc.apk":
                with zipfile.ZipFile(bp, "w") as z:  # stored, so the flipped byte reaches the CRC check
                    z.writestr("lib/armeabi-v7a/libjni.so", b"\x7fELF-member-with-a-payload")
                data = bytearray(open(bp, "rb").read())
                i = data.index(b"with-a-payload")
                data[i] ^= 0xff
                with open(bp, "wb") as fh:
                    fh.write(bytes(data))
            elif name.endswith(".apk"):
                shutil.copy(os.path.join(root, "app", "App.apk"), bp)
            else:
                with open(bp, "wb") as fh:
                    fh.write(b"\x7fELF-unreadable")
            if mode is not None:
                os.chmod(bp, mode)
            try:
                list(scan_users(broot, out))
                expect(False, "users: %s: no error" % what)
            except SystemExit as e:
                expect("cannot read" in str(e) and name in str(e), "users: %s: %s" % (what, e))
            except Exception as e:  # the old code let a bad CRC through as a traceback
                expect(False, "users: %s: %r instead of a stop" % (what, e))
            finally:
                os.chmod(bp, 0o644)
        # a missing --scan root, or a missing/empty --old-headers dir, stops the run instead of passing on nothing
        for what, fn in [("users: missing scan root", lambda: list(scan_users(os.path.join(tmp, "nope"), out))),
                         ("symbols: missing --old-headers", lambda: header_identifiers(os.path.join(tmp, "nope"))),
                         ("symbols: --old-headers without .h", lambda: header_identifiers(out))]:
            try:
                fn()
                expect(False, what + ": no error")
            except SystemExit as e:
                expect("not a directory" in str(e) or "no .h file" in str(e), what + ": %s" % e)
        hdir = os.path.join(tmp, "include", "openssl")
        os.makedirs(hdir)
        with open(os.path.join(hdir, "ssl.h"), "w") as fh:
            fh.write("SSL *SSL_new(SSL_CTX *ctx); /* ssl2_accept */\n")
        hid = header_identifiers(os.path.join(tmp, "include"))
        expect("SSL_new" in hid and "ssl2_accept" not in hid, "header_identifiers: %r" % sorted(hid))
        if hasattr(os, "geteuid") and os.geteuid() != 0:  # root reads a mode-000 directory anyway
            locked = os.path.join(root, "locked")
            os.makedirs(os.path.join(locked, "sub"))
            os.chmod(locked, 0)
            try:
                list(scan_users(root, out))
                expect(False, "users: unreadable directory under the scan root: no error")
            except SystemExit as e:
                expect("cannot read" in str(e), "users: unreadable directory: %s" % e)
            finally:
                os.chmod(locked, 0o755)
        # cmd_users with a canned readelf: a scan root without any OpenSSL user fails, one with a user passes
        pair = os.path.join(tmp, "pair")
        os.makedirs(pair)
        for lib in LIBS:
            open(os.path.join(pair, lib), "wb").close()

        class FakeReadelf:
            def dynsyms(self, f):
                if f.endswith("libssl.so"):
                    return parse_symbols(_syms_text([("SSL_new", "FUNC", "GLOBAL", "9", 4)]))
                if f.endswith("libcrypto.so"):
                    return parse_symbols(_syms_text([("EVP_sha1", "FUNC", "GLOBAL", "9", 4)]))
                return parse_symbols(_syms_text([("SSL_new", "FUNC", "GLOBAL", "UND", 0)]))

            def needed(self, f):
                return ["libssl.so"] if f.endswith("libuser.so") else ["libc.so"]

            def copy_relocs(self, f):
                return set()
        empty = os.path.join(tmp, "empty-root")
        os.makedirs(os.path.join(empty, "bin"))
        with open(os.path.join(empty, "bin", "tool"), "wb") as fh:
            fh.write(b"\x7fELF-no-openssl")
        for scans, want in [([root], 0), ([empty], 1), ([root, empty], 1)]:
            ns = argparse.Namespace(old=pair, new=pair, scan=scans, symbols_root=None, readelf=None)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cmd_users(ns, FakeReadelf())
            expect(rc == want and (want == 0 or "no ELF file with NEEDED" in buf.getvalue()),
                   "users: scan roots %r: rc %d, want %d: %s" % ([os.path.basename(x) for x in scans], rc, want,
                                                                 buf.getvalue()))
        # cmd_users on an executable with a copy relocation of a version string that grew by one byte (the objsize
        # allow list of `symbols` does not apply to users): readelf lists the symbol as defined, the import is found
        # through the R_ARM_COPY entry and fails
        vpair = {}
        for tag, size in (("old", 46), ("new", 47)):
            vpair[tag] = os.path.join(tmp, "vpair-" + tag)
            os.makedirs(vpair[tag])
            for lib in LIBS:
                with open(os.path.join(vpair[tag], lib), "w") as fh:
                    fh.write(str(size))
        croot = os.path.join(tmp, "copy-root")
        os.makedirs(os.path.join(croot, "bin"))
        with open(os.path.join(croot, "bin", "copyuser"), "wb") as fh:
            fh.write(b"\x7fELF-copy")

        class CopyReadelf:
            def dynsyms(self, f):
                if f.endswith("libcrypto.so"):
                    return parse_symbols(_syms_text([("BN_version", "OBJECT", "GLOBAL", "18", int(open(f).read()))]))
                if f.endswith(".so"):  # libssl.so: one export (load_pair stops on an empty map)
                    return parse_symbols(_syms_text([("SSL_new", "FUNC", "GLOBAL", "9", 4)]))
                return parse_symbols(_syms_text([("BN_version", "OBJECT", "GLOBAL", "18", 46)]))

            def needed(self, f):
                return ["libcrypto.so", "libc.so"]

            def copy_relocs(self, f):
                return parse_copy_relocs(relocs)
        ns = argparse.Namespace(old=vpair["old"], new=vpair["new"], scan=[croot], symbols_root=None, readelf=None)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cmd_users(ns, CopyReadelf())
        expect(rc == 1 and "BN_version (libcrypto.so): data object size 46 -> 47 (copy relocation)" in buf.getvalue(),
               "users: copy-relocated import: rc %d: %s" % (rc, buf.getvalue()))
        # review 3, codex 4: a library of the pair without any export (no .dynsym, only undefined symbols, or a table
        # readelf printed in a form parse_symbols does not read) stops the run; an empty old map passed `symbols`
        # (nothing removed) and `users` (no OpenSSL import)
        class EmptyReadelf(FakeReadelf):
            def __init__(self, empty_lib, syms):
                self.empty_lib, self.syms_ = empty_lib, syms

            def dynsyms(self, f):
                if os.path.dirname(f) == epair and f.endswith(self.empty_lib):
                    return self.syms_
                return FakeReadelf.dynsyms(self, f)
        epair = os.path.join(tmp, "epair")
        os.makedirs(epair)
        for lib in LIBS:
            open(os.path.join(epair, lib), "wb").close()
        for lib, syms, what in [("libssl.so", [], "no dynamic symbols"),
                                ("libcrypto.so", parse_symbols(_syms_text([("memcpy", "FUNC", "GLOBAL", "UND", 0)])),
                                 "only undefined symbols")]:
            for old_dir, new_dir in [(epair, pair), (pair, epair)]:
                tag = "%s %s as --%s" % (lib, what, "old" if old_dir == epair else "new")
                ns = argparse.Namespace(old=old_dir, new=new_dir, scan=[root], symbols_root=None, readelf=None)
                buf = io.StringIO()
                try:
                    with contextlib.redirect_stdout(buf):
                        rc = cmd_users(ns, EmptyReadelf(lib, syms))
                    expect(False, "users: %s: rc %d instead of a stop: %s" % (tag, rc, buf.getvalue()))
                except SystemExit as e:
                    expect(os.path.join(epair, lib) in str(e) and "no exported dynamic symbol" in str(e),
                           "users: %s: %s" % (tag, e))
    # readelf text that was not read completely stops Readelf.dynsyms: an entry line parse_symbols does not match, or
    # fewer entry lines than the table header declares (a dropped export of the old pair went unchecked)
    good_text = _syms_text([("", "NOTYPE", "LOCAL", "UND", 0), ("SSL_new", "FUNC", "GLOBAL", "9", 40)])
    bad_texts = [("an entry line that is not parsed", good_text + "\n     2: 00001002 garbled entry"),
                 ("fewer entry lines than declared", good_text.replace("contains 2 entries", "contains 3 entries"))]
    expect(symbol_text_problems(good_text) == [], "symbol_text_problems good: %r" % symbol_text_problems(good_text))
    expect(symbol_text_problems("") == [], "symbol_text_problems on no table: %r" % symbol_text_problems(""))

    class CannedReadelf(Readelf):
        def __init__(self, text):
            Readelf.__init__(self, "canned-readelf")
            self.text = text

        def run(self, args, f):
            return self.text
    expect([s_["name"] for s_ in CannedReadelf(good_text).dynsyms("lib.so")] == ["SSL_new"], "Readelf.dynsyms good")
    for what, text in bad_texts:
        try:
            CannedReadelf(text).dynsyms("libssl.so")
            expect(False, "Readelf.dynsyms: %s: no stop" % what)
        except SystemExit as e:
            expect("libssl.so" in str(e) and ("not parsed" in str(e) or "declared" in str(e)),
                   "Readelf.dynsyms: %s: %s" % (what, e))
    # allow list: exact names and struct patterns behave like the other kinds
    f, n = compare_symbols(old, grown, ids, {"symbol": {}, "objsize": {"OPENSSL_ia32cap": "why"}, "struct": {}})
    expect(any("data object OPENSSL_ia32cap_P size 8 -> 9" in x for x in f), "symbols: exact name is no prefix: %r" % f)
    expect(strip_c_comments("int a; /* ssl2_enc\n x */ int b; // c_d\n") == "int a;   int b; \n",
           "strip_c_comments: %r" % strip_c_comments("int a; /* ssl2_enc\n x */ int b; // c_d\n"))
    # structs
    src = probe_source()
    expect("char kktls_off__SSL3_STATE__client_random[offsetof(SSL3_STATE, client_random) + 1];" in src and
           "char kktls_off__SSL3_STATE__tmp__new_cipher[offsetof(SSL3_STATE, tmp.new_cipher) + 1];" in src and
           "char kktls_sz__EVP_MD_CTX[sizeof(EVP_MD_CTX)];" in src, "probe_source")
    entries = []
    for typ, _kind, members in STRUCTS:
        entries.append((probe_symbol(typ), "OBJECT", "GLOBAL", "4", 64))
        for i, m in enumerate(members):
            entries.append((probe_symbol(typ, m.lstrip("~")), "OBJECT", "GLOBAL", "4", 4 * i + 1))
    base = probe_values(parse_symbols(_syms_text(entries)))
    expect(base["SSL3_STATE.tmp.new_cipher"] == 4 * STRUCTS[1][2].index("tmp.new_cipher") and
           base["EVP_MD_CTX"] == 64, "probe_values")
    f, _ = compare_structs(base, dict(base), noallow)
    expect(not f, "structs identical: %r" % f)
    for key, val, want in [("EVP_MD_CTX", 72, "EVP_MD_CTX (byval): size 64 -> 72"),
                           ("SSL3_STATE.client_random", 999, "SSL3_STATE.client_random: offset"),
                           ("SSL_SESSION.master_key", 999, "SSL_SESSION.master_key: offset")]:
        mut = dict(base)
        mut[key] = val
        f, _ = compare_structs(base, mut, noallow)
        expect(any(want in x for x in f), "structs mutation %s: %r" % (key, f))
    for key, val, want in [("SSL", 80, "grown    SSL (lib): size 64 -> 80"),
                           ("SSL3_STATE.digest_rsa", 999, "internal SSL3_STATE.digest_rsa")]:
        mut = dict(base)
        mut[key] = val
        f, n = compare_structs(base, mut, noallow)
        expect(not f and any(want in x for x in n), "structs note %s: %r %r" % (key, f, n))
    mut = dict(base)
    mut["SSL3_STATE.client_random"] = 999
    f, n = compare_structs(base, mut, {"symbol": {}, "objsize": {}, "struct": {"SSL3_STATE.client_*": "why"}})
    expect(not f and any(x.startswith("allowed  SSL3_STATE.client_random") for x in n), "structs: allow pattern: %r" % f)
    mut = dict(base)
    del mut["SSL.s3"]
    f, _ = compare_structs(base, mut, noallow)
    expect(any("SSL.s3: missing from the new probe" in x for x in f), "structs: missing member: %r" % f)
    for e in errors:
        print("SELFTEST FAIL " + e)
    print("SELFTEST %s (%d checks)" % ("PASS" if not errors else "FAIL", count[0]))
    return 0 if not errors else 1


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--readelf")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("symbols")
    s.add_argument("--old", required=True)
    s.add_argument("--new", required=True)
    s.add_argument("--old-headers")
    s.add_argument("--allow")
    u = sub.add_parser("users")
    u.add_argument("--old", required=True)
    u.add_argument("--new", required=True)
    u.add_argument("--scan", action="append", required=True)
    u.add_argument("--symbols-root")
    ps = sub.add_parser("probe-source")
    ps.add_argument("--absent", action="append", help="Type.member to leave out (repeatable)")
    t = sub.add_parser("structs")
    t.add_argument("--old", required=True)
    t.add_argument("--new", required=True)
    t.add_argument("--allow")
    t.add_argument("--absent", action="append", help="Type.member left out of the probes (repeatable)")
    a = p.parse_args(argv[1:])
    if a.cmd == "symbols":
        return cmd_symbols(a)
    if a.cmd == "users":
        return cmd_users(a)
    if a.cmd == "probe-source":
        sys.stdout.write(probe_source(set(a.absent or ())))
        return 0
    return cmd_structs(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
