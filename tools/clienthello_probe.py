#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""clienthello_probe.py: record the TLS ClientHello of each client that connects, then refuse the handshake.

Layer-A network matrix without tcpdump: the emulator (or a device) connects to this server on the host
(the emulator sees the host's loopback as 10.0.2.2), and every ClientHello is printed as one JSON line:
record and client versions, the cipher list (with TLS_FALLBACK_SCSV 0x5600 and the renegotiation SCSV 0x00ff
flagged), extensions with the SNI name and the padding length, and the sizes (record bytes, handshake message).

After the ClientHello the server answers with a fatal handshake_failure alert. That makes the Android client fail its
first handshake, so okhttp's TLS fallback retries, and the second ClientHello shows the retry (TLSv1 + 0x5600).
A malformed ClientHello is one {"conn": N, "error": ...} line; the server keeps serving.

    python3 -I clienthello_probe.py serve --port 8443 [--bind 127.0.0.1] [--timeout S]
    python3 -I clienthello_probe.py intolerant --port 8444 --cert PEM --key PEM [--server-max TLSv1.2|TLSv1] [--bind]
                                               [--curve prime256v1]
    python3 -I clienthello_probe.py --selftest      # synthetic hellos + real ones from Python's ssl client

`intolerant` (Task 11, layer D) plays a TLS-1.3-intolerant server: a ClientHello whose supported_versions extension
offers TLS 1.3 is logged and the connection is closed without an answer (as a middlebox or an old server that chokes
on it); any other ClientHello is handed to a real TLS server (Python's ssl, TLS 1.0 up to --server-max, all OpenSSL
suites at security level 0), which completes the handshake and answers one HTTP/1.0 200. One JSON line per
connection: the parsed hello, "action" (drop|served|failed), the negotiated version and suite or the server's error.

stdlib only; run with python3 -I.
"""
import json
import socket
import ssl
import struct
import sys
import threading
import warnings

SCSV_FALLBACK = 0x5600
SCSV_RENEGO = 0x00FF
EXT_NAMES = {0: "server_name", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats",
             13: "signature_algorithms", 15: "heartbeat", 16: "alpn", 21: "padding", 23: "extended_master_secret",
             35: "session_ticket", 13172: "next_protocol_negotiation", 30031: "channel_id_old", 30032: "channel_id",
             65281: "renegotiation_info", 43: "supported_versions", 45: "psk_key_exchange_modes", 51: "key_share"}
VERSIONS = {0x0300: "SSLv3", 0x0301: "TLSv1", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}


class ParseError(Exception):
    pass


def read_handshake(recv):
    """Read TLS records via recv(n) until one complete handshake message; return (raw_records, record_version, msg)."""
    raw = b""
    body = b""
    rec_version = None

    def need(n):
        nonlocal raw
        buf = b""
        while len(buf) < n:
            chunk = recv(n - len(buf))
            if not chunk:
                raise ParseError("connection closed after %d bytes" % (len(raw) + len(buf)))
            buf += chunk
        raw += buf
        return buf

    while True:
        hdr = need(5)
        ctype, ver, length = struct.unpack(">BHH", hdr)
        if ctype == 0x80 or hdr[0] & 0x80:
            raise ParseError("SSLv2-format ClientHello (first byte 0x%02x)" % hdr[0])
        if ctype != 22:
            raise ParseError("record type %d, want 22 (handshake)" % ctype)
        if rec_version is None:
            rec_version = ver
        body += need(length)
        if len(body) >= 4:
            mlen = struct.unpack(">I", b"\0" + body[1:4])[0]
            if len(body) >= 4 + mlen:
                return raw, rec_version, body[:4 + mlen]


def parse_client_hello(msg):
    """Parse one handshake message (type 1). Returns a dict."""
    if len(msg) < 4 or msg[0] != 1:
        raise ParseError("not a ClientHello (handshake type %r)" % (msg[0] if msg else None))
    mlen = struct.unpack(">I", b"\0" + msg[1:4])[0]
    p = msg[4:4 + mlen]
    if len(p) != mlen:
        raise ParseError("truncated ClientHello: %d of %d bytes" % (len(p), mlen))
    off = 0

    def take(n):
        nonlocal off
        if off + n > len(p):
            raise ParseError("truncated at offset %d (+%d)" % (off, n))
        b = p[off:off + n]
        off += n
        return b

    client_version = struct.unpack(">H", take(2))[0]
    take(32)  # random
    sid = take(take(1)[0])
    cs_len = struct.unpack(">H", take(2))[0]
    if cs_len % 2:
        raise ParseError("odd cipher_suites length %d" % cs_len)
    cs_raw = take(cs_len)
    ciphers = [struct.unpack(">H", cs_raw[i:i + 2])[0] for i in range(0, cs_len, 2)]
    comp = list(take(take(1)[0]))
    exts = []
    sni = []
    padding_len = None
    alpn = []
    supported_versions = []
    if off < len(p):
        ext_total = struct.unpack(">H", take(2))[0]
        end = off + ext_total
        if end != len(p):
            raise ParseError("extensions length %d does not fill the message (%d left)" % (ext_total, len(p) - off))
        while off < end:
            etype, elen = struct.unpack(">HH", take(4))
            edata = take(elen)
            exts.append(etype)
            if etype == 0 and elen >= 2:
                q = 2
                while q + 3 <= len(edata):
                    ntype, nlen = edata[q], struct.unpack(">H", edata[q + 1:q + 3])[0]
                    if ntype == 0:
                        sni.append(edata[q + 3:q + 3 + nlen].decode("ascii", "replace"))
                    q += 3 + nlen
            elif etype == 21:
                padding_len = elen
            elif etype == 43:
                # ClientHello form: a one-byte length, then 2-byte versions filling the extension exactly
                if elen < 1 or edata[0] != elen - 1 or edata[0] % 2:
                    raise ParseError("malformed supported_versions (extension %d bytes, list length %s)"
                                     % (elen, edata[0] if elen else None))
                for q in range(1, elen, 2):
                    v = struct.unpack(">H", edata[q:q + 2])[0]
                    supported_versions.append(VERSIONS.get(v, "0x%04x" % v))
            elif etype == 16 and elen >= 2:
                q = 2
                while q < len(edata):
                    n = edata[q]
                    alpn.append(edata[q + 1:q + 1 + n].decode("ascii", "replace"))
                    q += 1 + n
    return {
        "client_version": VERSIONS.get(client_version, "0x%04x" % client_version),
        "session_id_len": len(sid),
        "n_ciphers": len(ciphers),
        "ciphers": ["0x%04x" % c for c in ciphers],
        "fallback_scsv": SCSV_FALLBACK in ciphers,
        "renego_scsv": SCSV_RENEGO in ciphers,
        "compression": comp,
        "extensions": [EXT_NAMES.get(e, str(e)) for e in exts],
        "sni": sni,
        "padding_len": padding_len,
        "alpn": alpn,
        "supported_versions": supported_versions,
        "hello_len": mlen + 4,  # handshake message incl. its 4-byte header
    }


def capture(recv):
    raw, rec_version, msg = read_handshake(recv)
    try:
        info = parse_client_hello(msg)
    except (struct.error, IndexError, ValueError) as e:  # a length the checks above missed: still a parse error
        raise ParseError("malformed ClientHello: %s" % e) from e
    info["record_version"] = VERSIONS.get(rec_version, "0x%04x" % rec_version)
    info["record_bytes"] = len(raw)
    return info


ALERT_HANDSHAKE_FAILURE = bytes([21, 3, 1, 0, 2, 2, 40])


def serve(bind, port, count, timeout, out=sys.stdout):
    """Log each ClientHello and answer it with a handshake_failure alert; count > 0 stops after that many connections
    (the selftest), 0 runs until `timeout` seconds pass without a connection."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(8)
    srv.settimeout(timeout)
    print(json.dumps({"listening": "%s:%d" % srv.getsockname()}), file=out, flush=True)
    n = 0
    try:
        while count == 0 or n < count:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                print(json.dumps({"timeout": timeout, "connections": n}), file=out, flush=True)
                return n
            n += 1
            conn.settimeout(30)
            try:
                info = capture(conn.recv)
                info["peer"] = "%s:%d" % addr
                info["conn"] = n
                print(json.dumps(info, sort_keys=True), file=out, flush=True)
                conn.sendall(ALERT_HANDSHAKE_FAILURE)
            except (ParseError, OSError) as e:
                print(json.dumps({"conn": n, "peer": "%s:%d" % addr, "error": str(e)}), file=out, flush=True)
            finally:
                conn.close()
    finally:
        srv.close()
    return n


def _pump_handshake(conn, so, inc, outb):
    """Drive a server-side SSLObject over conn until the handshake ends; returns None or the error text."""
    while True:
        try:
            so.do_handshake()
            conn.sendall(outb.read())
            return None
        except ssl.SSLWantReadError:
            pending = outb.read()
            if pending:
                conn.sendall(pending)
            data = conn.recv(16384)
            if not data:
                return "client closed during the handshake"
            inc.write(data)
        except ssl.SSLError as e:
            pending = outb.read()
            if pending:
                try:
                    conn.sendall(pending)  # the server's alert
                except OSError:
                    pass
            return "%s: %s" % (type(e).__name__, e.reason or e)


def intolerant(bind, port, timeout, cert, key, server_max, out=sys.stdout, count=0, curve=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    if curve:
        ctx.set_ecdh_curve(curve)  # e.g. prime256v1: a TLS 1.2 client then never computes X25519
    with warnings.catch_warnings():  # TLS 1.0 is deprecated in Python's ssl; the old server is the point here
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = {"TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1": ssl.TLSVersion.TLSv1}[server_max]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(8)
    srv.settimeout(timeout)
    print(json.dumps({"listening": "%s:%d" % srv.getsockname(), "mode": "intolerant", "server_max": server_max,
                      "curve": curve or "default"}), file=out, flush=True)
    lock = threading.Lock()

    def handle(conn, addr, n):
        conn.settimeout(30)
        rec = {"conn": n, "peer": "%s:%d" % addr}
        try:
            raw, rec_version, msg = read_handshake(conn.recv)
            info = parse_client_hello(msg)
            rec.update({k: info[k] for k in ("client_version", "supported_versions", "fallback_scsv", "sni",
                                             "n_ciphers", "hello_len")})
            if "TLSv1.3" in info["supported_versions"]:
                rec["action"] = "drop"
            else:
                inc, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
                so = ctx.wrap_bio(inc, outb, server_side=True)
                inc.write(raw)
                err = _pump_handshake(conn, so, inc, outb)
                if err:
                    rec.update({"action": "failed", "error": err})
                else:
                    rec.update({"action": "served", "version": so.version(), "cipher": so.cipher()[0]})
                    emit(rec)  # now: a client may keep the connection open after its handshake
                    rec = {"conn": n, "after_handshake": True}
                    req = b""
                    while b"\r\n\r\n" not in req:
                        try:
                            req += so.read(16384)
                        except ssl.SSLWantReadError:
                            data = conn.recv(16384)
                            if not data:
                                break
                            inc.write(data)
                        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                            break
                    if req:
                        body = ("intolerant-ok %s %s\n" % (so.version(), so.cipher()[0])).encode()
                        so.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                                 b"Content-Length: %d\r\n\r\n" % len(body) + body)
                        conn.sendall(outb.read())
                        rec["http"] = req.split(b"\r\n", 1)[0].decode("ascii", "replace")
        except (ParseError, OSError) as e:
            if rec.get("after_handshake"):
                rec["closed"] = str(e) or type(e).__name__
            else:
                rec.update({"action": "failed", "error": str(e) or type(e).__name__})
        finally:
            conn.close()
        if not rec.get("after_handshake") or len(rec) > 2:
            emit(rec)

    def emit(rec):
        with lock:
            print(json.dumps(rec, sort_keys=True), file=out, flush=True)

    n = 0
    threads = []
    try:
        while count == 0 or n < count:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                with lock:
                    print(json.dumps({"timeout": timeout, "connections": n}), file=out, flush=True)
                break
            n += 1
            t = threading.Thread(target=handle, args=(conn, addr, n), daemon=True)
            t.start()
            threads.append(t)
    finally:
        srv.close()
        for t in threads:
            t.join(35)
    return n


# ---- selftest -------------------------------------------------------------------------------------------------------

def _ext(etype, data):
    return struct.pack(">HH", etype, len(data)) + data


def _hello(version=0x0303, ciphers=(0xC02B, 0x00FF), sni=None, padding=None, record_split=None, rec_version=0x0301,
           versions=None, extra=b""):
    exts = extra
    if versions is not None:
        exts += _ext(43, bytes([2 * len(versions)]) + b"".join(struct.pack(">H", v) for v in versions))
    if sni is not None:
        name = sni.encode()
        lst = b"\0" + struct.pack(">H", len(name)) + name
        exts += _ext(0, struct.pack(">H", len(lst)) + lst)
    exts += _ext(11, b"\x01\x00")
    if padding is not None:
        exts += _ext(21, b"\0" * padding)
    body = struct.pack(">H", version) + b"\x11" * 32 + b"\0"
    body += struct.pack(">H", 2 * len(ciphers)) + b"".join(struct.pack(">H", c) for c in ciphers)
    body += b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    msg = b"\x01" + struct.pack(">I", len(body))[1:] + body
    chunks = [msg] if record_split is None else [msg[:record_split], msg[record_split:]]
    return b"".join(struct.pack(">BHH", 22, rec_version, len(c)) + c for c in chunks), len(msg)


def _recv_from(data):
    state = {"off": 0}

    def recv(n):
        b = data[state["off"]:state["off"] + n]
        state["off"] += len(b)
        return b
    return recv


def selftest():
    fails = []

    def check(cond, what):
        print(("ok   " if cond else "FAIL ") + what)
        if not cond:
            fails.append(what)

    raw, mlen = _hello(sni="hello.kktls.test")
    i = capture(_recv_from(raw))
    check(i["client_version"] == "TLSv1.2" and i["record_version"] == "TLSv1", "versions")
    check(i["sni"] == ["hello.kktls.test"], "SNI parsed")
    check(i["hello_len"] == mlen and i["record_bytes"] == len(raw), "sizes")
    check(i["renego_scsv"] and not i["fallback_scsv"], "renegotiation SCSV, no fallback SCSV")
    raw, _ = _hello(version=0x0301, ciphers=(0xC014, 0x5600), sni=None)
    i = capture(_recv_from(raw))
    check(i["client_version"] == "TLSv1" and i["fallback_scsv"] and i["sni"] == [], "TLSv1 retry with 0x5600, no SNI")
    raw, mlen = _hello(sni="x.kktls.test", padding=200, record_split=50)
    i = capture(_recv_from(raw))
    check(i["padding_len"] == 200 and "padding" in i["extensions"], "padding extension")
    check(i["hello_len"] == mlen and i["record_bytes"] == len(raw), "two-record ClientHello reassembled")
    raw, _ = _hello(versions=(0x0A0A, 0x0304, 0x0303))
    i = capture(_recv_from(raw))
    check(i["supported_versions"] == ["0x0a0a", "TLSv1.3", "TLSv1.2"], "supported_versions with GREASE parsed")
    for sv, what in ((b"\x03\x03\x04\x03", "odd supported_versions list"),
                     (b"\x08\x03\x04", "overlong supported_versions list"),
                     (b"", "empty supported_versions extension")):
        raw, _ = _hello(extra=_ext(43, sv))
        try:
            capture(_recv_from(raw))
            check(False, "rejects " + what + " with ParseError")
        except ParseError:
            check(True, "rejects " + what + " with ParseError")
        except Exception as e:  # struct.error/IndexError escaping would stop serve() and kill an intolerant thread
            check(False, "rejects " + what + " with ParseError, not %s" % type(e).__name__)
    for bad, what in ((b"\x16\x03\x01\x00\x05\x01\x00\x00\x09\x03", "truncated"),
                      (b"\x15\x03\x01\x00\x02\x02\x28", "alert instead of hello"),
                      (b"\x80\x2e\x01\x03\x01", "SSLv2 hello")):
        try:
            capture(_recv_from(bad))
            check(False, "rejects " + what)
        except ParseError:
            check(True, "rejects " + what)

    # A real ClientHello from Python's ssl client, through the server loop on loopback.
    import io
    out = io.StringIO()
    s0 = socket.socket()
    s0.bind(("127.0.0.1", 0))
    port = s0.getsockname()[1]
    s0.close()
    t = threading.Thread(target=serve, args=("127.0.0.1", port, 2, 20, out))
    t.start()
    for _ in range(50):
        if out.getvalue():
            break
        threading.Event().wait(0.05)
    # connection 1: a malformed ClientHello (odd supported_versions) must be logged as an error, not stop the loop
    with socket.create_connection(("127.0.0.1", port), timeout=10) as c:
        c.sendall(_hello(extra=_ext(43, b"\x03\x03\x04\x03"))[0])
        try:
            c.recv(16)
        except OSError:
            pass
    ctx = ssl.create_default_context()
    err = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as c:
            with ctx.wrap_socket(c, server_hostname="probe.kktls.test"):
                pass
    except (ssl.SSLError, OSError) as e:
        err = e
    t.join(30)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    hello = [x for x in lines if "sni" in x]
    check(any(x.get("conn") == 1 and "supported_versions" in x.get("error", "") for x in lines),
          "serve logs a malformed ClientHello as an error line and keeps serving")
    check(err is not None and "HANDSHAKE_FAILURE" in str(err).upper(), "client got the handshake_failure alert")
    check(len(hello) == 1 and hello[0]["sni"] == ["probe.kktls.test"], "real ClientHello captured with SNI")
    check(bool(hello) and hello[0]["n_ciphers"] > 0 and hello[0]["record_bytes"] >= hello[0]["hello_len"] + 5,
          "real ClientHello sizes consistent")
    _selftest_intolerant(check)
    print("SELFTEST " + ("PASS" if not fails else "FAIL (%d)" % len(fails)))
    return 0 if not fails else 1


def _selftest_intolerant(check):
    """Python ssl clients against `intolerant`: a TLS 1.3 hello is dropped, a TLS 1.2-only one is served."""
    import io
    import shutil
    import subprocess
    import tempfile
    if not shutil.which("openssl"):
        print("skip intolerant loopback: no openssl CLI for the throwaway certificate")
        return
    with tempfile.TemporaryDirectory() as td:
        key, crt = td + "/k.pem", td + "/c.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj",
                        "/CN=probe.kktls.test", "-addext", "subjectAltName=DNS:probe.kktls.test", "-keyout", key,
                        "-out", crt], check=True, capture_output=True)
        s0 = socket.socket()
        s0.bind(("127.0.0.1", 0))
        port = s0.getsockname()[1]
        s0.close()
        out = io.StringIO()
        t = threading.Thread(target=intolerant, args=("127.0.0.1", port, 20, crt, key, "TLSv1.2", out, 2))
        t.start()
        for _ in range(50):
            if out.getvalue():
                break
            threading.Event().wait(0.05)
        results = []
        for maxv in (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2):
            ctx = ssl.create_default_context(cafile=crt)
            ctx.maximum_version = maxv
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=10) as c:
                    with ctx.wrap_socket(c, server_hostname="probe.kktls.test") as tc:
                        tc.sendall(b"GET / HTTP/1.0\r\nHost: probe.kktls.test\r\n\r\n")
                        results.append(tc.recv(4096))
            except (ssl.SSLError, OSError) as e:
                results.append(e)
        t.join(30)
        lines = [json.loads(x) for x in out.getvalue().splitlines() if '"action"' in x]
        check(isinstance(results[0], Exception) and len(lines) == 2 and lines[0]["action"] == "drop",
              "intolerant: a TLS 1.3 ClientHello is dropped")
        check(isinstance(results[1], bytes) and b"intolerant-ok TLSv1.2" in results[1] and lines[1]["action"] == "served"
              and lines[1]["version"] == "TLSv1.2", "intolerant: a TLS 1.2 ClientHello is served over TLSv1.2")


def main(argv):
    if argv[:1] == ["--selftest"]:
        return selftest()
    if argv[:1] == ["serve"]:
        import argparse
        ap = argparse.ArgumentParser(prog="clienthello_probe.py serve")
        ap.add_argument("--bind", default="127.0.0.1")
        ap.add_argument("--port", type=int, default=8443)
        ap.add_argument("--timeout", type=float, default=300, help="stop after S seconds without a connection")
        a = ap.parse_args(argv[1:])
        serve(a.bind, a.port, 0, a.timeout)
        return 0
    if argv[:1] == ["intolerant"]:
        import argparse
        ap = argparse.ArgumentParser(prog="clienthello_probe.py intolerant")
        ap.add_argument("--bind", default="127.0.0.1")
        ap.add_argument("--port", type=int, default=8444)
        ap.add_argument("--timeout", type=float, default=300, help="stop after S seconds without a connection")
        ap.add_argument("--cert", required=True)
        ap.add_argument("--key", required=True)
        ap.add_argument("--server-max", choices=("TLSv1.2", "TLSv1"), default="TLSv1.2")
        ap.add_argument("--curve", help="the only ECDHE curve of the server, e.g. prime256v1")
        a = ap.parse_args(argv[1:])
        intolerant(a.bind, a.port, a.timeout, a.cert, a.key, a.server_max, curve=a.curve)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
