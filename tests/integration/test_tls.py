#!/usr/bin/env python3
"""TLS termination: real handshakes against the guard with Python's ssl module (and openssl s_client)."""
import sys, time, socket, os, re, ssl, subprocess, shutil, threading
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

def wait_until(fn, timeout=8, step=0.1):
    t = time.time() + timeout
    while time.time() < t:
        if fn(): return True
        time.sleep(step)
    return False

def client_ctx(cafile=None, minv=None, maxv=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if cafile: ctx.load_verify_locations(cafile)
    else: ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    if minv: ctx.minimum_version = minv
    if maxv: ctx.maximum_version = maxv
    return ctx

def https_raw(port, data, cafile=None, timeout=5, minv=None, maxv=None, sni="localhost"):
    s = socket.create_connection(("127.0.0.1", port), timeout)
    t = client_ctx(cafile, minv, maxv).wrap_socket(s, server_hostname=sni)
    t.settimeout(timeout)
    if data: t.sendall(data)
    out = b""
    try:
        while True:
            d = t.recv(65536)
            if not d: break
            out += d
    except (socket.timeout, ssl.SSLError, ConnectionResetError, OSError): pass
    try: t.close()
    except Exception: pass
    return out

def https_get(port, path="/", cafile=None, extra="", **kw):
    return https_raw(port, f"GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n".encode(), cafile, **kw)

def handshake_ok(port, cafile=None, **kw):
    try:
        s = socket.create_connection(("127.0.0.1", port), 5)
        t = client_ctx(cafile, kw.get("minv"), kw.get("maxv")).wrap_socket(s, server_hostname="localhost")
        v = t.version(); t.close(); return v
    except (ssl.SSLError, OSError) as e:
        return None

def closed_quickly(port, wait=3):
    """Connection opened, nothing sent: True if the server closes it within `wait` seconds."""
    s = socket.create_connection(("127.0.0.1", port), 3); s.settimeout(wait)
    try:
        d = s.recv(100); s.close(); return d == b""
    except socket.timeout: s.close(); return False
    except OSError: return True

OPENSSL = shutil.which("openssl")

# ============================================================ managed (self-signed) certificate
be = HttpBackend(); port = free_port()
g = Guard({"secure": {"type": "http", "port": port, "backendPort": be.port, "tls": 1, "connRate": 1000, "maxConnsPerIP": 400,
                      "reqRate": 5000, "tlsHandshakeTimeout": 3, "tlsMaxHandshaking": 6, "headerTimeout": 4}},
          {"strikeThreshold": 8, "strikeLeakPerSec": 0, "banSteps": "{30 60}"})
try:
    g.start(); assert wait_port(port)
    crt = os.path.join(g.dir, "certs", "secure.pem")
    check("a certificate (with its key) was generated in the state folder", os.path.exists(crt) and b"PRIVATE KEY" in open(crt, "rb").read())
    check("the key file is not world-readable", os.name == "nt" or (os.stat(crt).st_mode & 0o077) == 0)

    r = https_get(port, "/hello", cafile=crt)
    check("HTTPS request is served and the certificate verifies (SAN localhost)", status(r) == 200 and b"ok:GET /hello" in r, r[:100])
    q = be.requests[-1][1]
    check("backend still receives plain HTTP with the real client address", q.get("x-real-ip") == "127.0.0.1", q)
    check("X-Forwarded-Proto: https is passed to the backend", q.get("x-forwarded-proto") == "https", q)

    check("TLS 1.3 works", handshake_ok(port, crt, minv=ssl.TLSVersion.TLSv1_3) == "TLSv1.3")
    check("TLS 1.2 works", handshake_ok(port, crt, maxv=ssl.TLSVersion.TLSv1_2) == "TLSv1.2")
    # TLS 1.0/1.1 must be refused. Modern client libraries often cannot even try; use openssl with a low security level.
    if OPENSSL:
        for ver in ("tls1", "tls1_1"):
            p = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{port}", f"-{ver}", "-cipher", "DEFAULT@SECLEVEL=0"],
                               input=b"", capture_output=True, timeout=15)
            out = (p.stdout + p.stderr).decode("latin1")
            refused_old = ("Cipher is (NONE)" in out or "no protocols available" in out or "alert" in out.lower()
                           or "unsupported" in out.lower() or "Cipher    : 0000" in out or "handshake failure" in out)
            check(f"{ver} is refused", refused_old, out[-200:])
    rejected = False
    try:
        ctx = ssl.create_default_context()
        s = socket.create_connection(("127.0.0.1", port), 5); ctx.wrap_socket(s, server_hostname="localhost")
    except ssl.SSLError: rejected = True
    check("a default (verifying) client rejects the untrusted self-signed certificate", rejected)
    check("...and that is not treated as abuse (no strikes/ban)", "banned" not in g.ctl("bans")[1].lower() or "127.0.0.1" not in g.ctl("bans")[1])

    # ---- bodies, framing, keep-alive, pipelining through TLS ----
    body = os.urandom(1_500_000)
    n0 = len(be.requests)
    r = https_raw(port, b"POST /up HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body, crt, timeout=20)
    check("1.5 MB upload over TLS arrives intact", status(r) == 200 and be.requests[n0:] and len(be.requests[-1][2]) == len(body) and be.requests[-1][2] == body)
    n0 = len(be.requests)
    r = https_raw(port, b"GET /a HTTP/1.1\r\nHost: l\r\n\r\nGET /b HTTP/1.1\r\nHost: l\r\n\r\nGET /c HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n", crt)
    check("pipelined requests over TLS are all answered in order", r.count(b"HTTP/1.1 200") == 3 and r.index(b"GET /a") < r.index(b"GET /b") < r.index(b"GET /c"), r[:300])
    r = https_raw(port, b"POST / HTTP/1.1\r\nHost: l\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", crt)
    check("request smuggling attempt is refused inside TLS as well", status(r) == 400, r[:80])
    s = socket.create_connection(("127.0.0.1", port), 5)
    t = client_ctx(crt).wrap_socket(s, server_hostname="localhost"); t.settimeout(5)
    ok = 0
    for i in range(5):
        t.sendall(b"GET /k%d HTTP/1.1\r\nHost: l\r\n\r\n" % i)
        d = b""
        while b"ok:GET" not in d: d += t.recv(4096)
        ok += 1
    t.close()
    check("keep-alive: 5 requests on one TLS connection", ok == 5)

    # ---- abuse ----
    plain = http_raw(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", 4)
    check("plain HTTP sent to the TLS port is never answered with page content", b"ok:GET" not in plain and b"HTTP/1.1 200" not in plain, plain[:80])
    t0 = time.time(); silent = closed_quickly(port, wait=6)
    check("a client that never starts the handshake is cut off at tlsHandshakeTimeout (3 s)", silent and time.time() - t0 < 5.5, time.time() - t0)

    # handshake cap: 6 allowed in flight, the rest are refused immediately
    held = []
    for i in range(20):
        try:
            s = socket.create_connection(("127.0.0.1", port), 3); s.settimeout(0.01); held.append(s)
        except OSError: pass
    time.sleep(0.5)
    dead = 0
    for s in held:
        try:
            s.settimeout(0.05)
            d = s.recv(10)
            if d == b"": dead += 1
        except socket.timeout: pass
        except OSError: dead += 1
    check("handshake cap: at most 6 half-open handshakes are kept (14 of 20 refused)", dead >= 12, dead)
    for s in held:
        try: s.close()
        except Exception: pass
    time.sleep(4)   # let the survivors time out; their strikes are counted against 127.0.0.1

    # garbage that is not TLS earns strikes and finally a ban, and then costs no handshake at all
    for i in range(14):
        try:
            s = socket.create_connection(("127.0.0.1", port), 3); s.sendall(os.urandom(200)); time.sleep(0.15); s.close()
        except OSError: break
    wait_until(lambda: "127.0.0.1" in g.ctl("bans")[1], 6)
    check("repeated non-TLS garbage leads to a ban", "127.0.0.1" in g.ctl("bans")[1], g.ctl("bans")[1])
    t0 = time.time()
    try:
        s = socket.create_connection(("127.0.0.1", port), 3); s.settimeout(3)
        try: d = s.recv(100)
        except socket.timeout: d = b"timeout"
        s.close()
    except OSError: d = b""
    check("a banned address is dropped before any handshake (no ServerHello)", d == b"" and time.time() - t0 < 1.5, (d, time.time() - t0))
    bad = [l for l in g.stderr().splitlines() if "background error" in l or "invalid command" in l or "can't read" in l or "wrong # args" in l]
    check("no Tcl errors in the guard log", not bad, bad[:3])
finally:
    g.cleanup(); be.stop()

# ============================================================ provided certificate + hot reload + min version 1.3
if OPENSSL:
    be = HttpBackend(); port = free_port()
    d = tempfile.mkdtemp(prefix="tgcert")
    def mk(cn, name):
        subprocess.run([OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "30",
                        "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn},DNS:localhost,IP:127.0.0.1",
                        "-keyout", os.path.join(d, name + ".key"), "-out", os.path.join(d, name + ".crt")], capture_output=True, check=True)
    mk("first.test", "a"); mk("second.test", "b")
    shutil.copy(os.path.join(d, "a.crt"), os.path.join(d, "live.crt")); shutil.copy(os.path.join(d, "a.key"), os.path.join(d, "live.key"))
    g = Guard({"secure": {"type": "http", "port": port, "backendPort": be.port, "tls": 1, "tlsMinVersion": "1.3", "connRate": 1000, "maxConnsPerIP": 400,
                          "tlsCert": fwd(os.path.join(d, "live.crt")), "tlsKey": fwd(os.path.join(d, "live.key"))}}, {})
    try:
        g.start(); assert wait_port(port)
        def peer_cn():
            s = socket.create_connection(("127.0.0.1", port), 5)
            t = client_ctx(None).wrap_socket(s, server_hostname="localhost")
            der = t.getpeercert(binary_form=True); t.close()
            return subprocess.run([OPENSSL, "x509", "-inform", "DER", "-noout", "-subject"], input=der, capture_output=True).stdout.decode()
        check("provided certificate is the one served", "first.test" in peer_cn(), peer_cn())
        check("tlsMinVersion 1.3 refuses TLS 1.2", handshake_ok(port, None, maxv=ssl.TLSVersion.TLSv1_2) is None)
        check("tlsMinVersion 1.3 accepts TLS 1.3", handshake_ok(port, None, minv=ssl.TLSVersion.TLSv1_3) == "TLSv1.3")
        shutil.copy(os.path.join(d, "b.crt"), os.path.join(d, "live.crt")); shutil.copy(os.path.join(d, "b.key"), os.path.join(d, "live.key"))
        check("replacing the certificate files takes effect for new connections without a restart", "second.test" in peer_cn(), peer_cn())
        # a real three-level chain (root -> intermediate -> leaf) in one file, like a CA delivers it
        def run(*a, **k): subprocess.run(list(a), capture_output=True, check=True, **k)
        ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
        run(OPENSSL, "req", "-x509", *ec, "-days", "30", "-subj", "/CN=Test Root", "-keyout", d + "/root.key", "-out", d + "/root.pem", "-addext", "basicConstraints=critical,CA:TRUE")
        run(OPENSSL, "req", "-new", *ec, "-subj", "/CN=Test Intermediate", "-keyout", d + "/int.key", "-out", d + "/int.csr")
        open(d + "/int.ext", "w").write("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")
        run(OPENSSL, "x509", "-req", "-in", d + "/int.csr", "-CA", d + "/root.pem", "-CAkey", d + "/root.key", "-CAcreateserial", "-days", "30", "-out", d + "/int.pem", "-extfile", d + "/int.ext")
        run(OPENSSL, "req", "-new", *ec, "-subj", "/CN=localhost", "-keyout", d + "/leaf.key", "-out", d + "/leaf.csr")
        open(d + "/leaf.ext", "w").write("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n")
        run(OPENSSL, "x509", "-req", "-in", d + "/leaf.csr", "-CA", d + "/int.pem", "-CAkey", d + "/int.key", "-CAcreateserial", "-days", "30", "-out", d + "/leaf.pem", "-extfile", d + "/leaf.ext")
        open(d + "/live.crt", "wb").write(open(d + "/leaf.pem", "rb").read() + open(d + "/int.pem", "rb").read())
        shutil.copy(d + "/leaf.key", d + "/live.key")
        p = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{port}", "-showcerts", "-CAfile", d + "/root.pem", "-verify_hostname", "localhost"],
                           input=b"", capture_output=True, timeout=15)
        out = (p.stdout + p.stderr).decode("latin1")
        check("a CA-style chain file (leaf + intermediate): the whole chain is sent", out.count("BEGIN CERTIFICATE") >= 2, out.count("BEGIN CERTIFICATE"))
        check("...so a client that only trusts the root verifies it (no missing-intermediate error)", "Verify return code: 0 (ok)" in out, out[-300:])
    finally:
        g.cleanup(); be.stop(); shutil.rmtree(d, ignore_errors=True)

    # a certificate/key mismatch must refuse to start the listener, never fall back to plaintext
    be = HttpBackend(); port = free_port(); d = tempfile.mkdtemp(prefix="tgcert")
    mk("one.test", "a"); mk("two.test", "b")
    g = Guard({"secure": {"type": "http", "port": port, "backendPort": be.port, "tls": 1,
                          "tlsCert": fwd(os.path.join(d, "a.crt")), "tlsKey": fwd(os.path.join(d, "b.key"))}}, {})
    try:
        g.start()
        time.sleep(1)
        check("mismatched certificate and key: listener does not start (and never serves plaintext)", not wait_port(port, 1.5), g.stderr()[-300:])
        check("...and the reason is logged", "certificate/key problem" in g.stderr() or "not started" in g.stderr(), g.stderr()[-300:])
    finally:
        g.cleanup(); be.stop(); shutil.rmtree(d, ignore_errors=True)

# ============================================================ raw TCP listener with TLS termination (e.g. a TLS game/chat port)
echo = TcpEcho(); port = free_port()
g = Guard({"tcpsec": {"type": "tcp", "port": port, "backendPort": echo.port, "tls": 1, "connRate": 1000, "maxConnsPerIP": 400}}, {})
try:
    g.start(); assert wait_port(port)
    crt = os.path.join(g.dir, "certs", "tcpsec.pem")
    s = socket.create_connection(("127.0.0.1", port), 5)
    t = client_ctx(crt).wrap_socket(s, server_hostname="localhost"); t.settimeout(5)
    t.sendall(b"hello over tls"); d = t.recv(100)
    check("tcp listener terminates TLS and relays plain bytes to the backend", d == b"hello over tls" and echo.received and echo.received[0] == b"hello over tls", d)
    t.close()
finally:
    g.cleanup(); echo.stop()

# ============================================================ renegotiation abuse (TLS 1.2): must not be a CPU lever
if OPENSSL and os.name != "nt":
    import pty, select
    be = HttpBackend(); port = free_port()
    g = Guard({"secure": {"type": "http", "port": port, "backendPort": be.port, "tls": 1, "connRate": 1000, "maxConnsPerIP": 400}}, {})
    try:
        g.start(); assert wait_port(port)
        def cpu(pid):
            f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
            return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
        have_proc = os.path.exists(f"/proc/{g.proc.pid}/stat")
        pid, fd = pty.fork()
        if pid == 0:
            os.execvp(OPENSSL, [OPENSSL, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_2"])
        buf = b""
        def pump(t):
            global buf
            end = time.time() + t
            while time.time() < end:
                r, _, _ = select.select([fd], [], [], 0.05)
                if r:
                    try: d = os.read(fd, 65536)
                    except OSError: return False
                    if not d: return False
                    buf += d
            return True
        pump(2.0)
        c0 = cpu(g.proc.pid) if have_proc else 0; t0 = time.time(); alive = True
        while time.time() - t0 < 6 and alive:
            try: os.write(fd, b"R\n")
            except OSError: alive = False
            alive = pump(0.02) and alive
        c1 = cpu(g.proc.pid) if have_proc else 0
        n = buf.decode("latin1").count("RENEGOTIATING")
        try: os.kill(pid, 9); os.waitpid(pid, 0)
        except Exception: pass
        check("client-initiated renegotiation is not serviced repeatedly (<= 3 in 6 s)", n <= 3, n)
        check("...and costs the guard almost no CPU", c1 - c0 < 1.0, c1 - c0)
    finally:
        g.cleanup(); be.stop()

sys.exit(summary())
