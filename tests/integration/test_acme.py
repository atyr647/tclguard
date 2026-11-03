#!/usr/bin/env python3
"""Automatic certificates: the guard orders a certificate from a real ACME server (Pebble, Let's Encrypt's
own test server) and serves it. Needs PEBBLE (binary) and PEBBLE_TESTDIR (pebble's test/ directory); skipped
when they are absent.   Build Pebble with:  go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest"""
import sys, time, socket, os, re, ssl, json, subprocess, shutil, tempfile, urllib.request
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

PEBBLE = os.environ.get("PEBBLE") or shutil.which("pebble")
TESTDIR = os.environ.get("PEBBLE_TESTDIR")
if not PEBBLE or not TESTDIR or not os.path.isdir(os.path.join(TESTDIR, "certs")):
    print("SKIP ACME tests: set PEBBLE and PEBBLE_TESTDIR (see the docstring)"); sys.exit(0)
OPENSSL = shutil.which("openssl")

def wait_until(fn, timeout=8, step=0.2):
    t = time.time() + timeout
    while time.time() < t:
        v = fn()
        if v: return v
        time.sleep(step)
    return None

work = tempfile.mkdtemp(prefix="tgpebble")
api, mgmt, httpp, tlsp = free_port(), free_port(), free_port(), free_port()
cfg = {"pebble": {"listenAddress": f"127.0.0.1:{api}", "managementListenAddress": f"127.0.0.1:{mgmt}",
                  "certificate": os.path.join(TESTDIR, "certs/localhost/cert.pem"), "privateKey": os.path.join(TESTDIR, "certs/localhost/key.pem"),
                  "httpPort": httpp, "tlsPort": tlsp, "ocspResponderURL": "", "externalAccountBindingRequired": False,
                  "domainBlocklist": ["blocked-domain.example"], "retryAfter": {"authz": 1, "order": 1}, "keyAlgorithm": "ecdsa",
                  "profiles": {"default": {"description": "default", "validityPeriod": 7776000}}}}
cfgf = os.path.join(work, "pebble.json"); json.dump(cfg, open(cfgf, "w"))
env = dict(os.environ, PEBBLE_VA_NOSLEEP="1")
plog = open(os.path.join(work, "pebble.log"), "w")
pb = subprocess.Popen([PEBBLE, "-config", cfgf], env=env, stdout=plog, stderr=subprocess.STDOUT)
minica = os.path.join(TESTDIR, "certs/pebble.minica.pem")
mctx = ssl.create_default_context(cafile=minica)

def pebble_up():
    try: urllib.request.urlopen(f"https://localhost:{api}/dir", context=mctx, timeout=2).read(); return True
    except Exception: return False

def client_ctx(cafile):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.load_verify_locations(cafile); return c

def https_fetch(port, cafile, path, host="localhost", verify=True):
    s = socket.create_connection(("127.0.0.1", port), 5)
    if verify: c = client_ctx(cafile)
    else:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    t = c.wrap_socket(s, server_hostname=host); t.settimeout(5)
    t.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    out = b""
    try:
        while True:
            d = t.recv(4096)
            if not d: break
            out += d
    except socket.timeout: pass
    t.close()
    return out

def tls_status(g):
    rc, out = g.ctl("tls"); return out

try:
    check("Pebble ACME server started", wait_until(pebble_up, 20) is True, open(os.path.join(work, "pebble.log")).read()[-300:])

    # ====================================================== successful issuance
    be = HttpBackend(); webport = httpp; secport = free_port()
    g = Guard({"web": {"type": "http", "port": webport, "backendPort": be.port, "challenge": "always", "redirectHttps": 1, "redirectPort": secport,
                       "connRate": 1000, "maxConnsPerIP": 400},
               "secure": {"type": "http", "port": secport, "backendPort": be.port, "tls": 1, "acme": 1, "tlsNames": "localhost",
                          "acmeEmail": "admin@example.com", "acmeDirectory": f"https://localhost:{api}/dir", "acmeCaFile": minica.replace("\\", "/"),
                          "connRate": 1000, "maxConnsPerIP": 400}}, {"strikeThreshold": 50})
    try:
        g.start(); assert wait_port(secport) and wait_port(webport)
        pem = os.path.join(g.dir, "certs", "secure.pem")
        check("the listener starts at once with a temporary self-signed certificate", os.path.exists(pem) and "self-signed certificate" in g.stderr())
        ok = wait_until(lambda: re.search(r"state\s+(ok|failed)", tls_status(g)), 90, 1)
        st = tls_status(g)
        check("a certificate is obtained from the CA (status: ok)", re.search(r"state\s+ok", st) is not None, st[-500:] + "\n" + g.stderr()[-800:])
        iss = subprocess.run([OPENSSL, "x509", "-in", pem, "-noout", "-issuer"], capture_output=True, text=True).stdout if OPENSSL else "Pebble"
        check("the installed certificate was issued by the CA, not by us", "Pebble" in iss, iss)
        check("the file holds a chain (leaf + intermediate) and the key", open(pem).read().count("BEGIN CERTIFICATE") >= 2 and "PRIVATE KEY" in open(pem).read())
        # verify with the CA's real root
        root = urllib.request.urlopen(f"https://localhost:{mgmt}/roots/0", context=mctx, timeout=5).read()
        rootf = os.path.join(work, "root.pem"); open(rootf, "wb").write(root)
        try: r = https_fetch(secport, rootf, "/secure")
        except Exception as e: r = repr(e).encode()
        check("browsers' view: the chain verifies against the CA root and the name matches", r is not None and b"ok:GET /secure" in r, r[:200] if r else r)
        check("the ACME order did not need a restart (served by the running listener)", g.proc.poll() is None)
        # the challenge path is only special while an order is running
        r = get("/.well-known/acme-challenge/NOTAREALTOKEN12345", host="localhost", port=webport)
        check("an unknown challenge token is not answered by the guard once nothing is pending (normal redirect)", status(r) == 308 and b"NOTAREALTOKEN" in r.split(b"\r\n\r\n")[0], r[:150])
        # plain-HTTP side: the cookie challenge is 'always' yet issuance succeeded, so validators bypass it;
        # an ordinary visitor gets the https redirect
        r = get("/a/b?c=1", host="localhost", port=webport)
        check("redirectHttps: plain HTTP is sent to https with the same path and query",
              status(r) == 308 and f"Location: https://localhost:{secport}/a/b?c=1".encode() in r, r[:200])
        r = http_raw(webport, b"HEAD /x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        check("redirect for HEAD has headers and no body", status(r) == 308 and r.endswith(b"\r\n\r\n"), r[:200])
        r = http_raw(webport, b"GET / HTTP/1.1\r\nHost: evil.example/\xff\r\nConnection: close\r\n\r\n")
        check("a hostile Host header is refused, never reflected into Location", status(r) in (400,) and b"evil" not in r.split(b"\r\n\r\n")[0], r[:200])
        r = http_raw(webport, b"GET / HTTP/1.1\r\nHost: a.example\r\nX: y\r\nConnection: close\r\n\r\n")
        check("redirect uses the visitor's Host", b"Location: https://a.example:" in r, r[:200])
        r = http_raw(webport, b"POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        check("non-GET requests are not redirected (they hit the normal pipeline)", status(r) != 308, r[:100])
        bad = [l for l in g.stderr().splitlines() if "background error" in l or "invalid command" in l or "can't read" in l]
        check("no Tcl errors in the guard log", not bad, bad[:3])
        check("ctl tls reports expiry", re.search(r"daysLeft\s+(8\d|9\d)", st) is not None, st[-300:])
    finally:
        g.cleanup(); be.stop()

    # ====================================================== failure: a name the CA cannot validate
    be = HttpBackend(); webport2 = httpp; secport = free_port()
    g = Guard({"web": {"type": "http", "port": webport2, "backendPort": be.port, "connRate": 1000, "maxConnsPerIP": 400},
               "secure": {"type": "http", "port": secport, "backendPort": be.port, "tls": 1, "acme": 1, "tlsNames": "nonexistent.invalid",
                          "acmeDirectory": f"https://localhost:{api}/dir", "acmeCaFile": minica.replace("\\", "/"), "connRate": 1000, "maxConnsPerIP": 400}}, {})
    try:
        g.start(); assert wait_port(secport)
        wait_until(lambda: re.search(r"state\s+failed", tls_status(g)), 60, 1)
        st = tls_status(g)
        check("an unvalidatable name ends as 'failed' with a reason", re.search(r"state\s+failed", st) is not None and ("no such host" in st or "DNS" in st or "validation" in st.lower()), st[-400:])
        try: r = https_fetch(secport, None, "/fallback", host="x", verify=False)
        except Exception as e: r = repr(e).encode()
        check("the site keeps working with the self-signed certificate while ordering fails", b"ok:GET /fallback" in r, r[:100])
        check("a retry is scheduled (back-off), not a tight loop", re.search(r"next\s+(\d{10})", st) is not None and int(re.search(r"next\s+(\d{10})", st).group(1)) > time.time() + 60, st[-300:])
        rc, out = g.ctl("tls", "renew", "secure")
        check("ctl tls renew clears the back-off", rc == 0 and "retry" in out, out)
        bad = [l for l in g.stderr().splitlines() if "background error" in l or "invalid command" in l or "can't read" in l]
        check("no Tcl errors in the guard log (failure path)", not bad, bad[:3])
    finally:
        g.cleanup(); be.stop()
finally:
    pb.terminate()
    try: pb.wait(5)
    except Exception: pb.kill()
    shutil.rmtree(work, ignore_errors=True)

sys.exit(summary())
