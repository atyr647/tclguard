#!/usr/bin/env python3
"""Repeats the keep-alive pattern that stalled once in CI (test_tls.py: 5 requests on one TLS connection), on plain HTTP and
on TLS, many times over, and reports how many connections stalled. Usage: stress_keepalive.py [connections] [seconds-limit]"""
import sys, time, socket, os, ssl
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

N = int(sys.argv[1]) if len(sys.argv) > 1 else 300
LIMIT = float(sys.argv[2]) if len(sys.argv) > 2 else 240
be = HttpBackend(); tport = free_port(); pport = free_port()
g = Guard({"secure": {"type": "http", "port": tport, "backendPort": be.port, "tls": 1, "connRate": 100000, "maxConnsPerIP": 4000,
                      "reqRate": 1000000, "tlsHandshakeTimeout": 3, "tlsMaxHandshaking": 64, "headerTimeout": 4},
           "plain": {"type": "http", "port": pport, "backendPort": be.port, "connRate": 100000, "maxConnsPerIP": 4000, "reqRate": 1000000}},
          {"strikeThreshold": 1000, "strikeLeakPerSec": 0, "banSteps": "{30 60}"})
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

class OutOfPorts(Exception): pass

def session(port, tls, n=5):
    try: s = socket.create_connection(("127.0.0.1", port), 5)
    except OSError as e: raise OutOfPorts(str(e))      # (this machine's ephemeral ports are used up: stop, that is not a guard fault)
    if tls: s = ctx.wrap_socket(s, server_hostname="localhost")
    s.settimeout(4)
    try:
        for i in range(n):
            s.sendall(b"GET /k%d HTTP/1.1\r\nHost: l\r\n\r\n" % i)
            d = b""
            while b"ok:GET" not in d:
                c = s.recv(4096)
                if not c: return f"closed at request {i}"
                d += c
        return None
    except socket.timeout: return f"STALL at request {i}"
    except (OSError, ssl.SSLError) as e: return f"error at request {i}: {e}"
    finally:
        try: s.close()
        except Exception: pass

try:
    g.start(); assert wait_port(tport) and wait_port(pport)
    t0 = time.time(); done = {"plain": 0, "tls": 0}; bad = []
    try:
        for k in range(N):
            for name, port, tls in (("tls", tport, True), ("plain", pport, False)):
                r = session(port, tls); done[name] += 1
                if r: bad.append((name, k, r)); print("FAIL", name, k, r, flush=True)
            if time.time() - t0 > LIMIT or len(bad) >= 5: break
    except OutOfPorts as e: print("stopped early, out of local ports:", e)
    el = time.time() - t0
    print(f"{done['tls']} TLS and {done['plain']} plain sessions of 5 requests in {el:.0f} s; stalled or failed: {len(bad)}")
    check("no keep-alive session stalled (TLS and plain)", not bad, bad[:5])
    err = [l for l in g.stderr().splitlines() if "error" in l.lower() and "http reject" not in l.lower()]
    check("no Tcl errors in the guard log", not err, err[:3])
finally:
    g.cleanup()
sys.exit(summary())
