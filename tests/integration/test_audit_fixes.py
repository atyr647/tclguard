#!/usr/bin/env python3
"""Regression tests for the findings of the hardening audits, end to end through a real guard process: trusted proxies are never struck, the
client address from X-Forwarded-For can not be forged, only websocket upgrades are tunnelled, absurd lengths and paths are refused, and
spoofed client-address headers never reach the backend. Run against source (default) or TG_CMD."""
import sys, os, time, socket
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

def banned(g):
    rc, out = g.ctl("bans"); return out

def bad_flood(port, n=40):
    for i in range(n):
        try: http_raw(port, b"GARBAGE\r\n\r\n", timeout=2)
        except OSError: pass

# ------------------------------------------------------------ with a trusted proxy in front
be = HttpBackend(); port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "trustedProxies": "127.0.0.1", "connRate": 100000, "maxConnsPerIP": 5000,
                   "reqRate": 100000, "reqWindow": 10, "pathLimits": "{^/login 100000 10}"}}, {"strikeThreshold": 6, "strikeLeakPerSec": 0, "banSteps": "{60 120}"})
try:
    g.start(); assert wait_port(port)
    bad_flood(port)
    time.sleep(1.2)
    r = get("/after", extra="X-Forwarded-For: 203.0.113.5\r\n", port=port)
    check("a trusted proxy that forwards garbage is not struck or banned: the next good request still passes", status(r) == 200, r[:80])
    check("...and it is not in the ban list", "127.0.0.1" not in banned(g), banned(g)[:200])

    r = get("/x", extra="X-Forwarded-For: 1.2.3.4, 9.9.9.9\r\n", port=port)
    check("client address = the rightmost entry that is not a trusted proxy", be.requests[-1][1].get("x-real-ip") == "9.9.9.9", be.requests[-1][1])
    r = get("/x", extra="X-Forwarded-For: 5.5.5.5, junk-here\r\n", port=port)
    check("an unreadable nearest entry means the header is not trusted (the peer address is kept, not a forged entry)", be.requests[-1][1].get("x-real-ip") == "127.0.0.1", be.requests[-1][1].get("x-real-ip"))

    n = len(be.requests)
    r = http_raw(port, b"GET /h2c HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\nConnection: close\r\n\r\n")
    q = be.requests[-1][1] if len(be.requests) > n else {}
    check("an h2c upgrade is never tunnelled (the backend never sees the Upgrade header)", "upgrade" not in q, q)
    check("...it is refused outright (400), not passed on", status(r) == 400 and len(be.requests) == n, r[:60])
    r = get("/ws-lookalike", extra="Upgrade: websocket\r\n", port=port)
    check("an Upgrade header without the Connection: Upgrade token is refused (guard and backend could disagree about it)", status(r) == 400, r[:60])

    n = len(be.requests)
    r = get("/len", extra="Content-Length: 99999999999999999999\r\n", port=port)
    check("an absurd Content-Length is refused, not forwarded", status(r) in (400, 413) and len(be.requests) == n, r[:60])
    r = http_raw(port, b"POST /len HTTP/1.1\r\nHost: x\r\nContent-Length: 4294967297\r\nConnection: close\r\n\r\nabc", timeout=3)
    check("a Content-Length that would wrap a 32-bit counter is refused", status(r) in (400, 413) and len(be.requests) == n, r[:60])

    r = get("/" + "%41" * 200, port=port)
    check("a path built from hundreds of escapes is refused cheaply", status(r) == 400, r[:60])
    r = get("/" + "a/./" * 300, port=port)
    check("...and so is one built from hundreds of segments", status(r) == 400, r[:60])
finally:
    g.cleanup(); be.stop()

# ------------------------------------------------------------ without one
be = HttpBackend(); port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "connRate": 100000, "maxConnsPerIP": 5000, "reqRate": 100000, "reqWindow": 10}},
          {"strikeThreshold": 6, "strikeLeakPerSec": 0, "banSteps": "{60 120}"})
try:
    g.start(); assert wait_port(port)
    r = get("/s", extra="X-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 7.7.7.7\r\nForwarded: for=8.8.8.8\r\n", port=port)
    q = be.requests[-1][1]
    check("without a trusted proxy a forged X-Real-IP is replaced by the real peer", q.get("x-real-ip") == "127.0.0.1", q.get("x-real-ip"))
    check("...and a forged X-Forwarded-For does not lead the chain", q.get("x-forwarded-for", "").startswith("127.0.0.1") or "6.6.6.6" not in q.get("x-forwarded-for", "").split(",")[-1], q.get("x-forwarded-for"))
    bad_flood(port)
    time.sleep(1.2)
    check("(control) the same garbage from an ordinary client DOES get it banned", "127.0.0.1" in banned(g), banned(g)[:200])
finally:
    g.cleanup(); be.stop()

sys.exit(summary())
