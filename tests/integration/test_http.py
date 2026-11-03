#!/usr/bin/env python3
import sys, time, socket, os, threading
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

be = HttpBackend()
port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "reqRate": 60, "reqWindow": 10, "maxConnsPerIP": 12,
                   "connRate": 100, "headerTimeout": 2, "keepAliveTimeout": 4, "bodyTimeout": 3, "maxBodyMB": 2,
                   "pathLimits": "{^/login 3 10}"}},
          {"strikeThreshold": 100000})   # high: we test parser/limit behaviour without bans interfering
try:
    g.start(); assert wait_port(port)

    # ---- normal traffic ----
    r = get("/hello?a=1", port=port)
    check("GET passes through", status(r) == 200 and b"ok:GET /hello?a=1" in r, r[:120])
    last = be.requests[-1]
    check("X-Forwarded-For / X-Real-IP set to client", last[1].get("x-forwarded-for") == "127.0.0.1" and last[1].get("x-real-ip") == "127.0.0.1", last[1])
    r = get("/", extra="X-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\n", port=port)
    check("client-supplied X-Forwarded-For spoof is replaced", be.requests[-1][1].get("x-forwarded-for") == "127.0.0.1" and be.requests[-1][1].get("x-real-ip") == "127.0.0.1", be.requests[-1][1])

    body = b"x" * 5000
    r = http_raw(port, b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n" + body)
    check("POST body forwarded byte-exact", status(r) == 200 and be.requests[-1][2] == body and b":5000" in r)

    chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    r = http_raw(port, b"POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + chunked)
    check("chunked body forwarded and framed", status(r) == 200 and be.requests[-1][2] == b"hello world", (r, be.requests[-1]))

    # keep-alive: 3 sequential requests on one connection
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
    okc = 0
    for i in range(3):
        s.sendall(f"GET /k{i} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        d = b""
        while b"ok:GET /k%d" % i not in d: d += s.recv(4096)
        okc += 1
    s.close()
    check("keep-alive: 3 requests on one connection", okc == 3)

    # pipelining: 3 requests in one write
    before = len(be.requests)
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
    s.sendall(b"".join(f"GET /pipe{i} HTTP/1.1\r\nHost: x\r\n\r\n".encode() for i in range(3)))
    d = b""
    t = time.time()
    while d.count(b"ok:GET /pipe") < 3 and time.time() - t < 5: d += s.recv(4096)
    s.close()
    check("pipelined requests all answered in order", d.count(b"ok:GET /pipe") == 3, d)

    # large body: 1.5MB passes, 3MB (> maxBodyMB 2) rejected
    big = os.urandom(1_500_000)
    r = http_raw(port, b"POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(big) + big, timeout=15)
    check("1.5 MB upload passes intact", status(r) == 200 and be.requests[-1][2] == big)
    r = http_raw(port, b"POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: 3000000\r\nConnection: close\r\n\r\n", timeout=5)
    check("oversize Content-Length -> 413", status(r) == 413, r[:60])

    # ---- malformed / smuggling ----
    cases = [
      ("bare-LF header block",       b"GET / HTTP/1.1\nHost: x\n\n", 400),
      ("CL + TE together",           b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400),
      ("TE not exactly chunked",     b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 400),
      ("TE obfuscated",              b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: xchunked\r\n\r\n", 400),
      ("conflicting Content-Length", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcd", 400),
      ("non-numeric Content-Length", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4abc\r\n\r\n", 400),
      ("negative Content-Length",    b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n", 400),
      ("unknown method",             b"BREW / HTTP/1.1\r\nHost: x\r\n\r\n", 405),
      ("CONNECT",                    b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n", 405),
      ("absolute-form URI",          b"GET http://evil.com/ HTTP/1.1\r\nHost: x\r\n\r\n", 400),
      ("missing Host (1.1)",         b"GET / HTTP/1.1\r\n\r\n", 400),
      ("duplicate Host",             b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", 400),
      ("obs-fold header",            b"GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n  folded\r\n\r\n", 400),
      ("space before colon",         b"GET / HTTP/1.1\r\nHost : x\r\n\r\n", 400),
      ("NUL in header",              b"GET / HTTP/1.1\r\nHost: x\r\nX-A: a\x00b\r\n\r\n", 400),
      ("bad version",                b"GET / HTTP/2.0\r\nHost: x\r\n\r\n", 400),
      ("garbage",                    b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\r\n\r\n", 400),
      ("URI too long",               b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\nHost: x\r\n\r\n", 414),
      ("bad chunk size",             b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n", 400),
      ("bad chunk terminator",       b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n", 400),
    ]
    for name, raw, want in cases:
        r = http_raw(port, raw, timeout=4)
        check(f"reject: {name} -> {want}", status(r) == want, r[:70])
    # nothing malformed reached the backend
    check("backend never saw a malformed request", not any(b"evil.com" in (q[0].encode()) for q in be.requests))

    r = http_raw(port, b"GET / HTTP/1.1\r\nHost: x\r\n" + b"X-H: " + b"a" * 20000 + b"\r\n\r\n", timeout=4)
    check("oversize headers -> 431", status(r) == 431, r[:60])
    hdrs = b"".join(b"X-%d: v\r\n" % i for i in range(150))
    r = http_raw(port, b"GET / HTTP/1.1\r\nHost: x\r\n" + hdrs + b"\r\n", timeout=4)
    check("too many headers -> 431", status(r) == 431, r[:60])

    # ---- smuggling attempt end-to-end: second request hidden in body must stay a body ----
    n0 = len(be.requests)
    smug = b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"
    r = http_raw(port, b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(smug) + smug, timeout=3)
    reqs = be.requests[n0:]
    check("request hidden inside a body is treated as body (1 request seen)", len(reqs) == 1 and reqs[0][2] == smug, reqs)

    # ---- timeouts ----
    t = time.time()
    s = socket.create_connection(("127.0.0.1", port), 10); s.settimeout(10)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")        # never finishes
    d = b""
    try:
        while True:
            x = s.recv(4096)
            if not x: break
            d += x
    except socket.timeout: pass
    el = time.time() - t
    check("slowloris (incomplete headers) -> 408 within headerTimeout", status(d) == 408 and el < 5.5, (d[:40], round(el, 1)))
    s.close()

    # trickling: 1 byte per 0.5s must also be cut at headerTimeout (not extended by activity)
    t = time.time()
    s = socket.create_connection(("127.0.0.1", port), 10); s.settimeout(0.2)
    data = b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: " + b"a" * 200
    closed = False
    for ch in data:
        try:
            s.sendall(bytes([ch])); time.sleep(0.4)
        except OSError: closed = True; break
        try:
            if s.recv(100) == b"": closed = True; break
        except socket.timeout: pass
        except OSError: closed = True; break
        if time.time() - t > 8: break
    el = time.time() - t
    check("byte-trickle slowloris cut off near headerTimeout (2s)", closed and el < 6, round(el, 1))
    s.close()

    t = time.time()
    s = socket.create_connection(("127.0.0.1", port), 10); s.settimeout(10)
    d = s.recv(10) if True else b""
    el = time.time() - t
    check("connect-and-say-nothing is dropped after headerTimeout", d == b"" and 1.5 < el < 5, round(el, 1))
    s.close()

    t = time.time()
    s = socket.create_connection(("127.0.0.1", port), 10); s.settimeout(12)
    s.sendall(b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nabc")   # slow-POST stalls
    try: d = s.recv(10)
    except socket.timeout: d = b"TIMEOUT"
    el = time.time() - t
    check("slow-POST (body stalls) closed after bodyTimeout (3s)", d == b"" and el < 8, (d, round(el, 1)))
    s.close()

    # ---- per-IP concurrent connection cap (maxConnsPerIP 12) ----
    held = []
    for i in range(20):
        try:
            c = socket.create_connection(("127.0.0.1", port), 3); c.settimeout(0.8); held.append(c)
        except OSError: pass
    time.sleep(0.4)
    alive = 0
    for c in held:
        try:
            c.sendall(b"GET /cap HTTP/1.1\r\nHost: x\r\n\r\n")
            if status(c.recv(200)) == 200: alive += 1
        except OSError: pass
    for c in held: c.close()
    check("per-IP concurrent connection cap enforced (cap 12 of 20)", alive == 12, alive)
    time.sleep(0.3)

    # ---- rate limits (let the 10 s window from earlier requests drain first) ----
    time.sleep(11)
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
    codes = []
    try:
        for i in range(200):
            s.sendall(f"GET /f{i} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            d = b""
            while b"\r\n\r\n" not in d: 
                x = s.recv(4096)
                if not x: raise EOFError
                d += x
            codes.append(status(d))
            if status(d) == 429: break
            # drain body
            time.sleep(0.002)
    except (EOFError, OSError): pass
    check("per-IP request-rate limit answers 429", 429 in codes, codes[-3:])
    check("limit kicks in near configured rate (60/10s)", 50 <= len(codes) <= 75, len(codes))
    s.close()
    time.sleep(0.2)

finally:
    g.stop(); be.stop()
    print("--- guard log tail ---"); print("\n".join(g.stderr().splitlines()[-12:]))
    g.cleanup()
sys.exit(summary())
