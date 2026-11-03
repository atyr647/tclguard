#!/usr/bin/env python3
"""Regression tests for every bug the fuzzer found (plus the replayed minimised reproducers in corpus/).

  python3 tests/fuzz/test_regressions.py

Part 1: targeted checks against a live guard (explicit expectations, same style as tests/integration/test_http.py).
Part 2: every tests/fuzz/corpus/*.json is replayed in-process against the real Tcl parser and against a live
        guard with the full oracle set (reference parser, lenient-variant differential, identity, trailers);
        a reproducer must now produce no finding at all.
"""
import glob
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "integration"))
from harness import Guard, HttpBackend, check, free_port, http_raw, status, summary, wait_port   # noqa: E402
import gen        # noqa: E402
import inproc     # noqa: E402
import live as L  # noqa: E402


def cpu_ms(pid):
    return L.Proc(pid).cpu_ms()


def targeted():
    be = HttpBackend()
    port = free_port()
    g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "reqRate": 1000000, "connRate": 1000000, "maxConnsPerIP": 1000,
                       "headerTimeout": 2, "keepAliveTimeout": 4, "bodyTimeout": 3, "challenge": "off"}},
              {"strikeThreshold": 1000000})
    try:
        g.start()
        assert wait_port(port)

        def refused(name, raw, code=400):
            n0 = len(be.requests)
            r = http_raw(port, raw, timeout=3)
            check(name, status(r) == code and len(be.requests) == n0, (r[:50], [q[0] for q in be.requests[n0:]]))

        def passes(name, raw):
            n0 = len(be.requests)
            r = http_raw(port, raw, timeout=3)
            check(name, status(r) == 200 and len(be.requests) == n0 + 1, (r[:50], len(be.requests) - n0))

        POST = b"POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        # --- request line: TAB is not a delimiter
        refused("TAB inside the request target is refused", b"GET /a\tb HTTP/1.1\r\nHost: x\r\n\r\n")
        refused("TAB-smuggled HTTP/1.0 version (parser differential) is refused",
                b"POST /\tHTTP/1.0 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n")
        # --- chunk extensions are validated
        for nm, ext in (("unterminated quote", b';a="b'), ("quote spanning the line break", b';a="x'), ("control byte", b";a=\x01"),
                        ("space inside", b";a=b c"), ("NUL", b";a=b\x00c"), ("lone semicolon value", b";=b"), ("tab", b";a=b\tc"),
                        ("trailing garbage after quote", b';a="b"c')):
            refused("chunk extension refused: " + nm, POST + b"1" + ext + b"\r\nx\r\n0\r\n\r\n")
        for nm, ext in (("token", b";a=b"), ("bare name", b";a"), ("quoted", b';a="b c"'), ("two", b";a=b;c=d"), ("escaped quote", b';a="b\\"c"')):
            passes("chunk extension accepted: " + nm, POST + b"1" + ext + b"\r\nx\r\n0\r\n\r\n")
        # --- trailers: framing / routing / identity fields are not trailers
        for t in (b"Content-Length: 5", b"Transfer-Encoding: chunked", b"Host: evil", b"X-Forwarded-For: 6.6.6.6", b"X-Real-IP: 6.6.6.6",
                  b"Forwarded: for=6.6.6.6", b"Connection: close", b"Upgrade: websocket", b"content-length: 0"):
            refused("forbidden trailer refused: " + t.split(b":")[0].decode(), POST + b"1\r\nx\r\n0\r\n" + t + b"\r\n\r\n")
        passes("ordinary trailer still accepted", POST + b"1\r\nx\r\n0\r\nX-Checksum: abc\r\n\r\n")
        # --- '_' spellings of framing headers
        refused("Content_Length header refused", b"POST / HTTP/1.1\r\nHost: x\r\nContent_Length: 5\r\n\r\nabcde")
        refused("Transfer_Encoding header refused", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer_Encoding: chunked\r\n\r\n0\r\n\r\n")
        passes("other underscore headers are fine", b"GET / HTTP/1.1\r\nHost: x\r\nX_Custom_Header: 1\r\nConnection: close\r\n\r\n")
        # --- Connection naming protected fields (hop-by-hop stripping downstream)
        for tok in (b"Content-Length", b"close, X-Real-IP", b"x_forwarded_for", b"Transfer-Encoding", b"Host", b"Forwarded"):
            refused("Connection: %s refused" % tok.decode(), b"POST / HTTP/1.1\r\nHost: x\r\nConnection: %s\r\nContent-Length: 3\r\n\r\nabc" % tok)
        passes("Connection: keep-alive, close still fine", b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        # --- 16..127-byte chunks were unmetered and cost ~75 us each: 2000 of them per request now
        c0 = cpu_ms(g.proc.pid)
        refused("flood of 16-byte chunks is cut off", POST + (b"10\r\n" + b"x" * 16 + b"\r\n") * 4000 + b"0\r\n\r\n")
        spent = cpu_ms(g.proc.pid) - c0
        check("...and costs bounded CPU (was ~0.3 s for 4000 chunks, unbounded for more)", spent < 400, "%.0f ms" % spent)
        passes("chunks of 128 bytes and up are never counted", POST + (b"80\r\n" + b"x" * 128 + b"\r\n") * 2500 + b"0\r\n\r\n")
        # --- Content-Length with leading zeros: octal (strtol base 0) readers see another length
        refused("Content-Length: 010 refused (octal-reading backend would see 8)", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 010\r\n\r\n0123456789")
        refused("Content-Length: 00 refused", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 00\r\n\r\n")
        passes("Content-Length: 0 still fine", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        passes("Content-Length: 10 still fine", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789")
        # --- CPU: a long plain header value used to cost ~0.4 s (quadratic lazy regexp)
        c0 = cpu_ms(g.proc.pid)
        for _ in range(3):
            http_raw(port, b"GET / HTTP/1.1\r\nHost: x\r\nX-Long: " + b"a" * 16000 + b"\r\nConnection: close\r\n\r\n", timeout=5)
        spent = cpu_ms(g.proc.pid) - c0
        check("16 KB header value x3 costs little CPU (was 0.4 s each)", spent < 300, "%.0f ms" % spent)
    finally:
        g.stop()
        be.stop()
        g.cleanup()


def trusted_chain():
    """Behind a trusted proxy the client address chain must keep the order of the client's X-Forwarded-For lines
    and must not absorb spoofed spellings."""
    be = HttpBackend()
    port = free_port()
    g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "reqRate": 1000000, "connRate": 1000000, "maxConnsPerIP": 1000,
                       "challenge": "off", "trustedProxies": "127.0.0.1"}}, {"strikeThreshold": 1000000})
    try:
        g.start()
        assert wait_port(port)

        def seen(extra):
            n0 = len(be.requests)
            http_raw(port, b"GET / HTTP/1.1\r\nHost: x\r\n" + extra + b"Connection: close\r\n\r\n", timeout=3, read_until_close=False)
            q = be.requests[n0:]
            return (q[0][1].get("x-forwarded-for"), q[0][1].get("x-real-ip")) if q else (None, None)

        check("trusted proxy: one X-Forwarded-For line -> chain + peer", seen(b"X-Forwarded-For: 1.1.1.1\r\n") == ("1.1.1.1, 127.0.0.1", "1.1.1.1"), seen(b"X-Forwarded-For: 1.1.1.1\r\n"))
        r = seen(b"X-Forwarded-For: 1.1.1.1\r\nX-Forwarded-For: 2.2.2.2\r\n")
        check("trusted proxy: two X-Forwarded-For lines keep their order", r == ("1.1.1.1, 2.2.2.2, 127.0.0.1", "2.2.2.2"), r)
        r = seen(b"X_Forwarded_For: 9.9.9.9\r\nX-Forwarded-For: 3.3.3.3\r\n")
        check("trusted proxy: X_Forwarded_For spelling is dropped, not merged into the chain", r == ("3.3.3.3, 127.0.0.1", "3.3.3.3"), r)
        r = seen(b"X-Real-IP: 9.9.9.9\r\nForwarded: for=9.9.9.9\r\nX-Forwarded-For: 3.3.3.3\r\n")
        check("trusted proxy: client X-Real-IP / Forwarded still replaced", r == ("3.3.3.3, 127.0.0.1", "3.3.3.3"), r)
    finally:
        g.stop()
        be.stop()
        g.cleanup()


def path_limits():
    """Per-path limits must see the path the way the backend does (%XX, //, dot segments, ;params, backslash)."""
    be = HttpBackend()
    port = free_port()
    names = ["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8"]
    g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "reqRate": 1000000, "connRate": 1000000, "maxConnsPerIP": 1000,
                       "challenge": "off", "pathLimits": " ".join("{^/%s 3 30}" % n for n in names)}},
              {"strikeThreshold": 1000000})
    try:
        g.start()
        assert wait_port(port)
        variants = {"a1": "//a1", "a2": "/%61%32", "a3": "/./a3", "a4": "/x/../a4", "a5": "/%2e/a5", "a6": "/\\a6", "a7": "/a/%2e%2e/a7", "a8": "/a8"}
        for n, p in variants.items():
            codes = []
            for i in range(6):
                r = http_raw(port, ("GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % p).encode(), timeout=3, read_until_close=False)
                codes.append(status(r))
            check("path limit still applies to %s (-> /%s)" % (p, n), 429 in codes, codes)
    finally:
        g.stop()
        be.stop()
        g.cleanup()


def corpus():
    files = sorted(glob.glob(os.path.join(HERE, "corpus", "*.json")))
    if not files:
        return
    workers = {}
    lives = {}
    try:
        for p in files:
            case, meta = gen.case_from_json(open(p).read())
            name = os.path.basename(p)[:-5]
            cfg = meta.get("config", "default")
            upg = int(meta.get("upg", 0))
            if cfg not in workers:
                workers[cfg] = inproc.Worker(cfg)
            w = workers[cfg]
            pieces, end = inproc.flatten(case)
            res = w.run([(pieces, end, upg)])[0]
            import collections
            fs = inproc.evaluate(w, case, upg, res, True, collections.Counter())
            check("corpus/%s: in-process parser is clean" % name, not fs, [f.detail[:100] for f in fs])
            variant = meta.get("variant", "default")
            if variant.startswith("inproc:"):
                variant = variant.split(":", 1)[1]
            if variant not in lives:   # (setdefault would build, and start a guard for, a new Live on EVERY case)
                lives[variant] = L.Live(variant if variant in L.VARIANTS else "default")
            lv = lives[variant]
            fs = lv.submit(case)
            check("corpus/%s: live guard is clean" % name, not fs, [f.detail[:100] for f in fs])
        for lv in lives.values():
            fs, _ = lv.check_batch_state("corpus")
            check("corpus: tables drain, no log errors, guard alive", not fs, [f.detail[:100] for f in fs])
    finally:
        for w in workers.values():
            w.close()
        for lv in lives.values():   # (each one owns a live guard and its backend: leaving them running leaks processes)
            try: lv.close()
            except Exception: pass
        for lv in lives.values():
            lv.close()


if __name__ == "__main__":
    targeted()
    trusted_chain()
    path_limits()
    corpus()
    sys.exit(summary())
