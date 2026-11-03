#!/usr/bin/env python3
"""Abuse a running guard in many ways, then check every internal table drains to empty."""
import sys, os, time, socket, struct, random, threading, re
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

def dbg(g):
    rc, out = g.ctl("debug")
    return {k: int(v) for k, v in re.findall(r"(\w+)\s+(\d+)", out)}

be = HttpBackend(); eb = TcpEcho(); ue = UdpEcho()
hp, tp, up = free_port(), free_port(), free_port()
g = Guard({"web": {"type": "http", "port": hp, "backendPort": be.port, "maxConnsPerIP": 100000, "connRate": 100000000, "reqRate": 100000000,
                   "headerTimeout": 2, "keepAliveTimeout": 3, "bodyTimeout": 2, "idleTimeout": 5, "maxBodyMB": 1},
           "tcp": {"type": "tcp", "port": tp, "backendPort": eb.port, "maxConnsPerIP": 100000, "connRate": 100000000, "firstByteTimeout": 2, "idleTimeout": 4},
           "udp": {"type": "udp", "port": up, "backendPort": ue.port, "sessionTimeout": 3, "pps": 1000000, "maxSessionsPerIP": 100000, "newSessionRate": 100000000}},
          {"strikeThreshold": 1000000, "logLevel": "warn", "maxConnections": 3000}).start()
rss = lambda: [int(l.split()[1]) for l in open(f"/proc/{g.proc.pid}/status") if l.startswith("VmRSS")][0] / 1024
try:
    base = dbg(g); rss0 = rss()
    print("baseline:", base, f"RSS {rss0:.1f} MB")
    rnd = random.Random(7)

    def abuse_http(n):
        for i in range(n):
            try:
                s = socket.create_connection(("127.0.0.1", hp), 2)
                kind = rnd.randrange(12)
                if kind == 0: pass                                                     # connect, say nothing
                elif kind == 1: s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")            # incomplete headers
                elif kind == 2: s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")       # complete, then leave
                elif kind == 3: s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\nabc")  # body stall
                elif kind == 4: s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel")  # chunk stall
                elif kind == 5: s.sendall(os.urandom(rnd.randrange(1, 3000)))          # garbage
                elif kind == 6: s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")  # upgrade
                elif kind == 7:
                    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n" * 5)                # pipelined
                elif kind == 8:                                                        # abortive close (RST)
                    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                elif kind == 9: s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); s.shutdown(socket.SHUT_WR)   # half-close
                elif kind == 10: s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2000000\r\n\r\n")    # too big
                else: s.sendall(b"GET /" + b"a" * 20000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")                   # URI too long
                if rnd.random() < 0.5: s.close()
                else: threading.Timer(rnd.random() * 2, s.close).start()
            except OSError: pass
    def abuse_tcp(n):
        for i in range(n):
            try:
                s = socket.create_connection(("127.0.0.1", tp), 2)
                k = rnd.randrange(5)
                if k == 1: s.sendall(b"hello")
                elif k == 2: s.sendall(os.urandom(200000))
                elif k == 3: s.sendall(b"x"); s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                elif k == 4: s.sendall(b"x"); s.shutdown(socket.SHUT_WR)
                if rnd.random() < 0.5: s.close()
                else: threading.Timer(rnd.random() * 2, s.close).start()
            except OSError: pass
    def abuse_udp(n):
        for i in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for _ in range(rnd.randrange(1, 4)): s.sendto(os.urandom(rnd.randrange(1, 1400)), ("127.0.0.1", up))
            s.close()
    def one_round():
        threads = [threading.Thread(target=f, args=(a,)) for f, a in ((abuse_http, 800), (abuse_http, 800), (abuse_tcp, 500), (abuse_udp, 400))]
        t0 = time.time(); [t.start() for t in threads]; [t.join() for t in threads]
        time.sleep(12)
        return time.time() - t0
    el = one_round(); rssA = rss(); print(f"round 1 took {el:.0f}s, RSS {rssA:.1f} MB")
    el = one_round(); rssB = rss(); print(f"round 2 took {el:.0f}s, RSS {rssB:.1f} MB")
    el = one_round(); rssC = rss(); print(f"round 3 took {el:.0f}s, RSS {rssC:.1f} MB")
    after = dbg(g); rss1 = rssC
    print("after drain:", after)
    leaks = {k: v for k, v in after.items() if k in ("tcpConns", "tcpPerIp", "httpState", "httpBuf", "udpSessions", "udpPerIp") and v != 0}
    check("all per-connection state drained after abuse (no leaked connection records)", not leaks, leaks)
    check("open channels return to baseline", after["openChannels"] <= base["openChannels"] + 2, (base["openChannels"], after["openChannels"]))
    check("memory is stable: round 3 adds < 5 MB over round 1 (no leak, only the allocator high-water mark)", rssC - rssA < 5, f"{rssA:.1f} -> {rssB:.1f} -> {rssC:.1f} MB")
    # and it still serves normally
    r = get("/ok", port=hp, timeout=5)
    check("still serves normal traffic after the abuse", status(r) == 200, r[:50])
    errs = [l for l in g.stderr().splitlines() if "background error" in l or "can't read" in l or "invalid command" in l]
    check("no Tcl errors logged during abuse", not errs, errs[:4])
    if errs: print("\n".join(g.stderr().splitlines()[-10:]))
finally:
    g.stop(); be.stop(); eb.stop(); ue.stop(); g.cleanup()
sys.exit(summary())
