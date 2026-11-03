#!/usr/bin/env python3
"""Tcl 8.6 waits for events with select(): a descriptor numbered 1024 or more aborts the whole process
("bit out of range 0 - FD_SETSIZE on fd_set"). With a RAISED open-files limit (what 'LimitNOFILE=65536' or
'ulimit -n 20000' gives) the guard used to plan for tens of thousands of connections and an attacker holding
~1000 connections killed it. Now it caps itself regardless of the limit. Unix only."""
import sys, os, socket, time, resource
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

if os.name == "nt":
    print("SKIP fd-limit test: Unix only (Windows' event loop has no 1024 descriptor ceiling)"); sys.exit(0)
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
want = 20000 if hard == resource.RLIM_INFINITY else min(20000, hard)
resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))        # inherited by the guard and its children
check("the test runs with a RAISED open-files limit", resource.getrlimit(resource.RLIMIT_NOFILE)[0] >= 4096, resource.getrlimit(resource.RLIMIT_NOFILE))

be = HttpBackend(); port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "maxConns": 100000, "maxConnsPerIP": 100000,
                   "connRate": 1000000, "headerTimeout": 120, "idleTimeout": 300}}, {"allowlist": "{127.0.0.0/8}", "maxConnections": 0})
socks = []
try:
    g.start(); assert wait_port(port)
    for i in range(1300):
        try: socks.append(socket.create_connection(("127.0.0.1", port), 3))
        except OSError: break
    time.sleep(1.5)
    check("opened more than 1100 connections without the guard dying", len(socks) > 1100 and g.proc.poll() is None, (len(socks), g.proc.poll()))
    # how many of them does it actually hold? the rest were refused (closed) at the global cap
    held = 0
    for s in socks:
        s.settimeout(0.01)
        try:
            d = s.recv(1)
            if d == b"": continue
        except socket.timeout: pass
        except OSError: continue
        held += 1
    check("it holds a bounded number (the global cap) and refuses the rest", 100 < held < 600, held)
    check("the cap is logged as a warning that does NOT tell people to raise the limit", "ulimit" not in g.stderr() and "FD_SETSIZE" not in g.stderr(), g.stderr()[-300:])
    for s in socks: s.close()
    socks = []
    time.sleep(1.0)
    r = get("/after", port=port)
    check("after the connections are gone it serves normally again", status(r) == 200 and g.proc.poll() is None, (r[:60], g.proc.poll()))
    check("no abort, no Tcl errors in the guard log", "bit out of range" not in g.stderr() and "background error" not in g.stderr(), g.stderr()[-300:])
finally:
    for s in socks:
        try: s.close()
        except Exception: pass
    g.cleanup(); be.stop()
sys.exit(summary())
