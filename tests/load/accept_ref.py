#!/usr/bin/env python3
"""What the operating system itself can do: a blocking accept-and-close loop in one thread (no Tcl). Usage: accept_ref.py port seconds
Also: accept_ref.py backlog port  -> connect to a listener nobody accepts from and count how many connections the OS queues."""
import socket, sys, time, threading
if sys.argv[1] == "backlog":
    port = int(sys.argv[2]); ok = 0; t0 = time.time()
    while time.time() - t0 < 25:
        s = socket.socket(); s.settimeout(1.0)
        try: s.connect(("127.0.0.1", port)); ok += 1; keep = globals().setdefault("keep", []); keep.append(s)
        except OSError as e:
            print(f"backlog: {ok} connections queued before the first failure ({e})"); break
        if ok >= 20000: print("backlog: more than 20000 queued"); break
    sys.exit(0)
port, secs = int(sys.argv[1]), float(sys.argv[2])
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", port)); ls.listen(socket.SOMAXCONN)
ls.settimeout(0.5); n = 0; t0 = time.time()
while time.time() - t0 < secs:
    try: c, _ = ls.accept()
    except socket.timeout: continue
    n += 1; c.close()
print(f"python    {n / (time.time() - t0):8.0f} connections accepted and closed per second (blocking accept loop, one thread)")
