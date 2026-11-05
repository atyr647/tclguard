#!/usr/bin/env python3
"""The control port: bounded input, the challenge-response login (the token never crosses the wire), a listener that cannot prove it knows the
token, newline injection from the client, and the connection table. Run against source (default) or TG_CMD."""
import sys, os, time, socket, subprocess, threading, hmac, hashlib, re, shutil
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

def rss_mb(pid):
    try:
        for l in open(f"/proc/{pid}/status"):
            if l.startswith("VmRSS:"): return int(l.split()[1]) / 1024
    except OSError: pass
    return -1

def line(s, timeout=20):
    s.settimeout(timeout); d = b""
    while not d.endswith(b"\n"):
        c = s.recv(4096)
        if not c: break
        d += c
    return d.decode(errors="replace").strip()

be = HttpBackend(); port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port}}, {})
TOK = g.token
try:
    g.start()
    rc, out = g.ctl("status"); check("ctl works with the challenge-response login", rc == 0 and "TclGuard" in out or rc == 0, out[:80])

    # --- the old plain-token login is gone, and a correct HELLO/PROOF works by hand
    s = socket.create_connection(("127.0.0.1", g.ctlport), 5)
    s.sendall(f"AUTH {TOK}\nstatus\n".encode()); r1 = line(s)
    check("the old 'AUTH <token>' login is refused", r1.startswith("ERR"), r1); s.close()
    s = socket.create_connection(("127.0.0.1", g.ctlport), 5)
    cn = "ab" * 12
    s.sendall(f"HELLO {cn}\n".encode()); ch = line(s)
    m = re.match(r"CHALLENGE ([0-9a-f]{16,64}) ([0-9a-f]{64})$", ch)
    check("HELLO is answered with a challenge", bool(m), ch)
    if m:
        sn, sp = m.groups()
        check("...whose server proof is the HMAC of both nonces under the token", hmac.compare_digest(sp, hmac.new(TOK.encode(), f"S:{cn}:{sn}".encode(), hashlib.sha256).hexdigest()))
        s.sendall(f"PROOF {'0' * 64}\nstatus\n".encode()); bad = line(s)
        check("a wrong proof is refused", bad.startswith("ERR"), bad)
        s.close()
        s = socket.create_connection(("127.0.0.1", g.ctlport), 5)
        s.sendall(f"HELLO {cn}\n".encode()); m = re.match(r"CHALLENGE ([0-9a-f]+) ([0-9a-f]{64})$", line(s)); sn = m.group(1)
        s.sendall(f"PROOF {hmac.new(TOK.encode(), f'C:{cn}:{sn}'.encode(), hashlib.sha256).hexdigest()}\nping\n".encode())
        a = line(s); b = line(s)
        check("a correct proof is accepted and commands run", a.startswith("OK") and b.startswith("OK"), (a, b))
    s.close()

    # --- a line that never ends: bounded, and the guard stays responsive while it is attacked
    r0 = rss_mb(g.proc.pid); stop = threading.Event(); drops = []
    def flood():
        try:
            s = socket.create_connection(("127.0.0.1", g.ctlport), 5); blob = b"A" * 65536; n = 0
            while not stop.is_set():
                s.sendall(blob); n += 1
                if n > 4000: break
        except OSError: drops.append(1)
    ts = [threading.Thread(target=flood, daemon=True) for _ in range(6)]
    for t in ts: t.start()
    time.sleep(1.5)
    t0 = time.time(); rc, out = g.ctl("status"); took = time.time() - t0
    check("while 6 clients stream endless bytes without a newline, a real client is still served", rc == 0, out[:100])
    check("...promptly", took < 3, took)
    time.sleep(1.5); stop.set()
    for t in ts: t.join(5)
    r1 = rss_mb(g.proc.pid)
    check("the endless lines were cut off (every flooding connection was dropped)", len(drops) >= 5, len(drops))
    if r0 > 0: check("...and the guard's memory did not balloon", r1 - r0 < 60, (r0, r1))

    # --- the connection table: filling it with idle unauthenticated connections must not lock a real client out
    idle = []
    for i in range(40):
        try: idle.append(socket.create_connection(("127.0.0.1", g.ctlport), 5))
        except OSError: break
    rc, out = g.ctl("status"); check("with the table full of idle unauthenticated connections a real client still gets in", rc == 0, out[:100])
    for c in idle: c.close()
    # unauthenticated connections do not linger
    s = socket.create_connection(("127.0.0.1", g.ctlport), 5); t0 = time.time(); s.settimeout(12)
    try: d = s.recv(10)
    except socket.timeout: d = None
    check("an unauthenticated connection is closed by the guard within about 5 s", d == b"" and time.time() - t0 < 9, (d, time.time() - t0)); s.close()

    # --- the client refuses a line break in an argument (it would be a second command)
    rc, out = g.ctl("ban", "203.0.113.50", 600, "reason\nunbanall"); check("a line break in a ctl argument is refused by the client", rc != 0 and "control characters" in out, out[:150])
    rc, out = g.ctl("bans"); check("...and nothing was banned or unbanned by it", "203.0.113.50" not in out, out[:150])
finally:
    g.cleanup()

# --- a squatter that took the control port: the client must not hand it the token, and must say so
squat = socket.socket(); squat.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); squat.bind(("127.0.0.1", 0)); squat.listen(5)
sqport = squat.getsockname()[1]; seen = []
def serve():
    while True:
        try: c, _ = squat.accept()
        except OSError: return
        c.settimeout(3)
        try:
            while True:
                d = c.recv(4096)
                if not d: break
                seen.append(d)
                c.sendall(b"CHALLENGE " + b"0" * 16 + b" " + b"1" * 64 + b"\n")
        except OSError: pass
        c.close()
threading.Thread(target=serve, daemon=True).start()
g2 = Guard({}, {"controlPort": sqport})
try:
    rc, out = g2.ctl("status")
    got = b"".join(seen).decode(errors="replace")
    check("ctl refuses a listener that cannot prove it knows the token", rc != 0 and "did not prove" in out, out[:200])
    check("...and the token was never sent to it", g2.token not in got and "AUTH" not in got, got[:200])
finally:
    squat.close(); shutil.rmtree(g2.dir, ignore_errors=True)
sys.exit(summary())
