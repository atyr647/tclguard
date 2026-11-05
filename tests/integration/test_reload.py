#!/usr/bin/env python3
"""Reload and configuration safety: a bad or empty file never replaces the running configuration, control-port settings are applied on reload,
command-line overrides are not written to the file, weak tokens are rejected, and bans cannot cover the allowlist."""
import sys, os, time, re, socket, hmac, hashlib, subprocess
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

def conf_text(g): return open(g.conf).read()
def set_general(g, key, value):
    t = conf_text(g)
    if re.search(rf"^[ \t]+{key} .*$", t, re.M): t = re.sub(rf"^[ \t]+{key} .*$", f"    {key} {value}", t, flags=re.M)
    else: t = t.replace("general {\n", f"general {{\n  {key} {value}\n", 1)
    open(g.conf, "w").write(t)
def listeners(g):
    rc, out = g.ctl("listeners"); return out
def raw(g, cmd, token=None):
    """One control command with the handshake done by hand (the ctl client reads its token from the very file these tests damage)."""
    import hmac as _h, hashlib as _hl
    tok = (token or g.token).encode(); cn = "ef" * 12
    s = socket.create_connection(("127.0.0.1", g.ctlport), 5); s.settimeout(8)
    buf = [b""]
    def rl():      # exactly one line (replies can arrive coalesced in one segment)
        while b"\n" not in buf[0]:
            c = s.recv(4096)
            if not c: break
            buf[0] += c
        ln, _, buf[0] = buf[0].partition(b"\n")
        return ln.decode().strip()
    s.sendall(f"HELLO {cn}\n".encode()); m = re.match(r"CHALLENGE ([0-9a-f]+) ([0-9a-f]{64})", rl()); sn = m.group(1)
    s.sendall(f"PROOF {_h.new(tok, f'C:{cn}:{sn}'.encode(), _hl.sha256).hexdigest()}\n{cmd}\n".encode())
    a = rl(); b = rl(); s.close()
    return (0 if b.startswith("OK") else 1), b

be = HttpBackend(); port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port}}, {})
good = None
try:
    g.start(); assert wait_port(port)
    good = conf_text(g)
    before = listeners(g)
    check("baseline: the listener runs", "web" in before, before[:100])

    # --- reload refuses what is not a valid configuration, and leaves the running one alone
    open(g.conf, "w").write("")
    rc, out = raw(g, "reload"); check("an EMPTY config file is refused on reload", rc != 0 and "empty" in out, out[:160])
    open(g.conf, "w").write("# only a comment\n")
    rc, out = raw(g, "reload"); check("a file with nothing but comments is refused too", rc != 0, out[:160])
    rc, out = raw(g, "listeners")
    check("...the control port and the listener are untouched", rc == 0 and "web" in out and status(get("/", port=port)) == 200, out[:100])
    open(g.conf, "w").write(good.replace("listeners {", "listeners {\n  broken { type http port 99999 backendPort 1 }\n", 1))
    rc, out = g.ctl("reload"); check("an invalid config (port 99999) is refused on reload", rc != 0 and "not changed" in out, out[:200])
    open(g.conf, "w").write(good)
    rc, out = g.ctl("allow", "203.0.113.77"); check("...and later edits still work (the invalid one never became the running config)", rc == 0, out[:160])
    rc, out = g.ctl("listeners"); check("...and the invalid listener is not 'protecting' anything", "99999" not in out, out[:200])
    os.remove(g.conf)
    rc, out = raw(g, "reload"); check("a MISSING config file is refused on reload", rc != 0 and "does not exist" in out, out[:160])
    open(g.conf, "w").write(good)
    set_general(g, "stateDir", g.dir.replace("\\", "/"))

    # --- weak or malformed control settings are rejected by validation
    for key, val, word in (("controlToken", "abc", "too short"), ("controlHost", "not.an.address", "controlHost")):
        sav = conf_text(g); set_general(g, key, val)
        p = subprocess.run([*TG, "check", "--config", g.conf], capture_output=True, text=True, timeout=30)
        check(f"'tclguard check' rejects {key} {val!r}", p.returncode != 0 and word in (p.stdout + p.stderr), (p.stdout + p.stderr)[:200])
        open(g.conf, "w").write(sav)

    # --- bans may not cover the allowlist or be absurdly wide
    rc, out = g.ctl("allow", "10.0.0.0/8"); rc, out = g.ctl("allow", "127.0.0.0/8")
    for target, why in (("10.1.0.0/16", "inside an allow-listed range"), ("10.0.0.0/7", "covering an allow-listed range"), ("0.0.0.0/0", "everything"), ("127.0.0.0/8", "loopback"), ("2000::/3", "a huge IPv6 range")):
        rc, out = g.ctl("ban", target, 60, "test"); check(f"ctl ban {target} is refused ({why})", rc != 0, out[:160])
    rc, out = g.ctl("ban", "198.51.100.0/24", 60, "test"); check("an ordinary /24 ban is accepted", rc == 0, out[:160])

    # --- control settings are applied on reload: a rotated token drops old sessions and is the only one that works afterwards
    s = socket.create_connection(("127.0.0.1", g.ctlport), 5)
    def hello(sock, token):
        cn = "cd" * 12; sock.sendall(f"HELLO {cn}\n".encode()); sock.settimeout(5)
        d = b""
        while not d.endswith(b"\n"): d += sock.recv(4096)
        m = re.match(r"CHALLENGE ([0-9a-f]+) ([0-9a-f]{64})", d.decode()); sn = m.group(1)
        return cn, sn, hmac.new(token.encode(), f"C:{cn}:{sn}".encode(), hashlib.sha256).hexdigest(), hmac.compare_digest(m.group(2), hmac.new(token.encode(), f"S:{cn}:{sn}".encode(), hashlib.sha256).hexdigest())
    cn, sn, pr, srv_ok = hello(s, g.token)
    s.sendall(f"PROOF {pr}\nping\n".encode()); time.sleep(0.5)
    first = b""
    s.settimeout(3)
    while first.count(b"\n") < 2: first += s.recv(4096)
    check("an open authenticated session works before the token is rotated", first.count(b"OK") == 2, first)
    newtok = "n" * 40
    oldtok = g.token
    set_general(g, "controlToken", newtok); g.token = newtok
    rc, out = raw(g, "reload", oldtok); check("reload with a rotated token succeeds (told the old token that the running guard still uses)", rc == 0, out[:160])
    time.sleep(1.5)
    s.settimeout(3)
    try: gone = s.recv(4096) == b""
    except (socket.timeout, OSError): gone = False
    check("the session opened with the OLD token is dropped after the rotation", gone)
    s2 = socket.create_connection(("127.0.0.1", g.ctlport), 5)
    cn, sn, pr, srv_ok = hello(s2, "t" * 32)
    check("the old token no longer matches the server's proof", not srv_ok, srv_ok)
    s2.close()
    rc, out = g.ctl("status"); check("the new token works", rc == 0, out[:100])
    # control disabled on reload: the port closes
    set_general(g, "controlEnable", "0")
    rc, out = g.ctl("reload"); check("reload with controlEnable 0 is accepted", rc == 0, out[:100])
    time.sleep(1.5)
    try: socket.create_connection(("127.0.0.1", g.ctlport), 2).close(); up = True
    except OSError: up = False
    check("...and the control port is closed afterwards", not up)
finally:
    g.cleanup()

# --- command-line overrides stay out of the saved file and survive a reload
be = HttpBackend(); port = free_port(); ctl = free_port()
d = __import__("tempfile").mkdtemp(prefix="tgov")
conf = os.path.join(d, "tg.conf")
open(conf, "w").write("general {\n  controlPort %d\n  controlToken %s\n  stateDir %s\n  logLevel info\n  firewall auto\n  allowlist {}\n}\nlisteners {\n  web { type http port %d backendPort %d }\n}\n" % (ctl, "k" * 32, d.replace("\\", "/"), port, be.port))
proc = subprocess.Popen([*TG, "--config", conf, "--headless", "--no-firewall", "--verbose"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
try:
    assert wait_port(ctl, 20)
    r = subprocess.run([*TG, "ctl", "--config", conf, "allow", "198.51.100.1"], capture_output=True, text=True, timeout=30); check("ctl allow works", r.returncode == 0, r.stdout + r.stderr)
    t = open(conf).read()
    check("--no-firewall is not written into the config file", re.search(r"^\s*firewall auto\s*$", t, re.M) is not None and "firewall none" not in t, t[:300])
    check("--verbose is not written into the config file", "logLevel debug" not in t)
    r = subprocess.run([*TG, "ctl", "--config", conf, "reload"], capture_output=True, text=True, timeout=30); check("reload works", r.returncode == 0, r.stdout + r.stderr)
    r = subprocess.run([*TG, "ctl", "--config", conf, "fw", "status"], capture_output=True, text=True, timeout=30)
    check("after a reload the guard still obeys --no-firewall", "enabled 1" not in r.stdout and "installed 1" not in r.stdout, r.stdout[:200])
finally:
    proc.terminate()
    try: proc.wait(8)
    except Exception: proc.kill()
    __import__("shutil").rmtree(d, ignore_errors=True)
sys.exit(summary())
