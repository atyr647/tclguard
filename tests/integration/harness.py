"""Shared helpers for TclGuard integration tests (real sockets, real processes)."""
import os, socket, subprocess, sys, threading, time, tempfile, shutil, json, re, select

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MAIN = os.path.join(ROOT, "tclguard.vfs", "main.tcl")
# How to start TclGuard. Default: tclsh8.6 on the source tree. CI sets TG_CMD to a starpack
# (e.g. TG_CMD="releases/tclguard-linux-x86_64") or to a different interpreter
# (TG_CMD="/opt/homebrew/opt/tcl-tk/bin/tclsh8.6 tclguard.vfs/main.tcl").
import shlex
TG = shlex.split(os.environ["TG_CMD"], posix=(os.name != "nt")) if os.environ.get("TG_CMD") else ["tclsh8.6", MAIN]
NO_UDP = bool(os.environ.get("TG_NO_UDP"))
def fwd(p): return p.replace("\\", "/")
results = []

def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    d = str(detail)
    d = d if len(d) < 240 else d[:240] + "..."
    print(("PASS " if cond else "FAIL ") + name + (f"   [{d}]" if (detail != "" and not cond) else ""), flush=True)
    return bool(cond)

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def have_ipv6():
    try:
        s = socket.socket(socket.AF_INET6); s.bind(("::1", 0)); s.close(); return True
    except OSError: return False

def family(host): return socket.AF_INET6 if ":" in host else socket.AF_INET

def wait_port(port, timeout=8, host="127.0.0.1"):
    t = time.time() + timeout
    while time.time() < t:
        try:
            socket.create_connection((host, port), 0.3).close(); return True
        except OSError: time.sleep(0.1)
    return False

# ------------------------------------------------------------- backends ----
class HttpBackend:
    """Tiny threaded HTTP/1.1 server that records what it receives."""
    def __init__(self, port=None, close_after=False, host="127.0.0.1"):
        self.close_after = close_after
        self.port = port or free_port()
        self.requests = []          # raw header blocks + bodies
        self.lock = threading.Lock()
        self.sock = socket.socket(family(host)); self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, self.port)); self.sock.listen(256)
        self.running = True
        threading.Thread(target=self.loop, daemon=True).start()
    def loop(self):
        while self.running:
            try: c, _ = self.sock.accept()
            except OSError: return
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()
    def handle(self, c):
        buf = b""
        c.settimeout(10)
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d: return
                    buf += d
                head, _, buf = buf.partition(b"\r\n\r\n")
                lines = head.decode("latin1").split("\r\n")
                hdrs = {}
                for l in lines[1:]:
                    k, _, v = l.partition(":"); hdrs[k.strip().lower()] = v.strip()
                body = b""
                if hdrs.get("transfer-encoding", "").lower() == "chunked":
                    while True:
                        while b"\r\n" not in buf:
                            buf += c.recv(65536)
                        line, _, buf = buf.partition(b"\r\n")
                        n = int(line.split(b";")[0], 16)
                        if n == 0:
                            while b"\r\n" not in buf: buf += c.recv(65536)
                            _, _, buf = buf.partition(b"\r\n"); break
                        while len(buf) < n + 2: buf += c.recv(65536)
                        body += buf[:n]; buf = buf[n + 2:]
                else:
                    n = int(hdrs.get("content-length", "0"))
                    while len(buf) < n: buf += c.recv(65536)
                    body, buf = buf[:n], buf[n:]
                with self.lock: self.requests.append((lines[0], hdrs, body))
                if hdrs.get("upgrade", "").lower() == "websocket":
                    c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                    while True:
                        d = c.recv(65536)
                        if not d: return
                        c.sendall(b"echo:" + d)
                resp = b"ok:" + lines[0].encode() + b":" + str(len(body)).encode()
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(resp) + resp)
                if self.close_after or hdrs.get("connection", "").lower() == "close": return   # like a real server
        except Exception: pass
        finally:
            try: c.close()
            except Exception: pass
    def stop(self):
        self.running = False
        try: self.sock.shutdown(socket.SHUT_RDWR)   # wakes the blocked accept() so the port is really released
        except Exception: pass
        try: self.sock.close()
        except Exception: pass

class TcpEcho:
    def __init__(self, port=None, speak_first=None, host="127.0.0.1"):
        self.port = port or free_port(); self.received = []; self.speak_first = speak_first
        self.sock = socket.socket(family(host)); self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, self.port)); self.sock.listen(256)
        self.running = True
        threading.Thread(target=self.loop, daemon=True).start()
    def loop(self):
        while self.running:
            try: c, _ = self.sock.accept()
            except OSError: return
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()
    def handle(self, c):
        try:
            if self.speak_first: c.sendall(self.speak_first)
            while True:
                d = c.recv(65536)
                if not d: break
                self.received.append(d); c.sendall(d)
        except Exception: pass
        finally:
            try: c.close()
            except Exception: pass
    def stop(self):
        self.running = False
        try: self.sock.shutdown(socket.SHUT_RDWR)   # wakes the blocked accept() so the port is really released
        except Exception: pass
        try: self.sock.close()
        except Exception: pass

class UdpEcho:
    def __init__(self, port=None, host="127.0.0.1"):
        self.port = port or free_port(); self.count = 0; self.sources = set()
        self.sock = socket.socket(family(host), socket.SOCK_DGRAM); self.sock.bind((host, self.port))
        self.running = True
        threading.Thread(target=self.loop, daemon=True).start()
    def loop(self):
        while self.running:
            try: d, a = self.sock.recvfrom(65535)
            except Exception: return
            self.count += 1; self.sources.add(a)
            try: self.sock.sendto(b"echo:" + d, a)
            except Exception: pass
    def stop(self):
        self.running = False
        try: self.sock.shutdown(socket.SHUT_RDWR)   # wakes the blocked accept() so the port is really released
        except Exception: pass
        try: self.sock.close()
        except Exception: pass

# ------------------------------------------------------------- tclguard ----
class Guard:
    def __init__(self, listeners, general=None, keep_dir=None):
        self.dir = keep_dir or tempfile.mkdtemp(prefix="tgtest")
        self.conf = os.path.join(self.dir, "tg.conf")
        self.ctlport = free_port()
        self.token = "t" * 32
        g = {"firewall": "none", "allowlist": "{}", "controlPort": self.ctlport, "controlToken": self.token,
             "stateDir": fwd(self.dir), "logLevel": "debug", "learnTrusted": 1}
        g.update(general or {})
        text = "general {\n" + "".join(f"  {k} {v}\n" for k, v in g.items()) + "}\nlisteners {\n"
        for name, spec in listeners.items():
            text += f"  {name} {{\n" + "".join(f"    {k} {{{v}}}\n" if isinstance(v, str) and " " in v else f"    {k} {v}\n" for k, v in spec.items()) + "  }\n"
        text += "}\n"
        open(self.conf, "w").write(text)
        self.proc = None
        self.log = []
    def start(self):
        self.logf = open(os.path.join(self.dir, "stderr.log"), "a")
        self.proc = subprocess.Popen([*TG, "--config", self.conf, "--headless", *([] if os.environ.get("TG_FIREWALL") else ["--no-firewall"])], stdout=self.logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        if not wait_port(self.ctlport, 10):
            raise RuntimeError(f"TclGuard did not start (exit status: {self.proc.poll()}):\n" + self.stderr())
        return self
    def stderr(self):
        try: return open(os.path.join(self.dir, "stderr.log")).read()
        except Exception: return ""
    def ctl(self, *args):
        r = subprocess.run([*TG, "ctl", "--config", self.conf, *map(str, args)], capture_output=True, text=True, timeout=30)
        return r.returncode, (r.stdout + r.stderr)
    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try: self.proc.wait(5)
            except subprocess.TimeoutExpired: self.proc.kill()
    def cleanup(self):
        self.stop(); shutil.rmtree(self.dir, ignore_errors=True)

# ----------------------------------------------------------- http client ----
def http_raw(port, data, timeout=5, read_until_close=True, host="127.0.0.1"):
    """Send raw bytes, return everything received until close/timeout."""
    s = socket.create_connection((host, port), timeout)
    s.settimeout(timeout)
    if data: s.sendall(data)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            out += d
            if not read_until_close and b"\r\n\r\n" in out: break
    except (socket.timeout, ConnectionResetError, OSError): pass
    s.close()
    return out

def status(resp):
    m = re.match(rb"HTTP/1\.[01] (\d{3})", resp)
    return int(m.group(1)) if m else 0

def get(path="/", host="x", extra="", port=None, timeout=5):
    return http_raw(port, f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n".encode(), timeout)

def summary():
    bad = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(bad)}/{len(results)} passed" + (f"; FAILED: {bad}" if bad else ""))
    return 1 if bad else 0
