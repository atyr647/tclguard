"""Live fuzzing: real guard process, real sockets, recording backend, oracles."""
import collections
import json
import os
import random
import re
import select
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "integration"))
import gen        # noqa: E402
import oracle     # noqa: E402
import refparse   # noqa: E402
from backend import Backend   # noqa: E402
from harness import Guard, free_port, wait_port, http_raw, status   # noqa: E402

ERR_RE = re.compile(r"background error|while executing|invoked from within|\(procedure \"|can't read \"|can't set \"|"
                    r"invalid command name|wrong # args|bad option|unknown option|couldn't|bgerror| error: ", re.I)

VARIANTS = {
    "default": {"forwardIp": 1},
    "noxff": {"forwardIp": 0},
    "trusted": {"forwardIp": 1, "trustedProxies": "127.0.0.1"},
    "challenge": {"forwardIp": 1, "challenge": "always"},
}


class Proc:
    def __init__(self, pid):
        self.pid = pid

    def cpu_ms(self):
        tot = 0
        try:
            for t in os.listdir("/proc/%d/task" % self.pid):
                try:
                    tot += int(open("/proc/%d/task/%s/schedstat" % (self.pid, t)).read().split()[0])
                except (OSError, ValueError, IndexError):
                    pass
        except OSError:
            pass
        return tot / 1e6

    def fds(self):
        try:
            return len(os.listdir("/proc/%d/fd" % self.pid))
        except OSError:
            return -1

    def rss_mb(self):
        try:
            for line in open("/proc/%d/status" % self.pid):
                if line.startswith("VmRSS"):
                    return int(line.split()[1]) / 1024.0
        except OSError:
            pass
        return -1.0

    def alive(self):
        return os.path.exists("/proc/%d" % self.pid) and open("/proc/%d/stat" % self.pid).read().split()[2] != "Z"


class CaseResult:
    def __init__(self):
        self.sent = b""
        self.resp = b""
        self.cport = None
        self.bconn = None
        self.t0 = 0
        self.elapsed = 0
        self.err = None


def run_case(port, be, case, settle=5.0, wait_backend=True):
    r = CaseResult()
    r.t0 = t0 = time.time()
    try:
        s = socket.create_connection(("127.0.0.1", port), 5)
    except OSError as e:
        r.err = "connect: %s" % e
        return r
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    r.cport = s.getsockname()[1]
    s.setblocking(False)
    sent = bytearray()
    resp = bytearray()
    st = {"closed": False}

    def rd():
        try:
            d = s.recv(65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            st["closed"] = True
            return
        if d:
            if len(resp) < 1 << 20:
                resp.extend(d)
        else:
            st["closed"] = True

    def pause(secs):
        end = time.time() + secs
        while True:
            left = end - time.time()
            if left <= 0 or st["closed"]:
                return
            if select.select([s], [], [], min(left, 0.05))[0]:
                rd()

    def rst():
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError:
            pass
        s.close()

    dead = t0 + 30
    stop = False
    for op in case["ops"]:
        if stop or time.time() > dead:
            break
        k = op[0]
        if k == "s":
            mv = memoryview(op[1])
            off = 0
            while off < len(mv) and not st["closed"] and time.time() < dead:
                rl, wl, _ = select.select([s], [s], [], 0.2)
                if rl:
                    rd()
                if wl and not st["closed"]:
                    try:
                        n = s.send(mv[off:off + 65536])
                    except (BlockingIOError, InterruptedError):
                        continue
                    except OSError:
                        st["closed"] = True
                        break
                    sent.extend(mv[off:off + n])
                    off += n
            if st["closed"]:
                stop = True
        elif k == "d":
            pause(op[1])
        elif k == "h":
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        elif k == "r":
            rst()
            s = None
            stop = True
            break
    t_end = time.time()
    if s is not None:
        end = case.get("end", "half")
        if end == "half":
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            pause(settle)
            s.close()
        elif end == "close":
            s.close()
        elif end == "rst":
            rst()
        else:
            pause(min(settle, 4.0))
            s.close()
    r.sent = bytes(sent)
    r.resp = bytes(resp)
    if wait_backend:
        bc = None
        dl = time.time() + settle + 1.0
        while time.time() < dl:
            bc = bc or be.find(r.cport, t0 - 0.02)
            if bc is not None and bc.closed:
                break
            if bc is None and time.time() - t_end > 0.4:
                break
            time.sleep(0.01)
        r.bconn = bc
        if bc is not None:
            time.sleep(0.003)
    r.elapsed = time.time() - t0
    return r


class Live:
    """A guard + recording backend pair for one config variant."""

    def __init__(self, variant="default", extra_listener=None, extra_general=None, workers=12, keep_log=False):
        self.variant = variant
        self.be = Backend()
        self.port = free_port()
        lst = {"type": "http", "port": self.port, "backendPort": self.be.port, "proxyProtocol": "v1",
               "maxConnsPerIP": 100000, "connRate": 100000000, "connWindow": 1, "reqRate": 100000000, "maxConns": 100000,
               "headerTimeout": 2, "keepAliveTimeout": 2, "bodyTimeout": 2, "idleTimeout": 6, "maxBodyMB": 2,
               "challenge": "off"}
        lst.update(VARIANTS[variant])
        lst.update(extra_listener or {})
        gen_ = {"strikeThreshold": 1000000, "logLevel": "debug", "maxConnections": 4000}
        gen_.update(extra_general or {})
        self.g = Guard({"web": lst}, gen_)
        self.g.start()
        assert wait_port(self.port)
        self.proc = Proc(self.g.proc.pid)
        self.forward_ip = bool(lst["forwardIp"])
        self.trusted = bool(lst.get("trustedProxies"))
        self.workers = workers
        self.pool = ThreadPoolExecutor(max_workers=workers)
        self.stats = collections.Counter()
        self.findings = {}              # sig -> (Finding, case)
        self.lock = threading.Lock()
        self.base = None
        self.rss_hist = []
        self.log_tail_pos = 0
        self.reasons = collections.Counter()
        self.deadline = 0

    def close(self):
        try:
            self.pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        self.g.stop()
        self.be.stop()

    # ---------------------------------------------------------------- oracles
    def evaluate(self, case, r):
        if r.err:
            return [oracle.Finding("driver", r.err, "driver")]
        C = r.sent
        B = bytes(r.bconn.raw) if r.bconn is not None else b""
        fs = oracle.check_stream(C, B, r.bconn, self.forward_ip, self.trusted)
        if r.bconn is not None and not r.bconn.closed and r.elapsed > 0:
            fs.append(oracle.Finding("leak-backend-conn", "backend connection still open %.1fs after the client finished" % r.elapsed, "leak-be-conn"))
        # classification statistics (not findings)
        m = re.match(rb"HTTP/1\.[01] (\d{3})", r.resp)
        code = int(m.group(1)) if m else 0
        with self.lock:
            self.stats["cases"] += 1
            self.stats["resp%d" % code] += 1
            if r.bconn is not None and B:
                self.stats["forwarded"] += 1
        return fs

    def submit(self, case, tag=""):
        if self.deadline and time.time() > self.deadline:
            return []                      # time budget used up: drain the rest of the batch instantly
        r = run_case(self.port, self.be, case)
        fs = self.evaluate(case, r)
        if r.bconn is not None:
            self.be.forget(r.cport, r.bconn)
        for f in fs:
            self.record(f, case, r)
        return fs

    def record(self, f, case, r=None):
        with self.lock:
            self.stats["finding:" + f.kind] += 1
            if f.sig not in self.findings:
                self.findings[f.sig] = (f, case, (r.sent if r else b""), (bytes(r.bconn.raw) if r and r.bconn else b""))
                print("NEW FINDING [%s] %s: %s" % (self.variant, f.kind, f.detail[:200]), flush=True)

    # ---------------------------------------------------------------- guard-wide checks
    def debug(self):
        rc, out = self.g.ctl("debug")
        return {k: int(v) for k, v in re.findall(r"(\w+)\s+(\d+)", out)}

    def liveness(self, deadline=4.0):
        t = time.time()
        r = http_raw(self.port, b"GET /live HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", deadline)
        ok = status(r) == 200 and b"ok:" in r
        rc, out = self.g.ctl("ping")
        return ok and rc == 0 and "pong" in out, time.time() - t

    def settle_tables(self, timeout=12):
        """Wait until the guard has dropped every connection; return the debug dict."""
        end = time.time() + timeout
        d = {}
        while time.time() < end:
            d = self.debug()
            if d.get("tcpConns") == 0 and d.get("httpState") == 0 and d.get("httpBuf") == 0:
                break
            time.sleep(0.4)
        return d

    def baseline(self):
        time.sleep(0.5)
        d = self.settle_tables()
        self.base = {"debug": d, "fds": self.proc.fds(), "rss": self.proc.rss_mb()}
        return self.base

    def check_batch_state(self, label):
        fs = []
        d = self.settle_tables()
        for k in ("tcpConns", "tcpPerIp", "httpState", "httpBuf"):
            if d.get(k, 0) != 0:
                fs.append(oracle.Finding("leak-table", "%s: %s=%s did not return to 0" % (label, k, d.get(k)), "leak-table:" + k))
        if self.base:
            bo = self.base["debug"].get("openChannels", 0)
            if d.get("openChannels", 0) > bo + 2:
                fs.append(oracle.Finding("leak-channels", "%s: openChannels %s > baseline %s" % (label, d.get("openChannels"), bo), "leak-channels"))
            fd = self.proc.fds()
            if fd > self.base["fds"] + 6:
                fs.append(oracle.Finding("leak-fd", "%s: %d open fds > baseline %d" % (label, fd, self.base["fds"]), "leak-fd"))
        self.rss_hist.append(self.proc.rss_mb())
        ok, took = self.liveness()
        if not ok:
            fs.append(oracle.Finding("liveness", "%s: guard did not answer a normal request within the deadline" % label, "liveness"))
        if not self.proc.alive():
            fs.append(oracle.Finding("crash", "%s: guard process died" % label, "crash"))
        fs += self.scan_log()
        return fs, d

    def scan_log(self):
        txt = self.g.stderr()
        fs = []
        for line in txt.splitlines():
            m = re.search(r"http reject (\d+) from \S+: (.*)$", line)
            if m:
                self.reasons["%s %s" % (m.group(1), m.group(2))] += 1
            if " DEBUG " in line and "reject" in line:
                continue
            if ERR_RE.search(line) and "http reject" not in line:
                fs.append(oracle.Finding("log-error", line[:300], "log:" + re.sub(r"\d+", "N", line[20:90])))
        try:
            open(os.path.join(self.g.dir, "stderr.log"), "w").close()   # truncate (guard appends)
        except OSError:
            pass
        return fs

    def rss_growth(self):
        h = self.rss_hist
        if len(h) < 8:
            return None
        early = sum(h[2:5]) / 3
        late = sum(h[-3:]) / 3
        return late - early

    # ---------------------------------------------------------------- driving
    def run_batch(self, cases):
        futs = [self.pool.submit(self.submit, c) for c in cases]
        for f in futs:
            f.result()

    def cpu_of(self, case):
        """Run one case alone and return guard CPU ms consumed (utime+stime via schedstat)."""
        time.sleep(0.03)
        c0 = self.proc.cpu_ms()
        r = run_case(self.port, self.be, case, settle=6.0)
        time.sleep(0.02)
        c1 = self.proc.cpu_ms()
        if r.bconn is not None:
            self.be.forget(r.cport, r.bconn)
        return c1 - c0, r
