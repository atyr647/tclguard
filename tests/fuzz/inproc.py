"""In-process fuzzing: feed byte strings straight into the real Tcl parser (tests/fuzz/inproc.tcl)."""
import collections
import os
import random
import select
import shlex
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen        # noqa: E402
import oracle     # noqa: E402
import refparse   # noqa: E402

TCLSH = os.environ.get("TG_TCLSH", "tclsh8.6")

CONFIGS = {
    "default": ({"forwardIp": 1}, True, False),
    "noxff": ({"forwardIp": 0}, False, False),
    "trusted": ({"forwardIp": 1, "trustedProxies": "127.0.0.1"}, True, True),
    "challenge": ({"forwardIp": 1, "challenge": "always"}, True, False),
}


class Stall(Exception):
    pass


class FakeB:
    def __init__(self, upg, cut):
        self.upgraded_at = 0 if upg else None
        self.cut = cut


class Worker:
    def __init__(self, cfg="default"):
        self.proc = subprocess.Popen([TCLSH, os.path.join(HERE, "inproc.tcl")], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL)
        self.rfd = self.proc.stdout.fileno()
        over, self.forward_ip, self.trusted = CONFIGS[cfg]
        self.cfg = cfg
        self.timeout = 120.0
        txt = " ".join("%s {%s}" % (k, v) for k, v in over.items()).encode()
        self.proc.stdin.write(b"CFG %d\n%s" % (len(txt), txt))
        self.proc.stdin.flush()
        self.rbuf = bytearray()
        self.rpos = 0

    def encode(self, pieces, end, upg):
        out = [b"CASE {end=%s upg=%d} %d\n" % (end.encode(), upg, len(pieces))]
        for p in pieces:
            out.append(b"%d\n" % len(p))
            out.append(p)
        return b"".join(out)

    def _fill(self):
        if not select.select([self.rfd], [], [], self.timeout)[0]:
            raise Stall("no output from the in-process parser for %.0fs" % self.timeout)
        d = os.read(self.rfd, 1 << 20)
        if not d:
            raise EOFError("inproc worker died")
        if self.rpos > 1 << 20:
            del self.rbuf[:self.rpos]
            self.rpos = 0
        self.rbuf += d

    def _read(self, n):
        while len(self.rbuf) - self.rpos < n:
            self._fill()
        r = bytes(self.rbuf[self.rpos:self.rpos + n])
        self.rpos += n
        return r

    def _line(self):
        while True:
            i = self.rbuf.find(b"\n", self.rpos)
            if i >= 0:
                line = bytes(self.rbuf[self.rpos:i])
                self.rpos = i + 1
                return line
            self._fill()

    def _w(self, payload):
        self.proc.stdin.write(payload)
        self.proc.stdin.flush()

    def run(self, cases):
        """cases: list of (pieces, end, upg) -> list of dict results"""
        payload = b"".join(self.encode(*c) for c in cases) + b"SYNC\n"
        t = threading.Thread(target=self._w, args=(payload,))
        t.start()
        res = []
        for _ in cases:
            hdr = self._line().split()
            assert hdr[0] == b"R", hdr
            usec, bl, cl, el, ll, rl = (int(x) for x in hdr[1:7])
            ps = hdr[7].decode()
            b = self._read(bl)
            c = self._read(cl)
            e = self._read(el)
            lk = self._read(ll)
            rj = self._read(rl)
            res.append({"usec": usec, "B": b, "resp": c, "err": e.decode("utf-8", "replace"), "leaks": lk.decode(),
                        "reject": rj.decode(), "ps": ps})
        t.join()
        return res

    def close(self):
        try:
            self.proc.stdin.write(b"QUIT\n")
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(5)
        except Exception:
            self.proc.kill()


def flatten(case):
    """ops/end -> (pieces, end, ...) as the in-process driver understands them."""
    pieces = []
    end = {"half": "eof", "close": "eof", "rst": "rst", "hold": "hold"}[case.get("end", "half")]
    for op in case["ops"]:
        if op[0] == "s":
            pieces.append(op[1])
        elif op[0] == "h":
            end = "eof"
            break
        elif op[0] == "r":
            end = "rst"
            break
    return pieces, end


def locate_stall(cfg, cases):
    """Re-run a batch that stalled one case at a time (10 s each) and return the indexes that hang."""
    bad = []
    w = Worker(cfg)
    w.timeout = 10.0
    for i, c in enumerate(cases):
        try:
            w.run([c])
        except Stall:
            bad.append(i)
            w.close()
            w = Worker(cfg)
            w.timeout = 10.0
    w.close()
    return bad


def evaluate(w, case, upg, res, deep, stats):
    pieces, end = flatten(case)
    C = b"".join(pieces)
    B = res["B"]
    out = []
    if res["err"]:
        out.append(oracle.Finding("tcl-error", res["err"][:500], "tcl-error:" + res["err"].split("\n")[0][:80]))
    if res["leaks"]:
        out.append(oracle.Finding("leak-state", res["leaks"], "leak-state:" + res["leaks"][:60]))
    if res["usec"] > 200000 and res["usec"] > 10 * sum(len(p) for p in pieces):   # reflected channels make emit() slow: judge per byte
        out.append(oracle.Finding("cpu", "%.0f ms for %d input bytes (%d pieces)" % (res["usec"] / 1000, len(C), len(pieces)), "cpu"))
    fb = None
    if upg:
        r0 = refparse.parse_stream(C)
        cut = None
        if r0.msgs and r0.msgs[0].head_ok:
            cut = len(refparse.expected_head(r0.msgs[0], C, w.forward_ip))
        fb = FakeB(True, cut)
    out += oracle.check_stream(C, B, fb, w.forward_ip, w.trusted, deep=deep)
    stats["cases"] += 1
    stats["forwarded"] += 1 if B else 0
    if res["reject"]:
        stats["rej:" + res["reject"]] += 1
    return out


def run(seconds, seed, cfg="default", pool_size=3000, batch=500, deep_every=16, log=print):
    rng = random.Random(seed)
    w = Worker(cfg)
    stats = collections.Counter()
    findings = {}
    pool = []
    for _ in range(pool_size):
        g = gen.Gen(rng)
        pool.append(g.stream())
    t_end = time.time() + seconds
    t0 = time.time()
    last = t0
    slowest = []
    try:
        while time.time() < t_end:
            cases = []
            metas = []
            for _ in range(batch):
                k = rng.random()
                if k < 0.1:
                    s = gen.Gen(rng).stream()
                else:
                    s = pool[rng.randrange(len(pool))]
                    if rng.random() < 0.7:
                        s = gen.mutate(rng, s)
                    if rng.random() < 0.2:
                        s = s + pool[rng.randrange(len(pool))][:rng.choice([30, 200, 3000])]
                ops, end = gen.schedule(rng, s)
                case = {"ops": ops, "end": end}
                pieces, endm = flatten(case)
                upg = 1 if rng.random() < 0.5 else 0
                cases.append((pieces, endm, upg))
                metas.append((case, upg))
            try:
                res = w.run(cases)
            except Stall as e:
                bad = locate_stall(cfg, cases)
                for i in bad:
                    case = metas[i][0]
                    f = oracle.Finding("cpu-hang", "in-process parser did not finish a case within 10 s (%d bytes)" % sum(len(p) for p in cases[i][0]), "cpu-hang")
                    findings.setdefault("cpu-hang", (f, case, b"".join(cases[i][0]), b""))
                    stats["finding:cpu-hang"] += 1
                w.close()
                w = Worker(cfg)
                continue
            for i, ((case, upg), r) in enumerate(zip(metas, res)):
                for f in evaluate(w, case, upg, r, rng.random() < 1.0 / deep_every, stats):
                    stats["finding:" + f.kind] += 1
                    if f.sig not in findings:
                        findings[f.sig] = (f, case, b"".join(op[1] for op in case["ops"] if op[0] == "s"), r["B"])
                slowest.append((r["usec"], sum(len(p) for p in cases[i][0])))
            slowest = sorted(slowest, reverse=True)[:5]
            if time.time() - last > 20:
                last = time.time()
                log("[inproc:%s] %d cases, %.0f/s, findings %d" % (cfg, stats["cases"], stats["cases"] / (time.time() - t0), len(findings)))
    finally:
        w.close()
    log("[inproc:%s] done: %d cases in %.0fs (%.0f/s); forwarded %d; slowest (usec, bytes): %s" % (
        cfg, stats["cases"], time.time() - t0, stats["cases"] / max(1e-9, time.time() - t0), stats["forwarded"], slowest))
    rj = [(k[4:], v) for k, v in stats.items() if k.startswith("rej:")]
    rj.sort(key=lambda x: -x[1])
    log("[inproc:%s] reject reasons: %s" % (cfg, rj[:14]))
    return findings, stats
