#!/usr/bin/env python3
"""Sustained flood test for TclGuard (Linux). Pins the guard, the backend and the load generators to separate
CPU cores, runs a series of attacks while a constant "legitimate visitor" probe measures what real users would
experience, samples the guard's CPU / memory / descriptors every second, and writes a report.

Needs: a built tgload (cd tests/load/tgload && go build -o ../tgload .), taskset, and TG_CMD (optional) to test
a starpack:  TG_CMD=releases/tclguard-linux-x86_64 python3 tests/load/run_flood.py [--quick] [--workers N]

All attackers are loopback addresses (127.x.y.z), so nothing leaves the machine. Do not run this on a machine
you need for anything else, and do not point it anywhere but 127.0.0.0/8."""
import argparse, json, os, re, shlex, signal, subprocess, sys, threading, time, tempfile, shutil, socket

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "integration"))
from harness import Guard, free_port, wait_port, TG, UdpEcho     # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--quick", action="store_true", help="short phases (smoke test of the harness itself)")
ap.add_argument("--tgload", default=os.environ.get("TGLOAD") or os.path.join(HERE, "tgload-bin"))
ap.add_argument("--workers", type=int, default=0, help="guard worker threads, if the build supports it")
ap.add_argument("--out", default=os.path.join(HERE, "results"))
ap.add_argument("--cores", default="0,1,2,3", help="cores to use: guard, backend, then generators (rest)")
ap.add_argument("--soak", type=int, default=300, help="seconds for the mixed soak phase")
args = ap.parse_args()

cores = args.cores.split(",")
GUARD_CORE, BACKEND_CORE = cores[0], cores[1]
GEN_CORES = ",".join(cores[2:]) or cores[1]
Q = args.quick
def D(full, quick): return quick if Q else full

if not os.path.exists(args.tgload): sys.exit("build tgload first:  cd tests/load/tgload && go build -o ../tgload-bin .")

def pin(core, cmd): return ["taskset", "-c", core, *cmd]

# --------------------------------------------------------------------------- processes ----
backend_port = free_port()
backend = subprocess.Popen(pin(BACKEND_CORE, [args.tgload, "backend", "-listen", f"127.0.0.1:{backend_port}"]),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
assert wait_port(backend_port, 10), "backend did not start"
udp_echo = UdpEcho()
web, game, udp, tlsp, cap = free_port(), free_port(), free_port(), free_port(), free_port()
listeners = {
    "web":    {"type": "http", "port": web, "backendPort": backend_port},                               # defaults: what a user gets
    "cap":    {"type": "http", "port": cap, "backendPort": backend_port, "reqRate": 1000000, "connRate": 100000,
               "maxConnsPerIP": 5000, "maxConns": 20000},                                              # no per-address limits: raw capacity
    "game":   {"type": "tcp", "port": game, "backendPort": backend_port},
    "secure": {"type": "http", "port": tlsp, "backendPort": backend_port, "tls": 1},
    "gameudp": {"type": "udp", "port": udp, "backendPort": udp_echo.port},
}
general = {"allowlist": "{}", "logLevel": "warn"}
if args.workers: general["workers"] = args.workers
g = Guard(listeners, general)
g.start()
for p in (web, cap, game, tlsp): assert wait_port(p, 10), f"listener {p} not up"
# pin the guard (and any worker threads, which share its pid) to its core
subprocess.run(["taskset", "-a", "-p", "-c", GUARD_CORE, str(g.proc.pid)], capture_output=True)

# --------------------------------------------------------------------------- sampler ----
samples = []
stop_sampler = threading.Event()
CLK = os.sysconf("SC_CLK_TCK")
def sample_once(t0):
    pid = g.proc.pid
    try:
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        cpu = (int(st[11]) + int(st[12])) / CLK
        rss = 0
        for l in open(f"/proc/{pid}/status"):
            if l.startswith("VmRSS:"): rss = int(l.split()[1]) // 1024
        fds = len(os.listdir(f"/proc/{pid}/fd"))
        return {"t": time.time() - t0, "cpu_s": cpu, "rss_mb": rss, "fds": fds}
    except Exception: return None
def sampler():
    t0 = time.time()
    while not stop_sampler.is_set():
        s = sample_once(t0)
        if s: samples.append(s)
        stop_sampler.wait(1.0)
threading.Thread(target=sampler, daemon=True).start()

def guard_debug():
    rc, out = g.ctl("debug")
    d = {}
    for m in re.finditer(r"^\s*(\w+)\s+(\d+)\s*$", out, re.M): d[m.group(1)] = int(m.group(2))
    rc, st = g.ctl("status")
    m = re.search(r"level\s+(\S+)", st)
    d["level"] = m.group(1) if m else "?"
    return d

# ------------------------------------------------------------------------------ runners ----
def tgload(*a, core=None, timeout=None):
    cmd = pin(core or GEN_CORES, [args.tgload, *map(str, a)])
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

def result(p, timeout):
    try: out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired: p.kill(); out, _ = p.communicate()
    try: return json.loads(out.strip().splitlines()[-1])
    except Exception: return {"error": "no output", "raw": out[-200:]}

def legit(dur, url_port=None, tls=False, conns=16):
    """A steady stream of ordinary visitors: 16 distinct addresses, ~16 requests/s each (well inside the default limits)."""
    scheme = "https" if tls else "http"
    a = ["http", "-url", f"{scheme}://127.0.0.1:{url_port or web}/", "-conns", conns, "-dur", f"{dur}s",
         "-srcbase", "127.0.1.0", "-srcn", conns, "-think", "60ms"]
    if tls: a.append("-tls")
    return tgload(*a)

phases = []
def run_phase(name, dur, attackers, probe=True, probe_tls=False, note=""):
    d0 = guard_debug()
    s0 = samples[-1] if samples else {"cpu_s": 0, "rss_mb": 0, "fds": 0}
    t_start = time.time()
    procs = [(label, p) for label, p in attackers]
    pr = legit(dur, tlsp if probe_tls else web, tls=probe_tls) if probe else None
    out = {"name": name, "seconds": dur, "note": note, "attackers": {}}
    if pr: out["legit"] = result(pr, dur + 30)
    for label, p in procs: out["attackers"][label] = result(p, dur + 30)
    time.sleep(1.5)
    s1 = samples[-1] if samples else s0
    d1 = guard_debug()
    wall = max(time.time() - t_start, 1)
    out["guard"] = {"cpu_pct_of_core": round(100 * (s1["cpu_s"] - s0["cpu_s"]) / wall, 1), "rss_mb_start": s0["rss_mb"], "rss_mb_end": s1["rss_mb"],
                    "fds_start": s0["fds"], "fds_end": s1["fds"], "debug_end": d1, "level": d1.get("level")}
    phases.append(out)
    L = out.get("legit", {})
    print(f"[{name}] legit ok {L.get('ok_rps', 0):.0f} rps  p50 {L.get('p50_ms', 0):.1f} ms  p99 {L.get('p99_ms', 0):.1f} ms  "
          f"errors {L.get('counts', {}).get('error', 0)}  429s {L.get('counts', {}).get('status_429', 0)} | guard cpu {out['guard']['cpu_pct_of_core']}%  "
          f"rss {out['guard']['rss_mb_end']} MB  fds {out['guard']['fds_end']}  level {out['guard']['level']}", flush=True)
    return out

def settle(sec=8):
    """Let bans expire / tables drain a little between phases (and unban everything for a clean slate)."""
    g.ctl("unbanall"); time.sleep(sec)

try:
    # --- raw capacity (no per-address limits): the ceiling of one Tcl thread through the HTTP inspector
    run_phase("capacity (no limits)", D(25, 6), [("reqflood", tgload("reqflood", "-url", f"http://127.0.0.1:{cap}/", "-conns", 96, "-dur", f"{D(25, 6)}s",
                                                                      "-srcbase", "127.0.8.0", "-srcn", 8))], probe=False,
              note="peak requests/s through the guard with every per-address limit raised; one core")
    settle(3)
    run_phase("baseline", D(30, 6), [], note="legitimate visitors only")
    settle(2)
    run_phase("request flood", D(45, 8),
              [("reqflood", tgload("reqflood", "-url", f"http://127.0.0.1:{web}/", "-conns", 200, "-dur", f"{D(45, 8)}s", "-srcbase", "127.0.2.0", "-srcn", 200))],
              note="200 addresses hammering requests as fast as they can")
    settle(5)
    run_phase("connection flood", D(45, 8),
              [("connflood", tgload("connflood", "-addr", f"127.0.0.1:{web}", "-workers", 150, "-dur", f"{D(45, 8)}s", "-srcbase", "127.0.3.0", "-srcn", 500))],
              note="500 addresses opening and dropping connections as fast as possible")
    settle(5)
    run_phase("slowloris", D(45, 8),
              [("slowloris", tgload("slowloris", "-addr", f"127.0.0.1:{web}", "-conns", 1500, "-dur", f"{D(45, 8)}s", "-srcbase", "127.0.4.0", "-srcn", 300))],
              note="1500 connections dripping headers from 300 addresses")
    settle(5)
    run_phase("garbage / malformed", D(40, 8),
              [("garbage", tgload("garbage", "-addr", f"127.0.0.1:{web}", "-workers", 80, "-dur", f"{D(40, 8)}s", "-srcbase", "127.0.5.0", "-srcn", 120))],
              note="random bytes, request smuggling attempts, oversize URIs, TLS hello at a plain port")
    settle(5)
    run_phase("TLS handshake flood", D(40, 8),
              [("tlsflood", tgload("tlsflood", "-addr", f"127.0.0.1:{tlsp}", "-workers", 80, "-dur", f"{D(40, 8)}s", "-srcbase", "127.0.6.0", "-srcn", 120)),
               ("tls half-open", tgload("tlsflood", "-addr", f"127.0.0.1:{tlsp}", "-workers", 60, "-dur", f"{D(40, 8)}s", "-srcbase", "127.0.9.0", "-srcn", 120, "-halfopen"))],
              probe_tls=True, note="full and abandoned TLS handshakes from 240 addresses; the probe is an HTTPS visitor")
    settle(5)
    run_phase("UDP flood", D(30, 6),
              [("udpflood", tgload("udpflood", "-addr", f"127.0.0.1:{udp}", "-pps", 40000, "-dur", f"{D(30, 6)}s", "-srcbase", "127.0.7.0", "-srcn", 30, "-size", 80))],
              note="40,000 packets/s from 30 addresses at the UDP relay; the probe is an HTTP visitor")
    settle(5)
    soak = D(args.soak, 20)
    run_phase("mixed soak", soak,
              [("reqflood", tgload("reqflood", "-url", f"http://127.0.0.1:{web}/", "-conns", 60, "-dur", f"{soak}s", "-srcbase", "127.0.2.0", "-srcn", 60)),
               ("connflood", tgload("connflood", "-addr", f"127.0.0.1:{web}", "-workers", 40, "-dur", f"{soak}s", "-srcbase", "127.0.3.0", "-srcn", 200)),
               ("slowloris", tgload("slowloris", "-addr", f"127.0.0.1:{web}", "-conns", 400, "-dur", f"{soak}s", "-srcbase", "127.0.4.0", "-srcn", 100)),
               ("garbage", tgload("garbage", "-addr", f"127.0.0.1:{web}", "-workers", 20, "-dur", f"{soak}s", "-srcbase", "127.0.5.0", "-srcn", 60)),
               ("tlsflood", tgload("tlsflood", "-addr", f"127.0.0.1:{tlsp}", "-workers", 20, "-dur", f"{soak}s", "-srcbase", "127.0.6.0", "-srcn", 60)),
               ("udpflood", tgload("udpflood", "-addr", f"127.0.0.1:{udp}", "-pps", 8000, "-dur", f"{soak}s", "-srcbase", "127.0.7.0", "-srcn", 20, "-size", 80))],
              note="every attack type at a moderate rate, for minutes: looking for leaks, drift and collapse")
    settle(20)
    rec = run_phase("recovery", D(30, 6), [], note="attack over: does it return to baseline, and do the tables drain?")
    dbg = guard_debug()
    print("tables after recovery:", {k: v for k, v in dbg.items() if k not in ("level",)}, flush=True)
    settle(2)
    run_phase("capacity again (no limits)", D(25, 6), [("reqflood", tgload("reqflood", "-url", f"http://127.0.0.1:{cap}/", "-conns", 96, "-dur", f"{D(25, 6)}s",
                                                                           "-srcbase", "127.0.8.0", "-srcn", 8))], probe=False,
              note="after the whole run: is peak throughput the same? (a leak or fragmentation would show here)")
finally:
    stop_sampler.set()
    os.makedirs(args.out, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(args.out, f"flood-{stamp}{'-quick' if Q else ''}.json")
    report = {"when": stamp, "tg_cmd": TG, "workers": args.workers, "cores": cores, "phases": phases, "samples": samples,
              "host": {"nproc": os.cpu_count(), "kernel": os.uname().release}}
    json.dump(report, open(path, "w"))
    print("report written to", path)
    for pr in (backend,): pr.terminate()
    g.cleanup(); udp_echo.stop()
