#!/usr/bin/env python3
"""Rough throughput numbers for TclGuard on this machine (single Tcl thread)."""
import asyncio, multiprocessing as mp, os, sys, time, socket, subprocess
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

REQ = b"GET /bench HTTP/1.1\r\nHost: x\r\n\r\n"

async def keepalive(port, secs, out):
    n = 0
    r, w = await asyncio.open_connection("127.0.0.1", port)
    end = time.time() + secs
    while time.time() < end:
        w.write(REQ); await w.drain()
        hdr = await r.readuntil(b"\r\n\r\n")
        i = hdr.find(b"Content-Length: "); ln = int(hdr[i+16:hdr.find(b"\r\n", i)])
        await r.readexactly(ln); n += 1
    w.close(); out.append(n)

def ka_proc(port, secs, conns, q):
    async def main():
        out = []; await asyncio.gather(*[keepalive(port, secs, out) for _ in range(conns)]); return sum(out)
    q.put(asyncio.run(main()))

async def newconn(port, secs, out):
    n = 0; end = time.time() + secs
    while time.time() < end:
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); await w.drain()
            hdr = await r.readuntil(b"\r\n\r\n")
            i = hdr.find(b"Content-Length: "); ln = int(hdr[i+16:hdr.find(b"\r\n", i)])
            await r.readexactly(ln); w.close(); n += 1
        except OSError: pass
    out.append(n)

def nc_proc(port, secs, conns, q):
    async def main():
        out = []; await asyncio.gather(*[newconn(port, secs, out) for _ in range(conns)]); return sum(out)
    q.put(asyncio.run(main()))

async def rejected(port, secs, out):
    n = 0; end = time.time() + secs
    while time.time() < end:
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port); w.close(); n += 1
        except OSError: pass
    out.append(n)

def rj_proc(port, secs, conns, q):
    async def main():
        out = []; await asyncio.gather(*[rejected(port, secs, out) for _ in range(conns)]); return sum(out)
    q.put(asyncio.run(main()))

def run(fn, port, secs, procs, conns):
    q = mp.Queue(); ps = [mp.Process(target=fn, args=(port, secs, conns, q)) for _ in range(procs)]
    t = time.time(); [p.start() for p in ps]; tot = sum(q.get() for _ in ps); [p.join() for p in ps]
    return tot / (time.time() - t)

def cpu_of(pid):
    with open(f"/proc/{pid}/stat") as f: x = f.read().split()
    return (int(x[13]) + int(x[14])) / os.sysconf("SC_CLK_TCK")

def rss_mb(pid):
    for l in open(f"/proc/{pid}/status"):
        if l.startswith("VmRSS"): return int(l.split()[1]) / 1024

if __name__ == "__main__":
    be = HttpBackend(); port = free_port()
    g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "reqRate": 100000000, "connRate": 100000000,
                       "maxConnsPerIP": 100000, "maxConns": 100000, "idleTimeout": 0}},
              {"strikeThreshold": 1000000, "logLevel": "warn", "maxConnections": 4000}).start()
    pid = g.proc.pid
    secs = 8
    print(f"cpus available to the load generator: {os.cpu_count()}")
    c0 = cpu_of(pid); rate = run(ka_proc, port, secs, 2, 25)
    print(f"keep-alive requests through the HTTP inspector: {rate:,.0f} req/s   (tclguard cpu {(cpu_of(pid)-c0)/secs*100:.0f}% of one core, RSS {rss_mb(pid):.0f} MB)")
    c0 = cpu_of(pid); rate = run(nc_proc, port, secs, 2, 12)
    print(f"new connection + request + close:            {rate:,.0f} conn/s  (tclguard cpu {(cpu_of(pid)-c0)/secs*100:.0f}%)")
    g.ctl("ban", "127.0.0.1", 600, "bench")
    time.sleep(0.5)
    c0 = cpu_of(pid); rate = run(rj_proc, port, secs, 2, 12)
    print(f"connections from a BANNED address rejected: {rate:,.0f} conn/s  (tclguard cpu {(cpu_of(pid)-c0)/secs*100:.0f}%, RSS {rss_mb(pid):.0f} MB)")
    g.cleanup(); be.stop()
