#!/usr/bin/env python3
"""Keep-alive throughput with many distinct client addresses (127.0.1.1..), so sharding by
address spreads load. usage: bench.py <port> <seconds> <procs> <conns-per-proc>"""
import asyncio, multiprocessing as mp, sys, time
REQ = b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
async def one(port, secs, src, out):
    n = 0
    r, w = await asyncio.open_connection("127.0.0.1", port, local_addr=(src, 0))
    end = time.time() + secs
    while time.time() < end:
        w.write(REQ); await w.drain()
        hdr = await r.readuntil(b"\r\n\r\n"); await r.readexactly(2); n += 1
    w.close(); out.append(n)
def proc(port, secs, base, conns, q):
    async def main():
        out = []; await asyncio.gather(*[one(port, secs, f"127.0.1.{base + i}", out) for i in range(conns)]); return sum(out)
    q.put(asyncio.run(main()))
if __name__ == "__main__":
    port, secs, procs, conns = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    q = mp.Queue(); ps = [mp.Process(target=proc, args=(port, secs, 1 + k * conns, conns, q)) for k in range(procs)]
    t = time.time(); [p.start() for p in ps]; tot = sum(q.get() for _ in ps); [p.join() for p in ps]
    print(f"{tot / (time.time() - t):,.0f} req/s")
