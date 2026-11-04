# Load and flood test results

What happens to ordinary visitors while the guard is being attacked, measured with a real-socket harness
(`tests/load/`). Everything below was produced by `python3 tests/load/run_flood.py` against the shipped Linux
single-file program (`releases/tclguard-linux-x86_64`).

## How it is measured
* A constant **legitimate-visitor probe**: 16 addresses, each making about 16 keep-alive requests per second
  (256 requests/s in total, well inside the default limits). Its throughput, latency and errors are the figures
  that matter: *what do real users see while the attack runs?*
* **Attackers** are Go programs (`tests/load/tgload`), each pinned to its own CPU core so that the load generator never competes
  with the guard. The guard has its own core; the guard's CPU, memory and descriptor use are sampled once a second.
* Phases: capacity (limits off) -> baseline -> request flood -> connection flood -> slowloris -> garbage and
  smuggling attempts -> TLS handshake flood -> UDP flood -> a **5 minute mixed soak** of all of them -> recovery -> capacity again
  (a leak or fragmentation would show as lower peak throughput at the end).
* Run it yourself: `go build -o tests/load/tgload-bin ./tests/load/tgload` (Go 1.20+), then
  `TG_CMD=releases/tclguard-linux-x86_64 python3 tests/load/run_flood.py` (about 13 minutes; `--quick` for 3). Reports go to
  `tests/load/results/*.json`.

## Results (4-core virtual machine, Linux, the guard on one core)

| Phase | What the attacker did | Legit visitors (256 req/s offered) | Guard CPU |
|---|---|---|---|
| baseline | nothing | 255 req/s, p50 1.8 ms, p99 7.3 ms, 0 errors | 7% |
| request flood | 200 addresses, 4,470 req/s in total, each address just under its limit | **165 req/s, p50 29.6 ms, p99 76 ms, 0 errors** | 95% |
| connection flood | 500 addresses, 1.3 million connections in 45 s (about 29,000 per second) | 254 req/s, p50 1.8 ms, 0 errors | 94% |
| slowloris | 1,500 slow connections from 300 addresses; 33,000 cut off | 253 req/s, p50 2.2 ms, 0 errors | 18% |
| garbage / smuggling | 1.2 million connections sending junk | 256 req/s, p50 1.5 ms, 0 errors | 91% |
| TLS handshake flood | 156,000 failed + 364,000 abandoned handshakes | 227 req/s (HTTPS), p50 6.3 ms, 0 errors | 92% |
| UDP flood | 40,000 packets/s (1.2 million) | 256 req/s, p50 1.5 ms, 0 errors | 87% |
| **mixed soak, 5 min** | all of the above at moderate rates | **250 req/s, p50 1.3 ms, p99 15 ms, 0 errors** (75,000 requests) | 98% |
| recovery | nothing | 256 req/s, p50 1.6 ms, 0 errors; all tables empty, no bans left | 6% |

* **Peak capacity** (every per-address limit raised, so the guard is the only limit): 5,300 requests/s at the start of the run and 7,400 requests/s at
  the end of the *first* test run; after the hot-path work (memoised address parsing, cheaper per-request checks, whole chunks forwarded at once) the same test measures
  **9,200-10,100 requests/s** on the Linux runner. No degradation: throughput did not fall after 20 minutes of attacks.
* **Memory** stayed between 18 and 39 MB (the rise came with the first TLS flood and then stayed flat); **descriptors** peaked at 445
  (the planned cap, see below). After recovery every internal table (connections, per-address state, HTTP state, UDP sessions, bans, strikes) was empty.

## The honest weak spot
The only phase in which visitors noticed anything is the request flood, and that is not abuse the guard can reject:
200 addresses each staying just *under* their per-address limit is simply more legitimate-looking work than one core can do
(about 5,000 requests/s). Visitors were still served, with no errors, but 20 to 30 ms slower and at 165 of 256 requests/s.
More than one core would help here; measured, it does not help much (see [WORKERS.md](WORKERS.md): 1.5x for 3 cores), and in practice a
home connection fills up long before 5,000 requests/s of real pages do. The remedy is the kernel firewall rules, which drop flood
traffic before it reaches Tcl at all.

## Three things this test found, and fixed
1. **The guard crashed with more than about 1,000 connections.** Tcl 8.6 waits for events with `select()`, and a descriptor numbered 1024 or above
   aborts the whole process (`bit out of range 0 - FD_SETSIZE`). Raising the open-files limit, which our own service file used to recommend,
   made it reachable. The connection cap is now planned below that regardless of the limit (about 450 proxied connections) and the
   service file sets `LimitNOFILE=1024`. `tests/integration/test_fdlimit.py` holds 1,300 connections under a raised limit and checks that the guard survives.
2. **Ordinary visitors were banned by the guard's own defence.** Under an "under attack" threat level every per-address limit is multiplied by 0.35.
   16 steady visitors at 16 requests/s each exceeded that and were all banned within 8 seconds, for the rest of the attack. Visitors the guard already
   knows (three completed requests) now keep the limits of the level below. With the fix the same visitors saw 254 req/s through every phase.
3. **A slow-drip attack could take every connection slot.** 1,500 slow connections from 300 addresses made thousands of a returning visitor's attempts fail. The last
   quarter of the global connection cap is now reserved for known visitors (`tests/integration/test_reserve.py`).

## Over a real network path, with the kernel firewall (Linux)

The loopback run above has three weaknesses: no real network path, source addresses that are loopback aliases, and no kernel
firewall. `tests/load/run_flood_netns.sh` removes them: the guard sits in one network namespace and every visitor and attacker in
another, joined by a veth pair, so every packet crosses the real kernel TCP/IP stack between distinct real `10.77.x.y` addresses. It
also adds a **spoofed SYN flood** (60,000 packets/s, every one from a new random address, sent through a raw socket) and runs the
guard three ways: `none` (Tcl does everything), `bans` (bans are mirrored into nftables, so a banned address is dropped before it
reaches Tcl) and `harden` (bans plus the kernel's per-address SYN, connection and UDP limits). The same run on my machine and on a GitHub
runner (both 4 vCPU, 90 s soak):

| Phase (guard CPU, one core) | Tcl only | kernel bans | bans + hardening |
|---|---|---|---|
| connection flood (1.3 M connections) | 94-95% | **12-14%** | 13% |
| garbage / smuggling attempts | 89-94% | **11-13%** | 10-12% |
| TLS handshake flood | 89-93% | 15% (runner) / 53% (mine) | 14% / 53% |
| UDP flood (40,000 packets/s) | 88-94% | **7-8%** | 7-8% |
| mixed soak | 97% | **32-34%** | 31-38% |
| **spoofed SYN flood** | **5-7%** | 5-7% | 5-6% |
| request flood just under the per-address limits | 95% | 95% | 95% |

Visitors saw 227 to 261 requests/s (of 256 offered) and no errors in every one of these phases, with p50 between 0.8 and 2.3 ms. What the
table says:
* **The kernel firewall is what makes floods cheap.** With bans in nftables the guard's CPU during a connection, garbage or UDP flood
  falls from about 90% of a core to about 10%: the first few hundred packets of an address reach Tcl, the rest never do.
* **A spoofed SYN flood never reaches Tcl at all.** The kernel answered with SYN cookies (1.8 to 2.3 million per run) and the guard stayed at 5-7% CPU. It
  is not a per-address problem, so no per-address defence helps; the kernel's own cookies do the work. `ListenDrops` stayed in the tens to
  low hundreds. (A flood large enough to fill the network line is a different matter, see the README.)
* **Hardening costs a little tail latency.** With `harden`, the SYN-flood phase had p99 188 ms (p50 unchanged) and the mixed soak p99 81 ms on the runner,
  because the kernel's per-address SYN limit also trims some of a visitor's own new connections. Turn `harden` on when you are being attacked, not by default.
* **The one phase that did not improve is the request flood** (200 addresses, each just under its limit): 4,500 requests/s of work that looks
  legitimate to every per-address defence. Visitors got 132-159 requests/s at p50 35-56 ms, without errors. Nothing short of more CPU
  or a CDN helps there.

## The same test on real Windows and macOS (loopback, GitHub runners)

`tests/load/run_flood.py` also runs on Windows (the shipped `tclguard-windows-x86_64-console.exe`) and macOS (the shipped `tclguard-macos-arm64`,
3 Apple-silicon cores), each twice: with Tcl doing everything, and with bans mirrored into the system firewall (`netsh` on Windows, `pf` on macOS,
run as administrator/root). 90 s soak, 16 visitors, 256 requests/s offered.

**macOS** behaves like Linux once the firewall is on:

| Phase | visitors, Tcl only | visitors, `pf` bans | guard CPU (Tcl only -> pf) |
|---|---|---|---|
| baseline | 249 req/s, p50 2.6 ms | 239 req/s | 6% |
| connection flood | **118 req/s, p99 652 ms, 2,096 errors** | **237 req/s, p99 17 ms, 0 errors** | 38% -> 16% |
| slowloris | 235 | 233 | 23% -> 24% |
| garbage / smuggling | 250 | 238 | 83% -> 11% |
| TLS handshake flood | 228 (9 errors) | 221 | 79% -> 24% |
| UDP flood | 248 | 240 | 121% -> 13% |
| mixed soak | 235, p99 45 ms | 237, p99 24 ms | 79% -> 47% |
| request flood just under the limits | 155, p50 33 ms | 153 | 84% |

Capacity on macOS: 3,900 to 5,800 requests/s on one core (4,500-8,200 after the hot-path work). The 2,096 errors in the Tcl-only connection flood were all `local_ports`: the *generator* ran out of
macOS's 16,000 ephemeral ports (a measurement limit, not the guard refusing anyone); the real finding is the 652 ms p99, which `pf` removes.

**Windows was much weaker. Before and after the fix described below** (the same flood, real Windows Server 2025 runner, visitors offering 256 req/s):

| Phase | before: Tcl 8.6.14 as released | after: patched socket driver (+ the hot-path work) | after, with `netsh` bans |
|---|---|---|---|
| baseline | 260 req/s, p50 1.2 ms | 262 req/s, p50 0.6 ms | 262 |
| capacity, no limits | **830 requests/s** | **about 4,000 requests/s** (3,970-4,030, still 3,340-3,780 at the end of the run) | 3,970 |
| request flood just under the limits | **45 req/s, p50 193 ms** | **138 req/s, p50 55 ms** | 138 |
| connection flood | 180 req/s, 125 errors; about 140-220 connections accepted per second | 176 req/s, 105 errors; about 335 accepted per second | 162, 134 errors |
| garbage / smuggling | 168 req/s, 936 errors | 218 req/s, 0 errors | 212, 0 errors |
| TLS handshake flood | 157 req/s, 508 errors | 185 req/s, 1,005 errors | 166, 216 errors |
| UDP flood | 258 | 261 | 261 |
| **mixed soak (every attack at once)** | **4 req/s, 14,600 errors, p99 7 s** | **136 req/s, 1,278 errors (9% of visitors' requests), p99 67 ms** | 117 req/s, 4,179 errors |
| recovery | 257 | 261 | 262 |

Every error is `refused`: **the operating system refused the connection because the listen queue was full**, before the guard could see it (so the guard cannot ban the
sender). Windows is still the weakest platform: one core takes about 4,000 requests/s (Linux about 10,000 in the same run, macOS 4,500-8,000), and under a determined connection
flood about one in ten visitor requests still gets `refused` (before the fix: nearly all of them).

**What the cause turned out to be, and what was changed.** Measured with `tests/load/winbench.tcl` (Tcl's event loop alone, no TclGuard): on the Windows runner a plain
Tcl client/server pair could bounce only about 1,000 lines per second (Python on the same machine: 20,700). Tcl 8.6's Windows socket driver sends a *synchronous* message
to a helper thread around every `recv`, every `send` and every "is it really readable?" check, so each I/O costs several thread switches, and it accepts one connection
per round trip through that thread. `tools/patches/tcl-8.6.14-winsock-nonblocking.diff` (about 120 lines of C, `win/tclWinSock.c` only, explained in
`tools/patches/README.md`) removes those messages for non-blocking sockets, updates the shared ready flags with interlocked operations, and makes the listener try
`accept()` again immediately. Result in the same benchmark: **1,000 -> 4,300 round trips/s for one pair, 1,050 -> 12,600 for 16 pairs**.

**The first version of the patch was wrong, and the stress test caught it.** It kept a `select()` call on a socket that WinSock was still watching (the original
Tcl code unselects first, "so select will work correctly"). One real CI run then stalled a keep-alive TLS connection for 5 seconds. `tests/integration/stress_keepalive.py`
(`stress-win.yml`) repeats exactly that pattern: on the unpatched runtime (control, built from the same source) 8,000 sessions of 5 requests on a plain and a TLS
connection did not stall once; the first patch version stalled on the 1,300th TLS session. The final patch has no `select()` there, and ran 3 x 6,000 sessions on three
fresh runners without a stall or error while being about twice as fast as the control (6,000 sessions in 42 s instead of 90). That is evidence, not a proof: the change
is to a 20-year-old part of Tcl, it has been exercised for 18,000 keep-alive sessions, all the suites on real Windows, and three flood runs, but not for months in production.

One more Windows finding, isolated with `winbench.tcl`: in Tcl 8.6.14 for Windows a callback that re-queues itself with `after idle` starves *every* timer (even a watchdog
timer never fires), while plain timers run at about 486,000 per second and the same test on Linux is fine. It is not in the patched driver (the unpatched runtime did the same)
and TclGuard has no loop of that shape (its only `after idle` is a single call in the certificate code), so nothing was changed; it is a trap to avoid in any future code.

What this means in practice: **on Windows TclGuard now holds ordinary hostility and a moderate connection flood**; it still does not match Linux, and a determined
flood from many addresses will cost some visitors a refused connection. For a Windows host that matters, put the guard on a Linux VPS in front (the setup the README
recommends) or run it on Linux.

## What this test does not show
* The namespace run crosses a real kernel network path but still **one machine, one virtual link**: no physical NIC, no interrupt moderation, no packet loss, and
  bandwidth is limited only by the CPU. A **volumetric flood that fills the network line** is below the guard (see the README on what it cannot stop).
* The numbers are for this virtual machine; a different CPU will differ by a factor of two or more. The shape (who is affected, what recovers) is what to take from it.
* TLS handshakes were measured with the shipped OpenSSL (3.5); the per-handshake cost on a slow ARM board will be higher.
