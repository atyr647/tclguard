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
  the end. No degradation: throughput did not fall after 20 minutes of attacks.
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

## What this test does not show
* Everything runs on **one machine over loopback**: no network latency, no NIC or interrupt cost, no packet loss, and source addresses are `127.x.y.z`
  aliases. The kernel firewall was not used (no root), so bans were enforced by the guard at accept time, which is the slower path.
* A **SYN flood or volumetric UDP flood against the machine itself** is below the guard (see the README on what it cannot stop).
* The numbers are for this virtual machine; a different CPU will differ by a factor of two or more. The shape (who is affected, what recovers) is what to take from it.
* TLS handshakes were measured with the shipped OpenSSL (3.5); the per-handshake cost on a slow ARM board will be higher.
