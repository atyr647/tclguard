# Windows connection floods: what limits the guard, and the options for fixing it properly

Status: option A below was **tried and did not help**; the rest has not been implemented. Numbers are from GitHub's Windows Server 2025 runner (`acceptbench.yml`,
one fresh runner per variant, 150 attacker workers from 500 source addresses for 20 s, loopback). They are the ceiling of *one* Tcl thread.

## Measured

| What accepts and closes connections | accepted per second |
|---|---|
| Linux, Tcl 8.6.14 (bare accept-and-close, and a guard-like "state then drop") | **11,160** and 10,420 |
| Windows, Python (one thread, blocking `accept()`, no Tcl) | **2,955** |
| Windows, Tcl, bare accept-and-close, socket patch | 676 |
| Windows, Tcl, bare accept-and-close, **no** socket patch | 521 |
| Windows, Tcl, guard-like state (non-blocking channel, handler, timer), patched / unpatched | 922 / 1,014 |
| Windows, the real guard during the connection flood (flood test) | about 335 |

* **The listen queue is 200 connections** for a Tcl listener and for a Python one (`SOMAXCONN` means 200 on this Windows). When a flood outruns the accept rate,
  everything beyond those 200 is refused by the operating system, attackers and visitors alike.
* **The guard is not busy while this happens**: 30-35% of a core during the connection flood, `strikes 0`, `bans 0` at the end of the phase. It is *waiting*
  (latency), not computing. And because the operating system refuses connections at random, no single address is seen often enough to be struck or banned; the
  per-address detection that works on Linux has nothing to count. That is also why `netsh` bans did not help in the flood test.
* **What the first socket patch did and did not do**: it made reading and writing about 4-12x faster (docs/LOAD.md) but the accept path only about 1.3x
  (521 -> 676 per second, bare). The "guard-like" variants differ by less than the run-to-run noise. The accept path is dominated by something the patch does not touch.
* Python manages 4-5x what Tcl does on the same machine, so the operating system is not the limit: it is Tcl's driver (a socket is created, registered
  with the helper thread by a synchronous message, wrapped in a channel, and later unregistered by more messages, and each hand-off to that thread costs
  hundreds of microseconds on these VMs). The first benchmark run of this workflow put the variants in a row on one machine and was confounded by exhausted
  ephemeral ports; the numbers above are the clean ones.

## Options

| # | Option | Expected effect | Cost and risk | Keeps "pure Tcl"? |
|---|---|---|---|---|
| A | **(tried, no effect, reverted)** Remove the remaining hand-offs in Tcl's driver: register a new socket with `WSAAsyncSelect` directly instead of through a synchronous message, same for the unregister on close, and accept a bounded batch per event instead of one | maybe 1.5-3x on accepts (**a guess**; the same change gave 4-12x on reads and writes, only 1.3x on accepts so far) | small C patch to the file already patched; testable with `acceptbench.yml`, `stress-win.yml` and the flood test; the first patch had a real bug, so the same discipline applies | yes (a patched runtime) |
| B | **A small native acceptor** (a C extension linked into the Windows runtime): one OS thread does blocking `accept()` on a large queue, drops banned or over-rate addresses natively, and hands the rest to Tcl as ordinary channels | 5-10x on accepts, hostile connections handled at tens of thousands per second; refused-by-the-OS becomes rare | 200-300 lines of C, a ban/rate table shared with Tcl under a lock, a Windows-only runtime component; the largest risk of the options | **no** (a C component, the first in TclGuard itself) |
| C | **Deeper listen queue** (`SOMAXCONN_HINT(n)`, Windows 8 / Server 2012 and later, 200-65,535) | absorbs bursts: a 1-2 second burst no longer refuses visitors | one line in the driver. Does nothing for a sustained flood, and a deep queue is a *wait* instead of a refusal: at 700 accepts per second a 2,000-entry queue means about 3 seconds of waiting, and most entries are already dead connections | yes |
| D | **Put something in front** of a Windows guard: a Linux VPS running TclGuard (nftables drops about 29,000 connections per second), a CDN, or a router with SYN-flood protection | removes the problem for the Windows machine | a second machine or a service | yes |
| E | **Try Tcl 9.0 / 8.7** | unknown. Searching found nothing that says its Windows driver differs (still `WSAAsyncSelect` plus a helper thread, as far as I can tell) | a new runtime build for all three systems and a retest; cheap to *measure* (build, run `acceptbench`), expensive to adopt | yes |
| F | Replace the driver's design (completion ports, or `WSAEventSelect` with several waiting threads) | the real fix, in principle | a rewrite of about 3,500 lines of Tcl core; not realistic here | yes, but not realistic |
| G | Several guard processes on one port | none on Windows: no `SO_REUSEPORT`, and Tcl 8.6 does not offer `-reuseaddr` for load sharing | - | - |
| H | Windows Firewall rate limits | none: `netsh advfirewall` has no per-source rate or connection limit (the kernel filter that could is a driver) | - | - |

## Recommendation

1. **Today**: D for anything that matters; the README and docs/LOAD.md already say so.
2. **Next, cheap and measurable**: A, judged only by `acceptbench.yml` (clean runners), `stress-win.yml` (no stalls) and the flood test. If it gives 2x or better, keep it.
   Revert the "accept again immediately" change from the first patch if A makes it redundant (it is worth about 1.3x and adds a code path).
3. **Only if A is not enough and Windows hosting matters**: B, kept as small as possible (a ban set and a per-source rate limit; everything else stays in Tcl).
4. C is harmless and could be added with A, with a modest depth (about 1,000), once its latency effect has been measured.
5. E is worth one afternoon of measurement before investing in A or B, because it would settle whether the upstream driver is already fixed.


## Option A, tried: no effect

Built and measured (`acceptbench.yml`, one fresh runner per variant): register and unregister sockets with `WSAAsyncSelect` directly instead of by a blocking message
to the helper thread (three fewer thread hand-offs for every connection that is created, accepted or closed).

| bare accept-and-close on Windows | accepted per second |
|---|---|
| runtime without any socket patch | 711, 731, 828 (three runs) |
| first patch version (reads and writes; the build that ships) | 676, 709 |
| with direct registration (option A) | 532, 542, 872 |

All within the run-to-run noise of this runner (the same variant varied by 1.5x between runs), so **no measurable effect**. The change was reverted; the shipped
Windows runtime is the stress-tested one from before. What the experiments did show:

* **The Tcl script is not where the time goes.** Timed inside the accept callback: the script *including* `close` takes 3-4 microseconds of the 1,200-1,500 microseconds
  each accepted connection takes in wall-clock time (0% of the total). The cost is in the event machinery and the driver around it.
* **`WSAAsyncSelect` itself is cheap**: about 25 microseconds per call, measured in C without Tcl (`winsock_cost.c`, `winsock-cost.yml`). Removing hand-offs to the
  helper thread therefore could not have bought much, which is what the Tcl measurements found.
* **The C model of Tcl's design is inconclusive.** A plain C server fed by 8 or 96 blocking client threads manages only 420-850 accepts per second whatever the server
  does (blocking `accept()`, notification-driven, draining or not): the *client* side of that test is the limit (blocking `connect()` on Windows is slow), so it cannot
  rank server designs. It also shows that draining every pending connection per notification (what option A's accept loop would add) is not the lever: 437/s with
  48 wake-ups against 421/s with 4,300.
* **What is still unexplained:** Python (blocking `accept()`, one thread) handled 2,955, 7,883 and 13,382 accepts per second against the *same* flood generator, 4-20x
  what Tcl does, so a faster accept path exists on this machine; I do not know which part of Tcl's path costs the 1.2 ms.

## What would settle it

A runtime built with timing probes (QueryPerformanceCounter around `accept()`, the channel set-up, the notifier wake-up and the event-loop turn, printed at exit)
run in `acceptbench.yml` would show where the 1.2 ms goes in about an hour of work. Until then the only option with evidence behind it is **B** (a native acceptor: a blocking
`accept()` loop in its own thread is the one design shown to reach thousands per second on this machine), or **D** (something in front).
