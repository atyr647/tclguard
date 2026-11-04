# Windows connection floods: what limits the guard, and the options for fixing it properly

Status: options A (and two variants of it, below) were **tried and did not help**; the cause of the slow accept path in Tcl is **not yet found**. The rest has not been implemented. Numbers are from GitHub's Windows Server 2025 runner (`acceptbench.yml`,
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


## Round two: the accept path measured inside Tcl, and a C model that did not transfer

**Probes in the driver** (a Windows runtime with timing probes, run through `acceptbench` under the flood; the probe patch has since been removed): per accepted connection, the
`accept()` call itself took 380 microseconds on average, rising to 750 (and about 95 ms per call at the very end, when only a trickle was left); three synchronous messages to the
helper thread took 96 microseconds each; creating the channel 118, running the accept callback 133 (of which `close` 41), `getnameinfo` 5. And the **rate collapsed over the run**: about
2,200 accepts per second in the first 6 seconds, 445 in the next 6, about 10 in the last 6. That is a different picture from "a constant 1.2 ms per accept".

**A raw C accept loop under the same flood** (`tests/load/winsock_cost.c`, `winsock-cost.yml`, one runner per mode, the same `tgload connflood` generator as every other test here):

| accept loop (no Tcl) | accepts per second |
|---|---|
| plain blocking `accept()` | about 12,000, steady |
| `WSAAsyncSelect(FD_ACCEPT)`, one accept per notification (Tcl's design) | 1,400-2,700, then **28-69** |
| the same, draining every pending connection per notification | 7,500-11,000, steady |
| draining plus registering every accepted socket directly (`WSAAsyncSelect` on, off) | 9,275, steady |
| draining plus registering by **synchronous messages** to the pump thread, three per connection (Tcl's pattern) | 537, then **0** |

Read this table with the next section in mind: **each row is a single run, and runs of the same binary were later found not to agree**, so the "collapse" rows are a hint, not a measured cause.

**The patches that did exactly that did not help in Tcl.** A patch that drains the pending connections per notification (up to 16, in a tight loop) *and* registers sockets directly instead of by
synchronous message was built and measured on its own runner (`acceptbench`, bare accept-and-close under the flood):

| runtime | accepts per second |
|---|---|
| without any socket patch | 604, 629, 711, 731, 828 |
| first patch (reads and writes; the one that ships) | 676, 709, 742, 924, 940 |
| batched accept only | 587, 773 |
| direct registration only (option A) | 532, 542, 872 |
| both together, built cleanly | 504, 618 |
| Python, blocking `accept()` | 2,955, 5,643, 6,555, 7,883, 8,781, 13,382 |

(Two of those builds, "batched" and the first "both", carried a stale probe patch that had applied partly because the build script did not clear patches left in a reused build directory;
that is fixed in `tools/build-tclkit.sh`, and the "both together, built cleanly" row is a clean build whose source was compared byte for byte with the intended patch.)

**So the C model is not predictive for Tcl**, and I do not know why. Candidates, none tested: something else the Tcl driver does per connection that the model lacks (the notifier
thread and its wake-ups, the `SO_` options Tcl sets, `Tcl_CreateChannel`'s own bookkeeping, a lock the socket thread shares with the main thread, the 10,000-message limit of a Windows
message queue); or an interaction in Tcl's event loop that keeps `accept()` slow. The shipped Windows runtime is therefore still the stress-tested first patch. The next step that would
settle it is the probe build again, on the driver as patched in the "both together" row: if `accept()` is then fast and the time is elsewhere, the probes say where; if `accept()` is still
hundreds of microseconds, the cause is in how Tcl drives the listening socket, and a native acceptor (option B) would sidestep it.


## Round three: the probes on the combined driver, and why the C model cannot be trusted

**Probes on the clean combined driver** (batched accept + direct registration; probe patch `tools/patches/profile/`, run under the same flood): every accept event took a full batch of 16, so the
queue is never short. Yet `accept()` took **296 microseconds each** in the first 6 seconds and **712** in the next (30-60 in the C model), the accept callback 145, `closesocket` 81, creating the
channel only 8 (the three registrations now cost 20 each), and the socket thread's message handler **137 microseconds per message** (1.3 before) with 4,320 `FD_ACCEPT` notifications for 13,260 accepts.
The rate still fell from about 2,200 per second to a trickle. So the work is not in the registration messages or in the channel set-up any more; the kernel's `accept()` itself is slow in this
process, and the socket thread is slow too (it takes the shared lock for every message while the main thread holds it across the drain loop).

**The C model then failed its own repeat.** Further modes, one fresh runner each:

| mode (no Tcl, same flood) | accepts per second |
|---|---|
| drain + direct registration (mode 3), two runs | 6,445 and 9,275 |
| the same with a message handler that burns 20 microseconds per message (mode 7) | 9,416 (no collapse) |
| the same with fewer notifications per connection (mode 8) | 4,447 (no collapse) |
| the handler takes a kernel-event lock per message, the lock Tcl uses (mode 6) | **571 (collapsed to 0)**, and on the repeat **4,250 (no collapse)** |
| the same with a user-mode lock (mode 9) | 4,332 |

The same binary gave 571 once and 4,250 the next time, so single C runs cannot separate causes on these runners, and the "both are enough to collapse" reading of round two is withdrawn. The Tcl
numbers, by contrast, are consistent: about 500-1,000 accepts per second in more than twenty runs of five different driver variants, always collapsing over the run.

**What this leaves.** Nothing tried changes the Tcl accept rate (first patch, direct registration, batching, both), the cause of the slow `accept()` inside the Tcl process is not identified, and the
cheap experiments are exhausted: each further idea needs a driver build (about 40 minutes with a measurement) and the evidence so far says the effect of such changes is not predictable from a model.
The sensible choices are **D** (put something in front of a Windows guard that has to survive connection floods), or **B** (a native acceptor, the one design measured at thousands per second on
these runners: Python's blocking `accept()` loop against the same flood, 2,955 to 13,382 per second), with the caveat that B has not been measured inside this process either.
