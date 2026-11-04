# TclGuard

DDoS and abuse protection for **game servers** and **websites you host at home**, written entirely in Tcl/Tk and designed to ship as a single-file starpack.

TclGuard sits in front of your real server. Visitors talk to TclGuard first; it throws out floods, malformed requests and slow-drip attacks, and only passes good traffic through. On Linux it also pushes every ban and (optionally) per-address rate limits into the **kernel firewall** (nftables), so a flood is dropped for almost no CPU before a single byte reaches Tcl.

```
 players / visitors ──▶  TclGuard (public port)  ──▶  your real server (127.0.0.1:other port)
                              │
                              └─▶ kernel firewall: bans + rate limits (nftables / ipset / Windows Firewall)
```

## Read this first: what it can and cannot do

| It **can** | It **cannot** |
|---|---|
| Stop connection floods, request floods, slowloris / slow-POST, malformed and request-smuggling HTTP, UDP packet floods, brute-force logins (log watchers), connection hogging | Stop a flood that **fills your internet line itself**. If an attacker sends 500 Mbit/s into a 100 Mbit/s home connection, your router drowns before any software on your PC sees the packets. Only your ISP, or a provider with a bigger network, can fix that. |
| Keep a small server alive through attacks that would exhaust it | Make a game server immune to attacks that exploit the *game's own* bugs |
| Drop hostile traffic in the kernel when run as root/administrator | Verify who a **UDP** packet really came from (source addresses can be forged; see below) |

**The realistic setup for serious attacks** is to run TclGuard on a cheap VPS that has DDoS protection, point your domain / game address at the VPS, and have it forward to your home server over WireGuard. Your home IP then stays secret and the VPS absorbs the flood. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). For websites, a CDN (e.g. Cloudflare) in front plus TclGuard's *trusted proxies* setting works too.

## Quick start

1. **Move your real server off the public port.** Minecraft on `25566` instead of `25565`, or bind it to `127.0.0.1`. If the real server stays directly reachable, attackers just skip TclGuard.
2. **Run TclGuard** (`tclguard`, or `tclsh8.6 tclguard.vfs/main.tcl` from source). With a display it opens the control window; on a headless server it runs without one.
3. **Protection tab → "+ Add protection"**, pick your game or "Website", confirm the two ports. It takes effect immediately.
4. **Forward the public port** on your router to this computer and test from *outside* your network (mobile data).
5. **Firewall tab → install rules**, run as administrator/root. This is what makes it hold up against real floods.
6. Click **Help -> Run self-test** to watch it fend off a simulated attack on your own machine.

**You never need a terminal on Windows or macOS.** Everything is in the window: *Restart as administrator* (for the kernel firewall), *Start TclGuard when I sign in*, *Open data folder*, the self-test, and every setting. The command line (`tclguard ctl ...`) exists for servers without a screen.

Headless / server:

```sh
tclguard init --preset minecraft-java      # writes a starter config
tclguard check                             # validate it
sudo tclguard --headless                   # run (root for the kernel firewall)
tclguard ctl status                        # manage the running instance
tclguard ctl ban 203.0.113.5 3600 spamming
tclguard ctl unban 203.0.113.5
tclguard ctl level 2                       # force "under attack" mode
```

A systemd unit is in [packaging/tclguard.service](packaging/tclguard.service); `sudo tclguard install --service` sets it up for you.

**Install and update without a terminal:** `tclguard install` (Start Menu / application menu entry, Apps list on Windows, optional start at boot) and `tclguard uninstall` remove exactly what they added, see [docs/INSTALL.md](docs/INSTALL.md). `tclguard update check|apply|rollback` installs only releases signed with the maintainer's key, see [docs/UPDATES.md](docs/UPDATES.md).

## What's inside

| Layer | What it does |
|---|---|
| **HTTP inspector** (`http` listeners) | Strict streaming HTTP/1.x parser. Refuses anything ambiguous (conflicting `Content-Length`, `Content-Length` + chunked, obfuscated `Transfer-Encoding`, bare LF, obsolete folding, absolute-URI/`CONNECT` proxying, missing/duplicate `Host`). Header and body timeouts (slowloris, slow-POST), size limits, per-address request-rate and per-path limits (`/login` brute force), real-client-IP from trusted proxies, `X-Forwarded-For` rewriting (spoofed values are replaced), WebSocket upgrade tunnelling, a cookie **browser check** while under attack. |
| **TCP relay** (`tcp` listeners) | Per-address connection caps and connection-rate limits, first-byte timeout, idle timeout, lazy backend connect (silent attackers never touch your server), flow-controlled relay, PROXY protocol v1/v2 so your server can still see real player addresses. HTTPS can run through it in passthrough mode. |
| **UDP relay** (`udp` listeners) | One upstream socket per player, per-address packets/s, bytes/s, session count, join rate, packet-size limits, and a cap on *replies* so it cannot be used as an amplifier. |
| **Bans** | Violations add *strikes* that fade over time; enough strikes ⇒ ban. Ban length escalates for repeat offenders (1 min → 10 min → 1 h → 6 h → 24 h by default). Bans survive restarts. IPv6 is handled per `/64` (attackers own whole `/64`s). Allowlist (never limited/banned) and blocklist, with CIDR ranges. |
| **Adaptive threat level** | Normal → Elevated → Under attack → Lockdown, driven by connection rate, block rate, packets/s and link saturation. Limits shrink automatically; Lockdown admits only addresses that behaved well before. Needs two consecutive seconds to raise and a calm period to lower, so one spike doesn't flap it. |
| **Kernel firewall** | nftables (preferred), iptables+ipset, or Windows Firewall. Bans go in as timed set elements (they expire by themselves even if TclGuard dies). Optional *hardening*: per-source SYN/UDP/ICMP rate limits, invalid/fragment/bogus-flag drops, per-source connection counting where the kernel supports it (detected automatically). |
| **Monitors / watchers** | `/proc` (Linux) or `netstat` (Windows) scan for servers you *can't* proxy; fail2ban-style log watchers (sshd, nginx presets). |
| **Front ends** | A modern Tk desktop app (sidebar navigation, light and dark themes, live status hero, sparklines and a hoverable traffic chart, preset tile wizard, inline allow/block chips, anti-aliased icons rendered at runtime so it needs no image files), plus headless mode and a local control socket + CLI. |

## Honest limits

* **One Tcl thread, about 450 proxied connections.** Measured (4-core VM, see [docs/LOAD.md](docs/LOAD.md)): one core serves about 5,000 to 7,000 HTTP requests/s, rejects about 29,000 hostile connections/s, and 16 steady visitors saw 250 requests/s with no errors through every attack type for 5 minutes. The one thing that slows visitors is a request flood that stays just under every per-address limit (200 addresses, 4,500 requests/s): they were served 20 to 30 ms slower. Tcl 8.6 watches descriptors with `select()`, so a process can never hold more than about 1,000 of them (the guard caps itself at about 450 proxied connections and says so). More threads do not help much (1.5x on 3 cores, [docs/WORKERS.md](docs/WORKERS.md)), so there are none. Past roughly 10,000 new connections/s only the kernel can keep up, which is why the kernel firewall matters.
* **UDP and spoofing.** UDP source addresses can be forged, so an attacker could in principle get a *friend's* address banned. Bans are temporary and escalate gently, allowlisted addresses are immune, and each UDP listener has `banOffenders no` to switch bans off (limits still drop packets). Put friends' addresses on the allowlist.
* **UDP needs the `udp` extension** (tcludp). The game server sees every player as `127.0.0.1` (the relay's upstream socket); per-player IP bans inside the game won't work through a UDP relay.
* **HTTPS** can be terminated by TclGuard itself (your own certificate, a self-signed one, or automatic Let's Encrypt certificates over HTTP-01), so the full HTTP inspection applies to HTTPS too: [docs/TLS.md](docs/TLS.md). One certificate per listener (tcltls has no server-side SNI). `tcp` listeners can still pass TLS through untouched. HTTP-01 needs port 80 reachable from the internet; wildcard certificates (DNS-01) are not supported.
* **IPv6** (`bind ::`, per-/64 bans, UDP over IPv6, PROXY protocol) is tested end to end with real sockets on Linux, **real Windows and real macOS** (11 checks). On Windows `bind ::` is IPv6-only, so a site that must answer both families needs two listeners (`0.0.0.0` and `::`).
* **Windows and macOS** are tested on real GitHub runners (see Verification), not on years of home setups. **Both ship as single files** (`releases/`: Windows x86-64, macOS arm64 and Intel, the latter built on Mac runners by `.github/workflows/runtime-macos.yml`). Each passes the self-test, the integration suites, TLS termination and Let's Encrypt issuance against a test CA, its kernel-firewall tests (`netsh` with 2,500 bans over 5 rules; `pf`), the GUI flows, and it **updates itself and rolls back** on the real machine (a running Windows starpack cannot be renamed, so a small helper swaps the file once the program has exited: [docs/UPDATES.md](docs/UPDATES.md)). The Windows UAC path (`Restart as administrator`) is tested end to end on a real runner; on macOS the AppleScript, the root path and the GUI-as-root are tested, but **nobody has typed a password into the real dialogs yet**: [docs/ELEVATION.md](docs/ELEVATION.md). The programs are not signed with a paid developer certificate, so SmartScreen and Gatekeeper ask once (same document). Linux has the deepest testing (real-kernel nftables, real systemd).
* **Windows is still the slow platform, but much less than it was.** Tcl 8.6's Windows socket driver makes several thread switches per I/O; the Windows program is built with a small patch for that (`tools/patches/`, explained there), which took one core from about 830 to about 4,000 HTTP requests/s (Linux about 10,000, macOS 4,500-8,000) and the mixed attack from starving visitors completely (4 req/s) to 136 req/s with about 9% of requests refused. Under a connection flood the operating system can still *refuse* new connections before the guard sees them (the guard cannot ban what it never sees); the Windows Firewall bans (administrator, `netsh`) help once an address is banned. The patch was checked with 18,000 keep-alive sessions against a control built without it (the first version of the patch *did* stall one, which is how the check earned its place), but it is a change to Tcl itself and has not run for months in production. For anything beyond a hobby audience on Windows, the VPS/CDN setup is still the safer choice: [docs/LOAD.md](docs/LOAD.md).
* **Kernel hardening** drops *all* IP fragments and invalid-state packets, and rate-limits ICMP. Disable those options (Settings / config) if you run something that relies on them (some VPNs, VoIP).

## Verification

Everything below was run against this code. "Real" means a real GitHub-hosted Windows Server 2025 / macOS (Apple silicon) / Ubuntu machine, not an emulation. `releases/README.md` has the per-platform matrix.

| Suite | What it proves | Result |
|---|---|---|
| `make unit` | IP/CIDR math, config validation, ban/strike/escalation logic, threat-level state machine and its per-visitor scaling, firewall command generation (incl. injection attempts, Windows command-length chunking), log watchers, autostart, crypto (ECDSA verified against RFC 6979 vectors and OpenSSL), HTTPS client host-name checks, installer and updater logic | 342 checks pass |
| `make kernel` (root) | Real nftables in network namespaces: bans drop traffic and expire in-kernel; SYN flood 600→~40 connects; 70 simultaneous connections capped at the 40-per-source limit; UDP flood 6000→~400 packets; counters; clean uninstall | 22 checks pass |
| `make integration` | Real sockets against real backends: malformed/smuggling requests refused, byte-exact bodies, pipelining, half-close, keep-alive, slowloris/slow-POST, rate limits and bans, challenge cookie, trusted proxy, WebSocket, PROXY protocol v1/v2, UDP relay, lockdown, CLI, persistence, signed updates against a local HTTPS server, and the reserved-capacity rule | 48 + 57 + 53 + 6 checks pass on Linux; 48 + 57 on real Windows; 48 + 57 + 53 on real macOS |
| `tests/integration/test_tls.py` | TLS termination: TLS 1.2/1.3 only, certificate chains, renegotiation and key-update handling, handshake caps and timeouts, X-Forwarded-Proto, no plaintext fallback | 39 pass on Linux (source and single file) and on real macOS (tcltls 2.0.1); 34 on real Windows (the `openssl s_client` renegotiation / key-update checks are Unix-only) |
| `tests/integration/test_acme.py` | Automatic certificates against Let's Encrypt's own test CA (Pebble): issuance, chain, renewal path, failure back-off, redirect | 20 pass on Linux, real Windows and real macOS |
| `tests/integration/test_ipv6.py` | IPv6 listeners, backends, PROXY protocol, UDP, per-/64 bans, end to end | 11 pass on Linux, real Windows and real macOS |
| `test_update_starpack.py` | The shipped single file updates **itself** (signed manifest, local HTTPS), keeps `.previous`, rolls back, byte for byte | 12 pass on Linux, 15 on real Windows (where a helper swaps the file after the exit) |
| `tests/fuzz` | HTTP parser fuzzer: generated and mutated requests judged by an independent strict reference parser and 27 lenient-backend models (smuggling/desync), identity headers, CPU amplification (limit calibrated to the machine), leaks and liveness; every finding is a regression test | 0 findings in the CI smoke run; 103 regression checks |
| `tests/load/run_flood.py`, `run_flood_netns.sh` | Sustained flood test with per-second sampling: request, connection, slowloris, garbage, TLS handshake, UDP and spoofed SYN floods and a mixed soak while 16 visitors browse; loopback on all three systems, plus a real kernel network path with and without the kernel firewall on Linux | Linux: visitors saw 227-261 req/s with no errors in every phase except one (a request flood just under the limits); macOS the same with `pf`; **Windows holds a mixed attack at about 136 of 256 req/s (before the socket patch: 4)**; see [docs/LOAD.md](docs/LOAD.md) |
| `tests/integration/test_leaks.py` | 14,400 abusive connections (RST, half-close, stalls, garbage, oversize): every table drains to zero, descriptors return to baseline, memory flat | pass |
| `make gui-test` | Drives every GUI flow through the real widgets (wizard, edit dialog, bans, lists, level selector, settings, themes, autostart, HTTPS tab, self-test dialog) and fails on any background error | 36 checks pass (Xvfb, real Windows, real macOS under Aqua in the Mac starpack, and the Mac starpack run as root) |
| `tclguard selftest` | Live attack simulation you can run on your own machine | 15 checks pass |
| `tests/platform/` | `netsh` firewall lifecycle and 2,500 bans over 5 rules, Task Scheduler, `netstat`, `pf`, LaunchAgent; the installer on real Windows (user and system scope: shortcuts, Add/Remove Programs, Scheduled Task, self-removal of the running program) and real systemd | pass on the real systems |
| GitHub Actions (`ci.yml`) | All of the above on Ubuntu, Windows (the shipped starpack) and macOS; every step runs even if an earlier one failed | see the badge / Actions tab |

An independent review of the HTTP/TCP/UDP/firewall/control code found, and this release fixes: request smuggling through chunk trailers and through an Upgrade request with a body, a use-after-close leak, an uncaught error on a malformed cookie, two CPU-wedge patterns (floods of blank lines / tiny chunks), a UDP descriptor leak, descriptor budgeting across UDP sessions, byte-offset drift in log watchers on invalid UTF-8, underscore-spelled `X_Real_IP` spoofing, and non-canonical keys reaching firewall commands. UDP reputation learning is now off by default because UDP addresses can be forged.

## Getting and building the starpack

**Prebuilt single-file starpacks are in [`releases/`](releases/)** (Linux x86-64, Windows x86-64, macOS arm64 and macOS Intel, about 9-12 MB each, Tcl + Tk + UDP + TLS + TclGuard in one file; see `releases/README.md` for exactly what was verified on each platform and `SHA256SUMS` to check them).

To build your own:

```sh
tools/build-tclkit.sh linux        # ~15 min: builds a tclkit with Tk, tcludp, Thread, Metakit (KitCreator)
tools/build-tclkit.sh win64        # cross-compile for Windows (needs mingw-w64)
tools/build-tclkit.sh macos        # native, on a Mac (arm64 or Intel); CI does it: .github/workflows/runtime-macos.yml
cp .tclkit-build-linux/kc/tclkit-8.6.14 /tmp/rt     # wrap using a COPY of the runtime
make starpack RUNTIME=/tmp/rt                       # -> dist/tclguard
```

`build.tcl` writes a Metakit payload (run it *with* a tclkit that has `vfs::mk4`) or a zip payload (`--format zip`, needs only tclsh + tcllib). The payload is platform independent, so one machine can wrap both runtimes. The runtime must include **Tk** (for the GUI; headless mode works without it) and **`udp`** (tcludp, for the game-UDP relay).

Prebuilt tclkits found online are old and lack Tk and `udp`, which is why `tools/build-tclkit.sh` exists. Without any runtime, `tclsh8.6 tclguard.vfs/main.tcl` runs it directly (needs `tcl`, `tk` for the GUI, `tcl-udp` for UDP).

## Layout

```
tclguard.vfs/main.tcl            entry point, CLI
tclguard.vfs/lib/tclguard/       util  config  bans  firewall  limiter  tcpproxy  httpproxy
                                 udprelay  monitor  logwatch  control  engine  gui  selftest
                                 install  update  (installer, signed self-update)
build.tcl  Makefile              packaging;  tools/build-tclkit.sh builds the runtimes
releases/                        prebuilt starpacks (+ checksums)
experimental/xdp/                XDP/eBPF spike (see docs/XDP.md)
tests/                           unit (*.test), kernel/, integration/, gui/ (screenshot driver)
docs/                            CONFIG.md  DEPLOYMENT.md
packaging/tclguard.service       systemd unit
```

## License

MIT (see `LICENSE`). `vendor/sha256.tcl` is from tcllib (Tcl/Tk license).
