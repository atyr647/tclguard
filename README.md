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
6. Run `tclguard selftest` any time to watch it fend off a simulated attack on your own machine.

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

A systemd unit is in [packaging/tclguard.service](packaging/tclguard.service).

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

* **One Tcl thread.** Measured on a 4-core sandbox: ~3,000 HTTP requests/s through the inspector (one core, 11 MB RAM), ~900 complete connect-request-close cycles/s, and ~10,000–14,000 hostile connections/s *rejected* per core. That is plenty for a home site or game server, and it is why kernel-level dropping matters: past ~10k new connections/s only the kernel can keep up.
* **UDP and spoofing.** UDP source addresses can be forged, so an attacker could in principle get a *friend's* address banned. Bans are temporary and escalate gently, allowlisted addresses are immune, and each UDP listener has `banOffenders no` to switch bans off (limits still drop packets). Put friends' addresses on the allowlist.
* **UDP needs the `udp` extension** (tcludp). The game server sees every player as `127.0.0.1` (the relay's upstream socket); per-player IP bans inside the game won't work through a UDP relay.
* **No TLS termination.** HTTPS works in `tcp` passthrough mode (connection-level protection only). For full HTTP inspection of HTTPS, terminate TLS elsewhere (Caddy, nginx, Cloudflare) and put TclGuard behind it with the `http` listener.
* **IPv6 listening** (`bind ::`) is implemented and its address logic and nftables rules are tested, but the end-to-end socket path could not be exercised in the build environment (no IPv6 stack). Treat as beta.
* **Windows**: the Windows paths (`netsh` firewall rule, `netstat` scan, GUI) are implemented and their command/parse logic is unit-tested, but TclGuard has not yet been run on a real Windows machine. Linux is the verified platform.
* **Kernel hardening** drops *all* IP fragments and invalid-state packets, and rate-limits ICMP. Disable those options (Settings / config) if you run something that relies on them (some VPNs, VoIP).

## Verification

Everything below was run against this code:

| Suite | What it proves | Result |
|---|---|---|
| `make unit` | IP/CIDR math, config validation, ban/strike/escalation logic (incl. CIDR range bans), threat-level state machine, firewall command generation (incl. injection attempts), log watchers, packaging | 173 checks pass |
| `make kernel` (root) | Real nftables in network namespaces: bans drop traffic and expire in-kernel; SYN flood 600→~40 connects; 70 simultaneous connections capped at the 40-per-source limit; UDP flood 6000→~400 packets; counters; clean uninstall | 22 checks pass |
| `make integration` | Real sockets against real backends: 20 malformed/smuggling requests refused, byte-exact bodies (5 KB, 1.5 MB, chunked), pipelining, half-close, keep-alive, slowloris/slow-POST, rate limits and bans, challenge cookie, trusted proxy, WebSocket, PROXY protocol v1/v2, UDP relay, lockdown, CLI, persistence, plus regression tests for every issue an independent code review found | 105 checks pass |
| `python3 tests/integration/test_leaks.py` | 14,400 abusive connections (RST, half-close, stalls, garbage, oversize) in three rounds: every table drains to zero, descriptors return to baseline, memory flat after the first round | pass |
| `make gui-test` | Drives every GUI flow through the real widgets under a virtual display (wizard, edit dialog, toggles, bans, allow/block lists, level selector, settings, theme switch) and fails on any background error | 21 checks pass |
| `tclguard selftest` | Live attack simulation you can run on your own machine | 15 checks pass |
| `tools/lint_vars.py` | Catches procs that use namespace variables without declaring them | clean |

An independent review of the HTTP/TCP/UDP/firewall/control code found, and this release fixes: request smuggling through chunk trailers and through an Upgrade request with a body, a use-after-close leak, an uncaught error on a malformed cookie, two CPU-wedge patterns (floods of blank lines / tiny chunks), a UDP descriptor leak, descriptor budgeting across UDP sessions, byte-offset drift in log watchers on invalid UTF-8, underscore-spelled `X_Real_IP` spoofing, and non-canonical keys reaching firewall commands. UDP reputation learning is now off by default because UDP addresses can be forged.

## Building the starpack

The application is the VFS tree in `tclguard.vfs/` (`main.tcl` + `lib/`). A **starpack** is that tree wrapped around a Tcl runtime ("tclkit") into one executable.

```sh
make kit                                        # dist/tclguard.kit  (payload; run with any tclkit: tclkit tclguard.kit)
make starpack RUNTIME=/path/to/tclkit-8.6-linux-x86_64     # single-file Linux program
make starpack RUNTIME=/path/to/tclkit-8.6-win64.exe         # single-file Windows tclguard.exe
```

`build.tcl` writes either a Metakit payload (classic tclkit, run it *with* a tclkit so `vfs::mk4` is available) or a zip payload. Use a tclkit that includes **Tk, `udp` (tcludp) and `vfs`**; [KitCreator](https://kitcreator.rkeene.org/) can build one with `KITCREATOR_PKGS="udp"`. Without `udp` the game-UDP relay is unavailable but everything else works; Tk is only needed for the GUI (headless mode runs without it).

Without any runtime, `tclsh8.6 tclguard.vfs/main.tcl` runs it directly (needs `tcl`, `tk` for the GUI, `tcl-udp` for UDP).

## Layout

```
tclguard.vfs/main.tcl            entry point, CLI
tclguard.vfs/lib/tclguard/       util  config  bans  firewall  limiter  tcpproxy  httpproxy
                                 udprelay  monitor  logwatch  control  engine  gui  selftest
build.tcl  Makefile              packaging
tests/                           unit (*.test), kernel/, integration/, gui/ (screenshot driver)
docs/                            CONFIG.md  DEPLOYMENT.md
packaging/tclguard.service       systemd unit
```

## License

MIT (see `LICENSE`). `vendor/sha256.tcl` is from tcllib (Tcl/Tk license).
