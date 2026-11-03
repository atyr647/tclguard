# Prebuilt TclGuard starpacks

| File | Platform | Size |
|---|---|---|
| `tclguard-linux-x86_64` | Linux x86-64 (glibc 2.39+, X11 for the GUI) | ~11.6 MB |
| `tclguard-windows-x86_64.exe` | Windows x86-64, double-click GUI (no console window) | ~12.3 MB |
| `tclguard-macos-arm64` | macOS on Apple silicon (Tk is native Aqua; TLS via tcltls 2.0.1 + static OpenSSL 3.5.9) | ~9.3 MB |
| `tclguard-macos-x86_64` | macOS on Intel | ~9.9 MB |
| `tclguard-windows-x86_64-console.exe` | The same program flagged as a console app: use this one from Command Prompt / PowerShell so `selftest`, `ctl status`, `check` print their output | ~12.3 MB |

Each is **one self-contained file**: Tcl 8.6.14, Tk 8.6.14, tcludp 1.0.11, tcltls (1.7.22 on Linux and Windows, 2.0.1 on macOS) with a static OpenSSL 3.5.9, Metakit and the TclGuard
application. No installer, no Tcl installation needed.

```sh
chmod +x tclguard-linux-x86_64
./tclguard-linux-x86_64 selftest        # watch it defend itself (no changes to your system)
sudo ./tclguard-linux-x86_64            # GUI (or --headless on a server)
```

Windows: double-click `tclguard-windows-x86_64.exe`. For the Windows Firewall integration click **Restart as administrator** inside the app (Windows asks once). **Start TclGuard when I sign in** (Settings) creates a Scheduled Task, so it survives reboots without any command line.

## What has and has not been verified

Checked on **real GitHub-hosted runners** (Windows Server 2025 as administrator, macOS on Apple Silicon, Ubuntu) by
`.github/workflows/ci.yml`, on every push; all three are green for this release. See also `docs/LOAD.md` (flood test) and the README's Verification table.

| | Linux | Windows | macOS |
|---|---|---|---|
| Starpack in this folder | yes | yes (both .exe) | **yes (arm64 and Intel)** |
| `selftest` (15 live-attack checks incl. UDP relay) | yes | **yes, real Windows** | **yes, the starpack on a real Mac** (and from source) |
| Unit tests (342 checks: config, bans, firewall command logic, crypto, installer, updater ...) | yes | **yes, run by the Tcl inside the starpack** (Unix-simulating installer/updater tests are skipped there) | yes |
| Integration: real sockets, 48 HTTP + 57 feature checks incl. UDP, WebSocket, PROXY protocol | yes | **yes, against the Windows starpack** | **yes, against the Mac starpack** |
| TLS termination (own tcltls + static OpenSSL 3.5.9 in the starpacks) | 39 checks, source and starpack | **34 checks, real Windows, starpack** | **39 checks, the Mac starpack** (and from source with tcltls 2.0.1) |
| Let's Encrypt (ACME) against Pebble | 20 checks, source and starpack | **20 checks, real Windows** | 20 checks |
| IPv6 end to end | 11 checks | **11 checks** | 11 checks |
| Single file updates itself from a signed manifest, keeps `.previous`, rolls back | 12 checks, the shipped starpack | **15 checks, real Windows (a helper swaps the file after the exit)** | **13 checks, the Mac starpack updates itself** (+ 53 source checks) |
| Installer / uninstaller | real systemd unit, self-removal | **user and system scope, shortcuts, Add/Remove Programs, Scheduled Task, deferred self-removal** | **the Mac starpack installs itself and the installed copy removes itself**; plist lint, launchctl with a stand-in program |
| Kernel firewall rule install / ban / unban / remove | nftables, real kernel (22 checks) | **Windows Firewall via `netsh`: 2,500 bans over 5 rules** | pf: 18 platform checks |
| Live connection scan (`netstat`) | `/proc` | **parsed from a real Windows table** | parsed from BSD netstat |
| Start at sign-in | XDG autostart entry | **Task Scheduler task created, read back, removed** | LaunchAgent |
| GUI | Xvfb (36 flows) | **36 scripted flows on a real desktop** | **36 under Aqua, in the Mac starpack, also run as root** (what *Restart as administrator* produces) |
| HTTP parser fuzzer | 0 findings in the CI smoke run, 103 regression checks | (the parser is the same Tcl) | (same) |
| Sustained flood test (mixed soak etc.) | yes, loopback and network namespaces with the kernel firewall, [docs/LOAD.md](../docs/LOAD.md) | **yes, loopback, with and without `netsh` bans** | **yes, loopback, with and without `pf` bans** |

The macOS programs were built **on real Mac runners** (`.github/workflows/runtime-macos.yml`: Apple silicon and Intel) and are wrapped from the committed
runtimes in `tools/runtimes/` by `tools/rewrap.sh`. They carry only the linker's ad-hoc signature (no paid developer certificate, no notarization), so
after downloading run `xattr -cr tclguard-macos-arm64` once (or right-click, *Open*); see `docs/ELEVATION.md`. Only the arm64 build runs in the full test suite
(the runner is Apple silicon); the Intel build was built and passed the self-test on an Intel runner, nothing more.

Not verified anywhere: behaviour under a real multi-gigabit flood or over a real network (the flood test is loopback on one machine), the
"Restart as administrator" UAC / osascript prompts (they need a person to click), signed updates against a real release (the signing key has
not been generated yet, see `docs/UPDATES.md`), and real-world uptime.

The plain Windows executable uses the GUI subsystem (no console window), so command-line output does not appear in
Command Prompt. Use `tclguard-windows-x86_64-console.exe` for command-line work (it is the same file with one PE header
field changed, subsystem 2 -> 3; it passes the same self-test on real Windows). Run `tclguard-windows-x86_64-console.exe --gui`
if you want the window plus a console.

Linux runtime note: dynamically linked against glibc 2.39 (built on Ubuntu 24.04) and X11 for the GUI.
On older distributions rebuild the runtime there with `tools/build-tclkit.sh linux` and wrap with `make starpack`.

## Verify downloads

`sha256sum -c SHA256SUMS`

Runtimes are built from source with KitCreator (`tools/build-tclkit.sh`); the payload is added by `build.tcl`.
