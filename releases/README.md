# Prebuilt TclGuard starpacks

| File | Platform | Size |
|---|---|---|
| `tclguard-linux-x86_64` | Linux x86-64 (glibc 2.39+, X11 for the GUI) | ~5 MB |
| `tclguard-windows-x86_64.exe` | Windows x86-64, double-click GUI (no console window) | ~6.4 MB |
| `tclguard-windows-x86_64-console.exe` | The same program flagged as a console app: use this one from Command Prompt / PowerShell so `selftest`, `ctl status`, `check` print their output | ~6.4 MB |

Each is **one self-contained file**: Tcl 8.6.14, Tk 8.6.14, tcludp 1.0.11, Metakit and the TclGuard
application. No installer, no Tcl installation needed.

```sh
chmod +x tclguard-linux-x86_64
./tclguard-linux-x86_64 selftest        # watch it defend itself (no changes to your system)
sudo ./tclguard-linux-x86_64            # GUI (or --headless on a server)
```

Windows: double-click `tclguard-windows-x86_64.exe`. For the Windows Firewall integration click **Restart as administrator** inside the app (Windows asks once). **Start TclGuard when I sign in** (Settings) creates a Scheduled Task, so it survives reboots without any command line.

## What has and has not been verified

Checked on **real GitHub-hosted runners** (Windows Server 2025 as administrator, macOS on Apple Silicon, Ubuntu) by
`.github/workflows/ci.yml`, and under Wine / Xvfb during development.

| | Linux | Windows | macOS |
|---|---|---|---|
| Starpack in this folder | yes | yes (both .exe) | none shipped (see below) |
| `selftest` (15 live-attack checks incl. UDP relay) | yes | **yes, real Windows** | yes (from source) |
| Unit tests (config, bans, firewall command logic, monitor parser, autostart) | yes | **yes, run by the Tcl inside the starpack** | yes |
| Integration: real sockets, 48 HTTP + 57 feature checks incl. UDP, WebSocket, PROXY protocol | yes | **yes, against the Windows starpack** | yes |
| Kernel firewall rule install / ban / unban / remove | nftables, real kernel (22 checks) | **Windows Firewall via `netsh`, real rule lifecycle** | pf: 18 platform checks |
| Live connection scan (`netstat`) | `/proc` | **parsed from a real Windows table** | parsed from BSD netstat |
| Start at sign-in | XDG autostart entry | **Task Scheduler task created, read back, removed** | LaunchAgent |
| GUI | Xvfb | **26 scripted flows on a real desktop** | 27 under Aqua |

macOS has no starpack here: a macOS Tk kit has to be built on a Mac. It runs from source with Homebrew's Tcl/Tk 8.6 and
tcludp (see `docs/DEPLOYMENT.md`), which is what the macOS runner tests.

Not verified anywhere: behaviour under a real multi-gigabit flood, IPv6 end to end, the "Restart as administrator" UAC /
osascript prompts (they need a person to click), and real-world uptime.

The plain Windows executable uses the GUI subsystem (no console window), so command-line output does not appear in
Command Prompt. Use `tclguard-windows-x86_64-console.exe` for command-line work (it is the same file with one PE header
field changed, subsystem 2 -> 3; it passes the same self-test on real Windows). Run `tclguard-windows-x86_64-console.exe --gui`
if you want the window plus a console.

Linux runtime note: dynamically linked against glibc 2.39 (built on Ubuntu 24.04) and X11 for the GUI.
On older distributions rebuild the runtime there with `tools/build-tclkit.sh linux` and wrap with `make starpack`.

## Verify downloads

`sha256sum -c SHA256SUMS`

Runtimes are built from source with KitCreator (`tools/build-tclkit.sh`); the payload is added by `build.tcl`.
