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

| | Linux | Windows |
|---|---|---|
| Starts, `version` | yes | yes (under Wine) |
| `selftest` (15 live-attack checks incl. UDP relay) | yes, native | yes, **under Wine only** (both .exe variants) |
| GUI renders | yes, native (Xvfb) | yes, **under Wine only** |
| Headless daemon + `ctl`, kernel firewall install/remove | yes, native | not tested |
| Windows Firewall (`netsh`) integration | n/a | **not tested on real Windows** |

Wine is a compatibility layer, not Windows. The Windows binary is built and smoke-tested, not field-tested.

The plain Windows executable uses the GUI subsystem (no console window), so command-line output does not appear in
Command Prompt. Use `tclguard-windows-x86_64-console.exe` for command-line work (it is the same file with one PE header
field changed, subsystem 2 -> 3; it passes the same self-test under Wine). Run `tclguard-windows-x86_64-console.exe --gui`
if you want the window plus a console.

Linux runtime note: dynamically linked against glibc 2.39 (built on Ubuntu 24.04) and X11 for the GUI.
On older distributions rebuild the runtime there with `tools/build-tclkit.sh linux` and wrap with `make starpack`.

## Verify downloads

`sha256sum -c SHA256SUMS`

Runtimes are built from source with KitCreator (`tools/build-tclkit.sh`); the payload is added by `build.tcl`.
