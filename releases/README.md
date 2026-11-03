# Prebuilt TclGuard starpacks

| File | Platform | Size |
|---|---|---|
| `tclguard-linux-x86_64` | Linux x86-64 (glibc 2.39+, X11 for the GUI) | ~5 MB |
| `tclguard-windows-x86_64.exe` | Windows x86-64 | ~6.4 MB |

Each is **one self-contained file**: Tcl 8.6.14, Tk 8.6.14, tcludp 1.0.11, Metakit and the TclGuard
application. No installer, no Tcl installation needed.

```sh
chmod +x tclguard-linux-x86_64
./tclguard-linux-x86_64 selftest        # watch it defend itself (no changes to your system)
sudo ./tclguard-linux-x86_64            # GUI (or --headless on a server)
```

Windows: double-click `tclguard-windows-x86_64.exe` (right-click, *Run as administrator* for the Windows Firewall integration).

## What has and has not been verified

| | Linux | Windows |
|---|---|---|
| Starts, `version` | yes | yes (under Wine) |
| `selftest` (15 live-attack checks incl. UDP relay) | yes, native | yes, **under Wine only** |
| GUI renders | yes, native (Xvfb) | yes, **under Wine only** |
| Headless daemon + `ctl`, kernel firewall install/remove | yes, native | not tested |
| Windows Firewall (`netsh`) integration | n/a | **not tested on real Windows** |

Wine is a compatibility layer, not Windows. The Windows binary is built and smoke-tested, not field-tested.

The Windows executable uses the GUI subsystem (no console window): command-line output (`selftest`, `ctl`)
does not appear in a plain Command Prompt; redirect it (`tclguard-windows-x86_64.exe selftest > out.txt`) or use the GUI.

Linux runtime note: dynamically linked against glibc 2.39 (built on Ubuntu 24.04) and X11 for the GUI.
On older distributions rebuild the runtime there with `tools/build-tclkit.sh linux` and wrap with `make starpack`.

## Verify downloads

`sha256sum -c SHA256SUMS`

Runtimes are built from source with KitCreator (`tools/build-tclkit.sh`); the payload is added by `build.tcl`.
