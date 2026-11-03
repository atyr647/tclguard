# Deployment patterns

## 1. Everything on the home machine (small risk, casual attackers)

```
internet ─▶ router (forward port) ─▶ this PC: TclGuard :25565 ─▶ game server 127.0.0.1:25566
```

* Move the game/web server to a different port or to `127.0.0.1`.
* Forward the **public** port on the router to this PC.
* Run TclGuard as root/administrator and install the kernel rules (Firewall tab, `Kernel hardening` on).
* Put your own devices/friends on the allowlist (defaults already cover your LAN).

This handles connection floods, slowloris, request floods, small UDP floods and bad requests. It does **not** protect a saturated internet link.

## 2. TclGuard on a protected VPS, server stays at home (recommended against real attacks)

```
internet ─▶ VPS (DDoS-protected network): TclGuard :25565 ─▶ WireGuard tunnel ─▶ home server 10.8.0.2:25565
```

1. Rent a small VPS from a provider that includes DDoS mitigation.
2. Set up WireGuard between the VPS (`10.8.0.1`) and your home machine (`10.8.0.2`).
3. Home server listens only on the WireGuard address (or is firewalled to the VPS).
4. On the VPS, a listener forwards to the home server:
   ```
   listeners {
     mc {
       type tcp
       port 25565
       backendHost 10.8.0.2
       backendPort 25565
       proxyProtocol v1
     }
   }
   ```
5. Point your DNS/game address at the VPS. Your home IP is never exposed, so floods hit the VPS network, not your line.

Add `10.8.0.0/24` (the tunnel) to the VPS allowlist only if you trust everything inside it, and remember the default allowlist contains private ranges: on a VPS, remove them if clients can appear from private addresses (e.g. behind a cloud NAT).

## 3. Website behind a CDN/tunnel (Cloudflare etc.)

TclGuard sees the CDN's addresses, not visitors'. Tell it which peers to trust so limits apply to the real visitor:

```
listeners {
  site {
    type http
    port 8080
    backendPort 8081
    # the CDN's published address ranges:
    trustedProxies {173.245.48.0/20 103.21.244.0/22}
    realIpHeader CF-Connecting-IP
  }
}
```

Only trust addresses you know belong to the CDN, and make sure the origin port is reachable *only* from them (kernel firewall), otherwise anyone can forge the header.

## Systemd (Linux)

See `packaging/tclguard.service`. Leave `LimitNOFILE` at 1024: Tcl 8.6's event loop cannot use file descriptors numbered 1024 or higher (the process would abort), so raising the limit makes TclGuard *less* safe. One process holds about 450 proxied connections (two descriptors each); beyond that, new connections are refused at the global cap rather than crashing.

## Windows

No Command Prompt is needed. Double-click `tclguard-windows-x86_64.exe`:

* **Restart as administrator** (banner on the Overview page, button on the Firewall page) re-launches it elevated so the Windows Firewall integration works. Windows asks once.
* **Settings -> Start TclGuard when I sign in** creates a Scheduled Task that runs it at logon with highest privileges.
* **Settings -> Open data folder** opens the config and logs in Explorer; **Help -> Run self-test** shows the attack simulation in a window.

The plain `.exe` has no console window. Use `tclguard-windows-x86_64-console.exe` if you want `tclguard ctl status` style output in a terminal, or for headless servers:
`tclguard-windows-x86_64-console.exe --headless` (Task Scheduler: trigger "At startup", run with highest privileges).

## macOS

There is no macOS starpack yet (a Tk kit for macOS has to be built on a Mac with `tools/build-tclkit.sh`). From source:

```sh
brew install tcl-tk@8                      # Tcl/Tk 8.6 (the system one is 8.5)
# tcludp is needed for UDP game relays: build it from https://sourceforge.net/projects/tcludp/
/opt/homebrew/opt/tcl-tk@8/bin/wish8.6 tclguard.vfs/main.tcl
```

Bans go into a `pf` table under the `com.apple/tclguard` anchor (needs root; the app offers *Restart as administrator*). *Start TclGuard when I sign in* installs a LaunchAgent.
