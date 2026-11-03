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

See `packaging/tclguard.service`. Raise `LimitNOFILE` (each proxied connection uses two descriptors).

## Windows

Run `tclguard.exe` as Administrator for the Windows Firewall integration. To start at boot, use Task Scheduler ("Run with highest privileges", trigger "At startup", action `tclguard.exe --headless --config C:\ProgramData\TclGuard\tclguard.conf`).
