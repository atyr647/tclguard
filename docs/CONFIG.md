# Configuration reference

The config file is a plain Tcl dictionary (never executed as code). Lines starting with `#` are comments. Anything you leave out uses the default. `tclguard check` validates it and explains mistakes; the GUI edits the same file.

Default location: Linux `~/.config/tclguard/tclguard.conf` (or `/etc/tclguard/` when root and that folder exists); Windows `%APPDATA%\TclGuard\tclguard.conf`. Override with `--config FILE` or `TCLGUARD_HOME`.

```
general   { ...global settings... }
listeners { name { ...one protected port... } ... }
watchers  { name { ...log watcher... } ... }
```

## general

| Key | Default | Meaning |
|---|---|---|
| `firewall` | `auto` | `auto`, `nft`, `iptables`, `netsh`, `none`. Needs root/administrator; otherwise proxy-level protection only. |
| `harden` | `0` | Install kernel rate limits / drops for protected ports. |
| `hardenSynRate` / `hardenSynBurst` | 40 / 80 | New TCP connections per second (burst) per source address on protected TCP ports. |
| `hardenUdpRate` / `hardenUdpBurst` | 1000 / 2000 | Packets per second (burst) per source on protected UDP ports. |
| `hardenConnLimit` | 200 | Concurrent connections per source per port (only if the kernel supports `ct count`; skipped automatically otherwise). |
| `hardenIcmpRate` | 10 | Echo requests per second. |
| `hardenDropInvalid`, `hardenDropFragments`, `hardenDropBogusFlags` | 1 | Drop invalid-state packets / IP fragments / impossible TCP flag combinations. |
| `removeRulesOnExit` | 0 | Remove the kernel table when TclGuard exits (default keeps protection running). |
| `allowlist` | LAN + loopback | Addresses/CIDRs that are never limited or banned. |
| `blocklist` | empty | Addresses/CIDRs that are always refused. |
| `strikeThreshold` | 10 | Strikes before a ban. |
| `strikeLeakPerSec` | 0.25 | Strikes forgiven per second. |
| `banSteps` | `60 600 3600 21600 86400` | Ban seconds for the 1st, 2nd, … offence (the last repeats). |
| `banResetAfter` | 86400 | Seconds of good behaviour after which offence history is forgotten. |
| `autoLevel` / `autoLockdown` | 1 / 0 | Adaptive threat level / allow it to enter Lockdown on its own. |
| `levelFactors` | `1.0 0.6 0.35 0.2` | Multiplier applied to per-address limits at each level. |
| `thConnPerSec`, `thBlockedPerSec`, `thRxPps`, `thRxLinkPct` | see source | Three thresholds each: Elevated, Under attack, Lockdown (0 = off). |
| `linkMbps` | 100 | Your download speed, used for link saturation. |
| `watchPorts` | empty | TCP ports served *directly* (not proxied) to watch for floods via `/proc`/`netstat`. |
| `controlEnable`, `controlHost`, `controlPort`, `controlToken` | 1, 127.0.0.1, 9737, generated | Local management socket used by `tclguard ctl`. |

## listeners

Common: `type` (`http` `tcp` `udp`), `enabled`, `bind` (`0.0.0.0`; `::` for IPv6), `port`, `backendHost` (`127.0.0.1`), `backendPort`, `note`.

**tcp / http**: `maxConns`, `maxConnsPerIP`, `connRate` (+`connWindow`, 10 s), `idleTimeout`, `maxLifetime`, `lazyConnect` (connect to the backend only after the client sent data; turn **off** for server-speaks-first protocols like SSH/SMTP), `proxyProtocol` (`none` `v1` `v2`).
tcp only: `firstByteTimeout`.

**http** extras: `reqRate` (+`reqWindow`), `headerTimeout`, `keepAliveTimeout`, `bodyTimeout`, `maxHeaderBytes`, `maxHeaders`, `maxUriLength`, `maxBodyMB`, `methods`, `forwardIp`, `trustedProxies`, `realIpHeader`, `challenge` (`off` `auto` `always`), `challengeTtl`, `pathLimits` (list of `{regex count seconds}`).

**udp**: `maxSessions`, `maxSessionsPerIP`, `newSessionRate` (+`newSessionWindow`), `pps`, `bytesPerSec`, `replyBytesPerSec`, `minPacket`, `maxPacket`, `sessionTimeout`, `banOffenders`.

All per-address limits are multiplied by the current threat-level factor (never below 1).

**HTTPS (tcp / http listeners):** `tls` (`yes`/`no`), `tlsCert` + `tlsKey` (your own PEM files; leave both empty to use a managed certificate in `<state>/certs/<listener>.pem`), `tlsNames` (DNS names / addresses for the managed self-signed certificate and for ACME), `tlsMinVersion` (`1.2` or `1.3`), `tlsCiphers` (OpenSSL cipher string for TLS 1.2; default is ECDHE + AES-GCM/ChaCha20), `tlsHandshakeTimeout` (seconds, default 10), `tlsMaxHandshaking` (cap on unfinished handshakes across the guard, default 256). **Automatic certificates:** `acme` (`yes`/`no`), `acmeEmail`, `acmeDirectory` (default Let's Encrypt production; the staging URL is `https://acme-staging-v02.api.letsencrypt.org/directory`), `acmeCaFile` (trust file for a private ACME server, normally empty). **Redirect (http listeners):** `redirectHttps` + `redirectPort` send plain-HTTP visitors to the https:// address. See [TLS.md](TLS.md).

## watchers

```
watchers {
  sshd {
    file /var/log/auth.log
    # the first (capture group) must be the client address:
    pattern {Failed password for .* from ([0-9a-fA-F:.]+) port}
    hits 5
    window 120
    # banSec 0 = use the escalating ban lengths:
    banSec 0
  }
}
```

Comments must be on their own line (a `#` after a value is part of the value).
Watchers start at the end of the file (old history never causes bans) and survive log rotation.
