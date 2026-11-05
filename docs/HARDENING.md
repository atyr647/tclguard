# Hardening checklist

Do these in order; each one is cheap and the first three matter most. Background: [THREAT-MODEL.md](THREAT-MODEL.md).

## 1. Put the guard where it can work

* **Serious attacks need capacity in front of you**, not a program on the machine being flooded. Either run TclGuard on a small VPS with
  DDoS protection that forwards to your home server over WireGuard (your home address stays secret), or put a CDN in front of a website and
  list its addresses under `trustedProxies`. See [DEPLOYMENT.md](DEPLOYMENT.md).
* Make sure the server behind the guard **only accepts connections from the guard** (bind it to `127.0.0.1`, or firewall it). A backend that
  is also reachable directly can be attacked without the guard ever seeing it.
* On Windows prefer the VPS/CDN setup for anything beyond a hobby audience ([WINDOWS-ACCEPT.md](WINDOWS-ACCEPT.md)).

## 2. Use the kernel firewall

Run with the privileges the firewall needs (root / administrator, or the systemd unit's capabilities) and leave `firewall auto`. Banned
addresses then cost almost nothing, because the kernel drops them before the guard sees them. Set `harden 1` to add kernel rate limits.

## 3. Roll out in dry-run first

```sh
tclguard --dry-run            # or:  dryRun 1  in the configuration
```

Automatic bans are only **logged** (`DRY RUN: would ban 203.0.113.9: ...`, at most once a minute per address); nothing is blocked, and bans
you make by hand still work. Run it for a day or two on real traffic. Anyone you do not recognise in that list is a limit that is too tight
for your visitors: raise `reqRate`, `maxConnsPerIP` or `strikeThreshold`, or add them to `allowlist`. Then turn it off.

## 4. Run it as a service, not from a terminal

* Linux: `sudo tclguard install --system --service` (a systemd unit with only `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE`, `NoNewPrivileges`,
  a read-only system, private `/tmp`, no home access, restart after a crash). Leave `LimitNOFILE=1024` alone ([LOAD.md](LOAD.md)).
* macOS: `sudo tclguard install --system --service` (launchd, restarted by `KeepAlive`).
* Windows: `tclguard autostart on` from an administrator prompt creates a scheduled task that starts at sign-in with highest privileges, **has no
  72-hour time limit** (Windows' default for tasks made by `schtasks`), **restarts every minute if it dies**, and runs on battery power.
* Do not run the guard as root just to bind port 80/443 on Linux; the unit grants only that one capability.

## 5. Protect the files

* The configuration file holds the control token and, for TLS, the folder holds private keys: both are created **owner-only (0600/0700)**.
  Leave them that way. Never put the token in a ticket, a chat or a screenshot. `tclguard ctl` reads it from the file or from
  `TCLGUARD_TOKEN`.
* The control port listens on `127.0.0.1` only. Do not change `controlHost` to a public address; if you must reach it remotely use an SSH
  tunnel. The token never crosses the connection (challenge-response), but the port is still an administration interface.
* To rotate the token: change `controlToken` in the file and run `tclguard ctl reload`; every session opened with the old token is dropped.

## 6. Know when something is wrong

```
alertUrl     https://hooks.slack.com/services/...      # Slack, Discord, ntfy, or any URL that accepts a POST
alertFormat  json                                      # "text" for services such as ntfy that want a plain body
alertCooldown 300                                      # seconds between alerts of the same kind (and at most 30 an hour)
```

Alerts are sent when the threat level rises to *Under attack* or higher (and when it returns to normal), when the guard is **overloaded**
(its event loop is running late, which means it cannot keep up: see below), and when the overload ends. Test with `tclguard ctl alert test`.
The request is made by a short-lived helper process, so a slow or dead endpoint cannot stall the guard; the URL is passed in the helper's
environment, not on a command line other users can see. Plain `http://` is accepted only for local addresses.

**Overload** is measured as how late a 100 ms timer fires. If at least 3 of the last 5 seconds had a worst-case lateness of `satLagMs`
(default 250 ms), the guard logs `OVERLOADED`, `/readyz` answers 503 and the alert goes out. When that happens the answer is more capacity in
front of the guard (step 1), not a different setting.

## 7. Watch it

```
metricsEnable 1
metricsHost   127.0.0.1
metricsPort   9738
metricsToken  <at least 16 printable characters, if the endpoint is reachable from other computers>
```

`/healthz` (200 while running), `/readyz` (503 while overloaded) and `/metrics` (Prometheus text: threat level, connections, bans, every
counter, event-loop lag, overload flag, alert counts, per-listener connections). The listener is bounded (small requests, 8 connections,
3-second deadline) and off by default. Useful alerts to set up in your monitoring: `tclguard_overloaded == 1`, `tclguard_threat_level >= 2`
for more than a few minutes, `tclguard_up == 0`, and `rate(tclguard_alerts_failed_total[1h]) > 0`.

## 8. Keep it current

`tclguard update check` (or `updateCheck 1`) and `tclguard update apply`: signed, verified, tested before it replaces the running program,
with `tclguard update rollback` if something is wrong ([UPDATES.md](UPDATES.md)). Watch the repository's security advisories.

## 9. Test it before you need it

* `tclguard selftest` attacks a private copy of itself and prints what held.
* `tclguard check` validates the configuration; a wrong file passed to `ctl reload` is refused and the running configuration stays.
* Practise `tclguard ctl unban <ip>` and `tclguard ctl level 0`, so you know how to let a wrongly banned friend back in.
* After a restart the bans that were saved come back; the kernel rules keep working while the program restarts.

## What this will not do

Absorb a flood bigger than your link; protect a backend that is reachable around the guard; make one process serve more than about 450
simultaneous connections. If your site needs more than that, you need the setup in step 1, not more tuning.
