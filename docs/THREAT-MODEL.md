# Threat model

What TclGuard defends against, what it does not, and which assumptions its defences rest on. If a claim here is wrong, that is a bug:
see [SECURITY.md](../SECURITY.md).

## What is being protected

A server (a game, a website, any TCP/UDP service) behind a home or small-VPS connection, from **abusive clients on the internet**: floods of
connections or requests, slow-connection tricks, malformed or smuggled requests, brute-force on login paths, and the cheaper kinds of
volumetric flood. And the guard's **own integrity**: its configuration, ban list, certificates and updates.

## Who the attackers are

| Attacker | Can | Cannot (by design) |
|---|---|---|
| Anonymous client, one address | open connections, send any bytes, forge any HTTP header | exceed per-address limits for long, make the guard spend more CPU than a normal request costs by more than a small factor, forge its source address on a TCP connection |
| Many addresses (botnet) | stay under every per-address limit, collectively exceed what the machine can serve | be stopped by a program on the machine being flooded: only capacity in front of it (CDN, VPS with DDoS protection, ISP filtering) does that |
| Client behind a trusted proxy | have its address taken from `X-Forwarded-For` (rightmost entry that is not a trusted proxy) | choose its address: entries to the left of the nearest proxy are ignored, an unreadable nearest entry means the header is not believed |
| Spoofed-source UDP sender | make the guard think packets came from someone else | cause a bystander to be banned: UDP reputation learning is off by default and UDP sessions for unknown sources are capped to half the table |
| Local user without root on the same machine | connect to the control port, create files in shared temp folders | learn the token from the port (challenge-response, the token never crosses the connection), pre-create the guard's secret files (owner-only, exclusive creation, no following of links) |
| Network position between guard and update server | tamper with downloads | install anything not signed by the maintainer's key, roll the program back to an older version |
| Network position between a client and the guard | read plain HTTP | (that is what TLS termination is for) |

## Assumptions

* The machine and its operating system are not already compromised, and the account that runs the guard is the one you meant.
* The configuration file and the state folder are writable only by the operator. They hold the control token and private keys (mode 0600).
* The system clock is roughly right. A backwards step is absorbed (internal time never runs backwards); a large forward step shortens bans.
* The backend is trusted to speak HTTP correctly; the guard defends the backend against malformed *requests*, not against its own bugs.
* For HTTP, the guard's strict parser and the backend must agree on message boundaries. The guard refuses everything ambiguous
  (conflicting lengths, `Transfer-Encoding` tricks, obsolete line folding, lookalike header names) rather than forwarding it.

## Defences, and what each one rests on

| Layer | Defence | Limit of the defence |
|---|---|---|
| Kernel (optional, needs root) | nftables / iptables / `pf` / Windows Firewall bans with expiry in the kernel; SYN, UDP and ICMP rate limits; invalid-packet drops | Only as good as the platform's firewall; `netsh` rules are slower to update than nftables sets |
| Accept | global and per-address connection caps, a reserved share of capacity for addresses that already behaved well, connection-rate limits, lockdown mode | One Tcl process holds about 450 proxied connections; beyond that the guard refuses, it does not crash |
| HTTP | strict parsing with hard limits (header size and count, URI length, body size, chunk and trailer limits), slow-request deadlines, request-rate and per-path limits, cookie challenge under attack, websocket-only `Upgrade` | A flood that stays under every per-address limit from very many addresses is served, only slower |
| TLS | TLS 1.2/1.3 only, handshake caps (global, per address, with a reserve for known addresses), deadlines, renegotiation refused | One certificate per listener (no SNI) |
| Reputation | strikes that fade, escalating bans, trusted-visitor learning that raises limits for good behaviour | Addresses are the only identity there is; many users behind one NAT share a fate |
| Control plane | local-only listener, HMAC challenge-response in both directions, bounded input, connection and idle limits, token rotation | Anyone who can read the config file is the operator |
| Files | owner-only exclusive creation, atomic writes, symbolic links refused for logs and secrets, validated reloads (a bad config leaves the running one in place) | Root-run copies in user-owned folders hand ownership back only for the files the guard itself made |
| Updates | signed manifest, size and SHA-256 checks, test run of the new program, downgrade refused, previous version kept for rollback | A signed manifest can be replayed to *hide* a newer release (a freeze); the guard cannot tell it is stale |
| Operations | dry-run mode, overload detection (event-loop lateness), alert webhook, health/metrics endpoint | Alerts leave through a third party you choose; a dead network cannot send them |

## Known limitations (also in the README)

* A volumetric flood bigger than your link is not something this program can fix.
* One process, one thread: roughly 450 simultaneous proxied connections and about 5,000-10,000 requests per second on Linux (about 4,000 on
  Windows). More than that needs a CDN or a different design.
* On Windows the operating system can refuse a connection flood before the guard sees it ([docs/WINDOWS-ACCEPT.md](WINDOWS-ACCEPT.md)).
* Packaging is not paid-certificate signed; no human has typed a password into the real macOS elevation dialog yet.
* No third-party penetration test has been done. The audits so far were done by the author and by automated review agents, with fuzzing,
  flood, chaos and browser tests; that finds a great deal and still is not the same thing.
