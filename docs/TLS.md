# HTTPS (TLS termination) and automatic certificates

TclGuard can terminate TLS itself, so an HTTPS website gets the same request inspection, rate limits and bans as a plain one. Your real server keeps speaking ordinary HTTP to TclGuard on 127.0.0.1.

```
 visitor ──HTTPS──▶ TclGuard :443 (decrypts, inspects, limits) ──HTTP──▶ your site 127.0.0.1:8080
```

## The easy way (GUI)

**Protection → Add protection → "HTTPS website (free certificate)"**, enter your domain name and where your real site listens. That creates two protections:

* **port 443**: HTTPS, with a free certificate from Let's Encrypt that TclGuard fetches and renews by itself;
* **port 80**: sends visitors to the https:// address, and answers Let's Encrypt's "is this really your domain?" check.

Requirements: the domain name must point at this computer's public address, and ports **80 and 443 must be reachable from the internet** (forward them on your router). Until the certificate arrives (usually a few seconds) visitors get a temporary self-signed certificate and browsers warn.

The certificate status is shown on the protection's row and in **Edit → HTTPS**. If ordering fails (wrong DNS, port 80 blocked, rate limits) the reason is shown, TclGuard retries with back-off (5 min, 15 min, 1 h, 6 h, 24 h) and **Get certificate now** retries at once. Use Let's Encrypt's staging server (`acmeDirectory https://acme-staging-v02.api.letsencrypt.org/directory`) while experimenting: it has generous rate limits but its certificates are not trusted by browsers.

## Your own certificate

Edit → HTTPS: turn on HTTPS, leave the automatic option off, and give the paths of your certificate file (the certificate followed by any intermediate certificates, PEM) and private key (PEM). The files are re-read for every new connection, so renewing a certificate (for example with certbot or acme.sh) needs no restart. Expiry is shown and warned about 14 days ahead.

## What it protects against, specifically

* **No handshake work for bad guys.** Banned, blocklisted and rate-limited addresses are refused *before* any TLS work is done.
* **Handshake limits.** At most `tlsMaxHandshaking` (default 256) unfinished handshakes at once, each with a `tlsHandshakeTimeout` (default 10 s); silent clients are cut off and earn a strike.
* **Garbage is punished, rejection is not.** A client that sends non-TLS bytes earns strikes; a client that merely rejects your certificate (self-signed, name mismatch) does not.
* **Renegotiation.** TLS 1.2 client-initiated renegotiation (a classic way to burn server CPU from one connection) is detected and the connection is dropped with a strike. TLS 1.3 has no renegotiation. Verified against the starpack's OpenSSL.
* **Protocols.** TLS 1.2 and 1.3 only (`tlsMinVersion 1.3` for modern clients only); SSLv3, TLS 1.0 and 1.1 are refused.
* **No silent downgrade.** If the certificate or key cannot be loaded, or the two do not match, the listener refuses to start; it never falls back to plain HTTP.
* The backend learns the real scheme through `X-Forwarded-Proto: https` (client-supplied values are discarded unless the request came through a trusted proxy).

## Honest limits

* **One certificate per listener.** Several names can share one certificate (list them all in `tlsNames`), but you cannot serve different certificates for different names on the same port (the TLS library cannot select a certificate by SNI).
* **HTTP-01 only.** Automatic certificates need port 80 reachable. No wildcard certificates and no IP-address certificates (those need DNS validation).
* No OCSP stapling, no HTTP/2 (clients fall back to HTTP/1.1), no client-certificate authentication.
* **Handshakes are CPU work in a single Tcl thread.** An ECDSA certificate (the automatic and generated ones) is cheap; a large RSA key costs several times more per handshake. A flood of *valid* handshakes from many addresses can still saturate one core; that is what the kernel firewall and an upstream scrubbing service are for.
* The pure-Tcl crypto (used for generated certificates, ACME and update signatures) is not constant-time. It runs on your own machine for a handful of operations a day; do not reuse it as a general crypto library.

## Behind Cloudflare or another proxy

Let the proxy terminate TLS to visitors and keep TclGuard on plain HTTP, with `trustedProxies` set so the real visitor address is used. Or terminate TLS in TclGuard and use the proxy in "full (strict)" mode with an automatic or origin certificate.
