# Security policy

## Reporting a vulnerability

Please report security problems privately: open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private
vulnerability reporting), rather than a public issue. Include what you did, what you expected and what happened; a failing request or a
config file that reproduces it is the most useful thing you can send. This is a hobby project run by one person: expect an answer within
about a week, and a fix as fast as its size allows.

## What counts

TclGuard sits between the internet and your server, so these matter most:

* anything that lets an outside party **get past a limit or a ban** it should not be able to get past (including by forging a client address);
* anything that lets an outside party **crash, hang or exhaust** the guard much more cheaply than ordinary traffic would;
* a request the guard and the backend can **disagree about** (request smuggling, desynchronisation);
* a way to **read or change** the configuration, the control token, bans or keys without being allowed to;
* a flaw in the **installer or the signed updater** (installing something that was not signed by the maintainer, overwriting files that were
  not part of the install).

What does not count: "a large enough flood from enough addresses takes the connection down". No program on the machine that is being
flooded can prevent that, and the documentation says so ([README](README.md#read-this-first-what-it-can-and-cannot-do),
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)).

## Supported versions

Only the latest release is supported. `tclguard update check` tells you whether you are on it; updates are signed.

## How releases are protected

* The updater installs only files listed in a manifest that is **signed with the maintainer's key** (ECDSA P-256); the public key is embedded
  in the program. A build without an embedded key refuses to update at all. Downgrades are refused. See [docs/UPDATES.md](docs/UPDATES.md).
* The signing key is a repository secret that only the signing step of the release workflow can read; it is never written to disk or logs.
* GitHub build-provenance attestations are attached to the release files (`gh attestation verify <file> --repo <owner>/<repo>`), where the
  repository's plan allows them.
* The runtimes the programs are built on are reproducible from `tools/build-tclkit.sh`: the build framework is pinned to one check-in and
  verified by hash, OpenSSL and tcltls are pinned by hash, and the framework pins the rest by hash.
* The programs are **not** signed with a paid code-signing certificate (Windows) or notarised (macOS), so SmartScreen / Gatekeeper warn on the
  first start ([docs/ELEVATION.md](docs/ELEVATION.md)). The updater's own signature check does not depend on them.

## Hardening you should do yourself

[docs/HARDENING.md](docs/HARDENING.md) is the deployment checklist: a dedicated service account or the systemd unit, a kernel firewall,
`dryRun` first, alerts, the metrics endpoint, protecting the control token, and what to put in front of the guard for serious attacks.
