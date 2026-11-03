# Signed updates

TclGuard can update itself, but only to a release that **you** (the maintainer) signed. This page is the
trust model, how to set the keys up, how to cut a release, how users update, and what is *not* protected.

## Commands

```sh
tclguard update check          # is there a newer release? (works without a key, but says "NOT verified")
tclguard update apply          # download, verify, test-run, swap in; keeps the old program as <name>.previous
tclguard update rollback       # put the previous program back
tclguard update status         # current version, release key fingerprint, last check, previous copy
tclguard update keygen --out release-signing.key     # maintainers only: create the signing key
```

`--url URL` overrides the feed for one command; the permanent setting is `updateUrl` in the `general`
section of the config (default `https://github.com/atyr647/tclguard/releases/latest/download/manifest.json`).
The GUI uses the same API (`::tg::update::check|apply|rollback|status|autoCheck`).

## Trust model

* A release is described by **`manifest.json`**, signed with an **ECDSA P-256** key. The signature is in
  **`manifest.json.sig`** (base64url of the raw 64-byte `r||s`) and covers the *exact bytes* of the manifest.
* The matching **public** key is embedded in every TclGuard, in
  `tclguard.vfs/lib/tclguard/vendor/update-key.pub` (one line, `tgpub1:<base64url of the 65-byte point>`).
  The private key is never in the repository.
* **Nothing from the manifest is read before its signature verified.** Then, for `apply`:
  1. the manifest must be valid (https URLs only, safe file names, sha256 and size per file, size 1 B..64 MB);
  2. its version must be **strictly newer** than the running one (no downgrade, no replay of an old release);
     if `min` is set and the running version is older, `apply` refuses and says to download by hand;
  3. the file for this platform (`linux-x86_64`, `windows-x86_64`, `macos-arm64`, ...; the Windows console build
     uses `windows-x86_64-console` when the manifest has it) is downloaded to a temporary file **next to the
     installed program**, with the signed size as a hard limit *while downloading*;
  4. size and **SHA-256** must match the signed values;
  5. the new program is run as `<new> version` (20 s limit) and must print `TclGuard <the manifest's version>`,
     which proves it runs on this machine;
  6. the swap: on Unix the old program is copied to `<name>.previous`, then the new file is renamed over it
     (atomic). On Windows the running exe is renamed to `<name>.old` (Windows allows that), the new file takes
     its name, `.previous` is kept too, and `.old` is deleted at the next start.
  Every failure path leaves the old program in place and deletes the temporary file.
* **Transport:** HTTPS only (an `http://` feed, an `http://` download URL in the manifest, and a redirect to
  `http://` are all refused). Certificates are verified against the chain **and the host name** by
  `::tg::https`. TLS is defence in depth; the **signature** is what is trusted, so a CDN or proxy that
  re-terminates TLS cannot change a release.
* **While the embedded key is the `UNSET` placeholder**, `update apply` refuses (with an explanation) and
  `update check` still works but marks everything *unverified*.

Testing hooks (not for production): `TG_CA_FILE` / the `caFile` config key point the update download at a
different CA bundle (used by the integration test and for private mirrors; the signature still decides what
is trusted). `--target FILE` replaces that file instead of the running program (packagers, tests).

## One-time setup (maintainer)

```sh
tclguard update keygen --out release-signing.key
```

It writes the private key with owner-only permissions (it refuses to overwrite an existing file) and prints
the public key line and a fingerprint.

1. Paste the `tgpub1:...` line into `tclguard.vfs/lib/tclguard/vendor/update-key.pub`, replacing `tgpub1:UNSET`.
   Commit it, **rebuild the starpacks** (`make starpack`, see the README) so the key is inside them.
2. Add the key file's *text* as the GitHub Actions secret **`RELEASE_SIGNING_KEY`**.
3. Move `release-signing.key` somewhere offline (password manager, encrypted USB). **Anyone holding it can
   publish updates every TclGuard will install.** Publish the fingerprint (README) so people can compare it
   with `tclguard update status`.

Lose the key and you cannot ship updates that existing installs accept: they must be reinstalled by hand with
a build that embeds a new key. Rotating the key works the same way.

## Cutting a release

1. Bump `VERSION` in `tclguard.vfs/lib/tclguard/util.tcl`, build the starpacks into `releases/`, commit.
   (A new program must print the version in the manifest for `apply` to accept it.)
2. `git tag v1.2.3 && git push origin v1.2.3`.
3. `.github/workflows/release.yml` runs the unit tests, checks that the Linux starpack reports the tagged
   version, builds `manifest.json` from `releases/tclguard-*`, signs it with `RELEASE_SIGNING_KEY` and creates
   the GitHub Release with the binaries, `manifest.json` and `manifest.json.sig`. Without the secret it
   publishes nothing and says why.

By hand (for example, to sign offline):

```sh
tclsh8.6 tools/release-manifest.tcl --dir releases --version 1.2.3 --key release-signing.key \
    --notes-file notes.txt --out dist/        # then upload dist/* and the binaries to the release
```

The tool refuses to sign with a key that is not the one embedded in the app (every installed copy would
reject the release) unless you pass `--allow-key-mismatch` (key rotation), and it re-verifies its own signature.
File names it picks up: `tclguard-<linux|windows|macos>-<x86_64|arm64|x86|arm>[-console][.exe]`.

## How users update

`tclguard update check`, then `tclguard update apply`; restart TclGuard afterwards. If the new version
misbehaves, `tclguard update rollback`. The GUI offers the same through buttons. Running `apply` needs write
permission to the folder holding the program (administrator for `C:\Program Files\TclGuard`, root for
`/usr/local/bin`). Programs run from source files, or through another Tcl runtime, never replace themselves:
`apply` refuses.

`autoCheck` (called by the GUI/engine) asks at most once per 24 hours (an hour after a failed attempt), only
when `updateCheck yes` is set in the config (default **no**), and never installs anything. The request tells
the update server (GitHub by default) your IP address and that you run TclGuard, like any download.

## What is NOT protected

* **A stolen or leaked signing key.** There is no revocation or key-transparency mechanism; recovery means
  shipping a new build with a new embedded key.
* **Withholding and freezing.** A network attacker (or a compromised GitHub account that cannot sign) can keep
  serving an older, validly signed release, or block updates entirely. Version monotonicity stops *downgrades*,
  not *staleness*. There is no expiry timestamp in the manifest.
* **The first download.** Nothing protects the very first copy of TclGuard you download (or the embedded public
  key in it) except HTTPS to GitHub and the checksums in `releases/SHA256SUMS`. Compare the key fingerprint
  with the one the maintainer publishes.
* **A compromised build machine or repository** that changes the embedded public key before the starpacks are
  built: the signature check only proves "signed by the key this build contains".
* **Local attackers.** Anyone who can write the installed program or `update-key.pub` inside the starpack
  already controls the machine. `update apply` runs as whoever runs it.
* **The new program's behaviour.** The test run proves it starts and reports the right version, not that it is
  correct.
* The pure-Tcl ECDSA code is not constant-time; it only *verifies* on users' machines (public data) and signs
  on the maintainer's.
