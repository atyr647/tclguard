#!/usr/bin/env python3
"""Signed self-update, end to end over real HTTPS: `tclguard update check|apply|rollback` against a local
HTTPS server (Python http.server + ssl, throwaway certificate made with openssl).

Trust anchors used here are throwaway: a fresh signing key per run, embedded in a COPY of the source tree
(so the real code path that reads vendor/update-key.pub is exercised, and no trust-root override exists in
the product), and a throwaway CA file passed through TG_CA_FILE. Needs openssl and tclsh8.6 (TCLSH).
Linux and macOS; the "new program" is a tiny shell script that answers `version`."""
import sys, os, re, ssl, shutil, subprocess, tempfile, threading, time, platform, json, hashlib, socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

TCLSH = os.environ.get("TCLSH", "tclsh8.6")
OPENSSL = shutil.which("openssl")
if not OPENSSL or os.name == "nt":
    print("SKIP update tests: need openssl and a POSIX shell"); sys.exit(0)
OS_KEY = {"linux": "linux", "darwin": "macos"}.get(sys.platform)
ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
if not OS_KEY or not ARCH:
    print("SKIP update tests: unsupported platform", sys.platform, platform.machine()); sys.exit(0)
PKEY = f"{OS_KEY}-{ARCH}"

work = tempfile.mkdtemp(prefix="tgupd")
def P(*a): return os.path.join(work, *a)

# ------------------------------------------------------------------ source copies with embedded keys ----
def copy_tree(name):
    dst = P(name)
    shutil.copytree(os.path.join(ROOT, "tclguard.vfs"), os.path.join(dst, "tclguard.vfs"))
    os.makedirs(os.path.join(dst, "tools"))
    shutil.copy(os.path.join(ROOT, "tools", "release-manifest.tcl"), os.path.join(dst, "tools"))
    return dst

def pubfile(tree): return os.path.join(tree, "tclguard.vfs", "lib", "tclguard", "vendor", "update-key.pub")
def main_tcl(tree): return os.path.join(tree, "tclguard.vfs", "main.tcl")

def run(cmd, env=None, timeout=180):
    e = dict(os.environ); e.update(env or {})
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=e, errors="replace")
    return p.returncode, p.stdout + p.stderr

HOME = P("home"); os.makedirs(HOME)

def tg(tree, *args, ca=True, extra_env=None):
    env = {"TCLGUARD_HOME": HOME, "HOME": HOME}
    if ca: env["TG_CA_FILE"] = P("cert.pem")
    env.update(extra_env or {})
    return run([TCLSH, main_tcl(tree), *args], env)

# throwaway keys, made by the product's own keygen
def keygen(name):
    kf = P(name + ".key")
    rc, out = run([TCLSH, os.path.join(ROOT, "tclguard.vfs", "main.tcl"), "update", "keygen", "--out", kf], {"TCLGUARD_HOME": HOME})
    m = re.search(r"(tgpub1:[A-Za-z0-9_-]{87})", out)
    assert rc == 0 and m, out
    return kf, m.group(1), out

keyA, pubA, keygen_out = keygen("A")
keyB, pubB, _ = keygen("B")
check("keygen prints a public key, a fingerprint and a warning", "Fingerprint" in keygen_out and "KEEP IT SECRET" in keygen_out)
if os.name == "posix":
    check("keygen wrote the private key with 0600", (os.stat(keyA).st_mode & 0o777) == 0o600, oct(os.stat(keyA).st_mode))
rc, out = run([TCLSH, os.path.join(ROOT, "tclguard.vfs", "main.tcl"), "update", "keygen", "--out", keyA], {"TCLGUARD_HOME": HOME})
check("keygen refuses to overwrite an existing key", rc != 0 and "already exists" in out, out)

TREE = copy_tree("app")                    # embeds key A
open(pubfile(TREE), "w").write(pubA + "\n")
TREE_UNSET = copy_tree("app_unset")        # keeps the shipped UNSET placeholder
check("the shipped key file is the UNSET placeholder", "tgpub1:UNSET" in open(pubfile(TREE_UNSET)).read())

# throwaway certificate for localhost
rc, out = run([OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", P("key.pem"),
               "-out", P("cert.pem"), "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"])
assert rc == 0, out

# ------------------------------------------------------------------------------------- the server ----
ROUTES = {}      # path -> spec
REQUESTS = []    # paths requested
SENT = {"bytes": 0}
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        REQUESTS.append(self.path)
        spec = ROUTES.get(self.path)
        try:
            if spec is None:
                self.send_response(404); self.send_header("Content-Length", "0"); self.send_header("Connection", "close"); self.end_headers(); return
            kind = spec[0]
            if kind == "data":
                body = spec[1]
                self.send_response(200); self.send_header("Content-Length", str(len(body))); self.send_header("Connection", "close"); self.end_headers()
                self.wfile.write(body)
            elif kind == "redirect":
                body = b"<html><body>You are being <a href='x'>redirected</a>. " + b"padding " * 40 + b"</body></html>"
                self.send_response(spec[2] if len(spec) > 2 else 302); self.send_header("Location", spec[1])
                self.send_header("Content-Length", str(len(body))); self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(body)
            elif kind == "truncate":      # promises len(body) bytes, sends half, hangs up: "server died"
                body = spec[1]
                self.send_response(200); self.send_header("Content-Length", str(len(body))); self.send_header("Connection", "close"); self.end_headers()
                self.wfile.write(body[: len(body) // 2]); self.wfile.flush()
                self.connection.shutdown(socket.SHUT_RDWR)
            elif kind == "stream":        # more data than anybody asked for
                total = spec[1]
                self.send_response(200); self.send_header("Content-Length", str(total)); self.send_header("Connection", "close"); self.end_headers()
                chunk = b"A" * 65536; sent = 0
                while sent < total:
                    n = min(len(chunk), total - sent)
                    self.wfile.write(chunk[:n]); sent += n; SENT["bytes"] = sent
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
            pass
class Srv(ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, *a): pass
srv = Srv(("127.0.0.1", 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(P("cert.pem"), P("key.pem"))
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"https://localhost:{PORT}"
FEED = f"{BASE}/rel/manifest.json"

# ------------------------------------------------------------------------------------ fixtures ----
def program(version, pad="", mode="ok"):
    body = {"ok": f'if [ "$1" = version ]; then echo "TclGuard {version} (fake)"; fi',
            "fail": "exit 3", "silent": "exit 0"}[mode]
    return f"#!/bin/sh\n{body}\n# {pad}{version} {'x' * 100}\n".encode()

OLD = program("1.0.0")
def sha(b): return hashlib.sha256(b).hexdigest()

def sign(manifest_bytes, keyfile):
    """sign with the product's own code (the release tool does this in CI)"""
    mf = P("tosign.json"); open(mf, "wb").write(manifest_bytes)
    script = (f'source {ROOT}/tclguard.vfs/lib/tclguard/util.tcl; source {ROOT}/tclguard.vfs/lib/tclguard/crypto.tcl; '
              f'source {ROOT}/tclguard.vfs/lib/tclguard/json.tcl; source {ROOT}/tclguard.vfs/lib/tclguard/update.tcl; '
              f'set fh [open {{{mf}}} rb]; set d [read $fh]; close $fh; '
              f'puts -nonewline [::tg::update::signBytes [::tg::update::loadPrivateKey {{{keyfile}}}] $d]')
    sf = P("sign.tcl"); open(sf, "w").write(script)
    rc, out = run([TCLSH, sf]); assert rc == 0, out
    return out.strip()

def manifest(version, files, extra=None):
    m = {"version": version, "issued": "1700000000", "notes": "Fixes things.", "files": files}
    m.update(extra or {})
    return (json.dumps(m, separators=(",", ":")) + "\n").encode()

def entry(path, data, **kw):
    e = {"name": "tclguard-test", "url": f"{BASE}{path}", "sha256": sha(data), "size": len(data)}
    e.update(kw); return e

def publish(version, prog, key=None, sig=True, tamper=None, files_override=None, extra=None, path="/dl/new", served=None, sig_from=None):
    """Serve a release. served = bytes actually sent for the binary (default prog)."""
    ROUTES.clear()
    files = files_override if files_override is not None else {PKEY: entry(path, prog)}
    mb = manifest(version, files, extra)
    s = sign(mb, key or keyA)
    if tamper: mb = mb.replace(*tamper)
    ROUTES["/rel/manifest.json"] = ("data", mb)
    if sig: ROUTES["/rel/manifest.json.sig"] = ("data", (s + "\n").encode())
    ROUTES[path] = ("data", prog if served is None else served)
    return mb

def fresh_target():
    d = tempfile.mkdtemp(dir=work)
    t = os.path.join(d, "app"); open(t, "wb").write(OLD); os.chmod(t, 0o750)
    return d, t
def listing(d): return sorted(os.listdir(d))
def apply(t, tree=None, **kw): return tg(tree or TREE, "update", "apply", "--url", FEED, "--target", t, **kw)
def untouched(d, t): return open(t, "rb").read() == OLD and listing(d) == ["app"]

NEW = program("1.1.0")

# ------------------------------------------------------------------------------- the scenarios ----
print("--- good update")
publish("1.1.0", NEW)
rc, out = tg(TREE, "update", "check", "--url", FEED)
check("check reports the new version, verified", rc == 0 and "1.1.0 is available" in out and "signature verified" in out and "Fixes things." in out, out)
d, t = fresh_target()
rc, out = apply(t)
check("apply succeeds", rc == 0 and "Updated TclGuard 1.0.0 -> 1.1.0" in out, out)
check("the program was replaced by the verified download", open(t, "rb").read() == NEW)
check("the old program was kept as .previous", open(t + ".previous", "rb").read() == OLD)
check("permissions kept (executable)", os.access(t, os.X_OK) and (os.stat(t).st_mode & 0o777) == 0o750, oct(os.stat(t).st_mode))
check("no temporary files were left", listing(d) == ["app", "app.previous"], listing(d))
rc, out = tg(TREE, "update", "status", "--target", t)
check("status mentions the previous copy and the verified release", rc == 0 and "release key:   embedded" in out and "last check" in out, out)
rc, out = tg(TREE, "update", "rollback", "--target", t)
check("rollback restores the previous program", rc == 0 and "Restored the previous program" in out and open(t, "rb").read() == OLD, out)
check("rollback keeps the replaced program for rolling forward", open(t + ".previous", "rb").read() == NEW and listing(d) == ["app", "app.previous"])
d, t = fresh_target()
rc, out = tg(TREE, "update", "rollback", "--target", t)
check("rollback without a previous version fails cleanly", rc != 0 and "no previous version" in out and untouched(d, t), out)

print("--- redirects to https work and the redirect bodies never reach the download")
publish("1.1.0", NEW, path="/dl/final")
m = ROUTES.pop("/rel/manifest.json"); sg = ROUTES.pop("/rel/manifest.json.sig")
ROUTES["/rel2/manifest.json"] = m; ROUTES["/rel2/manifest.json.sig"] = sg
ROUTES["/rel/manifest.json"] = ("redirect", f"{BASE}/rel2/manifest.json", 301)
ROUTES["/rel/manifest.json.sig"] = ("redirect", "/rel2/manifest.json.sig", 302)        # relative redirect
ROUTES["/dl/final-real"] = ROUTES["/dl/final"]
ROUTES["/dl/final"] = ("redirect", f"{BASE}/dl/final-real", 307)
d, t = fresh_target()
rc, out = apply(t)
check("manifest, signature and binary all fetched through https redirects", rc == 0 and open(t, "rb").read() == NEW and listing(d) == ["app", "app.previous"], out)

print("--- tampered or wrongly signed")
publish("1.1.0", NEW, served=NEW.replace(b"1.1.0", b"6.6.6"))
d, t = fresh_target()
rc, out = apply(t)
check("a binary that differs from the signed checksum is refused", rc != 0 and "signed checksum" in out and untouched(d, t), out)

publish("1.1.0", NEW, key=keyB)
d, t = fresh_target()
rc, out = apply(t)
check("a manifest signed by another key is refused", rc != 0 and "signature is NOT valid" in out and untouched(d, t), out)
rc, out = tg(TREE, "update", "check", "--url", FEED)
check("check shows nothing from an invalid manifest", rc != 0 and "1.1.0" not in out.replace("signature is NOT valid", ""), out)

publish("1.1.0", NEW, tamper=(b"Fixes things.", b"Hacked things!"))
d, t = fresh_target()
rc, out = apply(t)
check("a manifest altered after signing is refused", rc != 0 and "signature is NOT valid" in out and untouched(d, t), out)

publish("1.1.0", NEW, sig=False)
d, t = fresh_target()
rc, out = apply(t)
check("an unsigned release is refused", rc != 0 and "not signed" in out and untouched(d, t), out)

print("--- no embedded key: check works but is unverified, apply refuses")
publish("1.1.0", NEW, sig=False)
REQUESTS.clear()
rc, out = tg(TREE_UNSET, "update", "check", "--url", FEED)
check("check works and says NOT verified", rc == 0 and "1.1.0 is available" in out and "NOT verified" in out and "will refuse" in out, out)
REQUESTS.clear()
d, t = fresh_target()
rc, out = apply(t, TREE_UNSET)
check("apply refuses without making any request", rc != 0 and "no release-signing key" in out and REQUESTS == [] and untouched(d, t), (out, REQUESTS))

print("--- downgrade and replay")
publish("0.9.0", program("0.9.0"))
d, t = fresh_target()
rc, out = apply(t)
check("an older signed release is refused (replay)", rc != 0 and "refusing to downgrade" in out and untouched(d, t), out)
publish("1.0.0", program("1.0.0", "same"))
rc, out = apply(t)
check("the same version is reported as up to date and changes nothing", rc == 0 and "already the newest" in out and untouched(d, t), out)

print("--- https only")
publish("1.1.0", NEW)
REQUESTS.clear()
d, t = fresh_target()
rc, out = tg(TREE, "update", "apply", "--url", FEED.replace("https://", "http://"), "--target", t)
check("an http:// feed address is refused before any request", rc != 0 and "non-HTTPS" in out and REQUESTS == [] and untouched(d, t), out)
publish("1.1.0", NEW, files_override={PKEY: entry("/dl/new", NEW, url=f"http://localhost:{PORT}/dl/new")})
rc, out = apply(t)
check("a signed manifest that names an http:// download is refused", rc != 0 and "HTTPS" in out and untouched(d, t), out)
publish("1.1.0", NEW)
ROUTES["/rel/manifest.json"] = ("redirect", f"http://localhost:{PORT}/rel/plain.json")
rc, out = apply(t)
check("a redirect from https to http is refused", rc != 0 and "redirect refused" in out and untouched(d, t), out)
publish("1.1.0", NEW)
ROUTES["/dl/new"] = ("redirect", f"http://localhost:{PORT}/dl/plain")
rc, out = apply(t)
check("a binary download redirected to http is refused", rc != 0 and "redirect refused" in out and untouched(d, t), out)
publish("1.1.0", NEW)
ROUTES["/rel/manifest.json"] = ("redirect", f"https://localhost:{PORT}/rel/manifest.json")     # loop
rc, out = apply(t)
check("a redirect loop ends with an error", rc != 0 and "too many redirects" in out and untouched(d, t), out)

print("--- TLS verification stays on")
publish("1.1.0", NEW)
rc, out = tg(TREE, "update", "check", "--url", FEED, ca=False)
check("a certificate from an unknown CA is refused", rc != 0 and ("handshake" in out or "TLS" in out or "certificate" in out), out)
rc, out = tg(TREE, "update", "check", "--url", FEED.replace("localhost", "127.0.0.1"))
check("a certificate for another host name is refused", rc != 0 and "not valid for that name" in out, out)

print("--- size limits and a dying server")
publish("1.1.0", NEW, files_override={PKEY: entry("/dl/big", NEW)})
ROUTES["/dl/big"] = ("stream", 30 * 1024 * 1024)
SENT["bytes"] = 0
d, t = fresh_target()
rc, out = apply(t)
time.sleep(0.5)
check("a download larger than the signed size is aborted and discarded", rc != 0 and ("larger than" in out or "request failed" in out) and untouched(d, t), out)
check("the client stopped reading long before 30 MB", SENT["bytes"] < 20 * 1024 * 1024, SENT["bytes"])
publish("1.1.0", NEW)
ROUTES["/rel/manifest.json"] = ("stream", 300 * 1024)
rc, out = apply(t)
check("a manifest over 256 KB is refused", rc != 0 and ("larger than" in out or "request failed" in out) and untouched(d, t), out)
publish("1.1.0", NEW, files_override={PKEY: entry("/dl/new", NEW, size=64 * 1024 * 1024 + 1)})
rc, out = apply(t)
check("a signed manifest announcing more than 64 MB is invalid", rc != 0 and "size outside" in out and untouched(d, t), out)
publish("1.1.0", NEW)
ROUTES["/dl/new"] = ("truncate", NEW)
d, t = fresh_target()
rc, out = apply(t)
check("a server that dies mid-download leaves the old program and no temp file", rc != 0 and untouched(d, t), out)
publish("1.1.0", NEW)
ROUTES["/dl/new"] = ("data", NEW[:-10])
rc, out = apply(t)
check("a complete-looking but short file is refused", rc != 0 and untouched(d, t), out)

print("--- the new program must run and report the signed version")
for label, prog, why in [("a program that exits with an error", program("1.1.0", mode="fail"), "does not run on this machine"),
                         ("a program that prints nothing", program("1.1.0", mode="silent"), "reports version ''"),
                         ("a program that reports another version", program("1.3.0"), "reports version '1.3.0' instead of 1.1.0"),
                         ("something that is not a program", b"MZ not a program at all\n" + b"x" * 50, "does not run on this machine")]:
    publish("1.1.0", prog)
    d, t = fresh_target()
    rc, out = apply(t)
    check(f"{label} is refused and the old program stays", rc != 0 and why in out and untouched(d, t), out)

print("--- platform and minimum version")
publish("1.1.0", NEW, files_override={"plan9-mips": entry("/dl/new", NEW)})
d, t = fresh_target()
rc, out = apply(t)
check("a release without a download for this platform is refused", rc != 0 and "no download for" in out and untouched(d, t), out)
publish("2.0.0", program("2.0.0"), extra={"min": "1.5.0"})
rc, out = apply(t)
check("a program older than the manifest's min is told to download by hand", rc != 0 and "oldest version that can update itself" in out and untouched(d, t), out)

print("--- the release tool")
reldir = P("reldir"); os.makedirs(reldir)
open(os.path.join(reldir, f"tclguard-{PKEY}"), "wb").write(NEW)
open(os.path.join(reldir, "SHA256SUMS"), "w").write("ignored\n")
tool = os.path.join(TREE, "tools", "release-manifest.tcl")
rc, out = run([TCLSH, tool, "--dir", reldir, "--version", "1.1.0", "--key", keyA, "--urlbase", f"{BASE}/dl/", "--notes", "from the tool"])
check("the release tool builds and signs a manifest", rc == 0 and os.path.exists(os.path.join(reldir, "manifest.json.sig")), out)
ROUTES.clear()
ROUTES["/rel/manifest.json"] = ("data", open(os.path.join(reldir, "manifest.json"), "rb").read())
ROUTES["/rel/manifest.json.sig"] = ("data", open(os.path.join(reldir, "manifest.json.sig"), "rb").read())
ROUTES[f"/dl/tclguard-{PKEY}"] = ("data", NEW)
d, t = fresh_target()
rc, out = apply(t)
check("a release made by the tool is accepted by the app (tool and client agree on the bytes)", rc == 0 and open(t, "rb").read() == NEW, out)
rc, out = run([TCLSH, tool, "--dir", reldir, "--version", "1.1.0", "--key", keyB, "--out", P("relB")])
check("the tool refuses a key that is not the embedded one", rc != 0 and "not the key embedded" in out and not os.path.exists(P("relB")), out)
rc, out = run([TCLSH, tool, "--dir", reldir, "--version", "1.1.0", "--key", keyB, "--out", P("relB"), "--allow-key-mismatch"])
check("... unless told to (key rotation)", rc == 0 and os.path.exists(os.path.join(P("relB"), "manifest.json.sig")), out)
rc, out = run([TCLSH, tool, "--dir", reldir, "--version", "1.1.0", "--out", P("relC")], {"TG_RELEASE_KEY": keyA})
check("the tool takes the key from TG_RELEASE_KEY (path)", rc == 0, out)
rc, out = run([TCLSH, tool, "--dir", reldir, "--version", "1.1.0", "--out", P("relD")], {"TG_RELEASE_KEY": open(keyA).read()})
check("... or the PEM text itself (CI secret)", rc == 0 and "BEGIN" not in out, out)
rc, out = run([TCLSH, tool, "--dir", reldir, "--version", "1.1.0", "--out", P("relE")], {"TG_RELEASE_KEY": ""})
check("the tool refuses to run without a key", rc != 0 and "no signing key" in out, out)
rc, out = run([TCLSH, os.path.join(TREE_UNSET, "tools", "release-manifest.tcl"), "--dir", reldir, "--version", "1.1.0", "--key", keyA, "--out", P("relF"), "--require-embedded-key"])
check("--require-embedded-key fails while the app still has the placeholder", rc != 0 and "UNSET" in out, out)
rc, out = run([TCLSH, tool, "--dir", P("nonexistent"), "--version", "1.1.0", "--key", keyA]); check("the tool reports a missing directory", rc != 0 and "not a directory" in out, out)
rc, out = run([TCLSH, tool, "--dir", reldir, "--version", "banana", "--key", keyA]); check("the tool rejects a bad version", rc != 0 and "not a version number" in out, out)

srv.shutdown()
shutil.rmtree(work, ignore_errors=True)
sys.exit(summary())
