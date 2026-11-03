#!/usr/bin/env python3
"""Self-update of a REAL starpack replacing ITSELF (what a user actually experiences), on Linux and Windows.

Needs the shipped single-file program in TG_STARPACK (default: releases/tclguard-<os>-x86_64[-console.exe]).
It builds two test starpacks from it (the shipped one is used as the Tcl runtime and as the build host), one
embedding a throwaway release key as v1.0.0 and one as v1.0.1, signs a manifest with that key, serves it over
local HTTPS, and then lets the v1.0.0 program update itself: no --target, so it replaces its own file while
it is running. Unit tests cannot catch this class of bug: a running starpack is mounted over its own path,
where Tcl's file commands act on the virtual contents instead of the real file."""
import hashlib, os, re, shutil, ssl, subprocess, sys, tempfile, threading, time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(__file__))
from harness import check, summary, ROOT

win = os.name == "nt"
STAR = os.environ.get("TG_STARPACK") or os.path.join(ROOT, "releases", "tclguard-windows-x86_64-console.exe" if win else "tclguard-linux-x86_64")
if sys.platform not in ("win32", "linux") or not os.path.exists(STAR):
    print("SKIP starpack update test: needs Linux or Windows and the shipped starpack"); sys.exit(0)
OPENSSL = shutil.which("openssl")
if not OPENSSL:
    print("SKIP starpack update test: no openssl binary for the throwaway certificate"); sys.exit(0)
PLAT = "windows-x86_64" if win else "linux-x86_64"
RUNTIME = os.path.join(ROOT, "tools", "runtimes", "rt-windows-x86_64.exe" if win else "rt-linux-x86_64")   # the raw Tcl runtime (no payload)
EXT = ".exe" if win else ""
W = tempfile.mkdtemp(prefix="tgupdsp")
HOME = os.path.join(W, "home"); os.makedirs(HOME)
ENV = {"TCLGUARD_HOME": HOME, "HOME": HOME}
if not win and not os.environ.get("DISPLAY"):
    XV = ["xvfb-run", "-a"] if shutil.which("xvfb-run") else []
else:
    XV = []

def sh(*a, env=None, timeout=600):
    e = dict(os.environ); e.update(ENV); e.update(env or {})
    p = subprocess.run(list(a), capture_output=True, text=True, env=e, timeout=timeout, errors="replace")
    return p.returncode, p.stdout + p.stderr

def sha(path): return hashlib.sha256(open(path, "rb").read()).hexdigest()

rc, out = sh(*XV, STAR, "update", "keygen", "--out", os.path.join(W, "key"))
m = re.search(r"(tgpub1:[A-Za-z0-9_-]{87})", out)
check("keygen works in the shipped program", rc == 0 and m, out)
pub = m.group(1)

def build(name, version):
    d = os.path.join(W, name); os.makedirs(d)
    shutil.copytree(os.path.join(ROOT, "tclguard.vfs"), os.path.join(d, "tclguard.vfs"))
    shutil.copy(os.path.join(ROOT, "build.tcl"), d)
    open(os.path.join(d, "tclguard.vfs", "lib", "tclguard", "vendor", "update-key.pub"), "w").write(pub + "\n")
    u = os.path.join(d, "tclguard.vfs", "lib", "tclguard", "util.tcl")
    text = open(u).read()
    open(u, "w").write(text.replace("variable VERSION 1.0.0", f"variable VERSION {version}"))
    rt = os.path.join(d, "runtime" + EXT); shutil.copy(RUNTIME, rt)
    out_exe = os.path.join(d, "tg" + EXT)
    rc, out = sh(*XV, STAR, "eval", os.path.join(d, "build.tcl"), "--runtime", rt, "--format", "mk4", "--out", out_exe)
    assert os.path.exists(out_exe), out
    os.chmod(out_exe, 0o755)
    if win:   # the runtime is the GUI-subsystem build: make it a console program so `version` prints into a pipe
        import struct
        b = bytearray(open(out_exe, "rb").read())
        pe = struct.unpack_from("<I", b, 0x3c)[0]; off = pe + 24 + 68
        if struct.unpack_from("<H", b, off)[0] == 2: struct.pack_into("<H", b, off, 3)
        open(out_exe, "wb").write(b)
    return out_exe

OLD = build("old", "1.0.0"); NEW = build("new", "1.0.1")
rc, v1 = sh(*XV, OLD, "version"); rc2, v2 = sh(*XV, NEW, "version")
check("the two test starpacks run and report their versions", "1.0.0" in v1 and "1.0.1" in v2, (v1, v2))

# release directory, signed manifest, local HTTPS server
rel = os.path.join(W, "rel"); os.makedirs(rel)
shutil.copy(NEW, os.path.join(rel, f"tclguard-{PLAT}{EXT}"))
rc, out = sh(OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", os.path.join(W, "k.pem"),
             "-out", os.path.join(W, "c.pem"), "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost")
assert rc == 0, out
class H(SimpleHTTPRequestHandler):
    def __init__(s, *a, **k): super().__init__(*a, directory=rel, **k)
    def log_message(s, *a): pass
srv = ThreadingHTTPServer(("127.0.0.1", 0), H); PORT = srv.server_address[1]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(os.path.join(W, "c.pem"), os.path.join(W, "k.pem"))
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
# tclsh is not guaranteed to exist (Windows): run the release tool with the shipped program's own Tcl
rc, out = sh(*XV, STAR, "eval", os.path.join(ROOT, "tools", "release-manifest.tcl"), "--dir", rel, "--version", "1.0.1",
             "--key", os.path.join(W, "key"), "--urlbase", f"https://localhost:{PORT}/", "--allow-key-mismatch")
check("the release tool signs the manifest", rc == 0 and os.path.exists(os.path.join(rel, "manifest.json.sig")), out[-300:])
env = {"TG_CA_FILE": os.path.join(W, "c.pem")}
feed = f"https://localhost:{PORT}/manifest.json"

rc, out = sh(*XV, OLD, "update", "check", "--url", feed, env=env)
check("update check sees 1.0.1 with a verified signature", "1.0.1 is available" in out and "signature verified" in out, out)

old_hash = sha(OLD); new_hash = sha(NEW)
t0 = time.time()
rc, out = sh(*XV, OLD, "update", "apply", "--url", feed, env=env, timeout=900)
check("update apply succeeds when the program replaces itself", rc == 0 and "Updated TclGuard 1.0.0 -> 1.0.1" in out, out[-500:])
print(f"INFO apply took {time.time() - t0:.0f} s")
check("the program file now IS the new release, byte for byte", sha(OLD) == new_hash)
check("the old program was kept as .previous, byte for byte", os.path.exists(OLD + ".previous") and sha(OLD + ".previous") == old_hash)
rc, out = sh(*XV, OLD, "version")
check("the updated program reports 1.0.1", "1.0.1" in out, out)
leftovers = [f for f in os.listdir(os.path.dirname(OLD)) if f not in ("tg" + EXT, "tg" + EXT + ".previous", "tg" + EXT + ".old", "build.tcl", "tclguard.vfs", "runtime" + EXT, "dist")]
check("no temporary files are left beside it", not leftovers, leftovers)
rc, out = sh(*XV, OLD, "update", "rollback", env=env)
check("update rollback restores the previous program", rc == 0 and "Restored" in out, out)
rc, out = sh(*XV, OLD, "version")
check("...and it runs as 1.0.0 again", "1.0.0" in out, out)
check("...byte for byte", sha(OLD) == old_hash)

srv.shutdown()
try: shutil.rmtree(W, ignore_errors=True)
except Exception: pass
sys.exit(summary())
