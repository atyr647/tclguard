#!/usr/bin/env python3
"""A real browser (Chromium via Playwright) through the guard: page, parallel keep-alive fetches, WebSocket, a 5 MB upload, the cookie challenge,
HTTPS with the guard's own certificate. Skips (exit 0) when node or the playwright module is not available. Needs: npm i playwright && npx playwright install chromium"""
import sys, os, json, subprocess, shutil
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = shutil.which("node")
def run_phase(phase, port):
    env = dict(os.environ)
    p = subprocess.run([NODE, os.path.join(HERE, "browser_check.js"), json.dumps({"phase": phase, "port": port})], capture_output=True, text=True, timeout=120, env=env, cwd=HERE)
    rows = []
    for line in p.stdout.splitlines():
        try: rows.append(json.loads(line))
        except ValueError: pass
    return rows, p

if not NODE:
    print("SKIP browser tests: node is not installed"); sys.exit(0)
probe = subprocess.run([NODE, "-e", "require('playwright')"], capture_output=True, text=True, cwd=HERE)
if probe.returncode != 0:
    print("SKIP browser tests: the playwright module is not available (npm i playwright)"); sys.exit(0)

be = HttpBackend(); web = free_port(); tls = free_port()
g = Guard({"web": {"type": "http", "port": web, "backendPort": be.port, "connRate": 1000, "maxConnsPerIP": 200, "reqRate": 2000, "reqWindow": 10},
           "secure": {"type": "http", "port": tls, "backendPort": be.port, "tls": 1, "connRate": 1000, "maxConnsPerIP": 200, "reqRate": 2000, "reqWindow": 10}},
          {"strikeThreshold": 50})
try:
    g.start(); assert wait_port(web) and wait_port(tls)
    for phase, port in (("basic", web), ("tls", tls)):
        rows, p = run_phase(phase, port)
        if not rows: check(f"browser phase {phase} produced results", False, p.stderr[-300:])
        for r in rows: check(r["name"], r["ok"], r["detail"])
    up = [q for q in be.requests if q[0].startswith("POST /up")]
    check("the backend received both 5 MB uploads byte for byte in size", len(up) >= 2 and all(len(q[2]) == 5242880 for q in up), [len(q[2]) for q in up])
    errs0 = [l for l in g.stderr().splitlines() if "Tcl error" in l or "background error" in l.lower()]
    check("no Tcl errors in the guard log after the browser phases", not errs0, errs0[:3])
finally:
    g.cleanup()

# the cookie challenge needs a visitor the guard does not know yet (a known visitor is deliberately not challenged), so: a fresh guard
be2 = HttpBackend(); web2 = free_port()
g2 = Guard({"web": {"type": "http", "port": web2, "backendPort": be2.port, "connRate": 1000, "maxConnsPerIP": 200, "reqRate": 2000, "reqWindow": 10}}, {"strikeThreshold": 50})
try:
    g2.start(); assert wait_port(web2)
    rc, out = g2.ctl("level", 2); check("pin the challenge level", rc == 0, out)
    rows, p = run_phase("challenge", web2)
    if not rows: check("browser challenge phase produced results", False, p.stderr[-300:])
    for r in rows: check(r["name"], r["ok"], r["detail"])
    g = g2
    errs = [l for l in g.stderr().splitlines() if "Tcl error" in l or "background error" in l.lower()]
    check("no Tcl errors in the guard log after the browser run", not errs, errs[:3])
finally:
    g2.cleanup()
sys.exit(summary())
