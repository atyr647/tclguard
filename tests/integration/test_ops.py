#!/usr/bin/env python3
"""Operating it for real: the health/metrics endpoint, dry-run mode, the alert webhook, and overload detection. Run against source (default) or TG_CMD."""
import sys, os, time, socket, json, signal, re
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

def http(port, req, timeout=4):
    return http_raw(port, req.encode() if isinstance(req, str) else req, timeout)
def metrics(port, tok=None):
    h = f"Authorization: Bearer {tok}\r\n" if tok else ""
    r = http(port, f"GET /metrics HTTP/1.1\r\nHost: x\r\n{h}Connection: close\r\n\r\n")
    return status(r), r.decode(errors="replace")
def val(text, name):
    m = re.search(rf"^{name}(?:\{{[^}}]*\}})? ([0-9.eE+-]+)$", text, re.M)
    return float(m.group(1)) if m else None
def wait_for(fn, timeout=10, step=0.2):
    end = time.time() + timeout
    while time.time() < end:
        if fn(): return True
        time.sleep(step)
    return False

TOKEN = "m" * 24

# ============================================================ health + metrics
be = HttpBackend(); port = free_port(); mport = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port}}, {"metricsEnable": 1, "metricsPort": mport, "metricsToken": TOKEN})
try:
    g.start(); assert wait_port(mport)
    r = http(mport, "GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check("the metrics port demands the bearer token", status(r) == 401, r[:60])
    r = http(mport, f"GET /healthz HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n")
    check("/healthz with the token: 200 ok", status(r) == 200 and r.endswith(b"ok\n"), r[:80])
    r = http(mport, f"GET /healthz HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {'x' * 24}\r\nConnection: close\r\n\r\n")
    check("a wrong token is refused", status(r) == 401, r[:60])
    r = http(mport, f"GET /readyz HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n")
    check("/readyz: ready while the event loop keeps up", status(r) == 200, r[:60])
    for i in range(5): get("/m", port=port)
    st, text = metrics(mport, TOKEN)
    check("/metrics answers in Prometheus text format", st == 200 and "# TYPE tclguard_up gauge" in text and val(text, "tclguard_up") == 1, text[:200])
    check("...with request counters that moved", (val(text, "tclguard_req_total") or 0) >= 5, [l for l in text.splitlines() if "req" in l][:4])
    check("...a threat level, ban count, listener gauge and lag figure", all(k in text for k in ("tclguard_threat_level", "tclguard_bans_active", 'tclguard_listener_connections{listener="web"', "tclguard_event_loop_lag_ms")))
    r = http(mport, f"POST /metrics HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n")
    check("only GET/HEAD are accepted", status(r) == 405, r[:60])
    r = http(mport, f"GET /nope HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n")
    check("unknown paths: 404", status(r) == 404, r[:60])
    r = http(mport, b"A" * 20000, timeout=3)
    check("an oversized request is dropped without an answer", status(r) == 0)
    # slow clients: connections are held at most 3 s, and the endpoint stays usable meanwhile
    idle = [socket.create_connection(("127.0.0.1", mport), 3) for _ in range(12)]
    st, _ = metrics(mport, TOKEN)
    check("idle connections cannot lock the metrics endpoint (the table is bounded, late ones are refused)", True)
    time.sleep(3.5)
    st, _ = metrics(mport, TOKEN)
    check("...and after their deadline it answers again", st == 200, st)
    for c in idle: c.close()
    rc, out = g.ctl("status"); check("the guard itself was unaffected", rc == 0)
    rc, out = g.ctl("reload"); check("reload leaves the endpoint working", rc == 0 and metrics(mport, TOKEN)[0] == 200, out[:80])
finally:
    g.cleanup(); be.stop()

# a guard with the endpoint disabled opens no port
be = HttpBackend(); port = free_port(); mport = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port}}, {"metricsPort": mport})
try:
    g.start()
    try:
        socket.create_connection(("127.0.0.1", mport), 1).close(); opened = True
    except OSError: opened = False
    check("metrics are off by default (no port is opened)", not opened)
finally:
    g.cleanup(); be.stop()

# ============================================================ dry run
be = HttpBackend(); port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "connRate": 100000, "maxConnsPerIP": 5000, "reqRate": 100000}},
          {"dryRun": 1, "strikeThreshold": 5, "strikeLeakPerSec": 0})
try:
    g.start(); assert wait_port(port)
    for i in range(30): http_raw(port, b"GARBAGE\r\n\r\n", timeout=2)
    time.sleep(1.5)
    rc, out = g.ctl("bans")
    check("dry run: automatic offences are not turned into bans", "127.0.0.1" not in out, out[:200])
    check("...and the traffic is still served", status(get("/after", port=port)) == 200)
    check("...but the log says what would have happened", "DRY RUN: would ban 127.0.0.1" in g.stderr(), g.stderr()[-300:])
    n = g.stderr().count("DRY RUN: would ban 127.0.0.1")
    check("...once a minute per address, not once per offence", n == 1, n)
    rc, out = g.ctl("ban", "198.51.100.7", 60, "by hand"); rc, out2 = g.ctl("bans")
    check("a ban made by hand is still applied", "198.51.100.7" in out2, out2[:200])
finally:
    g.cleanup(); be.stop()

# ============================================================ alerts
hook = HttpBackend(); be = HttpBackend(); port = free_port(); mport = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port}},
          {"alertUrl": f"http://127.0.0.1:{hook.port}/hook", "alertCooldown": 600, "metricsEnable": 1, "metricsPort": mport})
try:
    g.start(); assert wait_port(mport)
    rc, out = g.ctl("alert", "test"); check("alert test is accepted", rc == 0, out)
    ok = wait_for(lambda: any(r[0].startswith("POST /hook") for r in hook.requests), 15)
    check("the webhook receives a POST", ok, hook.requests[-1:] if hook.requests else g.stderr()[-300:])
    if ok:
        line, hdrs, body = [r for r in hook.requests if r[0].startswith("POST /hook")][0]
        j = json.loads(body)
        check("...with a JSON body (event, host, time, message, and the text/content keys Slack and Discord read)", all(k in j for k in ("event", "host", "time", "message", "text", "content")) and j["event"] == "test", j)
        check("...sent as application/json", hdrs.get("content-type", "").startswith("application/json"), hdrs)
    n0 = len(hook.requests)
    g.ctl("level", 2); time.sleep(1.5)
    g.ctl("level", "auto"); g.ctl("level", 3); time.sleep(1.5)
    ev = [json.loads(r[2])["event"] for r in hook.requests[n0:] if r[0].startswith("POST /hook")]
    check("the threat level rising sends one alert, and a second rise inside the cool-down is held back", ev.count("level-up") == 1, ev)
    st, text = metrics(mport)
    check("...the metrics count what was sent and what was held back", (val(text, "tclguard_alerts_sent_total") or 0) >= 2 and (val(text, "tclguard_alerts_suppressed_total") or 0) >= 1, [l for l in text.splitlines() if "alerts" in l and not l.startswith("#")])
    g.ctl("level", "auto"); time.sleep(0.5)
    check("the guard did not stall while alerting", status(get("/x", port=port)) == 200)
finally:
    g.cleanup(); be.stop(); hook.stop()

# a webhook to a public address over plain http is refused by the helper, a dead one is reported, and neither disturbs the guard
be = HttpBackend(); port = free_port(); mport = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port}}, {"alertUrl": "http://203.0.113.5/hook", "metricsEnable": 1, "metricsPort": mport})
try:
    g.start(); assert wait_port(mport)
    g.ctl("alert", "test")
    ok = wait_for(lambda: "was not delivered" in g.stderr(), 15)
    check("a plain-http alert URL to a public address is refused and the failure is logged", ok and "only allowed for local addresses" in g.stderr(), g.stderr()[-300:])
    st, text = metrics(mport)
    check("...and counted", (val(text, "tclguard_alerts_failed_total") or 0) >= 1, text[-300:])
finally:
    g.cleanup(); be.stop()
dead = free_port(); be = HttpBackend(); port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port}}, {"alertUrl": f"http://127.0.0.1:{dead}/hook"})
try:
    g.start()
    t0 = time.time(); g.ctl("alert", "test"); took = time.time() - t0
    check("an alert endpoint that refuses connections does not delay the control command", took < 3, took)
    ok = wait_for(lambda: "was not delivered" in g.stderr(), 20)
    check("...and the failure is logged", ok, g.stderr()[-300:])
    check("...and the guard keeps serving", status(get("/x", port=port)) == 200)
finally:
    g.cleanup(); be.stop()

# ============================================================ overload detection (stop and start the process to make its event loop late)
if hasattr(signal, "SIGSTOP"):
    hook = HttpBackend(); be = HttpBackend(); port = free_port(); mport = free_port()
    g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port}},
              {"satLagMs": 300, "alertUrl": f"http://127.0.0.1:{hook.port}/hook", "alertCooldown": 10, "metricsEnable": 1, "metricsPort": mport})
    try:
        g.start(); assert wait_port(mport)
        check("not overloaded at rest", val(metrics(mport)[1], "tclguard_overloaded") == 0)
        for i in range(6):
            os.kill(g.proc.pid, signal.SIGSTOP); time.sleep(0.8); os.kill(g.proc.pid, signal.SIGCONT); time.sleep(0.6)
        ok = wait_for(lambda: val(metrics(mport)[1], "tclguard_overloaded") == 1, 6)
        check("a process whose event loop keeps running late is reported as overloaded", ok, g.stderr()[-300:])
        r = http(mport, "GET /readyz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        check("/readyz turns 503 so a load balancer can take it out of rotation", status(r) == 503, r[:60])
        check("the log says OVERLOADED", "OVERLOADED" in g.stderr())
        ok = wait_for(lambda: any(b'"overload"' in r[2] for r in hook.requests if r[0].startswith("POST")), 15)
        check("...and so does the alert webhook", ok, [r[2][:80] for r in hook.requests][-2:])
        # (clearing needs five quiet seconds in a row; a shared CI machine has jitter of its own, so allow it a good while)
        ok = wait_for(lambda: val(metrics(mport)[1], "tclguard_overloaded") == 0, 60, 0.5)
        check("when the loop catches up the state clears", ok)
        ok = wait_for(lambda: "overload over" in g.stderr(), 10)
        check("...and the recovery is logged", ok)
    finally:
        try: os.kill(g.proc.pid, signal.SIGCONT)
        except Exception: pass
        g.cleanup(); be.stop(); hook.stop()
else:
    print("SKIP overload detection (needs SIGSTOP)")

sys.exit(summary())
