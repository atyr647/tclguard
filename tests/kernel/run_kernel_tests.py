#!/usr/bin/env python3
"""Real-kernel test of TclGuard's nftables layer using two network namespaces.

guard  (10.99.0.1) runs the actual Tcl firewall module + TCP/UDP servers
client (10.99.0.2) plays the attacker.
Needs root, nft, ip netns. Skips (exit 77) when unavailable.
"""
import os, subprocess, sys, time, socket, shutil, textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
G, C = "tgt_guard", "tgt_client"
fails = []
def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))
    if not cond: fails.append(name)

def sh(*a, check_=True, **kw):
    return subprocess.run(a, check=check_, capture_output=True, text=True, **kw)

def cleanup():
    for ns in (G, C):
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)

if os.geteuid() != 0 or not shutil.which("nft") or not shutil.which("ip"):
    print("SKIP: needs root + nft + ip"); sys.exit(77)
cleanup()
try:
    sh("ip", "netns", "add", G); sh("ip", "netns", "add", C)
except Exception as e:
    print("SKIP: cannot create network namespaces:", e); sys.exit(77)
try:
    sh("ip", "link", "add", "vg", "type", "veth", "peer", "name", "vc")
    sh("ip", "link", "set", "vg", "netns", G); sh("ip", "link", "set", "vc", "netns", C)
    for ns, dev, addr in ((G, "vg", "10.99.0.1/24"), (C, "vc", "10.99.0.2/24")):
        sh("ip", "netns", "exec", ns, "ip", "addr", "add", addr, "dev", dev)
        sh("ip", "netns", "exec", ns, "ip", "link", "set", dev, "up")
        sh("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")

    # --- servers inside the guard namespace ---
    server_code = textwrap.dedent('''
        import socket, threading, time, sys
        udp_count = 0
        def tcp():
            s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", 8080)); s.listen(4096)
            while True:
                c, _ = s.accept(); c.send(b"hi"); c.close()
        def udp():
            global udp_count
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 19132))
            while True:
                d, a = s.recvfrom(2048); udp_count += 1
        def ctl():
            s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 9999)); s.listen(5)
            while True:
                c, _ = s.accept(); c.send(str(udp_count).encode()); c.close()
        for f in (tcp, udp, ctl): threading.Thread(target=f, daemon=True).start()
        print("UP", flush=True); time.sleep(600)
    ''')
    srv = subprocess.Popen(["ip", "netns", "exec", G, "python3", "-u", "-c", server_code], stdout=subprocess.PIPE, text=True)
    assert srv.stdout.readline().strip() == "UP"

    guard = subprocess.Popen(["ip", "netns", "exec", G, "tclsh8.6", os.path.join(HERE, "guardd.tcl")],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    assert guard.stdout.readline().strip() == "READY"
    def gcmd(line):
        guard.stdin.write(line + "\n"); guard.stdin.flush()
        return guard.stdout.readline().strip()

    # --- attacker helpers (run inside the client namespace) ---
    def client(code, timeout=60):
        r = subprocess.run(["ip", "netns", "exec", C, "python3", "-c", code], capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    tcp_once = textwrap.dedent('''
        import socket
        s = socket.socket(); s.settimeout(1.5)
        try:
            s.connect(("10.99.0.1", 8080)); print("OK" if s.recv(2) == b"hi" else "BAD")
        except Exception as e: print("FAIL")
    ''')
    syn_flood = textwrap.dedent('''
        import socket, select, time
        N = 600; ok = 0; socks = []
        t0 = time.time()
        for i in range(N):
            s = socket.socket(); s.setblocking(False)
            try: s.connect(("10.99.0.1", 8080))
            except BlockingIOError: pass
            socks.append(s)
        time.sleep(1.2)
        for s in socks:
            _, w, _ = select.select([], [s], [], 0)
            if w and s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0: ok += 1
            s.close()
        print(ok, round(time.time() - t0, 2))
    ''')
    udp_flood = textwrap.dedent('''
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(6000): s.sendto(b"x" * 64, ("10.99.0.1", 19132))
        print("sent")
    ''')
    def udp_received():
        r = subprocess.run(["ip", "netns", "exec", G, "python3", "-c",
            "import socket; s=socket.socket(); s.connect(('127.0.0.1',9999)); print(s.recv(32).decode())"],
            capture_output=True, text=True)
        return int(r.stdout.strip())

    # 1. base install (no hardening): nothing blocked
    out = gcmd("INSTALL 0")
    check("base ruleset installs on real kernel", "installed=1" in out, out)
    check("table is visible to nft", "tclguard" in gcmd("TABLE"))
    check("baseline TCP connect works", client(tcp_once) == "OK")

    # 2. ban -> drop -> unban
    gcmd("BAN 10.99.0.2 0")
    check("banned address is dropped in the kernel", client(tcp_once) == "FAIL")
    counters = gcmd("COUNTERS")
    import re
    m = re.search(r"c_ban (\d+)", counters)
    check("ban counter increments", bool(m) and int(m.group(1)) > 0, counters)
    check("ban element visible in nft set", "10.99.0.2" in gcmd("LIST4"))
    gcmd("UNBAN 10.99.0.2")
    check("unban restores connectivity", client(tcp_once) == "OK")

    # 3. kernel-side expiry without TclGuard doing anything
    gcmd("BAN 10.99.0.2 3")
    check("timed ban active", client(tcp_once) == "FAIL")
    time.sleep(3.5)
    check("kernel expires the ban by itself", client(tcp_once) == "OK")

    # 4. hardening: SYN flood rate limit
    out = gcmd("INSTALL 1")
    check("hardened ruleset installs on real kernel", "installed=1" in out, out)
    print("   (features:", out, ")")
    time.sleep(1)
    res = client(syn_flood).split()
    ok, secs = int(res[0]), float(res[1])
    check("SYN flood is rate-limited (600 attempts, limit 40/s burst 80)", ok < 300, f"{ok}/600 connected in {secs}s")
    check("some legit connections still pass (burst allowance)", ok >= 40, f"{ok}")
    counters = gcmd("COUNTERS")
    m = re.search(r"c_syn (\d+)", counters)
    check("SYN drop counter increments", bool(m) and int(m.group(1)) > 100, counters)
    time.sleep(3)
    check("legit connection works again after the flood stops", client(tcp_once) == "OK")

    # 4b. per-source concurrent connection limit (kernel connlimit), limit 40
    check("per-source connection counting is active (connlimit feature detected)", "connlimit" in out, out)
    time.sleep(3)
    hold = textwrap.dedent('''
        import socket, time
        socks = []; ok = 0
        for i in range(70):
            s = socket.socket(); s.settimeout(1.2)
            try: s.connect(("10.99.0.1", 8080)); ok += 1; socks.append(s)
            except Exception: pass
            time.sleep(0.03)
        print(ok)
    ''')
    held = int(client(hold, timeout=60))
    check("connection limit caps simultaneous connections from one source (limit 40, tried 70)", 35 <= held <= 45, f"{held} connected")
    m = re.search(r"c_conn (\d+)", gcmd("COUNTERS"))
    check("connlimit drop counter increments", bool(m) and int(m.group(1)) > 5)
    time.sleep(3)

    # 5. UDP per-source rate limit
    before = udp_received()
    client(udp_flood)
    time.sleep(0.5)
    got = udp_received() - before
    check("UDP flood is rate-limited (6000 sent, limit 200/s burst 400)", got < 2500, f"{got}/6000 reached the server")
    check("some UDP packets still pass", got > 100, f"{got}")
    m = re.search(r"c_udp (\d+)", gcmd("COUNTERS"))
    check("UDP drop counter increments", bool(m) and int(m.group(1)) > 1000)

    # 6. uninstall
    gcmd("UNINSTALL")
    check("uninstall removes the table", "tclguard" not in gcmd("TABLE"))
    check("traffic flows after uninstall", client(tcp_once) == "OK")
    gcmd("QUIT")
finally:
    for p in ("srv", "guard"):
        try: locals()[p].kill()
        except Exception: pass
    cleanup()
print("\n%d failed" % len(fails) if fails else "\nall kernel tests passed")
sys.exit(1 if fails else 0)
