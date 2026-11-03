"""Recording HTTP backend for the fuzzer.

The guard's http listener is configured with `proxyProtocol v1`, so every backend connection starts
with a PROXY line that carries the client's source port: that is how the oracle ties what the backend
received to the fuzz input that caused it, even with many inputs in flight at once.

For every connection the backend keeps the exact bytes received (PROXY line removed), when it saw EOF,
and whether it switched protocols (101). It answers each request the strict reference parser finds
complete, so keep-alive pipelines keep flowing, and it closes on anything the strict parser rejects
(a strict origin server).
"""
import re
import selectors
import socket
import threading
import time

import refparse

RE_PROXY = re.compile(rb"PROXY TCP4 (\S+) (\S+) (\d+) (\d+)\r\n")


class BConn:
    def __init__(self, sock, mode):
        self.sock = sock
        self.mode = mode            # 'normal' | 'ws101' | 'early' | 'slow' | 'sloppy-upgrade'
        self.raw = bytearray()      # everything after the PROXY line
        self.pre = bytearray()
        self.cport = None
        self.t0 = time.time()
        self.eof = False            # the guard half-closed / closed
        self.closed = False
        self.responded = 0
        self.upgraded_at = None     # index of the message answered with 101
        self.out = bytearray()
        self.parse_dead = False
        self.cut = None             # (offset in raw where tunnel data starts)


class Backend:
    def __init__(self, port=0):
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", port))
        self.lsock.listen(512)
        self.lsock.setblocking(False)
        self.port = self.lsock.getsockname()[1]
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.lsock, selectors.EVENT_READ, None)
        self.lock = threading.Lock()
        self.conns = {}             # cport -> [BConn,...] (newest last)
        self.nconn = 0
        self.open = set()
        self.running = True
        self.mode_cycle = ["normal", "normal", "normal", "ws101", "early", "sloppy-upgrade", "normal", "slow"]
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    # ---- event loop
    def loop(self):
        while self.running:
            for key, ev in self.sel.select(0.05):
                if key.data is None:
                    self.accept()
                else:
                    self.readable(key.data)
            now = time.time()
            for c in list(self.open):
                if c.mode == "slow" and c.out and now - c.t0 > 0:
                    self.flush(c)

    def accept(self):
        try:
            while True:
                s, _ = self.lsock.accept()
                s.setblocking(False)
                self.nconn += 1
                c = BConn(s, self.mode_cycle[self.nconn % len(self.mode_cycle)])
                self.open.add(c)
                self.sel.register(s, selectors.EVENT_READ, c)
        except (BlockingIOError, OSError):
            pass

    def readable(self, c):
        try:
            data = c.sock.recv(262144)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""
        if not data:
            c.eof = True
            self.finish(c)
            return
        if c.cport is None:
            c.pre += data
            m = RE_PROXY.match(bytes(c.pre))
            if not m:
                if len(c.pre) > 200 or b"\r\n" in c.pre:
                    c.cport = -1          # not a PROXY line: record under -1
                    with self.lock:
                        self.conns.setdefault(-1, []).append(c)
                    c.raw += c.pre
                return
            c.cport = int(m.group(3))
            with self.lock:
                self.conns.setdefault(c.cport, []).append(c)
            c.raw += c.pre[m.end():]
            c.pre = bytearray()
        else:
            c.raw += data
        self.respond(c)

    def respond(self, c):
        if c.parse_dead:
            return
        if c.upgraded_at is not None:
            c.out += b"echo:" + b"x"
            self.flush(c)
            return
        d = bytes(c.raw)
        res = refparse.parse_stream(d)
        done = [m for m in res.msgs if m.complete]
        if c.mode == "early" and res.msgs and res.msgs[-1].head_ok and not res.msgs[-1].complete \
                and c.responded == len(done):
            body = b"early:%d" % c.responded      # answer before the body has arrived (legal for a server)
            c.out += b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body
            c.responded += 1
        while c.responded < len(done):
            m = done[c.responded]
            wants_up = (m.upgrade or (c.mode == "sloppy-upgrade" and m.hdr(b"upgrade"))) and m.method == b"GET"
            if wants_up and c.mode in ("ws101", "sloppy-upgrade") and c.responded == 0:
                c.upgraded_at = c.responded
                c.cut = m.end
                c.out += b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                c.responded += 1
                self.flush(c)
                return
            body = b"ok:%d" % c.responded
            c.out += b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body
            c.responded += 1
        if res.status == "invalid" and len(done) == c.responded:
            # strict origin server: error out and drop the connection
            c.parse_dead = True
            c.out += b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            self.flush(c)
            self.close(c)
            return
        if c.mode != "slow":
            self.flush(c)

    def flush(self, c):
        if not c.out or c.closed:
            return
        try:
            n = c.sock.send(bytes(c.out))
            del c.out[:n]
        except (BlockingIOError, InterruptedError):
            pass
        except OSError:
            self.close(c)

    def finish(self, c):
        """Guard closed (or half-closed) its side: flush what we owe, then close."""
        self.flush(c)
        self.close(c)

    def close(self, c):
        if c.closed:
            return
        c.closed = True
        try:
            self.sel.unregister(c.sock)
        except Exception:
            pass
        try:
            c.sock.close()
        except Exception:
            pass
        self.open.discard(c)

    # ---- API for the fuzz driver
    def find(self, cport, since):
        with self.lock:
            for c in self.conns.get(cport, []):
                if c.t0 >= since:
                    return c
        return None

    def forget(self, cport, c):
        with self.lock:
            lst = self.conns.get(cport, [])
            if c in lst:
                lst.remove(c)
            if not lst:
                self.conns.pop(cport, None)

    def stray(self):
        with self.lock:
            return list(self.conns.get(-1, []))

    def stop(self):
        self.running = False
        for c in list(self.open):
            self.close(c)
        try:
            self.lsock.close()
        except Exception:
            pass
