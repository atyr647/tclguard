"""Grammar-aware HTTP/1.x request generator, byte-level mutator and delivery scheduler.

A *case* is a list of ops that a client performs on one TCP connection:
    ("s", bytes)   send these bytes (one send call)
    ("d", secs)    sleep
    ("h",)         half-close (shutdown SHUT_WR)
    ("r",)         abortive close (RST) and stop
followed by an end-of-case disposition `end` in {"close", "half", "rst", "hold"}.
Everything is derived from a random.Random so a (seed, index) pair reproduces a case.
"""
import json
import random

CRLF = b"\r\n"
METHODS = [b"GET", b"GET", b"GET", b"POST", b"POST", b"PUT", b"HEAD", b"DELETE", b"PATCH", b"OPTIONS"]
ODD_METHODS = [b"CONNECT", b"TRACE", b"get", b"G\x00T", b"GE T", b"BREW", b"PROPFIND", b"X" * 11, b"GE", b"",
               b"G\tT", b"POST\t", b"PRI", b"*", b"GET\x0b"]
TARGETS = [b"/", b"/", b"/index.html", b"/a/b/c?x=1&y=2", b"/login", b"/login?next=/", b"/%00", b"/%2e%2e/", b"//x",
           b"/a#frag", b"/\xc3\xa9", b"/\x80\xff", b"*", b"/?", b"/ws", b"/upload"]
ODD_TARGETS = [b"http://evil.example/", b"evil.example:443", b"", b"/a b", b"/a\tb", b"/\x00", b"/\x7f", b"/\r", b"/\n",
               b"/\x01", b"\\", b"x", b"/" + b"a" * 8300, b"/%", b"/ HTTP/1.1", b"/\tHTTP/1.0", b"//", b"/\xff\xfe",
               b"*x", b"/\x0b", b"/\x0c", b"/\"", b"/<>{}|", b"/?" + b"&a=b" * 300, b"/a\tHTTP/1.0 HTTP/1.1"]
VERSIONS = [b"HTTP/1.1"] * 30 + [b"HTTP/1.0"] * 1
ODD_VERSIONS = [b"HTTP/0.9", b"HTTP/1.2", b"HTTP/2.0", b"HTTP/2", b"http/1.1", b"HTTP/1.1 ", b"HTTP/01.1", b"HTTP/1.01",
                b"HTTP/1.", b"HTTP/1", b"HTTP/1.1\r", b"HTTP /1.1", b"HTTP/1.1x", b"", b"HTTP/1.1 HTTP/1.0", b"HTTP/ 1.1",
                b"HTTP/9.9", b"HTTP/\xef\xbc\x91.1"]
NUM_ODD = [b"0", b"00", b"000", b"007", b"+5", b"-1", b"-0", b"0x5", b"0X10", b"5e0", b"1e3", b"1.0", b"\xd9\xa5",
           b"\xef\xbc\x95", b"2147483647", b"2147483648", b"4294967295", b"4294967296", b"4294967301",
           b"9223372036854775807", b"9223372036854775808", b"18446744073709551615", b"18446744073709551616",
           b"18446744073709551621", b"99999999999999999999999999", b"", b" ", b"5 5", b"5,5", b"5, 5", b"5, 6", b"5,",
           b",5", b"5;", b"5\x00", b"\x005", b"5\t", b"1_0", b"0b101", b"0o7", b"\t5", b"5\x0b", b"NaN", b"inf", b"-",
           b"+", b"0" * 30 + b"5", b"1" * 5000, b"010", b"0100", b"4294967296" + b"0" * 5, b"65536", b"1048576",
           b"3145728", b"2097153", b"2097152"]
TE_ODD = [b"chunked", b"Chunked", b"CHUNKED", b" chunked", b"chunked ", b"chunked, chunked", b"gzip, chunked",
          b"chunked, gzip", b"identity", b"xchunked", b"chunked\x00", b"chunkedx", b"ch unked", b"chunked;q=1",
          b"\tchunked", b"chunked,", b",chunked", b'"chunked"', b"", b"chunked\x0b", b"chunked\x0c", b"chunked\xa0",
          b"cow, chunked", b"identity, chunked", b"chunked\r", b"\x0bchunked", b"chunked, identity"]
CTRL_BYTES = [0, 1, 7, 8, 9, 10, 11, 12, 13, 27, 31, 32, 34, 39, 44, 58, 59, 61, 92, 127, 128, 160, 255]
HOSTS = [b"x", b"example.com", b"example.com:8080", b"[::1]", b"127.0.0.1", b"a.b.c" * 20, b"", b"x y", b"x\ty"]
EXTRA_HEADERS = [b"User-Agent", b"Accept", b"Accept-Encoding", b"Cookie", b"Referer", b"Origin", b"Range", b"If-None-Match",
                 b"X-Custom", b"Content-Type", b"Via", b"X-Forwarded-Proto", b"Authorization", b"Cache-Control"]
IDENT = [b"X-Forwarded-For", b"x-forwarded-for", b"X-FORWARDED-FOR", b"X_Forwarded_For", b"X-Forwarded_For", b"X-Real-IP",
         b"x-real-ip", b"X_Real_IP", b"X-Real_Ip", b"Forwarded", b"FORWARDED", b"True-Client-IP", b"CF-Connecting-IP",
         b"X-Client-IP", b"X-Originating-IP", b"Client-IP", b"X-Forwarded-Host", b"X-Forwarded-For\t", b"X-Forwarded-For ",
         b"X.Forwarded.For", b"X-Forwarded-For\x00", b"\xd8-Forwarded-For"]
FRAMING_NAMES = [b"Content-Length", b"content-length", b"CONTENT-LENGTH", b"Content_Length", b"Content-Length ",
                 b"Content-length", b"Content\x00-Length", b"Transfer-Encoding", b"transfer-encoding", b"Transfer_Encoding",
                 b"Transfer-Encoding ", b"Transfer-encoding", b"TRANSFER-ENCODING", b"Transfer-Encoding\t", b"X-Transfer-Encoding",
                 b"Content-Length\t", b"Content--Length", b"Content-Length:"]


def pick(rng, seq):
    return seq[rng.randrange(len(seq))]


def rbytes(rng, n):
    return bytes(rng.getrandbits(8) for _ in range(n)) if n < 64 else rng.randbytes(n)


def rtext(rng, n):
    return bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyzABCDEF0123456789 -_./") for _ in range(n))


class Gen:
    def __init__(self, rng, w=None):
        self.rng = rng
        # w: how often a field is mangled; ~35% of cases are fully well-formed (exactness oracle)
        self.w = w if w is not None else (0.0 if rng.random() < 0.35 else rng.choice([0.05, 0.15, 0.3, 0.6]))

    def odd(self, p=None):
        return self.rng.random() < (self.w if p is None else p * self.w)

    # ----------------------------------------------------------------- pieces
    def eol(self):
        if self.odd(0.15):
            return pick(self.rng, [b"\n", b"\r", b"\r\r\n", b"\n\r", b"\r\n\r\n", b"\x00\r\n", b"\r\n "])
        return CRLF

    def target(self):
        return pick(self.rng, ODD_TARGETS if self.odd(0.5) else TARGETS)

    def request_line(self):
        r = self.rng
        method = pick(r, ODD_METHODS if self.odd(0.2) else METHODS)
        ver = pick(r, ODD_VERSIONS if self.odd(0.25) else VERSIONS)
        sp = b" "
        if self.odd(0.15):
            sp = pick(r, [b"  ", b"\t", b" \t", b"\x00", b"\x0b", b"\xa0", b""])
        return method + sp + self.target() + (sp if self.odd(0.5) else b" ") + ver, ver

    def fieldname(self, name):
        r = self.rng
        if self.odd(0.15):
            m = r.randrange(5)
            if m == 0:
                return name.upper()
            if m == 1:
                return name.lower()
            if m == 2:
                return name.replace(b"-", b"_")
            if m == 3:
                return name + pick(r, [b" ", b"\t", b"\x00", b"\x0b", b"\xa0"])
            return pick(r, [b" ", b"\t"]) + name
        return name

    def hline(self, name, value):
        r = self.rng
        n = self.fieldname(name)
        sep = b":" + (b" " if not self.odd(0.2) else pick(r, [b"", b"  ", b"\t", b" \t ", b"\x0b", b"\x00", b"\xa0"]))
        v = value
        if self.odd(0.15):
            v = v + pick(r, [b" ", b"\t", b"  \t", b"\x00", b"\r", b"\n", b"\x7f", b"\x01", b"\xff", b"\r\n ", b"\r\n\t", b"\n"])
        return n + sep + v

    def extra_headers(self):
        r = self.rng
        out = []
        for _ in range(r.choice([0, 0, 1, 2, 3, 5])):
            nm = pick(r, EXTRA_HEADERS)
            val = rtext(r, r.choice([0, 1, 5, 20]))
            if self.odd(0.1):
                val = bytes(pick(r, CTRL_BYTES) if r.random() < 0.3 else r.getrandbits(8) for _ in range(r.randrange(8)))
            out.append((nm, val))
        if r.random() < (0.25 if self.w == 0 else 0.5):
            for _ in range(r.choice([1, 1, 2])):
                v = pick(r, [b"6.6.6.6", b"1.2.3.4, 5.6.7.8", b"::1", b"127.0.0.1", b"for=6.6.6.6", b"", b"evil", b"::ffff:7.7.7.7", b"1.2.3.4,,5.6.7.8, ,"])
                if self.odd(0.05):
                    v = b", ".join([b"1.2.3.%d" % i for i in range(r.choice([50, 500, 1500]))])
                out.append((pick(r, IDENT), v))
        if self.odd(0.15):
            for _ in range(r.choice([20, 90, 101, 150, 400])):
                out.append((b"X-H%d" % r.randrange(1000), b"v"))
        if self.odd(0.08):
            out.append((b"X-Long", pick(r, [b"a", b" ", b"\t", b" a"]) * r.choice([500, 5000, 16000, 20000])))
        if self.odd(0.15):
            out.append((b"Connection", pick(r, [b"close", b"keep-alive", b"Upgrade", b"close, Upgrade", b"X-Forwarded-For", b"close, X-Real-IP",
                                                 b"x-real_ip", b"Forwarded", b"upgrade, x-forwarded-for", b"TE", b"Content-Length", b"Host"])))
        if self.odd(0.1):
            out.append((b"Expect", pick(r, [b"100-continue", b"100-Continue", b"foo", b""])))
        if self.odd(0.1):
            out.append((b"Upgrade", pick(r, [b"websocket", b"h2c", b"WebSocket", b"foo", b"websocket, h2c"])))
        return out

    # ----------------------------------------------------------------- bodies
    def payload(self, n=None):
        r = self.rng
        if n is None:
            n = r.choice([0, 1, 2, 5, 10, 31, 100, 1000, 5000])
        k = r.random()
        if k < 0.25 and self.w > 0:
            # a complete nested request: the classic smuggling payload
            return (pick(r, [b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n", b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
                            b"0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n", b"GET /s HTTP/1.1\nHost: x\n\n",
                            b"\r\n\r\nGET /s HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n"]))
        if k < 0.5:
            return rtext(r, n)
        if k < 0.6:
            return b"\r\n" * (n // 2)
        return rbytes(r, n)

    def cl_value(self, true_len):
        r = self.rng
        if self.odd(0.4):
            return pick(r, NUM_ODD + [b"%d" % (true_len + 1), b"%d" % max(0, true_len - 1), b"%d" % (true_len + 2 ** 32),
                                      b"%d" % (true_len + 2 ** 64), b"%d" % true_len + b" ", b"0%d" % true_len, b"+%d" % true_len])
        return b"%d" % true_len

    def chunk_size_line(self, size):
        r = self.rng
        h = b"%x" % size
        if self.odd(0.5):
            m = r.randrange(14)
            if m == 0:
                h = h.upper()
            elif m == 1:
                h = b"0" * r.randrange(1, 14) + h
            elif m == 2:
                h = b"0x" + h
            elif m == 3:
                h = b"+" + h
            elif m == 4:
                h = b"-" + h
            elif m == 5:
                h = b" " + h
            elif m == 6:
                h = h + b" "
            elif m == 7:
                h = pick(r, [b"ffffffff", b"100000000", b"ffffffffffffffff", b"10000000000000000", b"7fffffffffffffff",
                             b"8000000000000000", b"fffffffffffffffff", b"1" + b"0" * 12, b"ffffffffffff"])
            elif m == 8:
                h = h + b"_" if r.random() < .5 else b"1_" + h
            elif m == 9:
                h = b""
            elif m == 10:
                h = h + pick(r, [b"g", b"\x00", b"\t", b"\x0b", b"\xa0"])
            elif m == 11:
                h = b"%d" % size + b"z"
            elif m == 12:
                h = b"\xef\xbc\x91"
            else:
                h = h + pick(r, [b"\n", b"\r"])
        if self.odd(0.4):
            ext = pick(r, [b";a=b", b";a", b";a=\"b\"", b";a=\"b", b";a=\"b\r\n", b";a=\"\\\"", b"; a=b", b" ;a=b", b";", b";;", b";a=b;c=d",
                           b";\x00", b";a=\x01", b";a=b\x7f", b";a=\"x\ry\"", b";a=\"x\ny\"", b";" + b"a" * 5000, b";\xff=\xfe",
                           b";a=\"" + b"0\r\n\r\nGET /s HTTP/1.1\r\nHost: x\r\n\r\n", b";a=b\x00c", b";a=\"b\"c", b";=b", b"\t;a=b",
                           b";a=b\tc", b";a b", b";a=b c", b";a=\"b c\""])
            h += ext
        return h

    def chunk_term(self):
        if self.odd(0.2):
            return pick(self.rng, [b"\n", b"\r", b"", b"XX", b"\r\r", b"\n\r", b"\r\n\r\n", b"\x00\x00", b"\r\n "])
        return CRLF

    def trailers(self):
        r = self.rng
        out = b""
        if r.random() < (0.2 if self.w == 0 else 0.5):
            for _ in range(r.choice([1, 1, 2, 3])):
                nm = pick(r, [b"X-Checksum", b"Expires", b"Content-Length", b"Transfer-Encoding", b"Host", b"X-Forwarded-For", b"X-Real-IP",
                              b"Content_Length", b"Connection", b"Upgrade", b"Forwarded"]) if self.odd(0.7) else b"X-Checksum"
                line = nm + b": " + pick(r, [b"abc", b"5", b"chunked", b"6.6.6.6", b""])
                if self.odd(0.3):
                    line = pick(r, [line + b"\n", b"nocolon", b" folded: x", line + b"\x00", line + b"\r", b"X: y\nGET /s HTTP/1.1\r\nHost: x\r\n",
                                    line + b"\x7f", b"X-A : b", b"\tX: y", b": v", line + b"\xff"])
                out += line + (CRLF if not self.odd(0.1) else pick(r, [b"\n", b"\r", b""]))
            if self.odd(0.05):
                out += b"X-T: v\r\n" * r.choice([20, 21, 100])
        return out

    def chunked_body(self, data):
        r = self.rng
        out = b""
        i = 0
        nchunks = 0
        mode = r.choice([0, 0, 1, 2, 3])
        while i < len(data):
            sz = [len(data), r.randrange(1, 20), 1, 16, r.randrange(1, 500)][mode]
            sz = min(max(sz, 1), len(data) - i)
            piece = data[i:i + sz]
            i += sz
            decl = sz
            if self.odd(0.06):
                decl = max(0, sz + r.choice([-2, -1, 1, 2, 100]))
            out += self.chunk_size_line(decl) + self.eol_chunk() + piece + self.chunk_term()
            nchunks += 1
            if nchunks > 4000:
                break
        if self.odd(0.05):
            out += (b"1" + CRLF + b"x" + CRLF) * r.choice([1999, 2000, 2001, 3000])
        last = b"0" if not self.odd(0.15) else pick(r, [b"00", b"0;x=y", b"0 ", b"0\x00", b"000000000000000", b"0;", b" 0", b""])
        out += last + self.eol_chunk() + self.trailers()
        out += self.eol_chunk() if not self.odd(0.1) else pick(r, [b"", b"\n", b"\r", b"\r\n\r\n"])
        return out

    def eol_chunk(self):
        if self.odd(0.08):
            return pick(self.rng, [b"\n", b"\r", b"\r\r\n", b"\x00\r\n"])
        return CRLF

    # --------------------------------------------------------------- requests
    def request(self, nested_ok=True):
        r = self.rng
        line, ver = self.request_line()
        hdrs = []
        if not self.odd(0.1) or ver == b"HTTP/1.1":
            hosts = r.choice([1, 1, 1, 1, 1, 1, 2, 0]) if self.odd(0.2) else 1
            for _ in range(hosts):
                hdrs.append((pick(r, [b"Host", b"Host", b"host", b"HOST"]) if self.odd(0.1) else b"Host",
                             pick(r, HOSTS if self.odd(0.2) else HOSTS[:3])))
        hdrs += self.extra_headers()
        kind = r.choice(["none", "cl", "cl", "chunked", "chunked", "mixed"] if self.w else ["none", "cl", "chunked", "cl", "chunked"])
        body = b""
        data = self.payload() if kind != "none" else b""
        if kind == "none":
            if self.odd(0.1):
                hdrs.append((b"Content-Length", b"0"))
        elif kind == "cl":
            hdrs.append((pick(r, FRAMING_NAMES[:3]) if self.odd(0.15) else b"Content-Length", self.cl_value(len(data))))
            body = data
            if self.odd(0.05):
                hdrs.append((b"Content-Length", self.cl_value(len(data))))
        elif kind == "chunked":
            te = pick(r, TE_ODD) if self.odd(0.4) else b"chunked"
            hdrs.append((pick(r, FRAMING_NAMES[3:]) if self.odd(0.15) else b"Transfer-Encoding", te))
            body = self.chunked_body(data)
            if self.odd(0.05):
                hdrs.append((b"Transfer-Encoding", pick(r, TE_ODD)))
        else:
            # conflicting / confusing framing combinations
            hdrs.append((b"Content-Length", self.cl_value(len(data) if r.random() < .5 else len(data) + 5)))
            hdrs.append((pick(r, FRAMING_NAMES[3:]), pick(r, TE_ODD) if r.random() < .5 else b"chunked"))
            if r.random() < 0.4:
                hdrs.append((b"Content-Length", self.cl_value(len(data))))
            body = self.chunked_body(data) if r.random() < .5 else data
        # header order: shuffle a bit
        if self.odd(0.2):
            r.shuffle(hdrs)
        out = line + self.eol()
        for n, v in hdrs:
            out += self.hline(n, v) + self.eol()
        if self.odd(0.05):
            out += pick(r, [b" continued: folded", b"\tfolded", b"X: y\n", b"\x00"]) + CRLF
        out += self.eol_end()
        if kind != "none" and self.odd(0.05):
            body = body[:r.randrange(len(body) + 1)]          # truncated body
        return out + body

    def eol_end(self):
        if self.odd(0.1):
            return pick(self.rng, [b"\n", b"\r", b"\r\n\r\n", b"\x00\r\n", b"\r\n\r"])
        return CRLF

    def upgrade_request(self):
        r = self.rng
        hdrs = [(b"Host", b"x"), (b"Upgrade", pick(r, [b"websocket", b"WebSocket", b"h2c"])),
                (b"Connection", pick(r, [b"Upgrade", b"upgrade", b"keep-alive, Upgrade", b"Upgrade, close", b"close", b"keep-alive"])),
                (b"Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="), (b"Sec-WebSocket-Version", b"13")]
        if self.odd(0.5):
            hdrs.append(pick(r, [(b"Content-Length", b"%d" % r.choice([0, 5, 20])), (b"Transfer-Encoding", b"chunked")]))
        r.shuffle(hdrs)
        out = pick(r, [b"GET /ws HTTP/1.1", b"GET /ws HTTP/1.1", b"POST /ws HTTP/1.1", b"GET /ws HTTP/1.0"]) + CRLF
        for n, v in hdrs:
            out += self.hline(n, v) + CRLF
        out += CRLF
        cl = [v for n, v in hdrs if n == b"Content-Length"]
        if cl and cl[0] != b"0" and r.random() < 0.8:
            out += b"x" * int(cl[0])
        if any(n == b"Transfer-Encoding" for n, v in hdrs) and r.random() < .8:
            out += b"0\r\n\r\n"
        return out

    def equiv_stream(self):
        """Framing values that different parsers read differently (octal/decimal, wrapped, signed) followed by a
        second request, so that a different interpretation shifts the request boundary."""
        r = self.rng
        n = r.choice([8, 9, 10, 11, 12, 16, 17, 20, 31, 64, 100, 256])
        body = rtext(r, n)
        nxt = b"GET /second HTTP/1.1\r\nHost: x\r\n\r\n"
        if r.random() < 0.5:
            cl = pick(r, [b"0%d" % n, b"00%d" % n, b"%d" % n, b"+%d" % n, b"%d " % n, b"\t%d" % n, b"%d%s" % (n, pick(r, [b"", b".0", b"e0", b"_", b"\x00", b"\x0b"])),
                          b"%d" % (n + 2 ** 32), b"%d" % (n + 2 ** 64), b"%d" % (n + 2 ** 63), b"0x%x" % n, b"%d, %d" % (n, n)])
            head = b"POST /first HTTP/1.1\r\nHost: x\r\n" + pick(r, [b"Content-Length", b"Content-Length", b"Content_Length", b"content-length"]) + b": " + cl + b"\r\n\r\n"
            return head + body + nxt
        sz = pick(r, [b"%x" % n, b"0%x" % n, b"00%x" % n, b"%X" % n, b"+%x" % n, b"%x " % n, b" %x" % n, b"0x%x" % n, b"%x" % (n + 2 ** 32),
                      b"%x" % (n + 2 ** 64), b"%x" % (n + 2 ** 63), b"%d" % n, b"%x;a=b" % n, b"%x;a=\"b" % n, b"%x\n" % n, b"%x\r" % n, b"1_%x" % n])
        head = b"POST /first HTTP/1.1\r\nHost: x\r\n" + pick(r, [b"Transfer-Encoding: chunked", b"Transfer-Encoding: chunked", b"Transfer_Encoding: chunked"]) + b"\r\n\r\n"
        return head + sz + b"\r\n" + body + pick(r, [b"\r\n", b"\n", b""]) + b"0\r\n\r\n" + nxt

    def stream(self):
        r = self.rng
        if r.random() < 0.06:
            return self.equiv_stream()
        parts = []
        n = r.choice([1, 1, 1, 1, 2, 2, 3, 5, 12])
        if r.random() < 0.03:
            n = r.choice([100, 600, 1500])          # deep pipeline of tiny requests
        for i in range(n):
            if r.random() < 0.05:
                parts.append(self.upgrade_request())
                if r.random() < 0.5:
                    parts.append(pick(r, [b"\x81\x05hello", b"GET /after HTTP/1.1\r\nHost: x\r\n\r\n", rbytes(r, 20), b"\r\n\r\n", b"\xff" * 10]))
            elif n > 50:
                parts.append(b"GET /p%d HTTP/1.1\r\nHost: x\r\n\r\n" % i)
            else:
                parts.append(self.request())
            if self.odd(0.1):
                parts.append(pick(r, [b"\r\n", b"\r\n\r\n", b"\n", b"\r\n" * 5, b"\r\n" * 9, b"\r\n" * 20, b" ", b"\x00"]))
        s = b"".join(parts)
        if r.random() < (0.15 if self.w else 0.0) or self.w > 0.5 and r.random() < 0.3:
            s = mutate(r, s)
        if r.random() < 0.02:
            s = rbytes(r, r.choice([1, 10, 200, 3000]))            # pure noise
        if r.random() < 0.01:
            s = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + rbytes(r, 100)   # TLS ClientHello-ish
        return s


# --------------------------------------------------------------------- mutation ---
def mutate(rng, s, rounds=None):
    s = bytearray(s)
    for _ in range(rounds or rng.choice([1, 1, 2, 3, 6])):
        if not s:
            s += b"G"
        k = rng.randrange(11)
        i = rng.randrange(len(s))
        if k == 0:
            s[i] ^= 1 << rng.randrange(8)
        elif k == 1:
            s[i] = pick(rng, CTRL_BYTES)
        elif k == 2:
            del s[i:i + rng.choice([1, 1, 2, 5, 20])]
        elif k == 3:
            j = rng.randrange(len(s))
            a, b = min(i, j), max(i, j)
            s[b:b] = s[a:min(b, a + 200)]
        elif k == 4:
            s[i:i] = pick(rng, [b"\r\n", b"\n", b"\r", b"\x00", b"\t", b" ", b":", b",", b";", b"\"", b"\r\n\r\n", b"0\r\n\r\n",
                                b"\xff", b"Transfer-Encoding: chunked\r\n", b"Content-Length: 0\r\n", b"X-Forwarded-For: 1.1.1.1\r\n"])
        elif k == 5:
            s = bytearray(bytes(s).replace(b"\r\n", b"\n", 1 + rng.randrange(3)))
        elif k == 6:
            s = bytearray(bytes(s).replace(b"\r\n", b"\r\n\r\n", 1))
        elif k == 7:
            s = s[:i]
        elif k == 8:
            s[i:i + 1] = bytes([rng.getrandbits(8)])
        elif k == 9:
            for needle, rep in ((b"chunked", b"chunKed"), (b"Content-Length", b"Content-length"), (b": ", b":"), (b"HTTP/1.1", b"HTTP/1.0"),
                                (b"Host", b"Host "), (b"POST", b"GET")):
                if rng.random() < 0.3:
                    s = bytearray(bytes(s).replace(needle, rep, 1))
        else:
            # swap two lines
            parts = bytes(s).split(b"\r\n")
            if len(parts) > 3:
                a, b = rng.randrange(len(parts)), rng.randrange(len(parts))
                parts[a], parts[b] = parts[b], parts[a]
            s = bytearray(b"\r\n".join(parts))
    return bytes(s)


# -------------------------------------------------------------------- scheduling ---
def schedule(rng, stream, big_ok=True):
    """Split the stream over many segments with random delays; pick half-close / RST points."""
    n = len(stream)
    mode = rng.choice(["whole", "whole", "few", "few", "many", "bytewise", "lines"]) if n < 4000 else rng.choice(["whole", "few", "few", "many"])
    if n > 300000 and mode in ("many", "bytewise"):
        mode = "few"
    cuts = set()
    if mode == "few":
        cuts = {rng.randrange(1, n) for _ in range(rng.randrange(1, 6))} if n > 1 else set()
    elif mode == "many":
        cuts = {rng.randrange(1, n) for _ in range(min(n - 1, rng.randrange(6, 60)))} if n > 1 else set()
    elif mode == "bytewise":
        cuts = set(range(1, min(n, 400)))
    elif mode == "lines":
        i = 0
        while True:
            j = stream.find(b"\n", i)
            if j < 0 or len(cuts) > 200:
                break
            cuts.update({j, j + 1} if rng.random() < 0.5 else {j + 1})
            i = j + 1
        cuts = {c for c in cuts if 0 < c < n}
    pts = [0] + sorted(cuts) + [n]
    ops = []
    delay_p = rng.choice([0, 0, 0.1, 0.3])
    for a, b in zip(pts, pts[1:]):
        if b > a:
            ops.append(["s", stream[a:b]])
            if rng.random() < delay_p:
                ops.append(["d", rng.choice([0.001, 0.005, 0.02, 0.05])])
    end = rng.choice(["close", "half", "half", "half", "rst", "hold"] if n < 100000 else ["half", "close"])
    # an early half-close / RST in the middle of the stream
    if rng.random() < 0.12 and len(ops) > 1:
        i = rng.randrange(1, len(ops))
        ops = ops[:i] + [["h"] if rng.random() < 0.5 else ["r"]] + ops[i:]
    return ops, end


def make_case(rng):
    g = Gen(rng)
    stream = g.stream()
    ops, end = schedule(rng, stream)
    return {"ops": ops, "end": end}


def case_bytes(case):
    return b"".join(op[1] for op in case["ops"] if op[0] == "s")


def case_to_json(case, **meta):
    ops = []
    for op in case["ops"]:
        ops.append(["s", op[1].hex()] if op[0] == "s" else list(op))
    d = {"ops": ops, "end": case["end"]}
    d.update(meta)
    return json.dumps(d)


def case_from_json(txt):
    d = json.loads(txt) if isinstance(txt, str) else txt
    ops = [["s", bytes.fromhex(op[1])] if op[0] == "s" else op for op in d["ops"]]
    return {"ops": ops, "end": d.get("end", "half")}, d


def simple_case(data, end="half"):
    return {"ops": [["s", data]], "end": end}
