"""Independent, deliberately strict HTTP/1.x request parser (RFC 9112 / RFC 9110 semantics).

It shares no code with the Tcl implementation. It is used as an oracle:

  * strict mode (no flags)  - what a correct intermediary may forward: anything else must be refused.
  * lenient "variant" flags - models of plausible *backend* leniencies (bare LF accepted, octal
    Content-Length, header-name normalisation, ...). Whatever the guard forwards must be framed
    identically by the strict parser and by every variant, otherwise some backend would see a
    different number of requests than the guard did (request smuggling / desync).

parse_stream(data, flags) parses a whole byte string; the last message may be partial (client or
guard stopped sending) or invalid (error offset recorded). Offsets are into `data`.
"""
import re

TOK = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
RE_REQLINE = re.compile(rb"(" + TOK + rb") ([\x21-\x7e\x80-\xff]+) HTTP/([0-9])\.([0-9])")
RE_HEADER = re.compile(rb"(" + TOK + rb"):[ \t]*([\t\x20-\x7e\x80-\xff]*?)[ \t]*")
_CRLF = re.compile(rb"[\r\n]")
RE_DIGITS = re.compile(rb"[0-9]+")
_QS = rb'"(?:[\t \x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t \x21-\x7e\x80-\xff])*"'
RE_CHUNK = re.compile(rb"([0-9A-Fa-f]+)((?:[ \t]*;[ \t]*" + TOK + rb"(?:[ \t]*=[ \t]*(?:" + TOK + rb"|" + _QS + rb"))?)*)[ \t]*")

IDENT_NAMES = {b"x-forwarded-for", b"x-real-ip", b"forwarded"}


class Incomplete(Exception):
    pass


class Invalid(Exception):
    def __init__(self, why, off):
        Exception.__init__(self, why)
        self.why, self.off = why, off


class Msg:
    __slots__ = ("start", "head_end", "end", "method", "target", "version", "reqline", "headers", "framing",
                 "clen", "body_dec", "trailers", "chunks", "complete", "head_ok", "valid_end", "err", "err_off",
                 "upgrade", "te_other")

    def __init__(self, start):
        self.start = start
        self.head_end = None
        self.end = None
        self.method = self.target = self.version = self.reqline = None
        self.headers = []          # (name_raw, value, line_raw)
        self.framing = "none"
        self.clen = 0
        self.body_dec = b""
        self.trailers = []         # raw trailer lines (without CRLF)
        self.chunks = []           # (size, ext) per chunk, incl. the last one
        self.complete = False
        self.head_ok = False
        self.valid_end = start     # offset up to which the bytes are an acceptable prefix of this message
        self.err = None
        self.err_off = None
        self.upgrade = False
        self.te_other = False

    def hdr(self, lname):
        return [v for (n, v, _) in self.headers if n.lower() == lname]


class Result:
    def __init__(self, msgs, status, pos, err):
        self.msgs, self.status, self.pos, self.err = msgs, status, pos, err

    def complete(self):
        return [m for m in self.msgs if m.complete]

    def last(self):
        return self.msgs[-1] if self.msgs else None


def _next_line(d, pos, flags):
    """Return (line_without_eol, next_pos); raise Incomplete/Invalid."""
    n = len(d)
    k = pos
    while True:
        m = _CRLF.search(d, k)
        if not m:
            raise Incomplete()
        k = m.start()
        c = d[k]
        if c == 10:
            if k > pos and d[k - 1] == 13:
                return d[pos:k - 1], k + 1
            if "lf" in flags:
                return d[pos:k], k + 1
            raise Invalid("bare LF", k)
        if k + 1 >= n:
            raise Incomplete()
        if d[k + 1] == 10:
            return d[pos:k], k + 2
        if "cr" in flags:
            return d[pos:k], k + 1
        raise Invalid("bare CR", k)


def _parse_int(s, flags, what):
    """Content-Length / chunk-size interpretation, strict or sloppy."""
    if what == "cl":
        if "cl-int" in flags:                      # python int(): sign, whitespace, underscores, unicode digits
            return int(s.decode("latin1").strip().replace("_", ""), 10)
        if "cl-octal" in flags:                    # strtol(s, 0, 0)
            return int(s, 8) if len(s) > 1 and s[:1] == b"0" else int(s, 10)
        v = int(s, 10)
        if "cl-wrap32" in flags:
            v &= 0xFFFFFFFF
        if "cl-wrap64" in flags:
            v &= 0x7FFFFFFFFFFFFFFF
        return v
    v = int(s, 16)
    if "chunk-wrap32" in flags:
        v &= 0xFFFFFFFF
    if "chunk-wrap64" in flags:
        v &= 0xFFFFFFFFFFFFFFFF
    return v


def _split_list(v):
    return [t.strip().lower() for t in v.split(b",") if t.strip()]


def _parse_head(d, pos, m, flags):
    try:
        line, p = _next_line(d, pos, flags)
        if "nul-trunc" in flags:
            line = line.split(b"\0")[0]
        if "ver-ws" in flags:
            parts = line.split()
            if len(parts) < 3:
                raise Invalid("request line", pos)
            m.method, m.target = parts[0], parts[1]
            mv = re.fullmatch(rb"HTTP/(\d)\.(\d)", parts[-1])
            if not mv:
                raise Invalid("version", pos)
            m.version = (int(mv.group(1)), int(mv.group(2)))
        else:
            mm = RE_REQLINE.fullmatch(line)
            if not mm:
                raise Invalid("malformed request line", pos)
            m.method, m.target = mm.group(1), mm.group(2)
            m.version = (int(mm.group(3)), int(mm.group(4)))
            if m.version not in ((1, 0), (1, 1)) and "any-version" not in flags:
                raise Invalid("unsupported version", pos)
        m.reqline = line
        while True:
            lstart = p
            line, p = _next_line(d, p, flags)
            if "nul-trunc" in flags:
                line = line.split(b"\0")[0]
            if line == b"":
                break
            if line[:1] in (b" ", b"\t"):
                if "obsfold" in flags and m.headers:
                    n_, v_, l_ = m.headers[-1]
                    m.headers[-1] = (n_, v_ + b" " + line.strip(), l_ + b" " + line.strip())
                    continue
                raise Invalid("obs-fold", lstart)
            if "name-norm" in flags:
                if b":" not in line:
                    continue
                nm, _, vv = line.partition(b":")
                m.headers.append((nm.strip().replace(b"_", b"-"), vv.strip(), line))
                continue
            hm = RE_HEADER.fullmatch(line)
            if not hm:
                raise Invalid("malformed header line", lstart)
            m.headers.append((hm.group(1), hm.group(2), line))
    except Incomplete:
        m.valid_end = m.start          # the head is forwarded only once complete
        raise
    m.head_end = p
    _framing(d, m, flags)
    m.head_ok = True
    m.valid_end = p


def _framing(d, m, flags):
    hs = {}
    for n, v, _ in m.headers:
        hs.setdefault(n.lower(), []).append(v)
    hosts = hs.get(b"host", [])
    if len(hosts) > 1 and "multi-host" not in flags:
        raise Invalid("multiple Host", m.start)
    if not hosts and m.version == (1, 1) and "no-host-ok" not in flags:
        raise Invalid("missing Host", m.start)
    te = hs.get(b"transfer-encoding", [])
    cl = hs.get(b"content-length", [])
    conn = []
    for v in hs.get(b"connection", []):
        conn += _split_list(v)
    m.upgrade = bool(hs.get(b"upgrade")) and b"upgrade" in conn
    # (strict) framing
    if te and m.version == (1, 0) and "te-ignore-10" in flags:
        te = []
    if te and ("cl-wins" in flags) and cl:
        te = []
    if te:
        if "te-contains" in flags:
            toks = [b"chunked"] if any(b"chunked" in v.lower() for v in te) else [b"x"]
        else:
            toks = [t for v in te for t in _split_list(v)]
        if m.version == (1, 0) and "te-in-10" not in flags:
            raise Invalid("Transfer-Encoding in HTTP/1.0", m.start)
        if cl and "cl-and-te" not in flags:
            raise Invalid("Content-Length with Transfer-Encoding", m.start)
        if not toks or toks[-1] != b"chunked" or toks.count(b"chunked") != 1:
            raise Invalid("Transfer-Encoding does not end in a single chunked", m.start)
        m.te_other = len(toks) > 1
        m.framing = "chunked"
        return
    if cl:
        vals = []
        for v in cl:
            parts = [p.strip() for p in v.split(b",")] if "cl-int" not in flags else [v]
            vals += parts
        if len(set(vals)) != 1 and "cl-first" not in flags:
            raise Invalid("conflicting Content-Length", m.start)
        raw = vals[0]
        if "cl-int" not in flags and not RE_DIGITS.fullmatch(raw):
            raise Invalid("invalid Content-Length", m.start)
        try:
            m.clen = _parse_int(raw, flags, "cl")
        except ValueError:
            raise Invalid("invalid Content-Length", m.start)
        if m.clen < 0:
            raise Invalid("negative Content-Length", m.start)
        m.framing = "length" if m.clen > 0 else "none"


def _parse_body(d, m, flags):
    p = m.head_end
    n = len(d)
    if m.framing == "none":
        m.end = p
        m.complete = True
        m.valid_end = p
        return
    if m.framing == "length":
        have = n - p
        if have < m.clen:
            m.valid_end = n
            raise Incomplete()
        m.body_dec = d[p:p + m.clen]
        m.end = p + m.clen
        m.valid_end = m.end
        m.complete = True
        return
    # chunked
    out = []
    while True:
        us = p
        try:
            line, p2 = _next_line(d, p, flags)
            if "quote" in flags:
                while line.count(b'"') - line.count(b'\\"') & 1:
                    nxt, p2 = _next_line(d, p2, flags)
                    line = line + b"\r\n" + nxt
            if "chunk-int" in flags:
                szs = line.split(b";")[0].strip().replace(b"_", b"")
                try:
                    size = int(szs, 16)
                except ValueError:
                    raise Invalid("chunk size", us)
                ext = b""
            elif "ext-skip" in flags:
                mm = re.match(rb"[0-9A-Fa-f]+", line)
                if not mm:
                    raise Invalid("chunk size", us)
                size, ext = _parse_int(mm.group(0), flags, "chunk"), line[mm.end():]
            else:
                mm = RE_CHUNK.fullmatch(line)
                if not mm:
                    raise Invalid("malformed chunk size line", us)
                size, ext = _parse_int(mm.group(1), flags, "chunk"), mm.group(2)
        except Incomplete:
            m.valid_end = us
            raise
        except Invalid as e:
            m.valid_end = us
            e.off = us
            raise
        m.chunks.append((size, ext))
        p = p2
        m.valid_end = p
        if size == 0:
            break
        if n - p < size:
            m.valid_end = n
            raise Incomplete()
        out.append(d[p:p + size])
        p += size
        m.valid_end = p
        if "lf" in flags and d[p:p + 1] == b"\n":
            p += 1
        elif "term-skip" in flags:
            if n - p < 2:
                raise Incomplete()
            p += 2
        else:
            if n - p < 2:
                raise Incomplete()
            if d[p:p + 2] != b"\r\n":
                raise Invalid("bad chunk terminator", p)
            p += 2
        m.valid_end = p
    # trailer section
    while True:
        ls = p
        try:
            line, p2 = _next_line(d, p, flags)
        except Incomplete:
            m.valid_end = ls
            raise
        except Invalid as e:
            m.valid_end = ls
            raise
        if line == b"":
            p = p2
            break
        if not RE_HEADER.fullmatch(line):
            m.valid_end = ls
            raise Invalid("malformed trailer line", ls)
        m.trailers.append(line)
        p = p2
        m.valid_end = p
    m.body_dec = b"".join(out)
    m.end = p
    m.valid_end = p
    m.complete = True


def parse_stream(d, flags=()):
    flags = frozenset(flags)
    pos = 0
    msgs = []
    n = len(d)
    while True:
        while True:
            if d.startswith(b"\r\n", pos):
                pos += 2
            elif "lf" in flags and d.startswith(b"\n", pos):
                pos += 1
            else:
                break
        if pos >= n:
            return Result(msgs, "clean", pos, None)
        if d[pos:] == b"\r":
            return Result(msgs, "partial", pos, None)
        m = Msg(pos)
        msgs.append(m)
        try:
            _parse_head(d, pos, m, flags)
            _parse_body(d, m, flags)
        except Incomplete:
            return Result(msgs, "partial", pos, None)
        except Invalid as e:
            m.err, m.err_off = e.why, e.off
            return Result(msgs, "invalid", pos, e)
        pos = m.end


# ------------------------------------------------------- guard-forwarding model ---

GUARD_DROP = {b"x-real-ip", b"forwarded", b"x-forwarded-for"}


def norm_name(n):
    return n.lower().replace(b"_", b"-")


def expected_head(m, d, forward_ip=True, peer=b"127.0.0.1"):
    """The bytes a correct guard emits for the head of message m (mirrors the documented rewriting)."""
    if not forward_ip:
        return d[m.start:m.head_end]
    out = m.reqline
    for name, val, line in m.headers:
        if norm_name(name) in GUARD_DROP:
            continue
        out += b"\r\n" + line
    return out + b"\r\nX-Forwarded-For: " + peer + b"\r\nX-Real-IP: " + peer + b"\r\n\r\n"


def expected_forward(d, res, forward_ip=True, tunnel_after=None):
    """Upper bound of what the guard may forward for client stream d (parse result res).

    tunnel_after: index of a message after which the connection became a raw tunnel (WebSocket 101);
    everything the client sent afterwards is passed through verbatim.
    Returns the byte string F; the guard's output must be a prefix of F.
    """
    out = []
    for i, m in enumerate(res.msgs):
        if not m.head_ok:
            break
        out.append(expected_head(m, d, forward_ip))
        out.append(d[m.head_end:m.valid_end])
        if tunnel_after is not None and i == tunnel_after and m.complete:
            out.append(d[m.end:])
            break
        if not m.complete:
            break
    return b"".join(out)


# every lenient variant a backend might plausibly implement; guard output must frame identically under all
VARIANTS = [
    ("lf",), ("cr",), ("quote",), ("cl-octal",), ("cl-int",), ("cl-wrap32",), ("cl-wrap64",),
    ("cl-wins",), ("te-contains",), ("ver-ws",), ("name-norm",), ("nul-trunc",), ("chunk-int",),
    ("chunk-wrap32",), ("chunk-wrap64",), ("ext-skip",), ("term-skip",), ("obsfold",),
    ("lf", "ext-skip"), ("lf", "name-norm", "ver-ws"), ("cl-first", "cl-and-te"),
    ("name-norm", "cl-and-te"), ("name-norm", "cl-and-te", "cl-wins"), ("cl-and-te",), ("cl-and-te", "cl-wins"),
    ("ver-ws", "te-ignore-10"), ("name-norm", "te-contains", "cl-and-te"),
]


def boundaries(d, flags):
    r = parse_stream(d, flags)
    return [(m.start, m.end) for m in r.msgs if m.complete], r.status


def differential(d):
    """Parse guard output d strictly and under every variant. Return a list of differences."""
    base, st = boundaries(d, ())
    diffs = []
    for v in VARIANTS:
        b, s2 = boundaries(d, v)
        if b != base:
            diffs.append((v, base, b))
    return diffs
