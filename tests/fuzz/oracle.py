"""Desync / smuggling oracles.

Inputs: the bytes the client actually got onto the wire (C) and the bytes the backend received (B).

 O1 prefix    B must be a prefix of F, the stream a *correct* guard may forward for C. F is computed with the
              independent strict parser: only requests it accepts, in order, with the documented
              X-Forwarded-For / X-Real-IP rewriting, plus verbatim tunnel bytes after a real 101.
              Anything else means the guard forwarded bytes the client did not send, a request the strict
              parser rejects, or more/other requests than the client sent (smuggling).
 O2 variants  B (before any tunnel) must be framed identically by the strict parser and by every lenient
              "backend" variant (bare LF, octal Content-Length, `_` header names, quoted chunk-ext, ...).
 O3 identity  No client-supplied X-Forwarded-For / X-Real-IP / Forwarded variant (any case, `_` for `-`,
              also as chunk trailer or hidden via Connection) may reach the backend; the guard's own
              X-Forwarded-For / X-Real-IP must be present exactly once.
 O4 trailers  Framing/routing/identity fields must not be forwarded as chunk trailers (RFC 9110 6.5.1):
              a backend that merges trailers into headers would otherwise see them.
"""
import ipaddress

import refparse
from refparse import parse_stream, norm_name

FORBIDDEN_TRAILERS = {b"content-length", b"transfer-encoding", b"host", b"connection", b"upgrade", b"expect", b"te",
                      b"x-forwarded-for", b"x-real-ip", b"forwarded", b"trailer", b"content-encoding", b"keep-alive",
                      b"proxy-connection", b"max-forwards"}


FRAMING_ALIAS = {b"content-length", b"transfer-encoding", b"host", b"connection", b"upgrade", b"expect", b"te"}


class Finding:
    def __init__(self, kind, detail, sig=None, **extra):
        self.kind = kind
        self.detail = detail
        self.sig = sig or kind
        self.extra = extra

    def __repr__(self):
        return "Finding(%s: %s)" % (self.kind, self.detail)


def _snip(b, n=120):
    return repr(bytes(b[:n]))


def _ip(b):
    try:
        return ipaddress.ip_address(b.decode("ascii"))
    except ValueError:
        return None


def _norm_ip(ip):
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip).encode()


def expected_identity(m, peer=b"127.0.0.1", trusted=(b"127.0.0.1",)):
    """(X-Forwarded-For, X-Real-IP) the guard must send for client message m when `peer` is a trusted proxy.

    The client address comes from the configured header (X-Forwarded-For): rightmost entry that is not itself a
    trusted proxy; the chain keeps the client's header lines in their original order, then the peer."""
    xs = [v for n, v, _ in m.headers if n.lower() == b"x-forwarded-for"]
    parts = [p.strip() for v in xs for p in v.split(b",")]
    parts = [p for p in parts if p and _ip(p) is not None]
    if not parts:
        return peer, peer
    cand = parts[0]
    for p in reversed(parts):
        if _norm_ip(_ip(p)) not in trusted:
            cand = p
            break
    return b", ".join(xs) + b", " + peer, _norm_ip(_ip(cand))


def tunnel_index(res, bconn):
    """Index of the message after which the connection became a raw tunnel, or None."""
    if bconn is None or bconn.upgraded_at is None:
        return None
    if not res.msgs or not res.msgs[0].complete:
        return None
    m = res.msgs[0]
    if bconn.upgraded_at == 0 and m.upgrade and m.method == b"GET" and m.framing == "none":
        return 0
    return None


def check_stream(C, B, bconn=None, forward_ip=True, trusted=False, deep=True):
    """Run all oracles; returns a list of Finding."""
    out = []
    res = parse_stream(C)
    tun = tunnel_index(res, bconn)
    if not trusted:
        F = refparse.expected_forward(C, res, forward_ip, tun)
        if not F.startswith(B):
            # locate the divergence
            i = 0
            n = min(len(F), len(B))
            while i < n and F[i] == B[i]:
                i += 1
            # classify by what the guard forwarded beyond what is allowed
            bres = parse_stream(B[:bconn.cut] if (bconn and tun is not None and bconn.cut) else B)
            why = "backend bytes diverge from allowed forward at offset %d (allowed %d bytes, backend got %d): allowed %s | got %s" % (
                i, len(F), len(B), _snip(F[max(0, i - 40):i + 40], 80), _snip(B[max(0, i - 40):i + 40], 80))
            sig = "prefix"
            if len(B) > len(F) and B.startswith(F):
                sig = "extra-bytes"
                why = "guard forwarded %d bytes beyond the last acceptable request: %s" % (len(B) - len(F), _snip(B[len(F):], 100))
                # which rule did the extra message break?
                if res.status == "invalid" and res.err is not None:
                    sig += ":" + res.err.why
                elif res.msgs and res.msgs[-1].err:
                    sig += ":" + res.msgs[-1].err
            out.append(Finding("desync-prefix", why, sig))
    else:
        bres = parse_stream(B[:bconn.cut] if (bconn is not None and tun is not None and bconn.cut) else B)
        cc = res.complete()
        bm = bres.complete()
        if bres.status == "invalid":
            out.append(Finding("backend-invalid", "backend stream is not valid HTTP: %s" % bres.err.why, "backend-invalid:" + bres.err.why))
        if len(bm) > len(cc):
            out.append(Finding("desync-count", "backend saw %d requests, client sent %d" % (len(bm), len(cc)), "count"))
        for a, b in zip(cc, bm):
            if a.reqline != b.reqline or a.body_dec != b.body_dec:
                out.append(Finding("desync-content", "request content differs", "content"))
                break
            if forward_ip:
                ex, er = expected_identity(a)
                bx = [v for n, v, _ in b.headers if norm_name(n) == b"x-forwarded-for"]
                br = [v for n, v, _ in b.headers if norm_name(n) == b"x-real-ip"]
                if bx != [ex]:
                    out.append(Finding("identity-chain", "behind a trusted proxy the backend got X-Forwarded-For %r, expected %r (client lines in order, then the peer; "
                                       "only the exact header name counts)" % (bx, ex), "chain-xff"))
                if br != [er]:
                    out.append(Finding("identity-chain", "behind a trusted proxy the backend got X-Real-IP %r, expected %r" % (br, er), "chain-xri"))
    # tunnel part is opaque: analyse only the HTTP part of B
    Bh = B
    if bconn is not None and tun is not None and bconn.cut:
        Bh = B[:bconn.cut]
    # O2 (only meaningful when the strict parser accepts the guard's output; otherwise O1 already reported it)
    for flags, base, other in ([] if (not deep or parse_stream(Bh).status == "invalid") else refparse.differential(Bh)):
        out.append(Finding("variant-differential",
                           "variant %s frames the guard's output differently: strict %s vs %s | data %s" % (
                               "+".join(flags), base[:4], other if isinstance(other, str) else other[:4], _snip(Bh, 160)),
                           "variant:" + "+".join(flags)))
    # O3/O4 on the guard's output
    bres = parse_stream(Bh)
    for m in bres.msgs:
        if not m.head_ok:
            break
        xff = [v for n, v, _ in m.headers if norm_name(n) == b"x-forwarded-for"]
        xri = [v for n, v, _ in m.headers if norm_name(n) == b"x-real-ip"]
        fwd = [v for n, v, _ in m.headers if norm_name(n) == b"forwarded"]
        if not trusted:
            if xff != [b"127.0.0.1"] and forward_ip:
                out.append(Finding("identity", "backend saw X-Forwarded-For %r (expected only the guard's own)" % (xff,), "xff"))
            if xri != [b"127.0.0.1"] and forward_ip:
                out.append(Finding("identity", "backend saw X-Real-IP %r" % (xri,), "xri"))
            if fwd and forward_ip:
                out.append(Finding("identity", "client Forwarded header reached the backend: %r" % (fwd,), "forwarded"))
        for v in m.hdr(b"connection"):
            toks = refparse._split_list(v)
            bad = [t for t in toks if norm_name(t) in refparse.IDENT_NAMES | {b"content-length", b"transfer-encoding", b"host"}]
            if bad and forward_ip:
                out.append(Finding("identity-hop", "Connection header names protected header(s) %r: a downstream hop would strip them (CL removal desync, lost client address)" % (bad,), "conn-hop"))
        for t in m.trailers:
            nm = t.split(b":", 1)[0]
            if norm_name(nm) in FORBIDDEN_TRAILERS:
                out.append(Finding("forbidden-trailer", "trailer %r forwarded to the backend" % (t[:60],), "trailer:" + norm_name(nm).decode("latin1")))
        for n, v, line in m.headers:
            if b"_" in n and norm_name(n) in FRAMING_ALIAS:
                out.append(Finding("framing-alias", "header %r forwarded: a backend folding '_' to '-' would treat it as a framing/routing header" % (n,),
                                   "alias:" + norm_name(n).decode("latin1")))
        if not m.complete:
            break
    return out
