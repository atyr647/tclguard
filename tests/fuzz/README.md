# HTTP parser fuzzer

Pure Python 3 standard library plus `tclsh8.6`; no pip installs. It attacks the `http` listener (strict HTTP/1.x
parser, request-smuggling defences, X-Forwarded-For rewriting) with generated and mutated requests and judges the
result with oracles that do not share code with the Tcl implementation.

```
tests/fuzz/
  fuzz.py            CLI: ci | live | inproc | cpu | replay | promote
  gen.py             grammar-aware request generator, byte mutator, TCP delivery scheduler
  refparse.py        independent strict reference parser (RFC 9112/9110) + lenient "backend" variants
  oracle.py          the desync / identity / trailer oracles
  backend.py         recording backend (exact bytes per connection, correlated to the client via PROXY v1)
  live.py            guard process + real sockets + liveness / leak / log oracles
  inproc.py/.tcl     the real Tcl parser driven without sockets (reflected channels), millions of cheap cases
  cpu.py             CPU amplification and scaling probes
  minimise.py        delta-debugging of reproducers
  corpus/            minimised reproducers of every bug found (replayed by test_regressions.py)
  test_regressions.py  explicit regression checks + corpus replay (in-process and live)
```

## Commands

```sh
python3 tests/fuzz/fuzz.py ci                                  # deterministic, ~1.5 min, exit 1 on any finding
python3 tests/fuzz/fuzz.py live   --seconds 3600 --seed 7 --variant default,noxff,trusted,challenge
python3 tests/fuzz/fuzz.py inproc --seconds 3600 --seed 7      # configs default, noxff, trusted
python3 tests/fuzz/fuzz.py cpu                                 # CPU probes (guard process CPU, not wall clock)
python3 tests/fuzz/fuzz.py replay path/to/finding.json         # one reproducer against a live guard
python3 tests/fuzz/fuzz.py promote out/x.json --name short-name --config default   # minimise into corpus/
python3 tests/fuzz/test_regressions.py                         # what CI runs for the corpus
```

Findings are written as JSON (ops, end mode, client bytes, backend bytes, detail) to `tests/fuzz/out/`
(git-ignored). `TG_CMD` selects a different build for the live modes (same convention as
`tests/integration/harness.py`), `TG_VFS` a different `tclguard.vfs` for the in-process mode, which is how a
reproducer is minimised against the *unfixed* code. At most two cores are used (guard + Python).

Case generation is deterministic per `--seed`; the live mode's outcome also depends on scheduling, so a finding
is saved with its exact ops and is replayed from the file rather than from the seed.

## Oracles

1. **Desync / smuggling (`oracle.py`).** Every connection goes through `proxyProtocol v1`, so the recording
   backend knows which client socket produced which backend connection and keeps the exact bytes it received.
   * *O1 prefix*: the strict reference parser parses what the client actually sent and computes the stream a
     correct guard may forward (accepted requests only, with the documented X-Forwarded-For / X-Real-IP rewrite,
     verbatim tunnel bytes after a real 101). The backend's bytes must be a *prefix* of that. This catches
     "forwarded something the reference rejects", "forwarded a different number of requests", and "backend
     received bytes the client never sent" in one comparison.
   * *O2 variants*: the guard's output must be framed identically by the strict parser and by 25 models of lenient
     backends (bare LF, bare CR, quote-aware chunk-ext, octal / wrapped / signed Content-Length, `_`-for-`-` header
     names, whitespace-split request line, TE-wins/CL-wins, NUL truncation, ...). A difference is a request the
     guard and some real backend would count differently.
   * *O3 identity*: no client X-Forwarded-For / X-Real-IP / Forwarded variant (any case, `_` for `-`, as a trailer,
     or hidden through `Connection:` hop-by-hop stripping) reaches the backend; the guard's own two headers appear
     exactly once with the real peer address. Run for `forwardIp` on and off, and with a trusted proxy.
   * *O4 trailers*: framing / routing / identity fields are never forwarded as chunk trailers (RFC 9110 6.5.1).
2. **Liveness and CPU.** After every batch the guard must answer a normal request and `ctl ping` within a deadline
   and must still be alive. `cpu.py` measures guard CPU (sum of `/proc/<pid>/task/*/schedstat`, nanosecond
   resolution) for families of pathological inputs at four sizes, one input at a time on an idle guard, and flags
   any input above 200 ms or super-linear growth. The in-process mode flags any case over 200 ms *and* 20 us per
   input byte (reflected channels make `emit` slow, so per-byte cost is the fair yardstick there).
3. **Leaks.** After each batch the connection tables (`ctl debug`: tcpConns, tcpPerIp, httpState, httpBuf), the
   channel count, `/proc/<pid>/fd` and the RSS trend (early vs late rounds) must be back at baseline. In-process,
   every per-connection array element must be gone after each case.
4. **Errors.** The guard log must contain no `background error` or Tcl error trace; the in-process worker reports
   any Tcl exception from the parser procs.

The generator covers: Content-Length and chunked framing (extensions, trailers, tiny/huge/overflowing sizes: 2^31,
2^32, 2^63, 2^64, negative, hex, `+`, unicode digits, leading zeros), CL+TE and duplicate/conflicting headers,
`Transfer_Encoding`-style spellings, HTTP/1.0 and 1.1, Upgrade/WebSocket (with bodies, pipelined, post-upgrade
bytes), Expect, absolute-form and odd request targets, odd whitespace/casing, NUL/CR/LF/TAB/high bytes in every
position, deep pipelines, header floods, then a byte-level mutator, then delivery split into 1..400 TCP segments
with random delays, half-close and RST at random points. The backend answers in several modes (normal, early
answer before the body, 101 for WebSocket, 101 even without `Connection: upgrade`, slow).

## Bugs found (all fixed; reproducers in `corpus/`)

| Class | Impact | Fix |
|---|---|---|
| Header lines parsed with a lazy-quantifier regexp, quadratic in Tcl | one 16 KB header value = ~0.4 s of CPU; ~40 KB/s of such requests pins the single-threaded guard | plain string operations |
| TAB accepted in the request line | whitespace-splitting parsers see another target/version (`POST /\tHTTP/1.0 HTTP/1.1` is 1.0 there: Transfer-Encoding ignored) = smuggling | reject |
| Chunk extensions forwarded unchecked | unterminated quote (quote-aware backends run it across the line break), control bytes, NUL, spaces move chunk boundaries ("funky chunks") | RFC 9112 chunk-ext grammar enforced |
| Chunk trailers `Content-Length`, `Transfer-Encoding`, `Host`, `Connection`, `Upgrade`, `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, ... forwarded | backends that merge trailers into headers accept client-chosen framing or client address | reject |
| `Content_Length` / `Transfer_Encoding` / `Host_` / `Connection` / `Upgrade` / `Expect` / `TE` spellings forwarded | servers that fold `_` to `-` (CGI/WSGI style) frame differently | reject |
| `Connection: Content-Length` (and `Transfer-Encoding`, `Host`, `X-Real-IP`, `X-Forwarded-For`, `Forwarded`) forwarded | the next hop strips the named field as hop-by-hop: body becomes a request, or the address added for the backend vanishes | reject |
| `Content-Length: 010` accepted | strtol(s, 0, 0) readers take it as octal 8: the request boundary moves | no leading zeros |
| Trusted-proxy X-Forwarded-For chain: several client lines were merged in reverse order, and `X_Forwarded_For` spellings were merged too | backend's "leftmost/rightmost untrusted" differs from the address the guard banned or limited; a client behind the proxy could inject chain entries | original order, exact header name only |
| Per-path limits matched the raw path only | `//login`, `/%6cogin`, `/./login`, `/x/../login`, `/\login` walk around a `^/login` limit (login brute force) | also match the %-decoded, dot-resolved, `;param`-free path |
| Tcl's default `string trim` also strips U+00A0 / U+0085, used for `Connection` tokens and X-Forwarded-For entries | `Connection:\xa0upgrade` was an Upgrade for the guard but not for a strict parser (and the reverse for protected-field names); a client address with a leading NBSP was accepted | trim only SP/HTAB (the RFC's OWS) |
| Tiny-chunk limit only counted chunks under 16 bytes | 16..127-byte chunks cost ~75 us each, unmetered: 3 Mbit/s pinned a core | count chunks under 128 bytes |

## Deliberate deviations from RFC 9112 (the guard is stricter on purpose)

Not findings; the oracles only require that what is forwarded is valid, so rejecting valid-but-unusual input is
allowed. Listed so nobody "fixes" them by accident.

* Absolute-form targets, `CONNECT`/authority-form and anything but origin-form (and `OPTIONS *`) are refused: the
  guard fronts one origin, it is not a forward proxy. Methods are limited to the listener's `methods` setting.
* `Transfer-Encoding` must be exactly `chunked` (no `gzip, chunked`); not allowed in HTTP/1.0; never together with
  `Content-Length`. Only HTTP/1.0 and HTTP/1.1 are accepted.
* `Content-Length` is `0` or `[1-9][0-9]{0,14}` only (leading zeros, more than 15 digits, a `5, 5` list, and values
  over `maxBodyMB` are refused). Several identical `Content-Length` headers are accepted and forwarded verbatim (RFC permits either).
* Chunk-size lines: 1..12 hex digits, no whitespace around `;`/`=` (RFC permits deprecated BWS), at most 4096 bytes;
  at most 20 trailer lines of 4096 bytes; at most 2000 chunks under 128 bytes per request.
* At most 8 leading empty lines before a request line (RFC: SHOULD ignore at least one).
* Bare LF, bare CR, obs-fold, whitespace before the colon, control characters (other than TAB in values) are refused
  everywhere, also in trailers. Header names with `_` that fold into a framing/routing header are refused.
* Upgrade is honoured only as the first, body-less GET of a connection, and only when `Connection` lists `upgrade`.
* Not rewritten by design: client-IP headers other than X-Forwarded-For / X-Real-IP / Forwarded
  (`True-Client-IP`, `CF-Connecting-IP`, `X-Client-IP` ...). The guard cannot know which one a backend trusts; make
  the backend trust only the two the guard controls.

## Known limits (suspected, not proven harmful)

* Trickling a header block one byte per packet re-scans the buffer each time (`trickle-header-bytes` in `cpu.py`:
  ~50 ms CPU for 12 KB, mildly super-linear, bounded by `maxHeaderBytes` and `headerTimeout`).
* The parser re-slices its buffer per state transition; pipelined tiny requests cost ~120 us each. Per-IP
  `reqRate` meters requests, not chunks; the 2000 small-chunk cap above is what bounds chunk floods.
* Per-path limits (`pathLimits`) match the path as sent and as normalised (%XX, `\`, `//`, dot segments, `;params`).
  They are case-sensitive (use `(?i)` in the regexp for a case-insensitive backend) and do not double-decode.

* `::tg::ip::parse` (util.tcl) trims with Tcl's default `string trim`, so an X-Forwarded-For entry with a leading
  NBSP (`\xa0127.0.0.1`) from a trusted proxy is accepted as 127.0.0.1 (the chain forwards the raw text, X-Real-IP
  is the normalised address). Found by the trusted-proxy identity oracle (`identity-chain`); not fixed because it
  lives outside the HTTP parser and needs a decision about the other callers of `parse`.

## Adding a regression

Run the fuzzer, take the JSON from `out/`, `fuzz.py promote out/x.json --name short-name` (minimises against the
in-process parser; use `TG_VFS=<unfixed tclguard.vfs>` before the fix), then add an explicit check to
`test_regressions.py` if the behaviour deserves a named test.
