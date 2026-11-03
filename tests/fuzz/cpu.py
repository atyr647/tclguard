"""CPU amplification / scaling probes against a live guard.

For each family of pathological inputs the guard's CPU time (sum of /proc/<pid>/task/*/schedstat, ns
resolution) is measured at 4 sizes (n, 2n, 4n, 8n), one input at a time on an otherwise idle guard.
Flags: any single input above CPU_LIMIT_MS, or super-linear growth (8x size costing > 12x more CPU
once above the noise floor).
This is a regression guard against algorithmic blow-ups, not a benchmark: it never compares absolute speed.
"""
import time

import gen
import oracle

CPU_LIMIT_MS = 200.0
NOISE_MS = 25.0
# The absolute limit is for a fast machine. Slower hardware (a shared CI runner is 3-4x slower) is accounted for by timing a
# fixed benign workload first (500 pipelined GETs) and scaling the limit by how much slower this machine is than the one
# the limit was chosen on (min of 5 runs there: 35 ms). The shape checks (super-linear growth) are not affected.
CAL_REF_MS = 35.0


def S(*parts):
    return b"".join(parts)


def case_of(data, end="close", per_byte=False, gap=0.0):
    if per_byte:
        ops = []
        for i in range(len(data)):
            ops.append(["s", data[i:i + 1]])
            if gap:
                ops.append(["d", gap])
        return {"ops": ops, "end": end}
    return {"ops": [["s", data]], "end": end}


def chunks(sz, n, ext=b""):
    return b"".join(b"%x%s\r\n%s\r\n" % (sz, ext, b"x" * sz) for _ in range(n)) + b"0\r\n\r\n"


H = b"Host: x\r\n"
POSTC = b"POST /u HTTP/1.1\r\n" + H + b"Transfer-Encoding: chunked\r\n\r\n"

FAMILIES = [
    # name, sizes, builder(n) -> case
    ("trickle-header-bytes", [1500, 3000, 6000, 12000], lambda n: case_of(S(b"GET / HTTP/1.1\r\n", H, b"X: ", b"a" * n), per_byte=True)),
    ("trickle-header-lines", [12, 25, 50, 99], lambda n: {"ops": [["s", b"GET / HTTP/1.1\r\nHost: x\r\n"]] + [["s", b"X-%d: vvvvvvvvvvvv\r\n" % i] for i in range(n)], "end": "close"}),
    ("whitespace-header-value", [2000, 4000, 8000, 16000], lambda n: case_of(S(b"GET / HTTP/1.1\r\n", H, b"X: ", b" " * n, b"a\r\n\r\n"))),
    ("tab-space-header-value", [1000, 2000, 4000, 8000], lambda n: case_of(S(b"GET / HTTP/1.1\r\n", H, b"X: ", b"\t " * n, b"a\r\n\r\n"))),
    ("trailing-ws-header-value", [2000, 4000, 8000, 16000], lambda n: case_of(S(b"GET / HTTP/1.1\r\n", H, b"X: a", b" " * n, b"\r\n\r\n"))),
    ("long-target", [1000, 2000, 4000, 8000], lambda n: case_of(S(b"GET /", b"a" * n, b" HTTP/1.1\r\n", H, b"\r\n"))),
    ("many-small-headers", [12, 25, 50, 100], lambda n: case_of(S(b"GET / HTTP/1.1\r\n", H, *[b"X%d: v\r\n" % i for i in range(n)], b"\r\n"))),
    ("leading-crlf", [8, 100, 10000, 100000], lambda n: case_of(S(b"\r\n" * n, b"GET / HTTP/1.1\r\n", H, b"\r\n"))),
    ("pipeline-tiny-gets", [250, 500, 1000, 2000], lambda n: case_of(b"GET /p HTTP/1.1\r\nHost: x\r\n\r\n" * n, end="half")),
    ("chunks-1byte (tiny flood)", [250, 500, 1000, 2000], lambda n: case_of(S(POSTC, chunks(1, n)))),
    ("chunks-16byte", [1000, 2000, 4000, 8000], lambda n: case_of(S(POSTC, chunks(16, n)), end="half")),
    ("chunks-64byte", [1000, 2000, 4000, 8000], lambda n: case_of(S(POSTC, chunks(64, n)), end="half")),
    ("chunks-1k", [250, 500, 1000, 2000], lambda n: case_of(S(POSTC, chunks(1024, n)), end="half")),
    ("chunk-ext-long", [250, 500, 1000, 2000], lambda n: case_of(S(POSTC, b"1;a=", b"b" * n, b"\r\nx\r\n0\r\n\r\n"))),
    ("chunk-line-trickle", [300, 600, 1200, 2400], lambda n: case_of(S(POSTC, b"1;a=", b"b" * n), per_byte=True)),
    ("trailers-long-line", [1000, 2000, 4000, 8000], lambda n: case_of(S(POSTC, b"0\r\nX-T: ", b"v" * n, b"\r\n\r\n"))),
    ("body-cl-single-write", [256 * 1024, 512 * 1024, 1024 * 1024, 2000 * 1024],
     lambda n: case_of(S(b"POST /u HTTP/1.1\r\n", H, b"Content-Length: %d\r\n\r\n" % n, b"x" * n), end="half")),
    ("body-cl-trickle", [1000, 2000, 4000, 8000], lambda n: case_of(S(b"POST /u HTTP/1.1\r\n", H, b"Content-Length: %d\r\n\r\n" % n, b"x" * n), per_byte=True)),
    ("body-chunked-trickle", [500, 1000, 2000, 4000], lambda n: case_of(S(POSTC, b"%x\r\n" % n, b"x" * n, b"\r\n0\r\n\r\n"), per_byte=True)),
]


# only meaningful when the client address comes from a trusted proxy header
TRUSTED_FAMILIES = [
    ("xff-many-ips (trusted proxy)", [250, 500, 1000, 2000], lambda n: case_of(S(b"GET / HTTP/1.1\r\n", H, b"X-Forwarded-For: ", b", ".join([b"1.2.%d.%d" % (i // 250, i % 250) for i in range(n)]), b"\r\n\r\n"))),
    ("xff-many-headers (trusted proxy)", [100, 200, 400, 800], lambda n: case_of(S(b"GET / HTTP/1.1\r\n", H, *[b"X-Forwarded-For: 1.2.3.%d\r\n" % (i % 250) for i in range(min(n, 99))], b"\r\n"))),
    ("xff-long-garbage (trusted proxy)", [2000, 4000, 8000, 16000], lambda n: case_of(S(b"GET / HTTP/1.1\r\n", H, b"X-Forwarded-For: ", b"1:" * (n // 2), b"\r\n\r\n"))),
]


# families whose cost is legitimately proportional to the work requested (many real requests / big bodies):
# only super-linear growth counts there, not the absolute figure
QUICK = ("whitespace-header-value", "trailing-ws-header-value", "trickle-header-bytes", "chunks-16byte", "chunk-ext-long",
         "trailers-long-line", "xff-many-ips", "body-chunked-trickle")
LINEAR_OK = ("pipeline", "body-cl-single", "chunks-1k")


def calibrate(live, runs=5):
    case = case_of(b"GET /p HTTP/1.1\r\nHost: x\r\n\r\n" * 500, end="half")
    return max(1.0, min(live.cpu_of(case)[0] for _ in range(runs)) / CAL_REF_MS)


def run_probe(live, quick=False, log=print, only=None, families=None):
    findings = []
    live.baseline()
    slow = calibrate(live)
    limit = CPU_LIMIT_MS * slow
    log("  (this machine is %.1fx slower than the reference: CPU limit %.0f ms)" % (slow, limit))
    for name, sizes, build in (families or FAMILIES):
        if only and only not in name:
            continue
        if quick:
            if not name.startswith(QUICK):
                continue
            sizes = sizes[1:]
        row = []
        for n in sizes:
            case = build(n)
            nbytes = sum(len(op[1]) for op in case["ops"] if op[0] == "s")
            best = None
            for _ in range(2):                       # CPU time is already insensitive to load; take the min of two runs
                ms, r = live.cpu_of(case)
                best = ms if best is None else min(best, ms)
                if best < 5:
                    break
            row.append((n, nbytes, best))
        txt = "  ".join("n=%d(%dB): %.0fms" % x for x in row)
        flag = ""
        worst = max(x[2] for x in row)
        if worst > limit and not name.startswith(LINEAR_OK):
            flag = "HIGH"
            findings.append(oracle.Finding("cpu", "%s: %.0f ms for a single input (limit %.0f): %s" % (name, worst, limit, txt), "cpu:" + name,
                                           case=build(row[[x[2] for x in row].index(worst)][0])))
        if len(row) >= 3 and row[-1][2] > NOISE_MS * 2:
            ratio = row[-1][2] / max(row[-2][2], NOISE_MS / 2)
            r = row[-1][1] / float(row[-2][1])
            if r >= 1.9 and ratio > 0.8 * r * r:
                flag += " QUADRATIC"
                findings.append(oracle.Finding("cpu-scaling", "%s: super-linear CPU growth (x%.1f bytes cost x%.1f): %s" % (name, r, ratio, txt), "cpuscale:" + name,
                                               case=build(row[-1][0])))
        log("  %-28s %s %s" % (name, txt, flag))
    return findings
