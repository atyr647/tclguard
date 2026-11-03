"""Reproducer minimisation (delta debugging) using the in-process parser as the fast predicate."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen        # noqa: E402
import inproc     # noqa: E402
import oracle     # noqa: E402


def finding_sigs(w, data, upg, end="eof", pieces=None):
    res = w.run([(pieces or [data], end, upg)])[0]
    case = {"ops": [["s", p] for p in (pieces or [data])], "end": "half"}
    stats = __import__("collections").Counter()
    return [f.sig for f in inproc.evaluate(w, case, upg, res, True, stats)], res


def ddmin(data, test, max_tests=1200):
    """Classic ddmin over bytes; test(data) -> True if the failure still reproduces."""
    n = 2
    tests = 0
    while len(data) >= 2:
        chunk = max(1, len(data) // n)
        subsets = [(i, data[i:i + chunk]) for i in range(0, len(data), chunk)]
        reduced = False
        for i, sub in subsets:
            comp = data[:i] + data[i + len(sub):]
            tests += 1
            if comp and test(comp):
                data = comp
                n = max(n - 1, 2)
                reduced = True
                break
            if tests > max_tests:
                return data
        if not reduced:
            if n >= len(data):
                break
            n = min(len(data), n * 2)
    return data


def line_pass(data, test):
    """Cheap first pass: drop whole CRLF-delimited lines."""
    parts = data.split(b"\r\n")
    i = 0
    while i < len(parts):
        cand = parts[:i] + parts[i + 1:]
        d = b"\r\n".join(cand)
        if d and test(d):
            parts = cand
        else:
            i += 1
    return b"\r\n".join(parts)


def minimise(cfg, case, sig, upg=0, log=print):
    """Return a minimised single-piece reproducer {"ops","end"} for finding `sig`, or the original case."""
    w = inproc.Worker(cfg)
    try:
        C = b"".join(op[1] for op in case["ops"] if op[0] == "s")
        end = "eof"
        orig_pieces, orig_end = inproc.flatten(case)

        def test(d):
            sigs, res = finding_sigs(w, d, upg, end)
            if sig.startswith("cpu"):
                return res["usec"] > 150000
            return sig in sigs

        if sig.startswith("cpu"):
            # every probe costs a fraction of a second: hand-reduce these (see the corpus entry) instead of ddmin
            return {"ops": [["s", C]], "end": "half"}, False
        if not test(C):
            log("  does not reproduce as one piece in-process; keeping the original schedule")
            return {"ops": case["ops"], "end": case["end"]}, False
        d = line_pass(C, test)
        d = ddmin(d, test)
        log("  minimised %d -> %d bytes" % (len(C), len(d)))
        return {"ops": [["s", d]], "end": "half"}, True
    finally:
        w.close()


def promote(path, name, outdir, cfg="default", upg=0, note=""):
    d = json.load(open(path))
    case, meta = gen.case_from_json(d)
    sig = meta.get("sig", meta.get("kind", ""))
    mincase, ok = minimise(cfg, case, sig, upg)
    os.makedirs(outdir, exist_ok=True)
    dest = os.path.join(outdir, name + ".json")
    with open(dest, "w") as fh:
        fh.write(gen.case_to_json(mincase, kind=meta.get("kind"), sig=sig, detail=meta.get("detail", "")[:400],
                                  variant=meta.get("variant", "default"), upg=upg, config=cfg, note=note, minimised=ok))
    return dest
