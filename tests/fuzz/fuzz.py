#!/usr/bin/env python3
"""TclGuard HTTP parser fuzzer (pure stdlib).

  python3 tests/fuzz/fuzz.py ci                      deterministic, ~60 s, exit 1 on any finding
  python3 tests/fuzz/fuzz.py live  --seconds 1800 --seed 7 --variant default
  python3 tests/fuzz/fuzz.py inproc --seconds 600 --seed 7
  python3 tests/fuzz/fuzz.py cpu                     CPU amplification / scaling probes against a live guard
  python3 tests/fuzz/fuzz.py replay corpus/foo.json  replay a reproducer against a live guard

Env TG_CMD points at a different build (same convention as tests/integration/harness.py).
"""
import argparse
import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen        # noqa: E402


def save_finding(outdir, tag, f, case, sent, got, variant):
    os.makedirs(outdir, exist_ok=True)
    name = "%s-%s.json" % (f.kind, "".join(c if c.isalnum() else "_" for c in f.sig)[:60])
    path = os.path.join(outdir, name)
    if os.path.exists(path):
        return path
    c = {"ops": case["ops"], "end": case["end"]}
    with open(path, "w") as fh:
        fh.write(gen.case_to_json(c, kind=f.kind, sig=f.sig, detail=f.detail[:600], variant=variant, tag=tag,
                                  client_hex=sent.hex()[:20000], backend_hex=got.hex()[:20000]))
    return path


def report(live, outdir, tag):
    n = 0
    for sig, (f, case, sent, got) in sorted(live.findings.items()):
        p = save_finding(outdir, tag, f, case, sent, got, live.variant)
        print("FINDING %-20s %s\n    %s\n    -> %s" % (f.kind, sig, f.detail[:300], p))
        n += 1
    return n


def cmd_live(a):
    import live as L
    outdir = a.out
    total_findings = 0
    variants = a.variant.split(",")
    per = a.seconds / len(variants)
    for variant in variants:
        lv = L.Live(variant, workers=a.workers)
        try:
            total_findings += run_live(lv, a, per, outdir)
        finally:
            lv.close()
    return total_findings


def run_live(lv, a, seconds, outdir):
    rng = random.Random("%d:%s" % (a.seed, lv.variant))
    lv.baseline()
    print("[live:%s] baseline %s fds=%d rss=%.1fMB" % (lv.variant, lv.base["debug"], lv.base["fds"], lv.base["rss"]), flush=True)
    t_end = time.time() + seconds
    lv.deadline = t_end
    done = 0
    rounds = 0
    cpu_c0 = lv.proc.cpu_ms()
    last_print = time.time()
    while time.time() < t_end:
        cases = [gen.make_case(rng) for _ in range(a.batch)]
        lv.run_batch(cases)
        done = lv.stats["cases"]
        if time.time() > t_end:
            lv.deadline = 0
        rounds += 1
        fs, d = lv.check_batch_state("round %d" % rounds)
        for f in fs:
            lv.record(f, {"ops": [], "end": "half"})
        if time.time() - last_print > 15:
            last_print = time.time()
            print("[live:%s] %d cases, rss %.1fMB fds %d, findings %d, stats %s" % (
                lv.variant, done, lv.proc.rss_mb(), lv.proc.fds(), len(lv.findings),
                {k: v for k, v in lv.stats.items() if k.startswith("resp") or k == "forwarded"}), flush=True)
    cpu = lv.proc.cpu_ms() - cpu_c0
    g = lv.rss_growth()
    print("[live:%s] done: %d cases in %d rounds, guard CPU %.1f s, rss growth %s MB" % (
        lv.variant, done, rounds, cpu / 1000, "n/a" if g is None else "%.1f" % g), flush=True)
    if g is not None and g > 25:
        import oracle
        lv.record(oracle.Finding("leak-rss", "guard RSS grew %.1f MB between early and late rounds (history %s)" % (g, [round(x) for x in lv.rss_hist]), "leak-rss"),
                  {"ops": [], "end": "half"})
    print("[live:%s] top reject reasons: %s" % (lv.variant, lv.reasons.most_common(12)))
    return report(lv, outdir, "seed%d" % a.seed)


def cmd_inproc(a):
    import inproc
    total = 0
    cfgs = a.variant.split(",") if a.variant != "all" else ["default", "noxff", "trusted"]
    per = a.seconds / len(cfgs)
    for cfg in cfgs:
        findings, stats = inproc.run(per, a.seed, cfg, on_finding=lambda f, c, s, g, cfg=cfg: print("    saved ->", save_finding(a.out, "inproc-seed%d" % a.seed, f, c, s, g, "inproc:" + cfg), flush=True))
        total += len(findings)
    return total


def cmd_cpu(a):
    import live as L
    import cpu
    n = 0
    lv = L.Live("trusted")
    try:
        fs = cpu.run_probe(lv, quick=a.quick, only=a.arg, families=cpu.TRUSTED_FAMILIES)
        for f in fs:
            case = f.extra.get("case") or {"ops": [], "end": "half"}
            p = save_finding(a.out, "cpu", f, case, b"", b"", "trusted")
            print("FINDING %-12s %s\n    %s\n    -> %s" % (f.kind, f.sig, f.detail[:400], p))
            n += 1
    finally:
        lv.close()
    lv = L.Live("default")
    try:
        fs = cpu.run_probe(lv, quick=a.quick, only=a.arg)
        for f in fs:
            case = f.extra.get("case") or {"ops": [], "end": "half"}
            p = save_finding(a.out, "cpu", f, case, b"", b"", "cpu")
            print("FINDING %-12s %s\n    %s\n    -> %s" % (f.kind, f.sig, f.detail[:400], p))
            n += 1
        errs = lv.scan_log()
        for f in errs:
            print("FINDING log-error", f.detail)
            n += 1
        ok, took = lv.liveness()
        print("guard alive and answering after the probes: %s" % ok)
        if not ok:
            n += 1
    finally:
        lv.close()
    return n


def cmd_replay(a):
    import live as L
    import json
    n = 0
    paths = [a.arg] if a.arg else []
    lvs = {}
    try:
        for p in paths:
            case, meta = gen.case_from_json(open(p).read())
            variant = meta.get("variant", "default")
            if variant.startswith("inproc:"):
                variant = variant.split(":", 1)[1]
            lv = lvs.setdefault(variant, L.Live(variant if variant in L.VARIANTS else "default"))
            fs = lv.submit(case)
            lv.settle_tables()
            print("%s: %s" % (p, "findings: %s" % fs if fs else "clean"))
            n += len(fs)
    finally:
        for lv in lvs.values():
            lv.close()
    return n


def cmd_promote(a):
    import minimise
    dest = minimise.promote(a.arg, a.name, os.path.join(HERE, "corpus"), cfg=a.config, upg=a.upg, note=a.note)
    print("wrote", dest)
    return 0


def cmd_ci(a):
    """Deterministic smoke: fixed seed, ~60 s total: in-process millions-style burst, live burst, CPU probes, corpus replay."""
    import inproc
    import live as L
    import cpu
    import subprocess
    n = 0
    t0 = time.time()
    # 1. in-process (fast, 2 configs)
    for cfg, secs in (("default", 14), ("trusted", 5)):
        findings, stats = inproc.run(secs, a.seed, cfg, pool_size=1500)
        for sig, (f, case, sent, got) in sorted(findings.items()):
            p = save_finding(a.out, "ci", f, case, sent, got, "inproc:" + cfg)
            print("FINDING %-20s %s\n    %s\n    -> %s" % (f.kind, sig, f.detail[:300], p))
            n += 1
    # 2. live
    lv = L.Live("default")
    try:
        a2 = argparse.Namespace(seed=a.seed, batch=100, workers=a.workers)
        n += run_live(lv, a2, 25, a.out)
    finally:
        lv.close()
    # 3. CPU probes (quick)
    a3 = argparse.Namespace(**vars(a))
    a3.quick = True
    a3.arg = None
    a3.variant = "default"
    n += cmd_cpu(a3)
    # 4. regression corpus
    r = subprocess.run([sys.executable, os.path.join(HERE, "test_regressions.py")], capture_output=True, text=True)
    print(r.stdout[-1500:])
    if r.returncode:
        n += 1
    print("ci mode took %.0fs" % (time.time() - t0))
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["live", "inproc", "cpu", "ci", "replay", "promote"])
    ap.add_argument("arg", nargs="?")
    ap.add_argument("--seconds", type=float, default=60)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--variant", default="default")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--batch", type=int, default=150)
    ap.add_argument("--out", default=os.path.join(HERE, "out"))
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--name", default="finding")
    ap.add_argument("--config", default="default")
    ap.add_argument("--upg", type=int, default=0)
    ap.add_argument("--note", default="")
    a = ap.parse_args()
    if a.mode == "live":
        n = cmd_live(a)
    elif a.mode == "inproc":
        n = cmd_inproc(a)
    elif a.mode == "cpu":
        n = cmd_cpu(a)
    elif a.mode == "replay":
        n = cmd_replay(a)
    elif a.mode == "promote":
        n = cmd_promote(a)
    elif a.mode == "ci":
        n = cmd_ci(a)
    else:
        raise SystemExit("not implemented yet")
    print("TOTAL FINDINGS:", n)
    sys.exit(1 if n else 0)


if __name__ == "__main__":
    main()
