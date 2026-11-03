# XDP / eBPF spike (experimental)

`guard.bpf.c` is a ~40 line XDP program: it drops IPv4 packets whose source is in a ban
map and applies a per-source packets-per-second limit. `xdp_test.sh` builds it, attaches it
to one end of a veth pair in a network namespace, then checks (real kernel, 6.18):

| Step | Result |
|---|---|
| 20 packets, no rules | 20 received |
| source added to the ban map with `bpftool map update` | 0 of 20 received |
| ban removed, limit set to 100 pps, 3000 packets sent | 100 received, 2920 counted as dropped |

It is **not** used by TclGuard yet. See `docs/XDP.md` for the assessment and integration plan.
