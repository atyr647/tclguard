# XDP / eBPF filtering: assessment

**Verdict: worth building as an optional third layer, after the worker-process work, not before. nftables already covers what a home connection can deliver; XDP matters when the link is faster than the kernel's normal path can drop.**

## What was verified (on this build machine)

`experimental/xdp/` contains a working program and test. On a real 6.18 kernel, generic-mode XDP attached to a veth interface:
ban-map drops work, bans can be added and removed from user space with `bpftool map update/delete`, and a per-source packets-per-second limit works (3000 packets sent, 100 passed at a 100 pps limit). Counters in a BPF array map match.

## What was *not* measured

There is no packet generator in the sandbox (`CONFIG_NET_PKTGEN` is off), and a Python sender cannot saturate either filter, so **no throughput comparison was made**. Any "XDP is N times faster" figure for this project would be invented, so none is claimed. Published kernel numbers put XDP drop (native mode) at an order of magnitude above iptables/nftables per core; that should be verified on real hardware before relying on it.

## Where it helps, where it doesn't

* **Helps:** a 10 Gbit/s+ link or a VPS with a fast NIC and a flood of small packets. XDP runs before the kernel allocates an `skb`, so dropping a packet is far cheaper than any netfilter hook.
* **Does not help:** a home line. 1 Gbit/s of 64-byte packets is ~1.5 Mpps, which the existing nftables `prerouting` raw-priority drop (already before conntrack) handles. And as the README says, a flood that saturates your *uplink* is dropped upstream of any software.
* **Generic vs native mode:** generic XDP (what the test used, works on any NIC) runs after `skb` allocation, so it is *not* dramatically cheaper than nftables. The big gain needs **native** driver support, which many consumer NICs, Wi-Fi and virtual NICs lack.

## What it would take to ship

1. Precompiled CO-RE object shipped inside the starpack (no clang on user machines).
2. A loader. Tcl has no `bpf()` syscall, so either shell out to `bpftool` (`bpftool batch` for bulk updates; not installed by default and not in the starpack) or ship a tiny static helper binary. This is the main departure from the "pure Tcl, single file" model, which is why it must stay **optional**.
3. IPv6: an LPM-trie map keyed by `/64` to match TclGuard's per-/64 keys.
4. Same ban semantics as nftables (timeouts via map-stored expiry, which the spike already does) and the same allowlist bypass.
5. Fall back to nftables whenever XDP is unavailable (no root, no native driver, old kernel, another XDP program already attached to the interface).

## Recommended order

1. Worker processes for the user-space data plane (see the architecture note in the project discussion).
2. XDP as an opt-in backend `firewall xdp` behind the same `fw::` interface, with the nftables rules kept as the always-on baseline.
3. Measure on real hardware (pktgen / `trafgen`) before documenting any speed-up.
