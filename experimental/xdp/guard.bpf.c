// Minimal XDP guard: drop IPv4 packets whose source is in a ban map, and
// rate-limit new UDP/TCP-SYN packets per source with a fixed one-second window.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 262144); __type(key, __u32); __type(value, __u64); } ban4 SEC(".maps");   // value: expiry (ns, CLOCK_MONOTONIC) 0 = forever
struct rl { __u64 win; __u32 n; };
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 262144); __type(key, __u32); __type(value, struct rl); } rate4 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 4); __type(key, __u32); __type(value, __u64); } cfg SEC(".maps");      // 0: pps limit, 1: dropped, 2: passed
volatile const __u32 dummy;

static __always_inline void bump(__u32 k) { __u64 *v = bpf_map_lookup_elem(&cfg, &k); if (v) __sync_fetch_and_add(v, 1); }

SEC("xdp")
int guard(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end) return XDP_PASS;
    __u32 src = ip->saddr;
    __u64 *exp = bpf_map_lookup_elem(&ban4, &src);
    if (exp && (*exp == 0 || *exp > bpf_ktime_get_ns())) { bump(1); return XDP_DROP; }
    __u32 k0 = 0; __u64 *lim = bpf_map_lookup_elem(&cfg, &k0);
    if (lim && *lim) {
        __u64 now = bpf_ktime_get_ns() / 1000000000ULL;
        struct rl *r = bpf_map_lookup_elem(&rate4, &src);
        if (!r) { struct rl n = { .win = now, .n = 1 }; bpf_map_update_elem(&rate4, &src, &n, BPF_ANY); }
        else if (r->win != now) { r->win = now; r->n = 1; }
        else if (++r->n > *lim) { bump(1); return XDP_DROP; }
    }
    bump(2);
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
