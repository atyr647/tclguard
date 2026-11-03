#!/bin/bash
# The flood test over a REAL kernel network path (Linux, root): the guard lives in one network namespace and every visitor and
# attacker in another, joined by a veth pair. Source addresses are real, distinct 10.77.x.y addresses (not loopback aliases),
# the kernel firewall can be switched on (--fw bans|harden) and a spoofed SYN flood can be added (--syn).
#
#   sudo TG_CMD=releases/tclguard-linux-x86_64 tests/load/run_flood_netns.sh [--fw none|bans|harden] [--syn] [--quick] [--label NAME]
#
# Everything stays inside the two namespaces; they are removed again afterwards. Needs: ip (iproute2), nft for --fw, a built
# tests/load/tgload-bin (cd tests/load/tgload && go build -o ../tgload-bin .).
set -euo pipefail
cd "$(dirname "$0")/../.."
G=tg-guard; A=tg-atk
cleanup() { ip netns del "$G" 2>/dev/null || true; ip netns del "$A" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
ip netns add "$G"; ip netns add "$A"
ip link add tgv-g type veth peer name tgv-a
ip link set tgv-g netns "$G"; ip link set tgv-a netns "$A"
ip -n "$G" addr add 10.77.0.1/16 dev tgv-g; ip -n "$G" link set tgv-g up; ip -n "$G" link set lo up
ip -n "$A" addr add 10.77.0.2/16 dev tgv-a; ip -n "$A" link set tgv-a up; ip -n "$A" link set lo up
# one address per simulated visitor/attacker (127.0.N.M in the loopback run becomes 10.77.N.M): about 2,300 aliases, added in one batch
python3 - > /tmp/tg-aliases.batch <<'PY'
for n in range(1, 10):
    for m in range(0, 256):
        print(f"addr add 10.77.{n}.{m}/32 dev tgv-a")
PY
ip -n "$A" -batch /tmp/tg-aliases.batch
rm -f /tmp/tg-aliases.batch
ip netns exec "$A" bash -c "exec 3<>/dev/tcp/10.77.0.1/9 2>/dev/null; true"; ip -n "$A" route get 10.77.0.1 >/dev/null && echo "namespaces joined: attacker 10.77.0.2 -> guard 10.77.0.1"
ip netns exec "$G" python3 tests/load/run_flood.py --target 10.77.0.1 --atk-ns "$A" --src-prefix 10.77 "$@"
