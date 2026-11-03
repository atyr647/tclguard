#!/bin/bash
# EXPERIMENTAL spike, not wired into TclGuard. Proves that an XDP ban map + per-source
# rate limit works on a real kernel. Needs root, clang, libbpf-dev, bpftool, iproute2.
#   BPFTOOL=/path/to/bpftool bash xdp_test.sh
set -e
BPFTOOL=${BPFTOOL:-bpftool}
cd "$(dirname "$0")"
[ -f guard.bpf.o ] || clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c guard.bpf.c -o guard.bpf.o
cleanup(){ ip netns del xg 2>/dev/null || true; ip netns del xc 2>/dev/null || true; rm -rf /sys/fs/bpf/tg 2>/dev/null || true; }
cleanup; trap cleanup EXIT
ip netns add xg; ip netns add xc
ip link add vg type veth peer name vc
ip link set vg netns xg; ip link set vc netns xc
ip netns exec xg sh -c 'ip addr add 10.98.0.1/24 dev vg; ip link set vg up; ip link set lo up'
ip netns exec xc sh -c 'ip addr add 10.98.0.2/24 dev vc; ip link set vc up; ip link set lo up'
mount | grep -q "/sys/fs/bpf" || mount -t bpf bpf /sys/fs/bpf
# load program + pin maps, attach in the guard namespace (generic mode: works on any NIC, incl. veth)
nsenter --net=/var/run/netns/xg $BPFTOOL prog loadall guard.bpf.o /sys/fs/bpf/tg type xdp pinmaps /sys/fs/bpf/tg 2>&1 | head -5
ls /sys/fs/bpf/tg
nsenter --net=/var/run/netns/xg $BPFTOOL net attach xdpgeneric pinned /sys/fs/bpf/tg/guard dev vg 2>&1 | head
ip netns exec xg ip link show vg | grep -o "xdp[a-z]*.*" | head -2
# udp sink counting packets
ip netns exec xg python3 -c "
import socket,time,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',9000)); s.settimeout(0.3); n=0; t=time.time()+float(sys.argv[1])
while time.time()<t:
    try: s.recvfrom(100); n+=1
    except socket.timeout: pass
print(n)" 3 > /tmp/xdp_recv1.txt &
sleep 0.5
ip netns exec xc python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(20): s.sendto(b'hello',('10.98.0.1',9000))"
wait
echo "1) no rules, 20 packets sent -> received: $(cat /tmp/xdp_recv1.txt)"
# 2) ban 10.98.0.2 via map update (key = 4 bytes network order: 10 98 0 2), value = 0 (forever)
nsenter --net=/var/run/netns/xg $BPFTOOL map update pinned /sys/fs/bpf/tg/ban4 key 10 98 0 2 value 0 0 0 0 0 0 0 0
ip netns exec xg python3 -c "
import socket,time,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',9000)); s.settimeout(0.3); n=0; t=time.time()+2
while time.time()<t:
    try: s.recvfrom(100); n+=1
    except socket.timeout: pass
print(n)" > /tmp/xdp_recv2.txt &
sleep 0.5
ip netns exec xc python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(20): s.sendto(b'hello',('10.98.0.1',9000))"
wait
echo "2) banned in XDP map, 20 sent -> received: $(cat /tmp/xdp_recv2.txt)"
nsenter --net=/var/run/netns/xg $BPFTOOL map dump pinned /sys/fs/bpf/tg/cfg 2>&1 | grep -E "value|key" | head -6
# 3) unban + per-source rate limit 100 pps; flood 3000 packets
nsenter --net=/var/run/netns/xg $BPFTOOL map delete pinned /sys/fs/bpf/tg/ban4 key 10 98 0 2
nsenter --net=/var/run/netns/xg $BPFTOOL map update pinned /sys/fs/bpf/tg/cfg key 0 0 0 0 value 100 0 0 0 0 0 0 0
ip netns exec xg python3 -c "
import socket,time,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',9000)); s.settimeout(0.5); n=0; t=time.time()+4
while time.time()<t:
    try: s.recvfrom(100); n+=1
    except socket.timeout: pass
print(n)" > /tmp/xdp_recv3.txt &
sleep 0.5
ip netns exec xc python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(3000): s.sendto(b'x'*64,('10.98.0.1',9000))"
wait
echo "3) rate limit 100 pps/source, 3000 sent in <1s -> received: $(cat /tmp/xdp_recv3.txt)"
nsenter --net=/var/run/netns/xg $BPFTOOL map dump pinned /sys/fs/bpf/tg/cfg 2>&1 | tr '\n' ' ' | cut -c1-300; echo
