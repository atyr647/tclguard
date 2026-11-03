//go:build !linux

package main

import (
	"fmt"
	"os"
	"time"
)

func runSynFlood(addr string, pps int, dur time.Duration, srcbase string, srcn int) {
	fmt.Fprintln(os.Stderr, "synflood needs Linux raw sockets")
	os.Exit(2)
}
