#!/bin/bash
# Worker-thread scaling with an UNCONFOUNDED rig: the proxy (main thread + workers) is pinned to cores 0-2, the backend and
# the Go load generator share core 3. Needs 4+ cores, taskset, gcc, a built tests/load/tgload-bin (see tests/load/README or
# `cd tests/load/tgload && go build -o ../tgload-bin .`). Usage: ./run_scaling.sh
cd "$(dirname "$0")"
[ -x /tmp/fast_backend ] || gcc -O2 -o /tmp/fast_backend fast_backend.c
taskset -c 3 /tmp/fast_backend 28081 > /dev/null 2>&1 & BE=$!
sleep 0.5
for n in 0 1 2 3; do
  taskset -c 0-2 tclsh8.6 spike.tcl $n 28080 28081 > /dev/null 2>&1 & P=$!
  sleep 2.5
  printf "workers=%s  " $n
  taskset -c 3 ../../tests/load/tgload-bin http -url http://127.0.0.1:28080/ -conns 64 -dur 10s -srcbase 127.0.1.0 -srcn 16 2>/dev/null | python3 -c "
import sys,json
r=json.loads(sys.stdin.read().strip().splitlines()[-1]); print('ok_rps',r['ok_rps'],'p50',round(r['p50_ms'],1),'p99',round(r['p99_ms'],1),r['counts'])"
  kill $P 2>/dev/null; wait $P 2>/dev/null; sleep 1
done
kill $BE
