#!/bin/bash
# Compare the single-thread data plane with 1..4 sharded worker threads.
# needs: tclsh8.6 + tcl-thread, gcc, python3.   usage: ./run_spike.sh [seconds-per-run]
cd "$(dirname "$0")"
SECS=${1:-8}
[ -x /tmp/fast_backend ] || gcc -O2 -o /tmp/fast_backend fast_backend.c
/tmp/fast_backend 28081 & BE=$!
trap 'kill $BE $P 2>/dev/null' EXIT
sleep 0.3
echo "cores: $(nproc)  (load generators and the backend share them, so numbers are a lower bound)"
for n in 0 1 2 3 4; do
  tclsh8.6 spike.tcl $n 28080 28081 >/dev/null 2>&1 & P=$!
  sleep 2.5
  printf "workers=%s  " $n
  python3 bench.py 28080 $SECS 2 8
  kill $P 2>/dev/null; wait $P 2>/dev/null; sleep 1
done
