# Worker-thread data plane: spike results

**Status: experimental, not part of the product. The design works, but measured scaling (1.5x on 3 cores, unconfounded rig) does not justify shipping it. See the second measurement and the verdict.**

## The idea
Keep the control plane (config, bans, threat level, GUI, control socket, kernel firewall) in the main interpreter. Run the data plane (the existing `tcp`/`http` modules, unmodified) in N worker threads. The main thread accepts, then hands each socket to a worker chosen by a hash of the client address, so one address always lands on the same worker and per-address counters need no locking.

## What the spike (`experimental/workers/`) proves
* The unmodified TclGuard HTTP/TCP modules run correctly inside worker threads and serve real traffic.
* Accepted sockets can be handed to workers. Two gotchas found: `thread::transfer` / `thread::detach` fail with *"channel is shared"* if called **inside** the accept callback, so the hand-off must be deferred with `after idle`; and `thread::transfer` is synchronous, so the worker's event loop must already be running.

## Measurements (4-core sandbox VM; backend = small C epoll server)

| Workers | Requests/s (keep-alive, 16 client addresses) |
|---|---|
| 0 (single thread, as shipped) | 5,591 |
| 1 | 5,816 |
| 2 | 6,087 |
| 3 | 8,275 |
| 4 | 8,293 |

CPU accounting during the 4-worker run: proxy ~300% of 400%, two Python load generators ~200%, backend ~16%. **The machine was oversubscribed**, so the rig, not the proxy, was the limit; per-core efficiency fell from ~56 to ~26 req/s per CPU-% as the cores filled up, which is what oversubscription (context switching) looks like, but a real lock/allocator contention cost cannot be ruled out with this data.

## Second measurement: an unconfounded rig (decides it)

The first run was confounded (Python load generators sharing the cores). It was repeated with `run_scaling.sh`: the proxy (main thread plus workers) pinned to cores 0-2, the C backend and the Go load generator (`tests/load/tgload`) pinned to core 3. The rig itself does 20,249 requests/s straight to the backend, so it is not the limit. 64 keep-alive connections from 16 client addresses, 10 s per run:

| Workers | Requests/s | p50 | p99 | Speed-up |
|---|---|---|---|---|
| 0 (single thread, as shipped) | 5,916 | 8.9 ms | 16.5 ms | 1.00x |
| 1 | 6,552 | 8.2 ms | 15.9 ms | 1.11x |
| 2 | 7,525 | 6.8 ms | 13.2 ms | 1.27x |
| 3 | 9,054 | 5.6 ms | 12.3 ms | 1.53x |

Three cores give 1.53x, i.e. about half the efficiency per core. The criterion set beforehand (at least 2.5x on 4 cores) is not met, and the shortfall is not the rig.

## Verdict: not shipped
* **Measured benefit is small**: about +50% requests/s for three cores' worth of CPU, on a workload (keep-alive, spread over many addresses) that is close to the best case for sharding. One-shot connections would pay the socket hand-off on the main thread as well.
* **The ceiling that matters at home is elsewhere**: one core already serves ~6,000 requests/s (see `docs/LOAD.md`), which is more than a home connection carries in real pages (a 20 KB page at 5,000 per second is 800 Mbit/s), and Tcl 8.6 waits for events with `select()`, so a *process* can never watch more than about 1,000 descriptors (about 450 proxied connections) however many threads it has. Threads share that ceiling; only more processes would lift it.
* **The cost is real**: bans, strikes, trust, rate state, threat level, config reloads, unban/allowlist commands and the control socket would all have to be kept consistent across threads, and every integration suite would need to run in both modes.

If someone needs more than this on one machine, the practical answer today is to run two or more TclGuard instances on different listeners (each has its own cap and its own core) or to put the kernel firewall (nftables) in front, which drops flood traffic without involving Tcl at all.

## Still unsolved if this is pursued
* Ban/strike/level propagation between workers (design: main thread owns the authoritative state and broadcasts; a few ms of lag).
* UDP: needs one socket per worker on the same port (`SO_REUSEPORT`, not confirmed exposed by tcludp) or a dispatcher thread.
* The single accept thread caps new-connection rate (~10k/s measured), unchanged by workers.
* The shipped tclkits already contain `Thread`, so packaging is not an obstacle.
