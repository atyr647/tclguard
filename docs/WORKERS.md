# Worker-thread data plane: spike results

**Status: experimental, not part of the product. The design works; whether it scales well enough to justify shipping is not yet established.**

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

## Verdict
The pass criterion set beforehand (at least 2.5x on 4 cores) **could not be evaluated here**: the achieved 1.5x is confounded by the test rig. To decide, rerun `experimental/workers/run_spike.sh` with the load generator on another machine (or on a host with at least 8 cores). Not done, so no scaling claim is made.

## Still unsolved if this is pursued
* Ban/strike/level propagation between workers (design: main thread owns the authoritative state and broadcasts; a few ms of lag).
* UDP: needs one socket per worker on the same port (`SO_REUSEPORT`, not confirmed exposed by tcludp) or a dispatcher thread.
* The single accept thread caps new-connection rate (~10k/s measured), unchanged by workers.
* The shipped tclkits already contain `Thread`, so packaging is not an obstacle.
