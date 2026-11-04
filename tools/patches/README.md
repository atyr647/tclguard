# Patches applied to the runtimes

`tcl-8.6.14-winsock-nonblocking.diff` — Windows runtime only (`tools/build-tclkit.sh win64` copies it into
KitCreator's `tcl/patches/all/`). It changes `win/tclWinSock.c`, nothing else.

**Why.** Tcl 8.6's Windows socket driver is built on `WSAAsyncSelect` with a helper thread that owns the notification
window. Every `recv`, every `send` and every "is it really readable?" check does a *synchronous* `SendMessage` to that
thread (UNSELECT before, SELECT after), i.e. several thread switches per I/O. Measured on GitHub's Windows runners that
is ~1 ms per proxied request (about 1000 round trips/s against 20 000+/s for the same hardware without Tcl in the
way), and connections are refused by the OS when the listen backlog fills while the interpreter is busy with it.

**What.** For *non-blocking* sockets (every socket TclGuard uses) the messages are skipped:

* `TcpInputProc` clears `FD_READ` *before* `recv()` instead of after (WinSock re-arms the notification inside `recv()`;
  a notification for data that arrives afterwards sets the flag again, one raised for data we are about to read only
  costs one harmless extra poll);
* the "is it really readable?" check no longer unselects, calls `select()` and re-selects: a flag left over from a
  notification for data that was read in the meantime now costs one harmless extra readable event (its read finds
  nothing and clears the flag), and nothing calls `select()` on a socket that WSAAsyncSelect is still watching;
* `TcpOutputProc` keeps the original synchronous ordering in the one place it matters — when `send()` returns
  `WSAEWOULDBLOCK` (buffer full) — and skips the messages otherwise;
* **the listener takes every waiting connection (up to 16) out of the kernel's queue in one tight loop** and only then does the per-connection work. The
  original accepts one connection per `FD_ACCEPT` notification; measured on a Windows runner with one flood generator, that design's accept rate collapsed from
  about 2,700 per second to 30-70, while the same notification design draining in a loop held about 7,500 and a plain blocking `accept()` about 12,000
  (`tests/load/winsock_cost.c`, `docs/WINDOWS-ACCEPT.md`). If the accept script closes the listener, the rest of the batch is closed;
* **sockets are registered with `WSAAsyncSelect` by the calling thread itself** when a channel is created, closed, accepted or connected, instead of by a synchronous
  message to the helper thread (about 100 microseconds each, three per connection). This and the batched accept above are only effective **together**: in a raw C accept loop
  under the same flood, batching without the direct registration managed 537 accepts per second and fell to 0, direct registration without batching 28-69, both together 9,275
  (`tests/load/winsock_cost.c`, modes 1-4). The blocking-socket paths still use the original synchronous messages;
* `readyEvents` (written by both threads) is updated with interlocked operations on the touched paths instead of
  plain read-modify-write.

Blocking sockets (`socket` clients used by tooling, `exec` pipes are not sockets) take the unchanged original path.
