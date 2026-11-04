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
* the readable check polls with `select()`, and when it finds nothing clears the flag and polls once more, so data that
  arrives in between is never forgotten;
* `TcpOutputProc` keeps the original synchronous ordering in the one place it matters — when `send()` returns
  `WSAEWOULDBLOCK` (buffer full) — and skips the messages otherwise;
* after accepting a connection the listener is marked as having another request pending, so the next pass of the event
  loop tries `accept()` again immediately instead of waiting for WinSock's next `FD_ACCEPT` message (which is posted only after
  the socket thread has noticed the previous accept — one connection per thread round trip, a few hundred a second);
  with nothing waiting the extra attempt simply finds nothing and clears the flag;
* `readyEvents` (written by both threads) is updated with interlocked operations on the touched paths instead of
  plain read-modify-write.

Blocking sockets (`socket` clients used by tooling, `exec` pipes are not sockets) take the unchanged original path.
