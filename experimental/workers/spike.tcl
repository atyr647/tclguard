# EXPERIMENT: shard TclGuard's HTTP data plane across worker threads.
#   tclsh8.6 spike.tcl <workers: 0 = single thread, as today> <public port> <backend port>
# Main thread: accept, hand the socket to worker (hash of client address) with thread::transfer.
# Workers: the unmodified TclGuard tcp/http modules. Per-address counters stay thread-local
# because one address always lands on the same worker.
package require Thread
set root [file normalize [file join [file dirname [info script]] .. ..]]
lassign $argv N port bport
set init [subst -nocommands {
    foreach m {util config bans limiter tcpproxy httpproxy} { source -encoding utf-8 [file join $root tclguard.vfs lib tclguard \$m.tcl] }
    namespace eval ::tg::udp { variable total 0 }   ;# the udp module is not loaded in this experiment
    set ::tg::log::stderr 1; ::tg::log::setLevel warn
    set c [::tg::cfg::new]
    dict set c general allowlist {}
    dict set c general strikeThreshold 1000000
    ::tg::cfg::set_ \$c
    ::tg::ban::configure; ::tg::level::configure; ::tg::rate::configure
    set L [::tg::cfg::fillListener [dict create type http bind 0.0.0.0 port $port backendPort $bport reqRate 100000000 \
        connRate 100000000 maxConnsPerIP 100000 maxConns 100000 idleTimeout 0]]
    set ::tg::tcp::cfg(web) \$L
    set ::tg::tcp::nconn(web) 0
    set ::tg::tcp::maxTotal 100000
    ::tg::http::prepare web \$L
    ::tg::onTick ::tg::tcp::sweep
    ::tg::onTick ::tg::rate::gc
    ::tg::startTicks
}]
if {$N == 0} {
    eval $init
    socket -server {::tg::tcp::accept web} $port
    puts "single-thread mode on $port"
    vwait forever
}
for {set i 0} {$i < $N} {incr i} {
    set tids($i) [thread::create "$init; thread::wait"]
    thread::send $tids($i) {expr 1}          ;# wait until it is initialised
}
proc accept {chan ip port} {
    # The channel is still referenced by the accept machinery inside this callback
    # ("channel is shared"), so hand it over from the event loop instead.
    after idle [list handoff $chan $ip $port]
}
proc handoff {chan ip port} {
    global tids N
    # shard by the last two octets of the client address (IPv4 here; real code would hash the /64 key)
    set o [split $ip .]
    set h [expr {([lindex $o end] + 7 * [lindex $o end-1]) % $N}]
    thread::transfer $tids($h) $chan
    thread::send -async $tids($h) [list ::tg::tcp::accept web $chan $ip $port]
}
socket -server accept $port
puts "$N worker threads on $port"
vwait forever
