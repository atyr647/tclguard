# Where does Tcl's event loop spend its time on this platform?  Run with the project's own Tcl:
#   <program> eval tests/load/winbench.tcl <section> [seconds]        (tclsh8.6 tests/load/winbench.tcl works too)
# sections:
#   timers     pure 'after 0' timer events (no sockets): how fast can the event loop turn?
#   idle       the same with a self-requeuing 'after idle' callback
#   pingpong   N loopback client/server pairs in ONE interpreter bouncing a line (fileevent-driven)
#   blocking   one client and one server in two THREADS using blocking I/O only (no fileevent, no notifier)
#   threads    the fileevent ping-pong, each group of pairs in its own thread
#   accept     a listener that counts and closes (needs ACCEPT_PORT; an external flood is aimed at it)
fconfigure stdout -buffering line
set section [lindex $argv 0]
set secs [expr {[llength $argv] > 1 ? [lindex $argv 1] : 5}]
puts "winbench: Tcl [info patchlevel] on $tcl_platform(os) $tcl_platform(machine) -- $section"
after [expr {($secs + 25) * 1000}] {puts "watchdog: stuck"; exit 1}

set pairScript {
    proc run {pairs secs} {
        set ::n 0
        set ::stop 0
        proc echo {c a p} { fconfigure $c -blocking 0 -buffering line -translation lf; fileevent $c readable [list ::echoRead $c] }
        proc echoRead {c} { if {[gets $c l] < 0} { if {[eof $c]} { close $c }; return }; puts $c $l }
        set srv [socket -server echo -myaddr 127.0.0.1 0]
        set port [lindex [fconfigure $srv -sockname] 2]
        for {set i 0} {$i < $pairs} {incr i} {
            set c [socket 127.0.0.1 $port]
            fconfigure $c -blocking 0 -buffering line -translation lf
            fileevent $c readable [list ::cliRead $c]
            puts $c ping
        }
        proc cliRead {c} { if {[gets $c l] < 0} return; if {!$::stop} { incr ::n; puts $c ping } }
        after [expr {$secs * 1000}] {set ::stop 1}
        set t0 [clock milliseconds]
        vwait ::stop
        set el [expr {([clock milliseconds] - $t0) / 1000.0}]
        return [expr {$::n / $el}]
    }
}
eval $pairScript

switch -- $section {
    timers {
        set ::k 0; set ::stop 0
        proc tick2 {} { incr ::k; after 0 tick2 }
        after 0 tick2
        after [expr {$secs * 1000}] {set ::stop 1}
        vwait ::stop
        puts [format "timers    %9.0f after-0 timer events/s" [expr {$::k / double($secs)}]]
    }
    idle {
        # a callback that re-queues itself with 'after idle': on Windows this starved every timer (even the watchdog) with the
        # stock Tcl 8.6.14 runtime; it is its own section so that it cannot hide the others
        set ::k 0; set ::stop 0
        proc tick {} { incr ::k; after idle tick }
        after idle tick
        after [expr {$secs * 1000}] {set ::stop 1}
        vwait ::stop
        puts [format "idle      %9.0f after-idle events/s" [expr {$::k / double($secs)}]]
    }
    pingpong {
        foreach pairs {1 16} { puts [format "pingpong  1 interpreter, %2d pairs : %8.0f round trips/s" $pairs [run $pairs $secs]] }
    }
    blocking {
        package require Thread
        set srvScript {
            set s [socket -server {apply {{c a p} { set ::cl $c }}} -myaddr 127.0.0.1 0]
            proc port {} { global s; lindex [fconfigure $s -sockname] 2 }
            proc serve {secs} {
                vwait ::cl
                set c $::cl
                fconfigure $c -blocking 1 -buffering line -translation lf
                set end [expr {[clock milliseconds] + $secs * 1000 + 500}]
                while {[clock milliseconds] < $end} { if {[gets $c l] < 0} break; puts $c $l }
                return done
            }
        }
        set t [thread::create "$srvScript; thread::wait"]
        set port [thread::send $t port]
        thread::send -async $t [list serve $secs] ::srvdone
        set c [socket 127.0.0.1 $port]
        fconfigure $c -blocking 1 -buffering line -translation lf
        set n 0
        set end [expr {[clock milliseconds] + $secs * 1000}]
        while {[clock milliseconds] < $end} { puts $c ping; gets $c l; incr n }
        puts [format "blocking  2 threads, blocking I/O : %8.0f round trips/s" [expr {$n / double($secs)}]]
        close $c
    }
    threads {
        package require Thread
        foreach th {1 2} {
            set ids {}
            for {set i 0} {$i < $th} {incr i} {
                set t [thread::create "$pairScript; thread::wait"]
                lappend ids $t
                thread::send -async $t [list run 16 $secs] ::res($i)
            }
            for {set i 0} {$i < $th} {incr i} { vwait ::res($i) }
            set sum 0.0
            for {set i 0} {$i < $th} {incr i} { set sum [expr {$sum + $::res($i)}] }
            puts [format "threads   %d thread(s) x 16 pairs  : %8.0f round trips/s total" $th $sum]
            foreach t $ids { thread::release $t }
        }
    }
    accept {
        # ACCEPT_MODE=bare : accept, count, close (the cheapest thing a Tcl server can do with a connection)
        # ACCEPT_MODE=state: what a guard does before it can decide: per-connection state, a non-blocking channel, a read handler
        #                    and a timeout timer, then drop it (the cost of a refused/banned connection)
        set ::acc 0
        set mode [expr {[info exists ::env(ACCEPT_MODE)] ? $::env(ACCEPT_MODE) : "bare"}]
        if {$mode eq "state"} {
            proc drop {c} { catch {after cancel $::to($c)}; unset -nocomplain ::st($c) ::to($c); catch {close $c} }
            proc rd {c} { catch {read $c}; drop $c }
            proc acc {c a p} {
                incr ::acc
                set ::st($c) [list $a $p [clock milliseconds]]
                fconfigure $c -blocking 0 -buffering none -translation binary
                fileevent $c readable [list rd $c]
                set ::to($c) [after 5000 [list drop $c]]
                drop $c
            }
        } else {
            proc acc {c a p} { incr ::acc; close $c }
        }
        socket -server acc -myaddr 127.0.0.1 $::env(ACCEPT_PORT)
        puts "accept    ($mode) listening on $::env(ACCEPT_PORT) for $secs s"
        after [expr {$secs * 1000}] {set ::done 1}
        set t0 [clock milliseconds]
        vwait ::done
        puts [format "accept    (%s) %8.0f connections accepted and closed per second" $mode [expr {$::acc / (([clock milliseconds]-$t0)/1000.0)}]]
    }
    backlog {
        # does not service events: how many connections does the operating system queue for a listener nobody is accepting from?
        socket -server {apply {{c a p} {}}} -myaddr 127.0.0.1 $::env(ACCEPT_PORT)
        puts "backlog   listening on $::env(ACCEPT_PORT); not accepting for $secs s"
        after [expr {$secs * 1000}]
    }
}
exit 0
