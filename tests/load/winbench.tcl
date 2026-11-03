# Where does Tcl's event loop spend its time on this platform?  Run with the project's own Tcl:
#   <program> eval tests/load/winbench.tcl [seconds]          (tclsh8.6 tests/load/winbench.tcl works too)
#
#   pingpong   N loopback client/server pairs in ONE interpreter bouncing a line: round trips per second = how many socket
#              events the notifier can deliver. (Every proxied request costs several of these.)
#   threads    the same, with each pair in its own thread: does throughput scale with threads on this platform?
#   accept     a listener that only counts and closes: accepts per second against an external connection flood
#              (the harness starts `tgload connflood` against port ACCEPT_PORT while this runs)
fconfigure stdout -buffering line
package require Thread
set secs [expr {[llength $argv] ? [lindex $argv 0] : 6}]
puts "winbench: Tcl [info patchlevel] on $tcl_platform(os) $tcl_platform(machine)"

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

proc pingpong {pairs secs} { run $pairs $secs }

foreach pairs {1 16} {
    puts [format "pingpong  1 interpreter, %2d pairs : %8.0f round trips/s" $pairs [pingpong $pairs $secs]]
}
foreach th {1 2 4} {
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

if {[info exists ::env(ACCEPT_PORT)]} {
    set ::acc 0
    proc acc {c a p} { incr ::acc; close $c }
    socket -server acc -myaddr 127.0.0.1 $::env(ACCEPT_PORT)
    puts "accept    listening on $::env(ACCEPT_PORT) for [expr {$secs*2}] s"
    after [expr {$secs * 2000}] {set ::done 1}
    set t0 [clock milliseconds]
    vwait ::done
    puts [format "accept    %8.0f connections accepted and closed per second" [expr {$::acc / (([clock milliseconds]-$t0)/1000.0)}]]
}
exit 0
