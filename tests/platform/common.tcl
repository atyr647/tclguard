# Shared helpers for the platform tests. Run with the project's own Tcl:
#   tclsh8.6 windows_test.tcl      or      tclguard.exe eval windows_test.tcl
# Piped stdout is fully buffered by default; a hang would then show no output at all.
fconfigure stdout -buffering line
set root [file normalize [file join [file dirname [info script]] .. ..]]
lappend auto_path [file join $root tclguard.vfs lib]
package require tclguard
set ::tg::log::stderr 0
set ::pass 0
set ::fail 0
proc check {name cond {detail ""}} {
    if {$cond} { incr ::pass; puts "PASS $name" } else { incr ::fail; puts "FAIL $name   $detail" }
    flush stdout
}
proc finish {} {
    puts "\n$::pass passed, $::fail failed"
    exit [expr {$::fail ? 1 : 0}]
}
proc freshCfg {general} {
    set c [::tg::cfg::new]
    dict for {k v} $general { dict set c general $k $v }
    ::tg::cfg::set_ $c
    set ::tg::cfg::path [file join [expr {[info exists ::env(RUNNER_TEMP)] ? $::env(RUNNER_TEMP) : [pwd]}] tgplat.conf]
    ::tg::ban::configure
    array unset ::tg::ban::banned
}
# Real sockets: a listener plus a connected client, then look for it in the OS connection table.
proc phase {name} { puts "--- $name"; flush stdout }
proc connectionTableSees {port} {
    set srv [socket -server {apply {{c a p} { set ::peer $c }}} -myaddr 127.0.0.1 $port]
    set cl [socket 127.0.0.1 $port]
    after 300 {set ::w 1}; vwait ::w
    set rows [::tg::mon::readConnections]
    close $cl; catch {close $::peer}; close $srv
    set hit 0
    foreach r $rows { lassign $r rip lport st; if {$lport == $port && $rip eq "127.0.0.1"} { set hit 1 } }
    list $hit [llength $rows]
}
