# Shared helpers for TclGuard tests.
package require tcltest
namespace import ::tcltest::*
set ::root [file normalize [file join [file dirname [info script]] ..]]
lappend auto_path [file join $::root tclguard.vfs lib]
proc loadmods {args} {
    foreach m $args { uplevel #0 [list source [file join $::root tclguard.vfs lib tclguard $m.tcl]] }
}

# Deterministic time for tests: now = fixed base + clockSkew (advance by bumping skew).
proc freezeClock {} {
    set ::tg::fakeBase 1700000000000
    proc ::tg::now {} { expr {$::tg::fakeBase + $::tg::clockSkew} }
}
