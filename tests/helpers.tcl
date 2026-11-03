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

# The install/update unit tests simulate a Unix machine with shell scripts, chmod and /bin paths; on real Windows those
# are covered by tests/platform/windows_install_test.tcl, which uses the real program, registry and Task Scheduler.
testConstraint unix [expr {$::tcl_platform(platform) eq "unix"}]   ;# (tests that fake another platform on a real Unix host)
