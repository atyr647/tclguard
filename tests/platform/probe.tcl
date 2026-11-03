# Tiny step-by-step probe: prints a marker before each risky operation so a hang is located exactly.
fconfigure stdout -buffering line
proc m {s} { puts "probe: $s"; flush stdout }
m "start, Tcl [info patchlevel], exe [info nameofexecutable]"
m "script [info script]"
set root [file normalize [file join [file dirname [info script]] .. ..]]
m "root $root"
lappend auto_path [file join $root tclguard.vfs lib]
m "package require tclguard"
package require tclguard
m "loaded [package present tclguard]"
m "isPrivileged"
m [::tg::fw::isPrivileged]
m "which netsh"
m [::tg::fw::which netsh]
m "netstat -ano"
set t [clock milliseconds]
catch {exec netstat -ano} out
m "netstat took [expr {[clock milliseconds]-$t}] ms, [llength [split $out \n]] lines"
m "readConnections"
set t [clock milliseconds]
m "rows [llength [::tg::mon::readConnections]] in [expr {[clock milliseconds]-$t}] ms"
m "schtasks /Query"
set t [clock milliseconds]
catch {exec schtasks /Query /TN TclGuard} out
m "schtasks took [expr {[clock milliseconds]-$t}] ms: [string range $out 0 80]"
m "done"
exit 0
