# Step-by-step TLS probe: shows exactly where TLS setup stops on a platform (crash, hang or error).
#   tclsh tests/platform/tls_probe.tcl      or      tclguard eval tests/platform/tls_probe.tcl
fconfigure stdout -buffering line
proc m {s} { puts "probe: $s"; flush stdout }
set root [file normalize [file join [file dirname [info script]] .. ..]]
lappend auto_path [file join $root tclguard.vfs lib]
m "Tcl [info patchlevel] on $tcl_platform(os) $tcl_platform(machine)"
m "package require tclguard"; package require tclguard
m "tls available: [::tg::tls::available]"
m "tls version: [tls::version]"
set dir [file join [expr {[info exists ::env(RUNNER_TEMP)] ? $::env(RUNNER_TEMP) : [pwd]}] tlsprobe]
file mkdir $dir
m "random bytes"; set b [::tg::crypto::randomBytes 16]; m "  [string length $b] bytes"
m "new key"; set k [::tg::crypto::newKey]
m "self-signed cert"; set pem [::tg::crypto::selfSigned $k {localhost 127.0.0.1}]
set f [file join $dir probe.pem]
m "write $f"; set fh [open $f w]; puts -nonewline $fh $pem[::tg::crypto::keyToPem $k]; close $fh
m "certInfo"; m "  [::tg::crypto::certInfo $pem]"
set null [expr {$tcl_platform(platform) eq "windows" ? "NUL" : "/dev/null"}]
m "open $null"; set ch [open $null r+]
m "tls::import (no cafile)"
if {[catch {tls::import $ch -server 1 -certfile $f -keyfile $f} e]} { m "  error: $e" } else { m "  ok" }
catch {close $ch}
m "open $null again"; set ch [open $null r+]
m "tls::import (-cafile, the way the guard does it)"
if {[catch {tls::import $ch {*}[::tg::tls::importOpts {tlsMinVersion 1.2} $f $f]} e]} { m "  error: $e" } else { m "  ok" }
catch {close $ch}
m "testLoad (what listener start does)"
if {[catch {::tg::tls::testLoad {tlsMinVersion 1.2} $f $f} e]} { m "  error: $e" } else { m "  ok" }
m "done"
exit 0
