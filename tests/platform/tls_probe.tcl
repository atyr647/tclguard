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
# a real TLS conversation over loopback, in the order the guard does it
set ::f $f
set ::done ""
proc probeinfo {args} { if {[lindex $args 0] eq "verify"} { return 1 } }
proc hs {who ch} {
    if {[catch {tls::handshake $ch} r]} { m "  $who handshake error: $r"; set ::done err; return }
    if {$r == 1} {
        m "  $who handshake complete"
        fileevent $ch writable {}
        if {$who eq "server"} { fileevent $ch readable [list srvread $ch] } else { puts $ch ping; flush $ch; fileevent $ch readable [list cliread $ch] }
    }
}
proc srvread {ch} {
    if {[catch {gets $ch line} n]} { m "  server read error: $n"; set ::done err; return }
    if {$n >= 0} { m "  server got: $line"; puts $ch pong; flush $ch }
}
proc cliread {ch} {
    if {[catch {gets $ch line} n]} { m "  client read error: $n"; set ::done err; return }
    if {$n >= 0} { m "  client got: $line"; set ::done ok }
}
proc accepted {ch addr port} {
    m "  accepted"
    fconfigure $ch -blocking 0 -translation binary
    m "  tls::import (server side)"
    tls::import $ch -server 1 -certfile $::f -keyfile $::f -cafile $::f -command ::probeinfo
    fileevent $ch readable [list hs server $ch]
    hs server $ch
}
m "listen on loopback"
set lsock [socket -server accepted -myaddr 127.0.0.1 0]
set port [lindex [fconfigure $lsock -sockname] 2]
m "connect to $port"
set c [socket 127.0.0.1 $port]
fconfigure $c -blocking 0 -translation binary
m "  tls::import (client side, no verification)"
tls::import $c -server 0 -require 0 -command ::probeinfo
fileevent $c writable [list hs client $c]
set t [after 8000 {set ::done timeout}]
vwait ::done
after cancel $t
m "real TLS conversation result: $::done"
catch {close $c}; catch {close $lsock}
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
