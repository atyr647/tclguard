# One TLS call per process, so a crash in one does not hide the others.   tclsh tls_variants.tcl <variant>
fconfigure stdout -buffering line
set v [lindex $argv 0]
package require tls
puts "variant $v: tls [package present tls] / [tls::version]"
set dir [expr {[info exists ::env(RUNNER_TEMP)] ? $::env(RUNNER_TEMP) : "."}]
set pem [file join $dir tlsprobe variants.pem]
file mkdir [file dirname $pem]
if {![file exists $pem]} {
    exec openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $pem.key -out $pem.crt -days 2 -subj /CN=localhost 2>@1
    set fh [open $pem w]; foreach s {crt key} { set in [open $pem.$s]; puts -nonewline $fh [read $in]; close $in }; close $fh
}
proc cb {args} { return 1 }
switch -- $v {
    socket-server {
        set s [tls::socket -server cb -certfile $pem -keyfile $pem -myaddr 127.0.0.1 0]
        puts "ok: tls::socket -server"
    }
    socket-client {
        set s [socket -server {apply {{c a p} {close $c}}} -myaddr 127.0.0.1 0]
        set port [lindex [fconfigure $s -sockname] 2]
        set c [tls::socket -async 127.0.0.1 $port]
        puts "ok: tls::socket client (async)"
    }
    import-bare {
        set s [socket -server {apply {{c a p} {close $c}}} -myaddr 127.0.0.1 0]
        set port [lindex [fconfigure $s -sockname] 2]
        set c [socket 127.0.0.1 $port]
        tls::import $c
        puts "ok: tls::import (no options)"
    }
    import-server-blocking {
        set s [socket -server {apply {{c a p} {close $c}}} -myaddr 127.0.0.1 0]
        set port [lindex [fconfigure $s -sockname] 2]
        set c [socket 127.0.0.1 $port]
        tls::import $c -server 0 -require 0
        puts "ok: tls::import -server 0 -require 0"
    }
    import-cmd {
        set s [socket -server {apply {{c a p} {close $c}}} -myaddr 127.0.0.1 0]
        set port [lindex [fconfigure $s -sockname] 2]
        set c [socket 127.0.0.1 $port]
        tls::import $c -server 0 -require 0 -command cb
        puts "ok: tls::import with -command"
    }
}
puts "done $v"
exit 0
