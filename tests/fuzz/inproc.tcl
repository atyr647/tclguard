# inproc.tcl -- drive the real httpproxy.tcl / tcpproxy.tcl parser without sockets.
#
# A persistent worker: reads framed cases on stdin, runs each against a fresh connection id whose client
# and backend channels are Tcl reflected channels (client side yields the scheduled pieces; backend side
# captures every byte the parser emits), and writes one framed result per case on stdout.
#
# Request  (stdin):   CFG <n>\n<n bytes: tcl dict of listener overrides>
#                     CASE <flags> <npieces>\n then per piece  <len>\n<bytes>
#                         flags: end=<eof|rst|hold> upg=<0|1> (space separated, inside one word list)
#                     QUIT
# Response (stdout):  R <usec> <blen> <clen> <errlen> <leaklen> <rejlen> <ps>\n then the 5 byte blocks
#                     (backend bytes, client-side response, error text, leaks, last reject reason)

set root [file normalize [file join [file dirname [info script]] .. ..]]
# TG_VFS points the harness at another checkout's tclguard.vfs (e.g. a pristine copy, to replay old bugs)
set vfs [expr {[info exists ::env(TG_VFS)] ? $::env(TG_VFS) : [file join $root tclguard.vfs]}]
foreach m {util config bans limiter tcpproxy httpproxy} {
    source -encoding utf-8 [file join $vfs lib tclguard $m.tcl]
}
set ::tg::log::stderr 0
catch {::tg::log::setLevel alert}
set ::tg::ban::threshold 1000000000

namespace eval fk {
    variable q; variable end; variable out
    array set q {}; array set end {}; array set out {}
}
proc fk::cmd {op chan args} {
    variable q; variable end; variable out
    switch -- $op {
        initialize { set q($chan) {}; set end($chan) hold; set out($chan) ""; return {initialize finalize watch read write} }
        finalize { return }
        watch { return }
        read {
            set n [lindex $args 0]
            if {[llength $q($chan)]} {
                set d [lindex $q($chan) 0]
                if {[string length $d] > $n} {
                    set q($chan) [lreplace $q($chan) 0 0 [string range $d $n end]]
                    return [string range $d 0 [expr {$n - 1}]]
                }
                set q($chan) [lrange $q($chan) 1 end]
                return $d
            }
            switch -- $end($chan) {
                eof { return "" }
                rst { return -code error ECONNRESET }
                default { return -code error EAGAIN }
            }
        }
        write { append out($chan) [lindex $args 0]; return [string length [lindex $args 0]] }
    }
}

# record why the parser refused (the real reject is still called)
rename ::tg::http::reject ::tg::http::reject_orig
proc ::tg::http::reject {id code why strike} {
    set ::lastReject "$code $why"
    reject_orig $id $code $why $strike
}

set ::L {}
set ::lname web
proc setConfig {over} {
    set L [dict merge [::tg::cfg::listenerDefaults http] {maxConnsPerIP 100000 connRate 100000000 reqRate 100000000 maxConns 100000
        maxBodyMB 2 challenge off forwardIp 1} $over]
    set ::L $L
    set ::tg::tcp::cfg($::lname) $L
    set ::tg::tcp::nconn($::lname) 0
    ::tg::http::prepare $::lname $L
}

proc leaks {id} {
    set bad {}
    foreach ns {::tg::http ::tg::tcp} {
        foreach v [info vars ${ns}::*] {
            if {![array exists $v] || [string match *::reasons $v]} continue
            if {[array names $v $id] ne "" || [array names $v $id,*] ne ""} { lappend bad $v }
        }
    }
    if {$::tg::tcp::total != 0} { lappend bad tcp::total=$::tg::tcp::total }
    if {$::tg::tcp::nconn($::lname) != 0} { lappend bad tcp::nconn=$::tg::tcp::nconn($::lname) }
    if {[array size ::tg::tcp::perip] != 0} { lappend bad tcp::perip }
    return $bad
}

proc runCase {pieces endmode upg} {
    set ::lastReject ""
    set cc [chan create {read write} fk::cmd]
    set bc [chan create {write} fk::cmd]
    fconfigure $bc -blocking 0 -buffering none -translation binary -encoding binary
    set fk::q($cc) $pieces
    set fk::end($cc) $endmode
    set err ""
    set t0 [clock microseconds]
    if {[catch {
        ::tg::tcp::newConn $::lname $::L $cc 127.0.0.1 40000 127.0.0.1
        set id $::tg::tcp::nextId
        set ::tg::tcp::bc($id) $bc
        set ::tg::tcp::st($id) open
        set ::tg::tcp::cdl($id) 0
        set iter 0
        set max [expr {[llength $pieces] * 4 + 400}]
        while {[info exists ::tg::tcp::cc($id)]} {
            if {[incr iter] > $max} { set err "parser made no progress ($iter iterations)"; break }
            set ps $::tg::http::ps($id)
            if {$ps eq "upgwait"} {
                ::tg::http::onResponseData $id [expr {$upg ? "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n" : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"}]
                continue
            }
            set cmd [fileevent $::tg::tcp::cc($id) readable]
            if {$cmd eq ""} break
            if {![llength $fk::q($cc)] && $endmode eq "hold"} break
            uplevel #0 $cmd
        }
        if {[info exists ::tg::tcp::cc($id)] && $endmode eq "hold"} {
            # the connection stalled: let the 1 Hz sweep's deadline handler fire, twice (408 then drain end)
            ::tg::http::deadline $id
            if {[info exists ::tg::tcp::cc($id)]} { ::tg::http::deadline $id }
        }
        set ps "closed"
        if {[info exists ::tg::http::ps($id)]} { set ps $::tg::http::ps($id) }
        if {[info exists ::tg::tcp::cc($id)]} { ::tg::tcp::close_ $id "end of case" }
    } e eo]} {
        set err "$e\n[dict get $eo -errorinfo]"
        catch {::tg::tcp::close_ $::tg::tcp::nextId "error"}
        set ps error
    }
    set usec [expr {[clock microseconds] - $t0}]
    set lk [leaks $::tg::tcp::nextId]
    set b $fk::out($bc); set c $fk::out($cc)
    catch {close $cc}; catch {close $bc}
    unset fk::q($cc) fk::end($cc) fk::out($cc) fk::out($bc)
    catch {unset fk::q($bc)}; catch {unset fk::end($bc)}
    return [list $usec $b $c $err $lk $::lastReject $ps]
}

fconfigure stdin -translation binary -buffering full -encoding binary
fconfigure stdout -translation binary -buffering full -encoding binary
proc blk {s} { string length $s }
while {[gets stdin line] >= 0} {
    set cmd [lindex $line 0]
    switch -- $cmd {
        CFG {
            set n [lindex $line 1]
            setConfig [encoding convertfrom utf-8 [read stdin $n]]
        }
        CASE {
            set flags [lindex $line 1]; set np [lindex $line 2]
            set pieces {}
            for {set i 0} {$i < $np} {incr i} {
                gets stdin l
                lappend pieces [read stdin $l]
            }
            set endmode hold; set upg 0
            foreach f $flags { lassign [split $f =] k v; if {$k eq "end"} { set endmode $v } elseif {$k eq "upg"} { set upg $v } }
            lassign [runCase $pieces $endmode $upg] usec b c err lk rej ps
            set err [encoding convertto utf-8 $err]
            set lk [encoding convertto utf-8 $lk]
            set rej [encoding convertto utf-8 $rej]
            puts -nonewline stdout "R $usec [string length $b] [string length $c] [string length $err] [string length $lk] [string length $rej] $ps\n$b$c$err$lk$rej"
        }
        SYNC { flush stdout }
        QUIT { exit 0 }
    }
}
