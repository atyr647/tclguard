# control.tcl -- local management socket and its client.
#
# Line protocol (the token itself never crosses the connection; a challenge-response proves that BOTH ends know it, so a
# process that squatted on the port cannot harvest the token from `tclguard ctl`, and a client cannot be fooled into talking to it):
#   client:  HELLO <client-nonce>
#   server:  CHALLENGE <server-nonce> <HMAC-SHA256(token, "S:" cnonce ":" snonce)>        (the client checks this)
#   client:  PROOF <HMAC-SHA256(token, "C:" cnonce ":" snonce)>     then   <verb> [args...]
#   server:  OK msg authenticated     then     OK msg <text> | OK data <tcl value> | ERR <message>
# Listens on 127.0.0.1 only by default. The token lives in the config file (mode 0600) and is compared in constant time.
# Limits: a line may not exceed 8 KB (checked while reading, not after), unauthenticated connections live 5 s, authenticated ones
# are dropped after 2 minutes without a command, and when all slots are taken the oldest unauthenticated connection makes room.

namespace eval ::tg::control {
    variable srv ""
    variable started {}      ;# {enable host port token} the listener was started with
    variable authed          ;# chan -> 1
    array set authed {}
    variable fails           ;# chan -> failed attempts (also: the set of open control connections)
    array set fails {}
    variable rbuf            ;# chan -> bytes received, not yet a full line
    array set rbuf {}
    variable born            ;# chan -> ms when accepted
    array set born {}
    variable lastAct         ;# chan -> ms of the last line received
    array set lastAct {}
    variable nonces          ;# chan -> {client-nonce server-nonce} after HELLO
    array set nonces {}
    variable sweeping 0
    variable maxConns 16
    variable maxLine 8192
    variable unauthSec 5
    variable idleSec 120
}

proc ::tg::control::start {} {
    variable srv
    variable started
    set started [settings]
    if {![::tg::bool [::tg::cfg::general controlEnable]]} return
    if {[catch {::tg::cfg::ensureToken} created]} {
        ::tg::log::alert "control socket disabled: cannot create a control token ($created)"
        return
    }
    if {$created} {
        catch { ::tg::cfg::save }
    }
    set host [::tg::cfg::general controlHost]
    set port [::tg::cfg::general controlPort]
    if {[catch {socket -server ::tg::control::accept -myaddr $host $port} s err]} {
        ::tg::log::alert "control socket unavailable on [::tg::joinHostPort $host $port]: $s (is another TclGuard running? Anything else holding that port could be listening in its place; `tclguard ctl` will refuse to talk to a listener that cannot prove it knows the token)"
        return
    }
    set srv $s
    if {$host ni {127.0.0.1 ::1 localhost}} {
        ::tg::log::warn "control socket is reachable from the network ($host); protect the token and firewall port $port"
    }
}

proc ::tg::control::stop {} {
    variable srv
    variable fails
    if {$srv ne ""} { catch {close $srv}; set srv "" }
    foreach c [array names fails] { drop $c }
}

proc ::tg::control::settings {} {
    list [::tg::bool [::tg::cfg::general controlEnable]] [::tg::cfg::general controlHost] [::tg::cfg::general controlPort] [::tg::cfg::general controlToken]
}

# Apply changed control settings after a configuration reload (enable, host, port, token): restart the listener and drop every
# session that was opened with the old settings. Deferred a moment so the reply to the command that caused the reload still gets out.
proc ::tg::control::sync {} {
    variable started
    if {[settings] ne $started} { after 300 ::tg::control::restart }
}

proc ::tg::control::restart {} {
    stop
    start
}

proc ::tg::control::accept {chan ip port} {
    variable fails
    variable born
    variable lastAct
    variable maxConns
    if {[array size fails] >= $maxConns} {
        # room for a real client: the oldest connection that has not authenticated goes
        set oldest ""; set t [clock milliseconds]
        foreach c [array names fails] {
            if {![info exists ::tg::control::authed($c)] && $born($c) <= $t} { set oldest $c; set t $born($c) }
        }
        if {$oldest eq ""} { catch {close $chan}; return }
        drop $oldest
    }
    fconfigure $chan -blocking 0 -buffering line -translation lf -encoding utf-8
    set fails($chan) 0
    set born($chan) [clock milliseconds]
    set lastAct($chan) $born($chan)
    set ::tg::control::rbuf($chan) ""
    fileevent $chan readable [list ::tg::control::readable $chan]
    startSweeper
}

proc ::tg::control::startSweeper {} {
    variable sweeping
    if {!$sweeping} { set sweeping 1; after 1000 ::tg::control::sweep }
}

proc ::tg::control::sweep {} {
    variable fails
    variable authed
    variable born
    variable lastAct
    variable sweeping
    variable unauthSec
    variable idleSec
    set now [clock milliseconds]
    foreach c [array names fails] {
        if {![info exists authed($c)]} {
            if {$now - $born($c) > $unauthSec * 1000} { drop $c }
        } elseif {$now - $lastAct($c) > $idleSec * 1000} {
            drop $c
        }
    }
    if {[array size fails] > 0} { after 1000 ::tg::control::sweep } else { set sweeping 0 }
}

proc ::tg::control::drop {chan} {
    variable authed
    variable fails
    variable rbuf
    variable born
    variable lastAct
    variable nonces
    catch {fileevent $chan readable {}}
    catch {close $chan}
    unset -nocomplain authed($chan) fails($chan) rbuf($chan) born($chan) lastAct($chan) nonces($chan)
}

proc ::tg::control::constEq {a b} {
    if {[string length $a] != [string length $b]} { return 0 }
    set d 0
    foreach x [split $a ""] y [split $b ""] { set d [expr {$d | ([scan $x %c] ^ [scan $y %c])}] }
    expr {$d == 0}
}

proc ::tg::control::proof {token who cn sn} {
    binary encode hex [::tg::crypto::hmac $token "$who:$cn:$sn"]
}

proc ::tg::control::reply {chan ok text {kind msg}} {
    set text [string map [list \n { } \r { }] $text]
    if {$ok} {
        catch { puts $chan "OK $kind $text" }
    } else {
        catch { puts $chan "ERR $text" }
    }
}

proc ::tg::control::readable {chan} {
    variable rbuf
    variable fails
    variable maxLine
    if {![info exists fails($chan)]} { catch {close $chan}; return }
    # read in small pieces and judge the size BEFORE waiting for a newline: `gets` on a line that never ends would buffer and rescan
    # without limit
    if {[catch {read $chan 4096} data]} { drop $chan; return }
    if {$data eq ""} {
        if {[catch {eof $chan} e] || $e} { drop $chan }
        return
    }
    append rbuf($chan) $data
    while {[info exists rbuf($chan)] && [set i [string first \n $rbuf($chan)]] >= 0} {
        set line [string range $rbuf($chan) 0 [expr {$i - 1}]]
        set rbuf($chan) [string range $rbuf($chan) [expr {$i + 1}] end]
        if {[string length $line] > $maxLine} { drop $chan; return }
        handleLine $chan $line
    }
    if {[info exists rbuf($chan)] && [string length $rbuf($chan)] > $maxLine} { drop $chan }
}

proc ::tg::control::handleLine {chan line} {
    variable authed
    variable fails
    variable nonces
    variable lastAct
    set lastAct($chan) [clock milliseconds]
    set line [string trim $line]
    if {$line eq ""} return
    if {![info exists authed($chan)]} {
        set tok [::tg::cfg::general controlToken]
        if {$tok ne "" && [regexp {^HELLO ([0-9a-f]{16,64})$} $line -> cn]} {
            set sn [::tg::randomHex 16]
            set nonces($chan) [list $cn $sn]
            catch { puts $chan "CHALLENGE $sn [proof $tok S $cn $sn]" }
            return
        }
        if {$tok ne "" && [info exists nonces($chan)] && [regexp {^PROOF ([0-9a-f]{64})$} $line -> p]} {
            lassign $nonces($chan) cn sn
            unset nonces($chan)
            if {[constEq $p [proof $tok C $cn $sn]]} {
                set authed($chan) 1
                reply $chan 1 "authenticated"
                return
            }
        }
        incr fails($chan)
        reply $chan 0 "authentication failed"
        if {$fails($chan) >= 3} { drop $chan }
        return
    }
    set words [split $line]
    if {[catch {::tg::engine::cmd {*}$words} result]} {
        reply $chan 0 $result
    } else {
        # queries return structured data, actions return a sentence
        set kind [expr {[lindex $words 0] in {status bans top log listeners debug tls} || [lrange $words 0 1] eq {fw status} ? "data" : "msg"}]
        reply $chan 1 $result $kind
    }
}

# ---- client (used by `tclguard ctl ...`) ----

# One line from the server with a deadline (ms); returns {1 line} or {0 reason}.
proc ::tg::control::readLine {chan ms} {
    set end [expr {[clock milliseconds] + $ms}]
    while {1} {
        if {[gets $chan line] >= 0} { return [list 1 $line] }
        if {[eof $chan]} { return [list 0 "connection closed"] }
        set left [expr {$end - [clock milliseconds]}]
        if {$left <= 0} { return [list 0 "no answer in time"] }
        set ::tg::control::_rd 0
        fileevent $chan readable {set ::tg::control::_rd 1}
        set t [after $left {set ::tg::control::_rd 2}]
        vwait ::tg::control::_rd
        after cancel $t
        fileevent $chan readable {}
    }
}

# Round trip with a hard timeout. Returns {ok kind text}.
proc ::tg::control::request {host port token verb args} {
    foreach w [concat [list $verb] $args] {
        # an argument with a line break would become a second protocol line, i.e. a second command
        if {[regexp {[\x00-\x1f\x7f]} $w]} { return [list 0 msg "control characters (such as line breaks) are not allowed in command arguments"] }
    }
    if {[catch {::tg::randomHex 12} cn]} { return [list 0 msg "cannot create a nonce: $cn"] }
    if {[catch {socket $host $port} chan]} { return [list 0 msg "cannot connect to TclGuard on [::tg::joinHostPort $host $port]: $chan (is it running?)"] }
    fconfigure $chan -blocking 0 -buffering line -translation lf -encoding utf-8
    try {
        puts $chan "HELLO $cn"
        flush $chan
        lassign [readLine $chan 5000] ok line
        if {!$ok} { return [list 0 msg "no answer from TclGuard ($line)"] }
        if {![regexp {^CHALLENGE ([0-9a-f]{16,64}) ([0-9a-f]{64})$} $line -> sn sp]} {
            if {[string match "ERR *" $line]} { return [list 0 msg "the control port refused the request: [string range $line 4 end] (is controlToken set?)"] }
            return [list 0 msg "unexpected answer: that is not a TclGuard control port"]
        }
        if {![constEq $sp [proof $token S $cn $sn]]} {
            return [list 0 msg "the listener on [::tg::joinHostPort $host $port] did not prove that it knows the token: wrong token (check controlToken in the config file), or something other than TclGuard is listening there"]
        }
        puts $chan "PROOF [proof $token C $cn $sn]"
        puts $chan [join [concat [list $verb] $args] " "]
        flush $chan
        lassign [readLine $chan 5000] ok authLine
        if {!$ok} { return [list 0 msg "no answer from TclGuard ($authLine)"] }
        if {![string match "OK *" $authLine]} { return [list 0 msg "authentication failed (wrong token? check controlToken in the config file)"] }
        lassign [readLine $chan 5000] ok resLine
        if {!$ok} { return [list 0 msg "no answer from TclGuard ($resLine)"] }
        if {[regexp {^OK (msg|data) ?(.*)$} $resLine -> kind payload]} { return [list 1 $kind $payload] }
        if {[regexp {^ERR ?(.*)$} $resLine -> err]} { return [list 0 msg $err] }
        return [list 0 msg "unexpected reply: $resLine"]
    } finally {
        catch {close $chan}
    }
}
