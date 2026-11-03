# control.tcl -- local management socket and its client.
#
# Line protocol:   AUTH <token>   then   <verb> [args...]
# Replies:         OK msg <text> | OK data <tcl value> | ERR <message>
# Listens on 127.0.0.1 only by default. The token lives in the config file
# (mode 0600) and is compared in constant time.

namespace eval ::tg::control {
    variable srv ""
    variable authed          ;# chan -> 1
    array set authed {}
    variable fails           ;# chan -> failed attempts
    array set fails {}
}

proc ::tg::control::start {} {
    variable srv
    if {![::tg::bool [::tg::cfg::general controlEnable]]} return
    if {[::tg::cfg::ensureToken]} {
        catch { ::tg::cfg::save }
    }
    set host [::tg::cfg::general controlHost]
    set port [::tg::cfg::general controlPort]
    if {[catch {socket -server ::tg::control::accept -myaddr $host $port} s err]} {
        ::tg::log::warn "control socket unavailable on [::tg::joinHostPort $host $port]: $s (is another TclGuard running?)"
        return
    }
    set srv $s
    if {$host ni {127.0.0.1 ::1 localhost}} {
        ::tg::log::warn "control socket is reachable from the network ($host); protect the token and firewall port $port"
    }
}

proc ::tg::control::stop {} {
    variable srv
    variable authed
    if {$srv ne ""} { catch {close $srv}; set srv "" }
    foreach c [array names authed] { catch {close $c} }
    array unset authed
}

proc ::tg::control::accept {chan ip port} {
    variable authed
    variable fails
    if {[array size fails] >= 8} { catch {close $chan}; return }   ;# local tool: a few sessions at most
    fconfigure $chan -blocking 0 -buffering line -translation lf -encoding utf-8
    set fails($chan) 0
    fileevent $chan readable [list ::tg::control::readable $chan]
    # an unauthenticated connection may not linger
    after 10000 [list ::tg::control::expire $chan]
}

proc ::tg::control::expire {chan} {
    variable authed
    variable fails
    if {[info exists fails($chan)] && ![info exists authed($chan)]} { drop $chan }
}

proc ::tg::control::drop {chan} {
    variable authed
    variable fails
    catch {close $chan}
    unset -nocomplain authed($chan) fails($chan)
}

proc ::tg::control::constEq {a b} {
    if {[string length $a] != [string length $b]} { return 0 }
    set d 0
    foreach x [split $a ""] y [split $b ""] { set d [expr {$d | ([scan $x %c] ^ [scan $y %c])}] }
    expr {$d == 0}
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
    variable authed
    variable fails
    if {[catch {gets $chan line} n] || $n < 0} {
        if {[catch {eof $chan} e] || $e} { drop $chan }
        return
    }
    if {[string length $line] > 8192} { drop $chan; return }
    set line [string trim $line]
    if {$line eq ""} return
    if {![info exists authed($chan)]} {
        if {[regexp {^AUTH (\S+)$} $line -> tok] && [constEq $tok [::tg::cfg::general controlToken]]} {
            set authed($chan) 1
            reply $chan 1 "authenticated"
        } else {
            incr fails($chan)
            reply $chan 0 "authentication failed"
            if {$fails($chan) >= 3} { drop $chan }
        }
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

# Blocking round trip with a hard timeout. Returns {ok kind text}.
proc ::tg::control::request {host port token verb args} {
    set ::tg::control::_done 0
    set ::tg::control::_res {}
    if {[catch {socket $host $port} chan]} { return [list 0 msg "cannot connect to TclGuard on [::tg::joinHostPort $host $port]: $chan (is it running?)"] }
    fconfigure $chan -blocking 0 -buffering line -translation lf -encoding utf-8
    set timer [after 5000 {set ::tg::control::_done timeout}]
    set want 2
    set got {}
    fileevent $chan readable {
        while {[gets $::tg::control::_chan line] >= 0} { lappend ::tg::control::_lines $line }
        if {[eof $::tg::control::_chan]} { set ::tg::control::_done eof }
        if {[llength $::tg::control::_lines] >= 2} { set ::tg::control::_done ok }
    }
    set ::tg::control::_chan $chan
    set ::tg::control::_lines {}
    puts $chan "AUTH $token"
    puts $chan [join [concat [list $verb] $args] " "]
    flush $chan
    vwait ::tg::control::_done
    after cancel $timer
    catch {close $chan}
    if {$::tg::control::_done ne "ok"} { return [list 0 msg "no answer from TclGuard ($::tg::control::_done)"] }
    lassign $::tg::control::_lines authLine resLine
    if {![string match "OK *" $authLine]} { return [list 0 msg "authentication failed (wrong token? check controlToken in the config file)"] }
    if {[regexp {^OK (msg|data) ?(.*)$} $resLine -> kind payload]} { return [list 1 $kind $payload] }
    if {[regexp {^ERR ?(.*)$} $resLine -> err]} { return [list 0 msg $err] }
    return [list 0 msg "unexpected reply: $resLine"]
}
