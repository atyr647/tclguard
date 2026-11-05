# ops.tcl -- running it for real: overload detection, the alert webhook, and the health / metrics endpoint.
#
#   * Overload detection: a 100 ms timer measures how late it fires. Under a flood the first thing that goes wrong in a single-threaded
#     event loop is that everything waits; the lateness is the one number that says "this process can no longer keep up", whatever the
#     cause. Sustained lateness is logged, exposed as a metric and sent as an alert.
#   * Alerts: one HTTPS POST (JSON, or plain text for services such as ntfy) to a URL you choose, for the few events worth waking someone
#     for: the threat level rising, overload starting and ending, the control port not starting. Rate-limited per kind and per hour. The
#     request is made by a short-lived helper process, so a slow DNS server or an unresponsive endpoint can never stall the guard, and the
#     URL (which often contains a secret) is passed in the environment, not on a command line other users could see.
#   * Health and metrics: an optional tiny HTTP listener (127.0.0.1 by default, off by default) with /healthz and Prometheus text on
#     /metrics. Bounded like everything else here: small requests only, a few connections, short deadlines, optional bearer token.

namespace eval ::tg::ops {
    # overload detection
    variable lagPrev 0
    variable lagCur 0              ;# worst lateness (ms) seen since the last second tick
    variable lagLast 0             ;# worst lateness of the previous second
    variable lagSecs {}            ;# the last five per-second worst values
    variable lagTimer ""
    variable saturated 0
    variable satSince 0
    # alerts
    variable alertAt               ;# kind -> ms of the last alert of that kind
    array set alertAt {}
    variable alertLog {}           ;# ms of alerts sent in the last hour
    variable alertsSent 0
    variable alertsSuppressed 0
    variable alertsFailed 0
    variable alertBusy 0
    variable maxAlertsPerHour 30
    # metrics listener
    variable msrv ""
    variable mstarted {}
    variable mc                    ;# chan -> {born buf}
    array set mc {}
    variable mMaxConns 8
}

# ---------------------------------------------------------------- lifecycle ----

proc ::tg::ops::start {} {
    variable lagPrev
    variable lagTimer
    variable lagCur
    variable lagLast
    variable lagSecs
    variable saturated
    set lagCur 0; set lagLast 0; set lagSecs {}; set saturated 0
    set lagPrev [clock milliseconds]
    if {$lagTimer eq ""} { set lagTimer [after 100 ::tg::ops::lagTick] }
    metricsStart
}

proc ::tg::ops::stop {} {
    variable lagTimer
    if {$lagTimer ne ""} { after cancel $lagTimer; set lagTimer "" }
    metricsStop
}

# Settings that need action when the configuration is reloaded.
proc ::tg::ops::sync {} {
    variable mstarted
    if {[metricsSettings] ne $mstarted} { metricsStop; metricsStart }
}

# ------------------------------------------------------------ overload detection ----

proc ::tg::ops::lagTick {} {
    variable lagPrev
    variable lagCur
    variable lagTimer
    set now [clock milliseconds]
    set late [expr {$now - $lagPrev - 100}]
    set lagPrev $now
    # a wall-clock step (suspend/resume, NTP) is not lateness
    if {$late > 0 && $late < 30000 && $late > $lagCur} { set lagCur $late }
    set lagTimer [after 100 ::tg::ops::lagTick]
}

# Called every second from the engine tick.
proc ::tg::ops::tick {t} {
    variable lagCur
    variable lagLast
    variable lagSecs
    variable saturated
    variable satSince
    set lagLast $lagCur
    set lagCur 0
    lappend lagSecs $lagLast
    if {[llength $lagSecs] > 5} { set lagSecs [lrange $lagSecs end-4 end] }
    set limit [::tg::cfg::general satLagMs]
    set hot 0; set calm 0
    foreach v $lagSecs { if {$v >= $limit} { incr hot }; if {$v < $limit / 2} { incr calm } }
    if {!$saturated && $hot >= 3} {
        set saturated 1
        set satSince [clock seconds]
        set msg "OVERLOADED: the event loop is running up to [::tcl::mathfunc::max {*}$lagSecs] ms late; this process cannot keep up with the traffic. Consider a CDN or a firewall rule in front of it, or lower the connection limits."
        ::tg::log::alert $msg
        alert overload $msg
    } elseif {$saturated && $calm == 5} {
        set saturated 0
        set msg "overload over: the event loop is keeping up again (after [expr {[clock seconds] - $satSince}] s)"
        ::tg::log::info $msg
        alert overload-end $msg
    }
}

proc ::tg::ops::status {} {
    variable lagLast
    variable lagCur
    variable saturated
    dict create lagMs [expr {max($lagLast, $lagCur)}] saturated $saturated
}

# ------------------------------------------------------------------ alerts ----

# alert kind text -- never raises, never blocks.
proc ::tg::ops::alert {kind text} {
    variable alertAt
    variable alertLog
    variable alertsSuppressed
    variable maxAlertsPerHour
    if {[catch {::tg::cfg::general alertUrl} url] || $url eq ""} return
    set now [clock milliseconds]
    set cool [expr {[::tg::cfg::general alertCooldown] * 1000}]
    if {[info exists alertAt($kind)] && $now - $alertAt($kind) < $cool} { incr alertsSuppressed; return }
    set recent {}
    foreach x $alertLog { if {$now - $x < 3600000} { lappend recent $x } }
    set alertLog $recent
    if {[llength $alertLog] >= $maxAlertsPerHour} { incr alertsSuppressed; return }
    set alertAt($kind) $now
    lappend alertLog $now
    after 0 [list ::tg::ops::deliver $url $kind $text]
}

proc ::tg::ops::alertBody {kind text} {
    set host [expr {[info exists ::env(COMPUTERNAME)] ? $::env(COMPUTERNAME) : [info hostname]}]
    if {[::tg::cfg::general alertFormat] eq "text"} { return "TclGuard on $host: $text" }
    set when [clock format [clock seconds] -format %Y-%m-%dT%H:%M:%SZ -gmt 1]
    # (both "text" and "content": Slack reads the first, Discord the second; both ignore what they do not know)
    set msg "TclGuard on $host: $text"
    ::tg::json::object event [::tg::json::quote $kind] host [::tg::json::quote $host] time [::tg::json::quote $when] \
        message [::tg::json::quote $text] text [::tg::json::quote $msg] content [::tg::json::quote $msg]
}

proc ::tg::ops::deliver {url kind text} {
    variable alertBusy
    variable alertsFailed
    variable alertsSent
    if {$alertBusy} { incr ::tg::ops::alertsSuppressed; return }
    if {[catch {
        set body [alertBody $kind $text]
        set type [expr {[::tg::cfg::general alertFormat] eq "text" ? "text/plain; charset=utf-8" : "application/json"}]
        set cmd [::tg::autostart::selfCommand alert-send]
        set ::env(TCLGUARD_ALERT_URL) $url
        set ::env(TCLGUARD_ALERT_TYPE) $type
        try {
            set ch [open |[list {*}$cmd 2>@1] r+]
        } finally {
            unset -nocomplain ::env(TCLGUARD_ALERT_URL) ::env(TCLGUARD_ALERT_TYPE)
        }
        fconfigure $ch -translation binary -blocking 0 -buffering full
        puts -nonewline $ch [encoding convertto utf-8 $body]
        flush $ch
        close $ch write
        set alertBusy 1
        set ::tg::ops::alertOut($ch) ""
        fileevent $ch readable [list ::tg::ops::deliverRead $ch $kind]
        set ::tg::ops::alertTimer($ch) [after 30000 [list ::tg::ops::deliverDone $ch $kind timeout]]
    } err]} {
        set alertBusy 0
        incr alertsFailed
        ::tg::log::warn "could not send the alert: $err"
    }
}

proc ::tg::ops::deliverRead {ch kind} {
    variable alertOut
    if {[catch {read $ch 4096} d]} { deliverDone $ch $kind "read error"; return }
    if {[string length $alertOut($ch)] < 2000} { append alertOut($ch) $d }
    if {[eof $ch]} { deliverDone $ch $kind eof }
}

proc ::tg::ops::deliverDone {ch kind how} {
    variable alertOut
    variable alertTimer
    variable alertBusy
    variable alertsSent
    variable alertsFailed
    if {![info exists alertOut($ch)]} return
    set out [string trim $alertOut($ch)]
    catch { after cancel $alertTimer($ch) }
    catch { fileevent $ch readable {} }
    fconfigure $ch -blocking 0
    set rc [catch {close $ch} cerr]
    unset -nocomplain alertOut($ch) alertTimer($ch)
    set alertBusy 0
    if {$how eq "timeout"} {
        incr alertsFailed
        ::tg::log::warn "alert '$kind' was not delivered: the helper did not finish in time"
    } elseif {$rc || [string match "ERROR*" $out]} {
        incr alertsFailed
        ::tg::log::warn "alert '$kind' was not delivered: [expr {$out ne {} ? $out : $cerr}]"
    } else {
        incr alertsSent
        ::tg::log::debug "alert '$kind' delivered (helper said: '$out')"
    }
}

# `tclguard alert-send`: the helper process. URL and content type come from the environment, the body from standard input.
proc ::tg::ops::alertSendMain {} {
    after 25000 { puts "ERROR: timed out"; exit 1 }
    set url [expr {[info exists ::env(TCLGUARD_ALERT_URL)] ? $::env(TCLGUARD_ALERT_URL) : ""}]
    set type [expr {[info exists ::env(TCLGUARD_ALERT_TYPE)] ? $::env(TCLGUARD_ALERT_TYPE) : "application/json"}]
    fconfigure stdin -translation binary
    set body [read stdin 65536]
    if {[catch {postAlert $url $type $body} err]} { puts "ERROR: $err"; exit 1 }
    exit 0
}

proc ::tg::ops::postAlert {url type body} {
    if {![regexp -nocase {^(https?)://(\[[0-9a-f:.]+\]|[^/:?#]+)} $url -> scheme host]} { error "the alert URL is not an http(s) address" }
    set allowHttp 0
    if {[string tolower $scheme] eq "http"} {
        # plain http only to this computer or the local network: the message must not cross the internet unprotected
        if {![::tg::ip::isPrivate [string trim $host {[]}]] && [string tolower $host] ne "localhost"} {
            error "plain http:// is only allowed for local addresses; use https:// for $host"
        }
        set allowHttp 1
    }
    set r [::tg::https::request POST $url -headers [list Content-Type $type] -body $body -timeout 15000 -maxbytes 65536 -allowHttp $allowHttp -redirects 0]
    set code [dict get $r code]
    if {$code < 200 || $code >= 300} { error "the alert endpoint answered HTTP $code" }
}

# ------------------------------------------------------- health + metrics ----

proc ::tg::ops::metricsSettings {} {
    list [::tg::bool [::tg::cfg::general metricsEnable]] [::tg::cfg::general metricsHost] [::tg::cfg::general metricsPort] [::tg::cfg::general metricsToken]
}

proc ::tg::ops::metricsStart {} {
    variable msrv
    variable mstarted
    set mstarted [metricsSettings]
    if {$msrv ne "" || ![::tg::bool [::tg::cfg::general metricsEnable]]} return
    set host [::tg::cfg::general metricsHost]
    set port [::tg::cfg::general metricsPort]
    if {[catch {socket -server ::tg::ops::maccept -myaddr $host $port} s err]} {
        ::tg::log::warn "metrics endpoint unavailable on [::tg::joinHostPort $host $port]: $s"
        return
    }
    set msrv $s
    if {$host ni {127.0.0.1 ::1 localhost}} {
        if {[::tg::cfg::general metricsToken] eq ""} {
            ::tg::log::warn "metrics endpoint is reachable from the network ($host) without a token: set metricsToken, or bind it to 127.0.0.1"
        } else {
            ::tg::log::info "metrics endpoint listening on [::tg::joinHostPort $host $port] (bearer token required)"
        }
    }
}

proc ::tg::ops::metricsStop {} {
    variable msrv
    variable mc
    if {$msrv ne ""} { catch {close $msrv}; set msrv "" }
    foreach c [array names mc] { mdrop $c }
}

proc ::tg::ops::maccept {chan ip port} {
    variable mc
    variable mMaxConns
    if {[array size mc] >= $mMaxConns} { catch {close $chan}; return }
    fconfigure $chan -blocking 0 -buffering full -translation binary
    set mc($chan) [list [clock milliseconds] ""]
    fileevent $chan readable [list ::tg::ops::mread $chan]
    after 3000 [list ::tg::ops::mdrop $chan]
}

proc ::tg::ops::mdrop {chan} {
    variable mc
    if {![info exists mc($chan)]} return
    unset mc($chan)
    catch { fileevent $chan readable {} }
    catch { close $chan }
}

proc ::tg::ops::mread {chan} {
    variable mc
    if {![info exists mc($chan)]} { catch {close $chan}; return }
    if {[catch {read $chan 2048} d]} { mdrop $chan; return }
    lassign $mc($chan) born buf
    append buf $d
    if {[string length $buf] > 4096} { mdrop $chan; return }
    if {[string first "\r\n\r\n" $buf] < 0 && [string first "\n\n" $buf] < 0} {
        if {[eof $chan]} { mdrop $chan } else { set mc($chan) [list $born $buf] }
        return
    }
    unset mc($chan)
    catch { fileevent $chan readable {} }
    set resp [mhandle $buf]
    catch { puts -nonewline $chan $resp; flush $chan }
    catch { close $chan }
}

proc ::tg::ops::mresp {code text body {type "text/plain; charset=utf-8"} {extra ""}} {
    set b [encoding convertto utf-8 $body]
    return "HTTP/1.1 $code $text\r\nContent-Type: $type\r\nContent-Length: [string length $b]\r\nCache-Control: no-store\r\nConnection: close\r\n$extra\r\n$b"
}

proc ::tg::ops::mhandle {req} {
    set lines [split [string map [list \r\n \n] $req] \n]
    if {![regexp {^(GET|HEAD) (/[^ ?#]*)(?:\?[^ ]*)? HTTP/1\.[01]$} [lindex $lines 0] -> method path]} {
        return [mresp 405 "Method Not Allowed" "GET only\n" text/plain "Allow: GET, HEAD\r\n"]
    }
    set tok [::tg::cfg::general metricsToken]
    if {$tok ne ""} {
        set got ""
        foreach l [lrange $lines 1 end] {
            if {[regexp -nocase {^authorization:[ \t]*(.*)$} $l -> v]} { set got [string trim $v] }
        }
        if {![::tg::control::constEq $got "Bearer $tok"]} {
            return [mresp 401 Unauthorized "unauthorized\n" text/plain "WWW-Authenticate: Bearer\r\n"]
        }
    }
    switch -- $path {
        /healthz {
            if {$::tg::engine::running} { set r [mresp 200 OK "ok\n"] } else { set r [mresp 503 "Service Unavailable" "not running\n"] }
        }
        /readyz {
            # ready = running and not overloaded (a load balancer can take an overloaded instance out of rotation)
            if {$::tg::engine::running && !$::tg::ops::saturated} { set r [mresp 200 OK "ready\n"] } else { set r [mresp 503 "Service Unavailable" "not ready\n"] }
        }
        /metrics { set r [mresp 200 OK [metricsText] "text/plain; version=0.0.4; charset=utf-8"] }
        default  { set r [mresp 404 "Not Found" "not found\n"] }
    }
    if {$method eq "HEAD"} { return [string range $r 0 [expr {[string first "\r\n\r\n" $r] + 3}]] }
    return $r
}

proc ::tg::ops::esc {s} { string map [list \\ \\\\ \" \\\" \n \\n] $s }

proc ::tg::ops::mline {name help type value {labels ""}} {
    return "# HELP $name $help\n# TYPE $name $type\n$name$labels $value\n"
}

proc ::tg::ops::metricsText {} {
    variable alertsSent; variable alertsSuppressed; variable alertsFailed
    set snap [::tg::engine::snapshot]
    set st [status]
    set o {}
    append o [mline tclguard_up "1 while TclGuard is running" gauge [dict get $snap running]]
    append o [mline tclguard_build_info "Version of this build" gauge 1 "\{version=\"[esc $::tg::VERSION]\"\}"]
    append o [mline tclguard_uptime_seconds "Seconds since the engine started" gauge [dict get $snap uptime]]
    append o [mline tclguard_threat_level "Threat level 0 (normal) to 3 (lockdown)" gauge [::tg::level::get]]
    append o [mline tclguard_dry_run "1 when automatic bans are only logged, not applied" gauge [::tg::bool [::tg::cfg::general dryRun]]]
    append o [mline tclguard_connections "Proxied TCP/HTTP connections open now" gauge [dict get $snap connections]]
    append o [mline tclguard_udp_sessions "UDP sessions open now" gauge [dict get $snap udpSessions]]
    append o [mline tclguard_bans_active "Addresses and ranges banned now" gauge [dict get $snap bans]]
    append o [mline tclguard_trusted_addresses "Addresses that have earned trust" gauge [dict get $snap trusted]]
    append o [mline tclguard_tracked_keys "Entries in the rate limiter" gauge [dict get $snap trackedKeys]]
    append o [mline tclguard_event_loop_lag_ms "Worst lateness of the event loop in the last second" gauge [dict get $st lagMs]]
    append o [mline tclguard_overloaded "1 while the event loop cannot keep up" gauge [dict get $st saturated]]
    append o [mline tclguard_alerts_sent_total "Alerts delivered to the webhook" counter $alertsSent]
    append o [mline tclguard_alerts_suppressed_total "Alerts held back by the rate limits" counter $alertsSuppressed]
    append o [mline tclguard_alerts_failed_total "Alerts that could not be delivered" counter $alertsFailed]
    foreach {name val} [dict get $snap counters] {
        if {![regexp {^[A-Za-z0-9_]+$} $name]} continue
        set mn "tclguard_[string tolower [regsub -all {([a-z0-9])([A-Z])} $name {\1_\2}]]_total"
        append o [mline $mn "TclGuard counter $name" counter $val]
    }
    append o "# HELP tclguard_listener_connections Connections or sessions per listener\n# TYPE tclguard_listener_connections gauge\n"
    foreach l [dict get $snap listeners] {
        append o "tclguard_listener_connections\{listener=\"[esc [dict get $l name]]\",type=\"[dict get $l type]\"\} [dict get $l conns]\n"
    }
    return $o
}
