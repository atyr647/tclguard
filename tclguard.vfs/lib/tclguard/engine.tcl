# engine.tcl -- lifecycle: start/stop/reload everything, one command surface.
#
# The GUI, the control socket and the CLI all go through ::tg::engine::cmd, so
# every front end sees exactly the same behaviour.

namespace eval ::tg::engine {
    variable running 0
    variable startedAt 0
    variable lastHouse 0
    variable runningCfg {}      ;# listener name -> config currently running
    variable lastGeneral {}
    variable hooked 0
}

# ---------------------------------------------------------------- start ----

proc ::tg::engine::start {{quiet 0}} {
    variable running
    variable startedAt
    variable hooked
    if {$running} return
    ::tg::log::setLevel [::tg::cfg::general logLevel]
    set lf [::tg::cfg::general logFile]
    if {$lf eq ""} { set lf [file join [::tg::cfg::stateDir] tclguard.log] }
    ::tg::log::setFile $lf

    ::tg::ban::configure
    ::tg::ban::setFile [file join [::tg::cfg::stateDir] bans.db]
    ::tg::trust::setFile [file join [::tg::cfg::stateDir] trusted.db]
    set ::tg::trust::enabled [::tg::bool [::tg::cfg::general learnTrusted]]
    ::tg::level::configure
    ::tg::rate::configure
    ::tg::tcp::computeMaxTotal
    ::tg::udp::init
    ::tg::logw::configure

    if {!$hooked} {
        set hooked 1
        ::tg::ban::registerOnBan   ::tg::tcp::dropKey
        ::tg::ban::registerOnBan   ::tg::udp::dropKey
        ::tg::ban::registerOnBan   ::tg::fw::onBan
        ::tg::ban::registerOnUnban ::tg::fw::onUnban
        ::tg::level::registerOnChange ::tg::engine::levelChanged
    }
    set restored [::tg::ban::load]
    ::tg::trust::load
    if {[llength $restored]} { ::tg::log::info "restored [llength $restored] active ban(s) from the previous run" }

    ::tg::fw::init
    if {[::tg::fw::enabled]} { ::tg::fw::sync }

    applyListeners
    ::tg::control::start
    ::tg::ops::start
    set startedAt [clock seconds]
    set running 1
    ::tg::onTick ::tg::engine::tick
    ::tg::startTicks
    ::tg::log::info "TclGuard $::tg::VERSION protecting [llength [::tg::tcp::listening]] TCP/HTTP and [llength [::tg::udp::listening]] UDP listener(s)"
    warnings
}

proc ::tg::engine::warnings {} {
    if {![::tg::fw::enabled]} {
        ::tg::log::warn "no kernel firewall in use: huge floods will still reach this process. Run as administrator/root for full protection."
    }
    # A protected backend that is reachable some other way defeats the point.
    foreach {n L} [::tg::cfg::listeners] {
        if {![::tg::bool [dict get $L enabled]]} continue
        if {[dict get $L backendHost] in {0.0.0.0 ::}} {
            ::tg::log::warn "listener '$n': backend host [dict get $L backendHost] is not a usable destination"
        }
    }
}

proc ::tg::engine::stop {} {
    variable running
    variable runningCfg
    if {!$running} return
    ::tg::control::stop
    ::tg::ops::stop
    ::tg::stopTicks
    ::tg::tcp::stopAll
    ::tg::udp::stopAll
    set runningCfg {}
    ::tg::ban::save
    ::tg::trust::save
    ::tg::fw::shutdown
    ::tg::cfg::handBack 1
    set running 0
    ::tg::log::info "TclGuard stopped"
}

# Start/stop/restart listeners so they match the active config.
proc ::tg::engine::applyListeners {} {
    variable runningCfg
    set want {}
    dict for {n L} [::tg::cfg::listeners] {
        if {[::tg::bool [dict get $L enabled]]} { dict set want $n $L }
    }
    dict for {n L} $runningCfg {
        if {![dict exists $want $n] || [dict get $want $n] ne $L} {
            stopListener $n [dict get $L type]
            set runningCfg [dict remove $runningCfg $n]
        }
    }
    dict for {n L} $want {
        if {[dict exists $runningCfg $n]} continue
        set ok [expr {[dict get $L type] eq "udp" ? [::tg::udp::start $n $L] : [::tg::tcp::start $n $L]}]
        if {$ok} { dict set runningCfg $n $L }
    }
}

proc ::tg::engine::stopListener {n type} {
    if {$type eq "udp"} { ::tg::udp::stop $n } else { ::tg::tcp::stop $n }
}

# Re-read settings from the (already updated) active config and apply them live.
proc ::tg::engine::reload {} {
    variable running
    variable lastGeneral
    if {!$running} return
    ::tg::log::setLevel [::tg::cfg::general logLevel]
    ::tg::ban::configure
    ::tg::level::configure
    ::tg::rate::configure
    ::tg::tcp::computeMaxTotal
    ::tg::logw::configure
    set ::tg::trust::enabled [::tg::bool [::tg::cfg::general learnTrusted]]
    applyListeners
    # allowlist/ports/hardening changed -> rebuild kernel state
    ::tg::fw::init
    if {[::tg::fw::enabled]} { ::tg::fw::sync } else { catch {::tg::fw::uninstall} }
    ::tg::control::sync
    ::tg::ops::sync
    ::tg::log::info "configuration applied"
}

proc ::tg::engine::levelChanged {old new why} {
    ::tg::engine::event level "threat level $old -> $new: $why"
    # the alert webhook hears about the level going up to "Under attack" or higher, and about it coming back down to normal
    if {$new >= 2 && $new > $old} {
        ::tg::ops::alert level-up "threat level raised to [lindex $::tg::level::names $new] ($why)"
    } elseif {$new == 0 && $old >= 2} {
        ::tg::ops::alert level-down "threat level back to normal"
    }
}

proc ::tg::engine::event {type text} {
    # reserved hook for GUI notifications; log already carries the information
}

# ----------------------------------------------------------------- tick ----

proc ::tg::engine::tick {t} {
    ::tg::cfg::handBack
    ::tg::stat::sample $t
    ::tg::mon::tick $t
    set sig [::tg::mon::signals]
    dict set sig connPerSec [::tg::stat::rateOf conn]
    dict set sig blockedPerSec [::tg::stat::rateOf blocked]
    ::tg::level::evaluate $sig
    ::tg::ban::tick $t
    ::tg::trust::tick $t
    ::tg::rate::gc $t
    ::tg::tcp::sweep $t
    ::tg::udp::sweep $t
    ::tg::logw::poll $t
    ::tg::ops::tick $t
    ::tg::fw::tick $t
    ::tg::acme::tick $t
    if {$t - $::tg::engine::lastHouse > 3600000} {
        set ::tg::engine::lastHouse $t
        catch {::tg::tls::housekeeping}
    }
}

# ------------------------------------------------------------- snapshot ----

proc ::tg::engine::snapshot {} {
    variable running
    variable startedAt
    variable runningCfg
    set ls {}
    dict for {n L} [::tg::cfg::listeners] {
        set ls [concat $ls [list [dict create name $n type [dict get $L type] port [dict get $L port] \
            backend [::tg::joinHostPort [dict get $L backendHost] [dict get $L backendPort]] \
            enabled [dict get $L enabled] running [dict exists $runningCfg $n] \
            conns [expr {[dict get $L type] eq "udp" ? [udpSessions $n] : [tcpConns $n]}]]]]
    }
    set st [::tg::stat::snapshot]
    dict create \
        version $::tg::VERSION running $running uptime [expr {$running ? [clock seconds] - $startedAt : 0}] \
        level [::tg::level::status] \
        counters [dict get $st counters] rates [dict get $st rates] \
        bans [::tg::ban::count] trusted [::tg::trust::count] \
        connections [::tg::tcp::connectionCount] udpSessions [dict get [::tg::udp::status] sessions] \
        top $::tg::stat::top \
        listeners $ls \
        firewall [::tg::fw::status] \
        net [dict create rx $::tg::mon::rx tx $::tg::mon::tx rxPps $::tg::mon::rxPps rxPct $::tg::mon::rxPct] \
        watchers [::tg::logw::status] \
        udpAvailable $::tg::udp::available \
        trackedKeys [::tg::rate::size] \
        ops [dict merge [::tg::ops::status] [dict create dryRun [::tg::bool [::tg::cfg::general dryRun]]]]
}

proc ::tg::engine::tcpConns {n} {
    if {[info exists ::tg::tcp::nconn($n)]} { return $::tg::tcp::nconn($n) }
    return 0
}
proc ::tg::engine::udpSessions {n} {
    if {[info exists ::tg::udp::nsess($n)]} { return $::tg::udp::nsess($n) }
    return 0
}

# ---------------------------------------------------------- command API ----

proc ::tg::engine::saveConfig {} {
    ::tg::cfg::save
}

proc ::tg::engine::setGeneral {key value} {
    set c $::tg::cfg::current
    dict set c general $key $value
    lassign [::tg::cfg::validate $c] errs warns
    if {[llength $errs]} { error [join $errs "; "] }
    ::tg::cfg::set_ $c
    saveConfig
}

proc ::tg::engine::listEdit {key op item} {
    set cur [::tg::cfg::general $key]
    set norm [::tg::ip::normCidr $item]
    if {$norm eq ""} { error "'$item' is not a valid IP address or CIDR range" }
    switch -- $op {
        add    { if {$norm ni $cur} { lappend cur $norm } }
        remove { set cur [lsearch -all -inline -not -exact $cur $norm] }
    }
    setGeneral $key $cur
    reload
}

# verb ?args?  -> result (throws on error)
proc ::tg::engine::cmd {verb args} {
    switch -- $verb {
        status    { return [snapshot] }
        bans      { return [::tg::ban::all] }
        ban {
            lassign $args ip sec
            set reason [join [lrange $args 2 end] " "]
            if {![::tg::ip::isTarget $ip]} { error "'$ip' is not a valid IP address or CIDR range" }
            if {$sec eq ""} { set sec 86400 }
            if {![::tg::isInt $sec 0 31536000]} { error "duration must be seconds (0 = forever)" }
            if {$reason eq ""} { set reason "manual ban" }
            if {[::tg::ban::isAllowed $ip]} { error "$ip is on the allowlist; remove it from the allowlist first" }
            if {[::tg::ip::overlapsSet allow $ip]} { error "$ip would cover addresses on the allowlist; remove them from the allowlist first" }
            lassign [::tg::ip::parseCidr $ip] pf pbits pnet
            if {$pbits < ($pf == 4 ? 8 : 16)} { error "$ip is far too wide a range to ban (shortest allowed prefix: /[expr {$pf == 4 ? 8 : 16}])" }
            ::tg::ban::add $ip $reason $sec manual
            return "banned [::tg::ip::key $ip]"
        }
        unban {
            lassign $args ip
            if {$ip eq ""} { error "usage: unban <ip>" }
            if {[::tg::ban::remove $ip]} { return "unbanned [::tg::ip::key $ip]" }
            error "$ip is not banned"
        }
        unbanall  { set n [::tg::ban::count]; ::tg::ban::clearAll; return "removed $n ban(s)" }
        allow     { listEdit allowlist add [lindex $args 0]; return "allowlisted [lindex $args 0]" }
        disallow  { listEdit allowlist remove [lindex $args 0]; return "removed [lindex $args 0] from allowlist" }
        block     { listEdit blocklist add [lindex $args 0]; return "blocked [lindex $args 0]" }
        unblock   { listEdit blocklist remove [lindex $args 0]; return "unblocked [lindex $args 0]" }
        level {
            set v [lindex $args 0]
            if {$v eq "auto"} { ::tg::level::setManual auto; return "threat level is automatic" }
            if {![::tg::isInt $v 0 3]} { error "level must be 0-3 or auto" }
            ::tg::level::setManual $v
            return "threat level pinned to [::tg::level::name]"
        }
        tls {
            # certificate + ACME state per TLS listener; "tls renew <listener>" retries a certificate order now
            if {[lindex $args 0] eq "renew"} {
                set n [lindex $args 1]
                if {$n eq "" || ![info exists ::tg::tls::files($n)]} { error "usage: tls renew <tls listener name>" }
                ::tg::acme::requestNow $n
                return "will retry the certificate order for $n within a second"
            }
            set out {}
            foreach {n L} [::tg::cfg::listeners] {
                if {![::tg::tls::enabled $L]} continue
                dict set out $n [dict merge [::tg::tls::certStatus $n] [dict create acme [::tg::acme::enabled $L] acmeState [::tg::acme::state $n]]]
            }
            return $out
        }
        top       { return $::tg::stat::top }
        log       { set n [lindex $args 0]; if {$n eq ""} { set n 50 }; return [::tg::log::tail $n info] }
        listeners { return [dict get [snapshot] listeners] }
        reload {
            ::tg::cfg::reloadFrom $::tg::cfg::path
            reload
            return "configuration reloaded"
        }
        fw {
            switch -- [lindex $args 0] {
                status    { return [::tg::fw::status] }
                install   { ::tg::fw::init; if {![::tg::fw::enabled]} { error [dict get [::tg::fw::status] error] }; if {![::tg::fw::sync]} { error [dict get [::tg::fw::status] error] }; return "kernel rules installed" }
                uninstall { ::tg::fw::uninstall; return "kernel rules removed" }
                preview   { return [::tg::fw::preview] }
                default   { error "usage: fw status|install|uninstall|preview" }
            }
        }
        stop      { after 100 {::tg::engine::stop; set ::tg::quit 1}; return "stopping" }
        debug {
            # sizes of internal tables: a steadily growing number after traffic stops is a leak
            return [dict create \
                tcpConns [array size ::tg::tcp::cc] tcpPerIp [array size ::tg::tcp::perip] \
                httpState [array size ::tg::http::ps] httpBuf [array size ::tg::http::buf] \
                udpSessions [array size ::tg::udp::sname] udpPerIp [array size ::tg::udp::perip] \
                rateKeys [::tg::rate::size] strikes [array size ::tg::ban::score] bans [::tg::ban::count] \
                trusted [::tg::trust::count] verified [array size ::tg::http::verified] \
                openChannels [llength [chan names]]]
        }
        alert {
            if {[lindex $args 0] ne "test"} { error "usage: alert test" }
            if {[::tg::cfg::general alertUrl] eq ""} { error "alertUrl is not set in the configuration" }
            unset -nocomplain ::tg::ops::alertAt(test)
            ::tg::ops::alert test "this is a test alert from TclGuard (everything is fine)"
            return "test alert queued; the log says whether it was delivered"
        }
        ping      { return pong }
        default   { error "unknown command '$verb'" }
    }
}
