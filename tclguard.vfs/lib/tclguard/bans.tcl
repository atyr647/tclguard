# bans.tcl -- decision state shared by every protection module.
#
#   ::tg::ban     strikes -> bans (escalating), allow/block lists, persistence
#   ::tg::trust   "known good" IP reputation, used by lockdown mode
#   ::tg::level   adaptive threat level (0 normal .. 3 lockdown)

# ================================================================ ::tg::ban ===

namespace eval ::tg::ban {
    variable banned          ;# key -> dict {until since reason level source}
    array set banned {}
    variable score           ;# key -> {points lastMs}
    array set score {}
    variable hist            ;# key -> {level lastBanMs}
    array set hist {}
    variable nScore 0        ;# table sizes kept as counters (`array size` is O(n) in Tcl 8.6); resynchronised by tick
    variable nBanned 0
    variable nHist 0
    variable onBan {}        ;# callbacks: {*}cmd key info
    variable onUnban {}      ;# callbacks: {*}cmd key
    variable dirty 0
    variable lastSave 0
    variable file ""
    variable threshold 10
    variable leak 0.25
    variable steps {60 600 3600 21600 86400}
    variable resetAfter 86400
    variable hasAllow 0
    variable hasBlock 0
    variable hasRanges 0       ;# any CIDR (non-/64) bans active
}

# (Re)read settings from the active config.
proc ::tg::ban::configure {} {
    variable threshold
    variable leak
    variable steps
    variable resetAfter
    variable hasAllow
    variable hasBlock
    set threshold  [::tg::cfg::general strikeThreshold]
    set leak       [::tg::cfg::general strikeLeakPerSec]
    set steps      [::tg::cfg::general banSteps]
    set resetAfter [::tg::cfg::general banResetAfter]
    set bad [::tg::ip::setLoad allow [::tg::cfg::general allowlist]]
    foreach b $bad { ::tg::log::warn "ignoring invalid allowlist entry '$b'" }
    set bad [::tg::ip::setLoad block [::tg::cfg::general blocklist]]
    foreach b $bad { ::tg::log::warn "ignoring invalid blocklist entry '$b'" }
    set hasAllow [expr {[llength [::tg::ip::setItems allow]] > 0}]
    set hasBlock [expr {[llength [::tg::ip::setItems block]] > 0}]
}

proc ::tg::ban::setFile {path} {
    variable file
    set file $path
}

proc ::tg::ban::registerOnBan {cmd}   { variable onBan;   if {$cmd ni $onBan}   { lappend onBan $cmd } }
proc ::tg::ban::registerOnUnban {cmd} { variable onUnban; if {$cmd ni $onUnban} { lappend onUnban $cmd } }

# Canonical key for an address or CIDR target: addresses collapse to the limit
# key (v4 exact, v6 /64); explicit ranges keep their prefix.
proc ::tg::ban::keyOf {target} {
    if {[string first / $target] >= 0} {
        set n [::tg::ip::normCidr $target]
        if {$n eq ""} { return $target }
        # a /32 (v4) or /128 normalises to a plain address
        return [expr {[string first / $n] < 0 ? [::tg::ip::key $n] : $n}]
    }
    ::tg::ip::key $target
}

# The automatic IPv6 /64 keys are looked up exactly; only operator ranges need the prefix table (rebuilding it for every automatic v6 ban
# made adding or expiring thousands of them quadratic: 10,000 bans stalled the event loop for 12 s).
proc ::tg::ban::isRangeKey {k} {
    expr {[string first / $k] >= 0 && ![string match {*:*/64} $k]}
}

# Ranges (CIDR bans other than the automatic v6 /64 keys) need a prefix match.
proc ::tg::ban::rebuildRanges {} {
    variable banned
    variable hasRanges
    set items {}
    foreach k [array names banned] {
        if {[string first / $k] < 0} continue
        if {[string match {*:*/64} $k]} continue
        lappend items $k
    }
    ::tg::ip::setLoad banrange $items
    set hasRanges [expr {[llength $items] > 0}]
}

proc ::tg::ban::isAllowed {ip} {
    variable hasAllow
    expr {$hasAllow && [::tg::ip::setMatch allow $ip]}
}

# Hot path. 0 = fine, 1 = temporarily banned, 2 = on the static blocklist.
proc ::tg::ban::check {ip} {
    variable banned
    variable hasBlock
    variable hasRanges
    if {[isAllowed $ip]} { return 0 }
    set k [::tg::ip::key $ip]
    if {[info exists banned($k)]} {
        set until [dict get $banned($k) until]
        if {$until == 0 || $until > [::tg::now]} { return 1 }
        remove $k expired
    }
    if {$hasRanges && [::tg::ip::setMatch banrange $ip]} { return 1 }
    if {$hasBlock && [::tg::ip::setMatch block $ip]} { return 2 }
    return 0
}

proc ::tg::ban::isBanned {ip} {
    expr {[check $ip] == 1}
}

# Add a weighted strike. Returns 1 if this strike caused a ban.
proc ::tg::ban::strike {ip points reason} {
    variable score
    variable banned
    variable threshold
    variable leak
    if {[isAllowed $ip]} { return 0 }
    # a configured trusted proxy (CDN, tunnel) stands for many visitors: it is never struck, whatever one of them does
    if {[::tg::ip::setMatch proxies $ip]} { return 0 }
    set k [::tg::ip::key $ip]
    if {[info exists banned($k)]} { return 0 }
    set t [::tg::now]
    ::tg::stat::incr strikes
    if {[info exists score($k)]} {
        lassign $score($k) p last
        set p [expr {max(0.0, $p - $leak * max(0, $t - $last) / 1000.0)}]
    } else {
        variable nScore
        if {$nScore > 300000} { return 0 }
        incr nScore
        set p 0.0
    }
    set p [expr {$p + $points}]
    if {$p >= $threshold} {
        unset -nocomplain score($k)
        add $k $reason "" auto
        return 1
    }
    set score($k) [list $p $t]
    return 0
}

# Ban an address/prefix. sec "" = escalate by history, 0 = permanent.
proc ::tg::ban::add {ip reason {sec ""} {source auto}} {
    variable banned
    variable hist
    variable steps
    variable resetAfter
    variable dirty
    if {[isAllowed $ip]} {
        ::tg::log::info "not banning allowlisted address $ip ($reason)"
        return 0
    }
    set k [keyOf $ip]
    variable nBanned
    variable nHist
    if {![info exists banned($k)] && $nBanned >= 200000} {
        ::tg::log::warn "ban table full (200000 entries); not banning $k"
        return 0
    }
    set t [::tg::now]
    set level 0
    set isNew [expr {![info exists banned($k)]}]
    # an address that is already banned keeps its ban and its history: repeated automatic reports against it (the connection monitor, a
    # log watcher) must neither extend the ban nor walk it up the escalation ladder in seconds
    if {!$isNew && $sec eq ""} { return 0 }
    if {$sec eq ""} {
        if {[info exists hist($k)]} {
            lassign $hist($k) lv last
            if {$t - $last <= $resetAfter * 1000} { set level $lv }
        }
        set idx [expr {min($level, [llength $steps] - 1)}]
        set sec [lindex $steps $idx]
        if {$nHist < 200000 || [info exists hist($k)]} {
            if {![info exists hist($k)]} { incr nHist }
            set hist($k) [list [expr {$level + 1}] [expr {$t + $sec * 1000}]]
        }
    }
    set until [expr {$sec == 0 ? 0 : $t + $sec * 1000}]
    if {!$isNew} {
        # extend only; never shorten an existing ban
        set old [dict get $banned($k) until]
        if {$old == 0 || ($until != 0 && $old >= $until)} { return 0 }
    }
    set info [dict create until $until since $t reason $reason level $level source $source]
    if {$isNew} { incr nBanned }
    set banned($k) $info
    set dirty 1
    if {[isRangeKey $k]} { rebuildRanges }
    if {$isNew} {
        ::tg::stat::incr bans
        ::tg::log::alert "BANNED $k for [expr {$sec == 0 ? {ever} : [::tg::fmtDuration $sec]}]: $reason"
    }
    variable onBan
    foreach cb $onBan {
        if {[catch {{*}$cb $k $info} err]} { ::tg::log::warn "ban callback failed: $err" }
    }
    return $isNew
}

proc ::tg::ban::remove {ip {why manual}} {
    variable banned
    variable score
    variable hist
    variable dirty
    variable onUnban
    set k [keyOf $ip]
    if {![info exists banned($k)]} { return 0 }
    variable nBanned
    if {$nBanned > 0} { incr nBanned -1 }
    unset banned($k)
    unset -nocomplain score($k)
    if {$why eq "manual"} { unset -nocomplain hist($k) }
    set dirty 1
    if {[isRangeKey $k]} { rebuildRanges }
    ::tg::log::info "unbanned $k ($why)"
    foreach cb $onUnban {
        if {[catch {{*}$cb $k} err]} { ::tg::log::warn "unban callback failed: $err" }
    }
    return 1
}

proc ::tg::ban::clearAll {} {
    variable banned
    foreach k [array names banned] { remove $k manual }
}

proc ::tg::ban::count {} {
    variable banned
    array size banned
}

proc ::tg::ban::all {} {
    variable banned
    set rows {}
    foreach k [array names banned] {
        lappend rows [dict create key $k {*}$banned($k)]
    }
    lsort -decreasing -command [list apply {{a b} {
        set x [dict get $a since]; set y [dict get $b since]
        expr {$x < $y ? -1 : $x > $y ? 1 : 0}
    }}] $rows
}

proc ::tg::ban::lookup {ip} {
    variable banned
    set k [keyOf $ip]
    if {[info exists banned($k)]} { return [dict create key $k {*}$banned($k)] }
    return {}
}

# 1 Hz maintenance: expiry, strike table GC, debounced persistence.
proc ::tg::ban::tick {t} {
    variable banned
    variable score
    variable hist
    variable leak
    variable resetAfter
    variable dirty
    variable lastSave
    foreach k [array names banned] {
        set until [dict get $banned($k) until]
        if {$until != 0 && $until <= $t} { remove $k expired }
    }
    # drop fully-decayed strike records and stale escalation history
    if {$t % 10000 < 1000} {
        foreach k [array names score] {
            lassign $score($k) p last
            if {$p - $leak * ($t - $last) / 1000.0 <= 0} { unset score($k) }
        }
        foreach k [array names hist] {
            if {$t - [lindex $hist($k) 1] > $resetAfter * 1000 && ![info exists banned($k)]} { unset hist($k) }
        }
    }
    variable nScore
    variable nBanned
    variable nHist
    set nScore [array size score]; set nBanned [array size banned]; set nHist [array size hist]
    if {$dirty && $t - $lastSave >= 5000} { save }
}

proc ::tg::ban::save {} {
    variable banned
    variable hist
    variable dirty
    variable lastSave
    variable file
    set dirty 0
    set lastSave [::tg::now]
    if {$file eq ""} return
    set data [dict create version 1 banned [array get banned] hist [array get hist]]
    if {[catch {
        file mkdir [file dirname $file]
        ::tg::writeFileAtomic $file $data
    } err]} {
        ::tg::log::warn "could not save bans to $file: $err"
    }
}

# Load persisted bans. Returns the keys restored (expired ones are dropped).
proc ::tg::ban::load {} {
    variable banned
    variable hist
    variable file
    if {$file eq "" || ![file exists $file]} { return {} }
    set restored {}
    if {[catch {
        set d [::tg::readFile $file]
        # (`dict exists` answers 0 for text that is not a dictionary at all, which would make a damaged file look like an empty one)
        dict size $d
        if {![dict exists $d banned] && ![dict exists $d hist] && [string trim $d] ne ""} { error "the file does not look like a TclGuard ban list" }
        set t [::tg::now]
        if {[dict exists $d banned]} {
            dict for {k info} [dict get $d banned] {
                set until [dict get $info until]
                if {$until != 0 && $until <= $t} continue
                # only canonical keys: these end up in firewall commands
                if {[::tg::ip::normCidr $k] ne $k} continue
                set banned($k) $info
                lappend restored $k
            }
        }
        if {[dict exists $d hist]} {
            dict for {k v} [dict get $d hist] { set hist($k) $v }
        }
    } err]} {
        ::tg::log::warn "could not read saved bans from $file: $err"
    }
    rebuildRanges
    return $restored
}

# ============================================================== ::tg::trust ===
# IPs that have behaved like real users (long, bidirectional sessions or several
# successful requests). Lockdown mode only lets these through.

namespace eval ::tg::trust {
    variable good
    array set good {}
    variable max 50000
    variable nGood 0           ;# entries (kept as a counter; prune resynchronises it)
    variable file ""
    variable dirty 0
    variable lastSave 0
    variable enabled 1
}

proc ::tg::trust::setFile {p} { variable file; set file $p }

proc ::tg::trust::note {ip} {
    variable good
    variable max
    variable dirty
    variable enabled
    if {!$enabled} return
    set k [::tg::ip::key $ip]
    if {![info exists good($k)]} {
        variable nGood
        if {$nGood >= $max} { prune; set nGood [array size good] }
        incr nGood
        set dirty 1
    }
    set good($k) [::tg::now]
}

proc ::tg::trust::prune {} {
    variable good
    variable max
    set rows {}
    foreach k [array names good] { lappend rows [list $k $good($k)] }
    set rows [lsort -integer -index 1 $rows]
    set drop [expr {[llength $rows] / 10 + 1}]
    foreach r [lrange $rows 0 [expr {$drop - 1}]] { unset good([lindex $r 0]) }
}

proc ::tg::trust::known {ip} {
    variable good
    info exists good([::tg::ip::key $ip])
}

proc ::tg::trust::count {} { variable good; array size good }

proc ::tg::trust::forget {ip} { variable good; unset -nocomplain good([::tg::ip::key $ip]) }

proc ::tg::trust::tick {t} {
    variable dirty
    variable lastSave
    if {$dirty && $t - $lastSave >= 30000} { save }
}

proc ::tg::trust::save {} {
    variable good
    variable file
    variable dirty
    variable lastSave
    set dirty 0
    set lastSave [::tg::now]
    if {$file eq ""} return
    if {[catch {
        file mkdir [file dirname $file]
        ::tg::writeFileAtomic $file [array get good]
    } err]} { ::tg::log::warn "could not save trusted list: $err" }
}

proc ::tg::trust::load {} {
    variable good
    variable file
    if {$file eq "" || ![file exists $file]} return
    if {[catch {
        set d [::tg::readFile $file]
        foreach {k v} $d {
            # timestamps are milliseconds: wider than 32 bits, so wideinteger
            if {[::tg::ip::isTarget $k] && [string is wideinteger -strict $v]} { set good($k) $v }
        }
    } err]} { ::tg::log::warn "could not read trusted list: $err" }
}

# ============================================================== ::tg::level ===

namespace eval ::tg::level {
    variable lvl 0
    variable manual -1          ;# -1 = automatic
    variable since 0
    variable reason ""
    variable names {Normal Elevated {Under attack} Lockdown}
    variable hot 0              ;# consecutive seconds the target exceeded current
    variable calm 0             ;# consecutive seconds below current thresholds
    variable onChange {}
    variable signals {}         ;# last evaluated: dict signal -> value
    variable factors {1.0 0.6 0.35 0.2}
}

proc ::tg::level::configure {} {
    variable factors
    set factors [::tg::cfg::general levelFactors]
}

proc ::tg::level::get {} { variable lvl; return $lvl }
proc ::tg::level::name {{l ""}} {
    variable names
    variable lvl
    if {$l eq ""} { set l $lvl }
    lindex $names $l
}
proc ::tg::level::isManual {} { variable manual; expr {$manual >= 0} }

# Multiplier applied to every per-IP limit (lower = stricter).
proc ::tg::level::factor {{l ""}} {
    variable factors
    variable lvl
    if {$l eq ""} { set l $lvl }
    lindex $factors $l
}

proc ::tg::level::registerOnChange {cmd} { variable onChange; if {$cmd ni $onChange} { lappend onChange $cmd } }

proc ::tg::level::enter {n why} {
    variable lvl
    variable since
    variable reason
    variable onChange
    variable hot
    variable calm
    if {$n == $lvl} return
    set old $lvl
    set lvl $n
    set since [::tg::now]
    set reason $why
    set hot 0; set calm 0
    set msg "threat level [expr {$n > $old ? {raised} : {lowered}}] to [string toupper [name]]: $why"
    if {$n > $old} { ::tg::log::alert $msg } else { ::tg::log::info $msg }
    foreach cb $onChange {
        if {[catch {{*}$cb $old $n $why} err]} { ::tg::log::warn "level callback failed: $err" }
    }
}

# n = 0..3, or "auto"
proc ::tg::level::setManual {n} {
    variable manual
    if {$n eq "auto"} {
        set manual -1
        # Back to automatic starts from Normal; the evaluator re-escalates within
        # seconds if the traffic still looks like an attack.
        enter 0 "returned to automatic control"
        ::tg::log::info "threat level is automatic again"
        return
    }
    set manual $n
    enter $n "set manually"
    ::tg::log::info "threat level pinned to [string toupper [name]] (manual)"
}

# Evaluate one signal against {elevated attack lockdown} thresholds.
# Returns the highest level reached (0..3). A threshold of 0 disables that step.
proc ::tg::level::classify {value thresholds} {
    set lv 0
    set i 1
    foreach th $thresholds {
        if {$th > 0 && $value >= $th} { set lv $i }
        incr i
    }
    return $lv
}

# Called once per second with a dict of measured signals.
#   connPerSec blockedPerSec rxPps rxLinkPct
proc ::tg::level::evaluate {sig} {
    variable manual
    variable lvl
    variable hot
    variable calm
    variable signals
    set signals $sig
    if {$manual >= 0} return
    if {![::tg::bool [::tg::cfg::general autoLevel]]} return
    set best 0
    set why ""
    foreach {name key} {connPerSec thConnPerSec blockedPerSec thBlockedPerSec rxPps thRxPps rxLinkPct thRxLinkPct} {
        if {![dict exists $sig $name]} continue
        set v [dict get $sig $name]
        set c [classify $v [::tg::cfg::general $key]]
        if {$c > $best} {
            set best $c
            set why "$name [::tg::fmtRate $v] (limit [lindex [::tg::cfg::general $key] [expr {$c - 1}]])"
        }
    }
    if {$best == 3 && ![::tg::bool [::tg::cfg::general autoLockdown]]} {
        set best 2
    }
    if {$best > $lvl} {
        incr hot
        set calm 0
        if {$hot >= 2} { enter $best $why }
    } elseif {$best < $lvl} {
        set hot 0
        incr calm
        if {$calm >= [::tg::cfg::general levelCalmSec]} {
            enter [expr {$lvl - 1}] "traffic back to normal for ${calm}s"
        }
    } else {
        set hot 0
        set calm 0
    }
}

proc ::tg::level::status {} {
    variable lvl
    variable manual
    variable since
    variable reason
    variable signals
    dict create level $lvl name [name] manual [expr {$manual >= 0}] since $since reason $reason signals $signals
}
