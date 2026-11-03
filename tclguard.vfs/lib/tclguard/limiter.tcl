# limiter.tcl -- O(1) sliding-window rate counters.
#
# Each key keeps two fixed-window counters (current and previous). The estimate
#     prev * (1 - elapsed/window) + cur
# approximates a true sliding window without storing per-event timestamps, so
# memory per tracked address is constant no matter how hard it is hammered.

namespace eval ::tg::rate {
    variable cur
    variable prev
    variable start
    variable win
    array set cur {}
    array set prev {}
    array set start {}
    array set win {}
    variable max 400000       ;# tracked keys; beyond this new keys are not tracked
    variable overflow 0       ;# hits we could not track (table full)
}

proc ::tg::rate::configure {} {
    variable max
    set max [::tg::cfg::general trackerMax]
}

# Register a hit and return the estimated number of hits in the last windowMs.
# If the table is full and the key is new, returns 0 (fail-open) and counts it.
proc ::tg::rate::hit {key windowMs {n 1}} {
    variable cur
    variable prev
    variable start
    variable win
    variable max
    variable overflow
    set t [::tg::now]
    if {![info exists start($key)]} {
        if {[array size start] >= $max} {
            incr overflow
            return 0
        }
        set start($key) $t
        set cur($key) $n
        set prev($key) 0
        set win($key) $windowMs
        return $n
    }
    set el [expr {$t - $start($key)}]
    if {$el >= $windowMs} {
        if {$el >= 2 * $windowMs} {
            set prev($key) 0
        } else {
            set prev($key) $cur($key)
        }
        set cur($key) 0
        set start($key) [expr {$start($key) + ($el / $windowMs) * $windowMs}]
        set el [expr {$t - $start($key)}]
    }
    set win($key) $windowMs
    incr cur($key) $n
    expr {$prev($key) * (1.0 - double($el) / $windowMs) + $cur($key)}
}

# Estimate without recording a hit.
proc ::tg::rate::peek {key windowMs} {
    variable cur
    variable prev
    variable start
    if {![info exists start($key)]} { return 0 }
    set t [::tg::now]
    set el [expr {$t - $start($key)}]
    if {$el >= 2 * $windowMs} { return 0 }
    if {$el >= $windowMs} {
        return [expr {$cur($key) * (1.0 - double($el - $windowMs) / $windowMs)}]
    }
    expr {$prev($key) * (1.0 - double($el) / $windowMs) + $cur($key)}
}

proc ::tg::rate::forget {key} {
    variable cur
    variable prev
    variable start
    variable win
    unset -nocomplain cur($key) prev($key) start($key) win($key)
}

proc ::tg::rate::size {} { variable start; array size start }

# Drop keys that have been idle for two windows. Runs every 10 s.
proc ::tg::rate::gc {t} {
    variable cur
    variable prev
    variable start
    variable win
    if {$t % 10000 >= 1000} return
    foreach k [array names start] {
        if {$t - $start($k) > 2 * $win($k)} {
            unset cur($k) prev($k) start($k) win($k)
        }
    }
}

proc ::tg::rate::reset {} {
    variable cur
    variable prev
    variable start
    variable win
    variable overflow
    array unset cur; array unset prev; array unset start; array unset win
    set overflow 0
}
