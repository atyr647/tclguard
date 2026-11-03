# monitor.tcl -- observe the machine: network load and (for ports not behind a
# TclGuard proxy) per-address connection counts.
#
# Linux reads /proc (cheap, no processes spawned). Windows parses `netstat`.
# The load figures feed the adaptive threat level.

namespace eval ::tg::mon {
    variable last {}            ;# previous /proc/net/dev sample {ms rxB rxP txB}
    variable rx 0.0             ;# rx megabits/s
    variable tx 0.0
    variable rxPps 0.0
    variable txPps 0.0
    variable rxPct 0.0
    variable lastScan 0
    variable scanCount 0
    variable perIp {}           ;# last scan: dict ip -> {est synrecv}
    variable series {}          ;# {ms rxMbps txMbps}
    variable seriesMax 600
}

# ---- parsing helpers (pure functions, unit tested) ------------------------------

# "0100007F" -> 127.0.0.1 ; 32 hex digits -> IPv6 text (each 32-bit word is little-endian)
proc ::tg::mon::hexToIp {h} {
    if {[string length $h] == 8} {
        scan $h %2x%2x%2x%2x d c b a
        return "$a.$b.$c.$d"
    }
    if {[string length $h] == 32} {
        set words {}
        foreach w [regexp -all -inline {.{8}} $h] {
            scan $w %2x%2x%2x%2x d c b a
            lappend words [format %02x%02x%02x%02x $a $b $c $d]
        }
        set j [join $words ""]
        set groups [regexp -all -inline {.{4}} $j]
        return [::tg::ip::norm [join $groups :]]
    }
    return ""
}

# Parse the text of /proc/net/tcp or tcp6 -> list of {remoteIp localPort stateHex}
proc ::tg::mon::parseProcTcp {text} {
    set out {}
    set first 1
    foreach line [split $text \n] {
        if {$first} { set first 0; continue }
        set f [split [string trim $line]]
        set f [lsearch -all -inline -not -exact $f ""]
        if {[llength $f] < 4} continue
        lassign [split [lindex $f 1] :] lhex lport
        lassign [split [lindex $f 2] :] rhex rport
        set st [lindex $f 3]
        set rip [hexToIp $rhex]
        if {$rip eq ""} continue
        lappend out [list $rip [scan $lport %x] $st]
    }
    return $out
}

# Parse `netstat -n -p tcp` (Windows) -> same shape
proc ::tg::mon::parseNetstat {text} {
    set out {}
    foreach line [split $text \n] {
        if {![regexp {^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)} $line -> l lp r rp state]} continue
        regsub -all {[\[\]]} $r {} r
        set rip [::tg::ip::norm $r]
        if {$rip eq ""} continue
        set st [switch -- $state { SYN_RECEIVED {expr 03} ESTABLISHED {expr 01} default {expr 0} }]
        lappend out [list $rip $lp [format %02X $st]]
    }
    return $out
}

# rx/tx totals from /proc/net/dev text, skipping loopback (and any given names)
proc ::tg::mon::parseNetDev {text {only auto}} {
    set rxb 0; set rxp 0; set txb 0; set txp 0
    foreach line [split $text \n] {
        if {![regexp {^\s*([^:\s]+):\s*(.*)$} $line -> ifc rest]} continue
        if {$only eq "auto"} {
            if {$ifc eq "lo" || [regexp {^(docker|veth|br-|virbr|tun|tap)} $ifc]} continue
        } elseif {$ifc ne $only} continue
        set f [regexp -all -inline {\d+} $rest]
        if {[llength $f] < 10} continue
        incr rxb [lindex $f 0]; incr rxp [lindex $f 1]
        incr txb [lindex $f 8]; incr txp [lindex $f 9]
    }
    list $rxb $rxp $txb $txp
}

# ---- sampling --------------------------------------------------------------------

proc ::tg::mon::sampleNet {t} {
    variable last; variable rx; variable tx; variable rxPps; variable txPps; variable rxPct; variable series; variable seriesMax
    if {![file readable /proc/net/dev]} return
    if {[catch {
        set fh [open /proc/net/dev r]; set txt [read $fh]; close $fh
    }]} return
    lassign [parseNetDev $txt [::tg::cfg::general iface]] rxb rxp txb txp
    if {$last ne ""} {
        lassign $last t0 rxb0 rxp0 txb0 txp0
        set dt [expr {($t - $t0) / 1000.0}]
        if {$dt > 0 && $rxb >= $rxb0} {
            set rx [expr {($rxb - $rxb0) * 8 / $dt / 1e6}]
            set tx [expr {($txb - $txb0) * 8 / $dt / 1e6}]
            set rxPps [expr {($rxp - $rxp0) / $dt}]
            set txPps [expr {($txp - $txp0) / $dt}]
            set link [::tg::cfg::general linkMbps]
            set rxPct [expr {$rx / $link * 100.0}]
        }
    }
    set last [list $t $rxb $rxp $txb $txp]
    lappend series [list $t $rx $tx]
    if {[llength $series] > $seriesMax} { set series [lrange $series end-[expr {$seriesMax - 1}] end] }
}

proc ::tg::mon::signals {} {
    variable rx; variable rxPps; variable rxPct
    dict create rxPps $rxPps rxLinkPct $rxPct
}

proc ::tg::mon::readConnections {} {
    global tcl_platform
    if {[file readable /proc/net/tcp]} {
        set rows {}
        foreach f {/proc/net/tcp /proc/net/tcp6} {
            if {![file readable $f]} continue
            if {![catch {set fh [open $f r]; set txt [read $fh]; close $fh}]} {
                lappend rows {*}[parseProcTcp $txt]
            }
        }
        return $rows
    }
    if {$tcl_platform(platform) eq "windows"} {
        if {![catch {exec netstat -n -p tcp} txt]} { return [parseNetstat $txt] }
    }
    return {}
}

# Check ports that are served directly (not through a proxy listener).
proc ::tg::mon::scanDirect {t} {
    variable perIp
    set ports [::tg::cfg::general watchPorts]
    set perIp {}
    if {![llength $ports]} return
    set maxPer [::tg::cfg::general watchMaxPerIP]
    set maxSyn [::tg::cfg::general watchMaxSynRecv]
    array set est {}
    array set syn {}
    foreach r [readConnections] {
        lassign $r rip lport st
        if {$lport ni $ports} continue
        set k [::tg::ip::key $rip]
        if {[::tg::ban::isAllowed $rip]} continue
        if {![info exists est($k)]} { set est($k) 0; set syn($k) 0 }
        incr est($k)
        if {$st eq "03"} { incr syn($k) }
        set ipOf($k) $rip
    }
    foreach k [array names est] {
        dict set perIp $k [list $est($k) $syn($k)]
        if {$syn($k) > $maxSyn} {
            ::tg::ban::add $ipOf($k) "$syn($k) half-open connections (SYN flood)" "" monitor
        } elseif {$est($k) > $maxPer} {
            ::tg::ban::add $ipOf($k) "$est($k) simultaneous connections to a protected port" "" monitor
        }
    }
}

proc ::tg::mon::tick {t} {
    variable lastScan
    sampleNet $t
    if {$t - $lastScan >= 5000} {
        set lastScan $t
        scanDirect $t
    }
}
