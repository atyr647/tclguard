# logwatch.tcl -- fail2ban-style log watchers.
# Each watcher tails a file, extracts an address with a regex (first capture
# group) and bans addresses that appear too often within a time window.

namespace eval ::tg::logw {
    variable w          ;# name -> dict config
    array set w {}
    variable pos        ;# name -> byte offset
    array set pos {}
    variable ino
    array set ino {}
    variable carry      ;# name -> incomplete last line
    array set carry {}
    variable err        ;# name -> last error (warn once)
    array set err {}
    variable matched    ;# name -> total matched lines
    array set matched {}
}

proc ::tg::logw::configure {} {
    variable w; variable pos; variable ino; variable carry; variable err; variable matched
    array unset w
    foreach n [array names pos] { if {![dict exists [::tg::cfg::watchers] $n]} { unset -nocomplain pos($n) ino($n) carry($n) } }
    dict for {n spec} [::tg::cfg::watchers] {
        if {![::tg::bool [dict get $spec enabled]]} continue
        set w($n) $spec
        if {![info exists matched($n)]} { set matched($n) 0 }
    }
}

# Pure helper: which address (if any) does this line yield?
proc ::tg::logw::extract {pattern line} {
    if {[catch {regexp -inline -- $pattern $line} m] || ![llength $m]} { return "" }
    set ip [string trim [lindex $m 1]]
    if {[::tg::ip::isValid $ip]} { return [::tg::ip::norm $ip] }
    return ""
}

proc ::tg::logw::feedLine {name line} {
    variable w; variable matched
    set spec $w($name)
    set ip [extract [dict get $spec pattern] $line]
    if {$ip eq ""} return
    incr matched($name)
    if {[::tg::ban::isAllowed $ip]} return
    set key [::tg::ip::key $ip]
    set n [::tg::rate::hit "w:$name:$key" [expr {[dict get $spec window] * 1000}]]
    if {$n >= [dict get $spec hits]} {
        set sec [dict get $spec banSec]
        ::tg::ban::add $ip "log watcher '$name': [expr {int($n)}] matches in [dict get $spec window]s" \
            [expr {$sec == 0 ? "" : $sec}] log
        ::tg::rate::forget "w:$name:$key"
    }
}

proc ::tg::logw::poll {t} {
    variable w; variable pos; variable ino; variable carry; variable err
    foreach name [array names w] {
        set path [dict get $w($name) file]
        if {[catch {file stat $path st}]} {
            if {![info exists err($name)]} {
                set err($name) 1
                ::tg::log::warn "log watcher '$name': cannot read $path (will keep trying)"
            }
            continue
        }
        unset -nocomplain err($name)
        if {![info exists pos($name)]} {
            # first sight: start at the end, never ban from old history
            set pos($name) $st(size); set ino($name) $st(ino); set carry($name) ""
            continue
        }
        if {$st(ino) != $ino($name) || $st(size) < $pos($name)} {
            set pos($name) 0; set ino($name) $st(ino); set carry($name) ""   ;# rotated/truncated
        }
        if {$st(size) == $pos($name)} continue
        if {[catch {
            set fh [open $path r]
            fconfigure $fh -encoding binary -translation binary
            seek $fh $pos($name)
            set data [read $fh 1048576]
            close $fh
        }]} continue
        # offsets are bytes; decode per line so invalid UTF-8 can never shift them
        incr pos($name) [string length $data]
        set text "$carry($name)$data"
        set lines [split $text \n]
        set carry($name) [lindex $lines end]
        foreach line [lrange $lines 0 end-1] {
            feedLine $name [encoding convertfrom utf-8 [string trimright $line \r]]
        }
    }
}

proc ::tg::logw::status {} {
    variable w; variable matched
    set out {}
    foreach n [array names w] { lappend out $n [expr {[info exists matched($n)] ? $matched($n) : 0}] }
    return $out
}
