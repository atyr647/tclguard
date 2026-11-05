# util.tcl -- foundation layer for TclGuard
#
#   ::tg           clock, scheduler, misc helpers
#   ::tg::ip       IPv4/IPv6 parsing, normalisation, CIDR sets
#   ::tg::log      leveled logging with ring buffer + rotating file
#   ::tg::stat     counters, per-second rates, chart series, top talkers
#
# Everything here is pure Tcl 8.6 and has no external dependencies.

namespace eval ::tg {
    variable VERSION 1.0.0
    variable clockSkew 0        ;# milliseconds; tests move time forward with this
    variable lastNow 0
    variable tickCmds {}
    variable tickRunning 0
    variable tickJob ""
    variable tickCount 0
}

# ---------------------------------------------------------------- clock ----

# Never runs backwards: if the wall clock is set back (NTP, a manual change, a VM resume) the step is absorbed, so rate windows keep rolling,
# a 60-second ban still ends after 60 seconds and strike scores do not jump. A step FORWARD is real elapsed time and is left alone.
proc ::tg::now {} {
    variable clockSkew
    variable lastNow
    set t [expr {[clock milliseconds] + $clockSkew}]
    if {$t < $lastNow} {
        incr clockSkew [expr {$lastNow - $t}]
        return $lastNow
    }
    return [set lastNow $t]
}

# ------------------------------------------------------------ scheduler ----
# One 1 Hz heartbeat drives every periodic job. Each job is wrapped in catch so
# a bug in one subsystem can never stop protection in another.

proc ::tg::onTick {cmd} {
    variable tickCmds
    if {$cmd ni $tickCmds} { lappend tickCmds $cmd }
}

proc ::tg::startTicks {} {
    variable tickRunning
    if {$tickRunning} return
    set tickRunning 1
    ::tg::tickLoop
}

proc ::tg::stopTicks {} {
    variable tickRunning
    variable tickJob
    set tickRunning 0
    if {$tickJob ne ""} { after cancel $tickJob; set tickJob "" }
}

proc ::tg::tickLoop {} {
    variable tickCmds
    variable tickRunning
    variable tickJob
    variable tickCount
    if {!$tickRunning} return
    incr tickCount
    set t [::tg::now]
    foreach cmd $tickCmds {
        if {[catch {{*}$cmd $t} err opts]} {
            ::tg::log::warn "tick job failed: $cmd: $err"
            ::tg::log::debug [dict get $opts -errorinfo]
        }
    }
    # Re-align to the second boundary so we never drift.
    set delay [expr {1000 - ([clock milliseconds] % 1000)}]
    if {$delay < 50} { incr delay 1000 }
    set tickJob [after $delay ::tg::tickLoop]
}

# ----------------------------------------------------------- misc helpers ----

proc ::tg::fmtBytes {n} {
    set n [expr {double($n)}]
    foreach u {B KB MB GB TB} {
        if {$n < 1024 || $u eq "TB"} {
            if {$u eq "B"} { return [format "%d B" [expr {int($n)}]] }
            return [format "%.1f %s" $n $u]
        }
        set n [expr {$n / 1024.0}]
    }
}

proc ::tg::fmtRate {n} {
    # n = number per second
    if {$n >= 1e6} { return [format "%.1fM" [expr {$n / 1e6}]] }
    if {$n >= 1e4} { return [format "%.1fk" [expr {$n / 1e3}]] }
    if {$n >= 100} { return [format "%d" [expr {int($n)}]] }
    if {$n == int($n)} { return [format "%d" [expr {int($n)}]] }
    return [format "%.1f" $n]
}

proc ::tg::fmtDuration {sec} {
    set sec [expr {int($sec)}]
    if {$sec < 0} { set sec 0 }
    if {$sec < 60} { return "${sec}s" }
    if {$sec < 3600} { return [format "%dm %02ds" [expr {$sec / 60}] [expr {$sec % 60}]] }
    if {$sec < 86400} { return [format "%dh %02dm" [expr {$sec / 3600}] [expr {($sec % 3600) / 60}]] }
    return [format "%dd %02dh" [expr {$sec / 86400}] [expr {($sec % 86400) / 3600}]]
}

proc ::tg::fmtTime {ms {fmt "%Y-%m-%d %H:%M:%S"}} {
    clock format [expr {$ms / 1000}] -format $fmt
}

# Atomic file write: write to a temp file in the same directory, then rename. The temp file is created exclusively (never through
# a symbolic link somebody planted at a guessable name) with the final permissions from the first byte on: everything this program
# writes can hold a secret (the control token, keys), so the default is owner-only (0600). Files that must be readable by other
# accounts (systemd units, launchd plists, desktop entries, the install record) pass 0644 explicitly. The mode is ignored on Windows.
proc ::tg::writeFileAtomic {path data {mode 0600}} {
    set fh ""
    for {set try 0} {$try < 8} {incr try} {
        set tmp [format "%s.tmp%d-%x%04x" $path [pid] [clock microseconds] [expr {int(rand() * 65536)}]]
        if {![catch {open $tmp [list WRONLY CREAT EXCL] $mode} fh]} break
        set fh ""
    }
    if {$fh eq ""} { error "cannot create a temporary file next to $path: $fh" }
    try {
        fconfigure $fh -encoding utf-8
        puts -nonewline $fh $data
        close $fh
        set fh ""
        file rename -force -- $tmp $path
    } on error {err opts} {
        if {$fh ne ""} { catch {close $fh} }
        catch {file delete -force -- $tmp}
        return -options $opts $err
    }
}

proc ::tg::readFile {path} {
    set fh [open $path r]
    fconfigure $fh -encoding utf-8
    try { return [read $fh] } finally { close $fh }
}

# Case-insensitive boolean parse used by config and control commands.
proc ::tg::bool {v} {
    if {[string is boolean -strict $v]} { return [expr {!!$v}] }
    return 0
}

# Parse "host:port" / "[v6]:port" / "port" into {host port}; {} on error.
proc ::tg::splitHostPort {s {defHost ""}} {
    set s [string trim $s " \t\r\n"]  ;# ASCII only (see ::tg::ip::parse)
    if {[regexp {^\[([^\]]+)\]:(\d+)$} $s -> h p]} {
        # fallthrough to validation
    } elseif {[regexp {^(\d+)$} $s -> p]} {
        set h $defHost
    } elseif {[regexp {^([^:\[\]]+):(\d+)$} $s -> h p]} {
        # fallthrough
    } else {
        return {}
    }
    if {$p < 1 || $p > 65535} { return {} }
    return [list $h [scan $p %d]]
}

proc ::tg::joinHostPort {h p} {
    if {[string first : $h] >= 0} { return "\[$h\]:$p" }
    return "$h:$p"
}

# Strict config-value validators ------------------------------------------------

proc ::tg::isInt {v {min -2147483648} {max 2147483647}} {
    # plain decimal digits only: Tcl's own idea of an integer also accepts 0x10, 0b1, 0o7, leading zeros (octal in expr) and a +
    expr {[regexp {^-?[0-9]{1,15}$} $v] && $v >= $min && $v <= $max}
}

proc ::tg::isNum {v {min -1e18} {max 1e18}} {
    expr {[string is double -strict $v] && $v >= $min && $v <= $max}
}

# bgerror: log instead of popping up modal dialogs on a headless/running guard.
proc ::bgerror {msg} {
    catch {
        ::tg::log::warn "background error: $msg"
        ::tg::log::debug $::errorInfo
    }
}

# =============================================================== ::tg::ip ====

namespace eval ::tg::ip {
    variable kc                  ;# key cache: raw ip string -> ban/limit key
    array set kc {}
    variable kcCount 0
    variable MASK64 [expr {((1 << 64) - 1) << 64}]
    variable sets                ;# set name -> dict {exact {...} ranges {...}}
    array set sets {}
}

# Parse an address. Returns {4 int} or {6 int} (128-bit), or {} when invalid.
# parse and norm are called several times per request with the same few strings (the client address); remember the answers
# (bounded: an attacker sending endless distinct strings only makes the table restart now and then).
namespace eval ::tg::ip { variable pcache; array set pcache {}; variable ncache; array set ncache {}; variable cacheCount 0 }
proc ::tg::ip::parse {s} {
    variable pcache
    variable cacheCount
    if {[info exists pcache($s)]} { return $pcache($s) }
    # ASCII whitespace only: Tcl's default also strips U+00A0 and U+0085, so "\u00a0127.0.0.1" would parse as an address
    set t [string trim $s " \t\r\n"]
    if {[string first % $t] >= 0} { set t [lindex [split $t %] 0] }
    if {[string first : $t] < 0} { set r [parse4 $t] } else { set r [parse6 $t] }
    # (only answers worth remembering: a stream of distinct junk strings must neither fill the table nor evict the real client addresses)
    if {$r eq ""} { return {} }
    if {$cacheCount > 20000} { array unset pcache; array unset ncache; set cacheCount 0 }
    incr cacheCount
    return [set pcache($s) $r]
}

proc ::tg::ip::parse4 {s} {
    if {![regexp {^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$} $s -> a b c d]} { return {} }
    set v 0
    foreach o [list $a $b $c $d] {
        if {[string length $o] > 1 && [string index $o 0] eq "0"} { return {} }
        if {$o > 255} { return {} }
        set v [expr {($v << 8) | $o}]
    }
    return [list 4 $v]
}

proc ::tg::ip::parse6 {s} {
    if {![regexp {^[0-9a-fA-F:.]+$} $s]} { return {} }
    if {[string match *:::* $s]} { return {} }
    set n [regexp -all {::} $s]
    if {$n > 1} { return {} }
    # Embedded IPv4 tail (::ffff:1.2.3.4, 64:ff9b::1.2.3.4) becomes two hextets.
    set tail {}
    if {[string first . $s] >= 0} {
        set li [string last : $s]
        set v4 [parse4 [string range $s [expr {$li + 1}] end]]
        if {$v4 eq ""} { return {} }
        set x [lindex $v4 1]
        set tail [list [format %x [expr {$x >> 16}]] [format %x [expr {$x & 0xffff}]]]
        set s [string range $s 0 $li]
        if {![string match *::* [string range $s end-1 end]]} { set s [string range $s 0 end-1] }
        if {$s eq ""} { return {} }
    }
    if {$n == 1} {
        set idx [string first :: $s]
        set head [string range $s 0 [expr {$idx - 1}]]
        set rest [string range $s [expr {$idx + 2}] end]
        set hg [expr {$head eq "" ? {} : [split $head :]}]
        set tg [expr {$rest eq "" ? {} : [split $rest :]}]
        set tg [concat $tg $tail]
        set fill [expr {8 - [llength $hg] - [llength $tg]}]
        if {$fill < 1} { return {} }
        set groups [concat $hg [lrepeat $fill 0] $tg]
    } else {
        set groups [concat [split $s :] $tail]
    }
    if {[llength $groups] != 8} { return {} }
    set v 0
    foreach g $groups {
        if {![regexp {^[0-9a-fA-F]{1,4}$} $g]} { return {} }
        set v [expr {($v << 16) | [scan $g %x]}]
    }
    return [list 6 $v]
}

proc ::tg::ip::fmt4 {v} {
    format %d.%d.%d.%d [expr {($v >> 24) & 255}] [expr {($v >> 16) & 255}] \
        [expr {($v >> 8) & 255}] [expr {$v & 255}]
}

# RFC 5952 compressed IPv6 text.
proc ::tg::ip::fmt6 {v} {
    set g {}
    for {set i 7} {$i >= 0} {incr i -1} {
        lappend g [expr {($v >> (16 * $i)) & 0xffff}]
    }
    # longest run of zeros, length >= 2
    set bestStart -1; set bestLen 0; set curStart -1; set curLen 0
    for {set i 0} {$i < 8} {incr i} {
        if {[lindex $g $i] == 0} {
            if {$curStart < 0} { set curStart $i; set curLen 0 }
            incr curLen
            if {$curLen > $bestLen} { set bestLen $curLen; set bestStart $curStart }
        } else {
            set curStart -1
        }
    }
    set hex {}
    foreach x $g { lappend hex [format %x $x] }
    if {$bestLen < 2} { return [join $hex :] }
    set left [join [lrange $hex 0 [expr {$bestStart - 1}]] :]
    set right [join [lrange $hex [expr {$bestStart + $bestLen}] end] :]
    return "${left}::${right}"
}

proc ::tg::ip::isValid {s} { expr {[parse $s] ne ""} }

# Canonical text for an address (v4-mapped v6 collapses to v4). "" if invalid.
proc ::tg::ip::norm {s} {
    variable ncache
    if {[info exists ncache($s)]} { return $ncache($s) }
    set p [parse $s]
    if {$p eq ""} { return [set ncache($s) ""] }
    lassign $p fam v
    if {$fam == 4} { set r [fmt4 $v] } elseif {($v >> 32) == 0xffff} { set r [fmt4 [expr {$v & 0xffffffff}]] } else { set r [fmt6 $v] }
    return [set ncache($s) $r]
}

# Limit/ban key: IPv4 exact, IPv6 aggregated to its /64 (attackers routinely own
# an entire /64, so per-address limits would be trivially bypassed).
# The key is also valid firewall syntax ("2001:db8::/64" or "1.2.3.4").
proc ::tg::ip::key {s} {
    variable kc
    variable kcCount
    variable MASK64
    if {[info exists kc($s)]} { return $kc($s) }
    set p [parse $s]
    if {$p eq ""} {
        return $s
    }
    lassign $p fam v
    if {$fam == 4} {
        set k [fmt4 $v]
    } elseif {($v >> 32) == 0xffff} {
        set k [fmt4 [expr {$v & 0xffffffff}]]
    } else {
        set k "[fmt6 [expr {$v & $MASK64}]]/64"
    }
    if {$kcCount > 20000} { array unset kc; set kcCount 0 }
    set kc($s) $k
    incr kcCount
    return $k
}

# Parse "a.b.c.d", "a.b.c.d/n", "v6", "v6/n" -> {fam prefixLen netInt} or {}
proc ::tg::ip::parseCidr {s} {
    set s [string trim $s " \t\r\n"]
    if {$s eq ""} { return {} }
    set bits -1
    if {[regexp {^([^/]+)/(\d{1,3})$} $s -> a bits]} {
        set s $a
        # decimal, always: "/010" is not octal 8 and "/08" is not an error (a leading zero means a typo, so refuse it)
        if {[string length $bits] > 1 && [string index $bits 0] eq "0"} { return {} }
    }
    set p [parse $s]
    if {$p eq ""} { return {} }
    lassign $p fam v
    set max [expr {$fam == 4 ? 32 : 128}]
    if {$fam == 6 && ($v >> 32) == 0xffff && $bits >= 96} {
        # v4-mapped prefix: treat as v4
        set fam 4; set v [expr {$v & 0xffffffff}]; set max 32; set bits [expr {$bits - 96}]
    }
    if {$bits < 0} { set bits $max }
    if {$bits > $max} { return {} }
    set shift [expr {$max - $bits}]
    list $fam $bits [expr {($v >> $shift) << $shift}]
}

proc ::tg::ip::isTarget {s} { expr {[parseCidr $s] ne ""} }

# Convert a user supplied ip/cidr into canonical text ("" if invalid).
proc ::tg::ip::normCidr {s} {
    set c [parseCidr $s]
    if {$c eq ""} { return "" }
    lassign $c fam bits net
    if {$fam == 4} {
        if {$bits == 32} { return [fmt4 $net] }
        return "[fmt4 $net]/$bits"
    }
    if {$bits == 128} { return [fmt6 $net] }
    return "[fmt6 $net]/$bits"
}

# ---- sets: exact addresses live in a hash, ranges in a list ------------------

proc ::tg::ip::setClear {name} {
    variable sets
    set sets($name) [dict create exact {} ranges {} src {}]
}

proc ::tg::ip::setLoad {name items} {
    variable sets
    setClear $name
    set bad {}
    foreach it $items {
        if {![setAdd $name $it]} { lappend bad $it }
    }
    return $bad
}

proc ::tg::ip::setAdd {name item} {
    variable sets
    if {![info exists sets($name)]} { setClear $name }
    set c [parseCidr $item]
    if {$c eq ""} { return 0 }
    lassign $c fam bits net
    set max [expr {$fam == 4 ? 32 : 128}]
    set txt [normCidr $item]
    dict lappend sets($name) src $txt
    if {$bits == $max} {
        dict set sets($name) exact "$fam,$net" 1
    } else {
        dict lappend sets($name) ranges [list $fam [expr {$max - $bits}] [expr {$net >> ($max - $bits)}]]
    }
    return 1
}

proc ::tg::ip::setItems {name} {
    variable sets
    if {![info exists sets($name)]} { return {} }
    dict get $sets($name) src
}

# Does the range/address `target` overlap any item of the set (either contains the other)? Used to refuse bans that would cover allow-listed addresses.
proc ::tg::ip::overlapsSet {name target} {
    set t [parseCidr $target]
    if {$t eq ""} { return 0 }
    lassign $t tf tb tn
    foreach item [setItems $name] {
        set c [parseCidr $item]
        if {$c eq ""} continue
        lassign $c cf cb cn
        if {$cf != $tf} continue
        set max [expr {$tf == 4 ? 32 : 128}]
        set m [expr {min($tb, $cb)}]
        set sh [expr {$max - $m}]
        if {($tn >> $sh) == ($cn >> $sh)} { return 1 }
    }
    return 0
}

proc ::tg::ip::setMatch {name s} {
    variable sets
    if {![info exists sets($name)]} { return 0 }
    set p [parse $s]
    if {$p eq ""} { return 0 }
    lassign $p fam v
    if {$fam == 6 && ($v >> 32) == 0xffff} { set fam 4; set v [expr {$v & 0xffffffff}] }
    if {[dict exists $sets($name) exact "$fam,$v"]} { return 1 }
    foreach r [dict get $sets($name) ranges] {
        lassign $r f shift ns
        if {$f == $fam && ($v >> $shift) == $ns} { return 1 }
    }
    return 0
}

# Private / loopback / link-local detection (used to warn about misconfiguration).
proc ::tg::ip::isPrivate {s} {
    set p [parse $s]
    if {$p eq ""} { return 0 }
    foreach c {127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 ::1 fe80::/10 fc00::/7} {
        lassign [parseCidr $c] fam bits net
        lassign $p f v
        if {$f != $fam} continue
        set max [expr {$fam == 4 ? 32 : 128}]
        if {($v >> ($max - $bits)) == ($net >> ($max - $bits))} { return 1 }
    }
    return 0
}

# Expand a hosts-or-cidrs text blob (whitespace, commas, newlines, # comments).
proc ::tg::ip::parseList {text} {
    set out {}
    foreach line [split $text \n] {
        set line [lindex [split $line #] 0]
        foreach tok [split [string map {, " " ; " "} $line]] {
            set tok [string trim $tok]
            if {$tok ne ""} { lappend out $tok }
        }
    }
    return $out
}

# ============================================================== ::tg::log ====

namespace eval ::tg::log {
    variable ring {}
    variable ringMax 3000
    variable level info
    variable levels {debug 0 info 1 warn 2 alert 3}
    variable sinks {}
    variable fh ""
    variable file ""
    variable written 0
    variable maxBytes 5242880
    variable keep 3
    variable stderr 1
}

proc ::tg::log::setLevel {l} {
    variable level
    variable levels
    if {[dict exists $levels $l]} { set level $l }
}

proc ::tg::log::setFile {path} {
    variable fh
    variable file
    variable written
    if {$fh ne ""} { catch {close $fh}; set fh "" }
    set file $path
    if {$path eq ""} return
    if {[catch {
        file mkdir [file dirname $path]
        # never append through a symbolic link (a program running as root must not write its log into whatever the link names)
        if {![catch {file type $path} ft] && $ft eq "link"} { error "refusing to write the log through a symbolic link" }
        set fh [open $path a]
        fconfigure $fh -encoding utf-8 -buffering line
        set written [file size $path]
    } err]} {
        set fh ""
        set file ""
        warn "cannot open log file $path: $err"
    }
}

proc ::tg::log::addSink {cmd} {
    variable sinks
    if {$cmd ni $sinks} { lappend sinks $cmd }
}

proc ::tg::log::rotate {} {
    variable fh
    variable file
    variable keep
    variable written
    catch {close $fh}
    for {set i [expr {$keep - 1}]} {$i >= 1} {incr i -1} {
        if {[file exists $file.$i]} { catch {file rename -force $file.$i $file.[expr {$i + 1}]} }
    }
    catch {file rename -force $file $file.1}
    set fh [open $file a]
    fconfigure $fh -encoding utf-8 -buffering line
    set written 0
}

proc ::tg::log::msg {lvl text} {
    variable level
    variable levels
    variable ring
    variable ringMax
    variable sinks
    variable fh
    variable written
    variable maxBytes
    variable stderr
    if {[dict get $levels $lvl] < [dict get $levels $level]} return
    set ms [::tg::now]
    # Never let control characters from attackers (log injection) into logs.
    set text [string map [list \n { } \r { } \t { }] $text]
    lappend ring [list $ms $lvl $text]
    if {[llength $ring] > $ringMax} { set ring [lrange $ring end-[expr {$ringMax - 500}] end] }
    set line "[::tg::fmtTime $ms] [string toupper $lvl] $text"
    if {$fh ne ""} {
        catch {
            puts $fh $line
            incr written [string length $line]
            if {$written > $maxBytes} { rotate }
        }
    }
    if {$stderr} { catch {puts stderr $line} }
    foreach s $sinks {
        catch {{*}$s $ms $lvl $text}
    }
}

proc ::tg::log::debug {t} { msg debug $t }
proc ::tg::log::info  {t} { msg info  $t }
proc ::tg::log::warn  {t} { msg warn  $t }
proc ::tg::log::alert {t} { msg alert $t }

proc ::tg::log::tail {{n 200} {minLevel debug}} {
    variable ring
    variable levels
    set out {}
    set min [dict get $levels $minLevel]
    foreach e $ring {
        if {[dict get $levels [lindex $e 1]] >= $min} { lappend out $e }
    }
    lrange $out end-[expr {$n - 1}] end
}

# ============================================================== ::tg::stat ===
# Counters are cheap (array incr). Once per second sample() converts deltas into
# rates and appends to chart series. Top talkers are tracked per 5 s window.

namespace eval ::tg::stat {
    variable c            ;# total counters
    array set c {}
    variable last         ;# counters at previous sample
    array set last {}
    variable rate         ;# per-second rates
    array set rate {}
    variable names {ok blocked conn connRej req reqBlocked udpIn udpDrop bytesIn bytesOut bans strikes kernelDrop}
    variable series {}    ;# list of {ms ok blocked}, newest last
    variable seriesMax 600
    variable tk           ;# talkers (current window): ip -> {ok blocked bytes}
    array set tk {}
    variable top {}       ;# last computed top talkers
    variable topAt 0
    variable started [clock seconds]
    foreach n $names { set c($n) 0; set last($n) 0; set rate($n) 0.0 }
}

proc ::tg::stat::incr {name {n 1}} {
    variable c
    if {[info exists c($name)]} { ::incr c($name) $n } else { set c($name) $n }
}

proc ::tg::stat::get {name} {
    variable c
    if {[info exists c($name)]} { return $c($name) }
    return 0
}

proc ::tg::stat::rateOf {name} {
    variable rate
    if {[info exists rate($name)]} { return $rate($name) }
    return 0.0
}

# kind: ok | blocked ; ip is the limit key
proc ::tg::stat::talk {ip kind {bytes 0}} {
    variable tk
    if {[info exists tk($ip)]} {
        lassign $tk($ip) o b by
    } else {
        if {[array size tk] > 5000} return   ;# bound memory during huge floods
        set o 0; set b 0; set by 0
    }
    if {$kind eq "ok"} { ::incr o } else { ::incr b }
    set tk($ip) [list $o $b [expr {$by + $bytes}]]
}

proc ::tg::stat::sample {t} {
    variable c
    variable last
    variable rate
    variable series
    variable seriesMax
    variable tk
    variable top
    variable topAt
    foreach n [array names c] {
        set l [expr {[info exists last($n)] ? $last($n) : 0}]
        set rate($n) [expr {double($c($n) - $l)}]
        set last($n) $c($n)
    }
    lappend series [list $t $rate(ok) $rate(blocked)]
    if {[llength $series] > $seriesMax} { set series [lrange $series end-[expr {$seriesMax - 1}] end] }
    if {$t - $topAt >= 5000} {
        set topAt $t
        set rows {}
        foreach ip [array names tk] {
            lassign $tk($ip) o b by
            lappend rows [list $ip $o $b $by]
        }
        set top [lrange [lsort -decreasing -integer -index 1 \
            [lsort -decreasing -integer -index 2 $rows]] 0 14]
        # sort by total activity
        set rows2 {}
        foreach r $rows { lappend rows2 [list {*}$r [expr {[lindex $r 1] + [lindex $r 2]}]] }
        set top {}
        foreach r [lrange [lsort -decreasing -integer -index 4 $rows2] 0 14] {
            lappend top [lrange $r 0 3]
        }
        array unset tk
    }
}

proc ::tg::stat::snapshot {} {
    variable c
    variable rate
    dict create counters [array get c] rates [array get rate]
}

proc ::tg::stat::resetForTests {} {
    variable c
    variable last
    variable rate
    variable series
    variable tk
    variable top
    foreach n [array names c] { set c($n) 0; set last($n) 0; set rate($n) 0.0 }
    set series {}
    array unset tk
    set top {}
}

# 'quoted' PowerShell string. PowerShell also treats the typographic single quotes as quotes.
proc ::tg::psq {s} {
    string cat ' [string map [list ' '' \u2018 \u2018\u2018 \u2019 \u2019\u2019 \u201a \u201a\u201a \u201b \u201b\u201b] $s] '
}
