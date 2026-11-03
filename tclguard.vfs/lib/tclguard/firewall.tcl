# firewall.tcl -- push bans and rate limits into the operating system firewall.
#
# Why this exists: a Tcl process can inspect thousands of connections per second,
# but a flood is millions of packets per second. The kernel drops packets for a
# few CPU cycles each, so every ban is mirrored there and (optionally) kernel-
# level rate limits protect the proxy ports before a packet reaches user space.
#
# Backends
#   nft       nftables (Linux, preferred; supports bans + hardening rules)
#   iptables  iptables + ipset (Linux, bans only)
#   netsh     Windows Defender Firewall (one rule holding every banned address)
#   none      proxy-level protection only
#
# Every external command goes through ::tg::fw::runner so tests can capture it.
# IP strings are validated before they get anywhere near exec, and exec is always
# called with an argument list (never through a shell).

namespace eval ::tg::fw {
    variable backend none          ;# active backend
    variable wanted auto           ;# configured backend
    variable privileged 0
    variable installed 0
    variable hardened 0
    variable features {}           ;# kernel features that worked: connlimit
    variable lastError ""
    variable queue {}              ;# pending ops {ban key secs|0} / {unban key}
    variable flushJob ""
    variable active                ;# key -> until(ms) mirrored in the kernel
    array set active {}
    variable counters {}           ;# dict name -> packets (last read)
    variable lastCounterTotal 0
    variable runner ::tg::fw::exec_
    variable table tclguard
    variable ruleName "TclGuard Bans"
    variable netshDirty 0
    variable maxNetsh 900
    variable reinstallAt -100000   ;# last automatic reinstall (ms), rate limiter
    variable pfAnchor com.apple/tclguard   ;# evaluated by the stock macOS ruleset ("anchor com.apple/*")
    variable pfTable tclguard_bans
    variable pfToken ""            ;# reference token from "pfctl -E", released on uninstall
}

# ----------------------------------------------------------------- exec ------

# Returns {exitcode output}. Never throws.
proc ::tg::fw::exec_ {argv {input ""}} {
    if {[catch {
        # Tcl requires the "2>@1" redirection to be the last word.
        if {$input ne ""} {
            exec {*}$argv << $input 2>@1
        } else {
            exec {*}$argv 2>@1
        }
    } out opts]} {
        set ec [dict get $opts -errorcode]
        if {[lindex $ec 0] eq "CHILDSTATUS"} { return [list [lindex $ec 2] $out] }
        return [list -1 $out]
    }
    return [list 0 $out]
}

proc ::tg::fw::run {argv {input ""}} {
    variable runner
    {*}$runner $argv $input
}

# ------------------------------------------------------------ detection ------

proc ::tg::fw::which {prog} {
    set p [auto_execok $prog]
    if {$p eq "" || $p eq "0"} {
        # /usr/sbin is often missing from a non-root PATH
        foreach d {/usr/sbin /sbin /usr/local/sbin /usr/bin /bin} {
            if {[file executable [file join $d $prog]]} { return [file join $d $prog] }
        }
        return ""
    }
    return [lindex $p 0]
}

proc ::tg::fw::isPrivileged {} {
    global tcl_platform
    if {$tcl_platform(platform) eq "windows"} {
        lassign [run [list net session]] rc
        return [expr {$rc == 0}]
    }
    if {[catch {exec id -u} uid]} { return 0 }
    expr {$uid == 0}
}

# Which backends could work on this machine (ignoring privileges)?
proc ::tg::fw::available {} {
    global tcl_platform
    set out {}
    if {$tcl_platform(platform) eq "windows"} {
        if {[which netsh] ne ""} { lappend out netsh }
        return $out
    }
    if {$tcl_platform(os) eq "Darwin"} {
        if {[which pfctl] ne ""} { lappend out pf }
        return $out
    }
    if {$tcl_platform(os) ne "Linux"} { return {} }
    if {[which nft] ne ""} { lappend out nft }
    if {[which iptables] ne "" && [which ipset] ne ""} { lappend out iptables }
    return $out
}

proc ::tg::fw::choose {want} {
    set avail [available]
    if {$want eq "none"} { return none }
    if {$want eq "auto"} {
        if {[llength $avail]} { return [lindex $avail 0] }
        return none
    }
    if {$want in $avail} { return $want }
    return ""
}

# ------------------------------------------------------------ public API -----

# Pick a backend, check privileges. Does not touch the system yet.
proc ::tg::fw::init {{want ""}} {
    variable backend
    variable wanted
    variable privileged
    variable lastError
    if {$want eq ""} { set want [::tg::cfg::general firewall] }
    set wanted $want
    set lastError ""
    set privileged [isPrivileged]
    set b [choose $want]
    if {$b eq ""} {
        set lastError "firewall backend '$want' is not available on this system"
        set backend none
        ::tg::log::warn $lastError
        return 0
    }
    set backend $b
    if {$b eq "none"} { return 1 }
    if {!$privileged} {
        set lastError "not running with administrator rights: kernel firewall ($b) disabled, using proxy-level protection only"
        ::tg::log::warn $lastError
        set backend none
        return 0
    }
    return 1
}

proc ::tg::fw::enabled {} { variable backend; expr {$backend ne "none"} }

# ---- allow/ban helpers -------------------------------------------------------

proc ::tg::fw::fam {key} { expr {[string first : $key] >= 0 ? 6 : 4} }

# Remove entries covered by a broader entry so interval sets never conflict.
proc ::tg::fw::minimize {items} {
    set parsed {}
    foreach it $items {
        set c [::tg::ip::parseCidr $it]
        if {$c ne ""} { lappend parsed [list {*}$c $it] }
    }
    set keep {}
    foreach a $parsed {
        lassign $a fa ba na ta
        set covered 0
        foreach b $parsed {
            if {$a eq $b} continue
            lassign $b fb bb nb tb
            if {$fa != $fb} continue
            # b covers a when b is shorter (or equal & earlier) and prefixes match
            if {$bb < $ba || ($bb == $ba && [lsearch -exact $parsed $b] < [lsearch -exact $parsed $a])} {
                set max [expr {$fa == 4 ? 32 : 128}]
                if {($na >> ($max - $bb)) == ($nb >> ($max - $bb))} { set covered 1; break }
            }
        }
        if {!$covered} { lappend keep [::tg::ip::normCidr $ta] }
    }
    lsort -unique $keep
}

# =========================================================== nftables =========

proc ::tg::fw::nftPorts {} {
    set tcp {}; set udp {}
    dict for {name L} [::tg::cfg::listeners] {
        if {![::tg::bool [dict get $L enabled]]} continue
        if {[dict get $L type] eq "udp"} { lappend udp [dict get $L port] } else { lappend tcp [dict get $L port] }
    }
    list [lsort -unique -integer $tcp] [lsort -unique -integer $udp]
}

# Build the complete ruleset text. opts: harden(0/1), connlimit(0/1)
proc ::tg::fw::nftScript {harden connlimit} {
    variable table
    set g {}
    foreach k {hardenSynRate hardenSynBurst hardenConnLimit hardenUdpRate hardenUdpBurst hardenIcmpRate
               hardenDropInvalid hardenDropFragments hardenDropBogusFlags} {
        dict set g $k [::tg::cfg::general $k]
    }
    lassign [nftPorts] tcpPorts udpPorts

    set allow4 {}; set allow6 {}
    foreach it [minimize [::tg::cfg::general allowlist]] {
        if {[fam $it] == 4} { lappend allow4 $it } else { lappend allow6 $it }
    }
    set block4 {}; set block6 {}
    foreach it [minimize [::tg::cfg::general blocklist]] {
        if {[fam $it] == 4} { lappend block4 $it } else { lappend block6 $it }
    }

    set s "add table inet $table\ndelete table inet $table\n"
    append s "table inet $table \{\n"
    append s "    set ban4 \{ type ipv4_addr; flags interval,timeout; \}\n"
    append s "    set ban6 \{ type ipv6_addr; flags interval,timeout; \}\n"
    append s "    set block4 \{ type ipv4_addr; flags interval; [expr {[llength $block4] ? "elements = \{ [join $block4 {, }] \}" : {}}] \}\n"
    append s "    set block6 \{ type ipv6_addr; flags interval; [expr {[llength $block6] ? "elements = \{ [join $block6 {, }] \}" : {}}] \}\n"
    append s "    set allow4 \{ type ipv4_addr; flags interval; [expr {[llength $allow4] ? "elements = \{ [join $allow4 {, }] \}" : {}}] \}\n"
    append s "    set allow6 \{ type ipv6_addr; flags interval; [expr {[llength $allow6] ? "elements = \{ [join $allow6 {, }] \}" : {}}] \}\n"
    foreach c {c_ban c_block} { append s "    counter $c \{ \}\n" }
    append s "    chain ban \{\n"
    append s "        type filter hook prerouting priority -300; policy accept;\n"
    append s "        ip saddr @ban4 counter name c_ban drop\n"
    append s "        ip6 saddr @ban6 counter name c_ban drop\n"
    append s "        ip saddr @block4 counter name c_block drop\n"
    append s "        ip6 saddr @block6 counter name c_block drop\n"
    append s "    \}\n"

    if {$harden} {
        foreach nm {syn4 syn6 udp4 udp6 conn4 conn6} {
            if {$nm in {conn4 conn6} && !$connlimit} continue
            set ty [expr {[string index $nm end] eq "4" ? "ipv4_addr" : "ipv6_addr"}]
            # connlimit elements cannot carry a timeout (the kernel rejects it), the others expire
            set flags [expr {$nm in {conn4 conn6} ? "flags dynamic; size 262144;" : "flags dynamic,timeout; timeout 1m; size 262144;"}]
            append s "    set $nm \{ type $ty; $flags \}\n"
        }
        foreach c {c_invalid c_bogus c_frag c_icmp c_syn c_conn c_udp} { append s "    counter $c \{ \}\n" }
        append s "    chain guard \{\n"
        append s "        type filter hook prerouting priority -150; policy accept;\n"
        append s "        ip saddr @allow4 return\n"
        append s "        ip6 saddr @allow6 return\n"
        if {[::tg::bool [dict get $g hardenDropInvalid]]} {
            append s "        ct state invalid counter name c_invalid drop\n"
        }
        if {[::tg::bool [dict get $g hardenDropBogusFlags]]} {
            append s "        tcp flags & (fin|syn) == (fin|syn) counter name c_bogus drop\n"
            append s "        tcp flags & (syn|rst) == (syn|rst) counter name c_bogus drop\n"
            append s "        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 counter name c_bogus drop\n"
        }
        if {[::tg::bool [dict get $g hardenDropFragments]]} {
            append s "        ip frag-off & 0x3fff != 0 counter name c_frag drop\n"
        }
        set ir [dict get $g hardenIcmpRate]
        append s "        icmp type echo-request limit rate over $ir/second burst [expr {$ir * 2}] packets counter name c_icmp drop\n"
        append s "        icmpv6 type echo-request limit rate over $ir/second burst [expr {$ir * 2}] packets counter name c_icmp drop\n"
        set m6 "ffff:ffff:ffff:ffff::"   ;# rate-limit IPv6 per /64, not per address
        if {[llength $tcpPorts]} {
            set pl "\{ [join $tcpPorts {, }] \}"
            set sr [dict get $g hardenSynRate]; set sb [dict get $g hardenSynBurst]
            append s "        tcp dport $pl tcp flags & (fin|syn|rst|ack) == syn add @syn4 \{ ip saddr limit rate over $sr/second burst $sb packets \} counter name c_syn drop\n"
            append s "        tcp dport $pl tcp flags & (fin|syn|rst|ack) == syn add @syn6 \{ ip6 saddr and $m6 limit rate over $sr/second burst $sb packets \} counter name c_syn drop\n"
            if {$connlimit} {
                set cl [dict get $g hardenConnLimit]
                append s "        tcp dport $pl ct state new add @conn4 \{ ip saddr ct count over $cl \} counter name c_conn drop\n"
                append s "        tcp dport $pl ct state new add @conn6 \{ ip6 saddr and $m6 ct count over $cl \} counter name c_conn drop\n"
            }
        }
        if {[llength $udpPorts]} {
            set pl "\{ [join $udpPorts {, }] \}"
            set ur [dict get $g hardenUdpRate]; set ub [dict get $g hardenUdpBurst]
            append s "        udp dport $pl add @udp4 \{ ip saddr limit rate over $ur/second burst $ub packets \} counter name c_udp drop\n"
            append s "        udp dport $pl add @udp6 \{ ip6 saddr and $m6 limit rate over $ur/second burst $ub packets \} counter name c_udp drop\n"
        }
        append s "    \}\n"
    }
    append s "\}\n"
    return $s
}

proc ::tg::fw::nftInstall {} {
    variable hardened
    variable features
    variable lastError
    set harden [::tg::bool [::tg::cfg::general harden]]
    set features {}
    set connlimit $harden
    set script [nftScript $harden $connlimit]
    lassign [run [list [which nft] -f -] $script] rc out
    if {$rc != 0 && $harden && $connlimit} {
        # Many kernels lack the connlimit module; keep everything else.
        ::tg::log::warn "kernel does not support per-source connection counting (ct count); installing the other hardening rules"
        set script [nftScript $harden 0]
        lassign [run [list [which nft] -f -] $script] rc out
    } elseif {$rc == 0 && $harden} {
        lappend features connlimit
    }
    if {$rc != 0} {
        set lastError "nft failed: [string trim $out]"
        return 0
    }
    set hardened $harden
    return 1
}

proc ::tg::fw::nftRemove {} {
    variable table
    # "add" first so delete never fails when the table is already gone
    lassign [run [list [which nft] -f -] "add table inet $table\ndelete table inet $table\n"] rc out
    expr {$rc == 0}
}

proc ::tg::fw::nftLine {op key secs} {
    variable table
    set set [expr {[fam $key] == 6 ? "ban6" : "ban4"}]
    if {$op eq "ban"} {
        if {$secs > 0} {
            return "add element inet $table $set \{ $key timeout ${secs}s \}"
        }
        return "add element inet $table $set \{ $key \}"
    }
    return "delete element inet $table $set \{ $key \}"
}

# Parse "nft list counters" into {name packets ...}
proc ::tg::fw::nftCounters {} {
    variable table
    lassign [run [list [which nft] list counters table inet $table]] rc out
    if {$rc != 0} { return {} }
    set d {}
    foreach {m name pk} [regexp -all -inline {counter (\w+) \{\s*packets (\d+)} $out] {
        dict set d $name $pk
    }
    return $d
}

# ====================================================== iptables + ipset ======

proc ::tg::fw::ipsInstall {} {
    variable lastError
    set ipset [which ipset]
    foreach {set fam} {tclguard inet tclguard6 inet6} {
        lassign [run [list $ipset create $set hash:net family $fam timeout 0 maxelem 262144 -exist]] rc out
        if {$rc != 0} { set lastError "ipset failed: [string trim $out]"; return 0 }
    }
    foreach {tool set} {iptables tclguard ip6tables tclguard6} {
        set bin [which $tool]
        if {$bin eq ""} continue
        lassign [run [list $bin -t raw -C PREROUTING -m set --match-set $set src -j DROP]] rc
        if {$rc != 0} {
            lassign [run [list $bin -t raw -I PREROUTING -m set --match-set $set src -j DROP]] rc out
            if {$rc != 0} { set lastError "$tool failed: [string trim $out]"; return 0 }
        }
    }
    return 1
}

proc ::tg::fw::ipsRemove {} {
    set ipset [which ipset]
    foreach {tool set} {iptables tclguard ip6tables tclguard6} {
        set bin [which $tool]
        if {$bin ne ""} { run [list $bin -t raw -D PREROUTING -m set --match-set $set src -j DROP] }
        run [list $ipset destroy $set]
    }
    return 1
}

proc ::tg::fw::ipsOp {op key secs} {
    set set [expr {[fam $key] == 6 ? "tclguard6" : "tclguard"}]
    set ipset [which ipset]
    if {$op eq "ban"} {
        if {$secs > 0} { return [list $ipset add $set $key timeout $secs -exist] }
        return [list $ipset add $set $key timeout 0 -exist]
    }
    return [list $ipset del $set $key -exist]
}


# ================================================================ pf (macOS) ===
# Bans only: pf tables have no per-entry timeout, so TclGuard removes expired entries itself
# (the ban manager already tracks expiry). Rules live in the anchor com.apple/tclguard, which the
# stock macOS ruleset already evaluates, so nothing in /etc/pf.conf is modified.

proc ::tg::fw::pfInstall {} {
    variable pfAnchor
    variable pfTable
    variable pfToken
    variable lastError
    set pfctl [which pfctl]
    # enable pf (reference counted: macOS keeps it on until every token is released)
    lassign [run [list $pfctl -E]] rc out
    if {[regexp {Token\s*:\s*(\d+)} $out -> tok]} { set pfToken $tok }
    if {$rc != 0 && ![string match "*already enabled*" $out]} { set lastError "pfctl -E failed: [string trim $out]"; return 0 }
    set rules "table <$pfTable> persist\nblock drop in quick from <$pfTable> to any\n"
    lassign [run [list $pfctl -a $pfAnchor -f -] $rules] rc out
    if {$rc != 0} { set lastError "pfctl anchor load failed: [string trim $out]"; return 0 }
    lassign [run [list $pfctl -a $pfAnchor -t $pfTable -T flush]] rc out
    return 1
}

proc ::tg::fw::pfRemove {} {
    variable pfAnchor
    variable pfToken
    set pfctl [which pfctl]
    run [list $pfctl -a $pfAnchor -F all]
    if {$pfToken ne ""} { run [list $pfctl -X $pfToken]; set pfToken "" }
    return 1
}

# One pfctl call per distinct operation, with every address as an argument.
proc ::tg::fw::pfApply {ops} {
    variable pfAnchor
    variable pfTable
    variable lastError
    set add {}; set del {}
    foreach op $ops {
        lassign $op o key secs
        if {$o eq "ban"} { lappend add $key } else { lappend del $key }
    }
    set pfctl [which pfctl]
    if {[llength $del]} { run [list $pfctl -a $pfAnchor -t $pfTable -T delete {*}$del] }
    if {[llength $add]} {
        lassign [run [list $pfctl -a $pfAnchor -t $pfTable -T add {*}$add]] rc out
        if {$rc != 0} { set lastError "pfctl: [string trim $out]"; ::tg::log::warn "firewall: [string trim $out]" }
    }
}

# ============================================================== netsh =========

proc ::tg::fw::netshApply {} {
    variable ruleName
    variable netshDirty
    variable active
    variable maxNetsh
    variable lastError
    set netshDirty 0
    set keys [lsort [array names active]]
    if {[llength $keys] > $maxNetsh} {
        ::tg::log::warn "Windows Firewall rule holds at most $maxNetsh addresses; [expr {[llength $keys] - $maxNetsh}] bans are enforced by TclGuard proxies only"
        set keys [lrange $keys 0 [expr {$maxNetsh - 1}]]
    }
    set netsh [which netsh]
    if {![llength $keys]} {
        run [list $netsh advfirewall firewall delete rule name=$ruleName]
        return 1
    }
    set ips [join $keys ,]
    lassign [run [list $netsh advfirewall firewall show rule name=$ruleName]] rc
    if {$rc == 0} {
        lassign [run [list $netsh advfirewall firewall set rule name=$ruleName new remoteip=$ips]] rc out
    } else {
        lassign [run [list $netsh advfirewall firewall add rule name=$ruleName dir=in action=block enable=yes profile=any remoteip=$ips]] rc out
    }
    if {$rc != 0} { set lastError "netsh failed: [string trim $out]"; return 0 }
    return 1
}

# ============================================================ common API ======

# Install (or reinstall) kernel state and mirror every current ban into it.
proc ::tg::fw::sync {} {
    variable backend
    variable installed
    variable active
    variable lastError
    variable queue
    if {$backend eq "none"} { return 0 }
    set ok 0
    switch -- $backend {
        nft      { set ok [nftInstall] }
        iptables { set ok [ipsInstall] }
        pf       { set ok [pfInstall] }
        netsh    { set ok 1 }
    }
    if {!$ok} {
        ::tg::log::warn "firewall install failed: $lastError"
        set installed 0
        return 0
    }
    set installed 1
    set lastError ""
    set queue {}
    array unset active
    if {$backend eq "iptables"} { run [list [which ipset] flush tclguard]; run [list [which ipset] flush tclguard6] }
    set t [::tg::now]
    foreach b [::tg::ban::all] {
        set until [dict get $b until]
        if {$until != 0 && $until <= $t} continue
        enqueue ban [dict get $b key] $until
    }
    if {$backend eq "netsh"} { variable netshDirty; set netshDirty 1 }
    commit
    ::tg::log::info "firewall backend '$backend' active[expr {[::tg::bool [::tg::cfg::general harden]] ? {, hardening rules installed} : {}}]"
    return 1
}

proc ::tg::fw::enqueue {op key until} {
    variable queue
    variable active
    variable backend
    variable flushJob
    # Never let anything but a plain address/prefix reach a command line.
    if {[::tg::ip::normCidr $key] ne $key} return      ;# canonical addresses only, never raw text
    if {[llength $queue] > 20000} {
        ::tg::log::warn "firewall queue overflow; dropping oldest entries"
        set queue [lrange $queue 10000 end]
    }
    set secs 0
    if {$until != 0} {
        set secs [expr {max(1, ($until - [::tg::now] + 999) / 1000)}]
    }
    if {$op eq "ban"} {
        # Re-banning (e.g. a longer ban): delete first, or the old shorter timeout stays.
        if {[info exists active($key)]} { lappend queue [list unban $key 0] }
        set active($key) $until
    } else {
        unset -nocomplain active($key)
    }
    lappend queue [list $op $key $secs]
    if {$flushJob eq ""} { set flushJob [after 250 [list ::tg::fw::commit]] }
}

# ban-manager callbacks
proc ::tg::fw::onBan {key info} {
    variable backend
    variable installed
    if {$backend eq "none" || !$installed} return
    enqueue ban $key [dict get $info until]
}

proc ::tg::fw::onUnban {key} {
    variable backend
    variable installed
    if {$backend eq "none" || !$installed} return
    enqueue unban $key 0
}

proc ::tg::fw::commit {} {
    variable queue
    variable backend
    variable flushJob
    variable lastError
    variable installed
    variable netshDirty
    if {$flushJob ne ""} { after cancel $flushJob; set flushJob "" }
    if {$backend eq "netsh"} {
        if {[llength $queue] || $netshDirty} { set queue {}; netshApply }
        return
    }
    if {![llength $queue]} return
    set ops $queue
    set queue {}
    switch -- $backend {
        pf { pfApply $ops }
        nft {
            set lines {}
            foreach op $ops {
                lassign $op o key secs
                lappend lines [nftLine $o $key $secs]
            }
            lassign [run [list [which nft] -f -] [join $lines \n]] rc out
            if {$rc != 0} {
                # Retry one by one so a single bad element can't drop the rest.
                foreach op $ops {
                    lassign $op o key secs
                    lassign [run [list [which nft] -f -] [nftLine $o $key $secs]] rc2 out2
                    if {$rc2 != 0} {
                        if {[string match "*No such file*" $out2] && $o eq "unban"} continue
                        if {[string match "*File exists*" $out2]} continue
                        if {[string match "*No such file*" $out2] && $o eq "ban"} {
                            # Table vanished (someone flushed the ruleset): rebuild it,
                            # but at most once per 30 s so a persistent fault can't loop.
                            variable reinstallAt
                            if {[::tg::now] - $reinstallAt > 30000} {
                                set reinstallAt [::tg::now]
                                ::tg::log::warn "firewall table disappeared; reinstalling"
                                sync
                            } else {
                                set lastError "firewall table keeps disappearing"
                                ::tg::log::warn "firewall: $key could not be added: table missing"
                            }
                            return
                        }
                        set lastError "nft: [string trim $out2]"
                        ::tg::log::warn "firewall: $key: [string trim $out2]"
                    }
                }
            }
        }
        iptables {
            # one process for the whole batch (a mass ban must not stall the event loop)
            set lines {}
            foreach op $ops {
                lassign $op o key secs
                set set [expr {[fam $key] == 6 ? "tclguard6" : "tclguard"}]
                if {$o eq "ban"} { lappend lines "add $set $key timeout $secs" } else { lappend lines "del $set $key" }
            }
            lassign [run [list [which ipset] restore -exist] "[join $lines \n]\n"] rc out
            if {$rc != 0} { ::tg::log::warn "firewall: ipset restore failed: [string trim $out]" }
        }
    }
}

proc ::tg::fw::tick {t} {
    variable backend
    variable installed
    variable lastCounterTotal
    variable counters
    variable active
    if {$backend eq "none" || !$installed} return
    commit
    # Forget kernel-side entries that have expired (the kernel removed them already).
    foreach k [array names active] {
        set u $active($k)
        if {$u != 0 && $u <= $t} { unset active($k) }
    }
    if {$backend eq "nft" && $t % 5000 < 1000} {
        set counters [nftCounters]
        set total 0
        dict for {n v} $counters { incr total $v }
        if {$total >= $lastCounterTotal} {
            ::tg::stat::incr kernelDrop [expr {$total - $lastCounterTotal}]
        }
        set lastCounterTotal $total
    }
}

# Remove everything TclGuard installed in the kernel.
proc ::tg::fw::uninstall {} {
    variable backend
    variable installed
    variable active
    variable hardened
    variable lastCounterTotal
    set ok 1
    switch -- $backend {
        nft      { set ok [nftRemove] }
        iptables { set ok [ipsRemove] }
        pf       { set ok [pfRemove] }
        netsh    { variable ruleName; run [list [which netsh] advfirewall firewall delete rule name=$ruleName] }
    }
    set installed 0
    set hardened 0
    set lastCounterTotal 0
    array unset active
    return $ok
}

proc ::tg::fw::shutdown {} {
    variable backend
    variable installed
    if {$backend eq "none" || !$installed} return
    commit
    if {[::tg::bool [::tg::cfg::general removeRulesOnExit]]} {
        uninstall
        ::tg::log::info "kernel firewall rules removed"
    }
}

proc ::tg::fw::status {} {
    variable backend
    variable wanted
    variable privileged
    variable installed
    variable hardened
    variable features
    variable lastError
    variable counters
    variable active
    dict create backend $backend wanted $wanted available [available] privileged $privileged \
        installed $installed hardened $hardened features $features error $lastError \
        counters $counters entries [array size active]
}

# Text shown in the GUI: what would be installed.
proc ::tg::fw::preview {} {
    variable backend
    set harden [::tg::bool [::tg::cfg::general harden]]
    switch -- $backend {
        nft { return "# nftables ruleset loaded with: nft -f -\n[nftScript $harden $harden]" }
        iptables {
            return "ipset create tclguard hash:net family inet timeout 0\nipset create tclguard6 hash:net family inet6 timeout 0\niptables -t raw -I PREROUTING -m set --match-set tclguard src -j DROP\nip6tables -t raw -I PREROUTING -m set --match-set tclguard6 src -j DROP\n# bans: ipset add tclguard <ip> timeout <sec>"
        }
        pf { return "pfctl -E\npfctl -a com.apple/tclguard -f -        # table <tclguard_bans> persist; block drop in quick from <tclguard_bans> to any\n# bans: pfctl -a com.apple/tclguard -t tclguard_bans -T add <address>" }
        netsh { return "netsh advfirewall firewall add rule name=\"TclGuard Bans\" dir=in action=block remoteip=<banned addresses>" }
    }
    return "(no kernel firewall backend active)"
}
