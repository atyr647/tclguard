# udprelay.tcl -- UDP session relay for game servers.
#
# Each client (ip:port) gets its own upstream socket, so the game server sees a
# stable "connection" from 127.0.0.1:<random port> and replies map back to the
# right player. Per-address limits (packets/s, bytes/s, sessions, new-session
# rate, packet size, reply bandwidth) are applied before anything is forwarded.
#
# Needs the tcludp extension ("udp" package). The game server only ever talks to
# this relay, so it should listen on 127.0.0.1 (or be firewalled from the world).
#
# A note on spoofing: UDP source addresses can be forged. Banning is therefore
# temporary and escalating, allowlisted addresses are never banned, and
# "banOffenders no" turns bans off for a listener (limits still drop packets).

namespace eval ::tg::udp {
    variable available 0
    variable srv            ;# listener name -> listening channel
    array set srv {}
    variable cfg
    array set cfg {}
    variable byChan         ;# any udp channel -> {kind name ?id?}
    array set byChan {}
    variable sess           ;# "name,ip:port" -> id
    array set sess {}
    variable nextId 0
    variable total 0
    variable nsess          ;# name -> sessions
    array set nsess {}
    variable perip          ;# "name,key" -> sessions
    array set perip {}
    # per-session data, keyed by id
    variable su; variable sname; variable sip; variable sport; variable skey
    variable sact; variable st0; variable spin; variable spout; variable snoted
    foreach v {su sname sip sport skey sact st0 spin spout snoted} { array set $v {} }
}

proc ::tg::udp::init {} {
    variable available
    if {[catch {package require udp}]} {
        set available 0
        return 0
    }
    set available 1
    return 1
}

proc ::tg::udp::start {name L} {
    variable available
    variable srv; variable cfg; variable byChan; variable nsess
    if {!$available} {
        ::tg::log::alert "UDP listener '$name' needs the tcludp extension, which is not available in this build"
        return 0
    }
    if {[info exists srv($name)]} { stop $name }
    if {[dict get $L bind] ni {0.0.0.0 ::}} {
        ::tg::log::warn "listener '$name': UDP listeners bind to all interfaces; bind address [dict get $L bind] is ignored (use the firewall to restrict)"
    }
    # bind :: opens an IPv6 socket (add a second listener with bind 0.0.0.0 for IPv4 clients on the same port)
    set openCmd [expr {[dict get $L bind] eq "::" ? [list udp_open [dict get $L port] ipv6] : [list udp_open [dict get $L port]]}]
    if {[catch {{*}$openCmd} s err]} {
        ::tg::log::alert "cannot open UDP port [dict get $L port] for '$name': $s"
        return 0
    }
    if {[catch {fconfigure $s -blocking 0 -buffering none -translation binary -buffersize 65536}]} {
        catch {close $s}
        return 0
    }
    set cfg($name) $L
    set srv($name) $s
    set nsess($name) 0
    set byChan($s) [list listen $name]
    fileevent $s readable [list ::tg::udp::inbound $name]
    ::tg::log::info "listening on UDP [expr {[dict get $L bind] eq "::" ? "(IPv6) " : ""}][dict get $L port] -> [::tg::joinHostPort [dict get $L backendHost] [dict get $L backendPort]]  \[$name\]"
    return 1
}

proc ::tg::udp::stop {name} {
    variable srv; variable cfg; variable byChan
    variable sname
    foreach id [array names sname] {
        if {$sname($id) eq $name} { closeSession $id }
    }
    if {[info exists srv($name)]} {
        catch {fileevent $srv($name) readable {}}
        catch {close $srv($name)}
        unset -nocomplain byChan($srv($name))
        unset srv($name)
    }
    unset -nocomplain cfg($name)
}

proc ::tg::udp::stopAll {} { variable srv; foreach n [array names srv] { stop $n } }
proc ::tg::udp::listening {} { variable srv; array names srv }

# Client -> server direction.
proc ::tg::udp::inbound {name} {
    variable srv; variable cfg; variable sess; variable perip; variable nsess; variable total
    variable su; variable sact; variable spin
    if {![info exists srv($name)]} return
    set s $srv($name)
    if {[catch {
        set data [read $s]
        set peer [fconfigure $s -peer]
    }]} return
    lassign $peer ip port
    set L $cfg($name)
    set len [string length $data]
    set key [::tg::ip::key $ip]

    if {[::tg::ban::check $ip]} {
        ::tg::stat::incr udpDrop
        ::tg::stat::incr blocked
        ::tg::stat::talk $key blocked
        return
    }
    set priv [::tg::ban::isAllowed $ip]
    set ban [expr {[dict exists $L banOffenders] ? [::tg::bool [dict get $L banOffenders]] : 1}]
    set addr "$name,$ip:$port"

    # size sanity first: cheapest check, kills runts and oversize junk
    if {$len < [dict get $L minPacket] || $len > [dict get $L maxPacket]} {
        drop $ip $key $ban 0.5 "bad UDP packet size ($len) on $name"
        return
    }
    if {!$priv && [::tg::level::get] >= 3 && ![::tg::trust::known $ip]} {
        drop $ip $key 0 0 ""
        return
    }
    set f [::tg::level::factor]
    if {!$priv} {
        set pps [expr {max(1, int([dict get $L pps] * $f))}]
        if {[::tg::rate::hit "u:$name:$key" 1000] > $pps} {
            drop $ip $key $ban 1 "UDP packet flood on $name"
            return
        }
        set bps [expr {max(1, int([dict get $L bytesPerSec] * $f))}]
        if {[::tg::rate::hit "ub:$name:$key" 1000 $len] > $bps} {
            drop $ip $key $ban 1 "UDP bandwidth flood on $name"
            return
        }
    }

    if {[info exists sess($addr)]} {
        set id $sess($addr)
    } else {
        # ---- new session ----
        if {!$priv} {
            set pk "$name,$key"
            set cur [expr {[info exists perip($pk)] ? $perip($pk) : 0}]
            if {$cur >= [::tg::tcp::scaled [dict get $L maxSessionsPerIP] $ip]} {
                drop $ip $key $ban 1 "too many UDP sessions from one address on $name"
                return
            }
            set win [expr {[dict get $L newSessionWindow] * 1000}]
            if {[::tg::rate::hit "us:$name:$key" $win] > [::tg::tcp::scaled [dict get $L newSessionRate] $ip]} {
                drop $ip $key $ban 1 "UDP session rate on $name"
                return
            }
        }
        if {$nsess($name) >= [dict get $L maxSessions] ||
            [::tg::tcp::connectionCount] + ($total / 2) >= $::tg::tcp::maxTotal} {
            drop $ip $key 0 0 ""
            return
        }
        set id [openSession $name $L $ip $port $key]
        if {$id eq ""} return
    }
    set sact($id) [::tg::now]
    incr spin($id)
    if {[catch {puts -nonewline $su($id) $data}]} { closeSession $id; return }
    ::tg::stat::incr ok
    ::tg::stat::incr udpIn
    ::tg::stat::incr bytesIn $len
    ::tg::stat::talk $key ok $len
}

proc ::tg::udp::drop {ip key ban weight reason} {
    ::tg::stat::incr udpDrop
    ::tg::stat::incr blocked
    ::tg::stat::talk $key blocked
    if {$ban && $weight > 0} { ::tg::ban::strike $ip $weight $reason }
}

proc ::tg::udp::openSession {name L ip port key} {
    variable nextId; variable sess; variable byChan; variable nsess; variable perip; variable total
    variable su; variable sname; variable sip; variable sport; variable skey
    variable sact; variable st0; variable spin; variable spout; variable snoted
    if {[catch {
        set u [udp_open]
        if {[catch {
            fconfigure $u -blocking 0 -buffering none -translation binary -buffersize 65536 \
                -remote [list [dict get $L backendHost] [dict get $L backendPort]]
        } err2]} {
            catch {close $u}          ;# never leak the descriptor on a bad backend address
            error $err2
        }
    } err]} {
        ::tg::log::warn "UDP: cannot open upstream socket for '$name': $err"
        return ""
    }
    set id [incr nextId]
    set now [::tg::now]
    set su($id) $u; set sname($id) $name; set sip($id) $ip; set sport($id) $port; set skey($id) $key
    set sact($id) $now; set st0($id) $now; set spin($id) 0; set spout($id) 0; set snoted($id) 0
    set sess($name,$ip:$port) $id
    set byChan($u) [list up $name $id]
    incr nsess($name); incr total
    set pk "$name,$key"
    if {[info exists perip($pk)]} { incr perip($pk) } else { set perip($pk) 1 }
    fileevent $u readable [list ::tg::udp::outbound $id]
    ::tg::stat::incr conn
    return $id
}

# Server -> client direction.
proc ::tg::udp::outbound {id} {
    variable su; variable sname; variable sip; variable sport; variable skey
    variable sact; variable spout; variable srv; variable cfg
    if {![info exists su($id)]} return
    if {[catch {set data [read $su($id)]}]} { closeSession $id; return }
    set len [string length $data]
    if {$len == 0} return
    set name $sname($id)
    if {![info exists srv($name)]} { closeSession $id; return }
    set L $cfg($name)
    if {![::tg::ban::isAllowed $sip($id)]} {
        # Outbound cap: stops the relay being used as a reflector/amplifier.
        set cap [expr {max(1, int([dict get $L replyBytesPerSec] * [::tg::level::factor]))}]
        if {[::tg::rate::hit "uo:$name:$skey($id)" 1000 $len] > $cap} {
            ::tg::stat::incr udpDrop
            return
        }
    }
    set sact($id) [::tg::now]
    incr spout($id)
    ::tg::stat::incr bytesOut $len
    set s $srv($name)
    if {[catch {
        fconfigure $s -remote [list $sip($id) $sport($id)]
        puts -nonewline $s $data
    }]} { closeSession $id }
}

proc ::tg::udp::closeSession {id} {
    variable su; variable sname; variable sip; variable sport; variable skey
    variable sact; variable st0; variable spin; variable spout; variable snoted
    variable sess; variable byChan; variable nsess; variable perip; variable total
    if {![info exists su($id)]} return
    set name $sname($id)
    catch {fileevent $su($id) readable {}}
    catch {close $su($id)}
    unset -nocomplain byChan($su($id))
    unset -nocomplain sess($name,$sip($id):$sport($id))
    set pk "$name,$skey($id)"
    if {[info exists perip($pk)] && [incr perip($pk) -1] <= 0} { unset perip($pk) }
    if {[info exists nsess($name)]} { incr nsess($name) -1 }
    incr total -1
    foreach v {su sname sip sport skey sact st0 spin spout snoted} { unset -nocomplain ${v}($id) }
}

proc ::tg::udp::dropKey {key info} {
    variable sip
    set n 0
    foreach id [array names sip] {
        if {[::tg::ban::check $sip($id)]} { closeSession $id; incr n }
    }
    if {$n} { ::tg::log::info "closed $n UDP session(s) from banned $key" }
}

proc ::tg::udp::sweep {t} {
    variable sname; variable sact; variable st0; variable spin; variable spout; variable snoted; variable sip
    variable cfg
    foreach id [array names sname] {
        if {![info exists sname($id)]} continue
        set name $sname($id)
        if {![info exists cfg($name)]} { closeSession $id; continue }
        set to [dict get $cfg($name) sessionTimeout]
        if {$t - $sact($id) > $to * 1000} { closeSession $id; continue }
        if {!$snoted($id) && [::tg::bool [dict get $cfg($name) learnTrust]] && $t - $st0($id) > 30000 && $spin($id) >= 20 && $spout($id) >= 20} {
            set snoted($id) 1
            ::tg::trust::note $sip($id)
        }
    }
}

proc ::tg::udp::status {} {
    variable total; variable nsess; variable available
    dict create available $available sessions $total listeners [array get nsess]
}
