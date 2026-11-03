# tcpproxy.tcl -- TCP reverse proxy core, shared by "tcp" and "http" listeners.
#
# Accept-time defences (in order): global cap, ban/blocklist, lockdown (unknown
# addresses refused), per-IP concurrent connections, per-IP new-connection rate,
# per-listener cap. Everything is scaled by the current threat level.
#
# Raw TCP listeners relay bytes. HTTP listeners hand the client->backend stream
# to ::tg::http which validates and meters each request before it is forwarded.
#
# The backend connection is made lazily (after the client has proven it can send
# data) so idle attackers never consume a backend socket.

namespace eval ::tg::tcp {
    variable srv            ;# listener name -> server socket
    array set srv {}
    variable cfg            ;# listener name -> filled config dict
    array set cfg {}
    variable nconn          ;# listener name -> current connections
    array set nconn {}
    variable perip          ;# "name,key" -> concurrent connections
    array set perip {}
    variable nextId 0
    variable total 0        ;# current connections, all listeners
    variable maxTotal 0     ;# effective global cap
    # per-connection state, keyed by id
    variable cc             ;# client channel
    variable bc             ;# backend channel ("" until connected)
    variable cl             ;# listener name
    variable cip            ;# client address (peer)
    variable cport
    variable ckey           ;# limit key of the peer
    variable t0
    variable act
    variable dl             ;# deadline ms (0 none)
    variable bin
    variable bout
    variable st             ;# state: wait | connecting | open
    variable cdl            ;# backend connect deadline ms (own slot: must not clobber dl)
    variable late           ;# client half-closed before the backend was ready: finish after flushing
    variable pend           ;# bytes waiting for the backend
    variable eofc           ;# half-close tracking "id,c2b" / "id,b2c"
    variable noted          ;# reputation already recorded
    variable mode
    foreach v {cc bc cl cip cport ckey t0 act dl cdl late bin bout st pend eofc noted mode} { array set $v {} }
    variable lastBackendWarn
    array set lastBackendWarn {}
    variable lastPublicWarn 0
}

# ----------------------------------------------------------- configuration ---

# Effective global connection cap, kept below the process fd limit
# (every proxied connection uses two descriptors).
proc ::tg::tcp::computeMaxTotal {} {
    variable maxTotal
    set want [::tg::cfg::general maxConnections]
    set fdSoft 1024
    if {[file readable /proc/self/limits]} {
        catch {
            set fh [open /proc/self/limits r]
            set txt [read $fh]
            close $fh
            if {[regexp {Max open files\s+(\d+)} $txt -> n]} { set fdSoft $n }
        }
    } elseif {$::tcl_platform(platform) eq "windows"} {
        set fdSoft 2048   ;# Windows has no small fd cap in the C runtime used by Tcl
    }
    set cap [expr {max(16, ($fdSoft - 96) / 2)}]
    if {$want == 0 || $want > $cap} {
        if {$want > $cap} {
            ::tg::log::warn "maxConnections $want is above what this process can hold ($cap, from the open-files limit [expr {$fdSoft}]); using $cap. Raise it with 'ulimit -n' or LimitNOFILE in systemd."
        }
        set want $cap
    }
    set maxTotal $want
    return $want
}

proc ::tg::tcp::scaled {value} {
    set v [expr {int($value * [::tg::level::factor])}]
    expr {max(1, $v)}
}

# ----------------------------------------------------------- start / stop ---

proc ::tg::tcp::start {name L} {
    variable srv
    variable cfg
    variable nconn
    if {[info exists srv($name)]} { stop $name }
    set cfg($name) $L
    set nconn($name) 0
    if {[::tg::tls::enabled $L]} {
        set terr [::tg::tls::prepare $name $L]
        if {$terr ne ""} {
            ::tg::log::alert "listener '$name' not started: $terr"
            unset cfg($name)
            return 0
        }
    }
    set bind [dict get $L bind]
    set port [dict get $L port]
    set args [list -server [list ::tg::tcp::accept $name]]
    if {$bind ne "" && $bind ne "::"} { lappend args -myaddr $bind } elseif {$bind eq "::"} { lappend args -myaddr :: }
    if {[catch {socket {*}$args $port} s err]} {
        ::tg::log::alert "cannot listen on $bind:$port for '$name': $err"
        unset cfg($name)
        return 0
    }
    set srv($name) $s
    set mode [dict get $L type]
    if {$mode eq "http"} { ::tg::http::prepare $name $L }
    if {[::tg::tls::enabled $L]} { append mode "+tls" }
    ::tg::log::info "listening on [::tg::joinHostPort $bind $port] ($mode) -> [::tg::joinHostPort [dict get $L backendHost] [dict get $L backendPort]]  \[$name\]"
    return 1
}

proc ::tg::tcp::stop {name} {
    variable srv
    variable cfg
    if {[info exists srv($name)]} {
        catch {close $srv($name)}
        unset srv($name)
    }
    # close this listener's connections
    variable cl
    foreach id [array names cl] {
        if {$cl($id) eq $name} { close_ $id "listener stopped" }
    }
    unset -nocomplain cfg($name)
    ::tg::tls::stop $name
}

proc ::tg::tcp::stopAll {} {
    variable srv
    foreach n [array names srv] { stop $n }
}

proc ::tg::tcp::listening {} { variable srv; array names srv }

# ----------------------------------------------------------------- accept ---

proc ::tg::tcp::reject {chan name ip key why {strike 0}} {
    catch {close $chan}
    ::tg::stat::incr connRej
    ::tg::stat::incr blocked
    ::tg::stat::talk $key blocked
    if {$strike > 0} { ::tg::ban::strike $ip $strike "$why on $name" }
}

proc ::tg::tcp::accept {name chan ip port} {
    variable cfg
    variable nconn
    variable perip
    variable total
    variable maxTotal
    if {![info exists cfg($name)]} { catch {close $chan}; return }
    set L $cfg($name)
    set key [::tg::ip::key $ip]

    if {[::tg::ban::check $ip]} {
        # Cheapest possible rejection: no logging, no strike.
        catch {close $chan}
        ::tg::stat::incr connRej
        ::tg::stat::incr blocked
        ::tg::stat::talk $key blocked
        return
    }
    set privileged [::tg::ban::isAllowed $ip]
    # UDP sessions hold a descriptor too: count two of them as one proxied connection
    if {$total + ($::tg::udp::total / 2) >= $maxTotal} {
        reject $chan $name $ip $key "global connection cap"
        return
    }
    if {!$privileged} {
        if {[::tg::level::get] >= 3 && ![::tg::trust::known $ip]} {
            reject $chan $name $ip $key "lockdown"
            return
        }
        set pk "$name,$key"
        set cur [expr {[info exists perip($pk)] ? $perip($pk) : 0}]
        if {$cur >= [scaled [dict get $L maxConnsPerIP]]} {
            reject $chan $name $ip $key "too many connections" 1
            return
        }
        set win [expr {[dict get $L connWindow] * 1000}]
        if {[::tg::rate::hit "c:$name:$key" $win] > [scaled [dict get $L connRate]]} {
            reject $chan $name $ip $key "connection rate" 1
            return
        }
    }
    if {$nconn($name) >= [dict get $L maxConns]} {
        reject $chan $name $ip $key "listener full"
        return
    }
    newConn $name $L $chan $ip $port $key
}

proc ::tg::tcp::newConn {name L chan ip port key} {
    variable nextId
    variable cc; variable bc; variable cl; variable cip; variable cport; variable ckey
    variable t0; variable act; variable dl; variable cdl; variable late; variable bin; variable bout; variable st
    variable pend; variable noted; variable mode
    variable nconn; variable perip; variable total
    set id [incr nextId]
    set now [::tg::now]
    set cc($id) $chan; set bc($id) ""; set cl($id) $name; set cip($id) $ip; set cport($id) $port
    set ckey($id) $key; set t0($id) $now; set act($id) $now; set bin($id) 0; set bout($id) 0
    set st($id) wait; set pend($id) ""; set noted($id) 0; set dl($id) 0; set cdl($id) 0; set late($id) 0
    set mode($id) [dict get $L type]
    incr nconn($name)
    incr total
    set pk "$name,$key"
    if {[info exists perip($pk)]} { incr perip($pk) } else { set perip($pk) 1 }
    if {[catch {fconfigure $chan -blocking 0 -buffering none -translation binary -encoding binary} err]} {
        close_ $id "socket error"
        return
    }
    ::tg::stat::incr conn
    if {[::tg::tls::enabled $L]} {
        ::tg::tls::start $id $chan $name $L      ;# continues in ready{} once the handshake is done
        return
    }
    ready $id
}

# The client connection is usable (immediately for plaintext, after the handshake for TLS):
# start the HTTP inspector or the raw relay.
proc ::tg::tcp::ready {id} {
    variable cc; variable cl; variable cfg; variable ckey; variable cip; variable dl; variable mode
    if {![info exists cc($id)]} return
    set name $cl($id); set L $cfg($name); set chan $cc($id); set key $ckey($id); set ip $cip($id)
    set now [::tg::now]
    if {$mode($id) eq "http"} {
        ::tg::http::begin $id $name $L $ip $key
        fileevent $chan readable [list ::tg::http::clientReadable $id]
    } else {
        ::tg::stat::incr ok
        ::tg::stat::talk $key ok
        if {[::tg::bool [dict get $L lazyConnect]]} {
            set fb [dict get $L firstByteTimeout]
            if {$fb > 0} { set dl($id) [expr {$now + $fb * 1000}] }
            fileevent $chan readable [list ::tg::tcp::firstData $id]
        } else {
            connectBackend $id
        }
    }
}

# ---------------------------------------------------------- raw tcp: setup ---

proc ::tg::tcp::firstData {id} {
    variable cc; variable pend; variable bin; variable act; variable dl
    if {![info exists cc($id)]} return
    set chan $cc($id)
    if {[catch {read $chan 65536} data]} { close_ $id "read error"; return }
    if {[string length $data]} {
        append pend($id) $data
        incr bin($id) [string length $data]
        set act($id) [::tg::now]
        set dl($id) 0
        fileevent $chan readable {}
        connectBackend $id
        return
    }
    if {[eof $chan]} { close_ $id "client closed before sending data" }
}

# Start the async connect to the backend (idempotent).
proc ::tg::tcp::connectBackend {id} {
    variable st; variable cl; variable cfg; variable bc
    if {![info exists st($id)] || $st($id) ne "wait"} return
    set L $cfg($cl($id))
    set st($id) connecting
    if {[catch {
        socket -async [dict get $L backendHost] [dict get $L backendPort]
    } b err]} {
        backendFailed $id "connect failed: $b"
        return
    }
    set bc($id) $b
    fileevent $b writable [list ::tg::tcp::backendReady $id]
    variable cdl
    set cdl($id) [expr {[::tg::now] + 10000}]
}

proc ::tg::tcp::backendReady {id} {
    variable bc; variable cc; variable st; variable cl; variable cfg; variable cdl; variable mode
    if {![info exists bc($id)]} return
    set b $bc($id)
    if {[catch {fileevent $b writable {}}]} {
        backendFailed $id "connect failed"
        return
    }
    if {[catch {fconfigure $b -error} e] || $e ne ""} {
        backendFailed $id [expr {$e eq "" ? "connect failed" : $e}]
        return
    }
    if {[catch {fconfigure $b -blocking 0 -buffering none -translation binary -encoding binary}]} {
        backendFailed $id "socket error"
        return
    }
    set L $cfg($cl($id))
    set st($id) open
    set cdl($id) 0
    # PROXY protocol header carries the real client address to the backend.
    set hdr ""
    switch -- [dict get $L proxyProtocol] {
        v1 { set hdr [proxyV1 $id] }
        v2 { set hdr [proxyV2 $id] }
    }
    variable pend
    set first "$hdr$pend($id)"
    set pend($id) ""
    if {[string length $first]} {
        if {[catch {puts -nonewline $b $first}]} { close_ $id "backend write error"; return }
    }
    if {$mode($id) eq "http"} {
        ::tg::http::backendUp $id
    } else {
        fileevent $cc($id) readable [readerFor $id c2b]
    }
    fileevent $b readable [readerFor $id b2c]
    # The client already finished sending (half-close) while we were connecting:
    # everything it sent is now queued to the backend, so pass the half-close on.
    variable late
    if {[info exists late($id)] && $late($id)} { sideClosed $id c2b $cc($id) $b }
}

proc ::tg::tcp::backendFailed {id why} {
    variable cl; variable lastBackendWarn; variable mode; variable cc
    set name $cl($id)
    set now [::tg::now]
    if {![info exists lastBackendWarn($name)] || $now - $lastBackendWarn($name) > 30000} {
        set lastBackendWarn($name) $now
        ::tg::log::warn "backend for '$name' unreachable: $why"
    }
    ::tg::stat::incr backendErr
    if {$mode($id) eq "http" && [info exists cc($id)]} {
        ::tg::http::respondRaw $id 502 "Bad Gateway" "The service behind this site is not reachable."
        return
    }
    close_ $id "backend unreachable"
}

# ------------------------------------------------------------- PROXY proto ---

proc ::tg::tcp::proxyV1 {id} {
    variable cc; variable cip; variable cport
    set ip [::tg::ip::norm $cip($id)]
    if {[catch {fconfigure $cc($id) -sockname} sn]} { set sn [list 0.0.0.0 0.0.0.0 0] }
    lassign $sn dip _ dport
    set dip [::tg::ip::norm $dip]
    set fam [expr {[string first : $ip] >= 0 ? "TCP6" : "TCP4"}]
    if {$dip eq "" || ([string first : $dip] >= 0) != ([string first : $ip] >= 0)} {
        return "PROXY UNKNOWN\r\n"
    }
    return "PROXY $fam $ip $dip $cport($id) $dport\r\n"
}

proc ::tg::tcp::proxyV2 {id} {
    variable cc; variable cip; variable cport
    set sig "\r\n\r\n\x00\r\nQUIT\n"
    set ip [::tg::ip::norm $cip($id)]
    if {[catch {fconfigure $cc($id) -sockname} sn]} { set sn [list 0.0.0.0 0.0.0.0 0] }
    lassign $sn dip _ dport
    set dip [::tg::ip::norm $dip]
    lassign [::tg::ip::parse $ip] fam sv
    lassign [::tg::ip::parse $dip] dfam dv
    if {$fam eq "" || $dfam eq "" || $fam != $dfam} {
        return "${sig}\x20\x00\x00\x00"        ;# LOCAL command, no addresses
    }
    if {$fam == 4} {
        set body [binary format IISS $sv $dv $cport($id) $dport]
        return "${sig}\x21\x11[binary format S [string length $body]]$body"
    }
    set m64 0xffffffffffffffff
    set sb [binary format WW [expr {($sv >> 64) & $m64}] [expr {$sv & $m64}]]
    set db [binary format WW [expr {($dv >> 64) & $m64}] [expr {$dv & $m64}]]
    set body "$sb$db[binary format SS $cport($id) $dport]"
    return "${sig}\x21\x21[binary format S [string length $body]]$body"
}

# ------------------------------------------------------------------- relay ---

# The fileevent script that reads one direction. HTTP listeners parse the
# client->backend stream; everything else is a plain byte pump.
proc ::tg::tcp::readerFor {id dir} {
    variable mode
    if {$mode($id) eq "http" && $dir eq "c2b"} { return [list ::tg::http::clientReadable $id] }
    list ::tg::tcp::pump $id $dir
}

# Copy one chunk from one side to the other with flow control.
proc ::tg::tcp::pump {id dir} {
    variable cc; variable bc; variable bin; variable bout; variable act; variable cl; variable mode
    if {![info exists cc($id)]} return
    if {$dir eq "c2b"} {
        set from $cc($id); set to $bc($id)
    } else {
        set from $bc($id); set to $cc($id)
    }
    if {$from eq "" || $to eq ""} return
    if {[catch {read $from 65536} data]} { close_ $id "read error"; return }
    set n [string length $data]
    if {$n} {
        set act($id) [::tg::now]
        if {$dir eq "c2b"} { incr bin($id) $n } else {
            incr bout($id) $n
            if {$mode($id) eq "http"} { ::tg::http::onResponseData $id $data }
        }
        ::tg::stat::incr [expr {$dir eq "c2b" ? "bytesIn" : "bytesOut"}] $n
        if {[catch {puts -nonewline $to $data}]} { close_ $id "write error"; return }
        if {[chan pending output $to] > 262144} { throttle $id $dir $from $to }
    }
    if {[eof $from]} { sideClosed $id $dir $from $to }
}

# Stop reading `from` until `to` has drained.
proc ::tg::tcp::throttle {id dir from to} {
    fileevent $from readable {}
    fileevent $to writable [list ::tg::tcp::drained $id $dir $from $to]
}

proc ::tg::tcp::drained {id dir from to} {
    variable cc
    if {![info exists cc($id)]} return
    if {[catch {chan pending output $to} p] || $p > 65536} return
    fileevent $to writable {}
    if {[catch {fileevent $from readable [readerFor $id $dir]}]} return
    ::tg::tcp::resumed $id $dir
}

# Hook: HTTP mode may need to continue processing buffered data after a resume.
proc ::tg::tcp::resumed {id dir} {
    variable mode
    if {$mode($id) eq "http" && $dir eq "c2b"} {
        ::tg::http::resume $id
    }
}

# One direction hit EOF: propagate as a half-close once pending data is flushed.
proc ::tg::tcp::sideClosed {id dir from to} {
    variable eofc; variable cc; variable bc; variable st; variable late
    fileevent $from readable {}
    if {$dir eq "c2b" && $st($id) ne "open"} {
        # Backend not connected yet: closing its write side now would lose the
        # request that is waiting in the queue. backendReady finishes the job.
        set late($id) 1
        return
    }
    set eofc($id,$dir) 1
    if {[info exists eofc($id,c2b)] && [info exists eofc($id,b2c)]} {
        close_ $id "finished"
        return
    }
    if {[catch {chan pending output $to} p] || $p == 0} {
        halfClose $id $to
    } else {
        fileevent $to writable [list ::tg::tcp::flushThenHalfClose $id $to]
    }
}

proc ::tg::tcp::flushThenHalfClose {id to} {
    variable cc
    if {![info exists cc($id)]} return
    if {[catch {chan pending output $to} p] || $p > 0} return
    fileevent $to writable {}
    halfClose $id $to
}

proc ::tg::tcp::halfClose {id to} {
    if {[catch {chan close $to write}]} { close_ $id "finished" }
}

# --------------------------------------------------------------- teardown ---

proc ::tg::tcp::close_ {id {why ""}} {
    variable cc; variable bc; variable cl; variable cip; variable cport; variable ckey
    variable t0; variable act; variable dl; variable cdl; variable late; variable bin; variable bout; variable st
    variable pend; variable noted; variable mode; variable eofc
    variable nconn; variable perip; variable total
    if {![info exists cc($id)]} return
    set name $cl($id)
    foreach ch [list $cc($id) $bc($id)] {
        if {$ch ne ""} {
            catch {fileevent $ch readable {}}
            catch {fileevent $ch writable {}}
            catch {close $ch}
        }
    }
    if {$st($id) eq "hs"} { ::tg::tls::forget $id }
    if {$mode($id) eq "http"} { catch {::tg::http::end $id} }
    if {!$noted($id) && [expr {[::tg::now] - $t0($id)}] > 20000 && $bin($id) > 0 && $bout($id) > 0 && $mode($id) ne "http"} {
        ::tg::trust::note $cip($id)
    }
    set pk "$name,$ckey($id)"
    if {[info exists perip($pk)]} {
        if {[incr perip($pk) -1] <= 0} { unset perip($pk) }
    }
    if {[info exists nconn($name)]} { incr nconn($name) -1 }
    incr total -1
    foreach v {cc bc cl cip cport ckey t0 act dl cdl late bin bout st pend noted mode} { unset -nocomplain ${v}($id) }
    unset -nocomplain eofc($id,c2b) eofc($id,b2c)
}

# Called when a key is banned: drop its live connections.
proc ::tg::tcp::dropKey {key info} {
    variable cip
    set n 0
    foreach id [array names cip] {
        if {[::tg::ban::check $cip($id)]} {
            close_ $id "banned"
            incr n
        }
    }
    if {$n} { ::tg::log::info "closed $n connection(s) from banned $key" }
}

# 1 Hz sweep: timeouts, lifetime, reputation.
proc ::tg::tcp::sweep {t} {
    variable cc; variable cl; variable cfg; variable t0; variable act; variable dl; variable cdl
    variable bin; variable bout; variable noted; variable cip; variable mode; variable st
    foreach id [array names cc] {
        if {![info exists cc($id)]} continue   ;# closed by an earlier iteration
        set L $cfg($cl($id))
        if {$st($id) eq "connecting" && $t > $cdl($id)} {
            backendFailed $id "connect timeout"
            continue
        }
        if {$st($id) eq "hs"} {
            if {$dl($id) > 0 && $t > $dl($id)} { ::tg::tls::timeout $id }
            continue
        }
        if {$dl($id) > 0 && $t > $dl($id)} {
            if {$mode($id) eq "http"} {
                ::tg::http::deadline $id
            } else {
                ::tg::ban::strike $cip($id) 1 "no data after connecting ($cl($id))"
                close_ $id "first-byte timeout"
            }
            continue
        }
        set idle [dict get $L idleTimeout]
        if {$idle > 0 && $t - $act($id) > $idle * 1000} {
            close_ $id "idle timeout"
            continue
        }
        set life [dict get $L maxLifetime]
        if {$life > 0 && $t - $t0($id) > $life * 1000} {
            close_ $id "max lifetime"
            continue
        }
        if {!$noted($id) && $mode($id) ne "http" && $bin($id) > 0 && $bout($id) > 0 && $t - $t0($id) > 20000} {
            set noted($id) 1
            ::tg::trust::note $cip($id)
        }
    }
}

proc ::tg::tcp::status {} {
    variable nconn; variable srv; variable total; variable maxTotal
    set l {}
    foreach n [array names srv] { lappend l $n [expr {[info exists nconn($n)] ? $nconn($n) : 0}] }
    dict create total $total max $maxTotal listeners $l
}

proc ::tg::tcp::connectionCount {} { variable total; return $total }
