# httpproxy.tcl -- HTTP/1.x request inspection on top of the TCP proxy core.
#
# The client->backend stream is parsed incrementally. Requests are validated
# strictly (this doubles as request-smuggling defence: anything ambiguous is
# refused rather than guessed), metered per client address and per path, and only
# then forwarded. Bodies and chunked bodies are framed so the next request on a
# keep-alive connection is found reliably. The response direction is relayed
# untouched, except that the first bytes after an Upgrade request are inspected
# to see whether the backend really switched protocols (WebSocket).

if {[catch {package require sha256}]} {
    source [file join [file dirname [info script]] vendor sha256.tcl]
}

namespace eval ::tg::http {
    variable name; variable L; variable ip; variable key; variable buf
    variable ps; variable need; variable nreq; variable upg; variable rp
    variable good; variable bodySeen; variable eip; variable nsmall
    foreach v {name L ip key buf ps need nreq upg rp good bodySeen eip nsmall} { array set $v {} }
    variable secret ""
    variable verified          ;# challenge: key -> expiry ms
    array set verified {}
    variable reasons
    array set reasons {
        200 OK 307 {Temporary Redirect} 400 {Bad Request} 403 Forbidden 405 {Method Not Allowed}
        408 {Request Timeout} 413 {Payload Too Large} 414 {URI Too Long} 429 {Too Many Requests}
        431 {Request Header Fields Too Large} 502 {Bad Gateway} 503 {Service Unavailable}
    }
}

# Prepare per-listener helper state (trusted proxy set). Called when a listener starts.
proc ::tg::http::prepare {name L} {
    variable secret
    ::tg::ip::setLoad "tp:$name" [dict get $L trustedProxies]
    if {$secret eq ""} { set secret [::tg::randomHex 32] }
}

proc ::tg::http::begin {id lname Lc pip pkey} {
    variable name; variable L; variable ip; variable key; variable buf
    variable ps; variable need; variable nreq; variable upg; variable rp
    variable good; variable bodySeen; variable eip; variable nsmall
    set nsmall($id) 0
    set name($id) $lname; set L($id) $Lc; set ip($id) $pip; set key($id) $pkey
    set buf($id) ""; set ps($id) hdr; set need($id) 0; set nreq($id) 0
    set upg($id) none; set rp($id) ""; set good($id) 0; set bodySeen($id) 0; set eip($id) $pip
    # a connection must produce its first request promptly
    set ::tg::tcp::dl($id) [expr {[::tg::now] + [dict get $Lc headerTimeout] * 1000}]
    if {[dict get $Lc headerTimeout] == 0} { set ::tg::tcp::dl($id) 0 }
}

proc ::tg::http::end {id} {
    foreach v {name L ip key buf ps need nreq upg rp good bodySeen eip nsmall} {
        variable $v
        unset -nocomplain ${v}($id)
    }
}

# ---------------------------------------------------------------- reading ---

proc ::tg::http::clientReadable {id} {
    variable buf; variable ps
    if {![info exists ::tg::tcp::cc($id)]} return
    set chan $::tg::tcp::cc($id)
    if {[catch {read $chan 65536} data]} { ::tg::tcp::close_ $id "read error"; return }
    set n [string length $data]
    if {$n == 0} {
        if {[eof $chan]} { clientEof $id }
        return
    }
    set ::tg::tcp::act($id) [::tg::now]
    if {$ps($id) eq "drain"} return
    if {$ps($id) eq "hdr" && $buf($id) eq ""} {
        # first byte of a new request starts the header clock
        variable L
        set ht [dict get $L($id) headerTimeout]
        set ::tg::tcp::dl($id) [expr {$ht > 0 ? [::tg::now] + $ht * 1000 : 0}]
    }
    append buf($id) $data
    process $id
}

proc ::tg::http::clientEof {id} {
    variable ps; variable buf
    set bc $::tg::tcp::bc($id)
    if {$bc eq "" || $ps($id) eq "drain" || $buf($id) ne "" && $ps($id) eq "hdr"} {
        ::tg::tcp::close_ $id "client closed"
        return
    }
    ::tg::tcp::sideClosed $id c2b $::tg::tcp::cc($id) $bc
}

# Re-enter the parser after the backend connected or output drained.
proc ::tg::http::resume {id} {
    variable ps; variable buf
    if {![info exists buf($id)]} return
    process $id
}

proc ::tg::http::backendUp {id} {
    variable ps; variable buf
    set cc $::tg::tcp::cc($id)
    if {$ps($id) ne "upgwait" && $ps($id) ne "drain"} {
        fileevent $cc readable [list ::tg::http::clientReadable $id]
    }
    process $id
}

# Send validated bytes towards the backend (connecting it first if needed).
proc ::tg::http::emit {id bytes} {
    set b $::tg::tcp::bc($id)
    set n [string length $bytes]
    incr ::tg::tcp::bin($id) $n
    ::tg::stat::incr bytesIn $n
    if {$b eq "" || $::tg::tcp::st($id) ne "open"} {
        append ::tg::tcp::pend($id) $bytes
        ::tg::tcp::connectBackend $id
        if {[string length $::tg::tcp::pend($id)] > 1048576} {
            catch {fileevent $::tg::tcp::cc($id) readable {}}
        }
        return
    }
    if {[catch {puts -nonewline $b $bytes}]} { ::tg::tcp::close_ $id "backend write error"; return }
    if {[chan pending output $b] > 262144} {
        ::tg::tcp::throttle $id c2b $::tg::tcp::cc($id) $b
    }
}

# ------------------------------------------------------------ the parser ---

proc ::tg::http::process {id} {
    variable buf; variable ps; variable need; variable L; variable bodySeen; variable nsmall
    set Lc $L($id)
    while {[info exists buf($id)]} {
        set st $ps($id)
        switch -- $st {
            hdr {
                if {$buf($id) eq ""} {
                    # idle between requests: keep-alive clock
                    set ka [dict get $Lc keepAliveTimeout]
                    set ::tg::tcp::dl($id) [expr {$ka > 0 ? [::tg::now] + $ka * 1000 : 0}]
                    return
                }
                # Leading CRLFs between requests are tolerated (RFC 9112 2.2), but a
                # handful at most: strip them in one step (no quadratic re-slicing).
                if {[regexp -indices {^(?:\r\n)+} $buf($id) crlf]} {
                    set nCr [expr {([lindex $crlf 1] + 1) / 2}]
                    if {$nCr > 8} { reject $id 400 "too many blank lines before request" 1; return }
                    set buf($id) [string range $buf($id) [expr {[lindex $crlf 1] + 1}] end]
                    continue
                }
                set idx [string first "\r\n\r\n" $buf($id)]
                if {$idx < 0} {
                    if {[string length $buf($id)] > [dict get $Lc maxHeaderBytes]} {
                        reject $id 431 "request headers too large" 1
                        return
                    }
                    # bare-LF terminated header block (not valid HTTP; smuggling vector)
                    if {[string first "\n\n" $buf($id)] >= 0} {
                        reject $id 400 "malformed request (bare LF)" 1
                        return
                    }
                    return
                }
                if {$idx + 4 > [dict get $Lc maxHeaderBytes]} {
                    reject $id 431 "request headers too large" 1
                    return
                }
                set block [string range $buf($id) 0 [expr {$idx + 3}]]
                set buf($id) [string range $buf($id) [expr {$idx + 4}] end]
                if {[handleRequest $id $block] ne "ok"} return
            }
            body {
                if {$buf($id) eq ""} return
                set n [string length $buf($id)]
                if {$n > $need($id)} { set n $need($id) }
                emit $id [string range $buf($id) 0 [expr {$n - 1}]]
                if {![info exists buf($id)]} return          ;# emit closed the connection
                set buf($id) [string range $buf($id) $n end]
                incr need($id) -$n
                set ::tg::tcp::dl($id) [expr {[::tg::now] + [dict get $Lc bodyTimeout] * 1000}]
                if {$need($id) == 0} { requestDone $id }
                if {![info exists buf($id)]} return
                if {$ps($id) eq "body" && $buf($id) eq ""} return
            }
            csize {
                set idx [string first "\r\n" $buf($id)]
                if {$idx < 0} {
                    if {[string length $buf($id)] > 4096} { reject $id 400 "bad chunk header" 1 }
                    return
                }
                set line [string range $buf($id) 0 [expr {$idx - 1}]]
                # size[;extensions]
                if {![regexp {^([0-9a-fA-F]{1,12})(;[^\r\n]*)?$} $line -> hex]} {
                    reject $id 400 "bad chunk size" 1
                    return
                }
                scan $hex %x size
                # Floods of tiny chunks cost us a buffer copy each; real clients send big ones.
                if {$size < 16 && [incr nsmall($id)] > 2000} { reject $id 400 "too many tiny chunks" 1; return }
                incr bodySeen($id) $size
                if {$bodySeen($id) > [dict get $Lc maxBodyMB] * 1048576} {
                    reject $id 413 "request body too large" 0
                    return
                }
                emit $id [string range $buf($id) 0 [expr {$idx + 1}]]
                if {![info exists buf($id)]} return
                set buf($id) [string range $buf($id) [expr {$idx + 2}] end]
                if {$size == 0} { set ps($id) ctrail; set need($id) 0 } else { set ps($id) cdata; set need($id) $size }
            }
            cdata {
                if {$buf($id) eq ""} return
                set n [string length $buf($id)]
                if {$n > $need($id)} { set n $need($id) }
                emit $id [string range $buf($id) 0 [expr {$n - 1}]]
                if {![info exists buf($id)]} return
                set buf($id) [string range $buf($id) $n end]
                incr need($id) -$n
                set ::tg::tcp::dl($id) [expr {[::tg::now] + [dict get $Lc bodyTimeout] * 1000}]
                if {$need($id) == 0} { set ps($id) ccrlf }
            }
            ccrlf {
                if {[string length $buf($id)] < 2} return
                if {[string range $buf($id) 0 1] ne "\r\n"} {
                    reject $id 400 "bad chunk terminator" 1
                    return
                }
                emit $id "\r\n"
                if {![info exists buf($id)]} return
                set buf($id) [string range $buf($id) 2 end]
                set ps($id) csize
            }
            ctrail {
                set idx [string first "\r\n" $buf($id)]
                if {$idx < 0} {
                    if {[string length $buf($id)] > 4096} { reject $id 431 "trailer too large" 1 }
                    return
                }
                set line [string range $buf($id) 0 [expr {$idx - 1}]]
                # Trailers are forwarded, so each one must be a clean header line:
                # a bare LF or control byte here would let a lenient backend see a
                # second request hidden inside the trailer section.
                if {$line ne ""} {
                    if {[regexp {[\x00-\x08\x0a-\x1f\x7f]} $line] || ![regexp {^[!#$%&'*+.^`|~0-9A-Za-z-]+:[^\x00-\x08\x0a-\x1f\x7f]*$} $line] || [incr need($id)] > 20} {
                        reject $id 400 "malformed chunk trailer" 1
                        return
                    }
                }
                emit $id [string range $buf($id) 0 [expr {$idx + 1}]]
                if {![info exists buf($id)]} return
                set last [expr {$idx == 0}]
                set buf($id) [string range $buf($id) [expr {$idx + 2}] end]
                if {$last} { requestDone $id }
            }
            tunnel {
                if {$buf($id) ne ""} { emit $id $buf($id); set buf($id) "" }
                return
            }
            upgwait - drain {
                return
            }
            default { return }
        }
    }
}

proc ::tg::http::requestDone {id} {
    variable ps; variable good; variable eip; variable bodySeen; variable nreq; variable nsmall
    if {![info exists ps($id)]} return          ;# connection already torn down
    set nsmall($id) 0
    set ps($id) hdr
    set bodySeen($id) 0
    if {!$good($id) && $nreq($id) >= 3} {
        set good($id) 1
        ::tg::trust::note $eip($id)
    }
}

# ------------------------------------------------------------ one request ---

# Parse header block into a dict; on failure returns {err status reason}.
proc ::tg::http::parseHead {id block} {
    variable L
    set Lc $L($id)
    set text [string range $block 0 end-4]
    set lines [split $text \n]
    set n [llength $lines]
    set clean {}
    for {set i 0} {$i < $n} {incr i} {
        set ln [lindex $lines $i]
        if {$i < $n - 1} {
            if {[string index $ln end] ne "\r"} { return {err 400 "bare LF in headers"} }
            set ln [string range $ln 0 end-1]
        }
        if {[regexp {[\x00-\x08\x0a-\x1f\x7f]} $ln]} { return {err 400 "control character in headers"} }
        lappend clean $ln
    }
    set reqline [lindex $clean 0]
    if {![regexp {^([A-Z]{3,10}) ([^ ]+) HTTP/(1\.[01])$} $reqline -> method target version]} {
        return {err 400 "malformed request line"}
    }
    if {[string length $target] > [dict get $Lc maxUriLength]} { return {err 414 "URI too long"} }
    if {$method ni [dict get $Lc methods]} { return {err 405 "method not allowed"} }
    if {[string index $target 0] ne "/" && !($target eq "*" && $method eq "OPTIONS")} {
        return {err 400 "unsupported request target"}
    }
    set hdrs [lrange $clean 1 end]
    if {[llength $hdrs] > [dict get $Lc maxHeaders]} { return {err 431 "too many headers"} }
    set cl {}; set te {}; set hosts 0; set conn {}; set upgrade 0; set cookie {}; set realip {}
    set parsed {}
    set realName [string tolower [dict get $Lc realIpHeader]]
    foreach h $hdrs {
        if {[string index $h 0] in {" " "\t"}} { return {err 400 "obsolete header folding"} }
        if {![regexp {^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*?)[ \t]*$} $h -> hn hv]} {
            return {err 400 "malformed header"}
        }
        set ln [string tolower $hn]
        lappend parsed [list $ln $hn $hv $h]
        switch -- $ln {
            content-length { lappend cl $hv }
            transfer-encoding { lappend te [string tolower $hv] }
            host { incr hosts }
            connection { lappend conn {*}[split [string tolower $hv] ,] }
            upgrade { set upgrade 1 }
            cookie { lappend cookie $hv }
        }
        if {$ln eq $realName} { lappend realip $hv }
    }
    if {$hosts > 1} { return {err 400 "duplicate Host header"} }
    if {$hosts == 0 && $version eq "1.1"} { return {err 400 "missing Host header"} }
    set connTokens {}
    foreach c $conn { lappend connTokens [string trim $c] }
    # ---- message framing (the part that must agree with the backend) ----
    set framing none; set clen 0
    if {[llength $te]} {
        if {$version eq "1.0" || [llength $te] > 1 || [lindex $te 0] ne "chunked" || [llength $cl]} {
            return {err 400 "ambiguous message framing"}
        }
        set framing chunked
    } elseif {[llength $cl]} {
        set first [lindex $cl 0]
        foreach c $cl {
            if {$c ne $first} { return {err 400 "conflicting Content-Length"} }
        }
        if {![regexp {^[0-9]{1,15}$} $first]} { return {err 400 "invalid Content-Length"} }
        scan $first %ld clen
        if {$clen > [dict get $Lc maxBodyMB] * 1048576} { return {err 413 "request body too large"} }
        if {$clen > 0} { set framing length }
    }
    dict create method $method target $target version $version reqline $reqline headers $parsed \
        framing $framing clen $clen upgrade [expr {$upgrade && "upgrade" in $connTokens}] \
        close [expr {"close" in $connTokens}] cookie $cookie realip $realip
}

# Returns ok, or "stop" after responding / closing.
proc ::tg::http::handleRequest {id block} {
    variable L; variable name; variable ip; variable nreq; variable ps; variable need
    variable upg; variable eip; variable bodySeen
    set Lc $L($id)
    set lname $name($id)
    set d [parseHead $id $block]
    if {[lindex $d 0] eq "err"} {
        reject $id [lindex $d 1] [lindex $d 2] 1
        return stop
    }
    set peer $ip($id)
    set cip $peer
    set viaProxy 0
    # Behind a trusted reverse proxy/tunnel the real client is in a header.
    if {[::tg::ip::setMatch "tp:$lname" $peer] && [dict get $d realip] ne ""} {
        set cand [pickClientIp [join [dict get $d realip] ,] "tp:$lname"]
        if {$cand ne ""} { set cip $cand; set viaProxy 1 }
    }
    set eip($id) $cip
    set ckey [::tg::ip::key $cip]
    if {$viaProxy && [::tg::ban::check $cip]} {
        ::tg::stat::incr blocked; ::tg::stat::incr reqBlocked
        ::tg::tcp::close_ $id "banned client behind proxy"
        return stop
    }
    set privileged [::tg::ban::isAllowed $cip]
    set method [dict get $d method]
    set target [dict get $d target]

    if {!$privileged} {
        # per-IP request rate
        set rw [expr {[dict get $Lc reqWindow] * 1000}]
        if {[::tg::rate::hit "r:$lname:$ckey" $rw] > [::tg::tcp::scaled [dict get $Lc reqRate]]} {
            ::tg::ban::strike $cip 2 "request flood on $lname"
            blockedReq $id $ckey
            respondRaw $id 429 "Too Many Requests" "Slow down." "Retry-After: [dict get $Lc reqWindow]\r\n"
            return stop
        }
        # per-path limits (e.g. login brute force)
        set path [lindex [split $target ?#] 0]
        set i 0
        foreach pl [dict get $Lc pathLimits] {
            lassign $pl re cnt sec
            incr i
            if {[regexp -- $re $path]} {
                if {[::tg::rate::hit "p:$lname:$i:$ckey" [expr {$sec * 1000}]] > $cnt} {
                    ::tg::ban::strike $cip 1 "path limit $re on $lname"
                    blockedReq $id $ckey
                    respondRaw $id 429 "Too Many Requests" "Too many attempts." "Retry-After: $sec\r\n"
                    return stop
                }
            }
        }
        # cookie challenge
        set ch [dict get $Lc challenge]
        if {$ch eq "always" || ($ch eq "auto" && [::tg::level::get] >= 2)} {
            if {![::tg::trust::known $cip] && ![challengePassed $d $ckey $Lc]} {
                if {[::tg::rate::hit "ch:$lname:$ckey" 10000] > 6} {
                    ::tg::ban::strike $cip 1 "ignores challenge cookie on $lname"
                }
                blockedReq $id $ckey
                challenge $id $d $ckey $Lc
                return stop
            }
        }
    }

    # ---- accepted: build what goes to the backend ----
    set out [dict get $d reqline]
    set isUp [dict get $d upgrade]
    if {$isUp} {
        if {$nreq($id) > 0 || $method ne "GET" || [dict get $d framing] ne "none"} {
            reject $id 400 "Upgrade only allowed as the first, body-less GET of a connection" 0
            return stop
        }
    }
    if {[::tg::bool [dict get $Lc forwardIp]]} {
        set chain [::tg::ip::norm $peer]
        foreach h [dict get $d headers] {
            lassign $h ln hn hv raw
            # also catch X_Real_IP style spellings that some backends fold to X-Real-IP
            set ln [string map {_ -} $ln]
            if {$ln in {x-real-ip forwarded}} continue
            if {$ln eq "x-forwarded-for"} {
                if {$viaProxy} { set chain "$hv, $chain" }
                continue
            }
            append out "\r\n$raw"
        }
        append out "\r\nX-Forwarded-For: $chain\r\nX-Real-IP: [::tg::ip::norm $cip]\r\n\r\n"
    } else {
        set out [string range $block 0 end]
    }
    incr nreq($id)
    ::tg::stat::incr ok
    ::tg::stat::incr req
    ::tg::stat::talk $ckey ok [string length $block]
    set framing [dict get $d framing]
    switch -- $framing {
        chunked { set ps($id) csize; set bodySeen($id) 0 }
        length  { set ps($id) body; set need($id) [dict get $d clen] }
        default { set ps($id) hdr }
    }
    emit $id $out
    if {![info exists ps($id)]} { return stop }       ;# emit closed the connection
    if {$isUp} {
        set upg($id) pending
        set ps($id) upgwait
        catch {fileevent $::tg::tcp::cc($id) readable {}}
        set ::tg::tcp::dl($id) [expr {[::tg::now] + 15000}]
    } elseif {$framing eq "none"} {
        requestDone $id
    } else {
        set ::tg::tcp::dl($id) [expr {[::tg::now] + [dict get $Lc bodyTimeout] * 1000}]
    }
    return ok
}

proc ::tg::http::blockedReq {id ckey} {
    ::tg::stat::incr blocked
    ::tg::stat::incr reqBlocked
    ::tg::stat::talk $ckey blocked
}

# Rightmost entry that is not one of our trusted proxies.
proc ::tg::http::pickClientIp {headerValue setName} {
    set parts {}
    foreach p [split $headerValue ,] {
        set p [string trim $p]
        if {$p ne "" && [::tg::ip::isValid $p]} { lappend parts $p }
    }
    if {![llength $parts]} { return "" }
    for {set i [expr {[llength $parts] - 1}]} {$i >= 0} {incr i -1} {
        set p [lindex $parts $i]
        if {![::tg::ip::setMatch $setName $p]} { return $p }
    }
    return [lindex $parts 0]
}

# Protocol switch verdict: look at the backend's first response bytes.
proc ::tg::http::onResponseData {id data} {
    variable upg; variable rp; variable ps
    if {![info exists upg($id)] || $upg($id) ne "pending"} return
    append rp($id) $data
    if {[string length $rp($id)] < 12} return
    if {[regexp {^HTTP/1\.[01] 101} $rp($id)]} {
        set upg($id) done
        set ps($id) tunnel
        set ::tg::tcp::dl($id) 0
    } else {
        set upg($id) none
        set ps($id) hdr
    }
    set rp($id) ""
    catch {fileevent $::tg::tcp::cc($id) readable [list ::tg::http::clientReadable $id]}
    process $id
}

# ------------------------------------------------------------- challenge ---

proc ::tg::http::mac {ckey exp} {
    variable secret
    string range [::sha2::hmac -hex -key $secret "$ckey|$exp"] 0 31
}

proc ::tg::http::challengePassed {d ckey Lc} {
    variable verified
    set now [::tg::now]
    if {[info exists verified($ckey)] && $verified($ckey) > $now} { return 1 }
    foreach c [dict get $d cookie] {
        if {[regexp {(?:^|[; ])tg_ok=([1-9][0-9]{0,11})\.([0-9a-f]{32})(?:;|$)} $c -> exp m]} {
            if {$exp * 1000 > $now && $m eq [mac $ckey $exp]} {
                if {[array size verified] < 100000} { set verified($ckey) [expr {$exp * 1000}] }
                return 1
            }
        }
    }
    return 0
}

proc ::tg::http::challenge {id d ckey Lc} {
    set method [dict get $d method]
    if {$method ni {GET HEAD}} {
        respondRaw $id 403 Forbidden "Verification required. Please reload the page and try again."
        return
    }
    set ttl [dict get $Lc challengeTtl]
    set exp [expr {[clock seconds] + $ttl}]
    # Never echo "//host" (open redirect); keep it a same-site absolute path.
    set target "/[string trimleft [dict get $d target] "/\\"]"
    set cookie "tg_ok=$exp.[mac $ckey $exp]; Path=/; Max-Age=$ttl; HttpOnly; SameSite=Lax"
    respondRaw $id 307 "Temporary Redirect" "" "Location: $target\r\nSet-Cookie: $cookie\r\nCache-Control: no-store\r\n"
}

# ------------------------------------------------------------- responses ---

proc ::tg::http::reject {id code why strike} {
    variable ip
    if {$strike > 0} { ::tg::ban::strike $::tg::http::ip($id) $strike "bad HTTP request: $why" }
    ::tg::stat::incr blocked
    ::tg::stat::incr reqBlocked
    ::tg::stat::talk $::tg::tcp::ckey($id) blocked
    ::tg::log::debug "http reject $code from $ip($id): $why"
    respondRaw $id $code "" $why
}

# Write a complete response, then drain the socket briefly. (Closing at once
# with unread request data makes the OS send a reset that can destroy the
# response before the client has read it.)
proc ::tg::http::respondRaw {id code {reason ""} {text ""} {extra ""}} {
    variable reasons; variable ps; variable buf
    if {![info exists ::tg::tcp::cc($id)]} return
    if {$reason eq ""} { set reason [expr {[info exists reasons($code)] ? $reasons($code) : "Error"}] }
    set body ""
    if {$text ne ""} {
        set safe [string map {& &amp; < &lt; > &gt;} $text]
        set body "<!doctype html><title>$code $reason</title><h1>$code $reason</h1><p>$safe</p>\n"
    }
    set resp "HTTP/1.1 $code $reason\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: [string length $body]\r\nConnection: close\r\nCache-Control: no-store\r\n$extra\r\n$body"
    set chan $::tg::tcp::cc($id)
    # the backend is no longer needed
    set b $::tg::tcp::bc($id)
    if {$b ne ""} { catch {fileevent $b readable {}; close $b}; set ::tg::tcp::bc($id) "" }
    set ::tg::tcp::pend($id) ""
    set ::tg::tcp::st($id) closed
    catch {puts -nonewline $chan $resp}
    catch {chan close $chan write}
    set ps($id) drain
    set buf($id) ""
    set ::tg::tcp::dl($id) [expr {[::tg::now] + 3000}]
    catch {fileevent $chan readable [list ::tg::http::drainRead $id]}
}

proc ::tg::http::drainRead {id} {
    if {![info exists ::tg::tcp::cc($id)]} return
    set chan $::tg::tcp::cc($id)
    if {[catch {read $chan 65536} d]} { ::tg::tcp::close_ $id; return }
    if {[eof $chan]} { ::tg::tcp::close_ $id "finished" }
}

# Called by the 1 Hz sweep when a connection's deadline passed.
proc ::tg::http::deadline {id} {
    variable ps; variable buf; variable nreq; variable ip
    if {![info exists ps($id)]} return
    switch -- $ps($id) {
        drain { ::tg::tcp::close_ $id "finished" }
        hdr {
            if {$buf($id) ne ""} {
                ::tg::ban::strike $ip($id) 1 "slow request headers (slowloris-style)"
                ::tg::stat::incr blocked
                respondRaw $id 408 "Request Timeout" "Request not received in time."
            } else {
                if {$nreq($id) == 0} { ::tg::ban::strike $ip($id) 1 "connected but sent no request" }
                ::tg::tcp::close_ $id "keep-alive timeout"
            }
        }
        upgwait { ::tg::tcp::close_ $id "upgrade timeout" }
        default {
            ::tg::ban::strike $ip($id) 1 "stalled request body"
            ::tg::tcp::close_ $id "body timeout"
        }
    }
}
