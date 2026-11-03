# httpsclient.tcl -- verified HTTPS requests for the ACME client and the updater.
#
# Certificates are always verified against a CA bundle (never "insecure"): the operating system's
# bundle when there is one, otherwise the Mozilla bundle that ships inside the starpack (needed on
# Windows, whose certificate store is not a PEM file). Hostname matching is enforced here as well,
# not left to the TLS library. Redirects are followed only to https:// and at most 5 times.

namespace eval ::tg::https {
    variable caFileOverride ""
    variable registered 0
    variable extracted ""
    variable dir [file dirname [info script]]    ;# captured while the file is being sourced
}

proc ::tg::https::caBundle {} {
    variable caFileOverride
    variable extracted
    if {$caFileOverride ne ""} { return $caFileOverride }
    foreach f {/etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem
               /usr/local/etc/openssl/cert.pem /opt/homebrew/etc/ca-certificates/cert.pem} {
        if {[file readable $f]} { return $f }
    }
    # OpenSSL cannot read from the starpack's virtual file system: copy the bundled file out once.
    if {$extracted ne "" && [file exists $extracted]} { return $extracted }
    variable dir
    set src [file join $dir vendor cacert.pem]
    set dst [file join [::tg::cfg::stateDir] cacert.pem]
    file copy -force $src $dst
    set extracted $dst
    return $dst
}

proc ::tg::https::setCaFile {path} { variable caFileOverride; set caFileOverride $path }

# Wait (running the event loop, so the guard keeps serving) until chan is ready or the time is up.
proc ::tg::https::waitFor {chan event ms} {
    variable wv
    set wv($chan) 0
    set after [after $ms [list set ::tg::https::wv($chan) timeout]]
    fileevent $chan $event [list set ::tg::https::wv($chan) ready]
    vwait ::tg::https::wv($chan)
    after cancel $after
    catch {fileevent $chan $event {}}
    set r $wv($chan)
    unset wv($chan)
    return $r
}

# Connect + handshake without blocking the event loop, then verify the host name (tcltls checks
# the certificate chain but NOT the name, so that is done here). Used as the https socket command
# for ::http; the -async flag ::http may pass is ignored because we return a connected channel.
proc ::tg::https::socket {args} {
    set host [lindex $args end-1]
    set port [lindex $args end]
    set ch [::socket -async $host $port]
    if {[waitFor $ch writable 15000] ne "ready" || [fconfigure $ch -error] ne ""} {
        set e [fconfigure $ch -error]
        catch {close $ch}
        error "cannot connect to $host:$port [expr {$e ne "" ? ": $e" : "(timeout)"}]"
    }
    fconfigure $ch -blocking 0
    set opts [list -server 0 -require 1 -cafile [caBundle] -servername $host \
                  -ssl2 0 -ssl3 0 -tls1 0 -tls1.1 0 -tls1.2 1 -tls1.3 1 -command ::tg::tls::callback]
    if {[catch {::tls::import $ch {*}$opts} err]} { catch {close $ch}; error "TLS setup failed: $err" }
    set deadline [expr {[clock milliseconds] + 15000}]
    while 1 {
        if {[catch {::tls::handshake $ch} r]} {
            catch {close $ch}
            # tcltls 2.x checks the host name itself and says "... due to "IP address mismatch""; 1.7 leaves it to us (below)
            if {[string match "*mismatch*" $r]} { error "the certificate presented by $host is not valid for that name ($r)" }
            error "TLS handshake with $host failed: $r"
        }
        if {$r == 1} break
        set left [expr {$deadline - [clock milliseconds]}]
        if {$left <= 0 || [waitFor $ch readable $left] ne "ready"} { catch {close $ch}; error "TLS handshake with $host timed out" }
    }
    set st [::tls::status $ch]
    if {[catch {::tg::crypto::certInfo [dict get $st certificate]} ci] || ![hostMatches $host $ci]} {
        catch {close $ch}
        error "the certificate presented by $host is not valid for that name"
    }
    return $ch
}

# Does the certificate (as parsed by crypto::certInfo) cover this host name?
proc ::tg::https::hostMatches {host ci} {
    set names [dict get $ci names]
    if {![llength $names] && [dict get $ci cn] ne ""} { set names [list [dict get $ci cn]] }   ;# CN only without SANs
    set h [string tolower $host]
    foreach n $names {
        set n [string tolower $n]
        if {$n eq $h} { return 1 }
        # one wildcard label, leftmost only: *.example.com matches www.example.com, not a.b.example.com
        if {[string match {\*.*} $n] && [regexp {^[^.]+(\..+)$} $h -> rest] && [string range $n 1 end] eq $rest} { return 1 }
    }
    return 0
}

proc ::tg::https::init {} {
    variable registered
    if {$registered} return
    package require http
    if {[catch {package require tls} err]} { error "this build has no TLS support (tcltls missing): $err" }
    ::http::register https 443 ::tg::https::socket
    set registered 1
}

# request method url ?-headers {k v ...}? ?-body data? ?-timeout ms? ?-maxbytes n? ?-channel chan?
# -> dict: code headers(dict, lower-case keys) body
proc ::tg::https::request {method url args} {
    init
    array set o {-headers {} -body "" -timeout 30000 -maxbytes 8388608 -channel "" -redirects 5 -allowHttp 0}
    array set o $args
    for {set hop 0} {$hop <= $o(-redirects)} {incr hop} {
        if {![regexp -nocase {^(https?)://([^/:?#]+)(:\d+)?} $url -> scheme host portPart]} { error "bad URL: $url" }
        if {[string tolower $scheme] ne "https" && !$o(-allowHttp)} { error "refusing non-HTTPS URL: $url" }
        set gargs [list -method $method -headers $o(-headers) -timeout $o(-timeout) -binary 1 -keepalive 0]
        if {$o(-body) ne "" || $method eq "POST"} { lappend gargs -query $o(-body) }
        if {$o(-channel) ne ""} { lappend gargs -channel $o(-channel) }
        set tok [::http::geturl $url {*}$gargs]
        try {
            set status [::http::status $tok]
            if {$status ne "ok"} {
                set why [expr {$status eq "error" ? [::http::error $tok] : $status}]
                error "request to $host failed: $why"
            }
            set code [::http::ncode $tok]
            set hdrs {}
            foreach {k v} [::http::meta $tok] { dict set hdrs [string tolower $k] $v }
            set body [::http::data $tok]
            if {[string length $body] > $o(-maxbytes)} { error "response from $host is larger than allowed" }
        } finally {
            ::http::cleanup $tok
        }
        if {$code in {301 302 303 307 308} && [dict exists $hdrs location]} {
            set loc [dict get $hdrs location]
            if {![regexp -nocase {^https?://} $loc]} {
                # relative redirect
                regexp -nocase {^(https?://[^/]+)} $url -> base
                set loc $base$loc
            }
            set url $loc
            if {$code == 303} { set method GET; set o(-body) "" }
            continue
        }
        return [dict create code $code headers $hdrs body $body url $url]
    }
    error "too many redirects"
}

proc ::tg::https::get {url args} { request GET $url {*}$args }
