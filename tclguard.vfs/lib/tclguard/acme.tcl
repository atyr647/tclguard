# acme.tcl -- automatic certificates from Let's Encrypt (or any RFC 8555 ACME server), HTTP-01.
#
# How it works for a TLS listener with  acme 1  and  tlsNames {example.com www.example.com}:
#   1. the listener starts with a temporary self-signed certificate (see tlsproxy.tcl);
#   2. once the guard is up this module orders a real certificate; the CA then fetches
#        http://example.com/.well-known/acme-challenge/<token>
#      and httpproxy.tcl answers that request (any http listener reachable on port 80);
#   3. the certificate + a fresh private key are written to <state>/certs/<listener>.pem and are
#      picked up by the next connection; it is renewed when 30 days (or a third of its life) remain.
#
# Limits, stated plainly: HTTP-01 needs port 80 reachable from the internet and cannot issue
# wildcard certificates; names must be DNS names (not IP addresses).

namespace eval ::tg::acme {
    variable pending                  ;# token -> key authorization (only while an order is running)
    array set pending {}
    variable nonce ""
    variable dirDoc {}
    variable kid ""
    variable acctKey {}
    variable busy 0
    variable status                   ;# listener -> {state msg next attempts}
    array set status {}
    variable default https://acme-v02.api.letsencrypt.org/directory
    variable staging https://acme-staging-v02.api.letsencrypt.org/directory
}

# ----------------------------------------------------------------- used by httpproxy ---

# Key authorization for /.well-known/acme-challenge/<token>, or "".
proc ::tg::acme::answer {path} {
    variable pending
    if {[regexp {^/\.well-known/acme-challenge/([A-Za-z0-9_-]{8,255})$} $path -> tok] && [info exists pending($tok)]} {
        return $pending($tok)
    }
    return ""
}

# ---------------------------------------------------------------------- transport ---

proc ::tg::acme::sleep {ms} {
    set v ::tg::acme::sleepVar[incr ::tg::acme::sleepCount]
    after $ms [list set $v 1]
    vwait $v
    unset $v
}

proc ::tg::acme::problem {r} {
    set body [dict get $r body]
    if {![catch {::tg::json::parse $body} doc] && [string is list -strict $doc] && [catch {dict exists $doc detail} ok] == 0 && $ok} {
        return "[::tg::json::get $doc type] [::tg::json::get $doc detail]"
    }
    return [string range $body 0 200]
}

proc ::tg::acme::newNonce {} {
    variable dirDoc
    variable nonce
    set r [::tg::https::request HEAD [dict get $dirDoc newNonce] -timeout 20000]
    if {![dict exists [dict get $r headers] replay-nonce]} { error "ACME server did not supply a nonce" }
    set nonce [dict get [dict get $r headers] replay-nonce]
}

# Signed POST (RFC 8555 section 6.2). payload "" is a POST-as-GET.
# Returns dict: code headers body (body parsed as JSON when it is JSON)
proc ::tg::acme::post {url payload {useJwk 0}} {
    variable nonce
    variable acctKey
    variable kid
    for {set attempt 0} {$attempt < 3} {incr attempt} {
        if {$nonce eq ""} { newNonce }
        set n $nonce
        set nonce ""
        if {$useJwk} {
            set prot [format {{"alg":"ES256","nonce":"%s","url":"%s","jwk":%s}} $n $url [::tg::crypto::jwk $acctKey]]
        } else {
            set prot [format {{"alg":"ES256","nonce":"%s","url":"%s","kid":"%s"}} $n $url $kid]
        }
        set r [::tg::https::request POST $url -headers {Content-Type application/jose+json Accept application/json} \
                   -body [::tg::crypto::jws $acctKey $prot $payload] -timeout 30000]
        if {[dict exists [dict get $r headers] replay-nonce]} { set nonce [dict get [dict get $r headers] replay-nonce] }
        set code [dict get $r code]
        if {$code == 400 && [string match "*badNonce*" [dict get $r body]]} continue
        if {$code >= 400} { error "ACME server said $code: [problem $r]" }
        set ct [expr {[dict exists [dict get $r headers] content-type] ? [dict get [dict get $r headers] content-type] : ""}]
        if {[string match "*json*" $ct]} { dict set r doc [::tg::json::parse [encoding convertfrom utf-8 [dict get $r body]]] } \
        else { dict set r doc {} }
        return $r
    }
    error "ACME server kept rejecting our nonce"
}

# ----------------------------------------------------------------------- the order ---

proc ::tg::acme::accountKey {} {
    variable acctKey
    if {[llength $acctKey]} { return $acctKey }
    set dir [file join [::tg::cfg::stateDir] acme]
    file mkdir $dir
    set f [file join $dir account.key]
    if {[file exists $f]} {
        set acctKey [::tg::crypto::keyFromPem [::tg::tls::readFile $f]]
    } else {
        set acctKey [::tg::crypto::newKey]
        ::tg::tls::writeSecret $f [::tg::crypto::keyToPem $acctKey]
    }
    return $acctKey
}

# Order a certificate for names; write the combined PEM to pemPath. Returns "" or raises.
proc ::tg::acme::order {names pemPath directory email {caFile ""}} {
    variable dirDoc
    variable nonce
    variable kid
    variable pending
    set nonce ""
    if {$caFile ne ""} { ::tg::https::setCaFile $caFile }
    accountKey

    set r [::tg::https::get $directory -timeout 30000]
    if {[dict get $r code] != 200} { error "cannot read the ACME directory ($directory): HTTP [dict get $r code]" }
    set dirDoc [::tg::json::parse [encoding convertfrom utf-8 [dict get $r body]]]
    foreach k {newNonce newAccount newOrder} { if {![dict exists $dirDoc $k]} { error "ACME directory has no $k" } }

    # account (returns the existing one when the key is already registered)
    set contact [expr {$email ne "" ? [format {,"contact":["mailto:%s"]} $email] : ""}]
    set r [post [dict get $dirDoc newAccount] "{\"termsOfServiceAgreed\":true$contact}" 1]
    set kid [dict get [dict get $r headers] location]

    # order
    set ids {}
    foreach n $names { lappend ids [format {{"type":"dns","value":"%s"}} $n] }
    set r [post [dict get $dirDoc newOrder] "{\"identifiers\":\[[join $ids ,]\]}"]
    set orderUrl [dict get [dict get $r headers] location]
    set ord [dict get $r doc]
    set authzUrls [dict get $ord authorizations]
    set finalize [dict get $ord finalize]

    try {
        foreach az $authzUrls { authorize $az }
        # certificate request with a fresh key
        set key [::tg::crypto::newKey]
        set csr [::tg::crypto::csr $key $names]
        set r [post $finalize [format {{"csr":"%s"}} [::tg::crypto::b64u $csr]]]
        set ord [dict get $r doc]
        set deadline [expr {[clock seconds] + 180}]
        while {[::tg::json::get $ord status] in {processing pending ready}} {
            if {[clock seconds] > $deadline} { error "the CA took too long to issue the certificate" }
            sleep 2000
            set ord [dict get [post $orderUrl ""] doc]
        }
        if {[::tg::json::get $ord status] ne "valid"} { error "order ended as '[::tg::json::get $ord status]': [::tg::json::get $ord error detail]" }
        set r [post [dict get $ord certificate] ""]
        set chain [encoding convertfrom utf-8 [dict get $r body]]
        # sanity: the certificate must be for our key and our names
        set leaf [::tg::crypto::unpem $chain CERTIFICATE]
        set ci [::tg::crypto::certInfo [::tg::crypto::pem CERTIFICATE $leaf]]
        lassign [::tg::crypto::certPublicPoint $leaf] x y
        if {$x != [dict get $key x] || $y != [dict get $key y]} { error "the CA returned a certificate for a different key" }
        foreach n $names { if {[string tolower $n] ni [dict get $ci names]} { error "the certificate does not cover $n" } }
        ::tg::tls::writeSecret $pemPath [string trim $chain]\n[::tg::crypto::keyToPem $key]
    } finally {
        foreach t [array names pending] { unset pending($t) }
    }
    return ""
}

proc ::tg::acme::authorize {url} {
    variable pending
    variable acctKey
    set az [dict get [post $url ""] doc]
    if {[::tg::json::get $az status] eq "valid"} return
    set chall {}
    foreach c [::tg::json::get $az challenges] { if {[::tg::json::get $c type] eq "http-01"} { set chall $c } }
    if {$chall eq ""} { error "the CA offered no http-01 challenge for [::tg::json::get $az identifier value]" }
    set token [dict get $chall token]
    if {![regexp {^[A-Za-z0-9_-]{8,255}$} $token]} { error "the CA sent an unusable challenge token" }
    set pending($token) $token.[::tg::crypto::thumbprint $acctKey]
    post [dict get $chall url] "{}"
    set deadline [expr {[clock seconds] + 120}]
    while 1 {
        sleep 1500
        set az [dict get [post $url ""] doc]
        set st [::tg::json::get $az status]
        if {$st eq "valid"} return
        if {$st ne "pending" && $st ne "processing"} {
            set detail ""
            foreach c [::tg::json::get $az challenges] { set e [::tg::json::get $c error detail]; if {$e ne ""} { set detail $e } }
            error "validation of [::tg::json::get $az identifier value] failed ($st): $detail"
        }
        if {[clock seconds] > $deadline} { error "validation of [::tg::json::get $az identifier value] timed out" }
    }
}

# --------------------------------------------------------------- per-listener driver ---

proc ::tg::acme::enabled {L} {
    expr {[::tg::tls::enabled $L] && [dict exists $L acme] && [::tg::bool [dict get $L acme]]}
}

proc ::tg::acme::state {name} {
    variable status
    if {[info exists status($name)]} { return $status($name) }
    return {state idle msg "" next 0 attempts 0}
}

proc ::tg::acme::setState {name args} {
    variable status
    set status($name) [dict merge [state $name] $args]
}

# Is a certificate needed (none yet, still our self-signed placeholder, or close to expiry)?
proc ::tg::acme::due {name L} {
    set st [::tg::tls::certStatus $name]
    if {![dict exists $st notAfter]} { return 1 }
    if {[dict get $st selfSigned]} { return 1 }
    set life [expr {[dict get $st notAfter] - [dict get $st notBefore]}]
    set renewAt [expr {min(30 * 86400, $life / 3)}]
    expr {[dict get $st notAfter] - [clock seconds] < $renewAt}
}

# Called every second by the engine; cheap unless something is due.
proc ::tg::acme::tick {t} {
    variable busy
    if {$busy} return
    foreach {n L} [::tg::cfg::listeners] {
        if {![enabled $L] || ![info exists ::tg::tls::files($n)]} continue
        set s [state $n]
        if {[dict get $s next] > [clock seconds]} continue
        if {![due $n $L]} continue
        set busy 1
        after idle [list ::tg::acme::run $n]
        return
    }
}

# Order now (also used by the GUI's "Get certificate now" button). Never raises.
proc ::tg::acme::run {name} {
    variable busy
    variable default
    set busy 1
    set L {}
    foreach {n spec} [::tg::cfg::listeners] { if {$n eq $name} { set L $spec } }
    if {![llength $L] || ![enabled $L]} { set busy 0; return }
    lassign [::tg::tls::locate $name $L] pem key mode
    set names [dict get $L tlsNames]
    set dirUrl [expr {[dict get $L acmeDirectory] ne "" ? [dict get $L acmeDirectory] : $default}]
    setState $name state issuing msg "ordering a certificate for [join $names {, }]"
    ::tg::log::info "ACME: ordering a certificate for [join $names {, }] from $dirUrl"
    if {[catch {order $names $pem $dirUrl [dict get $L acmeEmail] [dict get $L acmeCaFile]} err]} {
        set n [expr {[dict get [state $name] attempts] + 1}]
        set delay [lindex {300 900 3600 21600 86400} [expr {min($n, 5) - 1}]]
        setState $name state failed msg $err attempts $n next [expr {[clock seconds] + $delay}]
        ::tg::log::warn "ACME: could not get a certificate for [join $names {, }]: $err (will retry in [expr {$delay / 60}] min)"
    } else {
        ::tg::tls::refreshInfo $name $pem $mode
        set ci [::tg::tls::certStatus $name]
        setState $name state ok msg "certificate valid until [clock format [dict get $ci notAfter] -format {%Y-%m-%d} -timezone :UTC]" attempts 0 next 0
        ::tg::log::info "ACME: certificate for [join $names {, }] installed, valid until [clock format [dict get $ci notAfter] -format {%Y-%m-%d} -timezone :UTC]"
    }
    set busy 0
}

# Ask for an immediate attempt (clears the back-off).
proc ::tg::acme::requestNow {name} {
    setState $name next 0 attempts 0
}
