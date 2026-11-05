# crypto.tcl -- the small amount of public-key cryptography TclGuard needs, in pure Tcl, so
# that none of it depends on an openssl binary being installed (it usually is not on Windows):
#
#   * ECDSA over NIST P-256 (keygen, sign with RFC 6979 deterministic nonces, verify)
#   * DER building / minimal parsing, PEM armour
#   * self-signed X.509 certificates and PKCS#10 certificate requests (for ACME)
#   * JWK / JWS (ES256) and the RFC 7638 thumbprint (for ACME and for signed updates)
#
# Tcl 8.6 integers are arbitrary precision, which is all the field arithmetic needs.
# This code is NOT constant-time. That is acceptable here: it signs a handful of
# messages per day with a key held on the machine doing the signing, and nobody
# is timing it. Do not reuse it as a general crypto library.

if {[catch {package require sha256}]} {
    source [file join [file dirname [info script]] vendor sha256.tcl]
}

namespace eval ::tg::crypto {
    variable P  [expr {(1 << 256) - (1 << 224) + (1 << 192) + (1 << 96) - 1}]
    variable N  [expr {0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551}]
    variable B  [expr {0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B}]
    variable GX [expr {0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296}]
    variable GY [expr {0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5}]

    variable oid
    array set oid {
        ecPublicKey    1.2.840.10045.2.1
        prime256v1     1.2.840.10045.3.1.7
        ecdsaSha256    1.2.840.10045.4.3.2
        commonName     2.5.4.3
        organization   2.5.4.10
        subjectAltName 2.5.29.17
        keyUsage       2.5.29.15
        extKeyUsage    2.5.29.37
        basicConstr    2.5.29.19
        subjectKeyId   2.5.29.14
        serverAuth     1.3.6.1.5.5.7.3.1
        extensionReq   1.2.840.113549.1.9.14
    }
}

# ------------------------------------------------------------------ bytes <-> ints ---

proc ::tg::crypto::bytesToInt {b} {
    if {$b eq ""} { return 0 }
    binary scan $b H* h
    expr {"0x$h"}
}

# Big-endian, left-padded with zeros to exactly len bytes.
proc ::tg::crypto::intToBytes {n len} {
    set h [format %llx $n]
    if {[string length $h] > $len * 2} { error "integer does not fit in $len bytes" }
    binary format H* [string repeat 0 [expr {$len * 2 - [string length $h]}]]$h
}

# Entropy for key material: the operating system's source or an error (::tg::randomHex never falls back to a weak seed).
proc ::tg::crypto::randomBytes {n} {
    set hex [::tg::randomHex $n]
    if {[string length $hex] != $n * 2} { error "no random source available" }
    binary format H* $hex
}

proc ::tg::crypto::sha256 {data} { ::sha2::sha256 -bin $data }

proc ::tg::crypto::b64u {data} {
    string map {+ - / _ = {}} [binary encode base64 $data]
}

proc ::tg::crypto::b64uDecode {s} {
    set s [string map {- + _ /} $s]
    append s [string repeat = [expr {(4 - [string length $s] % 4) % 4}]]
    binary decode base64 $s
}

proc ::tg::crypto::pem {label der} {
    set b [binary encode base64 -maxlen 64 -wrapchar \n $der]
    return "-----BEGIN $label-----\n$b\n-----END $label-----\n"
}

# -> der bytes of the first PEM block with that label ("" label = any)
proc ::tg::crypto::unpem {text {label ""}} {
    if {$label eq ""} { set label {[A-Z0-9 ]+} } else { set label [string map {. \\.} $label] }
    if {![regexp -- "-----BEGIN ($label)-----(\[^-\]+)-----END \\1-----" $text -> l body]} {
        error "no PEM block found"
    }
    binary decode base64 [string map [list \n {} \r {} { } {} \t {}] $body]
}

# ------------------------------------------------------------------- field / curve ---

proc ::tg::crypto::inv {a m} {
    set a [expr {$a % $m}]
    set r0 $m; set r1 $a; set t0 0; set t1 1
    while {$r1 != 0} {
        set q [expr {$r0 / $r1}]
        set tmp [expr {$r0 - $q * $r1}]; set r0 $r1; set r1 $tmp
        set tmp [expr {$t0 - $q * $t1}]; set t0 $t1; set t1 $tmp
    }
    if {$r0 != 1} { error "value is not invertible" }
    expr {$t0 % $m}
}

# Points are Jacobian triples {X Y Z}; Z = 0 is the point at infinity.
proc ::tg::crypto::pDouble {pt} {
    variable P
    lassign $pt x1 y1 z1
    if {$z1 == 0 || $y1 == 0} { return {0 1 0} }
    set delta [expr {($z1 * $z1) % $P}]
    set gamma [expr {($y1 * $y1) % $P}]
    set beta  [expr {($x1 * $gamma) % $P}]
    set alpha [expr {(3 * (($x1 - $delta) * ($x1 + $delta))) % $P}]
    set x3 [expr {($alpha * $alpha - 8 * $beta) % $P}]
    set t  [expr {$y1 + $z1}]
    set z3 [expr {($t * $t - $gamma - $delta) % $P}]
    set y3 [expr {($alpha * (4 * $beta - $x3) - 8 * $gamma * $gamma) % $P}]
    list $x3 $y3 $z3
}

proc ::tg::crypto::pAdd {p1 p2} {
    variable P
    lassign $p1 x1 y1 z1
    lassign $p2 x2 y2 z2
    if {$z1 == 0} { return $p2 }
    if {$z2 == 0} { return $p1 }
    set z1z1 [expr {($z1 * $z1) % $P}]
    set z2z2 [expr {($z2 * $z2) % $P}]
    set u1 [expr {($x1 * $z2z2) % $P}]
    set u2 [expr {($x2 * $z1z1) % $P}]
    set s1 [expr {($y1 * $z2 * $z2z2) % $P}]
    set s2 [expr {($y2 * $z1 * $z1z1) % $P}]
    set h [expr {($u2 - $u1) % $P}]
    set r [expr {($s2 - $s1) % $P}]
    if {$h == 0} {
        if {$r == 0} { return [pDouble $p1] }
        return {0 1 0}
    }
    set hh  [expr {($h * $h) % $P}]
    set hhh [expr {($h * $hh) % $P}]
    set v   [expr {($u1 * $hh) % $P}]
    set x3 [expr {($r * $r - $hhh - 2 * $v) % $P}]
    set y3 [expr {($r * ($v - $x3) - $s1 * $hhh) % $P}]
    set z3 [expr {($z1 * $z2 * $h) % $P}]
    list $x3 $y3 $z3
}

proc ::tg::crypto::pMul {k pt} {
    set acc {0 1 0}
    foreach bit [split [format %llb $k] ""] {
        set acc [pDouble $acc]
        if {$bit} { set acc [pAdd $acc $pt] }
    }
    return $acc
}

# -> {x y} affine, or {} for infinity
proc ::tg::crypto::toAffine {pt} {
    variable P
    lassign $pt x y z
    if {$z == 0} { return {} }
    set zi [inv $z $P]
    set zi2 [expr {($zi * $zi) % $P}]
    list [expr {($x * $zi2) % $P}] [expr {($y * $zi2 * $zi) % $P}]
}

proc ::tg::crypto::onCurve {x y} {
    variable P; variable B
    expr {$x > 0 && $x < $P && $y > 0 && $y < $P &&
          ($y * $y - ($x * $x * $x - 3 * $x + $B)) % $P == 0}
}

# ------------------------------------------------------------------------- keys ---

# A key is a dict: d (private integer), x, y (public affine coordinates).
proc ::tg::crypto::newKey {} {
    variable N; variable GX; variable GY
    set d [expr {([bytesToInt [randomBytes 48]] % ($N - 1)) + 1}]
    keyFromPrivate $d
}

proc ::tg::crypto::keyFromPrivate {d} {
    variable GX; variable GY
    lassign [toAffine [pMul $d [list $GX $GY 1]]] x y
    dict create d $d x $x y $y
}

proc ::tg::crypto::pubPoint {key} {
    binary format ca*a* 4 [intToBytes [dict get $key x] 32] [intToBytes [dict get $key y] 32]
}

# SEC1 "EC PRIVATE KEY" PEM, which OpenSSL (and therefore tcltls) loads directly.
proc ::tg::crypto::keyToPem {key} {
    variable oid
    set der [seq \
        [derInt 1] \
        [derOctets [intToBytes [dict get $key d] 32]] \
        [derTag 0xA0 [derOid $oid(prime256v1)]] \
        [derTag 0xA1 [derBits [pubPoint $key]]]]
    pem "EC PRIVATE KEY" $der
}

proc ::tg::crypto::keyFromPem {text} {
    set der [unpem $text "EC PRIVATE KEY"]
    lassign [derRead $der 0] tag body
    lassign [derRead $body 0] t1 v off
    lassign [derRead $body $off] t2 priv
    keyFromPrivate [bytesToInt $priv]
}

# SubjectPublicKeyInfo DER for a key (or for a bare 65-byte point).
proc ::tg::crypto::spki {key} {
    variable oid
    seq [seq [derOid $oid(ecPublicKey)] [derOid $oid(prime256v1)]] [derBits [pubPoint $key]]
}

# ----------------------------------------------------------------------------- DER ---

proc ::tg::crypto::derLen {n} {
    if {$n < 128} { return [binary format c $n] }
    set h [format %x $n]
    if {[string length $h] % 2} { set h 0$h }
    binary format ca* [expr {0x80 | [string length $h] / 2}] [binary format H* $h]
}
proc ::tg::crypto::derTag {tag content} {
    append r [binary format c $tag] [derLen [string length $content]] $content
}
proc ::tg::crypto::seq {args}  { derTag 0x30 [join $args ""] }
proc ::tg::crypto::derSet {args} { derTag 0x31 [join $args ""] }
proc ::tg::crypto::derOctets {b} { derTag 0x04 $b }
proc ::tg::crypto::derBits {b}   { derTag 0x03 \x00$b }
proc ::tg::crypto::derUtf8 {s}   { derTag 0x0C [encoding convertto utf-8 $s] }
proc ::tg::crypto::derIa5 {s}    { derTag 0x16 $s }
proc ::tg::crypto::derBool {v}   { derTag 0x01 [expr {$v ? "\xff" : "\x00"}] }
proc ::tg::crypto::derInt {n} {
    set h [format %llx $n]
    if {[string length $h] % 2} { set h 0$h }
    if {[scan [string index $h 0] %x first] && $first >= 8} { set h 00$h }
    derTag 0x02 [binary format H* $h]
}
proc ::tg::crypto::derOid {dotted} {
    set parts [split $dotted .]
    set out [binary format c [expr {40 * [lindex $parts 0] + [lindex $parts 1]}]]
    foreach p [lrange $parts 2 end] {
        set chunk [binary format c [expr {$p & 0x7f}]]
        set p [expr {$p >> 7}]
        while {$p > 0} {
            set chunk [binary format c [expr {0x80 | ($p & 0x7f)}]]$chunk
            set p [expr {$p >> 7}]
        }
        append out $chunk
    }
    derTag 0x06 $out
}
proc ::tg::crypto::derTime {t} {
    set s [clock format $t -format %y%m%d%H%M%SZ -timezone :UTC]
    if {[clock format $t -format %Y -timezone :UTC] >= 2050} {
        return [derTag 0x18 [clock format $t -format %Y%m%d%H%M%SZ -timezone :UTC]]
    }
    derTag 0x17 $s
}

# Read one TLV at offset: -> {tag content nextOffset}
proc ::tg::crypto::derRead {data off} {
    binary scan $data @${off}cu tag
    binary scan $data @[expr {$off + 1}]cu l
    set pos [expr {$off + 2}]
    if {$l >= 128} {
        set nb [expr {$l & 0x7f}]
        if {$nb == 0 || $nb > 4} { error "unsupported DER length" }
        binary scan $data @${pos}a$nb lb
        set l [bytesToInt $lb]
        incr pos $nb
    }
    if {$pos + $l > [string length $data]} { error "DER truncated" }
    list $tag [string range $data $pos [expr {$pos + $l - 1}]] [expr {$pos + $l}]
}

# All TLVs directly inside a constructed value: -> list of {tag content}
proc ::tg::crypto::derChildren {content} {
    set out {}
    set off 0
    while {$off < [string length $content]} {
        lassign [derRead $content $off] tag body off
        lappend out [list $tag $body]
    }
    return $out
}

proc ::tg::crypto::oidString {body} {
    binary scan $body cu* bytes
    set first [lindex $bytes 0]
    set parts [list [expr {$first / 40}] [expr {$first % 40}]]
    set v 0
    foreach b [lrange $bytes 1 end] {
        set v [expr {($v << 7) | ($b & 0x7f)}]
        if {!($b & 0x80)} { lappend parts $v; set v 0 }
    }
    join $parts .
}

# ------------------------------------------------------------------------- ECDSA ---

proc ::tg::crypto::hmac {key data} { ::sha2::hmac -bin -key $key $data }

# RFC 6979 section 3.2 with SHA-256 over the P-256 order.
proc ::tg::crypto::nonce {d h1} {
    variable N
    set x [intToBytes $d 32]
    set hb [intToBytes [expr {[bytesToInt $h1] % $N}] 32]
    set V [string repeat \x01 32]
    set K [string repeat \x00 32]
    set K [hmac $K $V\x00$x$hb]; set V [hmac $K $V]
    set K [hmac $K $V\x01$x$hb]; set V [hmac $K $V]
    while 1 {
        set V [hmac $K $V]
        set k [bytesToInt $V]
        if {$k >= 1 && $k < $N} { return $k }
        set K [hmac $K $V\x00]; set V [hmac $K $V]
    }
}

# -> {r s}
proc ::tg::crypto::signInts {key message} {
    variable N; variable GX; variable GY
    set h [sha256 $message]
    set z [bytesToInt $h]
    set d [dict get $key d]
    set k [nonce $d $h]
    lassign [toAffine [pMul $k [list $GX $GY 1]]] kx ky
    set r [expr {$kx % $N}]
    set s [expr {([inv $k $N] * ($z + $r * $d)) % $N}]
    if {$r == 0 || $s == 0} { error "degenerate signature" }
    list $r $s
}

# ASN.1 DER ECDSA-Sig-Value (what X.509 and TLS carry)
proc ::tg::crypto::signDer {key message} {
    lassign [signInts $key $message] r s
    seq [derInt $r] [derInt $s]
}

# Raw r||s, 64 bytes (what JWS ES256 carries)
proc ::tg::crypto::signRaw {key message} {
    lassign [signInts $key $message] r s
    string cat [intToBytes $r 32] [intToBytes $s 32]
}

proc ::tg::crypto::verifyInts {x y message r s} {
    variable N; variable GX; variable GY
    if {$r < 1 || $r >= $N || $s < 1 || $s >= $N} { return 0 }
    if {![onCurve $x $y]} { return 0 }
    set z [bytesToInt [sha256 $message]]
    set w [inv $s $N]
    set u1 [expr {($z * $w) % $N}]
    set u2 [expr {($r * $w) % $N}]
    set pt [pAdd [pMul $u1 [list $GX $GY 1]] [pMul $u2 [list $x $y 1]]]
    set a [toAffine $pt]
    if {![llength $a]} { return 0 }
    expr {([lindex $a 0] % $N) == $r}
}

proc ::tg::crypto::verifyDer {x y message sigDer} {
    if {[catch {
        lassign [derRead $sigDer 0] tag body
        set kids [derChildren $body]
        set r [bytesToInt [lindex $kids 0 1]]
        set s [bytesToInt [lindex $kids 1 1]]
    }]} { return 0 }
    verifyInts $x $y $message $r $s
}

proc ::tg::crypto::verifyRaw {x y message sig} {
    if {[string length $sig] != 64} { return 0 }
    verifyInts $x $y $message [bytesToInt [string range $sig 0 31]] [bytesToInt [string range $sig 32 63]]
}

# Public key from SPKI DER -> {x y}
proc ::tg::crypto::spkiPoint {der} {
    lassign [derRead $der 0] tag body
    set kids [derChildren $body]
    set bits [lindex $kids 1 1]
    set pt [string range $bits 1 end]
    if {[string length $pt] != 65 || [string index $pt 0] ne "\x04"} { error "not an uncompressed P-256 point" }
    list [bytesToInt [string range $pt 1 32]] [bytesToInt [string range $pt 33 64]]
}

# ------------------------------------------------------------------- X.509 / CSR ---

proc ::tg::crypto::name {cn} {
    variable oid
    seq [derSet [seq [derOid $oid(commonName)] [derUtf8 $cn]]]
}

proc ::tg::crypto::isIpAddress {s} {
    expr {[regexp {^\d+\.\d+\.\d+\.\d+$} $s] || [string first : $s] >= 0}
}

proc ::tg::crypto::ipBytes {s} {
    if {[regexp {^(\d+)\.(\d+)\.(\d+)\.(\d+)$} $s -> a b c d]} {
        return [binary format c4 [list $a $b $c $d]]
    }
    # IPv6: normalise through ::tg::ip when available
    if {[llength [info commands ::tg::ip::expand6]]} {
        return [binary format H* [string map {: {}} [::tg::ip::expand6 $s]]]
    }
    error "cannot encode IPv6 address $s"
}

proc ::tg::crypto::generalNames {names} {
    set out ""
    foreach n $names {
        if {[isIpAddress $n]} { append out [derTag 0x87 [ipBytes $n]] } \
        else { append out [derTag 0x82 [string tolower $n]] }
    }
    return $out
}

proc ::tg::crypto::extension {oidStr critical value} {
    if {$critical} { seq [derOid $oidStr] [derBool 1] [derOctets $value] } \
    else           { seq [derOid $oidStr] [derOctets $value] }
}

# Self-signed certificate. names = DNS names and/or IP addresses; the first is the CN.
proc ::tg::crypto::selfSigned {key names {days 397}} {
    variable oid
    set cn [lindex $names 0]
    set now [clock seconds]
    set serial [expr {[bytesToInt [randomBytes 16]] | (1 << 127)}]
    set ski [string range [sha256 [pubPoint $key]] 0 19]
    set exts [seq \
        [extension $oid(basicConstr) 1 [seq]] \
        [extension $oid(keyUsage) 1 [derBits \x80]] \
        [extension $oid(extKeyUsage) 0 [seq [derOid $oid(serverAuth)]]] \
        [extension $oid(subjectKeyId) 0 [derOctets $ski]] \
        [extension $oid(subjectAltName) 0 [seq [generalNames $names]]]]
    set sigAlg [seq [derOid $oid(ecdsaSha256)]]
    set tbs [seq \
        [derTag 0xA0 [derInt 2]] \
        [derInt $serial] \
        $sigAlg \
        [name $cn] \
        [seq [derTime [expr {$now - 3600}]] [derTime [expr {$now + $days * 86400}]]] \
        [name $cn] \
        [spki $key] \
        [derTag 0xA3 $exts]]
    pem CERTIFICATE [seq $tbs $sigAlg [derBits [signDer $key $tbs]]]
}

# PKCS#10 certificate request (DER) for ACME finalisation.
proc ::tg::crypto::csr {key names} {
    variable oid
    set info [seq \
        [derInt 0] \
        [name [lindex $names 0]] \
        [spki $key] \
        [derTag 0xA0 [seq [derOid $oid(extensionReq)] \
            [derSet [seq [extension $oid(subjectAltName) 0 [seq [generalNames $names]]]]]]]]
    seq $info [seq [derOid $oid(ecdsaSha256)]] [derBits [signDer $key $info]]
}

# What we can read back out of a certificate PEM: notBefore, notAfter (epoch), dns names, cn.
proc ::tg::crypto::certInfo {pemText} {
    variable oid
    set der [unpem $pemText CERTIFICATE]
    lassign [derRead $der 0] t body
    lassign [lindex [derChildren $body] 0] t tbs
    set kids [derChildren $tbs]
    if {[lindex $kids 0 0] == 0xA0} { set kids [lrange $kids 1 end] }
    # serial, sigalg, issuer, validity, subject, spki, [extensions]
    set validity [lindex $kids 3 1]
    lassign [lindex [derChildren $validity] 0] nbTag nb
    lassign [lindex [derChildren $validity] 1] naTag na
    set parseTime {{tag s} {
        if {$tag == 0x17} { set fmt %y%m%d%H%M%SZ } else { set fmt %Y%m%d%H%M%SZ }
        clock scan $s -format $fmt -timezone :UTC
    }}
    set names {}
    set cn ""
    foreach rdn [derChildren [lindex $kids 4 1]] {
        foreach atv [derChildren [lindex $rdn 1]] {
            set pair [derChildren [lindex $atv 1]]
            if {[oidString [lindex $pair 0 1]] eq $oid(commonName)} { set cn [encoding convertfrom utf-8 [lindex $pair 1 1]] }
        }
    }
    foreach k [lrange $kids 6 end] {
        if {[lindex $k 0] != 0xA3} continue
        lassign [lindex [derChildren [lindex $k 1]] 0] t extList
        foreach e [derChildren $extList] {
            set parts [derChildren [lindex $e 1]]
            if {[oidString [lindex $parts 0 1]] ne $oid(subjectAltName)} continue
            lassign [lindex $parts end] t octets
            lassign [lindex [derChildren $octets] 0] t gn
            foreach g [derChildren $gn] {
                lassign $g gt gv
                if {$gt == 0x82} { lappend names $gv } \
                elseif {$gt == 0x87 && [string length $gv] == 4} { binary scan $gv cu4 q; lappend names [join $q .] }
            }
        }
    }
    dict create notBefore [apply $parseTime $nbTag $nb] notAfter [apply $parseTime $naTag $na] names $names cn $cn \
        selfSigned [expr {[lindex $kids 2 1] eq [lindex $kids 4 1]}]
}

# Public key {x y} of a certificate (DER).
proc ::tg::crypto::certPublicPoint {der} {
    lassign [derRead $der 0] t body
    lassign [lindex [derChildren $body] 0] t tbs
    set kids [derChildren $tbs]
    if {[lindex $kids 0 0] == 0xA0} { set kids [lrange $kids 1 end] }
    spkiPoint [derTag 0x30 [lindex $kids 5 1]]
}

# ------------------------------------------------------------------- JWK / JWS ---

# Canonical JWK member order for the RFC 7638 thumbprint is crv, kty, x, y.
proc ::tg::crypto::jwk {key} {
    format {{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}} \
        [b64u [intToBytes [dict get $key x] 32]] [b64u [intToBytes [dict get $key y] 32]]
}

proc ::tg::crypto::thumbprint {key} { b64u [sha256 [jwk $key]] }

# Flattened JWS (ACME style): protected header members are given as a ready JSON fragment.
proc ::tg::crypto::jws {key protectedJson payload} {
    set p [b64u $protectedJson]
    set c [b64u $payload]
    format {{"protected":"%s","payload":"%s","signature":"%s"}} $p $c [b64u [signRaw $key $p.$c]]
}
