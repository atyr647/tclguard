# tlsproxy.tcl -- TLS termination for "http" and "tcp" listeners (needs the tcltls package).
#
# The accept-time defences in tcpproxy.tcl run BEFORE any TLS work happens, so a banned or
# rate-limited address never costs a handshake. A connection that passes them is wrapped with
# tls::import and then sits in the "hs" state until the handshake finishes, with
#   * a deadline          (tlsHandshakeTimeout; slow/silent clients are cut off)
#   * a global cap        (tlsMaxHandshaking; handshakes are the expensive part of TLS)
#   * failure scoring     (protocol garbage earns a strike; a client that merely rejects our
#                          certificate does not)
# Only then does the normal pipeline start (HTTP inspection or the raw relay).
#
# Certificates: files you provide (tlsCert + tlsKey), or a managed one in <state>/certs. A managed
# certificate is a self-signed ECDSA one generated in pure Tcl (no openssl needed) until an ACME
# certificate replaces it (acme.tcl). Files are re-read for every new connection, so renewing a
# certificate on disk needs no restart.

namespace eval ::tg::tls {
    variable have 0
    variable handshaking 0
    variable hs                       ;# id -> start time (ms) while handshaking
    array set hs {}
    variable lastWarn
    array set lastWarn {}
    variable info                     ;# listener name -> cert status dict
    array set info {}
    variable files                    ;# listener name -> {cert key}
    array set files {}
    variable chanConn                 ;# TLS channel -> connection id (server side only)
    array set chanConn {}
    variable hsCount                  ;# TLS channel -> handshakes started so far
    array set hsCount {}
    variable why ""                   ;# when tcltls is present but refused: the reason
    if {![catch {package require tls} ver]} {
        set have 1
        # tcltls 1.7.x segfaults in tls::import (the first TLS use) on macOS: measured on a real Apple-silicon runner with Tcl 8.6.18 and
        # OpenSSL 3.5, 2.0.1 works there. A crash cannot be caught, so macOS with 1.7.x is refused up front.
        if {$::tcl_platform(os) eq "Darwin" && [package vcompare $ver 2.0] < 0} {
            set have 0
            set why "tcltls $ver crashes on macOS; install tcltls 2.0.1 or newer (see docs/TLS.md)"
        }
    }
}

proc ::tg::tls::available {} { variable have; return $have }

proc ::tg::tls::enabled {L} {
    expr {[dict exists $L tls] && [::tg::bool [dict get $L tls]]}
}

# ----------------------------------------------------------------- certificates ---

proc ::tg::tls::certDir {} {
    set d [file join [::tg::cfg::stateDir] certs]
    file mkdir $d
    catch {file attributes $d -permissions 0700}
    return $d
}

# Where this listener's certificate and key live.
proc ::tg::tls::locate {name L} {
    set c [expr {[dict exists $L tlsCert] ? [dict get $L tlsCert] : ""}]
    set k [expr {[dict exists $L tlsKey]  ? [dict get $L tlsKey]  : ""}]
    if {$c ne ""} { return [list $c $k provided] }
    set safe [regsub -all {[^A-Za-z0-9_.-]} $name _]
    # one file holding the certificate chain and the key, so a renewal is a single atomic replace
    set pem [file join [certDir] $safe.pem]
    list $pem $pem managed
}

proc ::tg::tls::defaultNames {L} {
    set n [expr {[dict exists $L tlsNames] ? [dict get $L tlsNames] : {}}]
    if {[llength $n]} { return $n }
    set host [string tolower [info hostname]]
    set names {localhost}
    if {$host ne "" && $host ne "localhost"} { set names [list $host localhost] }
    return [concat $names 127.0.0.1]
}

proc ::tg::tls::readFile {path} {
    set fh [open $path rb]
    set d [read $fh]
    close $fh
    return $d
}

proc ::tg::tls::writeSecret {path data} {
    # created exclusively with mode 0600 from the first byte (no window in which a key is readable by others, no symlink at the temp name)
    set tmp $path.new
    catch {file delete -force -- $tmp}
    set fh [open $tmp [list WRONLY CREAT EXCL] 0600]
    try {
        fconfigure $fh -translation binary
        puts -nonewline $fh $data
        close $fh
    } on error {err opts} {
        catch {close $fh}; catch {file delete -force -- $tmp}
        return -options $opts $err
    }
    file rename -force -- $tmp $path
}

# Make sure a usable certificate exists and is not about to expire; (re)generate a managed
# self-signed one when needed. Returns "" or an error message.
proc ::tg::tls::ensureCert {name L} {
    variable info
    lassign [locate $name $L] cert key mode
    if {$mode eq "provided"} {
        if {![file readable $cert]} { return "certificate file not readable: $cert" }
        if {$key eq "" || ![file readable $key]} { return "private key file not readable: $key" }
    } else {
        # (re)generate only our own self-signed placeholder; never overwrite a CA-issued certificate
        set renew 1
        if {[file exists $cert]} {
            if {![catch {::tg::crypto::certInfo [readFile $cert]} ci]} {
                if {![dict get $ci selfSigned] || [dict get $ci notAfter] - [clock seconds] > 14 * 86400} { set renew 0 }
            }
        }
        if {$renew} {
            if {[catch {
                set k [::tg::crypto::newKey]
                set names [defaultNames $L]
                writeSecret $cert [::tg::crypto::selfSigned $k $names 397][::tg::crypto::keyToPem $k]
            } err]} { return "could not create a certificate: $err" }
            ::tg::log::info "tls '$name': generated a self-signed certificate for [join [defaultNames $L] {, }] ($cert)"
        }
    }
    refreshInfo $name $cert $mode
    return ""
}

proc ::tg::tls::refreshInfo {name cert mode} {
    variable info
    set d [dict create mode $mode cert $cert]
    if {![catch {::tg::crypto::certInfo [readFile $cert]} ci]} {
        set d [dict merge $d $ci]
        dict set d daysLeft [expr {int(([dict get $ci notAfter] - [clock seconds]) / 86400)}]
    }
    set info($name) $d
}

# For the GUI / ctl: what certificate is a listener using?
proc ::tg::tls::certStatus {name} {
    variable info
    if {[info exists info($name)]} { return $info($name) }
    return {}
}

# ------------------------------------------------------------------- listener setup ---

# Called from tcp::start for tls-enabled listeners. Returns "" or an error message.
proc ::tg::tls::prepare {name L} {
    variable have
    variable files
    if {!$have} {
        return "this build has no TLS support (the tcltls package is missing); install it or use the TclGuard starpack from the releases folder"
    }
    set err [ensureCert $name $L]
    if {$err ne ""} { return $err }
    lassign [locate $name $L] cert key mode
    set files($name) [list $cert $key]
    # Prove the certificate and key load and match, once, now, so a mistake shows up when the
    # listener starts and not on the first visitor's connection.
    if {[catch {testLoad $L $cert $key} e]} { return "certificate/key problem: $e" }
    return ""
}

proc ::tg::tls::importOpts {L cert key} {
    set minv [expr {[dict exists $L tlsMinVersion] ? [dict get $L tlsMinVersion] : "1.2"}]
    # tcltls sends only the first certificate of a chain file unless the chain is also in the CA store
    # (OpenSSL then builds leaf + intermediates from it): without this, clients that do not fetch
    # missing intermediates (curl, Go, Python, mobile apps, game launchers) reject Let's Encrypt certificates.
    set opts [list -server 1 -request 0 -require 0 -certfile $cert -keyfile $key -cafile $cert \
        -ssl2 0 -ssl3 0 -tls1 0 -tls1.1 0 -tls1.2 [expr {$minv eq "1.2"}] -tls1.3 1]
    set ciphers [expr {[dict exists $L tlsCiphers] ? [dict get $L tlsCiphers] : ""}]
    if {$ciphers eq ""} { set ciphers {ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!3DES} }
    lappend opts -cipher $ciphers -command ::tg::tls::callback
    return $opts
}

# Without a callback tcltls turns every failed handshake (peer closed early, port scan, ...) into a
# Tcl background error. We handle failures ourselves in step{}, so keep this silent.
proc ::tg::tls::callback {event chan args} {
    variable chanConn
    variable hsCount
    if {$event eq "verify"} { return [lindex $args 2] }   ;# keep OpenSSL's verdict
    # A second "handshake start" on an established server connection is a client-initiated TLS 1.2
    # renegotiation: every one costs a full handshake, and with some TLS libraries (LibreSSL, which is
    # what the starpack uses) a single connection could demand them without limit. Nobody legitimate
    # needs it (we never ask for client certificates), so cut the connection off.
    if {$event eq "info" && [lindex $args 0] eq "handshake" && [lindex $args 1] eq "start" && [info exists chanConn($chan)]} {
        if {[incr hsCount($chan)] > 1} {
            set id $chanConn($chan)
            unset chanConn($chan)
            after 0 [list ::tg::tls::renegotiated $id]
        }
    }
    return
}

proc ::tg::tls::renegotiated {id} {
    if {![info exists ::tg::tcp::cc($id)]} return
    ::tg::stat::incr tlsFail
    ::tg::log::debug "tls '$::tg::tcp::cl($id)': renegotiation attempt from $::tg::tcp::cip($id): connection closed"
    ::tg::ban::strike $::tg::tcp::cip($id) 3 "TLS renegotiation on $::tg::tcp::cl($id)"
    ::tg::tcp::close_ $id "TLS renegotiation refused"
}

# Import a throwaway channel to make OpenSSL parse and match the key and certificate.
proc ::tg::tls::testLoad {L cert key} {
    set null [expr {$::tcl_platform(platform) eq "windows" ? "NUL" : "/dev/null"}]
    set ch [open $null r+]
    if {[catch {::tls::import $ch {*}[importOpts $L $cert $key]} err]} {
        catch {close $ch}
        error $err
    }
    catch {close $ch}
}

# ------------------------------------------------------------------ per connection ---

# Called by tcp::newConn instead of starting the pipeline. Returns 1 if the connection went on
# to the handshake state, 0 if it was refused (and closed).
proc ::tg::tls::start {id chan name L} {
    variable handshaking
    variable hs
    variable files
    variable chanConn
    variable hsCount
    set max [expr {[dict exists $L tlsMaxHandshaking] ? [dict get $L tlsMaxHandshaking] : 256}]
    if {$handshaking >= $max} {
        ::tg::stat::incr tlsRefused
        ::tg::tcp::close_ $id "too many TLS handshakes in progress"
        return 0
    }
    if {![info exists files($name)]} { ::tg::tcp::close_ $id "TLS not prepared"; return 0 }
    lassign $files($name) cert key
    if {[catch {::tls::import $chan {*}[importOpts $L $cert $key]} err]} {
        warnOnce $name "TLS import failed: $err"
        ::tg::tcp::close_ $id "TLS setup failed"
        return 0
    }
    incr handshaking
    set chanConn($chan) $id
    set hsCount($chan) 0
    set hs($id) [::tg::now]
    set ::tg::tcp::st($id) hs
    set ::tg::tcp::dl($id) [expr {[::tg::now] + [dict get $L tlsHandshakeTimeout] * 1000}]
    fileevent $chan readable [list ::tg::tls::step $id]
    return 1
}

proc ::tg::tls::step {id} {
    variable handshaking
    variable hs
    if {![info exists ::tg::tcp::cc($id)] || ![info exists hs($id)]} return
    set chan $::tg::tcp::cc($id)
    if {[catch {::tls::handshake $chan} r]} {
        failed $id $r
        return
    }
    if {$r != 1} return                      ;# needs more I/O
    # done
    unset hs($id)
    incr handshaking -1
    ::tg::stat::incr tlsOk
    fileevent $chan readable {}
    set ::tg::tcp::dl($id) 0
    set ::tg::tcp::st($id) wait
    ::tg::tcp::ready $id
}

# Errors that mean the other side did not like us (certificate rejected, closed early, ...) are
# not abuse; protocol garbage is.
proc ::tg::tls::classify {msg} {
    set m [string tolower $msg]
    if {[string match "*alert*" $m] || [string match "*unexpected eof*" $m] || [string match "*connection reset*" $m] ||
        [string match "*eof*" $m] || [string match "*broken pipe*" $m]} { return benign }
    if {[string match "*http request*" $m]} { return plain }
    return garbage
}

proc ::tg::tls::failed {id msg} {
    variable handshaking
    variable hs
    set ip $::tg::tcp::cip($id)
    set name $::tg::tcp::cl($id)
    if {[info exists hs($id)]} { unset hs($id); incr handshaking -1 }
    ::tg::stat::incr tlsFail
    switch -- [classify $msg] {
        garbage {
            ::tg::tcp::close_ $id "TLS handshake failed"
            ::tg::ban::strike $ip 1 "bad TLS handshake on $name"
        }
        plain   { ::tg::tcp::close_ $id "plain HTTP sent to a TLS port" }
        default { ::tg::tcp::close_ $id "TLS handshake aborted" }
    }
}

# 1 Hz: handshake deadline handled by tcp::sweep via timeout below.
proc ::tg::tls::timeout {id} {
    variable handshaking
    variable hs
    if {[info exists hs($id)]} { unset hs($id); incr handshaking -1 }
    ::tg::stat::incr tlsFail
    ::tg::ban::strike $::tg::tcp::cip($id) 1 "TLS handshake never completed on $::tg::tcp::cl($id)"
    ::tg::tcp::close_ $id "TLS handshake timeout"
}

# Connection closed while handshaking (called from tcp::close_).
proc ::tg::tls::forget {id} {
    variable handshaking
    variable hs
    if {[info exists hs($id)]} { unset hs($id); incr handshaking -1 }
}

# Drop the per-channel bookkeeping when a connection goes away (called from tcp::close_).
proc ::tg::tls::release {chan} {
    variable chanConn
    variable hsCount
    unset -nocomplain chanConn($chan) hsCount($chan)
}

proc ::tg::tls::warnOnce {name msg} {
    variable lastWarn
    set now [clock seconds]
    if {![info exists lastWarn($name,$msg)] || $now - $lastWarn($name,$msg) > 60} {
        set lastWarn($name,$msg) $now
        ::tg::log::warn "tls '$name': $msg"
    }
}

proc ::tg::tls::stop {name} {
    variable files
    variable info
    unset -nocomplain files($name) info($name)
}

# Daily-ish housekeeping from the engine: refresh expiry info, regenerate managed self-signed
# certificates before they expire, warn about provided ones.
proc ::tg::tls::housekeeping {} {
    variable files
    foreach {n L} [::tg::cfg::listeners] {
        if {![info exists files($n)] || ![enabled $L]} continue
        set err [ensureCert $n $L]
        if {$err ne ""} { warnOnce $n $err; continue }
        set st [certStatus $n]
        if {[dict exists $st daysLeft] && [dict get $st daysLeft] < 14 && [dict get $st mode] eq "provided"} {
            warnOnce $n "certificate expires in [dict get $st daysLeft] day(s): renew it"
        }
    }
}

proc ::tg::tls::status {} {
    variable handshaking
    variable info
    dict create handshaking $handshaking certs [array get info]
}
