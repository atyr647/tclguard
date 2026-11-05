# update.tcl -- signed self-update.
#
#   ::tg::update::check ?opts?     look for a newer release           -> dict (ok, status, latest, verified, ...)
#   ::tg::update::apply ?opts?     download, verify, swap in          -> dict (ok, error, old, new, ...)
#   ::tg::update::rollback ?opts?  put the previous program back      -> dict
#   ::tg::update::status           what we know (current, last check, previous copy) -> dict
#   ::tg::update::autoCheck        rate-limited (24 h) check for the GUI; never installs -> dict
#   ::tg::update::keygen file      create a release-signing key (maintainers)           -> dict
#   ::tg::update::buildManifest / signBytes      used by tools/release-manifest.tcl
#
# None of the API procs raises: failures come back as {ok 0 error "..."}.
#
# TRUST MODEL (docs/UPDATES.md has the long version)
#   * A release is described by manifest.json, signed with an ECDSA P-256 key. The matching PUBLIC key is
#     embedded in this program (vendor/update-key.pub). The signature (manifest.json.sig, base64url of
#     the raw 64-byte r||s) covers the EXACT bytes of the manifest. No field of the manifest is read,
#     let alone used, before that signature verified.
#   * The manifest names, per platform, a download URL, a SHA-256 and a size. The binary is accepted
#     only if size and SHA-256 match, the version is strictly newer than the running one, and the new
#     program prints that version when asked (`version`), i.e. it demonstrably runs on this machine.
#   * Transport: HTTPS only, certificate chain AND host name verified (::tg::https::socket), redirects
#     only to https:// (so TLS is defence in depth; the signature is what is trusted), hard size caps
#     enforced WHILE downloading.
#   * While the embedded key is the UNSET placeholder, `apply` refuses and `check` marks results unverified.
#   * Swap: the new file is written next to the old one, then renamed into place (Unix: atomic rename;
#     Windows: a running starpack cannot be renamed, so a hidden helper does the rename once the program has exited). The old program is
#     kept as <name>.previous (rollback). Every failure path leaves the old program untouched and removes
#     the temporary file.
#
# Not protected: see "What is NOT protected" in docs/UPDATES.md (a compromised signing key; a
# network attacker who simply withholds updates or serves an older, validly signed manifest;
# the very first download of TclGuard).

namespace eval ::tg::update {
    variable defaultUrl https://github.com/atyr647/tclguard/releases/latest/download/manifest.json
    variable maxManifest 262144
    variable maxSig 1024
    variable maxBinary 67108864
    variable dir [file dirname [info script]]     ;# captured while the file is being sourced
    variable pubKeyText ""         ;# tests: use this instead of vendor/update-key.pub
    variable targetOverride ""     ;# tests / packagers: replace this file instead of the running program
    variable stateFileOverride ""
    variable runTimeout 20000      ;# ms the new program gets to print its version
    variable checkInterval 86400   ;# autoCheck: once per day
    variable retryInterval 3600    ;# ... or after one hour when the last attempt failed
    variable keyPlaceholder UNSET
    variable xfer              ;# download state (array)
    array set xfer {}
    variable rv
    array set rv {}
}

# =========================================================================== versions ====

# "1.2.3", "1.10", "2.0.0-rc.1", "1.0.0+build5". Returns {numbers prerelease} or raises.
proc ::tg::update::parseVersion {v} {
    if {[string length $v] > 64 || ![regexp {^([0-9]{1,9}(?:\.[0-9]{1,9}){0,3})(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z.-]+)?$} $v -> nums pre]} {
        error "'$v' is not a version number"
    }
    list [lmap n [split $nums .] {scan $n %d}] $pre
}

proc ::tg::update::isVersion {v} { expr {![catch {parseVersion $v}]} }

# -1 / 0 / 1. Numbers compare numerically (1.10 > 1.9), 1.0 == 1.0.0, a release is newer than its pre-release.
proc ::tg::update::compareVersions {a b} {
    lassign [parseVersion $a] na pa
    lassign [parseVersion $b] nb pb
    set n [expr {max([llength $na], [llength $nb])}]
    for {set i 0} {$i < $n} {incr i} {
        set x [expr {$i < [llength $na] ? [lindex $na $i] : 0}]
        set y [expr {$i < [llength $nb] ? [lindex $nb $i] : 0}]
        if {$x != $y} { return [expr {$x < $y ? -1 : 1}] }
    }
    if {$pa eq $pb} { return 0 }
    if {$pa eq ""} { return 1 }
    if {$pb eq ""} { return -1 }
    set ia [split $pa .]
    set ib [split $pb .]
    set m [expr {min([llength $ia], [llength $ib])}]
    for {set i 0} {$i < $m} {incr i} {
        set x [lindex $ia $i]
        set y [lindex $ib $i]
        if {$x eq $y} continue
        set xn [string is digit -strict $x]
        set yn [string is digit -strict $y]
        if {$xn && $yn} { return [expr {[scan $x %d] < [scan $y %d] ? -1 : 1}] }
        if {$xn} { return -1 }
        if {$yn} { return 1 }
        return [expr {[string compare $x $y] < 0 ? -1 : 1}]
    }
    expr {[llength $ia] < [llength $ib] ? -1 : [llength $ia] > [llength $ib] ? 1 : 0}
}

# ============================================================================ platform ====

# linux-x86_64, windows-x86_64, macos-arm64 ... (arguments only for tests)
proc ::tg::update::platformKey {{os ""} {machine ""} {ptr ""}} {
    global tcl_platform
    if {$os eq ""} { set os $tcl_platform(os) }
    if {$machine eq ""} { set machine $tcl_platform(machine) }
    if {$ptr eq ""} { set ptr $tcl_platform(pointerSize) }
    switch -glob -- [string tolower $os] {
        linux*   { set o linux }
        windows* { set o windows }
        darwin*  { set o macos }
        default  { set o [regsub -all {[^a-z0-9]} [string tolower $os] {}] }
    }
    switch -- [string tolower $machine] {
        x86_64 - amd64 - x64 - em64t { set a x86_64 }
        aarch64 - arm64 { set a arm64 }
        intel - i386 - i486 - i586 - i686 - x86 { set a [expr {$ptr == 8 ? "x86_64" : "x86"}] }
        default { set a [regsub -all {[^a-z0-9_]} [string tolower $machine] {}] }
    }
    return $o-$a
}

# "console" for the console build of the Windows program (it must be replaced by the console build).
proc ::tg::update::flavor {exe} {
    if {[regexp -nocase {console} [file tail $exe]]} { return console }
    set rec [file join [file dirname $exe] install.json]
    if {[file isfile $rec] && ![catch {::tg::readFile $rec} t] && [regexp {"flavor"\s*:\s*"console"} $t]} { return console }
    return gui
}

# ================================================================================ keys ====

# -> dict: state (ok|unset), and for ok: x y point fingerprint. Raises on a malformed key file.
proc ::tg::update::publicKey {} {
    variable pubKeyText
    variable dir
    variable keyPlaceholder
    if {$pubKeyText ne ""} {
        set text $pubKeyText
    } else {
        set f [file join $dir vendor update-key.pub]
        if {[catch {::tg::readFile $f} text]} { error "the embedded update key (vendor/update-key.pub) cannot be read: $text" }
    }
    set line ""
    foreach l [split $text \n] {
        set l [string trim $l]
        if {$l eq "" || [string index $l 0] eq "#"} continue
        if {[string first "-----BEGIN" $l] == 0} { set line $text; break }
        set line $l
        break
    }
    if {$line eq ""} { error "the embedded update key file is empty" }
    if {[string match "tgpub1:*" $line]} {
        set body [string range $line 7 end]
        if {$body eq $keyPlaceholder} { return [dict create state unset] }
        if {![regexp {^[A-Za-z0-9_-]{87}$} $body]} { error "the embedded update key is malformed" }
        set pt [::tg::crypto::b64uDecode $body]
        if {[string length $pt] != 65 || [string index $pt 0] ne "\x04"} { error "the embedded update key is not an uncompressed P-256 point" }
        set x [::tg::crypto::bytesToInt [string range $pt 1 32]]
        set y [::tg::crypto::bytesToInt [string range $pt 33 64]]
    } elseif {[string match "*-----BEGIN PUBLIC KEY-----*" $line]} {
        if {[catch {::tg::crypto::spkiPoint [::tg::crypto::unpem $line "PUBLIC KEY"]} xy]} { error "the embedded update key is malformed: $xy" }
        lassign $xy x y
        set pt [binary format ca*a* 4 [::tg::crypto::intToBytes $x 32] [::tg::crypto::intToBytes $y 32]]
    } else {
        error "the embedded update key is in an unknown format"
    }
    if {![::tg::crypto::onCurve $x $y]} { error "the embedded update key is not a point on the P-256 curve" }
    dict create state ok x $x y $y point $pt fingerprint [fingerprint $pt]
}

proc ::tg::update::fingerprint {point} {
    binary scan [::tg::crypto::sha256 $point] H32 h
    join [regexp -all -inline {.{4}} $h] " "
}

proc ::tg::update::publicKeyLine {key} { return "tgpub1:[::tg::crypto::b64u [::tg::crypto::pubPoint $key]]" }

# Detached signature: base64url (no padding) of the 64-byte raw r||s over the exact bytes.
proc ::tg::update::signBytes {key bytes} { ::tg::crypto::b64u [::tg::crypto::signRaw $key $bytes] }

proc ::tg::update::verifyBytes {x y bytes sigText} {
    set sig [string trim $sigText]
    if {![regexp {^[A-Za-z0-9_-]{86}$} $sig]} { return 0 }
    if {[catch {::tg::crypto::b64uDecode $sig} raw] || [string length $raw] != 64} { return 0 }
    if {[catch {::tg::crypto::verifyRaw $x $y $bytes $raw} ok]} { return 0 }
    expr {!!$ok}
}

# keygen file -> dict ok error publicKey fingerprint path
proc ::tg::update::keygen {path} {
    if {[catch {
        if {$path eq ""} { error "give a file name: tclguard update keygen --out FILE" }
        if {[file exists $path]} { error "$path already exists; refusing to overwrite a key" }
        set key [::tg::crypto::newKey]
        # prove that the key works before it is trusted with anything
        set probe "tclguard key self-test"
        if {![verifyBytes [dict get $key x] [dict get $key y] $probe [signBytes $key $probe]]} { error "the generated key failed its self-test" }
        # created with owner-only permissions from the start, so there is never a world-readable moment
        set fh [open $path {WRONLY CREAT EXCL} 0600]
        try {
            fconfigure $fh -translation lf
            puts -nonewline $fh [::tg::crypto::keyToPem $key]
        } finally {
            close $fh
        }
        catch { file attributes $path -permissions 0600 }
        set back [::tg::crypto::keyFromPem [::tg::readFile $path]]
        if {[dict get $back d] != [dict get $key d]} { file delete -force -- $path; error "the key file could not be read back" }
    } err]} { return [dict create ok 0 error $err] }
    dict create ok 1 path $path publicKey [publicKeyLine $key] fingerprint [fingerprint [::tg::crypto::pubPoint $key]]
}

# Private key from a file path, or (path "") from the TG_RELEASE_KEY environment variable
# (a path, or the PEM text itself, which is what a CI secret provides).
proc ::tg::update::loadPrivateKey {{path ""}} {
    global env
    if {$path eq "" && [info exists env(TG_RELEASE_KEY)] && $env(TG_RELEASE_KEY) ne ""} { set path $env(TG_RELEASE_KEY) }
    if {$path eq ""} { error "no signing key: give a key file or set TG_RELEASE_KEY" }
    if {[string match "*-----BEGIN EC PRIVATE KEY-----*" $path]} {
        set text $path
    } else {
        if {![file isfile $path]} { error "signing key file not found: $path" }
        set text [::tg::readFile $path]
    }
    ::tg::crypto::keyFromPem $text
}

# ============================================================================ manifest ====

proc ::tg::update::checkUrl {url} {
    if {![regexp {^https://([^/?#@\s]+)(/[^\s\x00-\x1f"'<>\\^`{|}]*)?$} $url]} {
        if {[regexp -nocase {^http://} $url]} { error "refusing a non-HTTPS address: $url" }
        error "not a valid https:// address: $url"
    }
    if {[string length $url] > 2048} { error "address is too long" }
    return $url
}

# Raises on anything suspicious. Returns the checked manifest as a dict:
# version issued notes min files (dict platform -> {name url sha256 size}).
proc ::tg::update::validateManifest {m} {
    variable maxBinary
    if {[catch {dict size $m}]} { error "the manifest is not a JSON object" }
    foreach k {version issued files} { if {![dict exists $m $k]} { error "the manifest lacks '$k'" } }
    set ver [dict get $m version]
    if {![isVersion $ver]} { error "the manifest version '$ver' is not a version number" }
    set issued [dict get $m issued]
    if {![regexp {^[0-9]{1,12}$} $issued]} { error "the manifest 'issued' is not a unix time" }
    set min ""
    if {[dict exists $m min] && [dict get $m min] ne ""} {
        set min [dict get $m min]
        if {![isVersion $min]} { error "the manifest 'min' is not a version number" }
    }
    set notes ""
    if {[dict exists $m notes]} {
        set notes [dict get $m notes]
        if {[string length $notes] > 8000} { error "the release notes are too long" }
        set notes [regsub -all {[\x00-\x08\x0b-\x1f\x7f]} $notes {}]
    }
    set files {}
    set fd [dict get $m files]
    if {[catch {dict size $fd}]} { error "the manifest 'files' is not an object" }
    dict for {key f} $fd {
        if {![regexp {^[a-z0-9][a-z0-9_-]{0,39}$} $key]} { error "bad platform name '$key' in the manifest" }
        if {[catch {dict size $f}]} { error "entry '$key' is not an object" }
        foreach k {name url sha256 size} { if {![dict exists $f $k]} { error "entry '$key' lacks '$k'" } }
        set name [dict get $f name]
        if {![regexp {^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$} $name] || [string first .. $name] >= 0} { error "entry '$key' has an unsafe file name" }
        if {[catch {checkUrl [dict get $f url]} e]} { error "entry '$key': $e" }
        set sha [string tolower [dict get $f sha256]]
        if {![regexp {^[0-9a-f]{64}$} $sha]} { error "entry '$key' has a bad sha256" }
        set size [dict get $f size]
        if {![regexp {^[1-9][0-9]{0,9}$} $size] || $size > $maxBinary} { error "entry '$key' has a size outside 1..$maxBinary bytes" }
        dict set files $key [dict create name $name url [dict get $f url] sha256 $sha size [scan $size %d]]
    }
    dict create version $ver issued $issued notes $notes min $min files $files
}

# Bytes -> validated manifest dict. Does NOT check the signature; callers verify first.
proc ::tg::update::parseManifest {bytes} {
    variable maxManifest
    if {[string length $bytes] > $maxManifest} { error "the manifest is larger than $maxManifest bytes" }
    set text [encoding convertfrom utf-8 $bytes]
    validateManifest [::tg::json::parse $text]
}

# The entry for this machine, honouring the console flavour on Windows.
proc ::tg::update::pickFile {m exe} {
    set key [platformKey]
    set files [dict get $m files]
    if {[flavor $exe] eq "console" && [dict exists $files $key-console]} { return [dict get $files $key-console] }
    if {[dict exists $files $key]} { return [dict get $files $key] }
    error "this release has no download for $key"
}

# ---- release-side: build and sign (tools/release-manifest.tcl, tests) ----

# tclguard-linux-x86_64, tclguard-windows-x86_64.exe, tclguard-windows-x86_64-console.exe, tclguard-macos-arm64
proc ::tg::update::releaseKey {name} {
    if {![regexp {^tclguard-(linux|windows|macos)-(x86_64|arm64|x86|arm)(-console)?(\.exe)?$} $name -> os arch console exe]} { return "" }
    if {($os eq "windows") != ($exe ne "")} { return "" }
    return $os-$arch$console
}

# Streaming SHA-256 of a file (hex). progress is called with {done total} per megabyte.
proc ::tg::update::sha256File {path {progress ""}} {
    set total [file size $path]
    set tok [::sha2::SHA256Init]
    set fh [open $path rb]
    set done 0
    try {
        while {![eof $fh]} {
            set chunk [read $fh 1048576]
            if {$chunk eq ""} break
            ::sha2::SHA256Update $tok $chunk
            incr done [string length $chunk]
            if {$progress ne ""} { {*}$progress $done $total }
        }
    } on error {e o} {
        catch { ::sha2::SHA256Final $tok }
        return -options $o $e
    } finally {
        close $fh
    }
    binary scan [::sha2::SHA256Final $tok] H* hex
    return $hex
}

# buildManifest dir version ?-notes t -min v -issued n -urlbase u? -> manifest text (exact bytes to sign).
proc ::tg::update::buildManifest {dir version args} {
    variable maxBinary
    array set o {-notes "" -min "" -issued "" -urlbase ""}
    array set o $args
    if {![isVersion $version]} { error "'$version' is not a version number" }
    if {$o(-issued) eq ""} { set o(-issued) [clock seconds] }
    if {$o(-urlbase) eq ""} { set o(-urlbase) "https://github.com/atyr647/tclguard/releases/download/v$version/" }
    set base [string trimright $o(-urlbase) /]/
    set files {}
    foreach f [lsort [glob -nocomplain -directory $dir -types f tclguard-*]] {
        set name [file tail $f]
        set key [releaseKey $name]
        if {$key eq ""} continue
        set size [file size $f]
        if {$size < 1 || $size > $maxBinary} { error "$name: size $size is outside 1..$maxBinary" }
        lappend files $key [::tg::json::object \
            name [::tg::json::quote $name] \
            url [::tg::json::quote $base$name] \
            sha256 [::tg::json::quote [sha256File $f]] \
            size $size]
    }
    if {![llength $files]} { error "no release files (tclguard-<os>-<arch>\[.exe\]) found in $dir" }
    set pairs [list version [::tg::json::quote $version] issued [::tg::json::quote $o(-issued)] notes [::tg::json::quote $o(-notes)]]
    if {$o(-min) ne ""} { lappend pairs min [::tg::json::quote $o(-min)] }
    lappend pairs files [::tg::json::object {*}$files]
    return "[::tg::json::object {*}$pairs]\n"
}

# =========================================================================== transfer ====

proc ::tg::update::cfgCaFile {} {
    global env
    set ca ""
    catch { set ca [::tg::cfg::general caFile] }
    if {$ca eq "" && [info exists env(TG_CA_FILE)]} { set ca $env(TG_CA_FILE) }
    return $ca
}

# TLS trust anchors: the system bundle (or the one shipped in the starpack) unless the user pointed
# us at another CA file (private mirrors, tests). Signatures, not TLS, decide what is trusted.
proc ::tg::update::prepareTls {} {
    set ca [cfgCaFile]
    if {$ca ne ""} {
        if {![file readable $ca]} { error "the configured CA file '$ca' cannot be read" }
        ::tg::https::setCaFile $ca
    }
    catch { file mkdir [stateDir] }      ;# the bundled CA list is unpacked there on Windows
    ::tg::https::init
}

proc ::tg::update::resolveUrl {base loc} {
    if {[regexp -nocase {^https?://} $loc]} { return $loc }
    regexp -nocase {^(https?://[^/?#]+)(/[^?#]*)?} $base -> origin path
    if {[string match //* $loc]} { return "https:$loc" }
    if {[string index $loc 0] eq "/"} { return $origin$loc }
    set d [expr {[string last / $path] >= 0 ? [string range $path 0 [string last / $path]] : "/"}]
    return $origin$d$loc
}

# http -handler: called with each chunk. Redirect and error bodies are discarded (they must not end
# up in the download); the body of the final response is counted against the limit AS IT ARRIVES.
proc ::tg::update::onData {sock token} {
    variable xfer
    # A SIZED read: a plain [read $sock] keeps reading while data keeps arriving, so a server that sends faster than we can
    # return from the call (measured: one call took 53 MB, in another run 370 MB) defeats the size limit checked below and
    # fills memory. 64 KB per call bounds the overshoot to one block.
    set data [read $sock 65536]
    set n [string length $data]
    set code [::http::ncode $token]
    if {$code != 200} {
        incr xfer(discarded) $n
        if {$xfer(discarded) > 65536} { error "unexpected response body" }
        return $n
    }
    incr xfer(count) $n
    if {$xfer(count) > $xfer(max)} { error "the download is larger than the allowed $xfer(max) bytes" }
    if {$xfer(fh) ne ""} { puts -nonewline $xfer(fh) $data } else { append xfer(body) $data }
    if {$xfer(progress) ne ""} {
        set total 0
        catch { set total [dict get [::http::meta $token] Content-Length] }
        catch { {*}$xfer(progress) download $xfer(count) $total }
    }
    return $n
}

# fetch url ?-maxbytes n -timeout ms -file path -progress cmd -redirects n? -> dict code url body size
# Uses the verified HTTPS layer (::tg::https::socket: chain + host name) through ::http, so that the
# size limit applies while the data arrives and redirect bodies are never mixed into the result.
proc ::tg::update::fetch {url args} {
    variable xfer
    array set o {-maxbytes 262144 -timeout 30000 -file "" -progress "" -redirects 5}
    array set o $args
    checkUrl $url
    prepareTls
    set hops 0
    while 1 {
        array unset xfer
        array set xfer [list max $o(-maxbytes) count 0 discarded 0 body "" fh "" progress $o(-progress)]
        if {$o(-file) ne ""} {
            # never write through a pre-planted symbolic link: remove whatever is there, then create EXCLUSIVELY
            catch { file delete -force -- $o(-file) }
            set xfer(fh) [open $o(-file) {WRONLY CREAT EXCL BINARY} 0700]
        }
        set tok ""
        try {
            if {[catch {
                set tok [::http::geturl $url -method GET -binary 1 -keepalive 0 -timeout $o(-timeout) \
                    -handler ::tg::update::onData -headers [list User-Agent "TclGuard/$::tg::VERSION"]]
            } err]} { error "request failed: $err" }
            set status [::http::status $tok]
            if {$status ne "ok"} {
                set why [expr {$status eq "error" ? [::http::error $tok] : $status}]
                error "request failed: $why"
            }
            set code [::http::ncode $tok]
            set hdrs {}
            foreach {k v} [::http::meta $tok] { dict set hdrs [string tolower $k] $v }
        } finally {
            if {$tok ne ""} { ::http::cleanup $tok }
            if {$xfer(fh) ne ""} { catch { close $xfer(fh) }; set xfer(fh) "" }
        }
        if {$code in {301 302 303 307 308}} {
            if {![dict exists $hdrs location]} { error "redirect without a Location" }
            if {[incr hops] > $o(-redirects)} { error "too many redirects" }
            set url [resolveUrl $url [dict get $hdrs location]]
            if {[catch {checkUrl $url} e]} { error "redirect refused: $e" }
            if {$o(-file) ne ""} { catch { file delete -force -- $o(-file) } }
            continue
        }
        if {$code != 200} { error "the server answered $code for $url" }
        return [dict create code $code url $url body $xfer(body) size $xfer(count)]
    }
}

# ================================================================================ state ====

# The state folder, even when no configuration file has been loaded (then ::tg::cfg::stateDir would
# answer "./state", i.e. wherever the current directory happens to be).
proc ::tg::update::stateDir {} {
    if {$::tg::cfg::path eq "" && [::tg::cfg::general stateDir] eq ""} { return [file join [::tg::cfg::homeDir] state] }
    ::tg::cfg::stateDir
}

proc ::tg::update::stateFile {} {
    variable stateFileOverride
    if {$stateFileOverride ne ""} { return $stateFileOverride }
    file join [stateDir] update-state.json
}

proc ::tg::update::loadState {} {
    set f [stateFile]
    if {![file isfile $f]} { return {} }
    if {[catch {::tg::json::parse [::tg::readFile $f]} d] || [catch {dict size $d}]} { return {} }
    return $d
}

proc ::tg::update::saveState {d} {
    set pairs {}
    dict for {k v} $d {
        lappend pairs $k [expr {$k in {lastCheck lastVerified lastApplied lastRollback pendingRestart} && [regexp {^(0|[1-9][0-9]{0,11})$} $v] ? $v : [::tg::json::quote $v]}]
    }
    catch {
        file mkdir [file dirname [stateFile]]
        ::tg::writeFileAtomic [stateFile] "[::tg::json::object {*}$pairs]\n"
    }
}

proc ::tg::update::updateState {args} {
    set d [loadState]
    foreach {k v} $args { dict set d $k $v }
    saveState $d
}

proc ::tg::update::nowSec {} { expr {[::tg::now] / 1000} }

# ================================================================================ check ====

proc ::tg::update::feedUrl {opts} {
    variable defaultUrl
    if {[dict exists $opts url] && [dict get $opts url] ne ""} { return [dict get $opts url] }
    set u ""
    catch { set u [::tg::cfg::general updateUrl] }
    if {$u ne ""} { return $u }
    return $defaultUrl
}

# Fetch, verify and read the manifest. Returns a dict; raises nothing.
#   ok 0 error ...                     could not get a trustworthy manifest
#   ok 1 verified 0|1 manifest dict    verified 0 only while the embedded key is the placeholder
proc ::tg::update::loadManifest {opts} {
    variable maxManifest
    variable maxSig
    if {[catch {
        set url [feedUrl $opts]
        checkUrl $url
        set key [publicKey]
        set r [fetch $url -maxbytes $maxManifest -timeout 30000]
        set bytes [dict get $r body]
        set verified 0
        if {[dict get $key state] eq "ok"} {
            if {[catch {fetch $url.sig -maxbytes $maxSig -timeout 30000} sr]} {
                error "the release is not signed (could not get $url.sig: $sr). Not trusting it."
            }
            if {![verifyBytes [dict get $key x] [dict get $key y] $bytes [dict get $sr body]]} {
                error "the release signature is NOT valid. This manifest was not signed by the TclGuard release key; ignoring it."
            }
            set verified 1
        }
        set m [parseManifest $bytes]
    } err]} { return [dict create ok 0 error $err] }
    dict create ok 1 verified $verified manifest $m url $url keyState [dict get $key state]
}

# check ?{url U}? -> dict
#   ok status (uptodate|available|ahead|nofile|error) current latest verified keyState notes issued min
#   needsManual file(name url sha256 size) manifestUrl platform checkedAt
proc ::tg::update::check {{opts {}}} {
    set res [dict create ok 0 status error current $::tg::VERSION verified 0 platform [platformKey]]
    if {[catch {checkInner $opts} r opts2]} {
        catch { ::tg::log::debug [dict get $opts2 -errorinfo] }
        set r [dict create ok 0 error $r]
    }
    set res [dict merge $res $r]
    dict set res checkedAt [nowSec]
    if {![dict exists $opts noState] || ![dict get $opts noState]} {
        catch {
            updateState lastCheck [dict get $res checkedAt] lastStatus [dict get $res status] \
                latest [expr {[dict exists $res latest] ? [dict get $res latest] : ""}] \
                lastVerified [dict get $res verified] \
                lastError [expr {[dict exists $res error] ? [dict get $res error] : ""}] \
                lastNotes [expr {[dict exists $res notes] ? [dict get $res notes] : ""}]
        }
    }
    return $res
}

proc ::tg::update::checkInner {opts} {
    set lm [loadManifest $opts]
    if {![dict get $lm ok]} { return [dict create ok 0 status error error [dict get $lm error]] }
    set m [dict get $lm manifest]
    set res [dict create ok 1 verified [dict get $lm verified] keyState [dict get $lm keyState] manifestUrl [dict get $lm url] \
        latest [dict get $m version] notes [dict get $m notes] issued [dict get $m issued] min [dict get $m min] needsManual 0]
    set cmp [compareVersions [dict get $m version] $::tg::VERSION]
    if {$cmp < 0} { dict set res status ahead; return $res }
    if {$cmp == 0} { dict set res status uptodate; return $res }
    if {[dict get $m min] ne "" && [compareVersions $::tg::VERSION [dict get $m min]] < 0} {
        dict set res needsManual 1
    }
    if {[catch {pickFile $m [selfPath]} f]} {
        dict set res status nofile
        dict set res error $f
        return $res
    }
    dict set res status available
    dict set res file $f
    return $res
}

# The file an update would replace (the running starpack), or "" when there is none.
proc ::tg::update::selfPath {} {
    variable targetOverride
    if {$targetOverride ne ""} { return $targetOverride }
    set exe [info nameofexecutable]
    return [file normalize $exe]
}

# ================================================================================ apply ====

# The program to replace. Raises when this is not a single-file program.
proc ::tg::update::targetFor {opts} {
    variable targetOverride
    if {[dict exists $opts target] && [dict get $opts target] ne ""} { set t [dict get $opts target] } \
    elseif {$targetOverride ne ""} { set t $targetOverride } \
    else {
        # Only a real single-file program may replace itself. tclsh/wish running main.tcl from a
        # folder must NEVER be mistaken for it (that would overwrite the Tcl interpreter).
        set exe [info nameofexecutable]
        if {![info exists ::starkit::topdir] \
            || [string tolower [file normalize $::starkit::topdir]] ne [string tolower [file normalize $exe]]} {
            error "TclGuard is running from source files or through another Tcl runtime, so there is no single-file program to replace. Download the new release instead."
        }
        set t $exe
    }
    set t [file normalize $t]
    # follow symbolic links so the real file is replaced, not the link
    for {set i 0} {$i < 10 && ![catch {file readlink $t} l]} {incr i} { set t [file normalize [file join [file dirname $t] $l]] }
    if {![::tg::nfs::isFile $t]} { error "$t is not a file" }
    return $t
}

# Run `<path> version` with a timeout; -> {ok text}. The program is the one whose bytes were just
# verified; it still gets a hard time limit and a cap on the output it is read for.
proc ::tg::update::runVersion {path} {
    variable runTimeout
    variable rv
    array unset rv
    set rv(buf) ""
    set rv(state) 0
    if {[catch {open |[list $path version 2>@1] r} ch]} { return [list 0 "cannot be started: $ch"] }
    fconfigure $ch -blocking 0 -translation binary
    set pid [pid $ch]
    fileevent $ch readable [list ::tg::update::rvRead $ch]
    set timer [after $runTimeout [list set ::tg::update::rv(state) timeout]]
    vwait ::tg::update::rv(state)
    after cancel $timer
    catch { fileevent $ch readable {} }
    if {$rv(state) ne "eof"} {
        catch {
            if {$::tcl_platform(platform) eq "windows"} { exec taskkill /F /PID $pid } else { exec kill -9 $pid }
        }
        catch { close $ch }
        return [list 0 [expr {$rv(state) eq "timeout" ? "did not answer within [expr {$runTimeout / 1000}] seconds" : "printed too much output"}]]
    }
    fconfigure $ch -blocking 1
    set rc [catch {close $ch} err]
    if {$rc} { return [list 0 "exited with an error: [string trim $rv(buf)]"] }
    list 1 $rv(buf)
}

proc ::tg::update::rvRead {ch} {
    variable rv
    if {[catch {read $ch 4096} d]} { set rv(state) error; return }
    append rv(buf) $d
    if {[string length $rv(buf)] > 8192} { set rv(state) overflow; return }
    if {[eof $ch]} { set rv(state) eof }
}

# What a program prints for `version`: "TclGuard 1.2.3 (Tcl 8.6.14)" -> 1.2.3 (or "")
proc ::tg::update::versionOf {text} {
    if {[regexp {^TclGuard (\S+)} [string trim $text] -> v]} { return $v }
    return ""
}

# Windows: a running starpack cannot be renamed, overwritten or deleted. It keeps its own file open to read
# the virtual file system it carries, and that handle forbids all three (measured on a real runner with
# tests/platform/windows_lock_probe.ps1: reading and copying work, renaming fails with "being used by another
# process", while an ordinary running .exe can be renamed). So when the program being replaced IS this
# process, the final rename is done by a small hidden PowerShell that waits for this process to exit.
# Test hook: swapWaitPid names the process the helper waits for instead of this one.
namespace eval ::tg::update { variable swapWaitPid "" }

proc ::tg::update::swapHelperScript {waitPid src dst} {
    join [list \
        "\$ErrorActionPreference = 'SilentlyContinue'" \
        "Wait-Process -Id $waitPid -Timeout 120" \
        "\$done = \$false" \
        "for (\$i = 0; \$i -lt 120 -and -not \$done; \$i++) {" \
        "  try { Move-Item -LiteralPath [::tg::install::psq $src] -Destination [::tg::install::psq $dst] -Force -ErrorAction Stop; \$done = \$true } catch { Start-Sleep -Milliseconds 500 }" \
        "}" \
        "if (-not \$done) { Remove-Item -LiteralPath [::tg::install::psq $src] -Force }" \
        ] "\n"
}

# Put newFile in place of target, keeping the old program as target.previous. newFile must be a
# complete, verified file in the SAME directory (so the final step is a rename). On failure the old
# program is untouched. Returns "deferred" when the swap happens after this process exits (Windows,
# replacing the running program), otherwise "".
proc ::tg::update::swapIn {newFile target} {
    variable swapWaitPid
    set prev $target.previous
    set tmpPrev $target.prev[pid]
    try {
        ::tg::nfs::copy $target $tmpPrev
        file rename -force -- $tmpPrev $prev
    } on error {e} {
        catch { file delete -force -- $tmpPrev }
        error "could not keep the old program as $prev: $e"
    }
    if {$::tcl_platform(platform) eq "windows"} {
        if {[::tg::install::sameFile $target [::tg::install::runningExe]]} {
            set wp [expr {$swapWaitPid ne "" ? $swapWaitPid : [pid]}]
            set script [swapHelperScript $wp [file nativename $newFile] [file nativename $target]]
            if {[set e [::tg::install::spawn [::tg::install::psArgv $script]]] ne ""} {
                error "could not start the helper that puts the new program in place: $e"
            }
            return deferred
        }
        # not this process: a file nobody runs is simply replaced; one that another TclGuard runs is refused
        if {[catch {::tg::nfs::move $newFile $target} e]} {
            error "could not put the new program in place: $e. If a TclGuard started from $target is running, close it first (Windows does not let a running program be replaced)."
        }
        return ""
    }
    if {[catch {::tg::nfs::move $newFile $target} e]} { error "could not put the new program in place: $e" }
    return ""
}

# Executable bit: keep the old program's permissions, make sure the owner may run it.
proc ::tg::update::copyPermissions {from to} {
    if {$::tcl_platform(platform) eq "windows"} return
    set perm 0755
    catch { set perm [expr {[file attributes $from -permissions] | 0100}] }
    catch { file attributes $to -permissions $perm }
}

proc ::tg::update::canWriteBeside {target} {
    set probe $target.probe[pid]
    catch { file delete -force -- $probe }
    if {[catch {close [open $probe {WRONLY CREAT EXCL} 0600]}]} { return 0 }
    catch { file delete -force -- $probe }
    return 1
}

# The caller's progress command runs at global level (so that, e.g., "apply {...}" means Tcl's apply and
# not ::tg::update::apply). Errors in it never abort an update.
proc ::tg::update::progress {cmd phase done total} {
    if {$cmd ne ""} { catch { uplevel #0 [list {*}$cmd $phase $done $total] } }
}

# apply ?{url U target T progress CMD}? -> dict: ok error status old new backup restart
proc ::tg::update::apply {{opts {}}} {
    if {[catch {applyInner $opts} r o]} {
        catch { ::tg::log::debug [dict get $o -errorinfo] }
        return [dict create ok 0 error $r]
    }
    return $r
}

proc ::tg::update::applyInner {opts} {
    variable maxBinary
    set prog [expr {[dict exists $opts progress] ? [dict get $opts progress] : ""}]
    # 1. no trust anchor, no update. Before any network traffic.
    set key [publicKey]
    if {[dict get $key state] ne "ok"} {
        error "this build of TclGuard has no release-signing key embedded, so it cannot verify updates and refuses to install them. Download the new release from the project page instead."
    }
    set target [targetFor $opts]
    if {![canWriteBeside $target]} { error "cannot write next to $target (need permission to replace the program: run as the user or administrator that installed it)" }
    # 2. signed manifest (verified BEFORE any field of it is looked at)
    progress $prog check 0 0
    set lm [loadManifest $opts]
    if {![dict get $lm ok]} { error [dict get $lm error] }
    if {![dict get $lm verified]} { error "the release could not be verified" }
    set mf [dict get $lm manifest]
    set new [dict get $mf version]
    set cmp [compareVersions $new $::tg::VERSION]
    if {$cmp == 0} { return [dict create ok 1 status uptodate old $::tg::VERSION new $new restart 0] }
    if {$cmp < 0} { error "the newest published release ($new) is older than this program ($::tg::VERSION); refusing to downgrade" }
    if {[dict get $mf min] ne "" && [compareVersions $::tg::VERSION [dict get $mf min]] < 0} {
        error "version $::tg::VERSION is older than the oldest version that can update itself ([dict get $mf min]). Download release $new from the project page."
    }
    set f [pickFile $mf $target]
    set size [dict get $f size]
    set tmp $target.new[pid]
    set done 0
    try {
        # 3. download with the size announced in the SIGNED manifest as hard limit
        progress $prog download 0 $size
        catch { file delete -force -- $tmp }      ;# never write through a pre-existing file or link of that name
        fetch [dict get $f url] -file $tmp -maxbytes $size -timeout 600000 -progress [list ::tg::update::progress $prog]
        if {![file exists $tmp] || [file size $tmp] != $size} {
            error "the download is incomplete ([expr {[file exists $tmp] ? [file size $tmp] : 0}] of $size bytes)"
        }
        # 4. integrity
        set sha [sha256File $tmp [list ::tg::update::progress $prog hash]]
        if {$sha ne [dict get $f sha256]} { error "the downloaded file does not match the signed checksum; it was discarded" }
        copyPermissions $target $tmp
        # 5. does it run here, and is it what the manifest says?
        progress $prog verify 0 0
        lassign [runVersion $tmp] ok text
        if {!$ok} { error "the new program does not run on this machine ($text); the old one was kept" }
        set got [versionOf $text]
        if {$got ne $new} { error "the new program reports version '$got' instead of $new; the old one was kept" }
        # 6. swap (the bytes are checked once more: the file has been sitting next to the program while it was being run)
        if {[sha256File $tmp] ne [dict get $f sha256]} { error "the downloaded file changed while it was being checked; it was discarded" }
        progress $prog install 0 0
        set deferred [swapIn $tmp $target]
        set done 1
    } finally {
        if {!$done} { catch { file delete -force -- $tmp } }
    }
    catch { updateState lastApplied [nowSec] appliedFrom $::tg::VERSION appliedTo $new previousVersion $::tg::VERSION pendingRestart 1 }
    dict create ok 1 status applied old $::tg::VERSION new $new target $target backup $target.previous restart 1 deferred [expr {$deferred eq "deferred"}]
}

# ============================================================================== rollback ====

proc ::tg::update::rollback {{opts {}}} {
    if {[catch {rollbackInner $opts} r o]} {
        catch { ::tg::log::debug [dict get $o -errorinfo] }
        return [dict create ok 0 error $r]
    }
    return $r
}

proc ::tg::update::rollbackInner {opts} {
    set target [targetFor $opts]
    set prev $target.previous
    if {![file isfile $prev]} { error "there is no previous version to go back to ($prev does not exist)" }
    if {![canWriteBeside $target]} { error "cannot write next to $target" }
    set tmp $target.new[pid]
    set done 0
    try {
        file copy -force -- $prev $tmp
        copyPermissions $prev $tmp
        lassign [runVersion $tmp] ok text
        if {!$ok} { error "the previous program does not run on this machine ($text); nothing was changed" }
        set was [versionOf $text]
        set deferred [swapIn $tmp $target]
        set done 1
    } finally {
        if {!$done} { catch { file delete -force -- $tmp } }
    }
    catch { updateState lastRollback [nowSec] previousVersion $::tg::VERSION pendingRestart 1 }
    dict create ok 1 old $::tg::VERSION new $was target $target restart 1 deferred [expr {$deferred eq "deferred"}]
}

# ======================================================================== status, auto ====

proc ::tg::update::status {{opts {}}} {
    set st [loadState]
    set res [dict create current $::tg::VERSION platform [platformKey] updateUrl [feedUrl {}] \
        lastCheck [::tg::json::get $st lastCheck 0] lastStatus [::tg::json::get $st lastStatus ""] \
        latest [::tg::json::get $st latest ""] lastVerified [::tg::json::get $st lastVerified 0] \
        lastError [::tg::json::get $st lastError ""] notes [::tg::json::get $st lastNotes ""] \
        lastApplied [::tg::json::get $st lastApplied 0] previousVersion [::tg::json::get $st previousVersion ""]]
    if {[catch {publicKey} key]} {
        dict set res keyState malformed
        dict set res keyError $key
        dict set res fingerprint ""
    } else {
        dict set res keyState [dict get $key state]
        dict set res fingerprint [expr {[dict exists $key fingerprint] ? [dict get $key fingerprint] : ""}]
    }
    set latest [dict get $res latest]
    dict set res pending [expr {$latest ne "" && [isVersion $latest] && [compareVersions $latest $::tg::VERSION] > 0}]
    set t ""
    catch { set t [targetFor $opts] }
    dict set res target $t
    dict set res hasPrevious [expr {$t ne "" && [file isfile $t.previous]}]
    return $res
}

proc ::tg::update::statusText {{opts {}}} {
    set s [status $opts]
    set out "TclGuard [dict get $s current] ([dict get $s platform])\n"
    switch -- [dict get $s keyState] {
        ok        { append out "  release key:   embedded, fingerprint [dict get $s fingerprint]\n" }
        unset     { append out "  release key:   NOT SET in this build - updates cannot be verified, so 'update apply' refuses\n" }
        default   { append out "  release key:   unusable ([dict get $s keyError])\n" }
    }
    append out "  update feed:   [dict get $s updateUrl]\n"
    if {[dict get $s lastCheck]} {
        append out "  last check:    [clock format [dict get $s lastCheck] -format {%Y-%m-%d %H:%M:%S}]: [dict get $s lastStatus]"
        if {[dict get $s latest] ne ""} { append out " (latest [dict get $s latest][expr {[dict get $s lastVerified] ? {, signature verified} : {, NOT verified}}])" }
        if {[dict get $s lastError] ne ""} { append out " - [dict get $s lastError]" }
        append out "\n"
    } else {
        append out "  last check:    never\n"
    }
    append out "  update pending: [expr {[dict get $s pending] ? "yes: [dict get $s latest] (run 'tclguard update apply')" : "no"}]\n"
    append out "  previous copy: [expr {[dict get $s hasPrevious] ? "[dict get $s target].previous[expr {[dict get $s previousVersion] ne {} ? " (version [dict get $s previousVersion])" : {}}] - 'tclguard update rollback' restores it" : "none"}]\n"
    return $out
}

# For the GUI: at most one network check per day (an hour after a failed one), only when enabled in
# the configuration; never installs anything. Starts no timers: the caller decides when to ask.
# -> dict: status (skipped|uptodate|available|...), reason, and the same keys as check.
proc ::tg::update::autoCheck {} {
    variable checkInterval
    variable retryInterval
    set enabled 0
    catch { set enabled [::tg::bool [::tg::cfg::general updateCheck]] }
    set st [loadState]
    set cached [dict create status [::tg::json::get $st lastStatus ""] latest [::tg::json::get $st latest ""] \
        verified [::tg::json::get $st lastVerified 0] notes [::tg::json::get $st lastNotes ""] \
        checkedAt [::tg::json::get $st lastCheck 0] current $::tg::VERSION]
    if {!$enabled} { return [dict merge $cached [dict create ok 1 skipped 1 reason disabled]] }
    set last [::tg::json::get $st lastCheck 0]
    set wait [expr {[::tg::json::get $st lastStatus ""] eq "error" ? $retryInterval : $checkInterval}]
    if {[string is integer -strict $last] && $last > 0 && [nowSec] - $last < $wait && [nowSec] >= $last} {
        return [dict merge $cached [dict create ok 1 skipped 1 reason rate-limited]]
    }
    set r [check]
    dict set r skipped 0
    return $r
}

# Windows keeps the renamed running program as <name>.old until the next start. Called at start-up.
# Only files named exactly like this program plus .old / .old<pid> / .new<pid> (the latter only when
# stale) are touched.
proc ::tg::update::globEsc {s} {
    set out ""
    foreach c [split $s ""] {
        if {$c in {\\ * ? [ ] \{ \}}} { append out "\\" }
        append out $c
    }
    return $out
}

proc ::tg::update::cleanup {} {
    variable targetOverride
    set exe [expr {$targetOverride ne "" ? $targetOverride : [info nameofexecutable]}]
    set exe [file normalize $exe]
    set n 0
    set d [file dirname $exe]
    set t [globEsc [file tail $exe]]
    foreach f [glob -nocomplain -directory $d -- "$t.old*"] {
        if {[regexp {\.old[0-9]*$} $f] && ![catch {file delete -force -- $f}]} { incr n }
    }
    foreach f [glob -nocomplain -directory $d -- "$t.new*" "$t.prev*" "$t.probe*"] {
        if {![regexp {\.(new|prev|probe)[0-9]+$} $f]} continue
        if {[catch {file mtime $f} mt]} continue
        if {[clock seconds] - $mt > 3600 && ![catch {file delete -force -- $f}]} { incr n }
    }
    return $n
}
