#!/usr/bin/env tclsh8.6
# release-manifest.tcl -- build and sign the manifest for a TclGuard release.
#
#   tclsh8.6 tools/release-manifest.tcl --dir releases --version 1.2.3 [--key FILE] [options]
#
# Reads every tclguard-<os>-<arch>[.exe] file in --dir, writes manifest.json (sha256 + size per file)
# and manifest.json.sig (ECDSA P-256 over the exact manifest bytes, base64url) into --out
# (default: --dir). Upload manifest.json, manifest.json.sig and the binaries to the GitHub Release.
#
# The signing key is NEVER part of the repository. Give it as a file (--key FILE) or through the
# environment variable TG_RELEASE_KEY (a file path, or the PEM text itself, which is how a CI secret
# arrives). Create one with:   tclguard update keygen --out release-signing.key
#
# Options:
#   --notes TEXT | --notes-file FILE   release notes shown to users before they update
#   --min VERSION                      oldest version that may update itself to this release
#   --urlbase URL                      where the files are published
#                                      (default https://github.com/atyr647/tclguard/releases/download/v<version>/)
#   --issued UNIXTIME                  default: now
#   --out DIR
#   --allow-key-mismatch               sign even though the key is not the one embedded in the app
#   --require-embedded-key             fail (instead of warning) while update-key.pub is still UNSET
#
# Non-ASCII release notes: use --notes-file (always read as UTF-8); a --notes argument is decoded with
# the terminal's encoding.
#
# Safety checks before anything is written: the key must match the public key embedded in
# tclguard.vfs/lib/tclguard/vendor/update-key.pub (otherwise every installed TclGuard would reject the
# release), and the finished signature is verified again with the matching public key.

fconfigure stdout -buffering line
set here [file dirname [file normalize [info script]]]
set lib [file join $here .. tclguard.vfs lib tclguard]
foreach m {util crypto json update} { source -encoding utf-8 [file join $lib $m.tcl] }

proc die {msg} { puts stderr "release-manifest: $msg"; exit 1 }
proc usage {} {
    puts stderr "usage: tclsh8.6 tools/release-manifest.tcl --dir DIR --version X.Y.Z \[--key FILE\] \[--notes TEXT | --notes-file FILE\] \[--min V\] \[--urlbase URL\] \[--issued N\] \[--out DIR\] \[--allow-key-mismatch\] \[--require-embedded-key\]"
    exit 2
}

array set opt {--dir "" --version "" --key "" --notes "" --notes-file "" --min "" --urlbase "" --issued "" --out "" --allow-key-mismatch 0 --require-embedded-key 0}
set args $argv
while {[llength $args]} {
    set a [lindex $args 0]
    if {$a in {--allow-key-mismatch --require-embedded-key}} { set opt($a) 1; set args [lrange $args 1 end]; continue }
    if {![info exists opt($a)] || [llength $args] < 2} { usage }
    set opt($a) [lindex $args 1]
    set args [lrange $args 2 end]
}
if {$opt(--dir) eq "" || $opt(--version) eq ""} { usage }
if {![file isdirectory $opt(--dir)]} { die "not a directory: $opt(--dir)" }
if {$opt(--out) eq ""} { set opt(--out) $opt(--dir) }
if {![::tg::update::isVersion $opt(--version)]} { die "'$opt(--version)' is not a version number" }
if {$opt(--notes-file) ne ""} {
    if {![file isfile $opt(--notes-file)]} { die "no such notes file: $opt(--notes-file)" }
    set opt(--notes) [string trim [::tg::readFile $opt(--notes-file)]]
}

if {[catch {::tg::update::loadPrivateKey $opt(--key)} key]} { die $key }
set pub [::tg::update::publicKeyLine $key]
set fp [::tg::update::fingerprint [::tg::crypto::pubPoint $key]]

# the key must be the one the shipped programs trust
if {[catch {::tg::update::publicKey} embedded]} { die "the embedded update key is unusable: $embedded" }
if {[dict get $embedded state] eq "unset" && $opt(--require-embedded-key)} {
    die "tclguard.vfs/lib/tclguard/vendor/update-key.pub is still the UNSET placeholder. Put the public key there ($pub), rebuild the starpacks, and release again."
} elseif {[dict get $embedded state] eq "unset"} {
    puts "WARNING: vendor/update-key.pub is still the UNSET placeholder, so no installed TclGuard can verify this release yet."
    puts "         Put this line there and rebuild the starpacks:  $pub"
} elseif {[dict get $embedded fingerprint] ne $fp && !$opt(--allow-key-mismatch)} {
    die "this signing key (fingerprint $fp) is not the key embedded in the app ([dict get $embedded fingerprint]). Releases signed with it would be rejected by every installed TclGuard. Use the right key, or --allow-key-mismatch if you are rotating keys on purpose."
}

set build [list $opt(--dir) $opt(--version) -notes $opt(--notes) -min $opt(--min) -urlbase $opt(--urlbase)]
if {$opt(--issued) ne ""} { lappend build -issued $opt(--issued) }
if {[catch {::tg::update::buildManifest {*}$build} text]} { die $text }
# what is signed, stored and downloaded is this exact byte string (UTF-8)
set manifest [encoding convertto utf-8 $text]
# the finished text must parse and validate exactly as a client will read it
if {[catch {::tg::update::parseManifest $manifest} m]} { die "the generated manifest is invalid: $m" }
set sig [::tg::update::signBytes $key $manifest]
lassign [list [dict get $key x] [dict get $key y]] x y
if {![::tg::update::verifyBytes $x $y $manifest $sig]} { die "internal error: the new signature does not verify" }

file mkdir $opt(--out)
foreach {name data} [list manifest.json $manifest manifest.json.sig "$sig\n"] {
    set fh [open [file join $opt(--out) $name] wb]
    puts -nonewline $fh $data
    close $fh
}
puts "release $opt(--version): [dict size [dict get $m files]] file(s) signed with key $fp"
dict for {k f} [dict get $m files] {
    puts [format "  %-26s %10d bytes  sha256 %s" $k [dict get $f size] [string range [dict get $f sha256] 0 15]...]
}
puts "wrote [file join $opt(--out) manifest.json] and manifest.json.sig"
exit 0
