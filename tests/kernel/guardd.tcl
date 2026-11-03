# Runs INSIDE the "guard" network namespace. Reads commands on stdin, drives the
# real TclGuard firewall module against the real kernel, replies on stdout.
set root [file normalize [file join [file dirname [info script]] .. ..]]
foreach m {util config bans firewall} { source [file join $root tclguard.vfs lib tclguard $m.tcl] }
set ::tg::log::stderr 0

proc setup {harden} {
    set c [::tg::cfg::new]
    dict set c general allowlist {127.0.0.0/8}
    dict set c general firewall nft
    dict set c general harden $harden
    dict set c general hardenSynRate 40
    dict set c general hardenSynBurst 80
    dict set c general hardenUdpRate 200
    dict set c general hardenUdpBurst 400
    dict set c listeners t {type tcp port 8080 backendPort 8081}
    dict set c listeners u {type udp port 19132 backendPort 19133}
    ::tg::cfg::set_ $c
    ::tg::ban::configure
    array unset ::tg::ban::banned
    ::tg::ban::registerOnBan ::tg::fw::onBan
    ::tg::ban::registerOnUnban ::tg::fw::onUnban
}
proc reply {s} { puts [string map [list \n { | }] $s]; flush stdout }

proc handle {line} {
    lassign $line cmd a b
    switch -- $cmd {
        INSTALL { setup $a; ::tg::fw::init nft; reply "ok installed=[::tg::fw::sync] features=[dict get [::tg::fw::status] features] err=[dict get [::tg::fw::status] error]" }
        BAN     { ::tg::ban::add $a test $b manual; ::tg::fw::commit; reply ok }
        UNBAN   { ::tg::ban::remove $a; ::tg::fw::commit; reply ok }
        COUNTERS { reply [::tg::fw::nftCounters] }
        LIST4   { lassign [::tg::fw::run [list nft list set inet tclguard ban4]] rc out; reply $out }
        UNINSTALL { reply [::tg::fw::uninstall] }
        TABLE   { lassign [::tg::fw::run [list nft list tables]] rc out; reply $out }
        QUIT    { reply bye; exit 0 }
        default { reply "unknown command" }
    }
}
fconfigure stdin -buffering line
fileevent stdin readable {
    if {[gets stdin line] < 0} { exit 0 }
    if {[catch {handle $line} err]} { reply "ERROR $err" }
}
reply READY
vwait forever
