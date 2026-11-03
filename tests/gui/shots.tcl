# Drives the real GUI under Xvfb and captures a screenshot of each tab.
# usage: xvfb-run -a -s "-screen 0 1280x900x24" tclsh8.6 shots.tcl <outdir>
set root [file normalize [file join [file dirname [info script]] .. ..]]
lappend auto_path [file join $root tclguard.vfs lib]
package require tclguard
package require Tk
set out [lindex $argv 0]
file mkdir $out
set tmp [file join $out state]
file mkdir $tmp
set c [::tg::cfg::new]
dict set c general stateDir $tmp
dict set c general firewall none
dict set c general controlEnable 0
dict set c general controlToken abc
dict set c general allowlist {192.168.0.0/16 127.0.0.0/8}
foreach p {website minecraft-java valheim} {
    dict for {n s} [::tg::cfg::presetListeners $p [expr {[dict exists $c listeners] ? [dict get $c listeners] : {}}]] {
        dict set s port [expr {20000 + [dict size [expr {[dict exists $c listeners] ? [dict get $c listeners] : {}}]] * 10}]
        dict set c listeners $n $s
    }
}
dict set c listeners "old-ssh" {type tcp port 29022 backendPort 29023 enabled 0}
::tg::cfg::set_ $c
set ::tg::cfg::path [file join $tmp tg.conf]
set ::tg::log::stderr 0
::tg::gui::build
::tg::engine::start
::tg::gui::refreshFwPreview
# fake some activity so charts and tables have content
set ::tg::stat::series {}
for {set i 0} {$i < 300} {incr i} {
    lappend ::tg::stat::series [list $i [expr {40 + 25*sin($i/20.0) + rand()*10}] [expr {$i > 220 ? 60 + rand()*80 : rand()*4}]]
}
set ::tg::stat::top {{203.0.113.9 12 5400 98304} {198.51.100.4 340 3 2400000} {192.0.2.77 18 22 5000} {203.0.113.50 5 2 900}}
::tg::ban::add 203.0.113.9 "request flood on website-http-20000" 600 auto
::tg::ban::add 198.51.100.200 "bad HTTP request: malformed request line" 3600 auto
::tg::ban::add 192.0.2.1 "log watcher 'sshd': 5 matches in 120s" 0 log
::tg::log::alert "threat level raised to UNDER ATTACK: connPerSec 312 (limit 250)"
::tg::log::warn "backend for 'website-http-20000' unreachable: connection refused"
proc shot {name} {
    update idletasks; update
    after 250; update
    exec import -window root [file join $::out $name.png]
}
proc tabs {} {
    foreach t {dashboard protection bans firewall log settings help} {
        .nb select .nb.$t
        ::tg::gui::tabChanged
        shot $t
    }
    # dialogs
    .nb select .nb.protection
    after 100 {destroy .wiz}
    after 300 {::tg::gui::editListener minecraft-java-tcp-25565}
    after 800 { shot dlg-edit; destroy .edit; after 100 {set ::go 1} }
    vwait ::go
    after 300 {::tg::gui::addWizard}
    after 800 { shot dlg-wizard; destroy .wiz; set ::go 2 }
    vwait ::go
    set ::tg::quit 1
}
after 600 tabs
::tg::gui::tick
vwait ::tg::quit
::tg::engine::stop
exit 0
