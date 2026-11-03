# Drives the real GUI under Xvfb and captures every page.
# usage: xvfb-run -a -s "-screen 0 1300x860x24" wish8.6 shots.tcl <outdir> [dark|light]
set root [file normalize [file join [file dirname [info script]] .. ..]]
lappend auto_path [file join $root tclguard.vfs lib]
package require tclguard
set out [lindex $argv 0]
set theme [expr {[llength $argv] > 1 ? [lindex $argv 1] : "dark"}]
file mkdir $out
set tmp [file join $out state-$theme]
file mkdir $tmp
set c [::tg::cfg::new]
dict set c general stateDir $tmp
dict set c general firewall none
dict set c general controlEnable 0
dict set c general controlToken abc
dict set c general theme $theme
dict set c general allowlist {192.168.0.0/16 127.0.0.0/8 203.0.113.250}
dict set c general blocklist {198.51.100.0/24 192.0.2.66}
set L {}
foreach {p port} {website 20000 minecraft-java 20010 valheim 20020} {
    dict for {n s} [::tg::cfg::presetListeners $p $L] { dict set s port $port; incr port; dict set L $n $s }
}
dict set L old-ssh {type tcp port 29022 backendPort 29023 enabled 0}
dict set c listeners $L
::tg::cfg::set_ $c
set ::tg::cfg::path [file join $tmp tg.conf]
set ::tg::log::stderr 0
wm geometry . 1280x1000
::tg::kit::init $theme
::tg::gui::build
::tg::engine::start
::tg::gui::refreshFwPreview
set ::tg::stat::series {}
for {set i 0} {$i < 300} {incr i} {
    lappend ::tg::stat::series [list $i [expr {40 + 25*sin($i/20.0) + rand()*10}] [expr {$i > 220 ? 60 + rand()*80 : rand()*4}]]
}
set ::tg::stat::top {{203.0.113.9 12 5400 98304} {198.51.100.4 340 3 2400000} {192.0.2.77 18 22 5000} {203.0.113.50 5 2 900}}
::tg::ban::add 203.0.113.9 "request flood on website-http-20000" 600 auto
::tg::ban::add 198.51.100.200 "bad HTTP request: malformed request line" 3600 auto
::tg::ban::add 192.0.2.1 "log watcher 'sshd': 5 matches in 120s" 0 log
::tg::ban::add 203.0.113.0/24 "manual ban" 86400 manual
::tg::log::alert "threat level raised to UNDER ATTACK: connPerSec 312 (limit 250)"
::tg::log::warn "backend for 'website-http-20000' unreachable: connection refused"
foreach {k v} {conns {3 5 4 8 12 9 14 20 17 12 9 11 15 22 18} allowed {20 24 30 28 40 38 52 47 60 55 49 62 70 66 71} blocked {0 0 1 0 2 0 0 14 60 120 96 40 12 4 2} bans {0 0 0 1 1 1 2 2 3 3 4 4 4 4 4}} { set ::tg::gui::hist($k) $v }
proc shot {name} {
    update idletasks; update
    after 350; update
    exec import -window root [file join $::out $name-$::theme.png]
}
proc walk {} {
    foreach t {overview protection bans firewall activity settings help} {
        ::tg::gui::showPage $t
        shot $t
    }
    ::tg::gui::showPage protection
    after 100 {::tg::gui::addWizard}
    after 900 { shot dlg-wizard; destroy .wiz; set ::go 1 }
    vwait ::go
    after 100 {::tg::gui::editListener minecraft-java-tcp-25565}
    after 900 { shot dlg-edit; destroy .edit; set ::go 2 }
    vwait ::go
    after 100 {::tg::gui::banDialog}
    after 900 { shot dlg-ban; destroy .ban; set ::go 3 }
    vwait ::go
    set ::tg::quit 1
}
::tg::gui::showPage overview
after 600 walk
::tg::gui::tick
vwait ::tg::quit
::tg::engine::stop
exit 0
