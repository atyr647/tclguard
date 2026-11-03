# GUI smoke test: drive every flow through the real widgets and fail on any
# background error. usage: xvfb-run -a wish8.6 smoke.tcl
set root [file normalize [file join [file dirname [info script]] .. ..]]
lappend auto_path [file join $root tclguard.vfs lib]
package require tclguard
# (a starpack started as `<program> eval smoke.tcl` has Tk only when the platform's kit loads it at start: ask for it)
if {[info commands wm] eq ""} { package require Tk }
set tmp [file join [expr {[info exists ::env(TMPDIR)] ? $::env(TMPDIR) : "/tmp"}] tg-guismoke-[pid]]
file mkdir $tmp
set pass 0; set fail 0
proc check {name cond {detail ""}} {
    global pass fail
    if {$cond} { incr pass; puts "PASS $name" } else { incr fail; puts "FAIL $name  $detail" }
}
set c [::tg::cfg::new]
dict set c general stateDir $tmp
dict set c general firewall none
dict set c general controlEnable 0
dict set c general allowlist {}
::tg::cfg::set_ $c
set ::tg::cfg::path [file join $tmp tg.conf]
set ::tg::log::stderr 0
wm geometry . 1280x820
::tg::kit::init dark
::tg::gui::build
::tg::engine::start
::tg::gui::showPage overview
proc pump {{ms 150}} { after $ms {set ::pumped 1}; vwait ::pumped; update }

# 1. every page renders and refreshes
foreach p {overview protection bans firewall activity settings help overview} {
    ::tg::gui::showPage $p; pump 60
}
check "all 7 pages build and refresh" 1

# 2. theme switching rebuilds the whole UI, twice, on every page
foreach p {overview bans settings} {
    ::tg::gui::showPage $p
    ::tg::gui::setTheme light; pump 60
    ::tg::gui::setTheme dark; pump 60
}
check "theme switch light/dark round trip" [expr {$::tg::kit::theme eq "dark"}]
check "theme persisted to config" [expr {[::tg::cfg::general theme] eq "dark"}]

# 3. wizard: add a protection through the real widgets
::tg::gui::showPage protection; pump
set ::tg::gui::v(wizSel) minecraft-java
after 100 {
    ::tg::gui::wizPick .wiz.f minecraft-java
    set ::tg::gui::v(wizPub) 31000
    set ::tg::gui::v(wizBackend) 31001
    ::tg::gui::wizAdd .wiz
}
::tg::gui::addWizard
pump 200
set names [dict keys [::tg::cfg::listeners]]
check "wizard added the listener" [expr {[llength $names] == 1}] $names
set n [lindex $names 0]
check "listener has the chosen ports" [expr {[dict get [::tg::cfg::listeners] $n port] == 31000 && [dict get [::tg::cfg::listeners] $n backendPort] == 31001}]
check "listener is actually running" [expr {$n in [::tg::tcp::listening]}]
check "listener row appears in the Protection page" [winfo exists .main.body.protection.c.f.list]

# 4. edit dialog: change a limit and save
after 100 {
    set ::tg::gui::v(e,maxConnsPerIP) 9
    ::tg::gui::saveListener .edit $::n tcp [concat {*}[::tg::gui::listenerFields tcp]]
}
::tg::gui::editListener $n
pump 200
check "edit dialog saved the new limit" [expr {[dict get [::tg::cfg::listeners] $n maxConnsPerIP] == 9}] [dict get [::tg::cfg::listeners] $n maxConnsPerIP]

# 5. toggle off / on
set ::tg::gui::v(lrow,$n,en) 0; ::tg::gui::toggleListener $n; pump
check "toggle off stops the listener" [expr {$n ni [::tg::tcp::listening]}]
set ::tg::gui::v(lrow,$n,en) 1; ::tg::gui::toggleListener $n; pump
check "toggle on starts it again" [expr {$n in [::tg::tcp::listening]}]

# 6. bans page: manual ban through the dialog, list it, unban it
::tg::gui::showPage bans; pump
after 100 {
    set ::tg::gui::v(banIp) 198.51.100.77
    set ::tg::gui::v(banFor) "1 hour"
    set sec 3600
    ::tg::gui::do ban 198.51.100.77 3600 "gui test"
    destroy .ban
}
::tg::gui::banDialog
pump 200
check "ban created" [::tg::ban::isBanned 198.51.100.77]
::tg::gui::refresh; pump 100
check "ban row is shown on the Bans page" [expr {[llength [winfo children .main.body.bans.c.f.list.in.rows]] >= 1}]
::tg::gui::unban 198.51.100.77
check "unban from the page works" [expr {![::tg::ban::isBanned 198.51.100.77]}]
set ::tg::gui::v(add,allowlist) 203.0.113.9
::tg::gui::listAdd allowlist
check "allowlist add via inline field" [expr {"203.0.113.9" in [::tg::cfg::general allowlist]}]
::tg::gui::listRemove allowlist 203.0.113.9
check "allowlist chip remove" [expr {"203.0.113.9" ni [::tg::cfg::general allowlist]}]

# 7. level selector, pause/resume
::tg::gui::setLevel 2; pump 100
check "level selector pins level 2" [expr {[::tg::level::get] == 2}]
::tg::gui::setLevel auto; pump 100
check "back to automatic resets to Normal" [expr {[::tg::level::get] == 0 && ![::tg::level::isManual]}]

# 8. settings round trip
::tg::gui::showPage settings; pump
set ::tg::gui::v(s,strikeThreshold) 7
::tg::gui::saveSettings
check "settings saved" [expr {[::tg::cfg::general strikeThreshold] == 7}]

# 9. remove the listener
set c $::tg::cfg::current; dict unset c listeners $n; ::tg::gui::applyConfig $c; pump 100
check "remove listener" [expr {[llength [dict keys [::tg::cfg::listeners]]] == 0}]
::tg::gui::showPage protection; pump 100
check "empty state shown after removing the last listener" [winfo exists .main.body.protection.c.f.list.empty]

# 9b. autostart toggle writes/removes the OS entry (XDG on Linux; isolated HOME)
set ::env(XDG_CONFIG_HOME) [file join $tmp xdg]
set ::argv0 [file join $root tclguard.vfs main.tcl]
::tg::gui::showPage settings; pump 100
set ::tg::gui::v(autostart) 1; ::tg::gui::autostartToggled
check "autostart on creates the entry" [::tg::autostart::status]
set ::tg::gui::v(autostart) 0; ::tg::gui::autostartToggled
check "autostart off removes it" [expr {![::tg::autostart::status]}]

# 9c. the "needs administrator" banner appears only when it should
::tg::gui::showPage overview; pump 150
check "no admin banner while privileged" [expr {![winfo ismapped $::tg::gui::v(adminBanner)]}]
set savedPriv $::tg::fw::privileged
set ::tg::fw::privileged 0
set savedWanted [dict get $::tg::cfg::current general firewall]
dict set ::tg::cfg::current general firewall auto        ;# the banner is for users who want the firewall
::tg::gui::refresh; pump 150
check "admin banner shows when the firewall needs elevation" [winfo ismapped $::tg::gui::v(adminBanner)]
set ::tg::fw::privileged $savedPriv
dict set ::tg::cfg::current general firewall $savedWanted
::tg::gui::refresh; pump 150
check "banner hides again" [expr {![winfo ismapped $::tg::gui::v(adminBanner)]}]

# 9d. the self-test dialog runs the real attack simulation in a child process and reports a verdict
after 300 {
    set ::stDeadline [expr {[clock seconds] + 90}]
    proc waitSt {} {
        set vd $::tg::gui::v(stVerdict)
        if {[winfo exists $vd] && ([string match "All *" [$vd cget -text]] || [string match "*failed*" [$vd cget -text]] || [clock seconds] > $::stDeadline)} {
            set ::stResult [$vd cget -text]; destroy .selftest; return
        }
        after 500 waitSt
    }
    waitSt
}
::tg::gui::selfTest
check "self-test dialog reports all checks passed" [string match "All * checks passed*" $::stResult] $::stResult

# 9e. HTTPS: wizard preset with a domain, certificate chip, the HTTPS tab in the edit dialog
if {[::tg::tls::available]} {
    set ::tg::acme::busy 1                               ;# never contact a certificate authority from a test
    # the preset uses ports 80/443; use high ones so the test needs no privileges and cannot collide
    dict set ::tg::cfg::presets(website-https) listeners {
        {type http port 38080 backendPort 38081 redirectHttps 1 redirectPort 38443}
        {type http port 38443 backendPort 38081 tls 1 acme 1}
    }
    ::tg::gui::showPage protection; pump
    after 100 {
        ::tg::gui::wizPick .wiz.f website-https
        set ::tg::gui::v(wizDomain) "Example.Test"
        set ::tg::gui::v(wizBackend) 38081
        ::tg::gui::wizAdd .wiz
    }
    ::tg::gui::addWizard
    pump 300
    set ls [::tg::cfg::listeners]
    set tlsName ""; set redirName ""
    dict for {nm sp} $ls {
        if {[::tg::bool [dict get $sp tls]]} { set tlsName $nm }
        if {[::tg::bool [dict get $sp redirectHttps]]} { set redirName $nm }
    }
    check "HTTPS wizard creates the port 80 redirect and the TLS listener" [expr {$tlsName ne "" && $redirName ne ""}] [dict keys $ls]
    check "domain is lowercased and stored for the certificate" [expr {[dict get $ls $tlsName tlsNames] eq "example.test"}] [dict get $ls $tlsName tlsNames]
    check "TLS listener is running with a certificate" [expr {$tlsName in [::tg::tcp::listening] && [dict exists [::tg::tls::certStatus $tlsName] notAfter]}]
    set cs [::tg::gui::certSummary $tlsName]
    check "certificate status explains the temporary certificate" [expr {[lindex $cs 0] eq "warn" && [string match "*Temporary*" [lindex $cs 1]]}] $cs
    ::tg::gui::showPage protection; pump 150
    check "protection row shows an HTTPS chip" [winfo exists [lindex $::tg::gui::v(lrow,$tlsName) 2].tls]
    check "plain listener has no certificate chip" [expr {[::tg::gui::certSummary $redirName] eq ""}]

    # edit dialog: the HTTPS tab exists and its fields save (words are split into a list)
    after 150 {
        set ::seen [expr {[info exists ::tg::gui::v(e,acme)] && [info exists ::tg::gui::v(e,tlsNames)] && [winfo exists [lindex [winfo children .edit] 0].https]}]
        set ::tg::gui::v(e,tlsNames) "example.test, www.example.test  api.example.test"
        set ::tg::gui::v(e,tlsMinVersion) 1.3
        ::tg::gui::saveListener .edit $::tlsName http [concat {*}[::tg::gui::listenerFields http]]
    }
    ::tg::gui::editListener $tlsName
    pump 250
    check "edit dialog has an HTTPS tab with the TLS fields" $::seen
    set sp [dict get [::tg::cfg::listeners] $tlsName]
    check "domain names are saved as a list" [expr {[dict get $sp tlsNames] eq {example.test www.example.test api.example.test}}] [dict get $sp tlsNames]
    check "minimum TLS version saved" [expr {[dict get $sp tlsMinVersion] eq "1.3"}]
    # clean up the listeners again
    set c $::tg::cfg::current; foreach nm [dict keys [::tg::cfg::listeners]] { dict unset c listeners $nm }
    ::tg::gui::applyConfig $c; pump 100
    set ::tg::acme::busy 0
} else {
    puts "SKIP HTTPS GUI checks: this Tcl has no tls package"
}

# 10. no Tcl errors anywhere along the way
set errs {}
foreach e [::tg::log::tail 5000 debug] { if {[string match "*background error*" [lindex $e 2]]} { lappend errs [lindex $e 2] } }
check "no background errors logged" [expr {![llength $errs]}] [lrange $errs 0 2]

::tg::engine::stop
catch {file delete -force $tmp}   ;# Windows refuses while the log file is still open
puts "\n$pass passed, $fail failed"
exit [expr {$fail ? 1 : 0}]
