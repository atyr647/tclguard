# usage: windows_test.tcl ?phase ...?   (no phases = all). Phases: facts netstat firewall firewallscale autostart locations
puts "windows_test: starting"; flush stdout
source [file join [file dirname [info script]] common.tcl]
set ::phases [expr {[info exists ::argv] && [llength $::argv] ? $::argv : {facts netstat firewall firewallscale autostart locations elevation}}]
proc want {p} { expr {$p in $::phases} }
puts "Windows platform tests: Tcl [info patchlevel] on $tcl_platform(os) $tcl_platform(osVersion), [info nameofexecutable]"

set admin [::tg::fw::isPrivileged]
if {[want facts]} {
phase "facts"
check "administrator detection runs (admin=$admin)" 1
check "netsh is found" [expr {[::tg::fw::which netsh] ne ""}]
check "backend 'netsh' is offered" [expr {"netsh" in [::tg::fw::available]}] [::tg::fw::available]
check "auto picks netsh" [expr {[::tg::fw::choose auto] eq "netsh"}]
check "platform detected as windows" [expr {[::tg::autostart::platform] eq "windows"}]
}
if {[want netstat]} {
phase "netstat"
lassign [connectionTableSees 28999] hit n
check "netstat parser finds a live local connection ($n rows seen)" $hit
}
if {[want firewall]} {
phase "windows firewall (netsh)"
if {$admin} {
    freshCfg {firewall netsh allowlist {}}
    ::tg::fw::init netsh
    set rn $::tg::fw::ruleName
    catch {exec netsh advfirewall firewall delete rule name=$rn}
    check "firewall backend becomes active" [expr {$::tg::fw::backend eq "netsh"}] $::tg::fw::lastError
    check "sync (no bans yet) succeeds" [::tg::fw::sync] $::tg::fw::lastError
    ::tg::ban::registerOnBan ::tg::fw::onBan
    ::tg::ban::registerOnUnban ::tg::fw::onUnban
    ::tg::ban::add 203.0.113.7 "ci test" 600 manual
    ::tg::ban::add 198.51.100.0/24 "ci range" 600 manual
    ::tg::fw::commit
    set rc [catch {exec netsh advfirewall firewall show rule name=$rn verbose} out]
    check "rule exists after a ban" [expr {!$rc}] $out
    check "banned address is in the rule" [string match "*203.0.113.7*" $out] $out
    check "banned range is in the rule" [string match "*198.51.100.0*" $out] $out
    check "rule blocks inbound traffic" [expr {[string match "*Block*" $out] && [string match "*In*" $out]}] $out
    ::tg::ban::remove 203.0.113.7
    ::tg::ban::remove 198.51.100.0/24
    ::tg::fw::commit
    set rc [catch {exec netsh advfirewall firewall show rule name=$rn} out2]
    check "rule is removed when the last ban goes" [expr {$rc != 0 || [string match "*No rules match*" $out2]}] $out2
    ::tg::fw::uninstall
} else {
    puts "SKIP firewall tests: not an administrator"
}
}
if {[want firewallscale]} {
phase "windows firewall at scale (thousands of bans -> several rules)"
if {$admin} {
    freshCfg {firewall netsh allowlist {}}
    ::tg::fw::init netsh
    ::tg::ban::registerOnBan ::tg::fw::onBan
    ::tg::ban::registerOnUnban ::tg::fw::onUnban
    ::tg::fw::uninstall
    ::tg::fw::init netsh
    check "firewall backend active for the scale test" [expr {$::tg::fw::backend eq "netsh"}] $::tg::fw::lastError
    check "initial sync succeeds" [::tg::fw::sync] $::tg::fw::lastError
    set N 2500
    set t0 [clock milliseconds]
    for {set i 0} {$i < $N} {incr i} {
        ::tg::ban::add 20.[expr {$i / 60000 + 1}].[expr {($i / 250) % 240 + 1}].[expr {$i % 250 + 1}] "ci scale" 900 manual
    }
    set ok [::tg::fw::commit]
    set ms1 [expr {[clock milliseconds] - $t0}]
    puts "INFO $N bans -> firewall in ${ms1} ms (lastError: '$::tg::fw::lastError')"
    proc ruleExists {n} { expr {![catch {exec netsh advfirewall firewall show rule name=$n} out] && ![string match "*No rules match*" $out]} }
    check "all $N bans were accepted by netsh (no error)" [expr {$::tg::fw::lastError eq ""}] $::tg::fw::lastError
    set nr [llength $::tg::fw::netshHave]
    puts "INFO the bans were spread over $nr rules; netsh accepted at most $::tg::fw::netshMaxChars characters of addresses per rule"
    check "the bans need several rules ($nr)" [expr {$nr >= 4}] $nr
    set missing {}
    for {set k 1} {$k <= $nr} {incr k} { if {![ruleExists [::tg::fw::netshName $k]]} { lappend missing $k } }
    check "every one of those rules exists in the real Windows Firewall" [expr {![llength $missing]}] $missing
    check "there is no rule beyond them" [expr {![ruleExists [::tg::fw::netshName [expr {$nr + 1}]]]}]
    set last 20.[expr {($N - 1) / 60000 + 1}].[expr {(($N - 1) / 250) % 240 + 1}].[expr {($N - 1) % 250 + 1}]
    set found 0
    for {set k 1} {$k <= $nr} {incr k} {
        if {![catch {exec netsh advfirewall firewall show rule name=[::tg::fw::netshName $k] verbose} outk] && [string match "*$last*" $outk]} { set found $k }
    }
    check "the last banned address ($last) is inside one of the rules" [expr {$found > 0}] $found
    check "applying 2500 bans finished in a reasonable time (< 120 s)" [expr {$ms1 < 120000}] $ms1
    # shrink: keep 100 bans, the extra rules must disappear
    set t0 [clock milliseconds]
    for {set i 100} {$i < $N} {incr i} {
        ::tg::ban::remove 20.[expr {$i / 60000 + 1}].[expr {($i / 250) % 240 + 1}].[expr {$i % 250 + 1}]
    }
    ::tg::fw::commit
    puts "INFO shrink to 100 bans in [expr {[clock milliseconds] - $t0}] ms"
    check "after the bans expire, rule 1 remains" [ruleExists "TclGuard Bans"]
    set stale {}
    for {set k 2} {$k <= $nr} {incr k} { if {[ruleExists [::tg::fw::netshName $k]]} { lappend stale $k } }
    check "...and the other rules are removed" [expr {![llength $stale]}] $stale
    # a new process (restart) finds rules left behind
    ::tg::ban::add 20.200.1.1 "ci" 900 manual
    set ::tg::fw::netshHave {}; set ::tg::fw::netshKnown 0
    ::tg::fw::commit
    check "after a restart-style rediscovery the existing rule is updated, not duplicated" [expr {![catch {exec netsh advfirewall firewall show rule name=TclGuard\ Bans} o] && [regexp -all {Rule Name:} $o] == 1}] $o
    ::tg::fw::uninstall
    check "uninstall removes every TclGuard rule" [expr {![ruleExists "TclGuard Bans"] && ![ruleExists "TclGuard Bans 2"]}]
} else {
    puts "SKIP firewall scale test: not an administrator"
}
}
if {[want autostart]} {
phase "autostart (schtasks)"
catch {exec schtasks /Delete /TN TclGuard /F}
check "no autostart task to begin with" [expr {![::tg::autostart::status]}]
set err [::tg::autostart::enable]
check "autostart can be enabled" [expr {$err eq ""}] $err
check "scheduled task is reported" [::tg::autostart::status]
set rc [catch {exec schtasks /Query /TN TclGuard /V /FO LIST} q]
check "task runs the program with --gui at logon" [expr {!$rc && [string match "*--gui*" $q] && [string match "*logon*" [string tolower $q]]}] $q
set err [::tg::autostart::disable]
check "autostart can be removed" [expr {$err eq "" && ![::tg::autostart::status]}] $err
}
if {[want locations]} {
phase "locations"
set h [::tg::cfg::homeDir]
check "config folder is under %APPDATA% ($h)" [expr {[string match -nocase "*TclGuard" $h]}]
check "file attributes -permissions does not break saving" [expr {![catch {::tg::cfg::save [file join $::env(TEMP) tg-perm.conf] [::tg::cfg::new]}]}]
}
if {[want elevation]} {
phase "elevation: the real 'Restart as administrator' path (Start-Process -Verb RunAs)"
# The runner's account is an administrator with UAC off, so no consent dialog appears; what is verified is everything else: that
# the command is accepted by Windows, the elevated copy really starts elevated, and it receives the configuration path intact
# (spaces, an apostrophe and a non-ASCII letter included). The consent dialog itself belongs to Windows.
set tmp [expr {[info exists ::env(RUNNER_TEMP)] ? $::env(RUNNER_TEMP) : $::env(TEMP)}]
set marker [file join $tmp tg-elevated.txt]
file delete -force $marker
set cfgdir [file join $tmp "tg elev it's d\u00e9j\u00e0"]
file mkdir $cfgdir
set cfg [file join $cfgdir "my config.conf"]
set ::tg::cfg::path $cfg
set ::elevExe [info nameofexecutable]
set ::elevScript [file join $::root tests platform elev_marker.tcl]
set ::elevMarker $marker
proc ::tg::autostart::selfCommand {args} { return [list $::elevExe eval $::elevScript $::elevMarker {*}$args] }
set err [::tg::autostart::relaunchAsAdmin]
check "Windows accepted the elevation request" [expr {$err eq ""}] $err
set got ""
for {set i 0} {$i < 120 && $got eq ""} {incr i} { after 500; if {[file exists $marker]} { set fh [open $marker r]; fconfigure $fh -encoding utf-8; set got [string trim [read $fh]]; close $fh } }
check "the elevated copy started within a minute" [expr {$got ne ""}] "no marker file"
if {$got ne ""} {
    check "...and it is really elevated" [expr {[dict get $got privileged] == 1}] $got
    check "...and it got --gui and the configuration path exactly (spaces, apostrophe, accents)" [expr {[dict get $got argv] eq [list --gui --config [file normalize $cfg]]}] $got
}
}
finish
