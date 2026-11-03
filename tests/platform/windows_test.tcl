source [file join [file dirname [info script]] common.tcl]
puts "Windows platform tests: Tcl [info patchlevel] on $tcl_platform(os) $tcl_platform(osVersion), [info nameofexecutable]"

phase "facts"
set admin [::tg::fw::isPrivileged]
check "administrator detection runs (admin=$admin)" 1
check "netsh is found" [expr {[::tg::fw::which netsh] ne ""}]
check "backend 'netsh' is offered" [expr {"netsh" in [::tg::fw::available]}] [::tg::fw::available]
check "auto picks netsh" [expr {[::tg::fw::choose auto] eq "netsh"}]
check "platform detected as windows" [expr {[::tg::autostart::platform] eq "windows"}]

phase "netstat"
lassign [connectionTableSees 28999] hit n
check "netstat parser finds a live local connection ($n rows seen)" $hit

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

phase "locations"
set h [::tg::cfg::homeDir]
check "config folder is under %APPDATA% ($h)" [expr {[string match -nocase "*TclGuard" $h]}]
check "file attributes -permissions does not break saving" [expr {![catch {::tg::cfg::save [file join $::env(TEMP) tg-perm.conf] [::tg::cfg::new]}]}]
finish
