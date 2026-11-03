source [file join [file dirname [info script]] common.tcl]
puts "macOS platform tests: Tcl [info patchlevel] on $tcl_platform(os) $tcl_platform(osVersion) ($tcl_platform(machine)), uid [exec id -u]"
set root_user [::tg::fw::isPrivileged]
check "platform detected as macos" [expr {[::tg::autostart::platform] eq "macos"}]
check "pfctl is found" [expr {[::tg::fw::which pfctl] ne ""}]
check "backend 'pf' is offered" [expr {"pf" in [::tg::fw::available]}] [::tg::fw::available]
check "auto picks pf" [expr {[::tg::fw::choose auto] eq "pf"}]

# ---- connection table: real BSD netstat output ----
lassign [connectionTableSees 28999] hit n
check "netstat parser finds a live local connection ($n rows seen)" $hit

# ---- pf: needs root (the workflow runs this script with sudo) ----
if {$root_user} {
    freshCfg {firewall pf allowlist {}}
    ::tg::fw::init pf
    check "pf backend becomes active" [expr {$::tg::fw::backend eq "pf"}] $::tg::fw::lastError
    check "sync installs the anchor" [::tg::fw::sync] $::tg::fw::lastError
    ::tg::ban::registerOnBan ::tg::fw::onBan
    ::tg::ban::registerOnUnban ::tg::fw::onUnban
    ::tg::ban::add 203.0.113.7 "ci test" 600 manual
    ::tg::ban::add 2001:db8:1:2::9 "ci v6" 600 manual
    ::tg::fw::commit
    set rc [catch {exec pfctl -a com.apple/tclguard -t tclguard_bans -T show 2>@1} tbl]
    check "ban table lists the v4 address" [expr {!$rc && [string match "*203.0.113.7*" $tbl]}] $tbl
    check "ban table lists the v6 /64" [string match "*2001:db8:1:2::/64*" $tbl] $tbl
    set rc [catch {exec pfctl -a com.apple/tclguard -s rules 2>@1} rules]
    check "block rule is loaded in the anchor" [string match "*block drop in quick from <tclguard_bans>*" $rules] $rules
    ::tg::ban::remove 203.0.113.7
    ::tg::fw::commit
    catch {exec pfctl -a com.apple/tclguard -t tclguard_bans -T show 2>@1} tbl2
    check "unban removes it from the table" [expr {![string match "*203.0.113.7*" $tbl2] && [string match "*2001:db8:1:2::/64*" $tbl2]}] $tbl2
    ::tg::fw::uninstall
    catch {exec pfctl -a com.apple/tclguard -t tclguard_bans -T show 2>@1} tbl3
    check "uninstall empties the anchor" [expr {![string match "*2001:db8*" $tbl3]}] $tbl3
} else {
    puts "SKIP pf tests: not root (run with sudo)"
}

# ---- sign-in autostart through a LaunchAgent ----
catch {::tg::autostart::disable}
set err [::tg::autostart::enable]
check "autostart can be enabled" [expr {$err eq ""}] $err
check "LaunchAgent file exists" [file exists [::tg::autostart::plistPath]]
set rc [catch {exec plutil -lint [::tg::autostart::plistPath] 2>@1} lint]
check "plist passes plutil -lint" [expr {!$rc && [string match "*OK*" $lint]}] $lint
check "status reports it" [::tg::autostart::status]
set err [::tg::autostart::disable]
check "autostart can be removed" [expr {$err eq "" && ![::tg::autostart::status]}] $err

# ---- locations ----
check "config folder is under ~/.config" [string match "*.config/tclguard" [::tg::cfg::homeDir]] [::tg::cfg::homeDir]
finish
