# usage: sudo -E tclsh8.6 macos_install_test.tcl
#
# macOS runs from source on CI (there is no macOS starpack yet), and the installer refuses to run from source,
# so this script checks that refusal for real and then drives the installer with the test hook that
# stands in for the starpack: a stand-in program, HOME and the system root redirected into a temporary
# folder. What it proves on a real Mac: the generated plists pass plutil -lint, the commands the installer
# would run are the ones launchctl/pfctl accept (launchctl bootout of an unloaded label fails harmlessly),
# paths with spaces work, and uninstall removes exactly what was installed.
#
# It does NOT bootstrap the LaunchDaemon into launchd (that would start a stand-in program at boot).
puts "macos_install_test: starting"; flush stdout
source [file join [file dirname [info script]] common.tcl]
puts "macOS installer tests: Tcl [info patchlevel] on $tcl_platform(os) $tcl_platform(osVersion) ($tcl_platform(machine)), uid [exec id -u]"
if {$tcl_platform(os) ne "Darwin"} { puts "SKIP: not macOS"; exit 0 }
if {![llength [info commands ::tg::install::run]]} { check "installer present" 0 "::tg::install::run is missing"; finish }
set root_user [::tg::fw::isPrivileged]

proc rawCall {name body} {
    if {[catch {uplevel #0 $body} e opts]} { check "$name raised no error" 0 "$e\n[dict get $opts -errorinfo]" }
}
proc readFile {p} { set fh [open $p rb]; set d [read $fh]; close $fh; return $d }

rawCall main {
    phase "refusal from source"
    check "running from source is refused with a pointer to the download" \
        [string match "*single file*" [::tg::install::run {scope user}]] [::tg::install::run {scope user}]

    set base [expr {[info exists ::env(RUNNER_TEMP)] ? $::env(RUNNER_TEMP) : "/tmp"}]/tg-mac-install
    file delete -force $base
    file mkdir "$base/home dir" "$base/root" "$base/src"
    set prog "$base/src/tclguard-standin"
    set fh [open $prog w]; puts $fh "#!/bin/sh\necho TclGuard 0.0.0"; close $fh
    file attributes $prog -permissions 0755
    set ::tg::install::exeOverride $prog
    set realHome $::env(HOME)
    set ::env(HOME) "$base/home dir"
    unset -nocomplain ::env(XDG_CONFIG_HOME) ::env(XDG_DATA_HOME)

    phase "user scope: program in a folder with a space, LaunchAgent"
    set err [::tg::install::run {scope user service yes}]
    check "user install succeeds" [expr {$err eq ""}] $err
    set bin "$base/home dir/.local/bin/tclguard"
    check "program installed and executable" [expr {[file exists $bin] && [file executable $bin]}]
    set rc [catch {exec $bin version 2>@1} v]
    check "the installed copy runs" [expr {!$rc && [string match "TclGuard *" $v]}] $v
    set plist [::tg::autostart::plistPath]
    check "LaunchAgent plist written under the (redirected) home" [expr {[file exists $plist] && [string first $base $plist] == 0}] $plist
    set rc [catch {exec plutil -lint $plist 2>@1} lint]
    check "the LaunchAgent plist passes plutil -lint" [expr {!$rc && [string match "*OK*" $lint]}] $lint
    check "it starts the INSTALLED program" [string match "*$bin*" [readFile $plist]]
    set err [::tg::install::uninstall {scope user}]
    check "user uninstall succeeds" [expr {$err eq ""}] $err
    check "program, plist and record are gone" [expr {![file exists $bin] && ![file exists $plist] && ![dict get [::tg::install::status] installed]}]

    phase "system scope under a temporary root: LaunchDaemon and starter configuration"
    if {$root_user} {
        set ::tg::install::fsRoot "$base/root"
        set ::tg::install::elevatedOverride 1
        set err [::tg::install::run {scope system service yes}]
        check "system install succeeds" [expr {$err eq ""}] $err
        set pl "$base/root/Library/LaunchDaemons/com.tclguard.daemon.plist"
        check "LaunchDaemon plist exists" [file exists $pl]
        set rc [catch {exec plutil -lint $pl 2>@1} lint]
        check "the LaunchDaemon plist passes plutil -lint" [expr {!$rc && [string match "*OK*" $lint]}] $lint
        check "it runs the program headless with the config path" [expr {[string match "*--headless*" [readFile $pl]] && [string match "*/etc/tclguard/tclguard.conf*" [readFile $pl]]}]
        set conf "$base/root/etc/tclguard/tclguard.conf"
        check "starter configuration exists and is valid" [expr {[file exists $conf] && ![catch {::tg::cfg::parseText [readFile $conf]}]}]
        check "configuration is private (0600)" [expr {[file attributes $conf -permissions] eq "00600"}] [file attributes $conf -permissions]
        set ::tg::install::fsRoot ""
        # the real commands the uninstaller uses must at least be understood by this macOS
        set rc [catch {exec launchctl bootout system/com.tclguard.daemon.test.nonexistent 2>@1} out]
        check "launchctl bootout of an unloaded label fails harmlessly (what uninstall tolerates)" [expr {$rc != 0}] $out
        set ::tg::install::fsRoot "$base/root"
        set err [::tg::install::uninstall {scope system keepData no}]
        check "system uninstall succeeds" [expr {$err eq ""}] $err
        check "everything it installed is gone" [expr {![file exists $pl] && ![file exists "$base/root/usr/local/bin/tclguard"] && ![file exists $conf]}]
    } else {
        puts "SKIP system scope: not root (run with sudo)"
    }
    set ::env(HOME) $realHome
    file delete -force $base
}
finish
