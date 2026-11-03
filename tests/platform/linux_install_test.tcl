# usage: [sudo] <starpack> eval linux_install_test.tcl ?phase ...?    Phases: user system
#
# Real-Linux test of the installer with the single-file program (as CI runs it): user scope in the real home,
# and, as root on a machine with systemd (a GitHub ubuntu runner), a real systemd unit: installed, enabled,
# verified by systemd-analyze, actually started with the starter configuration, controlled through
# `tclguard ctl status`, and removed again.  The starpack must be built from this source tree.
puts "linux_install_test: starting"; flush stdout
source [file join [file dirname [info script]] common.tcl]
set ::phases [expr {[info exists ::argv] && [llength $::argv] ? $::argv : {user system}}]
proc want {p} { expr {$p in $::phases} }
puts "Linux installer tests: Tcl [info patchlevel], [info nameofexecutable], uid [exec id -u]"
if {$tcl_platform(os) ne "Linux"} { puts "SKIP: not Linux"; exit 0 }
if {![llength [info commands ::tg::install::run]]} { check "installer present (rebuild the starpack from this tree)" 0 "::tg::install::run is missing"; finish }
if {![info exists ::starkit::topdir]} { check "running from the single-file program" 0 "no ::starkit::topdir"; finish }
set root_user [::tg::fw::isPrivileged]
proc rawCall {name body} {
    if {[catch {uplevel #0 $body} e opts]} { check "$name raised no error" 0 "$e\n[dict get $opts -errorinfo]" }
}
proc readFile {p} { set fh [open $p rb]; set d [read $fh]; close $fh; return $d }
proc sh {argv} { ::tg::install::sh $argv }

if {[want user]} { rawCall user {
    phase "user scope (real home)"
    set home [file normalize ~]
    catch {::tg::install::uninstall {scope user keepData yes}}
    set bin [file join $home .local bin tclguard]
    set steps [::tg::install::plan {scope user service yes}]
    check "plan lists the program and the autostart entry" [expr {[string match "*$bin*" [join $steps]] && [string match "*sign in*" [join $steps]]}] $steps
    set err [::tg::install::run {scope user service yes}]
    check "install succeeds" [expr {$err eq ""}] $err
    check "program installed, executable, byte-for-byte identical" [expr {[file executable $bin] && [::tg::nfs::same $bin [info nameofexecutable]]}]
    set rc [catch {exec $bin version 2>@1} v]
    check "the installed copy runs" [expr {!$rc && [string match "TclGuard *" $v]}] $v
    set desk [file join $home .local share applications tclguard.desktop]
    check "application menu entry exists" [file exists $desk]
    set rc [catch {exec desktop-file-validate $desk 2>@1} out]
    check "the desktop entry validates (skipped when desktop-file-validate is not installed)" [expr {$rc == 0 || [string match "*no such file*" $out] || [string match "*couldn't execute*" $out]}] $out
    check "autostart entry starts the installed program" [string match "*Exec=*$bin*--gui*" [readFile [::tg::autostart::desktopPath]]]
    set err [::tg::install::run {scope user service yes}]
    check "installing again is fine" [expr {$err eq ""}] $err
    set err [::tg::install::uninstall {scope user keepData yes}]
    check "uninstall succeeds" [expr {$err eq ""}] $err
    check "everything is gone" [expr {![file exists $bin] && ![file exists $desk] && ![file exists [::tg::autostart::desktopPath]]}]

    # the case that matters to a person: the INSTALLED program removes itself (it is a mounted starpack over its own path, which Tcl sees as a folder)
    set err [::tg::install::run {scope user}]
    check "install again for the self-removal test" [expr {$err eq ""}] $err
    set rc [catch {exec $bin uninstall --user --keep-data 2>@1} out]
    check "the installed program's own 'uninstall' succeeds" [expr {!$rc}] $out
    check "...and the program file is gone" [expr {![file exists $bin]}] $out
} }

if {[want system]} {
    if {!$root_user} { puts "SKIP system scope: not root (use sudo)" } else { rawCall system {
        phase "system scope with real systemd"
        catch {::tg::install::uninstall {scope system keepData no}}
        set bin /usr/local/bin/tclguard
        set unit /etc/systemd/system/tclguard.service
        set err [::tg::install::run {scope system service yes}]
        check "install succeeds" [expr {$err eq ""}] $err
        check "program installed" [file executable $bin]
        check "unit file written" [file exists $unit]
        check "starter configuration is private" [expr {[file exists /etc/tclguard/tclguard.conf] && [file attributes /etc/tclguard/tclguard.conf -permissions] eq "00600"}]
        lassign [sh [list systemd-analyze verify $unit]] rc out
        check "systemd-analyze verify accepts the unit" [expr {$rc == 0}] $out
        lassign [sh [list systemctl is-enabled tclguard]] rc out
        check "the service is enabled" [expr {$rc == 0 && [string trim $out] eq "enabled"}] $out
        lassign [sh [list systemctl start tclguard]] rc out
        check "the service starts" [expr {$rc == 0}] $out
        after 4000
        lassign [sh [list systemctl is-active tclguard]] rc out
        check "the service is active (hardened unit, starpack, starter config)" [expr {$rc == 0 && [string trim $out] eq "active"}] [list $out [lindex [sh [list journalctl -u tclguard -n 20 --no-pager]] 1]]
        set rc [catch {exec env TCLGUARD_HOME=/etc/tclguard $bin ctl status 2>@1} out]
        check "ctl status talks to the running service" [expr {!$rc && [string match "*running*" $out]}] $out
        set err [::tg::install::uninstall {scope system keepData no}]
        check "uninstall succeeds" [expr {$err eq ""}] $err
        lassign [sh [list systemctl is-enabled tclguard]] rc out
        check "the service is gone" [expr {$rc != 0}] $out
        check "unit, program and configuration are removed" [expr {![file exists $unit] && ![file exists $bin] && ![file exists /etc/tclguard/tclguard.conf]}]
        check "the kernel table is gone" [expr {[catch {exec nft list table inet tclguard 2>@1}] != 0}]
    } }
}
finish
