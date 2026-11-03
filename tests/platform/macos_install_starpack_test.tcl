# usage: <the macOS starpack> eval macos_install_starpack_test.tcl
#
# The installer as a person meets it on a Mac: the single file installs ITSELF (user scope, HOME redirected into a temporary folder so
# the runner's own home is untouched; no launchctl bootstrap), the installed copy runs, the LaunchAgent plist is valid and points at it,
# and the INSTALLED program then removes itself (a mounted starpack looks like a folder to Tcl: found on real Windows, same on Unix).
puts "macos_install_starpack_test: starting"; flush stdout
source [file join [file dirname [info script]] common.tcl]
puts "macOS starpack installer tests: Tcl [info patchlevel], [info nameofexecutable], uid [exec id -u]"
if {$tcl_platform(os) ne "Darwin"} { puts "SKIP: not macOS"; exit 0 }
if {![info exists ::starkit::topdir]} { check "running from the single-file program" 0 "no ::starkit::topdir (run it as <starpack> eval ...)"; finish }
proc readFile {p} { set fh [open $p rb]; set d [read $fh]; close $fh; return $d }
set base [expr {[info exists ::env(RUNNER_TEMP)] ? $::env(RUNNER_TEMP) : "/tmp"}]/tg-mac-sp-install
file delete -force $base
file mkdir "$base/home dir"
set ::env(HOME) "$base/home dir"
unset -nocomplain ::env(XDG_CONFIG_HOME) ::env(XDG_DATA_HOME)
phase "user scope, real starpack"
set err [::tg::install::run {scope user service yes}]
check "install succeeds" [expr {$err eq ""}] $err
set bin [file join $::env(HOME) .local bin tclguard]
if {![file exists $bin]} {
    # find where it went (the record knows)
    set st [::tg::install::status]; if {[dict exists $st binary]} { set bin [dict get $st binary] }
}
check "program installed and executable" [expr {[file executable $bin]}] $bin
check "...and byte-for-byte identical to the running one" [::tg::nfs::same $bin [info nameofexecutable]]
set rc [catch {exec $bin version 2>@1} v]
check "the installed copy runs" [expr {!$rc && [string match "TclGuard *" $v]}] $v
set plist [::tg::autostart::plistPath]
check "LaunchAgent plist exists" [file exists $plist] $plist
set rc [catch {exec plutil -lint $plist 2>@1} lint]
check "the plist passes plutil -lint" [expr {!$rc && [string match "*OK*" $lint]}] $lint
check "it starts the INSTALLED program" [string match "*$bin*" [readFile $plist]]
phase "the installed program removes itself"
set rc [catch {exec $bin uninstall --user --keep-data 2>@1} out]
check "the installed program's own 'uninstall' succeeds" [expr {!$rc}] $out
check "...and the program file is gone" [expr {![file exists $bin]}] $out
check "...and so is the LaunchAgent plist" [expr {![file exists $plist]}]
file delete -force $base
finish
