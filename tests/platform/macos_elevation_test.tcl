# macOS: the "Restart as administrator" path, as far as a machine without a person can take it.
#   tclsh8.6 macos_elevation_test.tcl            (as the normal runner user; uses sudo -n for the root part, which a runner allows)
#
# What is verified: the AppleScript is valid and launches the program with every argument intact, including paths with spaces,
# apostrophes, double quotes, backslashes, $ ` & ; and accents (the same script runs WITHOUT the "with administrator
# privileges" words, which only add the dialog); the same shell line works when run by root; the cancel message is recognised.
# What cannot be verified here: the password dialog itself, which belongs to macOS.
source [file join [file dirname [info script]] common.tcl]
puts "macOS elevation tests: Tcl [info patchlevel] on $tcl_platform(os) $tcl_platform(osVersion) ($tcl_platform(machine)), uid [exec id -u]"
set tmp [expr {[info exists ::env(RUNNER_TEMP)] ? $::env(RUNNER_TEMP) : "/tmp"}]
set marker [file join $tmp tg-elev-mac.txt]
set script [file join $::root tests platform elev_marker.tcl]
set ::elevCmd [list [info nameofexecutable] $script $marker]
proc ::tg::autostart::selfCommand {args} { return [list {*}$::elevCmd {*}$args] }
proc readMarker {} {
    for {set i 0} {$i < 60} {incr i} {
        after 250
        if {[file exists $::marker]} { set fh [open $::marker r]; fconfigure $fh -encoding utf-8; set d [string trim [read $fh]]; close $fh; if {$d ne ""} { return $d } }
    }
    return ""
}

set paths [list \
    "/tmp/plain.conf" \
    "/tmp/with space/my config.conf" \
    "/tmp/it's/a.conf" \
    "/tmp/say \"hi\"/a.conf" \
    "/tmp/back\\slash/a.conf" \
    "/tmp/\$HOME `id` & ; (x) {y} \[z\]/a.conf" \
    "/tmp/déjà ☃/a.conf"]

phase "AppleScript text"
set ::tg::autostart::macPrivilege "with administrator privileges"
set ::tg::cfg::path "/tmp/x y/z.conf"
set osa [::tg::autostart::macScript [::tg::autostart::elevationCommand]]
check "the script asks for administrator privileges, with an explanatory prompt" [expr {[string match "*with prompt \"TclGuard needs administrator rights*\" with administrator privileges" $osa]}] $osa
check "the config path is part of the command" [string match "*--config*x y/z.conf*" $osa] $osa

phase "the script launches the program with every argument intact (run as the current user: no dialog)"
set ::tg::autostart::macPrivilege ""
foreach p $paths {
    file delete -force $marker
    set ::tg::cfg::path $p
    set osa [::tg::autostart::macScript [::tg::autostart::elevationCommand]]
    set rc [catch {exec osascript -e $osa 2>@1} out]
    set got [expr {$rc ? "" : [readMarker]}]
    set want [list --gui --config [file normalize $p]]
    check "osascript ran it, argv exact: $p" [expr {$got ne "" && [dict get $got argv] eq $want}] "rc=$rc out=$out got=$got"
}

phase "the same shell line run by root (what the dialog would do after the password)"
if {[catch {exec sudo -n true 2>@1}]} {
    puts "SKIP: no passwordless sudo here"
} else {
    foreach p [lrange $paths 1 end] {
        file delete -force $marker
        set ::tg::cfg::path $p
        set line [::tg::autostart::macShellLine [::tg::autostart::elevationCommand]]
        set rc [catch {exec sudo -n /bin/sh -c $line 2>@1} out]
        set got [expr {$rc ? "" : [readMarker]}]
        check "as root, argv exact, uid 0: $p" [expr {$got ne "" && [dict get $got uid] == 0 && [dict get $got argv] eq [list --gui --config [file normalize $p]]}] "rc=$rc out=$out got=$got"
    }
}

phase "cancel and error wording"
foreach {text want} [list \
    "execution error: User canceled. (-128)" 1 \
    "0:57: execution error: User cancelled. (-128)" 1 \
    "Start-Process : This command cannot be run due to the error: The operation was canceled by the user." 1 \
    "Start-Process : The system cannot find the file specified." 0 \
    "execution error: Permission denied (1)" 0] {
    check "declined? '[string range $text 0 50]' -> $want" [expr {[::tg::autostart::declined $text] == $want}]
}

phase "the REAL password dialog on this machine (information only: a script cannot know the account password here)"
set ::tg::autostart::macPrivilege "with administrator privileges"
set ::tg::cfg::path "/tmp/dialog.conf"
file delete -force $marker
set osa [::tg::autostart::macScript [::tg::autostart::elevationCommand]]
set ch [open [list |osascript -e $osa 2>@1] r]
fconfigure $ch -blocking 0
set out ""
set t0 [clock seconds]
while {[clock seconds] - $t0 < 20 && ![eof $ch]} { after 250; append out [read $ch] }
if {![eof $ch]} {
    puts "INFO the macOS password dialog opened and is waiting for a password after 20 s (as it should); closing it"
    catch {exec killall osascript}
    catch {exec killall SecurityAgent}
} else {
    catch {close $ch} err
    puts "INFO the dialog ended by itself: output '[string trim $out]' $err"
    puts "INFO that text is [expr {[::tg::autostart::declined "$out $err"] ? {recognised as a refusal by TclGuard} : {NOT recognised as a refusal}}]"
}
check "the dialog did not start the program without a password" [expr {![file exists $marker]}]
finish
