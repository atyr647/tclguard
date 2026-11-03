# usage: windows_install_test.tcl ?phase ...?   (no phases = all). Phases: user system defer update
#
# Real-Windows test of the installer (install.tcl): Start Menu / desktop shortcuts, the Add/Remove
# Programs registry entry, the Scheduled Task, replacing a RUNNING copy (rename to .old), the Windows
# Firewall rule removal, and the "an .exe cannot delete itself" helper. Run it with the starpack, as in CI:
#
#   tools\ci-bounded.ps1 ... eval tests\platform\windows_install_test.tcl user
#
# The "system" phase needs an administrator (it writes under %ProgramFiles% and HKLM). The starpack must be
# built from this source tree (an older starpack has no installer; the script says so and fails).
#
# Everything that can raise is caught and printed: an uncaught error in a Tk build on Windows becomes a
# modal dialog that nobody can dismiss on a CI runner.
puts "windows_install_test: starting"; flush stdout
source [file join [file dirname [info script]] common.tcl]
set ::phases [expr {[info exists ::argv] && [llength $::argv] ? $::argv : {user system defer update}}]
proc want {p} { expr {$p in $::phases} }
puts "Windows installer tests: Tcl [info patchlevel] on $tcl_platform(os) $tcl_platform(osVersion), [info nameofexecutable]"

if {$tcl_platform(platform) ne "windows"} { puts "SKIP: not Windows"; exit 0 }
if {![llength [info commands ::tg::install::run]]} {
    check "this build contains the installer (rebuild the starpack from this source tree)" 0 "::tg::install::run is missing"
    finish
}
if {![info exists ::starkit::topdir]} {
    check "running from the single-file program (use: <starpack>.exe eval windows_install_test.tcl)" 0 "no ::starkit::topdir"
    finish
}
set admin [::tg::fw::isPrivileged]
set exe [file normalize [info nameofexecutable]]
set tmp [expr {[info exists ::env(RUNNER_TEMP)] ? $::env(RUNNER_TEMP) : $::env(TEMP)}]

# ---- helpers ---------------------------------------------------------------------------------
proc sh {argv} { ::tg::install::sh $argv }
proc psOut {script} { lassign [sh [::tg::install::psArgv $script]] rc out; list $rc [string trim $out] }
proc regQuery {key {value ""}} {
    set cmd [list reg query $key]
    if {$value ne ""} { lappend cmd /v $value }
    lassign [sh $cmd] rc out
    list $rc $out
}
proc lnkTarget {lnk} { lindex [psOut "(New-Object -ComObject WScript.Shell).CreateShortcut('[string map {' ''} [file nativename $lnk]]').TargetPath"] 1 }
# case-insensitive "contains" for text full of backslashes (string match would read them as escapes)
proc contains {hay needle} { expr {[string first [string tolower $needle] [string tolower $hay]] >= 0} }
proc waitProcessGone {pid secs} {
    set end [expr {[clock seconds] + $secs}]
    while {[clock seconds] < $end} {
        lassign [sh [list tasklist /FI "PID eq $pid" /NH]] rc out
        if {![string match "*$pid*" $out]} { return 1 }
        after 500
    }
    return 0
}
proc waitGone {path secs} {
    set end [expr {[clock seconds] + $secs}]
    while {[file exists $path] && [clock seconds] < $end} { after 500 }
    expr {![file exists $path]}
}
proc rawCall {name body} {
    # run a phase body; report any error as a failed check instead of letting it escape
    if {[catch {uplevel #0 $body} e opts]} {
        check "$name raised no error" 0 "$e\n[dict get $opts -errorinfo]"
    }
}
# an isolated data folder, named like the real one so that the "only folders called TclGuard" rule applies
proc makeData {} {
    global tmp
    set d [file join $tmp tginstall-data TclGuard]
    file delete -force [file dirname $d]
    file mkdir [file join $d state]
    foreach {f c} [list tclguard.conf "general {}" state/bans.db x unrelated.txt "not ours"] {
        set fh [open [file join $d $f] w]; puts $fh $c; close $fh
    }
    set ::env(TCLGUARD_HOME) $d
    return $d
}
proc anExecutableCopy {name {extra ""}} {
    # a byte-different copy of the running program (the starpack is a plain file, so appending changes it)
    global exe tmp
    set dst [file join $tmp $name]
    ::tg::nfs::copy $exe $dst        ;# the running starpack is mounted over its own path: copy the real file
    if {$extra ne ""} { set fh [open $dst ab]; puts -nonewline $fh $extra; close $fh }
    return $dst
}

# ---- scenario shared by user and system scope ------------------------------------------------
proc scenario {scope} {
    global exe tmp admin
    set sys [expr {$scope eq "system"}]
    set data [makeData]
    set opts [list scope $scope service yes desktop yes]
    set dir [file join [expr {$sys ? $::env(ProgramFiles) : [file join $::env(LOCALAPPDATA) Programs]}] TclGuard]
    set inst [file join $dir tclguard.exe]
    set hive [expr {$sys ? "HKLM" : "HKCU"}]
    set regkey "$hive\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TclGuard"
    set menu [file join [::tg::install::shellFolder [expr {$sys ? "CommonPrograms" : "Programs"}] ""] TclGuard.lnk]
    set desk [file join [::tg::install::shellFolder [expr {$sys ? "CommonDesktopDirectory" : "Desktop"}] ""] TclGuard.lnk]
    # start clean (a previous run on a reused machine)
    catch {::tg::install::uninstall [list scope $scope keepData yes]}

    phase "$scope: plan and install"
    set steps [::tg::install::plan $opts]
    check "plan names the program, the shortcuts, the registry entry and the task" \
        [expr {[contains [join $steps] [file nativename $inst]] && [contains [join $steps] "Start Menu"] && [contains [join $steps] "Scheduled Task"] && [contains [join $steps] $hive]}] $steps
    check "plan changed nothing" [expr {![file exists $inst]}]
    set err [::tg::install::run $opts]
    check "install succeeds" [expr {$err eq ""}] $err
    check "the program is in [file nativename $dir]" [file exists $inst]
    check "the installed copy is byte-identical" [::tg::nfs::same $inst $exe]
    set rc [catch {exec $inst version 2>@1} v]
    check "the installed copy runs and reports its version" [expr {!$rc && [string match "TclGuard *" $v]}] $v
    check "Start Menu shortcut exists" [file exists $menu] $menu
    check "the shortcut points at the installed program" [expr {[string tolower [lnkTarget $menu]] eq [string tolower [file nativename $inst]]}] [lnkTarget $menu]
    check "desktop shortcut exists" [file exists $desk] $desk
    lassign [regQuery $regkey DisplayName] rc out
    check "Add/Remove Programs entry exists" [expr {$rc == 0 && [string match "*TclGuard*" $out]}] $out
    lassign [regQuery $regkey UninstallString] rc out
    check "its uninstall command runs the installed program with 'uninstall --interactive'" [expr {$rc == 0 && [string match "*tclguard.exe*uninstall --interactive*" $out]}] $out
    lassign [regQuery $regkey NoModify] rc out
    check "NoModify is set" [expr {$rc == 0 && [string match "*0x1*" $out]}] $out
    lassign [regQuery $regkey EstimatedSize] rc out
    check "EstimatedSize is set" [expr {$rc == 0 && [string match "*REG_DWORD*" $out]}] $out
    lassign [sh [list schtasks /Query /TN TclGuard /V /FO LIST]] rc out
    check "the Scheduled Task starts the INSTALLED program at logon" [expr {$rc == 0 && [contains $out [file nativename $inst]] && [contains $out "--gui"]}] $out
    check "the install record exists and lists the items" [expr {[file exists [file join $dir install.json]] && [llength [dict get [::tg::install::readManifest [file join $dir install.json]] items]] >= 5}]
    set st [::tg::install::status]
    check "status reports it installed ($scope)" [expr {[dict get $st installed] && [dict get $st scope] eq $scope}] $st

    phase "$scope: install again"
    set before [file mtime $inst]
    set err [::tg::install::run $opts]
    check "installing again is fine and changes nothing" [expr {$err eq "" && [file mtime $inst] == $before}] $err

    phase "$scope: installing over a RUNNING copy"
    set sleeper [file join $tmp tg-sleeper.tcl]
    set fh [open $sleeper w]; puts $fh {after 60000 {set ::done 1}; vwait ::done}; close $fh
    set pidRun [exec $inst eval $sleeper &]
    after 3000
    set newer [anExecutableCopy tg-newer.exe "\0padding"]
    set sizeBefore [file size $inst]
    set ::tg::install::exeOverride $newer
    set err [::tg::install::run $opts]
    check "installing over a copy that is running is refused with advice (Windows keeps a running program locked)" [expr {[string match "*is in use*" $err] && [string match "*Close TclGuard*" $err]}] $err
    check "...and the running copy is untouched, no temporary files are left" [expr {[file size $inst] == $sizeBefore && ![llength [glob -nocomplain "$inst.new*"]]}]
    catch {exec taskkill /F /PID $pidRun}
    check "the old running copy ended" [waitProcessGone $pidRun 30]
    set err [::tg::install::run $opts]
    set ::tg::install::exeOverride ""
    check "after it ended the install replaces the program" [expr {$err eq "" && [file size $inst] == [file size $newer]}] $err

    phase "$scope: uninstall from another copy"
    set cfgBefore [file exists [file join $data tclguard.conf]]
    if {$sys} {
        # a firewall rule TclGuard would have created: uninstall must remove it
        sh [list netsh advfirewall firewall add rule name=$::tg::fw::ruleName dir=in action=block remoteip=203.0.113.9]
    }
    set steps [::tg::install::uninstallPlan [list scope $scope keepData yes]]
    check "uninstall plan lists the items" [expr {[llength $steps] >= 6}] $steps
    set err [::tg::install::uninstall [list scope $scope keepData yes]]
    check "uninstall (keep data) succeeds" [expr {$err eq ""}] $err
    check "program is gone" [expr {![file exists $inst]}]
    check "install folder is gone" [expr {![file exists $dir]}] $dir
    check "shortcuts are gone" [expr {![file exists $menu] && ![file exists $desk]}]
    lassign [regQuery $regkey] rc out
    check "registry entry is gone" [expr {$rc != 0}] $out
    lassign [sh [list schtasks /Query /TN TclGuard]] rc out
    check "Scheduled Task is gone" [expr {$rc != 0}] $out
    if {$sys} {
        lassign [sh [list netsh advfirewall firewall show rule name=$::tg::fw::ruleName]] rc out
        check "the Windows Firewall rule is gone" [expr {$rc != 0 || [string match "*No rules match*" $out]}] $out
    }
    check "keepData left the configuration and unrelated files alone" [expr {[file exists [file join $data tclguard.conf]] && [file exists [file join $data unrelated.txt]]}]
    check "status says not installed" [expr {![dict get [::tg::install::status] installed]}]

    phase "$scope: reinstall, then uninstall deleting data"
    set err [::tg::install::run $opts]
    check "reinstall works" [expr {$err eq ""}] $err
    set err [::tg::install::uninstall [list scope $scope keepData no]]
    check "uninstall (delete data) succeeds" [expr {$err eq ""}] $err
    check "TclGuard's own files in the data folder are gone" [expr {![file exists [file join $data tclguard.conf]] && ![file exists [file join $data state bans.db]]}]
    check "a file TclGuard did not create survives, and so does its folder" [file exists [file join $data unrelated.txt]]
    catch {file delete -force [file dirname $data]}
}

if {[want user]} { rawCall "user scope" { scenario user } }
if {[want system]} {
    if {$admin} { rawCall "system scope" { scenario system } } else { puts "SKIP system scope: not an administrator" }
}

# ---- the real thing: an .exe uninstalling itself --------------------------------------------------
if {[want defer]} { rawCall "self-uninstall" {
    phase "uninstall from the INSTALLED program (a running .exe cannot delete itself)"
    set data [makeData]
    catch {::tg::install::uninstall {scope user keepData yes}}
    set dir [file join $::env(LOCALAPPDATA) Programs TclGuard]
    set inst [file join $dir tclguard.exe]
    set err [::tg::install::run {scope user}]
    check "install" [expr {$err eq ""}] $err
    set rc [catch {exec $inst uninstall --user --keep-data 2>@1} out]
    puts [string range $out 0 1500]
    check "the installed program's own 'uninstall' exits 0" [expr {!$rc}] $out
    check "it says the program is removed after it exits" [string match "*removed a few seconds after*" $out] $out
    check "the detached helper deletes the program and the install folder within 60 s" [waitGone $dir 60] "still there: [file exists $dir]"
    lassign [regQuery "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TclGuard"] rc o
    check "registry entry is gone" [expr {$rc != 0}] $o
    check "keepData left the data folder" [file exists [file join $data tclguard.conf]]
    catch {file delete -force [file dirname $data]}
} }

# ---- self-update mechanics on real Windows (the parts that cannot be faked) -------------------------
if {[want update]} { rawCall "update mechanics" {
    phase "update: a program answers 'version' over a pipe, and a RUNNING exe can be swapped"
    set guiExe [file join $::root releases tclguard-windows-x86_64.exe]
    if {[file exists $guiExe]} {
        # the GUI-subsystem build has no console: its output must still reach a pipe, or no update could ever be verified
        lassign [::tg::update::runVersion $guiExe] ok text
        check "the GUI (no-console) program prints its version into a pipe" [expr {$ok && [string match "TclGuard *" $text]}] $text
    } else {
        puts "SKIP GUI-build version check: $guiExe not present"
    }
    lassign [::tg::update::runVersion $exe] ok text
    check "the console program prints its version into a pipe" [expr {$ok && [string match "TclGuard *" $text]}] $text
    set target [file join $tmp tg-upd-target.exe]
    catch {file delete -force $target $target.previous $target.old}
    ::tg::nfs::copy $exe $target
    set sleeper [file join $tmp tg-sleeper2.tcl]
    set fh [open $sleeper w]; puts $fh {after 60000 {set ::done 1}; vwait ::done}; close $fh
    set pidRun [exec $target eval $sleeper &]
    after 3000
    set newer [file join $tmp tg-upd-new.exe]
    ::tg::nfs::copy $exe $newer
    set fh [open $newer ab]; puts -nonewline $fh "\0update"; close $fh
    set orig [file size $target]
    # (1) another process runs the file: Windows keeps a running starpack locked, so the swap is refused clearly
    set e [catch {::tg::update::swapIn $newer $target} msg]
    check "replacing a file another running TclGuard holds is refused, with advice" [expr {$e && [string match "*close it first*" $msg]}] $msg
    check "...and the running program is untouched" [expr {[file size $target] == $orig}]
    # (2) the target is THIS program (pretend it is): a helper does the swap after the process exits
    set ::tg::install::exeOverride $target
    set ::tg::update::swapWaitPid $pidRun
    set r [catch {::tg::update::swapIn $newer $target} msg]
    set ::tg::install::exeOverride ""
    set ::tg::update::swapWaitPid ""
    check "swapIn of the running program is deferred to a helper" [expr {!$r && $msg eq "deferred"}] $msg
    after 3000
    check "while the program runs nothing is touched" [expr {[file size $target] == $orig && [file exists $newer]}]
    check ".previous holds the old program" [expr {[file exists $target.previous] && [file size $target.previous] == $orig}]
    catch {exec taskkill /F /PID $pidRun}
    check "the old running copy ended" [waitProcessGone $pidRun 30]
    set ok 0
    for {set i 0} {$i < 60 && !$ok} {incr i} { after 500; set ok [expr {[file size $target] == $orig + 7 && ![file exists $newer]}] }
    check "within 30 s of the exit the helper has put the new program in place" $ok
    set ::tg::update::targetOverride $target
    set n [::tg::update::cleanup]
    set ::tg::update::targetOverride ""
    puts "INFO cleanup removed $n leftover(s)"
    catch {file delete -force $target $target.previous $newer}
} }
finish
