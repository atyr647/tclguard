# autostart.tcl -- "start TclGuard when I sign in", plus the small OS helpers the
# GUI needs so nobody has to open a terminal:
#
#   ::tg::autostart::status | enable | disable      sign-in autostart
#   ::tg::autostart::relaunchAsAdmin                restart elevated (UAC / macOS prompt)
#   ::tg::autostart::openFolder path                open a folder in Explorer / Finder / the file manager
#   ::tg::autostart::selfCommand args               command line that runs this program again
#
# Windows uses a Scheduled Task (so it can start elevated, which the Windows Firewall
# integration needs), macOS a LaunchAgent, Linux an XDG autostart entry.

namespace eval ::tg::autostart {
    variable taskName TclGuard
    variable label com.tclguard.app
    # Tests replace this to capture commands instead of running them.
    variable runner ::tg::autostart::run_
}

proc ::tg::autostart::run_ {argv} {
    if {[catch {exec {*}$argv 2>@1} out opts]} {
        set ec [dict get $opts -errorcode]
        if {[lindex $ec 0] eq "CHILDSTATUS"} { return [list [lindex $ec 2] $out] }
        return [list -1 $out]
    }
    list 0 $out
}

proc ::tg::autostart::run {argv} {
    variable runner
    {*}$runner $argv
}

# The command that starts this program again (works as a starpack and from source).
proc ::tg::autostart::selfCommand {args} {
    set exe [info nameofexecutable]
    if {[info exists ::starkit::topdir]} { return [list $exe {*}$args] }
    list $exe [file normalize $::argv0] {*}$args
}

proc ::tg::autostart::platform {} {
    global tcl_platform
    if {$tcl_platform(platform) eq "windows"} { return windows }
    if {$tcl_platform(os) eq "Darwin"} { return macos }
    return linux
}

proc ::tg::autostart::quoteWin {s} {
    if {[regexp {[\s"]} $s]} { return "\"[string map {\" \\\"} $s]\"" }
    return $s
}

# ---- Linux: ~/.config/autostart/tclguard.desktop ----

proc ::tg::autostart::desktopPath {} {
    global env
    set base [expr {[info exists env(XDG_CONFIG_HOME)] && $env(XDG_CONFIG_HOME) ne "" ? $env(XDG_CONFIG_HOME) : [file join [file normalize ~] .config]}]
    file join $base autostart tclguard.desktop
}

proc ::tg::autostart::desktopEntry {cmd} {
    set exec [join [lmap a $cmd {expr {[regexp {[\s"'\\$`]} $a] ? "\"[string map {\\ \\\\ \" \\\" $ \\$ ` \\`} $a]\"" : $a}}] " "]
    return "\[Desktop Entry\]\nType=Application\nName=TclGuard\nComment=DDoS protection for your game server or website\nExec=$exec\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
}

# ---- macOS: ~/Library/LaunchAgents/com.tclguard.app.plist ----

proc ::tg::autostart::plistPath {} {
    variable label
    file join [file normalize ~] Library LaunchAgents $label.plist
}

proc ::tg::autostart::xmlEsc {s} { string map {& &amp; < &lt; > &gt;} $s }

proc ::tg::autostart::plist {cmd} {
    variable label
    set args ""
    foreach a $cmd { append args "        <string>[xmlEsc $a]</string>\n" }
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n    <key>Label</key>\n    <string>$label</string>\n    <key>ProgramArguments</key>\n    <array>\n$args    </array>\n    <key>RunAtLoad</key>\n    <true/>\n</dict>\n</plist>\n"
}

# ---- public API ----

proc ::tg::autostart::status {} {
    variable taskName
    switch -- [platform] {
        windows { lassign [run [list schtasks /Query /TN $taskName]] rc; return [expr {$rc == 0}] }
        macos   { return [file exists [plistPath]] }
        default { return [file exists [desktopPath]] }
    }
}

# Returns "" on success, or an error message.
proc ::tg::autostart::enable {} {
    variable taskName
    set cmd [selfCommand --gui]
    switch -- [platform] {
        windows {
            set tr [join [lmap a $cmd {quoteWin $a}] " "]
            # highest privileges so the firewall integration works; needs an administrator
            lassign [run [list schtasks /Create /TN $taskName /TR $tr /SC ONLOGON /RL HIGHEST /F]] rc out
            if {$rc != 0} {
                # not elevated: a normal-privilege task still starts the app at sign-in
                lassign [run [list schtasks /Create /TN $taskName /TR $tr /SC ONLOGON /F]] rc out
            }
            if {$rc != 0} { return "could not create the scheduled task: [string trim $out]" }
        }
        macos {
            if {[catch {
                file mkdir [file dirname [plistPath]]
                ::tg::writeFileAtomic [plistPath] [plist $cmd]
            } err]} { return "could not write [plistPath]: $err" }
        }
        default {
            if {[catch {
                file mkdir [file dirname [desktopPath]]
                ::tg::writeFileAtomic [desktopPath] [desktopEntry $cmd]
            } err]} { return "could not write [desktopPath]: $err" }
        }
    }
    return ""
}

proc ::tg::autostart::disable {} {
    variable taskName
    switch -- [platform] {
        windows {
            lassign [run [list schtasks /Delete /TN $taskName /F]] rc out
            if {$rc != 0 && [status]} { return "could not remove the scheduled task: [string trim $out]" }
        }
        macos   { catch {file delete [plistPath]} }
        default { catch {file delete [desktopPath]} }
    }
    return ""
}

# Restart with administrator rights. Returns "" if the elevated copy was launched
# (the caller should then quit), otherwise a message to show the user.
proc ::tg::autostart::relaunchAsAdmin {} {
    set cmd [selfCommand --gui]
    switch -- [platform] {
        windows {
            set exe [lindex $cmd 0]
            set rest [lrange $cmd 1 end]
            set ps "Start-Process -FilePath '[string map {' ''} $exe]' -ArgumentList '[string map {' ''} [join [lmap a $rest {quoteWin $a}] { }]]' -Verb RunAs"
            lassign [run [list powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command $ps]] rc out
            if {$rc != 0} { return "Windows did not start the elevated copy: [string trim $out]" }
            return ""
        }
        macos {
            set sh [join [lmap a $cmd {string cat ' [string map {' '\\''} $a] '}] " "]
            set osa "do shell script \"$sh >/dev/null 2>&1 &\" with administrator privileges"
            lassign [run [list osascript -e $osa]] rc out
            if {$rc != 0} { return "macOS did not start the elevated copy: [string trim $out]" }
            return ""
        }
        default {
            return "Close this window and start TclGuard with:  sudo [join $cmd { }]"
        }
    }
}

proc ::tg::autostart::openFolder {path} {
    file mkdir $path
    switch -- [platform] {
        windows { run [list explorer [file nativename $path]] }
        macos   { run [list open $path] }
        default { run [list xdg-open $path] }
    }
    return ""
}
