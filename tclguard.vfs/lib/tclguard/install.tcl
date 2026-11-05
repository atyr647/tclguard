# install.tcl -- "I downloaded one file and never want to open a terminal": install and uninstall
# TclGuard on Windows, Linux and macOS.
#
#   ::tg::install::plan ?options?        human-readable list of what install WOULD do (no changes)
#   ::tg::install::planError ?options?   "" when the install can proceed, otherwise why not
#   ::tg::install::run options           do it; returns "" on success or an error message (never raises)
#   ::tg::install::uninstallPlan ?opts?  what uninstall would do
#   ::tg::install::uninstall options     undo it; returns "" or an error message (never raises)
#   ::tg::install::status                dict: installed, scope, binary, version, items, ...
#   ::tg::install::notes                 informational lines produced by the last run/uninstall
#
# Options are a dict:
#   scope      user | system | ""     "" = system when elevated (administrator / root), else user
#   service    0|1                    start automatically (Windows: Scheduled Task at sign-in with highest
#                                     privileges; Linux system: systemd unit, headless; macOS system:
#                                     LaunchDaemon, headless; user scope: start the GUI at sign-in)
#   startMenu  0|1  (default 1)       Start Menu shortcut (Windows) / application menu entry (Linux)
#   desktop    0|1  (default 0)       desktop shortcut (Windows)
#   keepData   0|1  (uninstall)       keep configuration, bans and certificates
#   dir        path                   install into this folder instead of the default
#   force      0|1                    overwrite a file we did not install ourselves
#
# SAFETY MODEL
#   * Everything the installer creates is written to an install record (install.json: next to the
#     program on Windows, in <share>/tclguard/ on Linux and macOS). Uninstall removes ONLY what that
#     record lists, re-checks every recorded path with unsafePath, deletes directories only when
#     they are empty, and removes configuration/state only by a fixed list of file names inside
#     folders that are called "tclguard".
#   * Refuses empty paths, "/", drive roots, the home folder (or a parent of it), system folders,
#     relative paths, paths with ".." and control characters (which would inject lines into unit
#     files, desktop entries and scripts).
#   * Never overwrites a file at the target that this installer did not put there, unless the bytes
#     are identical or force is set.
#   * Every external command goes through ::tg::install::runner (default: the autostart runner), so
#     tests capture commands instead of running them. Arguments are always passed as a Tcl list to
#     exec, never through a shell. PowerShell scripts are sent with -EncodedCommand, which removes
#     every quoting problem (spaces, quotes, non-ASCII user names).
#
# WINDOWS: a running .exe cannot delete itself. Uninstall removes everything it can, then starts a
# hidden, detached PowerShell that waits for this process to exit and deletes the locked files
# (retrying for a minute) and then the install folder if it is empty. Installing over a running
# copy does NOT work: a running starpack holds its own file open in a way that forbids renaming and
# overwriting it (measured on a real runner), so the install stops with a message asking to close the
# running TclGuard first. (Leftover <name>.old files of older versions are still cleaned up.)

namespace eval ::tg::install {
    variable runner ::tg::autostart::run          ;# {argv} -> {exitcode output}; tests replace it
    variable spawner ::tg::install::spawn_         ;# {argv} starts a detached process; tests replace it
    variable fsRoot ""            ;# test hook: prefix for SYSTEM paths on Linux/macOS (like DESTDIR)
    variable exeOverride ""       ;# test hook: pretend this file is the running starpack
    variable elevatedOverride ""  ;# test hook: 0/1
    variable toolOverride {}      ;# test hook: dict tool -> 0/1 for "is this command installed"
    variable pathStyleOverride "" ;# test hook: judge paths by unix rules while pretending to be Windows
    variable lastNotes {}
    variable manifestName install.json
    variable serviceName tclguard
    variable daemonLabel com.tclguard.daemon
    variable winTask TclGuard
    variable regPath {Software\Microsoft\Windows\CurrentVersion\Uninstall\TclGuard}
    variable projectUrl https://github.com/atyr647/tclguard
    variable defaults {scope "" service 0 startMenu 1 desktop 0 keepData 0 dir "" force 0}
    variable itemTypes {binary file conf dir regkey autostart service fwrule}
}

# ------------------------------------------------------------------ small helpers ----

proc ::tg::install::sh {argv} {
    variable runner
    {*}$runner $argv
}

# Start a detached process and return immediately. Returns "" or an error message.
proc ::tg::install::spawn_ {argv} {
    set null [expr {[::tg::autostart::platform] eq "windows" ? "NUL" : "/dev/null"}]
    if {[catch {exec {*}$argv < $null > $null 2> $null &} err]} { return "could not start [lindex $argv 0]: $err" }
    return ""
}

proc ::tg::install::spawn {argv} {
    variable spawner
    {*}$spawner $argv
}

proc ::tg::install::platform {} { ::tg::autostart::platform }
proc ::tg::install::isWin {} { expr {[platform] eq "windows"} }

proc ::tg::install::elevated {} {
    variable elevatedOverride
    if {$elevatedOverride ne ""} { return [expr {!!$elevatedOverride}] }
    if {[llength [info commands ::tg::fw::isPrivileged]]} { return [::tg::fw::isPrivileged] }
    return 0
}

proc ::tg::install::have {name} {
    variable toolOverride
    if {[dict exists $toolOverride $name]} { return [dict get $toolOverride $name] }
    expr {[auto_execok $name] ne ""}
}

proc ::tg::install::nat {p} { if {[isWin]} { return [file nativename $p] } ; return $p }

proc ::tg::install::envVar {name} {
    global env
    if {[info exists env($name)] && $env($name) ne ""} { return $env($name) }
    return ""
}

proc ::tg::install::homeDir {} {
    if {[isWin] && [envVar USERPROFILE] ne ""} { return [envVar USERPROFILE] }
    if {[catch {file normalize ~} h] || $h eq "" || $h eq "~"} { error "cannot determine your home folder" }
    return $h
}

proc ::tg::install::boolOpt {v} { expr {[string is boolean -strict $v] ? !!$v : 0} }

# Path under the (test-only) system root. Empty fsRoot = the real thing.
proc ::tg::install::sysPath {p} {
    variable fsRoot
    if {$fsRoot eq ""} { return $p }
    file join $fsRoot [string trimleft $p /]
}
proc ::tg::install::logical {p} {
    variable fsRoot
    if {$fsRoot ne "" && [string first $fsRoot $p] == 0} { return [string range $p [string length $fsRoot] end] }
    return $p
}

proc ::tg::install::runningExe {} {
    variable exeOverride
    if {$exeOverride ne ""} { return $exeOverride }
    return [info nameofexecutable]
}

proc ::tg::install::selfExe {} {
    variable exeOverride
    if {$exeOverride ne ""} { return $exeOverride }
    set exe [info nameofexecutable]
    # NB a mounted starpack looks like a directory to Tcl, so "isdirectory" says nothing here; what matters is that
    # topdir is the program file itself (an unwrapped folder or another runtime fails the comparison below).
    if {![info exists ::starkit::topdir]} {
        error "TclGuard is running from source files, not from the single-file program, so there is nothing to install. Download the single file for your system from $::tg::install::projectUrl/releases"
    }
    if {[canon $::starkit::topdir] ne [canon $exe]} {
        error "TclGuard is not running from its own single file (it was started through another Tcl runtime), so it cannot copy itself"
    }
    return [file normalize $exe]
}

# Comparable form of a path: normalized, long names and lower case on Windows.
proc ::tg::install::canon {p} {
    set n [file normalize $p]
    if {[isWin]} {
        catch { set n [file normalize [file attributes $n -longname]] }
        set n [string tolower $n]
    }
    return $n
}

proc ::tg::install::sameFile {a b} {
    if {![file exists $a] || ![file exists $b]} { return 0 }
    if {[canon $a] eq [canon $b]} { return 1 }
    if {[catch {file stat $a sa; file stat $b sb}]} { return 0 }
    expr {$sa(ino) != 0 && $sa(ino) == $sb(ino) && $sa(dev) == $sb(dev)}
}

# Byte-for-byte comparison without reading both files into memory.
proc ::tg::install::sameBytes {a b} {
    if {[file size $a] != [file size $b]} { return 0 }
    set fa [open $a rb]
    set fb [open $b rb]
    try {
        while {![eof $fa]} {
            if {[read $fa 1048576] ne [read $fb 1048576]} { return 0 }
        }
        return 1
    } finally {
        close $fa
        close $fb
    }
}

# Directories that would have to be created for dir to exist, outermost first.
proc ::tg::install::missingDirs {dir} {
    set missing {}
    set d $dir
    while {![file exists $d]} {
        lappend missing $d
        set p [file dirname $d]
        if {$p eq $d} break
        set d $p
    }
    lreverse $missing
}

proc ::tg::install::globEsc {s} {
    set out ""
    foreach c [split $s ""] {
        if {$c in {\\ * ? [ ] \{ \}}} { append out "\\" }
        append out $c
    }
    return $out
}

# files named <path><suffix> (suffix may contain glob wildcards; path is taken literally)
proc ::tg::install::siblings {path args} {
    set out {}
    foreach sfx $args { lappend out {*}[glob -nocomplain -directory [file dirname $path] -- [globEsc [file tail $path]]$sfx] }
    return $out
}

proc ::tg::install::note {text} {
    variable lastNotes
    lappend lastNotes $text
}
proc ::tg::install::notes {} { variable lastNotes; return $lastNotes }

# ------------------------------------------------------------------ path safety ----

# Return "" when path may be created/deleted by the installer, otherwise the reason it may not.
# level basic: structural checks only (used for a folder that legitimately already exists and
# holds other programs, like /usr/local/bin); level strict: additionally never a well-known
# system or per-user folder itself (used for everything we create or delete).
proc ::tg::install::unsafePath {path {level strict} {plat ""}} {
    variable pathStyleOverride
    if {$plat eq ""} { set plat [expr {$pathStyleOverride ne "" ? $pathStyleOverride : [platform]}] }
    if {$path eq ""} { return "the path is empty" }
    if {[regexp {[\x00-\x1f\x7f]} $path]} { return "the path contains control characters" }
    set p [string map {\\ /} $path]
    if {[regexp {(^|/)\.\.(/|$)} $p]} { return "the path contains '..'" }
    set low [string tolower $p]
    if {$plat eq "windows"} {
        if {[regexp {^[a-z]:/*$} $low]} { return "that is a drive root" }
        if {![regexp {^[a-z]:/} $low] && ![regexp {^//[^/]} $low]} { return "the path is not an absolute Windows path" }
        if {[regexp {^//[^/]*(/[^/]*)?/*$} $low]} { return "that is a network share root" }
        set t [string trimright [regsub -all {/+} $low /] /]
        set home [string trimright [string tolower [string map {\\ /} [envVar USERPROFILE]]] /]
    } else {
        if {[string index $p 0] ne "/"} { return "the path is not absolute" }
        set t [string trimright [regsub -all {/+} $p /] /]
        if {$t eq ""} { return "that is the root folder" }
        if {[catch {file normalize ~} home]} { set home "" }
        set home [string trimright $home /]
        set low $t
    }
    if {$home ne "" && ($t eq $home || [string first "$t/" "$home/"] == 0)} {
        return "that is your home folder or a folder that contains it"
    }
    if {$level eq "basic"} { return "" }
    if {$plat eq "windows"} {
        set bad {c:/windows c:/windows/system32 c:/program files "c:/program files (x86)" c:/programdata c:/users c:/users/public}
        foreach v {ProgramFiles ProgramFiles(x86) ProgramW6432 SystemRoot windir ProgramData USERPROFILE APPDATA LOCALAPPDATA TEMP TMP PUBLIC} {
            set e [envVar $v]
            if {$e ne ""} { lappend bad [string trimright [string tolower [string map {\\ /} $e]] /] }
        }
        lappend bad "[string trimright [string tolower [string map {\\ /} [envVar LOCALAPPDATA]]] /]/programs"
        if {$t in $bad} { return "that is a system or user folder, not a program folder" }
    } else {
        set bad {/bin /boot /dev /etc /home /lib /lib64 /opt /proc /root /run /sbin /srv /sys /tmp /usr /usr/bin /usr/lib
                 /usr/local /usr/local/bin /usr/local/share /usr/sbin /usr/share /var /var/lib /var/tmp /applications /library /system
                 /users /volumes /private /private/etc /private/var /etc/systemd /etc/systemd/system /library/launchdaemons
                 /library/launchagents /usr/share/applications}
        if {[string tolower $t] in $bad} { return "that is a system folder, not a file or folder TclGuard owns" }
        foreach sub {.local .local/bin .local/share .local/share/applications .config .config/autostart} {
            if {$home ne "" && $t eq "$home/$sub"} { return "that is a shared per-user folder" }
        }
    }
    return ""
}

# ------------------------------------------------------------------ options & layout ----

proc ::tg::install::normOptions {options} {
    variable defaults
    set o $defaults
    if {[catch {dict size $options}]} { error "options must be a dict" }
    dict for {k v} $options {
        if {![dict exists $defaults $k]} { error "unknown option '$k'" }
        dict set o $k $v
    }
    if {[dict get $o scope] ni {"" user system}} { error "scope must be user or system" }
    foreach k {service startMenu desktop keepData force} {
        set v [dict get $o $k]
        if {![string is boolean -strict $v]} { error "$k must be yes or no" }
        dict set o $k [boolOpt $v]
    }
    return $o
}

# Ask Windows where the Programs (Start Menu) and Desktop folders really are (they can be
# redirected); fall back to the usual place under the environment variables.
proc ::tg::install::shellFolder {special fallback} {
    set ps "\[Environment\]::GetFolderPath('$special')"
    lassign [sh [psArgv $ps]] rc out
    set out [string trim $out]
    if {$rc == 0 && $out ne "" && [unsafePath $out basic] eq ""} { return $out }
    return $fallback
}

# The facts about where everything goes. Raises an error (a plain message) when it cannot proceed.
proc ::tg::install::layout {o} {
    variable manifestName
    variable serviceName
    variable daemonLabel
    variable regPath
    set plat [platform]
    set scope [dict get $o scope]
    if {$scope eq ""} { set scope [expr {[elevated] ? "system" : "user"}] }
    if {$scope eq "system" && ![elevated]} {
        if {$plat eq "windows"} {
            error "a system-wide install needs administrator rights. Use 'Restart as administrator', or install for this user only."
        }
        error "a system-wide install needs root. Run it with sudo, or install for this user only (--user)."
    }
    set src [selfExe]
    set L [dict create platform $plat scope $scope exe $src]
    set custom [dict get $o dir]
    if {$plat eq "windows"} {
        if {$custom ne ""} {
            set dir $custom
        } elseif {$scope eq "system"} {
            set pf [envVar ProgramFiles]
            if {$pf eq ""} { error "the ProgramFiles environment variable is not set" }
            set dir [file join $pf TclGuard]
        } else {
            set la [envVar LOCALAPPDATA]
            if {$la eq ""} { error "the LOCALAPPDATA environment variable is not set" }
            set dir [file join $la Programs TclGuard]
        }
        if {[set why [unsafePath $dir strict]] ne ""} { error "refusing to install into '$dir': $why" }
        dict set L dir $dir
        dict set L binPath [file join $dir tclguard.exe]
        dict set L manifest [file join $dir $manifestName]
        dict set L flavor [expr {[regexp -nocase console [file tail $src]] ? "console" : "gui"}]
        if {[dict get $o startMenu]} {
            set fb [expr {$scope eq "system"
                ? [file join [expr {[envVar ProgramData] ne "" ? [envVar ProgramData] : "C:/ProgramData"}] Microsoft Windows {Start Menu} Programs]
                : [file join [expr {[envVar APPDATA] ne "" ? [envVar APPDATA] : [file join [homeDir] AppData Roaming]}] Microsoft Windows {Start Menu} Programs]}]
            set sf [shellFolder [expr {$scope eq "system" ? "CommonPrograms" : "Programs"}] $fb]
            dict set L startMenuLnk [file join $sf TclGuard.lnk]
        }
        if {[dict get $o desktop]} {
            set fb [expr {$scope eq "system"
                ? [file join [expr {[envVar PUBLIC] ne "" ? [envVar PUBLIC] : "C:/Users/Public"}] Desktop]
                : [file join [homeDir] Desktop]}]
            set df [shellFolder [expr {$scope eq "system" ? "CommonDesktopDirectory" : "Desktop"}] $fb]
            dict set L desktopLnk [file join $df TclGuard.lnk]
        }
        dict set L regKey "[expr {$scope eq {system} ? {HKLM} : {HKCU}}]\\$regPath"
        dict set L dataDirs [list [::tg::cfg::homeDir]]
    } else {
        set home [homeDir]
        set xdgData [expr {[envVar XDG_DATA_HOME] ne "" ? [envVar XDG_DATA_HOME] : [file join $home .local share]}]
        if {$scope eq "system"} {
            set dir [expr {$custom ne "" ? $custom : [sysPath /usr/local/bin]}]
            dict set L share [sysPath /usr/local/share/tclguard]
            dict set L appsDir [sysPath /usr/share/applications]
            dict set L confDir [sysPath /etc/tclguard]
            dict set L dataDirs [list [sysPath /etc/tclguard] [sysPath /var/lib/tclguard]]
        } else {
            set dir [expr {$custom ne "" ? $custom : [file join $home .local bin]}]
            dict set L share [file join $xdgData tclguard]
            dict set L appsDir [file join $xdgData applications]
            dict set L dataDirs [list [file join [expr {[envVar XDG_CONFIG_HOME] ne "" ? [envVar XDG_CONFIG_HOME] : [file join $home .config]}] tclguard]]
        }
        if {[set why [unsafePath $dir basic]] ne ""} { error "refusing to install into '$dir': $why" }
        dict set L dir $dir
        dict set L binPath [file join $dir tclguard]
        dict set L manifest [file join [dict get $L share] $manifestName]
        if {$scope eq "system"} {
            if {$plat eq "linux"} {
                dict set L unitPath [sysPath /etc/systemd/system/$serviceName.service]
            } else {
                dict set L plistPath [sysPath /Library/LaunchDaemons/$daemonLabel.plist]
            }
            dict set L confPath [file join [dict get $L confDir] tclguard.conf]
        }
        if {$plat eq "linux" && [dict get $o startMenu]} {
            dict set L desktopFile [file join [dict get $L appsDir] tclguard.desktop]
        }
    }
    foreach k {binPath manifest startMenuLnk desktopLnk desktopFile unitPath plistPath confPath} {
        if {[dict exists $L $k] && [set why [unsafePath [dict get $L $k] strict]] ne ""} {
            error "refusing to use '[dict get $L $k]': $why"
        }
    }
    return $L
}

# ------------------------------------------------------------------ PowerShell ----

# 'quoted' PowerShell string. PowerShell also treats the typographic single quotes as quotes.
proc ::tg::install::psq {s} { ::tg::psq $s }

# UTF-16LE bytes, the encoding -EncodedCommand wants (Tcl 8.6 has no utf-16le encoding).
proc ::tg::install::utf16le {s} {
    set units {}
    foreach ch [split $s ""] {
        scan $ch %c c
        if {$c > 0xFFFF} {
            set c [expr {$c - 0x10000}]
            lappend units [expr {0xD800 + ($c >> 10)}] [expr {0xDC00 + ($c & 0x3FF)}]
        } else {
            lappend units $c
        }
    }
    binary format s* $units
}

# Every script starts by silencing progress records: with redirected output PowerShell otherwise prints
# "Preparing modules for first use" as CLIXML on stderr, which then ends up in our results and messages.
set ::tg::install::psPrefix "\$ProgressPreference='SilentlyContinue'; "
proc ::tg::install::psArgv {script} {
    list powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden \
        -EncodedCommand [binary encode base64 [utf16le $::tg::install::psPrefix$script]]
}

proc ::tg::install::psDecode {argv} {
    set i [lsearch -exact $argv -EncodedCommand]
    if {$i < 0} { return "" }
    set b [binary decode base64 [lindex $argv [expr {$i + 1}]]]
    binary scan $b s* units
    set out ""
    set n [llength $units]
    for {set k 0} {$k < $n} {incr k} {
        set u [expr {[lindex $units $k] & 0xFFFF}]
        if {$u >= 0xD800 && $u < 0xDC00 && $k + 1 < $n} {
            set lo [expr {[lindex $units [incr k]] & 0xFFFF}]
            set u [expr {0x10000 + (($u - 0xD800) << 10) + ($lo - 0xDC00)}]
        }
        append out [format %c $u]
    }
    if {[string first $::tg::install::psPrefix $out] == 0} { set out [string range $out [string length $::tg::install::psPrefix] end] }
    return $out
}

proc ::tg::install::shortcutScript {lnk target workDir description} {
    return [join [list \
        "\$ErrorActionPreference = 'Stop'" \
        "\$s = (New-Object -ComObject WScript.Shell).CreateShortcut([psq $lnk])" \
        "\$s.TargetPath = [psq $target]" \
        "\$s.WorkingDirectory = [psq $workDir]" \
        "\$s.Description = [psq $description]" \
        "\$s.IconLocation = [psq $target,0]" \
        "\$s.Save()"] "\n"]
}

# Waits for the uninstaller process to exit, then deletes exactly the listed files (retrying while
# antivirus or the shell still holds them) and finally the listed folders if they are EMPTY.
# Nothing is ever deleted recursively.
proc ::tg::install::deleteHelperScript {parentPid files dirs} {
    set fl [join [lmap f $files {psq $f}] ,]
    set dl [join [lmap d $dirs {psq $d}] ,]
    return [join [list \
        "\$ErrorActionPreference = 'SilentlyContinue'" \
        "Wait-Process -Id $parentPid -Timeout 90" \
        "\$files = @($fl)" \
        "for (\$i = 0; \$i -lt 60; \$i++) {" \
        "  \$left = 0" \
        "  foreach (\$f in \$files) { if (Test-Path -LiteralPath \$f) { Remove-Item -LiteralPath \$f -Force; if (Test-Path -LiteralPath \$f) { \$left++ } } }" \
        "  if (\$left -eq 0) { break }" \
        "  Start-Sleep -Seconds 1" \
        "}" \
        "foreach (\$d in @($dl)) { if ((Test-Path -LiteralPath \$d) -and -not (Get-ChildItem -LiteralPath \$d -Force | Select-Object -First 1)) { Remove-Item -LiteralPath \$d -Force } }"] "\n"]
}

proc ::tg::install::regArgv {key name type data} {
    list reg add $key /v $name /t $type /d $data /f
}

# ------------------------------------------------------------------ file formats ----

proc ::tg::install::desktopQuote {a} {
    if {[regexp {[\s"'\\$`<>~|&;*?#()%=]} $a]} {
        return "\"[string map {\\ \\\\ \" \\\" $ \\$ ` \\` % %%} $a]\""
    }
    return $a
}

proc ::tg::install::desktopFileText {binPath} {
    return "\[Desktop Entry\]\nType=Application\nName=TclGuard\nComment=DDoS protection for your game server or website\nExec=[desktopQuote $binPath] --gui\nTerminal=false\nCategories=Network;Security;\nStartupNotify=false\n"
}

# systemd ExecStart word quoting: double quotes, with \ " escaped, and % / $ doubled.
proc ::tg::install::systemdQuote {a} {
    if {[regexp {[\s"'\\$%;]} $a]} {
        return "\"[string map {\\ \\\\ \" \\\" % %% $ $$} $a]\""
    }
    return [string map {% %% $ $$} $a]
}

# Mirrors packaging/tclguard.service (a test keeps them in step); only the program path differs.
proc ::tg::install::unitText {binPath confDir stateDir} {
    set conf [file join $confDir tclguard.conf]
    return "# Installed by 'tclguard install --service'. Remove with 'tclguard uninstall'.
\[Unit\]
Description=TclGuard DDoS protection
After=network-online.target
Wants=network-online.target

\[Service\]
Type=simple
Environment=TCLGUARD_HOME=$confDir
ExecStart=[systemdQuote $binPath] --headless --config [systemdQuote $conf]
LimitNOFILE=1024
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$stateDir $confDir
StateDirectory=tclguard

\[Install\]
WantedBy=multi-user.target
"
}

proc ::tg::install::daemonPlist {binPath confDir} {
    variable daemonLabel
    set conf [file join $confDir tclguard.conf]
    set args ""
    foreach a [list $binPath --headless --config $conf] { append args "        <string>[::tg::autostart::xmlEsc $a]</string>\n" }
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n    <key>Label</key>\n    <string>$daemonLabel</string>\n    <key>ProgramArguments</key>\n    <array>\n$args    </array>\n    <key>EnvironmentVariables</key>\n    <dict>\n        <key>TCLGUARD_HOME</key>\n        <string>[::tg::autostart::xmlEsc $confDir]</string>\n    </dict>\n    <key>RunAtLoad</key>\n    <true/>\n    <key>KeepAlive</key>\n    <true/>\n    <key>StandardOutPath</key>\n    <string>/var/log/tclguard.log</string>\n    <key>StandardErrorPath</key>\n    <string>/var/log/tclguard.log</string>\n</dict>\n</plist>\n"
}

# ------------------------------------------------------------------ install record ----

proc ::tg::install::manifestJson {m} {
    set items {}
    foreach it [dict get $m items] {
        set pairs {}
        dict for {k v} $it { lappend pairs $k [::tg::json::quote $v] }
        lappend items [::tg::json::object {*}$pairs]
    }
    set dd [lmap d [dict get $m dataDirs] {::tg::json::quote $d}]
    return "[::tg::json::object \
        schema 1 \
        version [::tg::json::quote [dict get $m version]] \
        scope [::tg::json::quote [dict get $m scope]] \
        platform [::tg::json::quote [dict get $m platform]] \
        flavor [::tg::json::quote [dict get $m flavor]] \
        installedAt [dict get $m installedAt] \
        updatedAt [dict get $m updatedAt] \
        exe [::tg::json::quote [dict get $m exe]] \
        dataDirs [::tg::json::array {*}$dd] \
        items [::tg::json::array {*}$items]]\n"
}

# -> record dict, or an error. Everything in it is untrusted until unsafePath has been applied.
proc ::tg::install::parseManifest {text} {
    variable itemTypes
    set d [::tg::json::parse $text]
    if {![string is list -strict $d] || [catch {dict size $d}]} { error "install record is not an object" }
    if {[::tg::json::get $d schema] ne "1"} { error "install record has an unknown format" }
    foreach k {version scope platform exe} {
        if {![dict exists $d $k]} { error "install record lacks '$k'" }
    }
    set m [dict create version [dict get $d version] scope [dict get $d scope] platform [dict get $d platform] \
        flavor [::tg::json::get $d flavor gui] installedAt [::tg::json::get $d installedAt 0] \
        updatedAt [::tg::json::get $d updatedAt 0] exe [dict get $d exe] dataDirs [::tg::json::get $d dataDirs {}] items {}]
    if {[dict get $m scope] ni {user system}} { error "install record has a bad scope" }
    foreach it [::tg::json::get $d items {}] {
        if {[catch {dict size $it}] || ![dict exists $it type] || [dict get $it type] ni $itemTypes} { error "install record has an unknown item" }
        dict set m items [linsert [dict get $m items] end $it]
    }
    return $m
}

proc ::tg::install::readManifest {path} {
    if {![file isfile $path]} { return "" }
    parseManifest [::tg::readFile $path]
}

# Every place an install record may be: the default location of each scope, plus next to the
# running program (a custom --dir install on Windows can be uninstalled from its own copy).
proc ::tg::install::manifestCandidates {{scope ""}} {
    variable manifestName
    set out {}
    foreach s {system user} {
        if {$scope ne "" && $s ne $scope} continue
        if {[catch {layoutPaths $s} p]} continue
        lappend out $s $p
    }
    if {$scope eq ""} {
        set here [file join [file dirname [file normalize [runningExe]]] $manifestName]
        if {[file isfile $here] && $here ni $out} { lappend out "" $here }
    }
    return $out
}

# Where the install record of a scope lives, without needing the running program to be installable.
proc ::tg::install::layoutPaths {scope} {
    variable manifestName
    if {[isWin]} {
        if {$scope eq "system"} {
            set b [envVar ProgramFiles]
            if {$b eq ""} { error "no ProgramFiles" }
            return [file join $b TclGuard $manifestName]
        }
        set b [envVar LOCALAPPDATA]
        if {$b eq ""} { error "no LOCALAPPDATA" }
        return [file join $b Programs TclGuard $manifestName]
    }
    if {$scope eq "system"} { return [file join [sysPath /usr/local/share/tclguard] $manifestName] }
    set xdgData [expr {[envVar XDG_DATA_HOME] ne "" ? [envVar XDG_DATA_HOME] : [file join [homeDir] .local share]}]
    return [file join $xdgData tclguard $manifestName]
}

# -> {scope path record} of the install to work on, or raises.
proc ::tg::install::findInstall {o} {
    set want [dict get $o scope]
    set order {}
    set cands [manifestCandidates $want]
    # prefer the scope we could actually modify
    set pref [expr {[elevated] ? {system user} : {user system}}]
    foreach pscope [concat $pref {{}}] {
        foreach {s p} $cands { if {$s eq $pscope && [file isfile $p]} { lappend order $s $p } }
    }
    if {![llength $order]} { error "TclGuard is not installed (no install record found), so there is nothing to remove" }
    lassign $order s p
    if {[catch {readManifest $p} m]} { error "the install record $p is damaged ($m); remove the files listed in docs/INSTALL.md by hand" }
    if {$s eq ""} { set s [dict get $m scope] }
    if {[dict get $m scope] eq "system" && ![elevated]} {
        error "TclGuard is installed system-wide; removing it needs [expr {[isWin] ? {administrator rights} : {root (use sudo)}}]"
    }
    return [list $s $p $m]
}

# ------------------------------------------------------------------ plan ----

proc ::tg::install::describeInstall {o L} {
    set steps {}
    set plat [dict get $L platform]
    set bin [dict get $L binPath]
    set same [sameFile [dict get $L exe] $bin]
    if {$same} {
        lappend steps "TclGuard is already running from [nat $bin]; nothing to copy"
    } elseif {[file isfile $bin] && ![catch {rawSame [dict get $L exe] $bin} same] && $same} {
        lappend steps "[nat $bin] is already this exact program; nothing to copy"
    } elseif {[file exists $bin]} {
        lappend steps "Replace the installed program [nat $bin] with this one (a running copy keeps using the old version until it is restarted[expr {$plat eq {windows} ? {; Windows refuses to replace a program while it runs, so close TclGuard first} : {}}])"
    } else {
        lappend steps "Copy this program to [nat $bin]"
    }
    if {$plat eq "windows"} {
        if {[dict exists $L startMenuLnk]} { lappend steps "Create the Start Menu shortcut [nat [dict get $L startMenuLnk]]" }
        if {[dict exists $L desktopLnk]} { lappend steps "Create the desktop shortcut [nat [dict get $L desktopLnk]]" }
        lappend steps "Add TclGuard to Settings > Apps (Add/Remove Programs): [dict get $L regKey]"
        if {[dict get $o service]} { lappend steps "Start TclGuard when you sign in (Scheduled Task '$::tg::install::winTask', highest privileges when permitted)" }
    } else {
        if {[dict exists $L desktopFile]} { lappend steps "Add an application menu entry [dict get $L desktopFile]" }
        if {[dict get $o service]} {
            if {[dict get $L scope] eq "system"} {
                if {$plat eq "linux"} {
                    lappend steps "Create the systemd service [dict get $L unitPath] (runs 'tclguard --headless' as root, hardened)"
                    lappend steps "Run: systemctl daemon-reload; systemctl enable tclguard (it is not started until you have edited the configuration)"
                } else {
                    lappend steps "Create the LaunchDaemon [dict get $L plistPath] (runs 'tclguard --headless' at boot)"
                }
                if {![file exists [dict get $L confPath]]} { lappend steps "Create a starter configuration [dict get $L confPath] (no listeners yet)" }
            } else {
                lappend steps "Start TclGuard when you sign in ([expr {$plat eq {macos} ? {LaunchAgent} : {autostart entry}}])"
            }
        }
    }
    lappend steps "Write the install record [dict get $L manifest] so that uninstall removes exactly these items and nothing else"
    return $steps
}

proc ::tg::install::planError {{options {}}} {
    if {[catch {layout [normOptions $options]} r]} { return $r }
    return ""
}

proc ::tg::install::plan {{options {}}} {
    if {[catch {
        set o [normOptions $options]
        set L [layout $o]
        set steps [describeInstall $o $L]
    } err]} { return [list "CANNOT INSTALL: $err"] }
    return $steps
}

# ------------------------------------------------------------------ install ----

proc ::tg::install::addItem {mVar item} {
    upvar 1 $mVar m
    set items [dict get $m items]
    foreach it $items { if {$it eq $item} return }
    # same thing, different attributes (e.g. a re-install): replace
    set idKeys [expr {[dict exists $item path] ? "path" : [dict exists $item key] ? "key" : "name"}]
    set k [dict get $item $idKeys]
    set n 0
    foreach it $items {
        if {[dict get $it type] eq [dict get $item type] && [dict exists $it $idKeys] && [dict get $it $idKeys] eq $k} {
            lset items $n $item
            dict set m items $items
            return
        }
        incr n
    }
    lappend items $item
    dict set m items $items
}

proc ::tg::install::hasItem {m type field value} {
    foreach it [dict get $m items] {
        if {[dict get $it type] eq $type && [dict exists $it $field] && [dict get $it $field] eq $value} { return 1 }
    }
    return 0
}

proc ::tg::install::saveManifest {L m} {
    set path [dict get $L manifest]
    foreach d [missingDirs [file dirname $path]] { lappend created $d }
    file mkdir [file dirname $path]
    if {[info exists created]} { foreach d $created { addItem m [dict create type dir path $d] } }
    ::tg::writeFileAtomic $path [manifestJson $m] 0644
    return $m
}

proc ::tg::install::newManifest {L} {
    set now [clock seconds]
    dict create version $::tg::VERSION scope [dict get $L scope] platform [dict get $L platform] \
        flavor [expr {[dict exists $L flavor] ? [dict get $L flavor] : "gui"}] installedAt $now updatedAt $now \
        exe [dict get $L binPath] dataDirs [dict get $L dataDirs] items {}
}

# The program file itself is only ever touched through ::tg::nfs (see nativefs.tcl): a running starpack is
# mounted over its own path, so Tcl's file commands would act on the files inside it.
# 'quoted' PowerShell string. PowerShell also treats the typographic single quotes as quotes.
proc ::tg::install::rawCopy {src dst} { if {[catch {::tg::nfs::copy $src $dst} e]} { error "could not copy the program: $e" } }
proc ::tg::install::rawSame {a b} { ::tg::nfs::same $a $b }

proc ::tg::install::copyProgram {o L mVar} {
    upvar 1 $mVar m
    set src [dict get $L exe]
    set dst [dict get $L binPath]
    set dir [file dirname $dst]
    if {[file exists $dst] && ![file isfile $dst]} { error "$dst exists and is not a regular file" }
    foreach d [missingDirs $dir] { lappend made $d }
    if {[sameFile $src $dst]} {
        addItem m [dict create type binary path $dst]
        return
    }
    if {[file exists $dst] && ![rawSame $src $dst] && ![hasItem $m binary path $dst] && ![dict get $o force]} {
        error "$dst already exists and was not installed by TclGuard. Move it away, or use --force to replace it."
    }
    file mkdir $dir
    if {[info exists made]} { foreach d $made { addItem m [dict create type dir path $d] } }
    if {[file exists $dst] && [rawSame $src $dst]} {
        addItem m [dict create type binary path $dst]
        return
    }
    if {[file exists $dst]} { note "A TclGuard that is already running keeps using the old version until it is restarted." }
    set tmp "$dst.new[pid]"
    try {
        rawCopy $src $tmp
        catch { file attributes $tmp -permissions 0755 }
        if {![rawSame $src $tmp]} { error "the copy to $tmp does not match the original (disk full?)[expr {$::tg::nfs::lastError ne {} ? " - $::tg::nfs::lastError" : {}}]" }
        putInPlace $tmp $dst
    } finally {
        catch { file delete -force -- $tmp }
    }
    addItem m [dict create type binary path $dst]
}

# Replace dst with tmp (same folder). On Windows a TclGuard that is running from dst keeps the file locked (a
# running starpack holds its own file open, so it cannot be renamed, overwritten or deleted: measured on a real
# runner), and the answer is to say so instead of leaving a half-done install.
proc ::tg::install::putInPlace {tmp dst} {
    if {[catch {file rename -force -- $tmp $dst} err]} {
        if {[isWin] && [file exists $dst]} {
            error "[nat $dst] is in use: a TclGuard started from it is running, and Windows does not let a running program be replaced. Close TclGuard (also check Task Manager and the TclGuard scheduled task) and run the installation again. ($err)"
        }
        error $err
    }
}

proc ::tg::install::writeShortcut {lnk target} {
    file delete -force -- $lnk
    lassign [sh [psArgv [shortcutScript [nat $lnk] [nat $target] [nat [file dirname $target]] "DDoS protection for your game server or website"]]] rc out
    if {$rc != 0} { error "could not create the shortcut $lnk: [string trim $out]" }
    if {![file exists $lnk]} { error "Windows reported success but the shortcut $lnk does not exist" }
}

proc ::tg::install::registerWindows {o L mVar} {
    upvar 1 $mVar m
    variable projectUrl
    set key [dict get $L regKey]
    set bin [nat [dict get $L binPath]]
    set kb [expr {([file size [dict get $L binPath]] + 1023) / 1024}]
    addItem m [dict create type regkey key $key]
    foreach {name type data} [list \
        DisplayName REG_SZ TclGuard \
        DisplayVersion REG_SZ $::tg::VERSION \
        Publisher REG_SZ {TclGuard project} \
        InstallLocation REG_SZ [nat [dict get $L dir]] \
        InstallDate REG_SZ [clock format [clock seconds] -format %Y%m%d] \
        DisplayIcon REG_SZ "$bin,0" \
        URLInfoAbout REG_SZ $projectUrl \
        UninstallString REG_SZ "\"$bin\" uninstall --interactive" \
        EstimatedSize REG_DWORD $kb \
        NoModify REG_DWORD 1 \
        NoRepair REG_DWORD 1] {
        lassign [sh [regArgv $key $name $type $data]] rc out
        if {$rc != 0} { error "could not write $key\\$name: [string trim $out]" }
    }
}

proc ::tg::install::starterConfig {L mVar} {
    upvar 1 $mVar m
    set conf [dict get $L confPath]
    if {[file exists $conf]} return
    foreach d [missingDirs [dict get $L confDir]] { addItem m [dict create type dir path $d] }
    file mkdir [dict get $L confDir]
    set c [::tg::cfg::new]
    dict set c general controlToken [::tg::randomHex 16]
    set fh [open $conf {WRONLY CREAT EXCL} 0600]
    try {
        fconfigure $fh -encoding utf-8
        puts -nonewline $fh [::tg::cfg::serialize $c]
    } finally {
        close $fh
    }
    addItem m [dict create type conf path $conf]
}

proc ::tg::install::installService {o L mVar} {
    upvar 1 $mVar m
    variable serviceName
    variable daemonLabel
    set plat [dict get $L platform]
    set bin [dict get $L binPath]
    if {$plat eq "windows"} {
        set e [::tg::autostart::enable [list [nat $bin] --gui]]
        if {$e ne ""} { error $e }
        addItem m [dict create type autostart mechanism task name $::tg::install::winTask]
        return
    }
    if {[dict get $L scope] eq "user"} {
        set file [expr {$plat eq "macos" ? [::tg::autostart::plistPath] : [::tg::autostart::desktopPath]}]
        set made [missingDirs [file dirname $file]]
        set e [::tg::autostart::enable [list $bin --gui]]
        foreach d $made { if {[file isdirectory $d]} { addItem m [dict create type dir path $d] } }
        if {$e ne ""} { error $e }
        addItem m [dict create type autostart mechanism [expr {$plat eq "macos" ? "launchagent" : "desktop"}] path $file]
        return
    }
    starterConfig $L m
    set confDir [logical [dict get $L confDir]]
    set stateDir [logical [sysPath /var/lib/tclguard]]
    if {$plat eq "linux"} {
        set unit [dict get $L unitPath]
        foreach d [missingDirs [file dirname $unit]] { addItem m [dict create type dir path $d] }
        file mkdir [file dirname $unit]
        ::tg::writeFileAtomic $unit [unitText [logical $bin] $confDir $stateDir] 0644
        catch { file attributes $unit -permissions 0644 }
        addItem m [dict create type service manager systemd name $serviceName.service path $unit]
        if {[have systemctl]} {
            lassign [sh [list systemctl daemon-reload]] rc out
            if {$rc != 0} { error "systemctl daemon-reload failed: [string trim $out]" }
            lassign [sh [list systemctl enable $serviceName]] rc out
            if {$rc != 0} { error "systemctl enable failed: [string trim $out]" }
            note "TclGuard is set to start at boot. Edit [logical [dict get $L confPath]] (or run 'tclguard init --preset ...' with TCLGUARD_HOME=$confDir), then start it with: systemctl start $serviceName"
        } else {
            note "systemd was not found. The unit file is at $unit; when systemd is available run: systemctl daemon-reload && systemctl enable --now $serviceName"
        }
    } else {
        set plist [dict get $L plistPath]
        file mkdir [file dirname $plist]
        ::tg::writeFileAtomic $plist [daemonPlist [logical $bin] $confDir] 0644
        catch { file attributes $plist -permissions 0644 }
        addItem m [dict create type service manager launchd name $daemonLabel path $plist]
        note "The LaunchDaemon starts TclGuard at the next boot. To start it now: sudo launchctl bootstrap system [logical $plist]   (edit [logical [dict get $L confPath]] first)"
    }
}

proc ::tg::install::run {options} {
    variable lastNotes
    set lastNotes {}
    if {[catch {runInner $options} err opts]} {
        catch { ::tg::log::debug "install failed: [dict get $opts -errorinfo]" }
        return $err
    }
    return ""
}

proc ::tg::install::runInner {options} {
    set o [normOptions $options]
    set L [layout $o]
    set manifest [dict get $L manifest]
    set m [newManifest $L]
    if {[file isfile $manifest]} {
        if {[catch {readManifest $manifest} pm]} {
            error "the existing install record $manifest is damaged ($pm). Remove it (and the files it lists, see docs/INSTALL.md) first."
        }
        # re-install: keep what an earlier install recorded, so uninstall still removes it
        set m [dict replace $pm version $::tg::VERSION updatedAt [clock seconds] dataDirs [dict get $L dataDirs] \
            exe [dict get $L binPath] flavor [dict get $m flavor]]
    }
    set failed ""
    try {
        copyProgram $o $L m
        if {[dict get $L platform] eq "windows"} {
            if {[dict exists $L startMenuLnk]} {
                writeShortcut [dict get $L startMenuLnk] [dict get $L binPath]
                addItem m [dict create type file path [dict get $L startMenuLnk]]
            }
            if {[dict exists $L desktopLnk]} {
                writeShortcut [dict get $L desktopLnk] [dict get $L binPath]
                addItem m [dict create type file path [dict get $L desktopLnk]]
            }
            registerWindows $o $L m
            if {[dict get $L scope] eq "system"} { addItem m [dict create type fwrule backend netsh name [fwRuleName]] }
        } else {
            if {[dict exists $L desktopFile]} {
                set df [dict get $L desktopFile]
                foreach d [missingDirs [file dirname $df]] { addItem m [dict create type dir path $d] }
                file mkdir [file dirname $df]
                ::tg::writeFileAtomic $df [desktopFileText [logical [dict get $L binPath]]] 0644
                addItem m [dict create type file path $df]
            }
            if {[dict get $L scope] eq "system"} {
                if {[dict get $L platform] eq "linux"} {
                    addItem m [dict create type fwrule backend nft name tclguard]
                } else {
                    addItem m [dict create type fwrule backend pf name com.apple/tclguard]
                }
            }
        }
        if {[dict get $o service]} { installService $o $L m }
        if {[dict get $L platform] ne "windows" && [dict get $L scope] eq "user"} {
            if {[lsearch -exact [split [envVar PATH] :] [dict get $L dir]] < 0} {
                note "[dict get $L dir] is not on your PATH; add it to run 'tclguard' from a terminal"
            }
        }
    } on error {err opts} {
        set failed $err
        catch { ::tg::log::debug [dict get $opts -errorinfo] }
    }
    # Record what exists even after a failure, so that uninstall can still clean it up.
    if {[catch {saveManifest $L $m} serr]} {
        if {$failed eq ""} { error "installed, but the install record could not be written ($serr); uninstall will not know about these files" }
        append failed "; the install record could not be written either ($serr)"
    }
    if {$failed ne ""} { error "$failed[expr {[llength [dict get $m items]] ? { (what was already done is recorded; 'tclguard uninstall' removes it)} : {}}]" }
}

proc ::tg::install::fwRuleName {} {
    if {[info exists ::tg::fw::ruleName]} { return $::tg::fw::ruleName }
    return "TclGuard Bans"
}

# ------------------------------------------------------------------ uninstall ----

# Items in the order they are removed: services and registry first, the program last; folders
# (only removed when empty) are returned separately, deepest first.
proc ::tg::install::orderedItems {m} {
    set rank {service 0 autostart 1 fwrule 2 regkey 3 file 4 binary 5 conf 6}
    set tagged {}
    set dirs {}
    foreach it [dict get $m items] {
        if {[dict get $it type] eq "dir"} { lappend dirs [dict get $it path]; continue }
        lappend tagged [list [dict get $rank [dict get $it type]] $it]
    }
    set out {}
    foreach t [lsort -integer -index 0 $tagged] { lappend out [lindex $t 1] }
    list $out [lsort -decreasing -unique $dirs]
}

proc ::tg::install::describeUninstall {o s mpath m} {
    set steps {}
    lassign [orderedItems $m] items dirs
    foreach it $items {
        set t [dict get $it type]
        switch -- $t {
            service  { lappend steps "Stop and remove the service [dict get $it name] ([dict get $it manager])" }
            autostart { lappend steps "Remove the start-at-sign-in entry ([dict get $it mechanism])" }
            fwrule   { lappend steps "Remove the kernel firewall rules TclGuard created ([dict get $it backend] [dict get $it name]), if any" }
            regkey   { lappend steps "Remove the Add/Remove Programs entry [dict get $it key]" }
            file     { lappend steps "Delete [nat [dict get $it path]]" }
            binary   { lappend steps "Delete the program [nat [dict get $it path]] (and its .previous/.old copies from updates)" }
            conf     { if {![dict get $o keepData]} { lappend steps "Delete the configuration [dict get $it path]" } else { lappend steps "Keep the configuration [dict get $it path]" } }
        }
    }
    foreach d $dirs { lappend steps "Remove the folder [nat $d] if it is empty" }
    foreach d [dict get $m dataDirs] {
        if {[dict get $o keepData]} { lappend steps "Keep your settings and data in [nat $d]" } else { lappend steps "Delete TclGuard's settings, bans, logs and certificates in [nat $d] (only files TclGuard created)" }
    }
    lappend steps "Delete the install record $mpath"
    return $steps
}

proc ::tg::install::uninstallPlan {{options {}}} {
    if {[catch {
        set o [normOptions $options]
        lassign [findInstall $o] s mpath m
        set steps [describeUninstall $o $s $mpath $m]
    } err]} { return [list "CANNOT UNINSTALL: $err"] }
    return $steps
}

# One recorded thing is removed. Returns "" (done), "deferred" (locked, left to the helper) or
# an error message.
proc ::tg::install::removeFile {path} {
    if {[set why [unsafePath $path strict]] ne ""} {
        return "not removing '$path': $why"
    }
    if {![file exists $path] && [catch {file type $path}]} { return "" }
    # The running program first: a mounted starpack looks like a FOLDER to Tcl (found on a real Windows runner: "it is a folder, not a file").
    if {[sameFile $path [runningExe]]} {
        if {[isWin]} { return deferred }
        # Unix lets a running program be unlinked, but Tcl's own `file delete` would act on the files INSIDE the mounted starpack
        if {[catch {::tg::nfs::delete $path} err]} { return "could not delete $path: $err" }
        return ""
    }
    if {[file isdirectory $path] && [file type $path] ne "link"} { return "not removing '$path': it is a folder, not a file" }
    if {[catch {file delete -- $path} err]} {
        if {[isWin]} { return deferred }
        return "could not delete $path: $err"
    }
    return ""
}

proc ::tg::install::removeDirIfEmpty {path} {
    # only EMPTY folders are ever removed, so the structural check is enough here
    if {[unsafePath $path basic] ne ""} { return "" }
    if {![file isdirectory $path]} { return "" }
    catch { file delete -- $path }     ;# fails (and so keeps the folder) unless it is empty
    return ""
}

# Settings and state TclGuard itself created in a data folder. Only these names; only inside a folder
# whose name is tclguard/state; subfolders only the known ones.
proc ::tg::install::purgeDataDir {dir} {
    if {[set why [unsafePath $dir strict]] ne ""} { return "not touching data folder '$dir': $why" }
    if {![regexp -nocase {(^|[/\\])(tclguard|state)$} $dir]} {
        return "not deleting '$dir': its name is not 'TclGuard', so it may hold other things (delete it yourself if you want it gone)"
    }
    if {![file isdirectory $dir]} { return "" }
    set err ""
    foreach pat {tclguard.conf* bans.db* trusted.db* tclguard.log* cacert.pem update-state.json*} {
        foreach f [glob -nocomplain -directory $dir -types f $pat] {
            if {[catch {file delete -- $f} e]} { append err "could not delete $f: $e; " }
        }
    }
    foreach sub {acme certs} {
        set p [file join $dir $sub]
        if {[file isdirectory $p] && [file type $p] ne "link"} {
            if {[catch {file delete -force -- $p} e]} { append err "could not delete $p: $e; " }
        }
    }
    set st [file join $dir state]
    if {[file isdirectory $st] && [file type $st] ne "link"} { append err [purgeDataDir $st] }
    removeDirIfEmpty $dir
    return $err
}

proc ::tg::install::removeItem {o it} {
    variable serviceName
    variable daemonLabel
    set t [dict get $it type]
    switch -- $t {
        service {
            set path [dict get $it path]
            if {[dict get $it manager] eq "systemd"} {
                if {[have systemctl] && [elevated]} {
                    sh [list systemctl disable --now $serviceName]
                }
                set e [removeFile $path]
                if {$e ne "" && $e ne "deferred"} { return $e }
                if {[have systemctl] && [elevated]} { sh [list systemctl daemon-reload] }
            } else {
                if {[have launchctl] && [elevated]} { sh [list launchctl bootout system/$daemonLabel] }
                return [removeFile $path]
            }
            return ""
        }
        autostart {
            if {[dict get $it mechanism] eq "task"} {
                if {[isWin]} { return [::tg::autostart::disable] }
                return ""
            }
            return [removeFile [dict get $it path]]
        }
        fwrule {
            if {![elevated]} {
                note "Could not check for leftover kernel firewall rules (needs [expr {[isWin] ? {administrator rights} : {root}}]); run 'tclguard fw remove' as an administrator if any remain"
                return ""
            }
            switch -- [dict get $it backend] {
                netsh {
                    # "No rules match" is fine: the rule only exists once TclGuard banned something
                    # (the rules are numbered when the list of banned addresses is long: "TclGuard Bans", "TclGuard Bans 2", ...)
                    set base [dict get $it name]
                    sh [list netsh advfirewall firewall delete rule name=$base]
                    for {set i 2} {$i <= 500} {incr i} {
                        set nm "$base $i"
                        lassign [sh [list netsh advfirewall firewall show rule name=$nm]] rc out
                        if {$rc != 0 || [string first $nm $out] < 0} break
                        sh [list netsh advfirewall firewall delete rule name=$nm]
                    }
                }
                nft {
                    if {[have nft]} { sh [list nft delete table inet [dict get $it name]] }
                }
                pf {
                    if {[have pfctl]} { sh [list pfctl -a [dict get $it name] -F all] }
                }
            }
            # the iptables/ipset fallback backend (Linux without nft) leaves a set and a rule in the raw table
            if {![isWin] && [have ipset] && [catch {::tg::fw::ipsRemove} e]} { note "Could not remove the iptables rules: $e" }
            return ""
        }
        regkey {
            set key [dict get $it key]
            if {![regexp {^HK(LM|CU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$} $key]} {
                return "not removing the registry key '$key': it is not an uninstall entry"
            }
            lassign [sh [list reg query $key]] rc out
            if {$rc != 0} { return "" }
            lassign [sh [list reg delete $key /f]] rc out
            if {$rc != 0} { return "could not remove $key: [string trim $out]" }
            return ""
        }
        file { return [removeFile [dict get $it path]] }
        binary {
            set path [dict get $it path]
            set res [removeFile $path]
            # leftovers of self-updates sit next to the program: <name>.previous, <name>.old*, <name>.new*
            foreach sfx {.previous .old} { set e [removeFile $path$sfx]; if {$res eq ""} { set res $e } }
            foreach f [siblings $path .old* .new*] {
                set e [removeFile $f]
                if {$res eq "" || $res eq "deferred"} { if {$e ne ""} { set res $e } }
            }
            return $res
        }
        conf {
            if {[dict get $o keepData]} { return "" }
            return [removeFile [dict get $it path]]
        }
    }
    return "unknown item type $t"
}

proc ::tg::install::uninstall {options} {
    variable lastNotes
    set lastNotes {}
    if {[catch {uninstallInner $options} err opts]} {
        catch { ::tg::log::debug "uninstall failed: [dict get $opts -errorinfo]" }
        return $err
    }
    return ""
}

proc ::tg::install::uninstallInner {options} {
    set o [normOptions $options]
    lassign [findInstall $o] s mpath m
    if {[set why [unsafePath $mpath strict]] ne ""} { error "refusing to use the install record '$mpath': $why" }
    set errors {}
    set deferred {}
    lassign [orderedItems $m] items dirs
    foreach it $items {
        set r [removeItem $o $it]
        if {$r eq "deferred"} {
            lappend deferred [dict get $it path]
            foreach f [siblings [dict get $it path] .previous .old* .new*] { lappend deferred $f }
        } elseif {$r ne ""} {
            lappend errors $r
        }
    }
    if {![dict get $o keepData]} {
        foreach d [dict get $m dataDirs] {
            set r [purgeDataDir $d]
            if {$r ne ""} { lappend errors $r }
        }
    }
    if {[llength $errors]} {
        error "uninstall is incomplete: [join $errors {; }]. The install record was kept, so you can run uninstall again."
    }
    if {[llength $deferred]} {
        # Windows: the program is running (this very process). A detached helper removes it after exit.
        set files [concat [lsort -unique $deferred] [list $mpath]]
        set fdirs [lsort -decreasing -unique [concat $dirs [lmap f $files {file dirname $f}]]]
        set script [deleteHelperScript [pid] [lmap f $files {nat $f}] [lmap d $fdirs {nat $d}]]
        if {[set e [spawn [psArgv $script]]] ne ""} {
            error "the program is in use and the cleanup helper could not be started ($e). Delete [nat [lindex $deferred 0]] after closing TclGuard."
        }
        note "TclGuard is still running, so its program file is removed a few seconds after this window closes."
        return
    }
    catch { file delete -- $mpath }
    removeDirIfEmpty [file dirname $mpath]
    foreach d $dirs { removeDirIfEmpty $d }
}

# ------------------------------------------------------------------ status ----

# -> dict: installed (0/1), scope, binary, version, installedAt, record, items, running (1 when this
# process is the installed copy), current (version of this program), others (other records found).
proc ::tg::install::status {} {
    set res [dict create installed 0 current $::tg::VERSION others {}]
    if {[catch {
        set found {}
        foreach {s p} [manifestCandidates] {
            if {![file isfile $p]} continue
            if {[catch {readManifest $p} m]} { lappend found [dict create record $p error $m]; continue }
            lappend found [dict create record $p scope [dict get $m scope] binary [dict get $m exe] version [dict get $m version] \
                installedAt [dict get $m installedAt] items [llength [dict get $m items]] platform [dict get $m platform] \
                present [file exists [dict get $m exe]]]
        }
    } err]} { return [dict set res error $err] }
    if {![llength $found]} { return $res }
    set first [lindex $found 0]
    set res [dict merge $res $first [dict create installed [expr {![dict exists $first error]}]]]
    dict set res others [lrange $found 1 end]
    if {[dict exists $res binary]} {
        dict set res running [sameFile [dict get $res binary] [runningExe]]
    }
    return $res
}

proc ::tg::install::statusText {} {
    set s [status]
    if {[dict exists $s error] && ![dict get $s installed]} { return "TclGuard install status could not be read: [dict get $s error]\n" }
    if {![dict get $s installed]} { return "TclGuard is not installed (this is version [dict get $s current], running without installation).\n" }
    set out "TclGuard [dict get $s version] is installed ([dict get $s scope])\n"
    append out "  program:  [nat [dict get $s binary]][expr {[dict get $s present] ? {} : {   (MISSING)}}]\n"
    append out "  record:   [dict get $s record]   ([dict get $s items] items)\n"
    append out "  this program is version [dict get $s current][expr {[dict get $s running] ? {, and it is the installed copy} : {}}]\n"
    foreach o [dict get $s others] {
        append out "  also found: [dict get $o record][expr {[dict exists $o scope] ? " ([dict get $o scope])" : ""}]\n"
    }
    return $out
}
