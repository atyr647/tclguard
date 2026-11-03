# main.tcl -- TclGuard entry point (starkit/starpack and plain `tclsh main.tcl`)
#
#   tclguard                       run: GUI when a display exists, otherwise headless
#   tclguard ctl <command...>      talk to a running instance (status, bans, ban, unban ...)
#   tclguard fw install|remove|status|print
#   tclguard check                 validate the config file
#   tclguard init [--preset NAME]  write a starter config
#   tclguard presets               list built-in presets
#   tclguard install [options]     copy this program into place, add menu entries, optional autostart
#   tclguard uninstall [options]   remove exactly what install added
#   tclguard update check|apply|rollback|status|keygen    signed self-update
#   tclguard selftest              attack ourselves and prove the defences work
#   tclguard version | help

if {![catch {package require starkit}]} {
    starkit::startup
}
set ::tg_root [file dirname [file normalize [info script]]]
if {[info exists ::starkit::topdir]} { set ::tg_root $::starkit::topdir }
lappend auto_path [file join $::tg_root lib]
package require Tcl 8.6
package require tclguard

set ::tg::quit 0
# A Tk-enabled kit creates the root window at startup; hide it so command-line
# use never flashes an empty window (the GUI shows it again when it starts).
catch {wm withdraw .}

proc usage {} {
    puts {TclGuard - DDoS protection for game servers and home-hosted websites

Usage:
  tclguard [--config FILE] [--headless | --gui] [--no-firewall] [--verbose]
        Run the guard. Opens the control window when a display is available.
  tclguard ctl <command> [args]     Control a running instance:
        status | bans | top | listeners | log [n]
        ban <ip|cidr> [seconds|0=forever] [reason...]    unban <ip>    unbanall
        allow <ip|cidr>    disallow <ip|cidr>    block <ip|cidr>    unblock <ip|cidr>
        level <0-3|auto>   reload   fw status|install|uninstall   stop
  tclguard fw install|remove|status|print     Manage kernel firewall rules (needs root/admin)
  tclguard check [--config FILE]              Validate the configuration
  tclguard init [--preset NAME] [--force]     Create a starter configuration
  tclguard presets                            List game/website presets
  tclguard autostart on|off|status            Start TclGuard when you sign in
  tclguard install [--system|--user] [--service] [--no-shortcut] [--desktop] [--dir PATH] [--force] [--dry-run]
        Install this single-file program: copy it into place, add a Start Menu / application menu
        entry, register it with Windows' Apps list, optionally start it at boot (--service).
        --system needs administrator/root, --user does not (default: system if elevated).
  tclguard install status                     Is it installed, where, which version
  tclguard uninstall [--system|--user] [--keep-data] [--dry-run]
        Remove exactly what 'install' recorded (and, unless --keep-data, TclGuard's own settings).
  tclguard update check [--url URL]           Look for a newer signed release
  tclguard update apply [--url URL]           Download, verify (signature, checksum, test run) and install it
  tclguard update rollback                    Go back to the previous version
  tclguard update status                      Current version, release key, last check
  tclguard update keygen --out FILE           (maintainers) create a release-signing key
  tclguard eval <script.tcl> [args]           Run a Tcl script with TclGuard loaded (testing)
  tclguard selftest                           Run a live attack simulation against itself
  tclguard version

Config file: platform default is shown by 'tclguard check'.}
}

proc die {msg {code 1}} {
    puts stderr "tclguard: $msg"
    exit $code
}

# ---- tiny option parser -------------------------------------------------------
proc takeOpt {argvVar name {hasValue 0}} {
    upvar 1 $argvVar a
    set i [lsearch -exact $a $name]
    if {$i < 0} { return {} }
    if {$hasValue} {
        if {$i + 1 >= [llength $a]} { die "option $name needs a value" }
        set v [lindex $a [expr {$i + 1}]]
        set a [lreplace $a $i [expr {$i + 1}]]
        return [list $v]
    }
    set a [lreplace $a $i $i]
    return [list 1]
}

# ---- output formatting for `ctl` --------------------------------------------------

proc pretty {v {indent ""}} {
    set out ""
    if {[catch {dict size $v}]} { return "$indent$v\n" }
    dict for {k x} $v {
        if {[catch {dict size $x}] == 0 && [llength $x] > 2 && [llength $x] % 2 == 0} {
            append out "$indent$k:\n[pretty $x "$indent  "]"
        } else {
            append out "$indent[format %-16s $k] $x\n"
        }
    }
    return $out
}

# Left-aligned text table.
proc table {headers rows} {
    set w [lmap h $headers {string length $h}]
    foreach r $rows {
        set i 0
        foreach c $r { if {[string length $c] > [lindex $w $i]} { lset w $i [string length $c] }; incr i }
    }
    set fmt ""
    set i 0
    foreach x $w { append fmt "%-${x}s  "; incr i }
    set out "[string trimright [format $fmt {*}$headers]]\n"
    foreach r $rows { append out "[string trimright [format $fmt {*}$r]]\n" }
    return $out
}

proc renderData {verb args data} {
    switch -- $verb {
        bans {
            if {![llength $data]} { return "no active bans\n" }
            set rows {}
            set now [clock milliseconds]
            foreach b $data {
                set u [dict get $b until]
                lappend rows [list [dict get $b key] [expr {$u == 0 ? "forever" : [::tg::fmtDuration [expr {($u - $now) / 1000}]]}] [dict get $b source] [dict get $b reason]]
            }
            return [table {ADDRESS LEFT SOURCE REASON} $rows]
        }
        top {
            if {![llength $data]} { return "no traffic recorded yet\n" }
            return [table {ADDRESS ALLOWED BLOCKED DATA} [lmap r $data {list [lindex $r 0] [lindex $r 1] [lindex $r 2] [::tg::fmtBytes [lindex $r 3]]}]]
        }
        listeners {
            return [table {NAME TYPE PORT FORWARDS-TO STATE CONNS} [lmap l $data {
                list [dict get $l name] [dict get $l type] [dict get $l port] [dict get $l backend] \
                    [expr {![dict get $l enabled] ? "disabled" : ([dict get $l running] ? "protecting" : "NOT RUNNING")}] [dict get $l conns]
            }]]
        }
        log {
            set out ""
            foreach e $data { lassign $e ms lvl text; append out "[::tg::fmtTime $ms %H:%M:%S] [format %-5s [string toupper $lvl]] $text\n" }
            return $out
        }
        status {
            set s $data
            set lv [dict get $s level]
            set fw [dict get $s firewall]
            set r [dict get $s rates]
            set c [dict get $s counters]
            set out "TclGuard [dict get $s version]   [expr {[dict get $s running] ? {running} : {stopped}}]   up [::tg::fmtDuration [dict get $s uptime]]\n\n"
            append out [format "%-16s %s%s\n" "Threat level" [dict get $lv name] [expr {[dict get $lv manual] ? { (pinned manually)} : {}}]]
            append out [format "%-16s %s TCP\n" "Connections" [dict get $s connections]]
            append out [format "%-16s %s\n" "UDP sessions" [dict get $s udpSessions]]
            append out [format "%-16s allowed %s/s, blocked %s/s   (since start: %s allowed, %s blocked)\n" "Traffic" \
                [::tg::fmtRate [dict get $r ok]] [::tg::fmtRate [dict get $r blocked]] [::tg::fmtRate [dict get $c ok]] [::tg::fmtRate [dict get $c blocked]]]
            append out [format "%-16s %s active\n" "Bans" [dict get $s bans]]
            append out [format "%-16s %s%s\n" "Kernel firewall" [dict get $fw backend] \
                [expr {[dict get $fw installed] ? " (installed[expr {[dict get $fw hardened] ? {, hardening on} : {}}], [dict get $c kernelDrop] packets dropped)" : " (off)"}]]
            append out "\nListeners:\n[renderData listeners {} [dict get $s listeners]]"
            return $out
        }
    }
    return [pretty $data]
}

proc loadConfigOrDie {argvVar} {
    upvar 1 $argvVar a
    set path [lindex [takeOpt a --config 1] 0]
    if {$path eq ""} { set path [::tg::cfg::defaultPath] }
    if {[catch {::tg::cfg::load $path} err]} { die "$path: $err" }
    return $path
}

# ---- subcommands -------------------------------------------------------------

proc cmdCheck {argv} {
    set path [loadConfigOrDie argv]
    puts "config file: $path [expr {[file exists $path] ? {} : {(does not exist yet - defaults in use)}}]"
    lassign [::tg::cfg::validate $::tg::cfg::current] errs warns
    foreach w $warns { puts "warning: $w" }
    foreach e $errs { puts "ERROR:   $e" }
    set n [dict size [::tg::cfg::listeners]]
    puts "$n listener(s) configured"
    dict for {name L} [::tg::cfg::listeners] {
        puts [format "  %-28s %-4s %s -> %s %s" $name [dict get $L type] [::tg::joinHostPort [dict get $L bind] [dict get $L port]] \
            [::tg::joinHostPort [dict get $L backendHost] [dict get $L backendPort]] \
            [expr {[::tg::bool [dict get $L enabled]] ? {} : {(disabled)}}]]
    }
    if {[llength $errs]} { exit 2 }
    puts "configuration OK"
}

proc cmdInit {argv} {
    set path [loadConfigOrDie argv]
    set preset [lindex [takeOpt argv --preset 1] 0]
    set force [takeOpt argv --force]
    if {[file exists $path] && $force eq ""} { die "$path already exists (use --force to overwrite)" }
    set c [::tg::cfg::new]
    dict set c general controlToken [::tg::randomHex 16]
    if {$preset ne ""} {
        if {[catch {::tg::cfg::presetListeners $preset} L]} { die $L }
        dict set c listeners $L
    }
    lassign [::tg::cfg::validate $c] errs warns
    ::tg::cfg::save $path $c
    puts "wrote $path"
    foreach w $warns { puts "warning: $w" }
    puts "Edit it (or use the GUI), then run: tclguard"
}

proc cmdPresets {} {
    foreach p $::tg::cfg::presetOrder {
        puts [format "  %-20s %s" $p [dict get $::tg::cfg::presets($p) description]]
    }
}

proc cmdCtl {argv} {
    set path [loadConfigOrDie argv]
    if {![llength $argv]} { die "usage: tclguard ctl <command>   (see 'tclguard help')" }
    set host [::tg::cfg::general controlHost]
    set port [::tg::cfg::general controlPort]
    set tok  [::tg::cfg::general controlToken]
    if {$tok eq ""} { die "no controlToken in $path - has TclGuard been started once?" }
    lassign [::tg::control::request $host $port $tok {*}$argv] ok kind text
    if {!$ok} { die $text }
    if {$kind eq "data"} {
        if {[lindex $argv 0] eq "fw"} { puts -nonewline [pretty $text] } else { puts -nonewline [renderData [lindex $argv 0] [lrange $argv 1 end] $text] }
    } else {
        puts $text
    }
}

proc cmdFw {argv} {
    set path [loadConfigOrDie argv]
    set verb [lindex $argv 0]
    ::tg::log::setLevel warn
    switch -- $verb {
        print {
            ::tg::fw::init
            if {$::tg::fw::backend eq "none"} { ::tg::fw::init nft }
            puts [::tg::fw::preview]
        }
        status {
            ::tg::fw::init
            puts -nonewline [pretty [::tg::fw::status]]
            set rc [catch {exec nft list table inet tclguard} out]
            if {!$rc} { puts "\nkernel table 'inet tclguard' is installed" } else { puts "\nkernel table 'inet tclguard' is not installed" }
        }
        install {
            ::tg::ban::configure
            ::tg::fw::init
            if {![::tg::fw::enabled]} { die [dict get [::tg::fw::status] error] }
            if {![::tg::fw::sync]} { die [dict get [::tg::fw::status] error] }
            puts "kernel rules installed ([::tg::fw::status])"
        }
        remove {
            ::tg::fw::init
            ::tg::fw::uninstall
            puts "kernel rules removed"
        }
        default { die "usage: tclguard fw install|remove|status|print" }
    }
}

proc cmdAutostart {argv} {
    switch -- [lindex $argv 0] {
        on     { set e [::tg::autostart::enable]; if {$e ne ""} { die $e }; puts "TclGuard will start when you sign in" }
        off    { set e [::tg::autostart::disable]; if {$e ne ""} { die $e }; puts "autostart removed" }
        status { puts [expr {[::tg::autostart::status] ? "on" : "off"}] }
        default { die "usage: tclguard autostart on|off|status" }
    }
}

# ---- install / uninstall -----------------------------------------------------------------

# --interactive: dialogs instead of a terminal (the Windows build has no console window).
proc uiAvailable {} {
    if {[info commands tk_messageBox] ne ""} { return 1 }
    expr {![catch {package require Tk}] && [info commands tk_messageBox] ne ""}
}
proc uiAsk {title text} {
    if {![uiAvailable]} { return 1 }
    expr {[tk_messageBox -icon question -type yesno -title $title -message $text] eq "yes"}
}
proc uiShow {title text {icon info}} {
    if {[uiAvailable]} { tk_messageBox -icon $icon -type ok -title $title -message $text } else { puts $text }
}
proc outcome {interactive title text {code 0}} {
    if {$interactive} { uiShow $title $text [expr {$code ? "error" : "info"}] } elseif {$code} { die $text } else { puts $text }
    if {$interactive && $code} { exit 1 }
}

proc cmdInstall {argv} {
    if {[lindex $argv 0] eq "status"} { puts -nonewline [::tg::install::statusText]; return }
    set o {}
    foreach {flag key val} {--system scope system  --user scope user  --service service 1  --no-shortcut startMenu 0
                            --desktop desktop 1  --force force 1} {
        if {[takeOpt argv $flag] ne ""} { dict set o $key $val }
    }
    set dir [lindex [takeOpt argv --dir 1] 0]
    if {$dir ne ""} { dict set o dir $dir }
    set dry [takeOpt argv --dry-run]
    set ui [expr {[takeOpt argv --interactive] ne ""}]
    if {[llength $argv]} { die "unknown argument '[lindex $argv 0]' (see 'tclguard help')" }
    set why [::tg::install::planError $o]
    if {$why ne ""} { outcome $ui "TclGuard setup" "Cannot install: $why" 1 }
    set steps [::tg::install::plan $o]
    set text "TclGuard will:\n  - [join $steps "\n  - "]"
    if {$dry ne ""} { puts "$text\n(dry run: nothing was changed)"; return }
    if {$ui && ![uiAsk "Install TclGuard" "$text\n\nContinue?"]} { return }
    if {!$ui} { puts $text }
    set err [::tg::install::run $o]
    if {$err ne ""} { outcome $ui "TclGuard setup" "Installation failed: $err" 1 }
    outcome $ui "TclGuard setup" "TclGuard is installed.[expr {[llength [::tg::install::notes]] ? "\n\n[join [::tg::install::notes] \n]" : ""}]"
}

proc cmdUninstall {argv} {
    set o {}
    foreach {flag key val} {--system scope system  --user scope user  --keep-data keepData 1} {
        if {[takeOpt argv $flag] ne ""} { dict set o $key $val }
    }
    set dry [takeOpt argv --dry-run]
    set ui [expr {[takeOpt argv --interactive] ne ""}]
    if {[llength $argv]} { die "unknown argument '[lindex $argv 0]' (see 'tclguard help')" }
    if {$ui && ![dict exists $o keepData]} {
        # the dialog asks about the data separately: the safe answer is the default
        dict set o keepData [uiAsk "Uninstall TclGuard" "Keep your TclGuard settings, ban list and certificates?\n\nChoose Yes to keep them (recommended if you may reinstall), No to delete them."]
    }
    set steps [::tg::install::uninstallPlan $o]
    if {[string match "CANNOT UNINSTALL*" [lindex $steps 0]]} { outcome $ui "Uninstall TclGuard" [lindex $steps 0] 1 }
    set text "TclGuard will:\n  - [join $steps "\n  - "]"
    if {$dry ne ""} { puts "$text\n(dry run: nothing was changed)"; return }
    if {$ui && ![uiAsk "Uninstall TclGuard" "$text\n\nContinue?"]} { return }
    if {!$ui} { puts $text }
    set err [::tg::install::uninstall $o]
    if {$err ne ""} { outcome $ui "Uninstall TclGuard" "Uninstall failed: $err" 1 }
    outcome $ui "Uninstall TclGuard" "TclGuard was removed.[expr {[llength [::tg::install::notes]] ? "\n\n[join [::tg::install::notes] \n]" : ""}]"
}

# ---- signed updates ----------------------------------------------------------------------

proc updateProgress {phase done total} {
    switch -- $phase {
        check    { puts "checking the release manifest and its signature ..." }
        download {
            if {$total > 0} {
                set pct [expr {$done * 100 / $total}]
                if {$pct / 10 != ($::lastPct / 10) || $done == 0} { puts "downloading ... $pct% ([::tg::fmtBytes $done] of [::tg::fmtBytes $total])" }
                set ::lastPct $pct
            }
        }
        hash     { if {$done == $total || ($done / 8388608) != (($done - 1048576) / 8388608)} { puts "verifying checksum ... [expr {$total > 0 ? $done * 100 / $total : 0}]%" } }
        verify   { puts "testing the new program ..." }
        install  { puts "installing ..." }
    }
    flush stdout
}

proc cmdUpdate {argv} {
    set sub [lindex $argv 0]
    set argv [lrange $argv 1 end]
    if {$sub eq "keygen"} {
        set out [lindex [takeOpt argv --out 1] 0]
        set r [::tg::update::keygen $out]
        if {![dict get $r ok]} { die [dict get $r error] }
        puts "Private signing key written to [dict get $r path] (owner-only permissions)."
        puts "KEEP IT SECRET AND OFFLINE: anyone holding it can publish updates that every TclGuard will trust."
        puts "Store it as the GitHub secret RELEASE_SIGNING_KEY (the file's text) and back it up somewhere safe."
        puts ""
        puts "Public key (paste this line into tclguard.vfs/lib/tclguard/vendor/update-key.pub, replacing the UNSET line):"
        puts "  [dict get $r publicKey]"
        puts "Fingerprint (publish it, e.g. in the README, so users can compare): [dict get $r fingerprint]"
        return
    }
    set path [loadConfigOrDie argv]
    set opts {}
    set url [lindex [takeOpt argv --url 1] 0]
    if {$url ne ""} { dict set opts url $url }
    set target [lindex [takeOpt argv --target 1] 0]
    if {$target ne ""} { dict set opts target $target }
    if {[llength $argv]} { die "unknown argument '[lindex $argv 0]' (see 'tclguard help')" }
    switch -- $sub {
        status { puts -nonewline [::tg::update::statusText $opts] }
        check {
            set r [::tg::update::check $opts]
            if {![dict get $r ok]} { die "update check failed: [dict get $r error]" }
            set v [expr {[dict get $r verified] ? "signature verified" : "signature NOT verified: this build has no release key"}]
            switch -- [dict get $r status] {
                uptodate { puts "TclGuard [dict get $r current] is up to date (newest release [dict get $r latest], $v)." }
                ahead    { puts "This is TclGuard [dict get $r current]; the newest published release is [dict get $r latest] (older)." }
                nofile   { puts "Release [dict get $r latest] exists ($v) but has no download for [dict get $r platform]: [dict get $r error]" }
                available {
                    puts "TclGuard [dict get $r latest] is available (you have [dict get $r current]; $v)."
                    if {[dict get $r notes] ne ""} { puts "\n[dict get $r notes]\n" }
                    if {[dict get $r needsManual]} {
                        puts "Your version is too old to update itself: download the new release from the project page."
                    } elseif {[dict get $r verified]} {
                        puts "Install it with: tclguard update apply"
                    } else {
                        puts "This build cannot verify updates, so 'update apply' will refuse."
                    }
                }
            }
        }
        apply {
            set ::lastPct -100
            dict set opts progress updateProgress
            set r [::tg::update::apply $opts]
            if {![dict get $r ok]} { die "update failed: [dict get $r error]" }
            if {[dict get $r status] eq "uptodate"} { puts "TclGuard [dict get $r old] is already the newest release."; return }
            puts "Updated TclGuard [dict get $r old] -> [dict get $r new]. The old program was kept as [dict get $r backup] ('tclguard update rollback' restores it)."
            puts "Restart TclGuard to run the new version."
        }
        rollback {
            set r [::tg::update::rollback $opts]
            if {![dict get $r ok]} { die "rollback failed: [dict get $r error]" }
            puts "Restored the previous program (version [dict get $r new]). Restart TclGuard to use it."
        }
        default { die "usage: tclguard update check|apply|rollback|status|keygen" }
    }
}

# Developer/CI hook: run a script with the application's packages available, e.g. to run the
# test suite with the exact Tcl and Tk that ship inside the starpack.
proc cmdEval {argv} {
    if {![llength $argv]} { die "usage: tclguard eval <script.tcl> [args]" }
    set script [lindex $argv 0]
    if {![file exists $script]} { die "no such script: $script" }
    set ::argv [lrange $argv 1 end]
    set ::argv0 $script
    set ::argc [llength $::argv]
    # global scope, so the script behaves exactly as under tclsh
    uplevel #0 [list source $script]
}

proc haveDisplay {} {
    global tcl_platform env
    if {$tcl_platform(platform) eq "windows"} { return 1 }
    if {$tcl_platform(os) eq "Darwin"} { return 1 }
    expr {([info exists env(DISPLAY)] && $env(DISPLAY) ne "") || ([info exists env(WAYLAND_DISPLAY)] && $env(WAYLAND_DISPLAY) ne "")}
}

proc cmdRun {argv} {
    set path [loadConfigOrDie argv]
    catch {::tg::update::cleanup}      ;# leftovers of a self-update (Windows keeps the renamed old .exe)
    set headless [takeOpt argv --headless]
    set gui [takeOpt argv --gui]
    set nofw [takeOpt argv --no-firewall]
    set verbose [takeOpt argv --verbose]
    if {[llength $argv]} { die "unknown argument '[lindex $argv 0]' (see 'tclguard help')" }
    if {$nofw ne ""} { dict set ::tg::cfg::current general firewall none }
    if {$verbose ne ""} { dict set ::tg::cfg::current general logLevel debug }
    lassign [::tg::cfg::validate $::tg::cfg::current] errs warns
    foreach w $warns { puts stderr "warning: $w" }
    if {[llength $errs]} {
        foreach e $errs { puts stderr "config error: $e" }
        die "fix the configuration ($path) and try again" 2
    }
    set useGui [expr {$headless eq "" && ($gui ne "" || [haveDisplay])}]
    if {$useGui && [catch {package require Tk} tkerr]} {
        if {$gui ne ""} { die "Tk is not available: $tkerr" }
        set useGui 0
    }
    set ::tg::log::stderr [expr {!$useGui}]
    if {![file exists $path]} {
        ::tg::cfg::ensureToken
        catch {::tg::cfg::save $path}
    }
    if {$useGui} {
        ::tg::gui::run
    } else {
        ::tg::engine::start
        if {![catch {package require Tclx}]} {
            catch {signal trap {SIGTERM SIGINT SIGHUP} {set ::tg::quit 1}}
        }
        vwait ::tg::quit
        ::tg::engine::stop
    }
}

# ---- dispatch -------------------------------------------------------------------

set cmd [lindex $argv 0]
# An uncaught error must reach stderr and end the process: in a Tk build on Windows it would
# otherwise become a modal dialog nobody can dismiss.
if {[catch {
switch -glob -- $cmd {
    help - -h - --help { usage }
    version - --version { puts "TclGuard $::tg::VERSION (Tcl [info patchlevel])" }
    check    { cmdCheck [lrange $argv 1 end] }
    init     { cmdInit [lrange $argv 1 end] }
    presets  { cmdPresets }
    ctl      { cmdCtl [lrange $argv 1 end] }
    fw       { cmdFw [lrange $argv 1 end] }
    selftest { exit [::tg::selftest::run [lrange $argv 1 end]] }
    autostart { cmdAutostart [lrange $argv 1 end] }
    install   { cmdInstall [lrange $argv 1 end] }
    uninstall { cmdUninstall [lrange $argv 1 end] }
    update    { cmdUpdate [lrange $argv 1 end] }
    eval     { cmdEval [lrange $argv 1 end] }
    default  { cmdRun $argv }
}

} err opts]} {
    puts stderr "tclguard: $err"
    puts stderr [dict get $opts -errorinfo]
    exit 1
}

# Tk kits stay in the event loop when the script ends, so always leave explicitly.
exit 0
