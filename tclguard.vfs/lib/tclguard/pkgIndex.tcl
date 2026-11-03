# Package index for TclGuard. Modules are sourced in dependency order.
package ifneeded tclguard 1.0.0 [list apply {{dir} {
    foreach f {util config bans firewall limiter tcpproxy httpproxy udprelay monitor logwatch control engine guikit gui selftest} {
        if {[file exists [file join $dir $f.tcl]]} {
            uplevel #0 [list source -encoding utf-8 [file join $dir $f.tcl]]
        }
    }
    package provide tclguard 1.0.0
}} $dir]
