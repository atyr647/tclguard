# Started BY the elevation test, as the elevated copy would be: records who it is and exactly what arguments it received.
#   <program> eval elev_marker.tcl <marker-file> <the arguments the real elevated copy would get>
set out [lindex $::argv 0]
catch {package require tclguard}
set priv "?"
catch {set priv [::tg::fw::isPrivileged]}
set uid ""
catch {set uid [exec id -u]}
# (diagnostics: the process's own command line as Windows recorded it)
set cmdline ""
if {$::tcl_platform(platform) eq "windows"} {
    catch {set cmdline [exec powershell -NoProfile -NonInteractive -Command "(Get-CimInstance Win32_Process -Filter 'ProcessId=[pid]').CommandLine"]}
}
set fh [open $out.tmp w]
fconfigure $fh -encoding utf-8
puts $fh [list privileged $priv uid $uid argv [lrange $::argv 1 end] cmdline [string trim $cmdline]]
close $fh
file rename -force $out.tmp $out
