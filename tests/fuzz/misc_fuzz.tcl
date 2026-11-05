# misc_fuzz.tcl -- in-process fuzzing of the parsers that are not the HTTP request parser: addresses and ranges, X-Forwarded-For, request
# paths, JSON, configuration text, release manifests, the log-watcher extractor and the ban table.
#   tclsh8.6 tests/fuzz/misc_fuzz.tcl ?seconds? ?seed?        exit status 1 on any finding
# A finding is: a command that raises when it is documented not to, a call that takes unreasonably long, or a process that stops
# answering (the whole run is bounded by an external timeout in CI).
set root [file normalize [file join [file dirname [info script]] .. ..]]
lappend auto_path [file join $root tclguard.vfs lib]
package require tclguard
set ::tg::log::stderr 0
set seconds [expr {$argc > 0 ? [lindex $argv 0] : 20}]
set seed    [expr {$argc > 1 ? [lindex $argv 1] : 1}]
expr {srand($seed)}

proc rnd {n} { expr {int(rand() * $n)} }
proc pick {l} { lindex $l [rnd [llength $l]] }

set alphabets [list {0123456789.} {0123456789abcdefABCDEF:.} {0123456789abcdef:./%} "0123456789./ \t,;" "abcé中‮\ud83d\x00\x01\x7f\xff\\\"'{}\[\]\$;" {/.%;\\aA0..}]
proc randStr {} {
    global alphabets
    set a [pick $alphabets]
    set n [rnd 60]
    set s ""
    for {set i 0} {$i < $n} {incr i} { append s [string index $a [rnd [string length $a]]] }
    return $s
}
set seedsIp {127.0.0.1 10.0.0.0/8 ::1 2001:db8::/32 ::ffff:1.2.3.4 1.2.3.4/33 01.2.3.4 1.2.3.4/08 fe80::1%eth0 0.0.0.0/0 ::/0 1:2:3:4:5:6:7:8 1::2::3 [::1]:80 1.2.3 256.1.1.1 1.2.3.4. 0x7f.1 ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255}
proc mutate {s} {
    set n [rnd 4]
    for {set i 0} {$i <= $n} {incr i} {
        set L [string length $s]
        switch [rnd 5] {
            0 { if {$L} { set p [rnd $L]; set s [string replace $s $p $p] } }
            1 { set p [rnd [expr {$L + 1}]]; set s [string range $s 0 [expr {$p - 1}]][string index "0123456789abcdef:./%- \x00" [rnd 24]][string range $s $p end] }
            2 { if {$L} { set p [rnd $L]; set s [string replace $s $p $p [string index "0:./%f9 -" [rnd 9]]] } }
            3 { set s $s$s }
            4 { set s [string range $s 0 [rnd [expr {$L + 1}]]] }
        }
        if {[string length $s] > 4000} { set s [string range $s 0 3999] }
    }
    return $s
}
proc ipInput {} { global seedsIp; if {[rnd 3] == 0} { randStr } else { mutate [pick $seedsIp] } }

set findings {}
set calls 0
proc finding {what input detail} {
    global findings
    if {[llength $findings] < 50} { lappend findings [list $what $input $detail]; puts "FINDING $what: [string range [string map {\n \\n \x00 \\0} $input] 0 120] -> $detail" }
}
# run a command that must not raise, within a time budget (ms)
proc probe {what budget script input} {
    global calls
    incr calls
    set t0 [clock microseconds]
    set rc [catch {uplevel #0 $script} r]
    set ms [expr {([clock microseconds] - $t0) / 1000.0}]
    if {$rc} { finding "$what raised" $input $r }
    if {$ms > $budget} { finding "$what slow" $input "[format %.1f $ms] ms" }
    return [expr {$rc ? "" : $r}]
}

# ---- the targets -------------------------------------------------------------------------------------------------------------------------

proc t_ip {} {
    set s [ipInput]
    probe ip::parse 20 [list ::tg::ip::parse $s] $s
    probe ip::isValid 20 [list ::tg::ip::isValid $s] $s
    probe ip::isTarget 20 [list ::tg::ip::isTarget $s] $s
    probe ip::normCidr 20 [list ::tg::ip::normCidr $s] $s
    probe ip::isPrivate 20 [list ::tg::ip::isPrivate $s] $s
    if {[::tg::ip::isValid $s]} {
        probe ip::norm 20 [list ::tg::ip::norm $s] $s
        probe ip::key 20 [list ::tg::ip::key $s] $s
    }
    probe ip::parseList 50 [list ::tg::ip::parseList $s] $s
    # a value that parses must round trip: the canonical form parses to the same thing
    if {[::tg::ip::isValid $s]} {
        set n [::tg::ip::norm $s]
        if {![::tg::ip::isValid $n] || [::tg::ip::norm $n] ne $n} { finding "ip::norm not idempotent" $s $n }
    }
}
proc t_xff {} {
    set parts {}
    for {set i [rnd 12]} {$i >= 0} {incr i -1} { lappend parts [ipInput] }
    set v [join $parts [pick {, ,\  ,\t {, ,}}]]
    ::tg::ip::setLoad fz:t {127.0.0.1 10.0.0.0/8}
    set r [probe http::pickClientIp 20 [list ::tg::http::pickClientIp $v fz:t] $v]
    if {$r ne "" && ![::tg::ip::isValid $r]} { finding "pickClientIp returned a non-address" $v $r }
    # independent oracle: when the last non-empty entry is a plain valid address that is not one of our proxies, that entry IS the client
    set last ""
    foreach it [split $v ,] { set it [string trim $it " \t"]; if {$it ne ""} { set last $it } }
    if {$last ne "" && [string length $last] <= 45 && [::tg::ip::isValid $last] && ![::tg::ip::setMatch fz:t $last] && $r ne $last} { finding "pickClientIp ignored the nearest untrusted entry" $v "$r instead of $last" }
}
proc t_path {} {
    set s [pick [list /a/b /%41%2e%2e/ //a///b/../../c "/a;b/../c" "/a\\b" /./. /%252e%252e/x [string repeat %41 [rnd 300]] [string repeat a/./ [rnd 400]] ""]]
    if {[rnd 2]} { set s [mutate $s] }
    set r [probe http::normPath 30 [list ::tg::http::normPath $s] $s]
    if {$r ne "" && ([string index $r 0] ne "/" || [string match */../* $r/] )} { finding "normPath result not normalised" $s $r }
}
proc t_json {} {
    set seeds [list {{"a":1,"b":[true,false,null,"xé\n"]}} {[1,2,3]} {"str"} {{"a":{"b":{"c":[]}}}} 12.5e3 {{"k":"😀"}}]
    set s [mutate [pick $seeds]]
    if {[rnd 20] == 0} { set s [string repeat \[ [expr {100 + [rnd 5000]}]] }
    set t0 [clock milliseconds]
    catch {::tg::json::parse $s}     ;# may raise on bad input; must come back
    if {[clock milliseconds] - $t0 > 300} { finding "json::parse slow" $s "[expr {[clock milliseconds] - $t0}] ms" }
    incr ::calls
}
proc t_config {} {
    set base "general {\n  strikeThreshold 10\n  banSteps {60 600}\n}\nlisteners {\n  web {\n    type http\n    port 8080\n    backendPort 9000\n    trustedProxies {10.0.0.0/8}\n  }\n}\n"
    set s [mutate $base]
    if {[catch {::tg::cfg::parseText $s} cfg]} { incr ::calls; return }
    set rc [catch {::tg::cfg::validate $cfg} r]
    incr ::calls
    if {$rc} { finding "cfg::validate raised on text that parsed" $s $r }
}
proc t_manifest {} {
    set seeds [list {{"version":"1.2.3","files":{}}} {}]
    set s [mutate [pick $seeds]]
    catch {::tg::update::parseManifest $s}
    incr ::calls
    probe update::parseVersion 20 [list catch [list ::tg::update::parseVersion [ipInput]]] x
    probe update::compareVersions 20 [list catch [list ::tg::update::compareVersions [ipInput] [ipInput]]] x
}
proc t_extract {} {
    set line [mutate "1.2.3.4 - - \[x\] \"GET /login HTTP/1.1\" 401 12"]
    probe logw::extract 20 [list ::tg::logw::extract {^(\S+) } $line] $line
    probe logw::extract-bad-pattern 20 [list ::tg::logw::extract "\[" $line] $line
}
proc t_ban {} {
    set s [ipInput]
    if {![::tg::ip::isTarget $s]} return
    ::tg::ban::configure
    probe ban::add 50 [list ::tg::ban::add $s fuzz "" auto] $s
    probe ban::check 20 [list ::tg::ban::check $s] $s
    probe ban::strike 20 [list ::tg::ban::strike $s 1 fuzz] $s
    if {[rnd 20] == 0} { ::tg::ban::clearAll; array unset ::tg::ban::score }
}

set targets {t_ip t_ip t_ip t_xff t_xff t_path t_path t_json t_config t_manifest t_extract t_ban}
set end [expr {[clock seconds] + $seconds}]
while {[clock seconds] < $end} {
    for {set i 0} {$i < 50} {incr i} { [pick $targets] }
    if {[llength $findings] >= 50} break
}
puts "\n$calls calls, seed $seed, [llength $findings] finding(s)"
exit [expr {[llength $findings] ? 1 : 0}]
