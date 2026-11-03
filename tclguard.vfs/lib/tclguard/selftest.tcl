# selftest.tcl -- `tclguard selftest`: attack ourselves and show the defences work.
#
# Starts the real engine on private ports with throw-away backends, then plays
# visitors and attackers against it with plain sockets. Nothing outside this
# process is touched (no firewall changes, your config and bans are not used).

namespace eval ::tg::selftest {
    variable results {}
    variable dir ""
    variable hb ""        ;# fake HTTP backend server socket
    variable eb ""        ;# fake TCP echo backend
    variable ub ""        ;# fake UDP echo backend
    variable hits 0       ;# requests the fake HTTP backend received
    variable udpHits 0
    variable ports
}

proc ::tg::selftest::freePort {} {
    set s [socket -server {apply {{c a p} {close $c}}} -myaddr 127.0.0.1 0]
    set p [lindex [fconfigure $s -sockname] 2]
    close $s
    return $p
}

# ---- fake backends ----------------------------------------------------------

proc ::tg::selftest::httpBackendAccept {chan ip port} {
    fconfigure $chan -blocking 0 -translation binary -buffering none
    fileevent $chan readable [list ::tg::selftest::httpBackendRead $chan]
    set ::tg::selftest::hbuf($chan) ""
}
proc ::tg::selftest::httpBackendRead {chan} {
    variable hits
    variable hbuf
    if {[catch {read $chan} d] || ([string length $d] == 0 && [eof $chan])} {
        catch {close $chan}; unset -nocomplain hbuf($chan); return
    }
    append hbuf($chan) $d
    while {[set i [string first "\r\n\r\n" $hbuf($chan)]] >= 0} {
        set hbuf($chan) [string range $hbuf($chan) [expr {$i + 4}] end]
        incr hits
        set body "hello from the backend"
        catch {puts -nonewline $chan "HTTP/1.1 200 OK\r\nContent-Length: [string length $body]\r\n\r\n$body"}
    }
}
proc ::tg::selftest::echoAccept {chan ip port} {
    fconfigure $chan -blocking 0 -translation binary -buffering none
    fileevent $chan readable [list ::tg::selftest::echoRead $chan]
}
proc ::tg::selftest::echoRead {chan} {
    if {[catch {read $chan} d] || ([string length $d] == 0 && [eof $chan])} { catch {close $chan}; return }
    catch {puts -nonewline $chan $d}
}
proc ::tg::selftest::udpBackendRead {} {
    variable ub
    variable udpHits
    set d [read $ub]
    set peer [fconfigure $ub -peer]
    incr udpHits
    fconfigure $ub -remote $peer
    puts -nonewline $ub "echo:$d"
}

# ---- tiny client ------------------------------------------------------------

# Connect, send `data`, collect the answer until the peer closes or the timeout
# passes. Returns {status text} where status is ok|closed|refused|timeout.
proc ::tg::selftest::talk {port data {timeoutMs 3000}} {
    variable talkDone
    variable talkBuf
    set talkBuf ""
    set talkDone ""
    if {[catch {socket 127.0.0.1 $port} c]} { return [list refused ""] }
    fconfigure $c -blocking 0 -translation binary -buffering none
    fileevent $c readable [list ::tg::selftest::talkRead $c]
    if {$data ne ""} { catch {puts -nonewline $c $data} }
    set timer [after $timeoutMs [list set ::tg::selftest::talkDone timeout]]
    vwait ::tg::selftest::talkDone
    after cancel $timer
    catch {close $c}
    list $talkDone $talkBuf
}
proc ::tg::selftest::talkRead {c} {
    variable talkBuf
    variable talkDone
    if {[catch {read $c} d]} { set talkDone closed; return }
    append talkBuf $d
    if {[eof $c]} { set talkDone closed }
    # an HTTP response that is complete counts as an answer
    if {[regexp {^HTTP/1\.1 \d+ [^\r]*\r\n.*?\r\n\r\n} $talkBuf] && $talkDone eq "" && [string match "*Connection: close*" $talkBuf]} {
        # wait for close
    }
}
proc ::tg::selftest::httpStatus {resp} {
    if {[regexp {^HTTP/1\.[01] (\d{3})} $resp -> c]} { return $c }
    return 0
}

proc ::tg::selftest::wait {ms} {
    set ::tg::selftest::_w 0
    after $ms {set ::tg::selftest::_w 1}
    vwait ::tg::selftest::_w
}

# ---- reporting ----------------------------------------------------------------

proc ::tg::selftest::check {name cond detail} {
    variable results
    lappend results [expr {$cond ? 1 : 0}]
    puts [format "  %s  %s" [expr {$cond ? "PASS" : "FAIL"}] $name]
    if {$detail ne ""} { puts "        $detail" }
}

proc ::tg::selftest::section {title} { puts "\n$title" }

# ---- the scenarios --------------------------------------------------------------

proc ::tg::selftest::run {{argv {}}} {
    variable results
    variable dir
    variable hb; variable eb; variable ub
    variable hits; variable udpHits
    set results {}
    puts "TclGuard self-test: starting a private copy on high ports and attacking it.\nNothing outside this process is changed.\n"

    set dir [file join [expr {[info exists ::env(TMP)] ? $::env(TMP) : "/tmp"}] "tclguard-selftest-[pid]"]
    if {$::tcl_platform(platform) ne "windows" && ![file isdirectory /tmp]} { set dir [file join [pwd] tclguard-selftest] }
    file mkdir $dir
    set hp [freePort]; set tp [freePort]; set up [freePort]
    set hbp [freePort]; set ebp [freePort]; set ubp [freePort]

    set hb [socket -server ::tg::selftest::httpBackendAccept -myaddr 127.0.0.1 $hbp]
    set eb [socket -server ::tg::selftest::echoAccept -myaddr 127.0.0.1 $ebp]
    set haveUdp [expr {![catch {package require udp}]}]
    if {$haveUdp} {
        set ub [udp_open $ubp]
        fconfigure $ub -blocking 0 -translation binary -buffering none
        fileevent $ub readable ::tg::selftest::udpBackendRead
    }

    set c [::tg::cfg::new]
    dict set c general stateDir $dir
    dict set c general logFile [file join $dir test.log]
    dict set c general firewall none
    dict set c general controlEnable 0
    dict set c general allowlist {}
    dict set c general strikeThreshold 6
    dict set c general strikeLeakPerSec 0
    dict set c general banSteps {6 30}
    dict set c general autoLevel 0
    dict set c listeners web [dict create type http bind 127.0.0.1 port $hp backendPort $hbp maxConnsPerIP 6 \
        reqRate 20 reqWindow 10 headerTimeout 2 connRate 500 maxBodyMB 1]
    dict set c listeners game [dict create type tcp bind 127.0.0.1 port $tp backendPort $ebp maxConnsPerIP 2 connRate 6 firstByteTimeout 2]
    if {$haveUdp} {
        dict set c listeners udp [dict create type udp port $up backendPort $ubp pps 50 maxSessionsPerIP 2 maxPacket 400]
    }
    ::tg::cfg::set_ $c
    set ::tg::cfg::path [file join $dir selftest.conf]
    set savedStderr $::tg::log::stderr
    set ::tg::log::stderr 0
    array unset ::tg::ban::banned
    ::tg::stat::resetForTests
    ::tg::rate::reset
    set ::tg::engine::running 0
    ::tg::engine::start

    # ---------------------------------------------------------------- website
    section "Website protection"
    lassign [talk $hp "GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"] st resp
    check "A normal visitor gets the page" [expr {[httpStatus $resp] == 200 && [string match "*hello from the backend*" $resp]}] \
        "status [httpStatus $resp]"

    set before $hits
    lassign [talk $hp "GET / HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 5\r\nHost: x\r\n\r\nabcd"] st resp
    check "A request-smuggling attempt is refused" [expr {[httpStatus $resp] == 400 && $hits == $before}] \
        "answer [httpStatus $resp], backend saw [expr {$hits - $before}] requests"
    lassign [talk $hp "\x16\x03\x01garbage\r\n\r\n"] st resp
    check "Garbage / wrong protocol is refused" [expr {[httpStatus $resp] == 400}] "answer [httpStatus $resp]"

    set t0 [clock milliseconds]
    lassign [talk $hp "GET / HTTP/1.1\r\nHost: x\r\nX-Slow: " 6000] st resp
    set el [expr {[clock milliseconds] - $t0}]
    check "Slowloris (never finishing the request) is cut off" [expr {[httpStatus $resp] == 408 && $el < 4500}] \
        "answered [httpStatus $resp] after [expr {$el / 1000.0}]s (limit 2s)"
    ::tg::ban::clearAll
    ::tg::rate::reset

    # request flood on one keep-alive connection, paced like a real (fast) bot
    set c [socket 127.0.0.1 $hp]
    fconfigure $c -blocking 0 -translation binary -buffering none
    set ::tg::selftest::flood ""
    set ::tg::selftest::fc $c
    fileevent $c readable {append ::tg::selftest::flood [read $::tg::selftest::fc]}
    for {set i 0} {$i < 60} {incr i} {
        if {[catch {puts -nonewline $c "GET /f$i HTTP/1.1\r\nHost: x\r\n\r\n"}]} break
        wait 8
    }
    wait 300
    catch {close $c}
    set n200 [regexp -all {HTTP/1\.1 200} $::tg::selftest::flood]
    set n429 [regexp -all {HTTP/1\.1 429} $::tg::selftest::flood]
    check "A request flood is throttled (limit 20 per 10 s)" [expr {$n429 >= 1 && $n200 >= 15 && $n200 <= 25}] \
        "$n200 requests served, then 429 Too Many Requests"
    wait 200
    ::tg::ban::clearAll
    ::tg::rate::reset

    # repeated flooding => ban
    for {set round 0} {$round < 6 && ![::tg::ban::isBanned 127.0.0.1]} {incr round} {
        set c [socket 127.0.0.1 $hp]
        fconfigure $c -blocking 0 -translation binary -buffering none
        for {set i 0} {$i < 40} {incr i} { catch {puts -nonewline $c "GET /g$i HTTP/1.1\r\nHost: x\r\n\r\n"} }
        wait 300
        catch {close $c}
    }
    check "A persistent flooder gets banned automatically" [::tg::ban::isBanned 127.0.0.1] \
        [expr {[::tg::ban::isBanned 127.0.0.1] ? "banned: [dict get [::tg::ban::lookup 127.0.0.1] reason]" : "not banned"}]
    lassign [talk $hp "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" 1500] st resp
    check "...and is then refused instantly" [expr {$resp eq ""}] "status: $st"
    ::tg::ban::remove 127.0.0.1
    ::tg::rate::reset
    wait 100
    lassign [talk $hp "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"] st resp
    check "...but is let back in when unbanned" [expr {[httpStatus $resp] == 200}] "status [httpStatus $resp]"
    ::tg::ban::clearAll
    ::tg::rate::reset

    # -------------------------------------------------------------- game TCP
    section "Game server (TCP) protection"
    lassign [talk $tp "hello"] st resp
    # echo server keeps the connection open, so we get "timeout" with the data
    check "A real player gets through to the server" [expr {$resp eq "hello"}] "echoed: '$resp'"
    set t0 [clock milliseconds]
    lassign [talk $tp "" 6000] st resp
    set el [expr {[clock milliseconds] - $t0}]
    check "A connection that never sends anything is dropped" [expr {$st eq "closed" && $el < 4500}] "dropped after [expr {$el / 1000.0}]s"
    ::tg::ban::clearAll
    ::tg::rate::reset

    set open {}
    set refused 0
    for {set i 0} {$i < 5} {incr i} {
        if {[catch {socket 127.0.0.1 $tp} c]} { incr refused; continue }
        fconfigure $c -blocking 0 -translation binary -buffering none
        catch {puts -nonewline $c "x"}
        lappend open $c
        wait 40
    }
    wait 200
    set served 0
    foreach c $open { if {![catch {read $c} d] && $d eq "x"} { incr served } }
    foreach c $open { catch {close $c} }
    check "One address cannot hog the server (limit 2 connections)" [expr {$served == 2}] "$served of 5 attempts served"
    ::tg::ban::clearAll
    ::tg::rate::reset

    set bannedBefore [::tg::stat::get bans]
    for {set i 0} {$i < 40} {incr i} {
        if {![catch {socket 127.0.0.1 $tp} c]} { catch {close $c} }
        if {$i % 8 == 0} { update }
    }
    wait 200
    check "A connection flood gets the source banned" [::tg::ban::isBanned 127.0.0.1] \
        [expr {[::tg::ban::isBanned 127.0.0.1] ? "banned: [dict get [::tg::ban::lookup 127.0.0.1] reason]" : "not banned"}]
    ::tg::ban::clearAll
    ::tg::rate::reset

    # -------------------------------------------------------------------- UDP
    section "Game server (UDP) protection"
    if {!$haveUdp} {
        puts "  SKIP  this build has no UDP extension (tcludp); UDP relay tests skipped"
    } else {
        set uc [udp_open]
        fconfigure $uc -blocking 0 -translation binary -buffering none -remote [list 127.0.0.1 $up]
        set ::tg::selftest::ureply ""
        fileevent $uc readable {append ::tg::selftest::ureply [read $::tg::selftest::uc]}
        set ::tg::selftest::uc $uc
        puts -nonewline $uc "ping"
        wait 400
        check "A normal UDP packet round-trips" [expr {$::tg::selftest::ureply eq "echo:ping"}] "got '$::tg::selftest::ureply'"
        set before $udpHits
        for {set i 0} {$i < 2000} {incr i} { catch {puts -nonewline $uc "flood$i"} ; if {$i % 200 == 0} { update } }
        wait 700
        set reached [expr {$udpHits - $before}]
        check "A UDP flood is mostly dropped before the game server sees it" [expr {$reached < 400}] "$reached of 2000 packets reached the server"
        check "...and the flooder is banned" [::tg::ban::isBanned 127.0.0.1] ""
        catch {close $uc}
    }

    # ----------------------------------------------------------------- finish
    set rate [::tg::stat::get blocked]
    puts "\nTclGuard blocked $rate hostile events during this test."
    ::tg::engine::stop
    catch {close $hb}; catch {close $eb}; if {$ub ne ""} { catch {close $ub} }
    set ::tg::log::stderr $savedStderr
    catch {file delete -force $dir}

    set total [llength $results]
    set passed [expr {[tcl::mathop::+ {*}$results]}]
    if {$passed == $total} {
        puts "\nAll $total checks passed: the protections work on this machine."
        return 0
    }
    puts "\n[expr {$total - $passed}] of $total checks FAILED."
    return 1
}
