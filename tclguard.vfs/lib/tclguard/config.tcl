# config.tcl -- configuration model, presets, validation, load/save.
#
# The config file is a plain Tcl dict (never evaluated as code). Lines whose
# first non-blank character is '#' are comments. Missing keys fall back to the
# defaults below, so a config can be as short as a single listener.

namespace eval ::tg::cfg {
    variable path ""
    variable current {}

    # ---- global settings -----------------------------------------------------
    variable generalDefaults {
        firewall            auto
        harden              0
        hardenSynRate       40
        hardenSynBurst      80
        hardenConnLimit     200
        hardenUdpRate       1000
        hardenUdpBurst      2000
        hardenIcmpRate      10
        hardenDropInvalid   1
        hardenDropFragments 1
        hardenDropBogusFlags 1
        removeRulesOnExit   0
        logFile             ""
        theme               dark
        stateDir            ""
        logLevel            info
        allowlist           {127.0.0.0/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 fe80::/10 fc00::/7}
        blocklist           {}
        strikeThreshold     10
        strikeLeakPerSec    0.25
        banSteps            {60 600 3600 21600 86400}
        banResetAfter       86400
        autoLevel           1
        autoLockdown        0
        levelCalmSec        60
        levelFactors        {1.0 0.6 0.35 0.2}
        thConnPerSec        {80 250 800}
        thBlockedPerSec     {60 250 1000}
        thRxPps             {20000 60000 200000}
        thRxLinkPct         {60 85 97}
        linkMbps            100
        iface               auto
        maxConnections      0
        trackerMax          400000
        learnTrusted        1
        controlEnable       1
        controlHost         127.0.0.1
        controlPort         9737
        controlToken        ""
        watchPorts          {}
        watchMaxPerIP       150
        watchMaxSynRecv     40
    }

    # ---- per-listener defaults ----------------------------------------------
    variable commonDefaults {
        enabled 1
        type tcp
        bind 0.0.0.0
        port 0
        backendHost 127.0.0.1
        backendPort 0
        note ""
    }
    variable tcpDefaults {
        maxConns 2000
        maxConnsPerIP 40
        connRate 60
        connWindow 10
        firstByteTimeout 10
        idleTimeout 300
        maxLifetime 0
        lazyConnect 1
        proxyProtocol none
    }
    variable httpDefaults {
        maxConns 2000
        maxConnsPerIP 60
        connRate 80
        connWindow 10
        reqRate 300
        reqWindow 10
        headerTimeout 10
        keepAliveTimeout 60
        bodyTimeout 30
        idleTimeout 120
        maxLifetime 0
        maxHeaderBytes 16384
        maxHeaders 100
        maxUriLength 8192
        maxBodyMB 100
        methods {GET HEAD POST PUT DELETE PATCH OPTIONS}
        forwardIp 1
        trustedProxies {}
        realIpHeader X-Forwarded-For
        challenge auto
        challengeTtl 3600
        pathLimits {}
        lazyConnect 1
        proxyProtocol none
    }
    variable udpDefaults {
        maxSessions 4000
        maxSessionsPerIP 4
        newSessionRate 12
        newSessionWindow 10
        pps 800
        bytesPerSec 1000000
        replyBytesPerSec 2000000
        minPacket 1
        maxPacket 1500
        sessionTimeout 60
        banOffenders 1
    }
    variable watcherDefaults {
        enabled 1
        file ""
        pattern ""
        hits 5
        window 60
        banSec 0
        note ""
    }

    # ---- presets -------------------------------------------------------------
    # Each preset is a list of listener specs. They are starting points; every
    # value can be edited afterwards.
    variable presets
    array set presets {}
    set presets(website) {
        title "Website / web app (HTTP)"
        description "Website / web app (HTTP, port 80). Full request inspection."
        listeners {
            {type http port 80 backendPort 8080}
        }
    }
    set presets(website-tls) {
        title "HTTPS website (TLS passed through)"
        description "HTTPS website (port 443, TLS passed through untouched). Connection-level protection only."
        listeners {
            {type tcp port 443 backendPort 8443 maxConnsPerIP 60 connRate 100 firstByteTimeout 15}
        }
    }
    set presets(minecraft-java) {
        title "Minecraft: Java Edition"
        description "Minecraft: Java Edition (TCP 25565)."
        listeners {
            {type tcp port 25565 backendPort 25566 maxConnsPerIP 4 connRate 15 firstByteTimeout 8}
        }
    }
    set presets(minecraft-bedrock) {
        title "Minecraft: Bedrock Edition"
        description "Minecraft: Bedrock Edition (UDP 19132)."
        listeners {
            {type udp port 19132 backendPort 19133 maxSessionsPerIP 3 pps 1200}
        }
    }
    set presets(valheim) {
        title "Valheim"
        description "Valheim dedicated server (UDP 2456-2457)."
        listeners {
            {type udp port 2456 backendPort 12456 maxSessionsPerIP 3 pps 600}
            {type udp port 2457 backendPort 12457 maxSessionsPerIP 3 pps 600}
        }
    }
    set presets(source-engine) {
        title "Source games (CS2, TF2, Garry's Mod...)"
        description "Source engine games: CS2, TF2, Garry's Mod, L4D2 (UDP+TCP 27015)."
        listeners {
            {type udp port 27015 backendPort 27115 maxSessionsPerIP 3 pps 500 replyBytesPerSec 600000}
            {type tcp port 27015 backendPort 27115 maxConnsPerIP 3 connRate 10}
        }
    }
    set presets(terraria) {
        title "Terraria"
        description "Terraria (TCP 7777)."
        listeners {
            {type tcp port 7777 backendPort 7778 maxConnsPerIP 4 connRate 12 firstByteTimeout 10}
        }
    }
    set presets(factorio) {
        title "Factorio"
        description "Factorio (UDP 34197)."
        listeners {
            {type udp port 34197 backendPort 34198 maxSessionsPerIP 2 pps 500}
        }
    }
    set presets(palworld) {
        title "Palworld"
        description "Palworld (UDP 8211)."
        listeners {
            {type udp port 8211 backendPort 8212 maxSessionsPerIP 3 pps 800}
        }
    }
    set presets(rust) {
        title "Rust"
        description "Rust (UDP 28015)."
        listeners {
            {type udp port 28015 backendPort 28016 maxSessionsPerIP 3 pps 900}
        }
    }
    set presets(ssh) {
        title "SSH (remote login)"
        description "SSH (TCP 22). The server speaks first, so backend connects immediately."
        listeners {
            {type tcp port 22 backendPort 2222 maxConnsPerIP 6 connRate 12 lazyConnect 0 firstByteTimeout 0}
        }
    }
    set presets(custom-tcp) {
        title "Other TCP service"
        description "Generic TCP service."
        listeners {
            {type tcp port 9000 backendPort 9001}
        }
    }
    set presets(custom-udp) {
        title "Other UDP service"
        description "Generic UDP service."
        listeners {
            {type udp port 9000 backendPort 9001}
        }
    }

    variable presetOrder {website website-tls minecraft-java minecraft-bedrock valheim
        source-engine terraria factorio palworld rust ssh custom-tcp custom-udp}

    variable watcherPresets
    array set watcherPresets {}
    set watcherPresets(sshd) {
        description "SSH failed logins (/var/log/auth.log)"
        file /var/log/auth.log
        pattern {Failed password for .* from ([0-9a-fA-F:.]+) port}
        hits 5 window 120 banSec 0
    }
    set watcherPresets(nginx-errors) {
        description "nginx access log: many 4xx/5xx responses"
        file /var/log/nginx/access.log
        pattern {^([0-9a-fA-F:.]+) [^"]*"[A-Z]+ [^"]*" (?:4[0-9][0-9]|5[0-9][0-9]) }
        hits 40 window 60 banSec 0
    }
    set watcherPresets(nginx-login) {
        description "nginx access log: repeated POSTs to a login page"
        file /var/log/nginx/access.log
        pattern {^([0-9a-fA-F:.]+) [^"]*"POST /[^" ]*login[^" ]*}
        hits 8 window 60 banSec 0
    }
}

# ------------------------------------------------------------------ paths ----

proc ::tg::cfg::homeDir {} {
    global env tcl_platform
    if {[info exists env(TCLGUARD_HOME)] && $env(TCLGUARD_HOME) ne ""} {
        return $env(TCLGUARD_HOME)
    }
    if {$tcl_platform(platform) eq "windows"} {
        if {[info exists env(APPDATA)]} { return [file join $env(APPDATA) TclGuard] }
        return [file join [file normalize ~] TclGuard]
    }
    set isRoot 0
    catch { set isRoot [expr {[exec id -u] == 0}] }
    if {$isRoot && [file isdirectory /etc/tclguard]} { return /etc/tclguard }
    if {[info exists env(XDG_CONFIG_HOME)] && $env(XDG_CONFIG_HOME) ne ""} {
        return [file join $env(XDG_CONFIG_HOME) tclguard]
    }
    return [file join [file normalize ~] .config tclguard]
}

proc ::tg::cfg::defaultPath {} { file join [homeDir] tclguard.conf }

proc ::tg::cfg::stateDir {} {
    variable current
    global env tcl_platform
    if {[dict exists $current general stateDir] && [dict get $current general stateDir] ne ""} {
        return [dict get $current general stateDir]
    }
    variable path
    set base [file dirname $path]
    # system installs keep state in /var/lib
    if {$tcl_platform(platform) ne "windows" && $base eq "/etc/tclguard"} { return /var/lib/tclguard }
    return [file join $base state]
}

# ------------------------------------------------------------- accessors ----

proc ::tg::cfg::general {key} {
    variable current
    variable generalDefaults
    if {[dict exists $current general $key]} { return [dict get $current general $key] }
    dict get $generalDefaults $key
}

proc ::tg::cfg::listenerDefaults {type} {
    variable commonDefaults
    variable tcpDefaults
    variable httpDefaults
    variable udpDefaults
    set d $commonDefaults
    switch -- $type {
        http { set d [dict merge $d $httpDefaults] }
        udp  { set d [dict merge $d $udpDefaults] }
        default { set d [dict merge $d $tcpDefaults] }
    }
    dict set d type $type
    return $d
}

# Fill a listener spec with defaults for its type.
proc ::tg::cfg::fillListener {spec} {
    set type tcp
    if {[dict exists $spec type]} { set type [dict get $spec type] }
    dict merge [listenerDefaults $type] $spec
}

proc ::tg::cfg::listeners {} {
    variable current
    if {![dict exists $current listeners]} { return {} }
    set out {}
    dict for {name spec} [dict get $current listeners] {
        dict set out $name [fillListener $spec]
    }
    return $out
}

proc ::tg::cfg::watchers {} {
    variable current
    variable watcherDefaults
    if {![dict exists $current watchers]} { return {} }
    set out {}
    dict for {name spec} [dict get $current watchers] {
        dict set out $name [dict merge $watcherDefaults $spec]
    }
    return $out
}

# A fresh, valid config dict containing only defaults.
proc ::tg::cfg::new {} {
    variable generalDefaults
    dict create general $generalDefaults listeners {} watchers {}
}

# Build listener specs from a preset. Returns dict name->spec with unique names.
proc ::tg::cfg::presetListeners {presetName {existing {}}} {
    variable presets
    if {![info exists presets($presetName)]} { error "unknown preset '$presetName'" }
    set out {}
    foreach spec [dict get $presets($presetName) listeners] {
        set type [dict get $spec type]
        set base "$presetName-$type-[dict get $spec port]"
        set name $base
        set i 2
        while {[dict exists $existing $name] || [dict exists $out $name]} {
            set name "$base-$i"; incr i
        }
        dict set out $name [dict merge [dict create note [dict get $presets($presetName) description]] $spec]
    }
    return $out
}

# ------------------------------------------------------------ validation ----

# Returns {errors warnings} where each is a list of human readable strings.
proc ::tg::cfg::validate {cfg} {
    variable generalDefaults
    set errs {}
    set warns {}
    set g [expr {[dict exists $cfg general] ? [dict get $cfg general] : {}}]

    dict for {k v} $g {
        if {![dict exists $generalDefaults $k]} { lappend warns "unknown setting '$k' (ignored)" }
    }
    set G [dict merge $generalDefaults $g]
    foreach {k min max} {
        strikeThreshold 1 1000000  banResetAfter 60 31536000  levelCalmSec 5 86400
        linkMbps 1 1000000  maxConnections 0 1000000  trackerMax 1000 5000000
        controlPort 1 65535
    } {
        if {![::tg::isInt [dict get $G $k] $min $max]} { lappend errs "$k must be a whole number between $min and $max" }
    }
    if {![::tg::isNum [dict get $G strikeLeakPerSec] 0 1000]} { lappend errs "strikeLeakPerSec must be a number >= 0" }
    foreach k {harden autoLevel autoLockdown learnTrusted controlEnable removeRulesOnExit hardenDropInvalid hardenDropFragments hardenDropBogusFlags} {
        if {![string is boolean -strict [dict get $G $k]]} { lappend errs "$k must be yes/no (1/0)" }
    }
    foreach k {hardenSynRate hardenSynBurst hardenConnLimit hardenUdpRate hardenUdpBurst hardenIcmpRate} {
        if {![::tg::isInt [dict get $G $k] 1 100000000]} { lappend errs "$k must be a positive whole number" }
    }
    if {[dict get $G firewall] ni {auto nft iptables netsh none}} {
        lappend errs "firewall must be one of: auto nft iptables netsh none"
    }
    if {[dict get $G theme] ni {dark light}} { lappend errs "theme must be dark or light" }
    if {[dict get $G logLevel] ni {debug info warn alert}} { lappend errs "logLevel must be debug, info, warn or alert" }
    set steps [dict get $G banSteps]
    if {[llength $steps] == 0} { lappend errs "banSteps must contain at least one duration (seconds)" }
    foreach s $steps {
        if {![::tg::isInt $s 1 31536000]} { lappend errs "banSteps entry '$s' is not a valid number of seconds"; break }
    }
    foreach k {allowlist blocklist} {
        foreach item [dict get $G $k] {
            if {![::tg::ip::isTarget $item]} { lappend errs "$k: '$item' is not a valid IP address or CIDR range" }
        }
    }
    set lf [dict get $G levelFactors]
    if {[llength $lf] != 4} {
        lappend errs "levelFactors needs exactly 4 numbers"
    } else {
        foreach f $lf { if {![::tg::isNum $f 0.01 1]} { lappend errs "levelFactors values must be between 0.01 and 1"; break } }
    }
    foreach k {thConnPerSec thBlockedPerSec thRxPps thRxLinkPct} {
        set l [dict get $G $k]
        if {[llength $l] != 3} { lappend errs "$k needs exactly 3 numbers (elevated attack lockdown)"; continue }
        foreach f $l { if {![::tg::isNum $f 0]} { lappend errs "$k values must be numbers >= 0"; break } }
    }

    # ---- listeners ----
    set seen {}
    set lst [expr {[dict exists $cfg listeners] ? [dict get $cfg listeners] : {}}]
    dict for {name spec} $lst {
        set p "listener '$name'"
        if {![regexp {^[A-Za-z0-9_.-]{1,40}$} $name]} {
            lappend errs "$p: name may only contain letters, digits, '_', '-' and '.' (max 40)"
        }
        set type [expr {[dict exists $spec type] ? [dict get $spec type] : "tcp"}]
        if {$type ni {tcp http udp}} { lappend errs "$p: type must be tcp, http or udp"; continue }
        set L [fillListener $spec]
        set known [dict keys [listenerDefaults $type]]
        dict for {k v} $spec {
            if {$k ni $known} { lappend warns "$p: unknown option '$k' (ignored)" }
        }
        if {![::tg::isInt [dict get $L port] 1 65535]} { lappend errs "$p: listen port must be 1-65535" }
        if {![::tg::isInt [dict get $L backendPort] 1 65535]} { lappend errs "$p: backend port must be 1-65535" }
        if {![string is boolean -strict [dict get $L enabled]]} { lappend errs "$p: enabled must be yes/no" }
        set bind [dict get $L bind]
        if {$bind ne "::" && ![::tg::ip::isValid $bind]} { lappend errs "$p: bind address '$bind' is not a valid IP" }
        set bh [dict get $L backendHost]
        if {$bh eq ""} { lappend errs "$p: backend host is empty" }
        if {[::tg::isInt [dict get $L port] 1 65535] && [::tg::isInt [dict get $L backendPort] 1 65535]} {
            set samePort [expr {[dict get $L port] == [dict get $L backendPort]}]
            set loopBackend [expr {$bh in {127.0.0.1 localhost ::1 0.0.0.0}}]
            if {$samePort && $loopBackend && $bind in {0.0.0.0 :: 127.0.0.1}} {
                lappend errs "$p: the backend ([::tg::joinHostPort $bh [dict get $L backendPort]]) is the same address as the listener, which would loop forever. Move your real server to a different port (e.g. [expr {[dict get $L port] + 1}])."
            }
            set lk "$type/$bind/[dict get $L port]"
            if {[dict exists $seen $lk]} {
                lappend errs "$p: another listener already uses $type port [dict get $L port] on $bind ([dict get $seen $lk])"
            } else {
                dict set seen $lk $name
            }
            if {$loopBackend eq "0" && ![::tg::ip::isPrivate $bh] && [::tg::ip::isValid $bh]} {
                lappend warns "$p: backend $bh is a public address; make sure traffic can only reach it through TclGuard."
            }
        }
        foreach k {maxConns maxConnsPerIP connRate maxSessions maxSessionsPerIP newSessionRate pps bytesPerSec replyBytesPerSec
                   reqRate maxHeaderBytes maxHeaders maxUriLength maxBodyMB maxPacket sessionTimeout connWindow reqWindow newSessionWindow} {
            if {[dict exists $L $k] && ![::tg::isInt [dict get $L $k] 1 1000000000]} {
                lappend errs "$p: $k must be a positive whole number"
            }
        }
        foreach k {firstByteTimeout headerTimeout keepAliveTimeout bodyTimeout idleTimeout maxLifetime minPacket challengeTtl} {
            if {[dict exists $L $k] && ![::tg::isInt [dict get $L $k] 0 1000000000]} {
                lappend errs "$p: $k must be a whole number >= 0 (seconds, 0 = off)"
            }
        }
        foreach k {lazyConnect forwardIp banOffenders} {
            if {[dict exists $L $k] && ![string is boolean -strict [dict get $L $k]]} { lappend errs "$p: $k must be yes/no" }
        }
        if {[dict exists $L proxyProtocol] && [dict get $L proxyProtocol] ni {none v1 v2}} {
            lappend errs "$p: proxyProtocol must be none, v1 or v2"
        }
        if {$type eq "udp"} {
            if {[dict get $L maxPacket] < [dict get $L minPacket]} { lappend errs "$p: maxPacket must be >= minPacket" }
            if {[dict get $L maxPacket] > 65000} { lappend errs "$p: maxPacket is unreasonably large" }
        }
        if {$type eq "http"} {
            if {[dict get $L challenge] ni {off auto always}} { lappend errs "$p: challenge must be off, auto or always" }
            foreach m [dict get $L methods] {
                if {![regexp {^[A-Z]{3,10}$} $m]} { lappend errs "$p: invalid HTTP method '$m'" }
            }
            foreach it [dict get $L trustedProxies] {
                if {![::tg::ip::isTarget $it]} { lappend errs "$p: trustedProxies: '$it' is not a valid IP/CIDR" }
            }
            if {![regexp {^[A-Za-z0-9-]+$} [dict get $L realIpHeader]]} { lappend errs "$p: realIpHeader is not a valid header name" }
            foreach pl [dict get $L pathLimits] {
                if {[llength $pl] != 3 || [catch {regexp -- [lindex $pl 0] ""}] ||
                    ![::tg::isInt [lindex $pl 1] 1] || ![::tg::isInt [lindex $pl 2] 1]} {
                    lappend errs "$p: each pathLimits entry must be {regex count seconds}, got '$pl'"
                }
            }
        }
        if {[dict get $L port] < 1024 && [dict get $L port] > 0} {
            global tcl_platform
            if {$tcl_platform(platform) ne "windows"} {
                set isRoot 0
                catch { set isRoot [expr {[exec id -u] == 0}] }
                if {!$isRoot} {
                    lappend warns "$p: ports below 1024 need root on Linux (or: sudo setcap cap_net_bind_service=+ep <binary>)."
                }
            }
        }
    }

    # ---- watchers ----
    set wl [expr {[dict exists $cfg watchers] ? [dict get $cfg watchers] : {}}]
    dict for {name spec} $wl {
        set p "log watcher '$name'"
        set W [dict merge $::tg::cfg::watcherDefaults $spec]
        if {[dict get $W file] eq ""} { lappend errs "$p: file path is empty" }
        if {[dict get $W pattern] eq ""} {
            lappend errs "$p: pattern is empty"
        } elseif {[catch {regexp -- [dict get $W pattern] ""} e]} {
            lappend errs "$p: pattern is not a valid regular expression ($e)"
        } elseif {[lindex [regexp -about -- [dict get $W pattern]] 0] < 1} {
            lappend errs "$p: pattern needs a (capture group) around the client IP address"
        }
        foreach k {hits window} {
            if {![::tg::isInt [dict get $W $k] 1 1000000]} { lappend errs "$p: $k must be a positive whole number" }
        }
        if {![::tg::isInt [dict get $W banSec] 0 31536000]} { lappend errs "$p: banSec must be 0 (use escalating bans) or a number of seconds" }
    }
    list $errs $warns
}

# ------------------------------------------------------------- load/save ----

proc ::tg::cfg::parseText {text} {
    set clean {}
    foreach line [split $text \n] {
        if {[string index [string trimleft $line] 0] eq "#"} continue
        lappend clean $line
    }
    set body [join $clean \n]
    if {[string trim $body] eq ""} { return [new] }
    if {[catch {dict size $body} err]} { error "config file is not valid: $err" }
    set d $body
    foreach sect {general listeners watchers} {
        if {[dict exists $d $sect] && [catch {dict size [dict get $d $sect]}]} {
            error "config section '$sect' is malformed"
        }
    }
    foreach k [dict keys $d] {
        if {$k ni {general listeners watchers}} { error "unknown top-level section '$k' (expected general, listeners, watchers)" }
    }
    variable generalDefaults
    set out [dict create general $generalDefaults listeners {} watchers {}]
    if {[dict exists $d general]}   { dict set out general   [dict merge $generalDefaults [dict get $d general]] }
    if {[dict exists $d listeners]} { dict set out listeners [dict get $d listeners] }
    if {[dict exists $d watchers]}  { dict set out watchers  [dict get $d watchers] }
    return $out
}

proc ::tg::cfg::load {file} {
    variable path
    variable current
    set path $file
    if {![file exists $file]} {
        set current [new]
        return 0
    }
    set text [::tg::readFile $file]
    set current [parseText $text]
    return 1
}

proc ::tg::cfg::set_ {cfg} {
    variable current
    set current $cfg
}

# Quote one value so it re-reads as exactly one dict element.
proc ::tg::cfg::q {v} {
    if {$v eq ""} { return "{}" }
    list $v
}

# Pretty printer producing a hand-editable file.
proc ::tg::cfg::serialize {cfg} {
    variable generalDefaults
    set out "# TclGuard configuration\n"
    append out "# Edit with care or use the GUI. Lines starting with # are comments.\n"
    append out "# Values left out fall back to built-in defaults.\n\n"
    append out "general \{\n"
    set g [dict merge $generalDefaults [expr {[dict exists $cfg general] ? [dict get $cfg general] : {}}]]
    dict for {k v} $g {
        # only write settings that differ from the default, plus a few key ones
        if {$k in {firewall harden allowlist blocklist controlToken} || $v ne [dict get $generalDefaults $k]} {
            append out "    $k [q $v]\n"
        }
    }
    append out "\}\n\nlisteners \{\n"
    if {[dict exists $cfg listeners]} {
        dict for {name spec} [dict get $cfg listeners] {
            append out "    [q $name] \{\n"
            set type [expr {[dict exists $spec type] ? [dict get $spec type] : "tcp"}]
            set def [listenerDefaults $type]
            # Always write the identity keys first
            foreach k {type enabled bind port backendHost backendPort note} {
                if {[dict exists $spec $k]} { append out "        $k [q [dict get $spec $k]]\n" }
            }
            dict for {k v} $spec {
                if {$k in {type enabled bind port backendHost backendPort note}} continue
                if {![dict exists $def $k] || $v ne [dict get $def $k]} { append out "        $k [q $v]\n" }
            }
            append out "    \}\n"
        }
    }
    append out "\}\n\nwatchers \{\n"
    if {[dict exists $cfg watchers]} {
        dict for {name spec} [dict get $cfg watchers] {
            append out "    [q $name] \{\n"
            dict for {k v} $spec { append out "        $k [q $v]\n" }
            append out "    \}\n"
        }
    }
    append out "\}\n"
    return $out
}

proc ::tg::cfg::save {{file ""} {cfg ""}} {
    variable path
    variable current
    if {$file eq ""} { set file $path }
    if {$cfg eq ""} { set cfg $current }
    file mkdir [file dirname $file]
    ::tg::writeFileAtomic $file [serialize $cfg]
    catch { file attributes $file -permissions 0600 }   ;# contains the control token
    return $file
}

# Make sure the control token exists (generated once, persisted).
proc ::tg::cfg::ensureToken {} {
    variable current
    if {[general controlToken] eq ""} {
        dict set current general controlToken [::tg::randomHex 16]
        return 1
    }
    return 0
}

# ------------------------------------------------------- randomness ----------

proc ::tg::randomHex {nBytes} {
    global tcl_platform
    if {[file exists /dev/urandom]} {
        set fh [open /dev/urandom rb]
        set d [read $fh $nBytes]
        close $fh
        binary scan $d H* hex
        return $hex
    }
    # Windows: ask the OS CSPRNG through PowerShell, fall back to a mixed seed.
    if {$tcl_platform(platform) eq "windows"} {
        if {![catch {
            exec powershell -NoProfile -NonInteractive -Command \
                "\$b=New-Object byte\[\] $nBytes; \[Security.Cryptography.RandomNumberGenerator\]::Create().GetBytes(\$b); (\$b|ForEach-Object{\$_.ToString('x2')}) -join ''"
        } out]} {
            set out [string trim $out]
            if {[regexp "^\[0-9a-f\]{[expr {$nBytes * 2}]}\$" $out]} { return $out }
        }
    }
    expr {srand([clock microseconds] ^ [pid])}
    set hex ""
    for {set i 0} {$i < $nBytes} {incr i} { append hex [format %02x [expr {int(rand() * 256)}]] }
    return $hex
}
