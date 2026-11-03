# gui.tcl -- the TclGuard window.
#
# A sidebar app (Overview, Protection, Bans, Firewall, Activity, Settings, Help)
# built on ::tg::kit. The GUI only reads ::tg::engine::snapshot and changes things
# through ::tg::engine::cmd and the config API, so everything it can do is also
# possible from the command line.

namespace eval ::tg::gui {
    variable v                ;# widget-bound variables
    array set v {}
    variable page overview
    variable pages {overview protection bans firewall activity settings help}
    variable titles
    array set titles {
        overview   {Overview   {Live protection status}}
        protection {Protection {What TclGuard guards, and how strictly}}
        bans       {Bans       {Who is blocked, and who is always trusted}}
        firewall   {Firewall   {Stop floods before they reach this program}}
        activity   {Activity   {Everything TclGuard has noticed and done}}
        settings   {Settings   {Ban rules, threat levels and logging}}
        help       {Help       {Setup guide and honest limits}}
    }
    variable snap {}
    variable hist             ;# per-second history for sparklines
    array set hist {conns {} allowed {} blocked {} bans {}}
    variable banSig ""
    variable banRows
    array set banRows {}
    variable lstSig ""
    variable navPaths
    array set navPaths {}
}

# ----------------------------------------------------------------- helpers ----

proc ::tg::gui::fr {path parent args} {
    array set o {-bg ""}
    array set o $args
    set bg [expr {$o(-bg) ne "" ? [::tg::kit::col $o(-bg)] : [::tg::kit::bgOf $parent]}]
    frame $path -background $bg -borderwidth 0 -highlightthickness 0
    return $path
}

proc ::tg::gui::tx {path parent text args} { ::tg::kit::lbl $path $parent $text {*}$args }

proc ::tg::gui::sep {path parent} {
    frame $path -background [::tg::kit::col border] -height 1 -borderwidth 0 -highlightthickness 0
    return $path
}

proc ::tg::gui::msg {kind title text} {
    tk_messageBox -parent . -icon $kind -title $title -message $text -type ok
}
proc ::tg::gui::ask {title text} {
    expr {[tk_messageBox -parent . -icon question -title $title -message $text -type yesno] eq "yes"}
}
proc ::tg::gui::do {args} {
    if {[catch {::tg::engine::cmd {*}$args} res]} { msg error "TclGuard" $res; return [list 0 $res] }
    list 1 $res
}

proc ::tg::gui::levelColor {l} { lindex {ok warn bad violet} $l }
proc ::tg::gui::levelWord {l} { lindex {Protected Elevated {Under attack} Lockdown} $l }

# ------------------------------------------------------------------ shell ----

proc ::tg::gui::build {} {
    variable v
    variable pages
    variable navPaths
    foreach w [winfo children .] { destroy $w }
    array unset navPaths
    wm title . "TclGuard"
    . configure -background [::tg::kit::col bg]

    fr .side . -bg side
    pack .side -side left -fill y
    .side configure -width [::tg::kit::px 244]
    pack propagate .side 0
    fr .sep . -bg border
    .sep configure -width 1
    pack .sep -side left -fill y

    # brand
    fr .side.brand .side -bg side
    pack .side.brand -fill x -padx 22 -pady {26 20}
    label .side.brand.i -image [::tg::kit::icon shieldcheck 30 accent] -background [::tg::kit::col side] -borderwidth 0
    tx .side.brand.t .side.brand "TclGuard" -font h2
    tx .side.brand.v .side.brand "v$::tg::VERSION" -font small -fg faint
    pack .side.brand.i -side left
    pack .side.brand.t -side left -padx {10 0}
    pack .side.brand.v -side left -padx {8 0} -pady {3 0}

    # navigation
    foreach {id icon label} {overview overview Overview protection server Protection bans ban Bans firewall wall Firewall activity activity Activity settings sliders Settings help info Help} {
        navItem .side.n_$id .side $id $icon $label
        pack .side.n_$id -fill x -padx 12 -pady 1
    }

    # bottom block
    fr .side.bottom .side -bg side
    pack .side.bottom -side bottom -fill x -padx 14 -pady {0 18}
    set in [::tg::kit::card .side.bottom.pc .side.bottom -fill surface]
    pack .side.bottom.pc -fill x
    fr $in.r $in -bg surface
    pack $in.r -fill x -padx 14 -pady {12 2}
    tx $in.r.t $in.r "Protection" -font bold -bg surface
    set v(running) [expr {$::tg::engine::running ? 1 : 0}]
    ::tg::kit::toggle $in.r.sw $in.r ::tg::gui::v(running) -command ::tg::gui::toggleRun
    pack $in.r.t -side left
    pack $in.r.sw -side right
    tx $in.st $in "" -font small -fg muted -bg surface -wrap 170
    pack $in.st -anchor w -padx 14 -pady {0 12}
    set v(statusLabel) $in.st
    set v(theme) $::tg::kit::theme
    ::tg::kit::segment .side.bottom.th .side.bottom ::tg::gui::v(theme) {{dark Dark} {light Light}} -command ::tg::gui::setTheme
    pack .side.bottom.th -pady {12 0} -anchor w

    # main area
    fr .main . -bg bg
    pack .main -side left -fill both -expand 1
    fr .main.top .main -bg bg
    pack .main.top -fill x -padx 32 -pady {26 6}
    tx .main.top.t .main.top "" -font h1
    tx .main.top.s .main.top "" -font body -fg muted
    pack .main.top.t -side top -anchor w
    pack .main.top.s -side top -anchor w -pady {2 0}
    fr .main.top.act .main.top -bg bg
    place .main.top.act -relx 1 -rely 0.5 -anchor e
    fr .main.body .main -bg bg
    pack .main.body -fill both -expand 1 -padx 32 -pady {8 0}

    buildOverview
    buildProtection
    buildBans
    buildFirewall
    buildActivity
    buildSettings
    buildHelp
}

proc ::tg::gui::navItem {path parent id icon label} {
    variable navPaths
    set h [::tg::kit::px 42]
    canvas $path -height $h -background [::tg::kit::col side] -highlightthickness 0 -borderwidth 0 -cursor hand2
    set navPaths($id) [list $path $icon $label]
    bind $path <Configure> [list ::tg::gui::navDraw $id 0]
    bind $path <Enter> [list ::tg::gui::navDraw $id 1]
    bind $path <Leave> [list ::tg::gui::navDraw $id 0]
    bind $path <ButtonRelease-1> [list ::tg::gui::showPage $id]
}

proc ::tg::gui::navDraw {id hover} {
    variable navPaths
    variable page
    lassign $navPaths($id) path icon label
    if {![winfo exists $path]} return
    set w [winfo width $path]
    if {$w < 20} return
    set h [::tg::kit::px 42]
    $path delete all
    set side [::tg::kit::col side]
    set active [expr {$id eq $page}]
    if {$active} {
        ::tg::kit::roundRect $path 0 0 $w $h [::tg::kit::px 10] [::tg::kit::col accentSoft] $side
        set ic accent; set tc accent
    } elseif {$hover} {
        ::tg::kit::roundRect $path 0 0 $w $h [::tg::kit::px 10] [::tg::kit::col hover] $side
        set ic text; set tc text
    } else { set ic muted; set tc muted }
    $path create image [::tg::kit::px 16] [expr {$h / 2}] -anchor w -image [::tg::kit::icon $icon 20 $ic]
    $path create text [::tg::kit::px 46] [expr {$h / 2}] -anchor w -text $label -fill [::tg::kit::col $tc] -font [expr {$active ? $::tg::kit::F(bold) : $::tg::kit::F(body)}]
}

proc ::tg::gui::showPage {id} {
    variable page
    variable pages
    variable titles
    variable navPaths
    set page $id
    foreach p $pages { catch {pack forget .main.body.$p} }
    pack .main.body.$id -fill both -expand 1
    lassign $titles($id) title sub
    .main.top.t configure -text $title
    .main.top.s configure -text $sub
    foreach w [winfo children .main.top.act] { pack forget $w }
    if {[winfo exists .main.top.act.$id]} { pack .main.top.act.$id -side right }
    foreach p $pages { if {[info exists navPaths($p)]} { navDraw $p 0 } }
    if {$id eq "firewall"} { refreshFwPreview }
    refresh
}

# --------------------------------------------------------------- overview ----

proc ::tg::gui::buildOverview {} {
    variable v
    set p [::tg::kit::scroll .main.body.overview .main.body]

    # ---- "needs administrator" banner (shown only when it applies) ----
    set bn [::tg::kit::card $p.admin $p -fill warnSoft -border 0]
    fr $bn.r $bn -bg warnSoft
    pack $bn.r -fill x -padx 18 -pady 14
    label $bn.r.i -image [::tg::kit::icon shield 24 warn] -background [::tg::kit::col warnSoft] -borderwidth 0
    fr $bn.r.t $bn.r -bg warnSoft
    tx $bn.r.t.h $bn.r.t "The kernel firewall is off" -font bold -bg warnSoft
    tx $bn.r.t.b $bn.r.t "TclGuard needs administrator rights to hand bans and rate limits to the operating system. Without it, big floods still reach this program." -font small -bg warnSoft -wrap 560
    pack $bn.r.t.h -anchor w
    pack $bn.r.t.b -anchor w -pady {2 0}
    ::tg::kit::button $bn.r.b $bn.r "Restart as administrator" -style primary -icon shieldcheck -command ::tg::gui::restartAdmin
    pack $bn.r.i -side left -anchor n
    pack $bn.r.t -side left -padx {14 0}
    pack $bn.r.b -side right
    set v(adminBanner) $p.admin

    # ---- hero ----
    set hero [::tg::kit::card $p.hero $p -radius 16]
    pack $p.hero -fill x -pady {0 16}
    fr $hero.g $hero -bg surface
    pack $hero.g -fill x -padx 24 -pady {22 16}
    canvas $hero.g.ring -width [::tg::kit::px 116] -height [::tg::kit::px 116] -background [::tg::kit::col surface] -highlightthickness 0 -borderwidth 0
    fr $hero.g.mid $hero.g -bg surface
    tx $hero.g.mid.state $hero.g.mid "Protected" -font huge -fg ok
    tx $hero.g.mid.sub $hero.g.mid "" -font body -fg muted -wrap 640
    fr $hero.g.mid.chips $hero.g.mid -bg surface
    pack $hero.g.mid.state -anchor w
    pack $hero.g.mid.sub -anchor w -pady {4 10}
    pack $hero.g.mid.chips -anchor w
    pack $hero.g.ring -side left
    pack $hero.g.mid -side left -fill x -expand 1 -padx {24 0}
    sep $hero.sep $hero
    pack $hero.sep -fill x -padx 24
    fr $hero.bot $hero -bg surface
    pack $hero.bot -fill x -padx 24 -pady 14
    tx $hero.bot.cap $hero.bot "Threat level" -font bold -bg surface
    set v(lvl) auto
    ::tg::kit::segment $hero.bot.seg $hero.bot ::tg::gui::v(lvl) {{auto Auto} {0 Normal} {1 Elevated} {2 {Under attack}} {3 Lockdown}} -command ::tg::gui::setLevel
    tx $hero.bot.hint $hero.bot "Auto tightens limits by itself when traffic looks hostile." -font small -fg muted -bg surface
    pack $hero.bot.cap -side left
    pack $hero.bot.seg -side left -padx {16 16}
    pack $hero.bot.hint -side left
    set v(hero) $hero.g

    # ---- metric cards ----
    fr $p.metrics $p -bg bg
    pack $p.metrics -fill x -pady {0 16}
    set i 0
    foreach {id title} {conns "Open connections" allowed "Allowed per second" blocked "Blocked per second" bans "Banned addresses"} {
        set in [::tg::kit::card $p.metrics.$id $p.metrics]
        grid $p.metrics.$id -row 0 -column $i -sticky nsew -padx [expr {$i == 0 ? {0 8} : ($i == 3 ? {8 0} : {8 8})}]
        grid columnconfigure $p.metrics $i -weight 1 -uniform m
        tx $in.t $in $title -font small -fg muted -bg surface
        tx $in.v $in "0" -font big -bg surface
        tx $in.s $in "" -font small -fg muted -bg surface
        canvas $in.sp -height [::tg::kit::px 38] -background [::tg::kit::col surface] -highlightthickness 0 -borderwidth 0
        pack $in.t -anchor w -padx 18 -pady {16 0}
        pack $in.v -anchor w -padx 18
        pack $in.s -anchor w -padx 18
        pack $in.sp -fill x -padx 18 -pady {8 14}
        set v(m,$id) $in
        incr i
    }

    # ---- chart ----
    set cin [::tg::kit::card $p.chart $p]
    pack $p.chart -fill x -pady {0 16}
    fr $cin.h $cin -bg surface
    pack $cin.h -fill x -padx 20 -pady {16 0}
    tx $cin.h.t $cin.h "Traffic" -font h3 -bg surface
    tx $cin.h.sub $cin.h "last 5 minutes" -font small -fg muted -bg surface
    ::tg::kit::chip $cin.h.c2 $cin.h "Blocked" -tone bad -dot 1
    ::tg::kit::chip $cin.h.c1 $cin.h "Allowed" -tone accent -dot 1
    pack $cin.h.t -side left
    pack $cin.h.sub -side left -padx {10 0} -pady {3 0}
    pack $cin.h.c2 -side right
    pack $cin.h.c1 -side right -padx {0 8}
    canvas $cin.c -height [::tg::kit::px 230] -background [::tg::kit::col surface] -highlightthickness 0 -borderwidth 0
    pack $cin.c -fill x -padx 12 -pady {8 14}
    set v(chart) $cin.c
    bind $cin.c <Configure> {::tg::gui::drawChart}
    bind $cin.c <Motion> {::tg::gui::chartHover %x %y}
    bind $cin.c <Leave> {catch {$::tg::gui::v(chart) delete hover}}

    # ---- bottom row ----
    fr $p.low $p -bg bg
    pack $p.low -fill x -pady {0 24}
    grid columnconfigure $p.low {0 1} -weight 1 -uniform l
    set tin [::tg::kit::card $p.low.top $p.low]
    grid $p.low.top -row 0 -column 0 -sticky nsew -padx {0 8}
    tx $tin.t $tin "Busiest sources" -font h3 -bg surface
    tx $tin.s $tin "right now" -font small -fg muted -bg surface
    pack $tin.t -anchor w -padx 20 -pady {16 0}
    pack $tin.s -anchor w -padx 20
    for {set i 0} {$i < 6} {incr i} {
        fr $tin.r$i $tin -bg surface
        tx $tin.r$i.ip $tin.r$i "" -font mono -bg surface
        canvas $tin.r$i.bar -width [::tg::kit::px 110] -height [::tg::kit::px 8] -background [::tg::kit::col surface] -highlightthickness 0 -borderwidth 0
        tx $tin.r$i.n $tin.r$i "" -font small -fg muted -bg surface -anchor e
        pack $tin.r$i.ip -side left
        pack $tin.r$i.n -side right
        pack $tin.r$i.bar -side right -padx 12
    }
    tx $tin.empty $tin "No traffic yet." -font body -fg muted -bg surface
    set v(top) $tin
    set ain [::tg::kit::card $p.low.act $p.low]
    grid $p.low.act -row 0 -column 1 -sticky nsew -padx {8 0}
    tx $ain.t $ain "Recent activity" -font h3 -bg surface
    tx $ain.s $ain "bans, level changes, problems" -font small -fg muted -bg surface
    pack $ain.t -anchor w -padx 20 -pady {16 0}
    pack $ain.s -anchor w -padx 20
    for {set i 0} {$i < 6} {incr i} {
        fr $ain.r$i $ain -bg surface
        label $ain.r$i.d -image [::tg::kit::disc [::tg::kit::col muted] [::tg::kit::px 8]] -background [::tg::kit::col surface] -borderwidth 0
        tx $ain.r$i.x $ain.r$i "" -font small -bg surface -wrap 330
        tx $ain.r$i.w $ain.r$i "" -font tiny -fg faint -bg surface
        pack $ain.r$i.d -side left -anchor n -pady {5 0}
        pack $ain.r$i.x -side left -padx {10 0} -anchor w
        pack $ain.r$i.w -side right -anchor n -pady {2 0}
    }
    tx $ain.empty $ain "All quiet." -font body -fg muted -bg surface
    set v(act) $ain
}

# ring gauge + status text
proc ::tg::gui::drawHero {s} {
    variable v
    set g $v(hero)
    set lv [dict get $s level]
    set level [dict get $lv level]
    set running [dict get $s running]
    set key [expr {$running ? [levelColor $level] : "muted"}]
    set col [::tg::kit::col $key]
    set c $g.ring
    set sz [::tg::kit::px 116]
    $c delete all
    set m [::tg::kit::px 8]; set wd [::tg::kit::px 9]
    $c create arc $m $m [expr {$sz - $m}] [expr {$sz - $m}] -start 90 -extent 359.9 -style arc -width $wd -outline [::tg::kit::col track]
    if {$running} { $c create arc $m $m [expr {$sz - $m}] [expr {$sz - $m}] -start 90 -extent 359.9 -style arc -width $wd -outline $col }
    set icon [expr {!$running ? "shieldx" : ($level == 0 ? "shieldcheck" : ($level == 1 ? "warn" : "shieldbolt"))}]
    $c create image [expr {$sz / 2}] [expr {$sz / 2}] -image [::tg::kit::icon $icon 46 $key]
    set word [expr {$running ? [levelWord $level] : "Paused"}]
    $g.mid.state configure -text $word -foreground $col
    set reason [dict get $lv reason]
    set sub [expr {!$running ? "Nothing is being checked or blocked. Turn protection back on in the sidebar." :
        ($level == 0 ? "All quiet. Visitors are checked and passed through normally." :
        "Limits are tightened: $reason")}]
    $g.mid.sub configure -text $sub
    # rebuild the chip row only when its content changes
    set fw [dict get $s firewall]
    set sig [list [expr {[dict get $s uptime] / 5}] [dict get $fw installed] [dict get $fw backend] [dict get $s trusted]]
    if {![info exists v(chipSig)] || $v(chipSig) ne $sig} {
        set v(chipSig) $sig
        foreach w [winfo children $g.mid.chips] { destroy $w }
        ::tg::kit::chip $g.mid.chips.up $g.mid.chips "up [::tg::fmtDuration [dict get $s uptime]]"
        ::tg::kit::chip $g.mid.chips.fw $g.mid.chips [expr {[dict get $fw installed] ? "kernel firewall: [dict get $fw backend]" : "kernel firewall off"}] \
            -tone [expr {[dict get $fw installed] ? "ok" : "warn"}] -dot 1
        ::tg::kit::chip $g.mid.chips.tr $g.mid.chips "[dict get $s trusted] trusted visitors"
        pack $g.mid.chips.up $g.mid.chips.fw $g.mid.chips.tr -side left -padx {0 8}
    }
}

proc ::tg::gui::spark {c vals colorKey} {
    $c delete all
    set w [winfo width $c]; set h [winfo height $c]
    if {$w < 20 || [llength $vals] < 2} return
    set max 1.0
    foreach x $vals { if {$x > $max} { set max $x } }
    set n [llength $vals]
    set pts {}
    set i 0
    foreach x $vals {
        lappend pts [expr {$w * double($i) / ($n - 1)}] [expr {($h - 3) - ($h - 8) * ($x / $max)}]
        incr i
    }
    set col [::tg::kit::col $colorKey]
    set fillc [::tg::kit::mix [::tg::kit::col surface] $col 0.16]
    $c create polygon 0 $h {*}$pts $w $h -fill $fillc -outline ""
    $c create line {*}$pts -fill $col -width 2 -smooth 1 -capstyle round -joinstyle round
}

proc ::tg::gui::niceMax {m} {
    if {$m <= 4} { return 4 }
    set p [expr {pow(10, floor(log10($m)))}]
    foreach k {1 2 2.5 5 10} { if {$m <= $k * $p} { return [expr {$k * $p}] } }
    return [expr {10 * $p}]
}

proc ::tg::gui::chartGeom {c} {
    set w [winfo width $c]; set h [winfo height $c]
    list $w $h [::tg::kit::px 40] [::tg::kit::px 8] [::tg::kit::px 8] [::tg::kit::px 24]
}

proc ::tg::gui::drawChart {} {
    variable v
    if {![info exists v(chart)] || ![winfo exists $v(chart)]} return
    set c $v(chart)
    $c delete all
    lassign [chartGeom $c] w h padL padR padT padB
    if {$w < 120} return
    set pw [expr {$w - $padL - $padR}]; set ph [expr {$h - $padT - $padB}]
    set series [lrange $::tg::stat::series end-299 end]
    set n [llength $series]
    set max 0
    foreach s $series { set m [expr {max([lindex $s 1], [lindex $s 2])}]; if {$m > $max} { set max $m } }
    set top [niceMax $max]
    for {set i 0} {$i <= 4} {incr i} {
        set y [expr {$padT + $ph - $ph * $i / 4.0}]
        $c create line $padL $y [expr {$w - $padR}] $y -fill [::tg::kit::col border]
        $c create text [expr {$padL - 10}] $y -text [::tg::fmtRate [expr {$top * $i / 4.0}]] -anchor e -fill [::tg::kit::col faint] -font $::tg::kit::F(small)
    }
    foreach {frac lab} {0 -5m 0.2 -4m 0.4 -3m 0.6 -2m 0.8 -1m 1.0 now} {
        set x [expr {$padL + $pw * $frac}]
        $c create text $x [expr {$h - 8}] -text $lab -fill [::tg::kit::col faint] -font $::tg::kit::F(small) \
            -anchor [expr {$frac == 1.0 ? "e" : ($frac == 0 ? "w" : "center")}]
    }
    if {$n < 2} {
        $c create text [expr {$w / 2}] [expr {$h / 2}] -text "collecting data..." -fill [::tg::kit::col muted] -font $::tg::kit::F(body)
        return
    }
    foreach {idx key fill} {1 chart1 1 2 chart2 0} {
        set pts {}
        set i 0
        foreach s $series {
            set age [expr {$n - 1 - $i}]
            incr i
            lappend pts [expr {$padL + $pw * (1.0 - $age / 300.0)}] [expr {$padT + $ph - $ph * min(1.0, [lindex $s $idx] / double($top))}]
        }
        if {$fill} {
            $c create polygon [lindex $pts 0] [expr {$padT + $ph}] {*}$pts [lindex $pts end-1] [expr {$padT + $ph}] \
                -fill [::tg::kit::col chart1Fill] -outline ""
        }
        $c create line {*}$pts -fill [::tg::kit::col $key] -width 2 -smooth 1 -joinstyle round
    }
}

proc ::tg::gui::chartHover {x y} {
    variable v
    set c $v(chart)
    $c delete hover
    set series [lrange $::tg::stat::series end-299 end]
    set n [llength $series]
    if {$n < 2} return
    lassign [chartGeom $c] w h padL padR padT padB
    set pw [expr {$w - $padL - $padR}]
    if {$x < $padL || $x > $w - $padR} return
    set age [expr {int(round((1.0 - ($x - $padL) / double($pw)) * 300))}]
    set idx [expr {$n - 1 - $age}]
    if {$idx < 0 || $idx >= $n} return
    lassign [lindex $series $idx] t ok bl
    set px [expr {$padL + $pw * (1.0 - $age / 300.0)}]
    $c create line $px $padT $px [expr {$h - $padB}] -fill [::tg::kit::col faint] -dash {3 3} -tags hover
    set bw [::tg::kit::px 150]; set bh [::tg::kit::px 70]
    set bx [expr {$px + 14}]
    if {$bx + $bw > $w} { set bx [expr {$px - 14 - $bw}] }
    set by $padT
    ::tg::kit::roundRect $c $bx $by [expr {$bx + $bw}] [expr {$by + $bh}] [::tg::kit::px 9] [::tg::kit::col border] [::tg::kit::col surface] hover
    ::tg::kit::roundRect $c [expr {$bx + 1}] [expr {$by + 1}] [expr {$bx + $bw - 1}] [expr {$by + $bh - 1}] [::tg::kit::px 8] [::tg::kit::col surface2] [::tg::kit::col border] hover
    $c create text [expr {$bx + 14}] [expr {$by + 15}] -anchor w -text [expr {$age == 0 ? "now" : "$age s ago"}] -fill [::tg::kit::col faint] -font $::tg::kit::F(small) -tags hover
    $c create text [expr {$bx + 14}] [expr {$by + 35}] -anchor w -text "Allowed  [::tg::fmtRate $ok]/s" -fill [::tg::kit::col chart1] -font $::tg::kit::F(bold) -tags hover
    $c create text [expr {$bx + 14}] [expr {$by + 54}] -anchor w -text "Blocked  [::tg::fmtRate $bl]/s" -fill [::tg::kit::col chart2] -font $::tg::kit::F(bold) -tags hover
}

# ------------------------------------------------------------- protection ----

proc ::tg::gui::buildProtection {} {
    variable v
    fr .main.top.act.protection .main.top.act -bg bg
    ::tg::kit::button .main.top.act.protection.add .main.top.act.protection "Add protection" -style primary -icon plus -command ::tg::gui::addWizard
    pack .main.top.act.protection.add
    set sc [::tg::kit::scroll .main.body.protection .main.body]
    set v(lstFrame) $sc
    fr $sc.list $sc -bg bg
    pack $sc.list -fill x
    fr $sc.hint $sc -bg bg
    pack $sc.hint -fill x -pady {6 24}
    set in [::tg::kit::card $sc.hint.c $sc.hint -fill warnSoft -border 0]
    pack $sc.hint.c -fill x
    fr $in.r $in -bg warnSoft
    pack $in.r -fill x -padx 16 -pady 14
    label $in.r.i -image [::tg::kit::icon info 20 warn] -background [::tg::kit::col warnSoft] -borderwidth 0
    tx $in.r.t $in.r "Your real server must not be reachable directly. Move it to a different port (or bind it to 127.0.0.1), then forward the public port on your router to this computer. Otherwise attackers can simply skip TclGuard." -font small -bg warnSoft -wrap 760
    pack $in.r.i -side left -anchor n
    pack $in.r.t -side left -padx {12 0}
}

proc ::tg::gui::typeIcon {t} { dict get {http globe tcp server udp gamepad} $t }

proc ::tg::gui::rebuildListeners {s} {
    variable v
    variable lstSig
    set list [dict get $s listeners]
    set sig {}
    foreach L $list { lappend sig [dict get $L name] [dict get $L enabled] [dict get $L port] [dict get $L backend] }
    if {$sig eq $lstSig} {
        foreach L $list { updateListenerRow $L }
        return
    }
    set lstSig $sig
    set lf $v(lstFrame).list
    foreach w [winfo children $lf] { destroy $w }
    array unset v lrow,*
    if {![llength $list]} {
        set in [::tg::kit::card $lf.empty $lf -radius 16]
        pack $lf.empty -fill x -pady {20 0}
        label $in.i -image [::tg::kit::icon shield 64 faint] -background [::tg::kit::col surface] -borderwidth 0
        tx $in.t $in "Nothing is protected yet" -font h2 -bg surface -anchor center
        tx $in.s $in "Pick your game or website and TclGuard starts guarding its port straight away." -font body -fg muted -bg surface -anchor center -wrap 460
        ::tg::kit::button $in.b $in "Add protection" -style primary -icon plus -command ::tg::gui::addWizard
        pack $in.i -pady {36 8}
        pack $in.t
        pack $in.s -pady {4 18}
        pack $in.b -pady {0 40}
        return
    }
    set cl [::tg::cfg::listeners]
    foreach L $list {
        set n [dict get $L name]
        set id [string map {. _ - _ : _} $n]
        set in [::tg::kit::card $lf.c_$id $lf]
        pack $lf.c_$id -fill x -pady {0 12}
        fr $in.r $in -bg surface
        pack $in.r -fill x -padx 18 -pady 16
        set tile [::tg::kit::card $in.r.tile $in.r -fill accentSoft -border 0 -radius 12]
        label $tile.i -image [::tg::kit::icon [typeIcon [dict get $L type]] 24 accent] -background [::tg::kit::col accentSoft] -borderwidth 0
        pack $tile.i -padx 12 -pady 12
        fr $in.r.info $in.r -bg surface
        set bindAddr [expr {[dict exists $cl $n] ? [dict get $cl $n bind] : "0.0.0.0"}]
        tx $in.r.info.n $in.r.info $n -font h3 -bg surface
        tx $in.r.info.a $in.r.info "[::tg::joinHostPort $bindAddr [dict get $L port]]  →  [dict get $L backend]" -font monosm -fg muted -bg surface
        pack $in.r.info.n -anchor w
        pack $in.r.info.a -anchor w -pady {3 0}
        fr $in.r.chips $in.r -bg surface
        ::tg::kit::chip $in.r.chips.t $in.r.chips [string toupper [dict get $L type]] -tone accent
        pack $in.r.chips.t -side left
        tx $in.r.cn $in.r "" -font small -fg muted -bg surface -anchor e
        set v(lrow,$n,en) [expr {[::tg::bool [dict get $L enabled]] ? 1 : 0}]
        ::tg::kit::toggle $in.r.sw $in.r ::tg::gui::v(lrow,$n,en) -command [list ::tg::gui::toggleListener $n]
        ::tg::kit::button $in.r.ed $in.r "Edit" -style secondary -icon edit -command [list ::tg::gui::editListener $n]
        ::tg::kit::button $in.r.rm $in.r "" -style ghost -icon trash -width 38 -command [list ::tg::gui::removeListener $n]
        pack $in.r.tile -side left
        pack $in.r.info -side left -padx {16 0}
        pack $in.r.rm -side right
        pack $in.r.ed -side right -padx {0 8}
        pack $in.r.sw -side right -padx {0 16}
        pack $in.r.cn -side right -padx {0 20}
        pack $in.r.chips -side right -padx {0 20}
        set v(lrow,$n) [list $in.r.chips $in.r.cn]
    }
    foreach L $list { updateListenerRow $L }
}

proc ::tg::gui::updateListenerRow {L} {
    variable v
    set n [dict get $L name]
    if {![info exists v(lrow,$n)]} return
    lassign $v(lrow,$n) chips cn
    if {![winfo exists $chips]} return
    set state [expr {![::tg::bool [dict get $L enabled]] ? "Disabled" : ([dict get $L running] ? "Protecting" : "Not running")}]
    set tone [expr {$state eq "Protecting" ? "ok" : ($state eq "Disabled" ? "muted" : "bad")}]
    if {![info exists v(lrowState,$n)] || $v(lrowState,$n) ne $state} {
        set v(lrowState,$n) $state
        catch {destroy $chips.s}
        ::tg::kit::chip $chips.s $chips $state -tone $tone -dot 1
        pack $chips.s -side left -padx {8 0}
    }
    $cn configure -text "[dict get $L conns] [expr {[dict get $L type] eq {udp} ? {sessions} : {connections}}]"
}

proc ::tg::gui::toggleListener {n} {
    variable v
    set c $::tg::cfg::current
    dict set c listeners $n enabled $v(lrow,$n,en)
    applyConfig $c
}

proc ::tg::gui::removeListener {n} {
    if {![ask "Remove protection" "Stop protecting '$n' and delete it from the configuration?"]} return
    set c $::tg::cfg::current
    dict unset c listeners $n
    applyConfig $c
}

proc ::tg::gui::applyConfig {c} {
    variable lstSig
    lassign [::tg::cfg::validate $c] errs warns
    if {[llength $errs]} { msg error "Cannot apply" [join $errs "\n\n"]; return 0 }
    ::tg::cfg::set_ $c
    if {[catch {::tg::cfg::save} err]} { msg warning "TclGuard" "Applied, but saving the configuration failed:\n$err" }
    ::tg::engine::reload
    set lstSig "force"
    array unset ::tg::gui::v lrowState,*
    refreshFwPreview
    if {[llength $warns]} { msg warning "Note" [join $warns "\n\n"] }
    refresh
    return 1
}

# ---- form rows shared by dialogs and settings ----

proc ::tg::gui::formRow {parent id label hint kind var args} {
    array set o {-values {} -bg surface -command "" -hintwrap 470 -fieldw 24}
    array set o $args
    set bg $o(-bg)
    fr $parent.$id $parent -bg $bg
    pack $parent.$id -fill x -padx 20 -pady 9
    fr $parent.$id.l $parent.$id -bg $bg
    tx $parent.$id.l.a $parent.$id.l $label -font bold -bg $bg
    pack $parent.$id.l.a -anchor w
    if {$hint ne ""} {
        tx $parent.$id.l.b $parent.$id.l $hint -font small -fg muted -bg $bg -wrap $o(-hintwrap)
        pack $parent.$id.l.b -anchor w -pady {2 0}
    }
    pack $parent.$id.l -side left -fill x -expand 1
    set w $parent.$id.c
    switch -- $kind {
        bool   { ::tg::kit::toggle $w $parent.$id $var -command $o(-command) }
        int    { ::tg::kit::stepper $w $parent.$id $var -width 7 -step 1 }
        num    { ::tg::kit::stepper $w $parent.$id $var -width 7 -step 0.05 -float 1 }
        choice { ::tg::kit::select $w $parent.$id $var $o(-values) -width 8 }
        default { ::tg::kit::field $w $parent.$id $var -width $o(-fieldw) }
    }
    pack $w -side right -padx {20 0}
}

# ----- edit dialog -----

proc ::tg::gui::listenerFields {type} {
    set common {
        {enabled "Enabled" bool "Turn protection for this port on or off."}
        {bind "Listen address" text "Which local address to accept connections on. 0.0.0.0 = every network card."}
        {port "Public port" int "The port players or visitors connect to. Forward this on your router."}
        {backendHost "Server address" text "Where your real server is (almost always 127.0.0.1)."}
        {backendPort "Server port" int "The port your real server listens on."}
        {note "Note" text "Free text for yourself."}
    }
    switch -- $type {
        http {
            set adv {
                {maxConnsPerIP "Connections per visitor" int "Simultaneous connections from one address. Browsers use up to ~6 per tab; offices share one address."}
                {connRate "New connections per visitor / 10 s" int "More than this in 10 seconds counts as a flood."}
                {reqRate "Requests per visitor / 10 s" int "A normal page load is 20-80 requests. Bots send thousands."}
                {headerTimeout "Seconds to send headers" int "Stops slow-loris attacks that drip headers forever. 0 = off."}
                {keepAliveTimeout "Idle keep-alive seconds" int "How long an idle connection may wait between requests."}
                {bodyTimeout "Seconds without upload data" int "Stops slow-POST attacks."}
                {maxBodyMB "Largest upload (MB)" int "Bigger requests are refused."}
                {maxConns "Max connections (this port)" int "Hard ceiling for this listener."}
                {challenge "Browser check" choice "auto: only while under attack. always: always. off: never. Unknown visitors must prove they keep cookies." {auto always off}}
                {forwardIp "Pass visitor address to server" bool "Adds X-Forwarded-For / X-Real-IP so your site sees the real address."}
                {trustedProxies "Trusted proxies" list "Only if TclGuard sits behind Cloudflare or another proxy: addresses allowed to name the real visitor."}
                {proxyProtocol "PROXY protocol" choice "Tell the server the real address via the PROXY protocol (server must support it)." {none v1 v2}}
            }
        }
        udp {
            set adv {
                {pps "Packets per second per player" int "Above this, packets are dropped. Games usually send 20-300/s."}
                {bytesPerSec "Bytes per second per player" int "Incoming bandwidth limit per player."}
                {maxSessionsPerIP "Sessions per player address" int "Several PCs behind one router need more than 1."}
                {newSessionRate "New sessions / 10 s" int "Join-spam limit."}
                {maxSessions "Max sessions (this port)" int "Hard ceiling."}
                {replyBytesPerSec "Reply bytes per second per player" int "Limits what the server can send back, so it cannot be abused as an amplifier."}
                {maxPacket "Largest packet (bytes)" int "Bigger packets are dropped."}
                {sessionTimeout "Session idle seconds" int "Forget a silent player after this long."}
                {banOffenders "Ban offenders" bool "Temporarily ban addresses that break the limits. Turn off if you fear spoofed addresses."}
            }
        }
        default {
            set adv {
                {maxConnsPerIP "Connections per player" int "Simultaneous connections from one address."}
                {connRate "New connections per player / 10 s" int "More than this counts as a flood."}
                {firstByteTimeout "Seconds to send first data" int "Silent connections are dropped and never reach your server. 0 = off."}
                {idleTimeout "Idle seconds" int "Close connections silent for this long. 0 = never."}
                {maxConns "Max connections (this port)" int "Hard ceiling."}
                {lazyConnect "Wait for first data" bool "Only connect to your server once the player has sent something. Turn OFF for services where the server speaks first (SSH, SMTP)."}
                {proxyProtocol "PROXY protocol" choice "Tell the server the real address via the PROXY protocol (server must support it)." {none v1 v2}}
            }
        }
    }
    list $common $adv
}

proc ::tg::gui::editListener {name} {
    variable v
    set spec [::tg::cfg::fillListener [dict get $::tg::cfg::current listeners $name]]
    set type [dict get $spec type]
    lassign [listenerFields $type] common adv
    set f [::tg::kit::dialog edit "Edit $name"]
    set t [winfo toplevel $f]
    fr $f.h $f -bg surface
    pack $f.h -fill x -padx 24 -pady {22 6}
    label $f.h.i -image [::tg::kit::icon [typeIcon $type] 26 accent] -background [::tg::kit::col surface] -borderwidth 0
    tx $f.h.t $f.h $name -font h2 -bg surface
    ::tg::kit::chip $f.h.c $f.h [string toupper $type] -tone accent
    pack $f.h.i -side left
    pack $f.h.t -side left -padx {10 10}
    pack $f.h.c -side left
    set v(edTab) basic
    ::tg::kit::segment $f.seg $f ::tg::gui::v(edTab) {{basic Basic} {limits {Limits and timeouts}}} -command [list ::tg::gui::editTab $f]
    pack $f.seg -anchor w -padx 24 -pady {8 8}
    foreach {tab fields} [list basic $common limits $adv] {
        set sc [::tg::kit::scroll $f.$tab $f]
        $f.$tab.c configure -width [::tg::kit::px 700] -height [::tg::kit::px 400]
        foreach fld $fields {
            lassign $fld key label kind hint choices
            set val [dict get $spec $key]
            if {$kind eq "bool"} { set val [expr {[::tg::bool $val] ? 1 : 0}] }
            if {$kind eq "list"} { set val [join $val " "] }
            set v(e,$key) $val
            formRow $sc $key $label $hint $kind ::tg::gui::v(e,$key) -values $choices -hintwrap 330 -fieldw 17
        }
    }
    pack $f.basic -fill both -expand 1
    fr $f.b $f -bg surface
    pack $f.b -fill x -padx 24 -pady {10 22}
    ::tg::kit::button $f.b.ok $f.b "Save and apply" -style primary -command [list ::tg::gui::saveListener $t $name $type [concat $common $adv]]
    ::tg::kit::button $f.b.c $f.b "Cancel" -style ghost -command [list destroy $t]
    pack $f.b.ok -side right
    pack $f.b.c -side right -padx {0 8}
    ::tg::kit::modal $t
}

proc ::tg::gui::editTab {f tab} {
    pack forget $f.basic $f.limits
    pack $f.$tab -fill both -expand 1 -before $f.b
}

proc ::tg::gui::saveListener {t name type fields} {
    variable v
    set spec [dict get $::tg::cfg::current listeners $name]
    foreach fld $fields {
        lassign $fld key label kind
        set val $v(e,$key)
        switch -- $kind {
            bool { set val [expr {[::tg::bool $val] ? 1 : 0}] }
            list { set val [::tg::ip::parseList $val] }
            default { set val [string trim $val] }
        }
        dict set spec $key $val
    }
    set c $::tg::cfg::current
    dict set c listeners $name $spec
    if {[applyConfig $c]} { destroy $t }
}

# ----- add wizard -----

proc ::tg::gui::presetSub {p} {
    set seen {}
    foreach s [dict get $::tg::cfg::presets($p) listeners] {
        set x "[string toupper [dict get $s type]] [dict get $s port]"
        if {$x ni $seen} { lappend seen $x }
    }
    join $seen " + "
}

proc ::tg::gui::presetIcon {p} {
    switch -glob -- $p {
        website* { return globe }
        ssh - custom-tcp { return terminal }
        default { return gamepad }
    }
}

proc ::tg::gui::addWizard {} {
    variable v
    set f [::tg::kit::dialog wiz "Add protection"]
    set t [winfo toplevel $f]
    tx $f.h $f "What do you want to protect?" -font h2 -bg surface
    pack $f.h -anchor w -padx 28 -pady {24 2}
    tx $f.s $f "Pick one. You can fine-tune every limit afterwards." -font body -fg muted -bg surface
    pack $f.s -anchor w -padx 28 -pady {0 14}
    fr $f.grid $f -bg surface
    pack $f.grid -padx 23
    set v(wizSel) [lindex $::tg::cfg::presetOrder 0]
    set v(wizPub) ""; set v(wizBackend) ""; set v(wizHost) 127.0.0.1
    fr $f.form $f -bg surface
    pack $f.form -fill x -padx 28 -pady {14 0}
    set v(wizFormParent) $f.form
    wizTiles $f
    wizForm $f
    fr $f.b $f -bg surface
    pack $f.b -fill x -padx 28 -pady {16 24}
    ::tg::kit::button $f.b.ok $f.b "Add protection" -style primary -icon plus -command [list ::tg::gui::wizAdd $t]
    ::tg::kit::button $f.b.c $f.b "Cancel" -style ghost -command [list destroy $t]
    pack $f.b.ok -side right
    pack $f.b.c -side right -padx {0 8}
    ::tg::kit::modal $t
}

proc ::tg::gui::wizTiles {f} {
    variable v
    foreach w [winfo children $f.grid] { destroy $w }
    set i 0
    foreach p $::tg::cfg::presetOrder {
        set sel [expr {$p eq $v(wizSel)}]
        set bg [expr {$sel ? "accentSoft" : "surface2"}]
        set tile [::tg::kit::card $f.grid.t$i $f.grid -fill $bg -radius 12 -border 0]
        grid $f.grid.t$i -row [expr {$i / 3}] -column [expr {$i % 3}] -padx 5 -pady 5 -sticky nsew
        fr $tile.r $tile -bg $bg
        pack $tile.r -fill x -padx 12 -pady 11
        label $tile.r.i -image [::tg::kit::icon [presetIcon $p] 22 [expr {$sel ? "accent" : "muted"}]] -background [::tg::kit::col $bg] -borderwidth 0
        fr $tile.r.t $tile.r -bg $bg
        tx $tile.r.t.a $tile.r.t [dict get $::tg::cfg::presets($p) title] -font bold -bg $bg -wrap 150 -fg [expr {$sel ? "accent" : "text"}]
        tx $tile.r.t.b $tile.r.t [presetSub $p] -font small -fg muted -bg $bg
        pack $tile.r.t.a -anchor w
        pack $tile.r.t.b -anchor w
        pack $tile.r.i -side left -anchor n
        pack $tile.r.t -side left -padx {10 0}
        foreach w [list $f.grid.t$i $tile $tile.r $tile.r.i $tile.r.t $tile.r.t.a $tile.r.t.b] {
            bind $w <ButtonRelease-1> [list ::tg::gui::wizPick $f $p]
            catch {$w configure -cursor hand2}
        }
        incr i
    }
    grid columnconfigure $f.grid {0 1 2} -weight 1 -uniform w
}

proc ::tg::gui::wizPick {f p} {
    variable v
    set v(wizSel) $p
    wizTiles $f
    wizForm $f
}

proc ::tg::gui::wizForm {f} {
    variable v
    set fm $v(wizFormParent)
    foreach w [winfo children $fm] { destroy $w }
    set pr $::tg::cfg::presets($v(wizSel))
    set specs [dict get $pr listeners]
    set multi [expr {[llength $specs] > 1}]
    set s [lindex $specs 0]
    set v(wizPub) [dict get $s port]; set v(wizBackend) [dict get $s backendPort]
    tx $fm.d $fm [dict get $pr description] -font small -fg muted -wrap 640
    pack $fm.d -anchor w -pady {0 10}
    if {$multi} {
        tx $fm.m $fm "This preset sets up [llength $specs] listeners with the standard ports. Edit them afterwards from the Protection page." -font body -bg surface -wrap 640
        pack $fm.m -anchor w
        return
    }
    fr $fm.r $fm -bg surface
    pack $fm.r -fill x
    foreach {id label kind var} {a "Players / visitors connect to port" int ::tg::gui::v(wizPub) b "Your real server listens on port" int ::tg::gui::v(wizBackend) c "...on this address" text ::tg::gui::v(wizHost)} {
        fr $fm.r.$id $fm.r -bg surface
        tx $fm.r.$id.l $fm.r.$id $label -font small -fg muted -bg surface
        if {$kind eq "int"} { ::tg::kit::stepper $fm.r.$id.e $fm.r.$id $var -width 6 -step 1 } else { ::tg::kit::field $fm.r.$id.e $fm.r.$id $var -width 14 }
        pack $fm.r.$id.l -anchor w
        pack $fm.r.$id.e -anchor w -pady {4 0}
        pack $fm.r.$id -side left -padx {0 16}
    }
}

proc ::tg::gui::wizAdd {t} {
    variable v
    set p $v(wizSel)
    set new [::tg::cfg::presetListeners $p [dict get $::tg::cfg::current listeners]]
    if {[llength [dict keys $new]] == 1} {
        set n [lindex [dict keys $new] 0]
        dict set new $n port [string trim $v(wizPub)]
        dict set new $n backendPort [string trim $v(wizBackend)]
        dict set new $n backendHost [string trim $v(wizHost)]
    }
    set c $::tg::cfg::current
    dict for {n s} $new { dict set c listeners $n $s }
    if {[applyConfig $c]} { destroy $t; showPage protection }
}

# -------------------------------------------------------------------- bans ----

proc ::tg::gui::buildBans {} {
    variable v
    fr .main.top.act.bans .main.top.act -bg bg
    ::tg::kit::button .main.top.act.bans.all .main.top.act.bans "Unban everyone" -style secondary -command ::tg::gui::unbanAll
    ::tg::kit::button .main.top.act.bans.add .main.top.act.bans "Ban an address" -style primary -icon ban -command ::tg::gui::banDialog
    pack .main.top.act.bans.add -side right
    pack .main.top.act.bans.all -side right -padx {0 8}
    set sc [::tg::kit::scroll .main.body.bans .main.body]
    set in [::tg::kit::card $sc.list $sc]
    pack $sc.list -fill x -pady {0 16}
    set v(banIn) $in
    fr $in.hd $in -bg surface
    pack $in.hd -fill x -padx 20 -pady {16 6}
    tx $in.hd.t $in.hd "Active bans" -font h3 -bg surface
    tx $in.hd.n $in.hd "" -font small -fg muted -bg surface
    pack $in.hd.t -side left
    pack $in.hd.n -side left -padx {10 0} -pady {3 0}
    fr $in.rows $in -bg surface
    pack $in.rows -fill x -padx 8 -pady {0 10}
    tx $in.none $in "No one is banned. Offenders are banned automatically, for longer each time they return." -font body -fg muted -bg surface
    set v(banNone) $in.none

    fr $sc.lists $sc -bg bg
    pack $sc.lists -fill x -pady {0 24}
    grid columnconfigure $sc.lists {0 1} -weight 1 -uniform b
    set i 0
    foreach {id title sub key} {allow "Never ban" "Your own devices, friends, monitoring. Never limited or banned." allowlist block "Always block" "Addresses or ranges that are always refused." blocklist} {
        set cin [::tg::kit::card $sc.lists.$id $sc.lists]
        grid $sc.lists.$id -row 0 -column $i -sticky nsew -padx [expr {$i == 0 ? {0 8} : {8 0}}]
        tx $cin.t $cin $title -font h3 -bg surface
        tx $cin.s $cin $sub -font small -fg muted -bg surface -wrap 340
        pack $cin.t -anchor w -padx 20 -pady {16 0}
        pack $cin.s -anchor w -padx 20 -pady {2 10}
        fr $cin.chips $cin -bg surface
        pack $cin.chips -fill x -padx 20
        set v(chips,$key) $cin.chips
        fr $cin.add $cin -bg surface
        pack $cin.add -fill x -padx 20 -pady {10 18}
        set v(add,$key) ""
        ::tg::kit::field $cin.add.f $cin.add ::tg::gui::v(add,$key) -width 18 -mono 1
        ::tg::kit::button $cin.add.b $cin.add "Add" -style secondary -icon plus -command [list ::tg::gui::listAdd $key]
        pack $cin.add.f -side left
        pack $cin.add.b -side left -padx {8 0}
        incr i
    }
}

proc ::tg::gui::refreshBans {} {
    variable v
    variable banSig
    variable banRows
    set rows [::tg::ban::all]
    set now [::tg::now]
    set sig {}
    foreach b $rows { lappend sig [dict get $b key] [dict get $b until] }
    set in $v(banIn)
    $in.hd.n configure -text [expr {[llength $rows] ? "[llength $rows] address[expr {[llength $rows] == 1 ? {} : {es}}]" : ""}]
    if {$sig ne $banSig} {
        set banSig $sig
        foreach w [winfo children $in.rows] { destroy $w }
        array unset banRows
        pack forget $v(banNone)
        if {![llength $rows]} {
            pack $v(banNone) -padx 20 -pady {4 22} -anchor w
        } else {
            set i 0
            foreach b [lrange $rows 0 149] {
                set k [dict get $b key]
                set rid r[incr i]
                set rw $in.rows.$rid
                fr $rw $in.rows -bg surface
                pack $rw -fill x
                if {$i > 1} { sep $rw.sep $rw; pack $rw.sep -fill x -padx 12 }
                fr $rw.in $rw -bg surface
                pack $rw.in -fill x -padx 12 -pady 9
                label $rw.in.i -image [::tg::kit::icon ban 18 bad] -background [::tg::kit::col surface] -borderwidth 0
                fr $rw.in.t $rw.in -bg surface
                tx $rw.in.t.a $rw.in.t $k -font mono -bg surface
                tx $rw.in.t.b $rw.in.t [dict get $b reason] -font small -fg muted -bg surface -wrap 440
                pack $rw.in.t.a -anchor w
                pack $rw.in.t.b -anchor w
                ::tg::kit::chip $rw.in.src $rw.in [dict get $b source]
                tx $rw.in.left $rw.in "" -font bold -bg surface -anchor e
                ::tg::kit::button $rw.in.un $rw.in "Unban" -style secondary -height 32 -command [list ::tg::gui::unban $k]
                pack $rw.in.i -side left -padx {6 12}
                pack $rw.in.t -side left
                pack $rw.in.un -side right -padx {0 6}
                pack $rw.in.left -side right -padx {0 18}
                pack $rw.in.src -side right -padx {0 18}
                set banRows($k) $rw.in.left
            }
        }
    }
    foreach b $rows {
        set k [dict get $b key]
        if {![info exists banRows($k)] || ![winfo exists $banRows($k)]} continue
        set until [dict get $b until]
        $banRows($k) configure -text [expr {$until == 0 ? "forever" : [::tg::fmtDuration [expr {($until - $now) / 1000}]]}]
    }
    foreach key {allowlist blocklist} {
        set items [::tg::cfg::general $key]
        set ch $v(chips,$key)
        if {![info exists v(chipSig,$key)] || $v(chipSig,$key) ne $items} {
            set v(chipSig,$key) $items
            foreach w [winfo children $ch] { destroy $w }
            set i 0
            set rowf ""
            foreach it $items {
                if {$i % 2 == 0} { set rowf $ch.row$i; fr $rowf $ch -bg surface; pack $rowf -anchor w -pady 3 }
                chipX $rowf.c$i $rowf $it [list ::tg::gui::listRemove $key $it]
                pack $rowf.c$i -side left -padx {0 6}
                incr i
            }
            if {![llength $items]} { tx $ch.none $ch "Nothing here yet." -font small -fg faint -bg surface; pack $ch.none -anchor w }
        }
    }
}

# removable chip: "text x"
proc ::tg::gui::chipX {path parent text cmd} {
    set F $::tg::kit::F(monosm)
    set h [::tg::kit::px 26]
    set tw [font measure $F $text]
    set w [expr {$tw + [::tg::kit::px 38]}]
    canvas $path -width $w -height $h -background [::tg::kit::bgOf $parent] -highlightthickness 0 -borderwidth 0 -cursor hand2
    ::tg::kit::roundRect $path 0 0 $w $h [expr {$h / 2}] [::tg::kit::col surface2] [::tg::kit::bgOf $parent]
    $path create text [::tg::kit::px 12] [expr {$h / 2}] -anchor w -text $text -fill [::tg::kit::col text] -font $F
    $path create image [expr {$w - [::tg::kit::px 14]}] [expr {$h / 2}] -image [::tg::kit::icon close 12 muted]
    bind $path <ButtonRelease-1> $cmd
    return $path
}

proc ::tg::gui::unban {k} { do unban $k; refresh }
proc ::tg::gui::unbanAll {} {
    if {[::tg::ban::count] == 0} return
    if {[ask "Unban everyone" "Remove all [::tg::ban::count] bans?"]} { do unbanall; refresh }
}
proc ::tg::gui::listAdd {key} {
    variable v
    set val [string trim $v(add,$key)]
    if {$val eq ""} return
    lassign [do [expr {$key eq "allowlist" ? "allow" : "block"}] $val] ok
    if {$ok} { set v(add,$key) ""; refresh }
}
proc ::tg::gui::listRemove {key item} {
    do [expr {$key eq "allowlist" ? "disallow" : "unblock"}] $item
    refresh
}

proc ::tg::gui::banDialog {} {
    variable v
    set f [::tg::kit::dialog ban "Ban an address"]
    set t [winfo toplevel $f]
    set v(banIp) ""; set v(banWhy) "manual ban"; set v(banFor) "1 day"
    tx $f.h $f "Ban an address" -font h2 -bg surface
    pack $f.h -anchor w -padx 28 -pady {24 12}
    tx $f.la $f "IP address or range" -font small -fg muted -bg surface
    pack $f.la -anchor w -padx 28
    ::tg::kit::field $f.ea $f ::tg::gui::v(banIp) -width 34 -mono 1
    pack $f.ea -anchor w -padx 28 -pady {4 12}
    tx $f.lc $f "Reason" -font small -fg muted -bg surface
    pack $f.lc -anchor w -padx 28
    ::tg::kit::field $f.ec $f ::tg::gui::v(banWhy) -width 34
    pack $f.ec -anchor w -padx 28 -pady {4 12}
    tx $f.lb $f "Ban for" -font small -fg muted -bg surface
    pack $f.lb -anchor w -padx 28
    ::tg::kit::segment $f.sg $f ::tg::gui::v(banFor) {{{1 hour} {1 hour}} {{1 day} {1 day}} {{1 week} {1 week}} {Forever Forever}}
    pack $f.sg -anchor w -padx 28 -pady {4 0}
    tx $f.ex $f "Examples: 203.0.113.5   or   203.0.113.0/24   or   2001:db8::/32" -font small -fg faint -bg surface
    pack $f.ex -anchor w -padx 28 -pady {12 0}
    fr $f.b $f -bg surface
    pack $f.b -fill x -padx 28 -pady {18 24}
    ::tg::kit::button $f.b.ok $f.b "Ban" -style danger -icon ban -command [list apply {{t} {
        set sec [dict get {{1 hour} 3600 {1 day} 86400 {1 week} 604800 Forever 0} $::tg::gui::v(banFor)]
        lassign [::tg::gui::do ban [string trim $::tg::gui::v(banIp)] $sec $::tg::gui::v(banWhy)] ok
        if {$ok} { destroy $t; ::tg::gui::refresh }
    }} $t]
    ::tg::kit::button $f.b.c $f.b "Cancel" -style ghost -command [list destroy $t]
    pack $f.b.ok -side right
    pack $f.b.c -side right -padx {0 8}
    ::tg::kit::modal $t
}

# ---------------------------------------------------------------- firewall ----

proc ::tg::gui::buildFirewall {} {
    variable v
    set sc [::tg::kit::scroll .main.body.firewall .main.body]
    set in [::tg::kit::card $sc.st $sc]
    pack $sc.st -fill x -pady {0 16}
    tx $in.t $in "Status" -font h3 -bg surface
    pack $in.t -anchor w -padx 20 -pady {16 4}
    foreach {k label} {backend "Firewall type" priv "Permissions" inst "Kernel rules" harden "Hardening" drops "Packets dropped in the kernel" err "Last problem"} {
        fr $in.$k $in -bg surface
        pack $in.$k -fill x -padx 20 -pady 7
        label $in.$k.i -image [::tg::kit::icon info 18 muted] -background [::tg::kit::col surface] -borderwidth 0
        tx $in.$k.l $in.$k $label -font body -fg muted -bg surface
        tx $in.$k.v $in.$k "-" -font bold -bg surface -anchor e -wrap 560
        pack $in.$k.i -side left
        pack $in.$k.l -side left -padx {10 0}
        pack $in.$k.v -side right
        set v(fw,$k) $in.$k
    }
    ::tg::kit::button $in.adm $in "Restart as administrator" -style secondary -icon shieldcheck -command ::tg::gui::restartAdmin
    set v(fwAdminBtn) $in.adm
    pack [fr $in.pad $in -bg surface] -pady 6

    set in2 [::tg::kit::card $sc.opt $sc]
    pack $sc.opt -fill x -pady {0 16}
    set v(fwHarden) [expr {[::tg::bool [::tg::cfg::general harden]] ? 1 : 0}]
    formRow $in2 harden "Kernel hardening" "Rate-limit new connections and packets per address, and drop malformed or fragmented packets, on your protected ports. Allowlisted addresses are exempt." bool ::tg::gui::v(fwHarden) -command ::tg::gui::fwHardenToggled
    fr $in2.b $in2 -bg surface
    pack $in2.b -fill x -padx 20 -pady {4 18}
    ::tg::kit::button $in2.b.i $in2.b "Install / update rules" -style primary -icon shieldcheck -command ::tg::gui::fwInstall
    ::tg::kit::button $in2.b.r $in2.b "Remove all rules" -style secondary -icon trash -command ::tg::gui::fwRemove
    pack $in2.b.i -side left
    pack $in2.b.r -side left -padx {8 0}

    set in3 [::tg::kit::card $sc.pv $sc]
    pack $sc.pv -fill x -pady {0 16}
    tx $in3.t $in3 "Rules TclGuard installs" -font h3 -bg surface
    pack $in3.t -anchor w -padx 20 -pady {16 8}
    text $in3.tx -height 12 -wrap none -background [::tg::kit::col field] -foreground [::tg::kit::col text] -relief flat -borderwidth 0 \
        -highlightthickness 0 -padx 12 -pady 10 -font $::tg::kit::F(monosm) -state disabled -insertbackground [::tg::kit::col text]
    pack $in3.tx -fill x -padx 20 -pady {0 18}
    set v(fwText) $in3.tx
    tx $sc.note $sc "A program like this can inspect thousands of connections a second, but a flood is millions of packets a second. The kernel drops those for almost no CPU, so TclGuard hands every ban to it. Needs administrator / root rights." -font small -fg muted -wrap 800
    pack $sc.note -anchor w -pady {0 24}
}

proc ::tg::gui::fwHardenToggled {} {
    variable v
    set c $::tg::cfg::current
    dict set c general harden [expr {$v(fwHarden) ? 1 : 0}]
    applyConfig $c
}
proc ::tg::gui::fwInstall {} {
    lassign [do fw install] ok res
    if {$ok} { msg info "Firewall" "Kernel rules installed." }
    refresh
}
proc ::tg::gui::fwRemove {} {
    if {![ask "Remove rules" "Remove all TclGuard rules from the operating-system firewall? Bans will then only be enforced by TclGuard itself."]} return
    do fw uninstall
    refresh
}

proc ::tg::gui::refreshFwPreview {} {
    variable v
    if {![info exists v(fwText)] || ![winfo exists $v(fwText)]} return
    set tx $v(fwText)
    $tx configure -state normal
    $tx delete 1.0 end
    $tx insert end [::tg::fw::preview]
    $tx configure -state disabled
}

proc ::tg::gui::fwRow {k ok text} {
    variable v
    set r $v(fw,$k)
    $r.v configure -text $text
    $r.i configure -image [::tg::kit::icon [expr {$ok == 1 ? "check" : ($ok == 0 ? "warn" : "info")}] 18 [expr {$ok == 1 ? "ok" : ($ok == 0 ? "warn" : "muted")}]]
}

# ---------------------------------------------------------------- activity ----

proc ::tg::gui::buildActivity {} {
    variable v
    fr .main.top.act.activity .main.top.act -bg bg
    set v(logf) 1
    ::tg::kit::button .main.top.act.activity.save .main.top.act.activity "Save" -style secondary -command ::tg::gui::saveLog
    ::tg::kit::button .main.top.act.activity.clr .main.top.act.activity "Clear" -style secondary -command ::tg::gui::clearLog
    ::tg::kit::segment .main.top.act.activity.seg .main.top.act.activity ::tg::gui::v(logf) {{0 Everything} {1 Info} {2 Warnings} {3 Alerts}} -command ::tg::gui::reloadLog
    pack .main.top.act.activity.clr .main.top.act.activity.save -side right
    pack .main.top.act.activity.seg -side right -padx {0 8}
    fr .main.body.activity .main.body -bg bg
    set in [::tg::kit::card .main.body.activity.c .main.body.activity]
    pack .main.body.activity.c -fill both -expand 1 -pady {0 24}
    text $in.tx -wrap word -background [::tg::kit::col surface] -foreground [::tg::kit::col text] -relief flat -borderwidth 0 \
        -highlightthickness 0 -padx 18 -pady 14 -font $::tg::kit::F(monosm) -state disabled -cursor arrow -spacing1 3
    ttk::scrollbar $in.sb -orient vertical -style Kit.Vertical.TScrollbar -command "$in.tx yview"
    $in.tx configure -yscrollcommand "$in.sb set"
    pack $in.sb -side right -fill y -padx {0 4} -pady 8
    pack $in.tx -fill both -expand 1 -padx 4 -pady 4
    foreach {tag col} {debug faint info text warn warn alert bad time faint} { $in.tx tag configure $tag -foreground [::tg::kit::col $col] }
    set v(logTx) $in.tx
    ::tg::log::addSink ::tg::gui::logSink
}

proc ::tg::gui::logSink {ms lvl text} {
    variable v
    if {![info exists v(logTx)] || ![winfo exists $v(logTx)]} return
    if {[dict get {debug 0 info 1 warn 2 alert 3} $lvl] < $v(logf)} return
    set tx $v(logTx)
    $tx configure -state normal
    $tx insert end "[::tg::fmtTime $ms %H:%M:%S]  " time
    $tx insert end "[format %-5s [string toupper $lvl]]  $text\n" $lvl
    if {[$tx count -lines 1.0 end] > 3000} { $tx delete 1.0 500.0 }
    $tx see end
    $tx configure -state disabled
}
proc ::tg::gui::reloadLog {args} {
    variable v
    $v(logTx) configure -state normal
    $v(logTx) delete 1.0 end
    $v(logTx) configure -state disabled
    foreach e [::tg::log::tail 3000 debug] { logSink {*}$e }
}
proc ::tg::gui::clearLog {} {
    variable v
    $v(logTx) configure -state normal
    $v(logTx) delete 1.0 end
    $v(logTx) configure -state disabled
}
proc ::tg::gui::saveLog {} {
    variable v
    set f [tk_getSaveFile -parent . -defaultextension .log -initialfile tclguard-log.txt]
    if {$f eq ""} return
    set fh [open $f w]
    puts -nonewline $fh [$v(logTx) get 1.0 end]
    close $fh
}

# ---------------------------------------------------------------- settings ----

proc ::tg::gui::settingsSpec {} {
    list \
      {Bans {Strikes add up when an address breaks a limit. At the threshold it is banned, for longer each time it returns.} {
        {strikeThreshold "Strikes before a ban" int "Each limit violation adds a strike (bad requests add 1-2)."}
        {strikeLeakPerSec "Strikes forgiven per second" num "Strikes fade over time so occasional slips are forgiven."}
        {banSteps "Ban lengths (seconds)" list "First ban, second ban, third... Example: 60 600 3600 21600 86400"}
        {banResetAfter "Forget offences after (seconds)" int "A well-behaved address starts again from the first ban length."}}} \
      {{Threat level} {TclGuard raises its guard when traffic looks like an attack and relaxes when it ends.} {
        {autoLevel "Adjust automatically" bool "Tighten limits when traffic looks hostile, relax when it ends."}
        {autoLockdown "Allow automatic lockdown" bool "At extreme load, admit only addresses that behaved well before. Can lock out new players."}
        {linkMbps "Your download speed (Mbit/s)" int "Used to judge how full your connection is."}
        {levelCalmSec "Calm seconds before relaxing" int "How long traffic must stay normal before the level drops one step."}
        {learnTrusted "Remember well-behaved visitors" bool "Addresses with long, healthy sessions are remembered for lockdown mode."}}} \
      {{Logging and control} {} {
        {logLevel "Log detail" choice "debug is very chatty." {debug info warn alert}}
        {controlEnable "Allow command-line control" bool "Lets 'tclguard ctl ...' manage this running instance (this computer only)."}}}
}

proc ::tg::gui::buildSettings {} {
    variable v
    fr .main.top.act.settings .main.top.act -bg bg
    ::tg::kit::button .main.top.act.settings.rv .main.top.act.settings "Revert" -style secondary -command ::tg::gui::loadSettings
    ::tg::kit::button .main.top.act.settings.ok .main.top.act.settings "Save and apply" -style primary -icon check -command ::tg::gui::saveSettings
    pack .main.top.act.settings.ok -side right
    pack .main.top.act.settings.rv -side right -padx {0 8}
    settingsVars
    set sc [::tg::kit::scroll .main.body.settings .main.body]
    # startup + folders: everything a terminal would otherwise be needed for
    set su [::tg::kit::card $sc.startup $sc]
    pack $sc.startup -fill x -pady {0 16}
    tx $su.t $su "Startup" -font h3 -bg surface
    pack $su.t -anchor w -padx 20 -pady {16 0}
    set v(autostart) [::tg::autostart::status]
    formRow $su auto "Start TclGuard when I sign in" "Protection resumes by itself after a reboot. On Windows this creates a scheduled task (elevated when TclGuard has administrator rights)." bool ::tg::gui::v(autostart) -command ::tg::gui::autostartToggled
    fr $su.b $su -bg surface
    pack $su.b -fill x -padx 20 -pady {4 18}
    ::tg::kit::button $su.b.d $su.b "Open data folder" -style secondary -icon server -command [list ::tg::gui::openFolder [::tg::cfg::stateDir]]
    ::tg::kit::button $su.b.c $su.b "Open settings folder" -style secondary -icon sliders -command [list ::tg::gui::openFolder [file dirname $::tg::cfg::path]]
    pack $su.b.d -side left
    pack $su.b.c -side left -padx {8 0}
    set n 0
    foreach grp [settingsSpec] {
        lassign $grp title sub rows
        set in [::tg::kit::card $sc.g$n $sc]
        pack $sc.g$n -fill x -pady {0 16}
        tx $in.t $in $title -font h3 -bg surface
        pack $in.t -anchor w -padx 20 -pady {16 0}
        if {$sub ne ""} { tx $in.s $in $sub -font small -fg muted -bg surface -wrap 700; pack $in.s -anchor w -padx 20 -pady {2 4} }
        foreach r $rows {
            lassign $r key label kind hint choices
            formRow $in $key $label $hint $kind ::tg::gui::v(s,$key) -values $choices
        }
        pack [fr $in.end $in -bg surface] -pady 5
        incr n
    }
    tx $sc.path $sc "" -font small -fg faint -wrap 900
    pack $sc.path -anchor w -pady {0 24}
    set v(settingsPath) $sc.path
    loadSettings
}

proc ::tg::gui::loadSettings {} {
    variable v
    settingsVars
    $v(settingsPath) configure -text "Configuration file: $::tg::cfg::path      State folder: [::tg::cfg::stateDir]"
}

proc ::tg::gui::settingsVars {} {
    variable v
    foreach grp [settingsSpec] {
        foreach r [lindex $grp 2] {
            lassign $r key label kind
            set val [::tg::cfg::general $key]
            if {$kind eq "bool"} { set val [expr {[::tg::bool $val] ? 1 : 0}] }
            if {$kind eq "list"} { set val [join $val " "] }
            set v(s,$key) $val
        }
    }
}

proc ::tg::gui::saveSettings {} {
    variable v
    set c $::tg::cfg::current
    foreach grp [settingsSpec] {
        foreach r [lindex $grp 2] {
            lassign $r key label kind
            set val $v(s,$key)
            switch -- $kind {
                bool { set val [expr {[::tg::bool $val] ? 1 : 0}] }
                list { set val [::tg::ip::parseList $val] }
                default { set val [string trim $val] }
            }
            dict set c general $key $val
        }
    }
    if {[applyConfig $c]} { loadSettings }
}

# -------------------------------------------------------------------- help ----

proc ::tg::gui::buildHelp {} {
    set sc [::tg::kit::scroll .main.body.help .main.body]
    set tin [::tg::kit::card $sc.test $sc -fill accentSoft -border 0]
    pack $sc.test -fill x -pady {0 16}
    fr $tin.r $tin -bg accentSoft
    pack $tin.r -fill x -padx 20 -pady 16
    label $tin.r.i -image [::tg::kit::icon shieldcheck 28 accent] -background [::tg::kit::col accentSoft] -borderwidth 0
    fr $tin.r.t $tin.r -bg accentSoft
    tx $tin.r.t.h $tin.r.t "Check that it really works" -font h3 -bg accentSoft
    tx $tin.r.t.b $tin.r.t "Runs a private copy of TclGuard on spare ports and attacks it with floods, broken requests and slow-drip connections. Nothing on your computer or network is changed." -font small -fg muted -bg accentSoft -wrap 600
    pack $tin.r.t.h -anchor w
    pack $tin.r.t.b -anchor w -pady {2 0}
    ::tg::kit::button $tin.r.b $tin.r "Run self-test" -style primary -icon activity -command ::tg::gui::selfTest
    pack $tin.r.i -side left -anchor n
    pack $tin.r.t -side left -padx {14 0}
    pack $tin.r.b -side right
    set in [::tg::kit::card $sc.start $sc]
    pack $sc.start -fill x -pady {0 16}
    tx $in.t $in "Getting started" -font h3 -bg surface
    pack $in.t -anchor w -padx 20 -pady {16 6}
    set n 1
    foreach {head body} {
        "Move your real server out of the way" "Make it listen on a private port (for example Minecraft on 25566 instead of 25565) or only on 127.0.0.1. TclGuard takes the public port. If the real server stays directly reachable, attackers simply skip TclGuard."
        "Add protection" "Open Protection, press Add protection, pick your game or Website and check the two port numbers. It takes effect immediately."
        "Forward the public port on your router" "Forward the public port to this computer. Test from outside your home network (mobile data), not from inside it."
        "Turn on the kernel firewall" "On the Firewall page, install the rules. Start TclGuard as administrator (Windows) or with sudo (Linux) for this. It stops floods before they cost any CPU."} {
        fr $in.s$n $in -bg surface
        pack $in.s$n -fill x -padx 20 -pady 8
        canvas $in.s$n.b -width [::tg::kit::px 30] -height [::tg::kit::px 30] -background [::tg::kit::col surface] -highlightthickness 0 -borderwidth 0
        $in.s$n.b create image 0 0 -anchor nw -image [::tg::kit::disc [::tg::kit::col accentSoft] [::tg::kit::px 30]]
        $in.s$n.b create text [expr {[::tg::kit::px 30] / 2}] [expr {[::tg::kit::px 30] / 2}] -text $n -fill [::tg::kit::col accent] -font $::tg::kit::F(bold)
        fr $in.s$n.t $in.s$n -bg surface
        tx $in.s$n.t.h $in.s$n.t $head -font bold -bg surface
        tx $in.s$n.t.b $in.s$n.t $body -font body -fg muted -bg surface -wrap 760
        pack $in.s$n.t.h -anchor w
        pack $in.s$n.t.b -anchor w -pady {2 0}
        pack $in.s$n.b -side left -anchor n
        pack $in.s$n.t -side left -padx {14 0}
        incr n
    }
    pack [fr $in.end $in -bg surface] -pady 8

    set w [::tg::kit::card $sc.warn $sc -fill warnSoft -border 0]
    pack $sc.warn -fill x -pady {0 16}
    fr $w.r $w -bg warnSoft
    pack $w.r -fill x -padx 20 -pady 18
    label $w.r.i -image [::tg::kit::icon warn 24 warn] -background [::tg::kit::col warnSoft] -borderwidth 0
    fr $w.r.t $w.r -bg warnSoft
    tx $w.r.t.h $w.r.t "It cannot stop a flood that fills your internet connection" -font bold -bg warnSoft
    tx $w.r.t.b $w.r.t "If an attacker sends more traffic than your home connection can carry (500 Mbit/s into a 100 Mbit/s line), your router drowns before any software on your PC sees the packets. Only your ISP, or a provider with a bigger network, can fix that.\n\nRealistic options: run TclGuard on a cheap VPS with DDoS protection and forward to your home server over WireGuard (your home IP stays secret); put a website behind a CDN and list its addresses under Trusted proxies; or ask your ISP for a new IP address and keep it private." -font body -bg warnSoft -wrap 740
    pack $w.r.t.h -anchor w
    pack $w.r.t.b -anchor w -pady {4 0}
    pack $w.r.i -side left -anchor n
    pack $w.r.t -side left -padx {14 0}

    set in [::tg::kit::card $sc.lv $sc]
    pack $sc.lv -fill x -pady {0 16}
    tx $in.t $in "Threat levels" -font h3 -bg surface
    pack $in.t -anchor w -padx 20 -pady {16 6}
    foreach {tone name desc} {
        ok Normal "Standard limits."
        warn Elevated "Per-visitor limits shrink automatically."
        bad {Under attack} "Limits shrink further, and websites ask unknown visitors to pass a cookie check."
        violet Lockdown "Only addresses that behaved well before get in. A last resort: new players cannot join."} {
        fr $in.l$tone $in -bg surface
        pack $in.l$tone -fill x -padx 20 -pady 5
        ::tg::kit::chip $in.l$tone.c $in.l$tone $name -tone $tone -dot 1
        tx $in.l$tone.d $in.l$tone $desc -font body -fg muted -bg surface
        pack $in.l$tone.c -side left
        pack $in.l$tone.d -side left -padx {12 0}
    }
    pack [fr $in.end $in -bg surface] -pady 6

    set in [::tg::kit::card $sc.cli $sc]
    pack $sc.cli -fill x -pady {0 24}
    tx $in.t $in "Locked yourself out? Command line" -font h3 -bg surface
    pack $in.t -anchor w -padx 20 -pady {16 6}
    tx $in.d $in "Addresses under Bans > Never ban are never limited or banned (your home network is already covered). On a server without a screen TclGuard runs without this window; manage it with:" -font body -fg muted -bg surface -wrap 780
    pack $in.d -anchor w -padx 20
    text $in.code -height 5 -wrap none -background [::tg::kit::col field] -foreground [::tg::kit::col text] -relief flat -borderwidth 0 \
        -highlightthickness 0 -padx 12 -pady 10 -font $::tg::kit::F(monosm)
    $in.code insert end "tclguard ctl status\ntclguard ctl ban 203.0.113.5 3600 spamming\ntclguard ctl unban 203.0.113.5\ntclguard ctl level 2"
    $in.code configure -state disabled
    pack $in.code -fill x -padx 20 -pady {10 18}
}

# ----------------------------------------------------------------- refresh ----

proc ::tg::gui::refresh {} {
    variable v
    variable snap
    variable page
    variable hist
    if {[catch {set snap [::tg::engine::snapshot]} err]} return
    set s $snap
    set running [dict get $s running]
    set lv [dict get $s level]
    set rates [dict get $s rates]
    set cnt [dict get $s counters]

    set v(running) [expr {$running ? 1 : 0}]
    $v(statusLabel) configure -text [expr {$running ? "Checking every connection" : "Paused: nothing is checked"}]
    set v(lvl) [expr {[dict get $lv manual] ? [dict get $lv level] : "auto"}]

    switch -- $page {
        overview {
            drawHero $s
            set fwst [dict get $s firewall]
            set needAdmin [expr {![dict get $fwst privileged] && [llength [dict get $fwst available]] > 0 && [::tg::cfg::general firewall] ne "none"}]
            if {$needAdmin && ![winfo ismapped $v(adminBanner)]} {
                pack $v(adminBanner) -fill x -pady {0 16} -before .main.body.overview.c.f.hero
            } elseif {!$needAdmin && [winfo ismapped $v(adminBanner)]} {
                pack forget $v(adminBanner)
            }
            set totalConn [expr {[dict get $s connections] + [dict get $s udpSessions]}]
            foreach {id val sub} [list \
                conns $totalConn "[dict get $s connections] TCP, [dict get $s udpSessions] UDP" \
                allowed [::tg::fmtRate [dict get $rates ok]] "[::tg::fmtRate [dict get $cnt ok]] since start" \
                blocked [::tg::fmtRate [dict get $rates blocked]] "[::tg::fmtRate [dict get $cnt blocked]] since start" \
                bans [dict get $s bans] "[dict get $cnt bans] banned since start"] {
                set in $v(m,$id)
                $in.v configure -text $val -foreground [::tg::kit::col [expr {$id eq "blocked" && [dict get $rates blocked] > 0 ? "bad" : "text"}]]
                $in.s configure -text $sub
            }
            foreach {id cur} [list conns $totalConn allowed [dict get $rates ok] blocked [dict get $rates blocked] bans [dict get $s bans]] {
                lappend hist($id) $cur
                if {[llength $hist($id)] > 60} { set hist($id) [lrange $hist($id) end-59 end] }
                spark $v(m,$id).sp $hist($id) [expr {$id eq "blocked" ? "chart2" : ($id eq "bans" ? "violet" : "chart1")}]
            }
            drawChart
            set tin $v(top)
            set top [dict get $s top]
            set maxv 1
            foreach r $top { set tot [expr {[lindex $r 1] + [lindex $r 2]}]; if {$tot > $maxv} { set maxv $tot } }
            pack forget $tin.empty
            for {set i 0} {$i < 6} {incr i} {
                if {$i < [llength $top]} {
                    lassign [lindex $top $i] ip ok bl by
                    $tin.r$i.ip configure -text $ip
                    $tin.r$i.n configure -text "$ok ok · $bl blocked"
                    set bar $tin.r$i.bar
                    set bw [::tg::kit::px 110]; set bh [::tg::kit::px 8]
                    $bar delete all
                    set okw [expr {int($bw * $ok / double($maxv))}]; set blw [expr {int($bw * $bl / double($maxv))}]
                    $bar create rectangle 0 0 $bw $bh -fill [::tg::kit::col track] -outline ""
                    if {$okw > 0} { $bar create rectangle 0 0 $okw $bh -fill [::tg::kit::col chart1] -outline "" }
                    if {$blw > 0} { $bar create rectangle $okw 0 [expr {$okw + $blw}] $bh -fill [::tg::kit::col chart2] -outline "" }
                    pack $tin.r$i -fill x -padx 20 -pady 6
                } else { pack forget $tin.r$i }
            }
            if {![llength $top]} { pack $tin.empty -anchor w -padx 20 -pady {10 20} }
            set ain $v(act)
            set shown 0
            for {set i 0} {$i < 6} {incr i} { pack forget $ain.r$i }
            pack forget $ain.empty
            foreach e [lreverse [::tg::log::tail 200 info]] {
                lassign $e ms lvl text
                if {$lvl eq "info" && ![regexp {unbanned|threat level|restored|stopped} $text]} continue
                set i $shown
                set dot [dict get {info muted warn warn alert bad debug muted} $lvl]
                $ain.r$i.d configure -image [::tg::kit::disc [::tg::kit::col $dot] [::tg::kit::px 8]]
                $ain.r$i.x configure -text $text
                $ain.r$i.w configure -text [::tg::fmtTime $ms %H:%M:%S]
                pack $ain.r$i -fill x -padx 20 -pady 5
                if {[incr shown] >= 6} break
            }
            if {$shown == 0} { pack $ain.empty -anchor w -padx 20 -pady {10 20} }
        }
        protection { rebuildListeners $s }
        bans { refreshBans }
        firewall {
            set fw [dict get $s firewall]
            fwRow backend [expr {[dict get $fw backend] ne "none"}] [expr {[dict get $fw backend] eq "none" ? "none (available: [join [dict get $fw available] {, }])" : [dict get $fw backend]}]
            fwRow priv [dict get $fw privileged] [expr {[dict get $fw privileged] ? "administrator / root" : "standard user: restart TclGuard as administrator/root"}]
            fwRow inst [dict get $fw installed] [expr {[dict get $fw installed] ? "installed, bans enforced in the kernel" : "not installed"}]
            fwRow harden [dict get $fw hardened] [expr {[dict get $fw hardened] ? "on" : "off"}]
            fwRow drops 2 [::tg::fmtRate [dict get $cnt kernelDrop]]
            if {![dict get $fw privileged] && [llength [dict get $fw available]] > 0} {
                if {![winfo ismapped $v(fwAdminBtn)]} { pack $v(fwAdminBtn) -anchor w -padx 20 -pady {8 4} }
            } else { pack forget $v(fwAdminBtn) }
            fwRow err [expr {[dict get $fw error] eq ""}] [expr {[dict get $fw error] eq "" ? "none" : [dict get $fw error]}]
        }
    }
}

# ---- actions that would otherwise need a terminal ----

proc ::tg::gui::restartAdmin {} {
    if {![ask "Restart as administrator" "TclGuard will close and reopen with administrator rights so it can control the operating-system firewall.\n\nYour protection pauses for a few seconds. Continue?"]} return
    # free the listening ports first, so the elevated copy can take them
    ::tg::engine::stop
    set err [::tg::autostart::relaunchAsAdmin]
    if {$err eq ""} {
        after 800 {set ::tg::quit 1}
        return
    }
    ::tg::engine::start
    msg warning "TclGuard" $err
    refresh
}

proc ::tg::gui::autostartToggled {} {
    variable v
    set want $v(autostart)
    set err [expr {$want ? [::tg::autostart::enable] : [::tg::autostart::disable]}]
    if {$err ne ""} {
        msg error "TclGuard" $err
        set v(autostart) [::tg::autostart::status]
    }
}

proc ::tg::gui::openFolder {path} {
    if {[catch {::tg::autostart::openFolder $path} err]} { msg error "TclGuard" $err }
}

# Run the built-in attack simulation in a separate process (it starts its own engine, which must
# not touch the live one) and show its output as it arrives.
proc ::tg::gui::selfTest {} {
    variable v
    set f [::tg::kit::dialog selftest "Self-test"]
    set t [winfo toplevel $f]
    tx $f.h $f "Self-test" -font h2 -bg surface
    pack $f.h -anchor w -padx 24 -pady {22 2}
    tx $f.s $f "Attacking a private copy of TclGuard. This takes about 30 seconds." -font body -fg muted -bg surface
    pack $f.s -anchor w -padx 24 -pady {0 12}
    text $f.tx -width 86 -height 24 -wrap word -background [::tg::kit::col field] -foreground [::tg::kit::col text] -relief flat \
        -borderwidth 0 -highlightthickness 0 -padx 14 -pady 10 -font $::tg::kit::F(monosm) -state disabled -cursor arrow
    foreach {tag col} {pass ok fail bad skip warn dim faint} { $f.tx tag configure $tag -foreground [::tg::kit::col $col] }
    pack $f.tx -padx 24 -fill both -expand 1
    fr $f.b $f -bg surface
    pack $f.b -fill x -padx 24 -pady {14 22}
    tx $f.b.v $f.b "Running..." -font bold -bg surface
    ::tg::kit::button $f.b.c $f.b "Close" -style primary -command [list destroy $t]
    pack $f.b.v -side left
    pack $f.b.c -side right
    set v(stText) $f.tx; set v(stVerdict) $f.b.v
    set v(stPass) 0; set v(stFail) 0
    set cmd [::tg::autostart::selfCommand selftest]
    if {[catch {open [concat | $cmd [list 2>@1]] r} ch]} {
        msg error "TclGuard" "Could not start the self-test: $ch"
        destroy $t
        return
    }
    fconfigure $ch -blocking 0 -buffering line -encoding utf-8
    fileevent $ch readable [list ::tg::gui::selfTestRead $ch]
    bind $t <Destroy> [list apply {{ch w} { if {$w eq {.selftest}} { catch {fileevent $ch readable {}}; catch {close $ch} } }} $ch %W]
    ::tg::kit::modal $t
}

proc ::tg::gui::selfTestRead {ch} {
    variable v
    if {![info exists v(stText)] || ![winfo exists $v(stText)]} { catch {close $ch}; return }
    set tx $v(stText)
    while {[gets $ch line] >= 0} {
        set tag [expr {[string match "*PASS*" $line] ? "pass" : ([string match "*FAIL*" $line] ? "fail" : ([string match "*SKIP*" $line] ? "skip" : ([string match "        *" $line] ? "dim" : "")))}]
        if {$tag eq "pass"} { incr v(stPass) } elseif {$tag eq "fail"} { incr v(stFail) }
        $tx configure -state normal
        $tx insert end "$line\n" $tag
        $tx see end
        $tx configure -state disabled
    }
    if {[eof $ch]} {
        catch {close $ch}
        if {[winfo exists $v(stVerdict)]} {
            if {$v(stFail) == 0 && $v(stPass) > 0} {
                $v(stVerdict) configure -text "All $v(stPass) checks passed. The protections work on this computer." -foreground [::tg::kit::col ok]
            } else {
                $v(stVerdict) configure -text "$v(stFail) check(s) failed. See the output above." -foreground [::tg::kit::col bad]
            }
        }
    }
}

proc ::tg::gui::setLevel {val} {
    do level $val
    refresh
}

proc ::tg::gui::toggleRun {} {
    variable v
    if {$::tg::engine::running} {
        if {![ask "Pause protection" "While paused, nothing is checked or blocked and your server is exposed directly (if its port is reachable).\n\nPause?"]} {
            set v(running) 1
            return
        }
        ::tg::engine::stop
    } else {
        ::tg::engine::start
    }
    set v(running) [expr {$::tg::engine::running ? 1 : 0}]
    refresh
}

proc ::tg::gui::setTheme {t} {
    variable page
    variable banSig
    variable lstSig
    variable v
    if {$t eq $::tg::kit::theme} return
    set c $::tg::cfg::current
    dict set c general theme $t
    ::tg::cfg::set_ $c
    catch {::tg::cfg::save}
    ::tg::kit::init $t
    set banSig ""; set lstSig ""
    array unset v chipSig*
    array unset v lrowState,*
    build
    showPage $page
    reloadLog
    refreshFwPreview
}

proc ::tg::gui::tick {} {
    refresh
    after 1000 ::tg::gui::tick
}

proc ::tg::gui::quit {} {
    if {$::tg::engine::running} {
        if {![ask "Quit TclGuard" "Closing this window stops protection. Quit anyway?\n\n(Tip: on a server, run 'tclguard --headless' so it needs no window.)"]} return
    }
    catch {::tg::engine::stop}
    set ::tg::quit 1
}

proc ::tg::gui::run {} {
    variable v
    package require Tk
    ::tg::kit::init [::tg::cfg::general theme]
    wm geometry . 1280x820
    wm minsize . 1060 700
    wm protocol . WM_DELETE_WINDOW ::tg::gui::quit
    wm deiconify .
    build
    ::tg::engine::start
    showPage overview
    reloadLog
    refreshFwPreview
    tick
    if {[dict size [::tg::cfg::listeners]] == 0} {
        after 500 {
            if {[::tg::gui::ask "Welcome to TclGuard" "Nothing is protected yet.\n\nSet up protection for a game server or website now?"]} {
                ::tg::gui::showPage protection
                ::tg::gui::addWizard
            }
        }
    }
    vwait ::tg::quit
}
