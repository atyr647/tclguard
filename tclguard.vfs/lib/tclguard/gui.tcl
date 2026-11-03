# gui.tcl -- Tk control window.
#
# The GUI is a thin skin over ::tg::engine: it reads ::tg::engine::snapshot once
# a second and changes things only through ::tg::engine::cmd / the config API,
# so everything it can do is also possible from the CLI.

namespace eval ::tg::gui {
    variable P                ;# palette
    array set P {
        bg      #11141b   panel   #1a1f2b   panel2  #232a3a   border  #2e374b
        text    #e8ebf2   muted   #8e98ad   accent  #4f9dff   accent2 #3a7fd9
        ok      #35c27a   warn    #f0b429   bad     #ef5350   grid    #2a3245
        sel     #2b3b5c
    }
    variable snap {}
    variable tab dashboard
    variable lastBanSig ""
    variable lastListenerSig ""
    variable tipWin ""
    variable tipJob ""
    variable fonts
    variable v                ;# bound variables for widgets
    array set v {}
}

# ------------------------------------------------------------------ theme ----

proc ::tg::gui::theme {} {
    variable P
    variable fonts
    set fam [dict get [font actual TkDefaultFont] -family]
    font configure TkDefaultFont -size 10
    font configure TkTextFont -size 10
    font configure TkFixedFont -size 10
    set fonts(base) TkDefaultFont
    set fonts(big)   [font create tgBig   -family $fam -size 24 -weight bold]
    set fonts(med)   [font create tgMed   -family $fam -size 13 -weight bold]
    set fonts(small) [font create tgSmall -family $fam -size 9]
    set fonts(bold)  [font create tgBold  -family $fam -size 10 -weight bold]
    set fonts(title) [font create tgTitle -family $fam -size 17 -weight bold]

    ttk::style theme use clam
    ttk::style configure . -background $P(bg) -foreground $P(text) -fieldbackground $P(panel2) \
        -bordercolor $P(border) -lightcolor $P(border) -darkcolor $P(border) -troughcolor $P(panel) \
        -focuscolor $P(accent) -insertcolor $P(text) -selectbackground $P(sel) -selectforeground $P(text)
    ttk::style configure TFrame -background $P(bg)
    ttk::style configure Panel.TFrame -background $P(panel)
    ttk::style configure Card.TFrame -background $P(panel) -relief flat
    ttk::style configure TLabel -background $P(bg) -foreground $P(text)
    ttk::style configure Panel.TLabel -background $P(panel)
    ttk::style configure Muted.TLabel -foreground $P(muted)
    ttk::style configure PanelMuted.TLabel -background $P(panel) -foreground $P(muted)
    ttk::style configure Big.TLabel -font tgBig -background $P(panel)
    ttk::style configure Med.TLabel -font tgMed
    ttk::style configure Title.TLabel -font tgTitle
    ttk::style configure H.TLabel -font tgBold -background $P(bg)
    ttk::style configure PH.TLabel -font tgBold -background $P(panel)
    ttk::style configure Small.TLabel -font tgSmall -foreground $P(muted)
    ttk::style configure PSmall.TLabel -font tgSmall -foreground $P(muted) -background $P(panel)

    ttk::style configure TButton -background $P(panel2) -foreground $P(text) -padding {14 6} -borderwidth 1 -relief flat -focusthickness 1
    ttk::style map TButton -background [list active $P(border) pressed $P(border) disabled $P(panel)] \
        -foreground [list disabled $P(muted)]
    ttk::style configure Accent.TButton -background $P(accent2) -foreground white -font tgBold
    ttk::style map Accent.TButton -background [list active $P(accent) pressed $P(accent) disabled $P(panel)]
    ttk::style configure Danger.TButton -background #8c2f2f -foreground white
    ttk::style map Danger.TButton -background [list active $P(bad) pressed $P(bad) disabled $P(panel)]

    ttk::style configure TEntry -fieldbackground $P(panel2) -padding 5 -foreground $P(text)
    ttk::style configure TCombobox -fieldbackground $P(panel2) -background $P(panel2) -padding 4 -arrowcolor $P(text)
    ttk::style map TCombobox -fieldbackground [list readonly $P(panel2)] -foreground [list readonly $P(text)]
    ttk::style configure TSpinbox -fieldbackground $P(panel2) -padding 4 -arrowcolor $P(text)
    ttk::style configure TCheckbutton -background $P(bg) -foreground $P(text) -indicatorbackground $P(panel2) -indicatorforeground $P(accent)
    ttk::style map TCheckbutton -background [list active $P(bg)]
    ttk::style configure Panel.TCheckbutton -background $P(panel)
    ttk::style configure TRadiobutton -background $P(bg) -foreground $P(text)
    ttk::style configure TSeparator -background $P(border)
    ttk::style configure TLabelframe -background $P(bg) -bordercolor $P(border) -relief solid
    ttk::style configure TLabelframe.Label -background $P(bg) -foreground $P(accent) -font tgBold

    ttk::style configure TNotebook -background $P(bg) -borderwidth 0 -tabmargins {0 0 0 0} -bordercolor $P(panel) -lightcolor $P(panel) -darkcolor $P(panel)
    ttk::style configure TNotebook.Tab -background $P(bg) -foreground $P(muted) -padding {18 9} -borderwidth 0 -font tgBold \
        -bordercolor $P(bg) -lightcolor $P(bg) -darkcolor $P(bg)
    ttk::style map TNotebook.Tab -background [list selected $P(panel) active $P(panel2)] -foreground [list selected $P(text) active $P(text)] \
        -bordercolor [list selected $P(panel) active $P(panel2)] -lightcolor [list selected $P(panel) active $P(panel2)] \
        -darkcolor [list selected $P(panel) active $P(panel2)]

    ttk::style configure Treeview -background $P(panel) -fieldbackground $P(panel) -foreground $P(text) \
        -rowheight 28 -borderwidth 0 -relief flat
    ttk::style map Treeview -background [list selected $P(sel)] -foreground [list selected $P(text)]
    ttk::style configure Treeview.Heading -background $P(panel2) -foreground $P(muted) -relief flat -padding {8 6} -font tgBold
    ttk::style map Treeview.Heading -background [list active $P(border)]
    foreach o {Vertical Horizontal} {
        ttk::style configure $o.TScrollbar -background $P(border) -troughcolor $P(panel) -arrowcolor $P(muted) \
            -bordercolor $P(panel) -lightcolor $P(border) -darkcolor $P(border) -gripcount 0 -relief flat
        ttk::style map $o.TScrollbar -background [list active $P(muted) pressed $P(muted)] \
            -lightcolor [list active $P(muted) pressed $P(muted)] -darkcolor [list active $P(muted) pressed $P(muted)]
    }
    ttk::style configure Horizontal.TProgressbar -background $P(accent) -troughcolor $P(panel2)

    option add *TCombobox*Listbox.background $P(panel2)
    option add *TCombobox*Listbox.foreground $P(text)
    option add *TCombobox*Listbox.selectBackground $P(sel)
    option add *Menu.background $P(panel2)
    option add *Menu.foreground $P(text)
    option add *Menu.activeBackground $P(sel)
    option add *Menu.activeForeground $P(text)
    option add *Menu.relief flat
    . configure -background $P(bg)
}

# --------------------------------------------------------------- helpers ----

# Tooltip: show text after the pointer rests on a widget.
proc ::tg::gui::tip {w text} {
    bind $w <Enter> [list ::tg::gui::tipSchedule %W $text]
    bind $w <Leave> [list ::tg::gui::tipHide]
    bind $w <ButtonPress> [list ::tg::gui::tipHide]
}
proc ::tg::gui::tipSchedule {w text} {
    variable tipJob
    tipHide
    set tipJob [after 600 [list ::tg::gui::tipShow $w $text]]
}
proc ::tg::gui::tipShow {w text} {
    variable tipWin
    variable P
    if {![winfo exists $w]} return
    set tipWin .tgtip
    catch {destroy $tipWin}
    toplevel $tipWin -background $P(border)
    wm overrideredirect $tipWin 1
    label $tipWin.l -text $text -justify left -wraplength 380 -background $P(panel2) -foreground $P(text) \
        -padx 10 -pady 7 -borderwidth 0
    pack $tipWin.l -padx 1 -pady 1
    set x [expr {[winfo pointerx .] + 14}]
    set y [expr {[winfo pointery .] + 18}]
    wm geometry $tipWin +$x+$y
}
proc ::tg::gui::tipHide {} {
    variable tipWin
    variable tipJob
    if {$tipJob ne ""} { after cancel $tipJob; set tipJob "" }
    if {$tipWin ne ""} { catch {destroy $tipWin}; set tipWin "" }
}

proc ::tg::gui::pill {w text color} {
    $w configure -text " $text " -background $color -foreground #0b0e14
}

# Centered modal dialog frame. Returns the toplevel path.
proc ::tg::gui::dialog {name title {w 560} {h 0}} {
    variable P
    set t .$name
    catch {destroy $t}
    toplevel $t -background $P(bg)
    wm title $t $title
    wm transient $t .
    wm resizable $t 0 0
    return $t
}

proc ::tg::gui::center {t} {
    update idletasks
    set w [winfo reqwidth $t]; set h [winfo reqheight $t]
    set x [expr {[winfo rootx .] + ([winfo width .] - $w) / 2}]
    set y [expr {[winfo rooty .] + ([winfo height .] - $h) / 3}]
    if {$x < 0} { set x 0 }
    if {$y < 0} { set y 0 }
    wm geometry $t +$x+$y
}

proc ::tg::gui::modal {t} {
    center $t
    wm deiconify $t
    catch {grab $t}
    focus $t
    tkwait window $t
}

proc ::tg::gui::msg {kind title text} {
    tk_messageBox -parent . -icon $kind -title $title -message $text -type ok
}

proc ::tg::gui::ask {title text} {
    expr {[tk_messageBox -parent . -icon question -title $title -message $text -type yesno] eq "yes"}
}

# Run an engine command, showing errors in a dialog. Returns {ok result}.
proc ::tg::gui::do {args} {
    if {[catch {::tg::engine::cmd {*}$args} res]} {
        msg error "TclGuard" $res
        return [list 0 $res]
    }
    return [list 1 $res]
}

proc ::tg::gui::card {parent title} {
    variable P
    set f [ttk::frame $parent -style Card.TFrame -padding {16 12}]
    ttk::label $f.t -text $title -style PSmall.TLabel
    ttk::label $f.v -text "-" -style Big.TLabel
    ttk::label $f.s -text "" -style PSmall.TLabel
    pack $f.t -anchor w
    pack $f.v -anchor w -pady {2 0}
    pack $f.s -anchor w
    return $f
}

# ------------------------------------------------------------- main window ----

proc ::tg::gui::build {} {
    variable P
    variable v
    theme
    wm title . "TclGuard $::tg::VERSION"
    wm geometry . 1180x780
    wm minsize . 960 640
    wm protocol . WM_DELETE_WINDOW ::tg::gui::quit

    # ---- header ----
    ttk::frame .hdr -padding {20 14 20 10}
    ttk::label .hdr.logo -text "◆ TclGuard" -style Title.TLabel -foreground $P(accent)
    label .hdr.state -text " STARTING " -font tgBold -padx 6 -pady 2 -background $P(muted) -foreground #0b0e14
    label .hdr.level -text " NORMAL " -font tgBold -padx 6 -pady 2 -background $P(ok) -foreground #0b0e14
    ttk::label .hdr.up -text "" -style Muted.TLabel
    ttk::menubutton .hdr.lvlbtn -text "Threat level ▾" -menu .hdr.lvlbtn.m
    menu .hdr.lvlbtn.m -tearoff 0
    .hdr.lvlbtn.m add command -label "Automatic (recommended)" -command {::tg::gui::do level auto}
    .hdr.lvlbtn.m add separator
    .hdr.lvlbtn.m add command -label "Force: Normal"       -command {::tg::gui::do level 0}
    .hdr.lvlbtn.m add command -label "Force: Elevated"     -command {::tg::gui::do level 1}
    .hdr.lvlbtn.m add command -label "Force: Under attack" -command {::tg::gui::do level 2}
    .hdr.lvlbtn.m add command -label "Force: Lockdown (known visitors only)" -command {::tg::gui::do level 3}
    tip .hdr.lvlbtn "Normal: standard limits.\nElevated / Under attack: limits tighten automatically (and websites ask unverified visitors to prove they run a browser).\nLockdown: only addresses that behaved well before can connect."
    ttk::button .hdr.toggle -text "Pause protection" -command ::tg::gui::toggleRun
    pack .hdr.logo -side left
    pack .hdr.state -side left -padx {16 6}
    pack .hdr.level -side left -padx 4
    pack .hdr.up -side left -padx 12
    pack .hdr.toggle -side right
    pack .hdr.lvlbtn -side right -padx 8
    pack .hdr -fill x

    # ---- notebook ----
    ttk::notebook .nb
    foreach {id label} {dashboard Dashboard protection Protection bans Bans firewall Firewall log Log settings Settings help Help} {
        ttk::frame .nb.$id -style Panel.TFrame
        .nb add .nb.$id -text $label
    }
    pack .nb -fill both -expand 1 -padx 16 -pady {0 14}
    bind .nb <<NotebookTabChanged>> {::tg::gui::tabChanged}

    buildDashboard .nb.dashboard
    buildProtection .nb.protection
    buildBans .nb.bans
    buildFirewall .nb.firewall
    buildLog .nb.log
    buildSettings .nb.settings
    buildHelp .nb.help

    # ---- status bar ----
    ttk::label .status -text "" -style Muted.TLabel -padding {20 0 20 8}
    pack .status -fill x -before .nb -side bottom
}

proc ::tg::gui::tabChanged {} {
    variable tab
    set sel [.nb select]
    set tab [lindex [split $sel .] end]
    if {$tab eq "firewall"} { refreshFwPreview }
    refresh
}

# --------------------------------------------------------------- dashboard ----

proc ::tg::gui::buildDashboard {f} {
    variable P
    ttk::frame $f.cards -style Panel.TFrame
    foreach {id title} {conns "Open connections" allowed "Allowed per second" blocked "Blocked per second" bans "Banned addresses"} {
        card $f.cards.$id $title
        pack $f.cards.$id -side left -fill x -expand 1 -padx 6
    }
    pack $f.cards -fill x -padx 10 -pady {14 6}

    ttk::frame $f.mid -style Panel.TFrame
    ttk::label $f.mid.t -text "Traffic, last 5 minutes" -style PH.TLabel
    ttk::label $f.mid.legend -text "■ allowed   " -style PSmall.TLabel -foreground $P(accent)
    ttk::label $f.mid.legend2 -text "■ blocked" -style PSmall.TLabel -foreground $P(bad)
    canvas $f.mid.c -height 210 -background $P(panel) -highlightthickness 0
    grid $f.mid.t -row 0 -column 0 -sticky w
    grid $f.mid.legend -row 0 -column 1 -sticky e
    grid $f.mid.legend2 -row 0 -column 2 -sticky e
    grid $f.mid.c -row 1 -column 0 -columnspan 3 -sticky nsew -pady {6 0}
    grid columnconfigure $f.mid 0 -weight 1
    grid rowconfigure $f.mid 1 -weight 1
    pack $f.mid -fill both -expand 1 -padx 16 -pady 6
    bind $f.mid.c <Configure> {::tg::gui::drawChart}

    ttk::frame $f.low -style Panel.TFrame
    # top sources
    ttk::frame $f.low.l -style Panel.TFrame
    ttk::label $f.low.l.t -text "Busiest sources (last 5 s)" -style PH.TLabel
    ttk::treeview $f.low.l.tv -columns {ip ok blocked bytes} -show headings -height 6 -selectmode browse
    foreach {c t w a} {ip Address 190 w ok Allowed 80 e blocked Blocked 80 e bytes Data 90 e} {
        $f.low.l.tv heading $c -text $t
        $f.low.l.tv column $c -width $w -anchor $a
    }
    $f.low.l.tv tag configure hot -foreground $P(bad)
    pack $f.low.l.t -anchor w -pady {0 6}
    pack $f.low.l.tv -fill both -expand 1
    # events
    ttk::frame $f.low.r -style Panel.TFrame
    ttk::label $f.low.r.t -text "Recent events" -style PH.TLabel
    text $f.low.r.tx -height 7 -wrap word -background $P(panel) -foreground $P(text) -relief flat -borderwidth 0 \
        -highlightthickness 0 -padx 4 -pady 2 -state disabled -font TkDefaultFont -cursor arrow
    $f.low.r.tx tag configure alert -foreground $P(bad)
    $f.low.r.tx tag configure warn  -foreground $P(warn)
    $f.low.r.tx tag configure info  -foreground $P(text)
    $f.low.r.tx tag configure time  -foreground $P(muted)
    pack $f.low.r.t -anchor w -pady {0 6}
    pack $f.low.r.tx -fill both -expand 1
    pack $f.low.l -side left -fill both -expand 1 -padx {0 12}
    pack $f.low.r -side left -fill both -expand 1
    pack $f.low -fill both -padx 16 -pady {6 14}
}

# Round a maximum up to a pleasant axis value.
proc ::tg::gui::niceMax {m} {
    if {$m <= 5} { return 5 }
    set p [expr {pow(10, floor(log10($m)))}]
    foreach k {1 2 2.5 5 10} {
        if {$m <= $k * $p} { return [expr {$k * $p}] }
    }
    return [expr {10 * $p}]
}

proc ::tg::gui::drawChart {} {
    variable P
    set c .nb.dashboard.mid.c
    if {![winfo exists $c]} return
    $c delete all
    set w [winfo width $c]; set h [winfo height $c]
    if {$w < 100 || $h < 60} return
    set series $::tg::stat::series
    set padL 46; set padR 12; set padT 8; set padB 22
    set pw [expr {$w - $padL - $padR}]; set ph [expr {$h - $padT - $padB}]
    set n [llength $series]
    set max 0
    foreach s $series { set m [expr {max([lindex $s 1], [lindex $s 2])}]; if {$m > $max} { set max $m } }
    set top [niceMax $max]
    # grid
    for {set i 0} {$i <= 4} {incr i} {
        set y [expr {$padT + $ph - $ph * $i / 4.0}]
        $c create line $padL $y [expr {$w - $padR}] $y -fill $P(grid)
        $c create text [expr {$padL - 8}] $y -text [::tg::fmtRate [expr {$top * $i / 4.0}]] -anchor e -fill $P(muted) -font tgSmall
    }
    foreach {frac lab} {0 -5m 0.2 -4m 0.4 -3m 0.6 -2m 0.8 -1m 1.0 now} {
        set x [expr {$padL + $pw * $frac}]
        $c create text $x [expr {$h - 8}] -text $lab -fill $P(muted) -font tgSmall -anchor [expr {$frac == 1.0 ? {e} : ($frac == 0 ? {w} : {center})}]
    }
    if {$n < 2} {
        $c create text [expr {$w / 2}] [expr {$h / 2}] -text "collecting data..." -fill $P(muted)
        return
    }
    set span 300.0
    foreach {col idx fill} [list $P(accent) 1 1 $P(bad) 2 0] {
        set pts {}
        set i 0
        foreach s $series {
            set age [expr {($n - 1 - $i)}]    ;# seconds ago (1 sample/s)
            incr i
            if {$age > $span} continue
            set x [expr {$padL + $pw * (1.0 - $age / $span)}]
            set y [expr {$padT + $ph - $ph * min(1.0, [lindex $s $idx] / double($top))}]
            lappend pts $x $y
        }
        if {[llength $pts] < 4} continue
        if {$fill} {
            set poly [concat [lrange $pts 0 1] $pts]
            set poly [concat [list [lindex $pts 0] [expr {$padT + $ph}]] $pts [list [lindex $pts end-1] [expr {$padT + $ph}]]]
            $c create polygon {*}$poly -fill #1f3a63 -outline ""
        }
        $c create line {*}$pts -fill $col -width 2 -smooth 0
    }
}

# ----------------------------------------------------------- protection tab ----

proc ::tg::gui::buildProtection {f} {
    variable P
    ttk::frame $f.top -style Panel.TFrame
    ttk::label $f.top.t -text "What TclGuard protects" -style PH.TLabel
    ttk::label $f.top.s -text "Visitors connect to the 'Listens on' port; TclGuard checks them and passes the good ones to your real server ('Forwards to')." -style PSmall.TLabel
    pack $f.top.t -anchor w
    pack $f.top.s -anchor w -pady {2 0}
    pack $f.top -fill x -padx 16 -pady {14 8}

    ttk::frame $f.btns -style Panel.TFrame
    ttk::button $f.btns.add  -text "+ Add protection" -style Accent.TButton -command ::tg::gui::addWizard
    ttk::button $f.btns.edit -text "Edit..." -command ::tg::gui::editSelected
    ttk::button $f.btns.tog  -text "Enable / disable" -command ::tg::gui::toggleSelected
    ttk::button $f.btns.del  -text "Remove" -command ::tg::gui::removeSelected
    pack $f.btns.add -side left
    pack $f.btns.edit $f.btns.tog $f.btns.del -side left -padx {8 0}
    pack $f.btns -fill x -padx 16 -pady {0 8}

    ttk::frame $f.tvw -style Panel.TFrame
    ttk::treeview $f.tvw.tv -columns {name type listen backend state conns} -show headings -selectmode browse
    foreach {c t w a} {name Name 190 w type Type 70 w listen "Listens on" 170 w backend "Forwards to" 170 w state Status 130 w conns Connections 100 e} {
        $f.tvw.tv heading $c -text $t
        $f.tvw.tv column $c -width $w -anchor $a
    }
    $f.tvw.tv tag configure running -foreground $P(ok)
    $f.tvw.tv tag configure off -foreground $P(muted)
    $f.tvw.tv tag configure failed -foreground $P(bad)
    ttk::scrollbar $f.tvw.sb -orient vertical -command "$f.tvw.tv yview"
    $f.tvw.tv configure -yscrollcommand "$f.tvw.sb set"
    pack $f.tvw.sb -side right -fill y
    pack $f.tvw.tv -fill both -expand 1
    pack $f.tvw -fill both -expand 1 -padx 16 -pady {0 8}
    bind $f.tvw.tv <Double-1> ::tg::gui::editSelected

    ttk::label $f.hint -style PSmall.TLabel -wraplength 900 -justify left -text \
        "Important: your real server must listen on a different port (or only on 127.0.0.1) than the public port, and your router should forward the public port to this computer. Otherwise attackers can talk to the server directly and skip TclGuard."
    pack $f.hint -anchor w -padx 16 -pady {0 14}
}

proc ::tg::gui::selectedListener {} {
    set tv .nb.protection.tvw.tv
    set s [$tv selection]
    if {$s eq ""} { msg info "TclGuard" "Select a protection in the list first."; return "" }
    return $s
}

proc ::tg::gui::editSelected {} {
    set n [selectedListener]
    if {$n ne ""} { editListener $n }
}

proc ::tg::gui::toggleSelected {} {
    set n [selectedListener]
    if {$n eq ""} return
    set c $::tg::cfg::current
    set cur [dict get [::tg::cfg::fillListener [dict get $c listeners $n]] enabled]
    dict set c listeners $n enabled [expr {![::tg::bool $cur]}]
    applyConfig $c
}

proc ::tg::gui::removeSelected {} {
    set n [selectedListener]
    if {$n eq ""} return
    if {![ask "Remove protection" "Stop protecting '$n' and delete it from the configuration?"]} return
    set c $::tg::cfg::current
    dict unset c listeners $n
    applyConfig $c
}

# Validate, save and apply a whole new config dict. Returns 1 on success.
proc ::tg::gui::applyConfig {c} {
    lassign [::tg::cfg::validate $c] errs warns
    if {[llength $errs]} {
        msg error "Cannot apply" [join $errs "\n\n"]
        return 0
    }
    ::tg::cfg::set_ $c
    if {[catch {::tg::cfg::save} err]} { msg warning "TclGuard" "Applied, but saving the configuration failed:\n$err" }
    ::tg::engine::reload
    refreshFwPreview
    if {[llength $warns]} { msg warning "Note" [join $warns "\n\n"] }
    refresh
    return 1
}

# ---- add wizard ----

proc ::tg::gui::addWizard {} {
    variable P
    variable v
    set t [dialog wiz "Add protection"]
    ttk::frame $t.f -padding 20
    pack $t.f
    ttk::label $t.f.h -text "What do you want to protect?" -style Med.TLabel
    grid $t.f.h -row 0 -column 0 -columnspan 3 -sticky w -pady {0 10}

    listbox $t.f.lb -height 12 -width 34 -background $P(panel2) -foreground $P(text) -relief flat -highlightthickness 0 \
        -selectbackground $P(sel) -selectforeground $P(text) -activestyle none -exportselection 0
    set names {}
    foreach p $::tg::cfg::presetOrder {
        $t.f.lb insert end [dict get $::tg::cfg::presets($p) title]
        lappend names $p
    }
    grid $t.f.lb -row 1 -column 0 -rowspan 6 -sticky ns -padx {0 18}

    ttk::label $t.f.desc -wraplength 360 -justify left -text "" -style Muted.TLabel
    grid $t.f.desc -row 1 -column 1 -columnspan 2 -sticky nw
    set v(wizPub) ""; set v(wizBackend) ""; set v(wizHost) 127.0.0.1
    ttk::label $t.f.l1 -text "Players / visitors connect to port"
    ttk::spinbox $t.f.e1 -from 1 -to 65535 -width 8 -textvariable ::tg::gui::v(wizPub)
    ttk::label $t.f.l2 -text "Your real server listens on port"
    ttk::spinbox $t.f.e2 -from 1 -to 65535 -width 8 -textvariable ::tg::gui::v(wizBackend)
    ttk::label $t.f.l3 -text "...on this address"
    ttk::entry $t.f.e3 -width 18 -textvariable ::tg::gui::v(wizHost)
    grid $t.f.l1 -row 3 -column 1 -sticky w -pady {16 4}; grid $t.f.e1 -row 3 -column 2 -sticky w -pady {16 4}
    grid $t.f.l2 -row 4 -column 1 -sticky w -pady 4;       grid $t.f.e2 -row 4 -column 2 -sticky w -pady 4
    grid $t.f.l3 -row 5 -column 1 -sticky w -pady 4;       grid $t.f.e3 -row 5 -column 2 -sticky w -pady 4
    ttk::label $t.f.note -wraplength 360 -justify left -style Small.TLabel -text \
        "Tip: change your game/web server's own port to the second number (or set it to listen on 127.0.0.1 only), then forward the first number on your router."
    grid $t.f.note -row 6 -column 1 -columnspan 2 -sticky nw -pady {10 0}

    ttk::frame $t.f.b
    ttk::button $t.f.b.cancel -text Cancel -command [list destroy $t]
    ttk::button $t.f.b.ok -text "Add" -style Accent.TButton
    pack $t.f.b.ok $t.f.b.cancel -side right -padx {8 0}
    grid $t.f.b -row 8 -column 0 -columnspan 3 -sticky e -pady {16 0}

    set sel [list apply {{t names} {
        set i [lindex [$t.f.lb curselection] 0]
        if {$i eq ""} return
        set p [lindex $names $i]
        set pr $::tg::cfg::presets($p)
        $t.f.desc configure -text [dict get $pr description]
        set specs [dict get $pr listeners]
        set multi [expr {[llength $specs] > 1}]
        set s [lindex $specs 0]
        set ::tg::gui::v(wizPub) [dict get $s port]
        set ::tg::gui::v(wizBackend) [dict get $s backendPort]
        foreach w {e1 e2 e3} { $t.f.$w configure -state [expr {$multi ? "disabled" : "normal"}] }
        $t.f.note configure -text [expr {$multi ? "This preset sets up [llength $specs] listeners with the standard ports; edit them afterwards from the list." : "Tip: change your game/web server's own port to the second number (or set it to listen on 127.0.0.1 only), then forward the first number on your router."}]
    }} $t $names]
    bind $t.f.lb <<ListboxSelect>> [list {*}$sel]
    $t.f.lb selection set 0
    {*}$sel

    $t.f.b.ok configure -command [list apply {{t names} {
        set i [lindex [$t.f.lb curselection] 0]
        if {$i eq ""} return
        set p [lindex $names $i]
        set new [::tg::cfg::presetListeners $p [dict get $::tg::cfg::current listeners]]
        if {[llength [dict keys $new]] == 1} {
            set n [lindex [dict keys $new] 0]
            dict set new $n port $::tg::gui::v(wizPub)
            dict set new $n backendPort $::tg::gui::v(wizBackend)
            dict set new $n backendHost [string trim $::tg::gui::v(wizHost)]
        }
        set c $::tg::cfg::current
        dict for {n s} $new { dict set c listeners $n $s }
        if {[::tg::gui::applyConfig $c]} { destroy $t }
    }} $t $names]
    modal $t
}

# ---- edit dialog (generated from a field table) ----

proc ::tg::gui::listenerFields {type} {
    # key label kind hint ?choices?
    set common {
        {enabled "Enabled" bool "Turn protection for this port on or off."}
        {bind "Listen address" text "Which local address to accept connections on. 0.0.0.0 = every network card."}
        {port "Public port" int "The port players/visitors connect to. Forward this port on your router."}
        {backendHost "Server address" text "Where your real server is (almost always 127.0.0.1)."}
        {backendPort "Server port" int "The port your real server listens on."}
        {note "Note" text "Free text for yourself."}
    }
    switch -- $type {
        http {
            set adv {
                {maxConnsPerIP "Max connections per visitor" int "Simultaneous connections from one address. Browsers use up to ~6 per tab; families/offices share one address."}
                {connRate "New connections per visitor (per 10 s)" int "More than this in 10 seconds counts as a flood."}
                {reqRate "Requests per visitor (per 10 s)" int "A normal page load is 20-80 requests. Bots send thousands."}
                {headerTimeout "Seconds to send request headers" int "Stops slow-loris attacks that drip headers forever. 0 = off."}
                {keepAliveTimeout "Idle keep-alive seconds" int "How long an idle connection may stay open between requests."}
                {bodyTimeout "Seconds without upload data" int "Stops slow-POST attacks."}
                {maxBodyMB "Largest upload (MB)" int "Requests bigger than this are refused."}
                {maxConns "Max connections (this port)" int "Hard ceiling for this listener."}
                {challenge "Browser check" choice "auto: only while under attack. always: always. off: never. Unknown visitors must prove they keep cookies." {auto always off}}
                {forwardIp "Pass visitor address to server" bool "Adds X-Forwarded-For / X-Real-IP so your site sees the real address."}
                {trustedProxies "Trusted proxies (IPs)" list "Only if TclGuard sits behind Cloudflare/another proxy: addresses allowed to tell us the real visitor IP."}
                {proxyProtocol "PROXY protocol" choice "Tell the server the real address using the PROXY protocol (server must support it)." {none v1 v2}}
            }
        }
        udp {
            set adv {
                {pps "Packets per second per player" int "Above this, packets are dropped. Games usually send 20-300/s."}
                {bytesPerSec "Bytes per second per player" int "Incoming bandwidth limit per player."}
                {maxSessionsPerIP "Sessions per player address" int "Several PCs behind one router need more than 1."}
                {newSessionRate "New sessions per 10 s" int "Join-spam limit."}
                {maxSessions "Max sessions (this port)" int "Hard ceiling."}
                {replyBytesPerSec "Reply bytes per second per player" int "Limits what the server can send back, so it can't be used to flood others."}
                {maxPacket "Largest packet (bytes)" int "Bigger packets are dropped."}
                {sessionTimeout "Session idle seconds" int "Forget a silent player after this long."}
                {banOffenders "Ban offenders" bool "Temporarily ban addresses that break the limits. Turn off if you fear spoofed addresses."}
            }
        }
        default {
            set adv {
                {maxConnsPerIP "Max connections per player" int "Simultaneous connections from one address."}
                {connRate "New connections per player (per 10 s)" int "More than this counts as a flood."}
                {firstByteTimeout "Seconds to send first data" int "Silent connections are dropped (and never reach your server). 0 = off."}
                {idleTimeout "Idle seconds" int "Close connections silent for this long. 0 = never."}
                {maxConns "Max connections (this port)" int "Hard ceiling."}
                {lazyConnect "Wait for first data" bool "Only connect to your server once the player has sent something. Turn OFF for services where the server speaks first (SSH, SMTP)."}
                {proxyProtocol "PROXY protocol" choice "Tell the server the real address using the PROXY protocol (server must support it)." {none v1 v2}}
            }
        }
    }
    list $common $adv
}

proc ::tg::gui::editListener {name} {
    variable P
    variable v
    set spec [::tg::cfg::fillListener [dict get $::tg::cfg::current listeners $name]]
    set type [dict get $spec type]
    lassign [listenerFields $type] common adv
    set t [dialog edit "Edit: $name"]
    ttk::frame $t.f -padding 20
    pack $t.f -fill both
    ttk::label $t.f.h -text "$name  ($type)" -style Med.TLabel
    pack $t.f.h -anchor w -pady {0 10}
    ttk::notebook $t.f.nb
    foreach {tabid title fields} [list basic Basic $common limits "Limits & timeouts" $adv] {
        ttk::frame $t.f.nb.$tabid -padding 14
        $t.f.nb add $t.f.nb.$tabid -text $title
        set r 0
        foreach fld $fields {
            lassign $fld key label kind hint choices
            set var ::tg::gui::v(edit,$key)
            set val [dict get $spec $key]
            if {$kind eq "bool"} { set val [::tg::bool $val] }
            set $var $val
            ttk::label $t.f.nb.$tabid.l$r -text $label
            switch -- $kind {
                bool   { ttk::checkbutton $t.f.nb.$tabid.e$r -variable $var }
                choice { ttk::combobox $t.f.nb.$tabid.e$r -textvariable $var -values $choices -state readonly -width 14 }
                int    { ttk::spinbox $t.f.nb.$tabid.e$r -from 0 -to 100000000 -width 14 -textvariable $var }
                default { ttk::entry $t.f.nb.$tabid.e$r -width 34 -textvariable $var }
            }
            grid $t.f.nb.$tabid.l$r -row $r -column 0 -sticky w -pady 5 -padx {0 18}
            grid $t.f.nb.$tabid.e$r -row $r -column 1 -sticky w -pady 5
            tip $t.f.nb.$tabid.l$r $hint
            tip $t.f.nb.$tabid.e$r $hint
            incr r
        }
    }
    pack $t.f.nb -fill both
    ttk::frame $t.f.b
    ttk::button $t.f.b.cancel -text Cancel -command [list destroy $t]
    ttk::button $t.f.b.ok -text "Save and apply" -style Accent.TButton -command [list ::tg::gui::saveListener $t $name $type [concat $common $adv]]
    pack $t.f.b.ok $t.f.b.cancel -side right -padx {8 0}
    pack $t.f.b -fill x -pady {14 0}
    modal $t
}

proc ::tg::gui::saveListener {t name type fields} {
    set spec [dict get $::tg::cfg::current listeners $name]
    foreach fld $fields {
        lassign $fld key label kind
        set val [set ::tg::gui::v(edit,$key)]
        switch -- $kind {
            bool { set val [expr {[::tg::bool $val] ? 1 : 0}] }
            list { set val [::tg::ip::parseList $val] }
            int  { set val [string trim $val] }
            default { set val [string trim $val] }
        }
        dict set spec $key $val
    }
    set c $::tg::cfg::current
    dict set c listeners $name $spec
    if {[applyConfig $c]} { destroy $t }
}

# ---------------------------------------------------------------- bans tab ----

proc ::tg::gui::buildBans {f} {
    variable P
    ttk::frame $f.top -style Panel.TFrame
    ttk::label $f.top.t -text "Banned addresses" -style PH.TLabel
    ttk::label $f.top.s -text "Offenders are banned automatically, for longer each time they come back. Bans also block them in the operating-system firewall when it is enabled." -style PSmall.TLabel
    pack $f.top.t -anchor w; pack $f.top.s -anchor w -pady {2 0}
    pack $f.top -fill x -padx 16 -pady {14 8}

    ttk::frame $f.btns -style Panel.TFrame
    ttk::button $f.btns.ban -text "Ban an address..." -command ::tg::gui::banDialog
    ttk::button $f.btns.un -text "Unban selected" -command ::tg::gui::unbanSelected
    ttk::button $f.btns.all -text "Unban everyone" -command ::tg::gui::unbanAll
    pack $f.btns.ban $f.btns.un $f.btns.all -side left -padx {0 8}
    pack $f.btns -fill x -padx 16 -pady {0 8}

    ttk::frame $f.tvw -style Panel.TFrame
    ttk::treeview $f.tvw.tv -columns {key reason source since left} -show headings -selectmode extended -height 9
    foreach {c t w a} {key Address 190 w reason Reason 380 w source Source 80 w since "Banned at" 150 w left "Time left" 110 e} {
        $f.tvw.tv heading $c -text $t
        $f.tvw.tv column $c -width $w -anchor $a
    }
    ttk::scrollbar $f.tvw.sb -orient vertical -command "$f.tvw.tv yview"
    $f.tvw.tv configure -yscrollcommand "$f.tvw.sb set"
    pack $f.tvw.sb -side right -fill y
    pack $f.tvw.tv -fill both -expand 1
    pack $f.tvw -fill both -expand 1 -padx 16 -pady {0 10}

    ttk::frame $f.lists -style Panel.TFrame
    foreach {id title key tooltip} {allow "Never ban (allowlist)" allowlist "These addresses are never limited or banned: your own devices, friends, monitoring." block "Always block (blocklist)" blocklist "These addresses/ranges are always refused."} {
        ttk::frame $f.lists.$id -style Panel.TFrame
        ttk::label $f.lists.$id.t -text $title -style PH.TLabel
        listbox $f.lists.$id.lb -height 4 -background $P(panel2) -foreground $P(text) -relief flat -highlightthickness 0 \
            -selectbackground $P(sel) -selectforeground $P(text) -activestyle none -exportselection 0
        ttk::frame $f.lists.$id.b -style Panel.TFrame
        ttk::button $f.lists.$id.b.add -text "Add..." -command [list ::tg::gui::listAdd $key]
        ttk::button $f.lists.$id.b.del -text "Remove" -command [list ::tg::gui::listDel $key $f.lists.$id.lb]
        pack $f.lists.$id.b.add $f.lists.$id.b.del -side left -padx {0 8}
        pack $f.lists.$id.t -anchor w -pady {0 4}
        pack $f.lists.$id.lb -fill both -expand 1
        pack $f.lists.$id.b -anchor w -pady {6 0}
        tip $f.lists.$id.t $tooltip
        pack $f.lists.$id -side left -fill both -expand 1 -padx {0 12}
    }
    pack $f.lists -fill x -padx 16 -pady {0 14}
}

proc ::tg::gui::banDialog {} {
    set t [dialog ban "Ban an address"]
    variable v
    set v(banIp) ""; set v(banSec) 86400; set v(banWhy) "manual ban"
    ttk::frame $t.f -padding 20
    pack $t.f
    ttk::label $t.f.l1 -text "IP address or range (e.g. 203.0.113.5 or 203.0.113.0/24)"
    ttk::entry $t.f.e1 -width 36 -textvariable ::tg::gui::v(banIp)
    ttk::label $t.f.l2 -text "Ban for"
    ttk::combobox $t.f.e2 -width 22 -state readonly -values {"1 hour" "1 day" "1 week" "Forever"}
    $t.f.e2 set "1 day"
    ttk::label $t.f.l3 -text "Reason"
    ttk::entry $t.f.e3 -width 36 -textvariable ::tg::gui::v(banWhy)
    grid $t.f.l1 -sticky w; grid $t.f.e1 -sticky w -pady {2 12}
    grid $t.f.l2 -sticky w; grid $t.f.e2 -sticky w -pady {2 12}
    grid $t.f.l3 -sticky w; grid $t.f.e3 -sticky w -pady {2 12}
    ttk::frame $t.f.b
    ttk::button $t.f.b.c -text Cancel -command [list destroy $t]
    ttk::button $t.f.b.ok -text Ban -style Danger.TButton -command [list apply {{t} {
        set sec [dict get {"1 hour" 3600 "1 day" 86400 "1 week" 604800 Forever 0} [$t.f.e2 get]]
        lassign [::tg::gui::do ban [string trim $::tg::gui::v(banIp)] $sec [string map {" " _} $::tg::gui::v(banWhy)]] ok
        if {$ok} { destroy $t; ::tg::gui::refresh }
    }} $t]
    pack $t.f.b.ok $t.f.b.c -side right -padx {8 0}
    grid $t.f.b -sticky e
    modal $t
}

proc ::tg::gui::unbanSelected {} {
    set tv .nb.bans.tvw.tv
    foreach k [$tv selection] { ::tg::gui::do unban $k }
    refresh
}

proc ::tg::gui::unbanAll {} {
    if {[::tg::ban::count] == 0} return
    if {[ask "Unban everyone" "Remove all [::tg::ban::count] bans?"]} { do unbanall; refresh }
}

proc ::tg::gui::listAdd {key} {
    variable v
    set t [dialog ladd "Add address"]
    set v(listIp) ""
    ttk::frame $t.f -padding 20
    pack $t.f
    ttk::label $t.f.l -text "IP address or range (e.g. 192.168.1.20 or 10.0.0.0/8)"
    ttk::entry $t.f.e -width 36 -textvariable ::tg::gui::v(listIp)
    ttk::frame $t.f.b
    ttk::button $t.f.b.c -text Cancel -command [list destroy $t]
    ttk::button $t.f.b.ok -text Add -style Accent.TButton -command [list apply {{t key} {
        lassign [::tg::gui::do [expr {$key eq "allowlist" ? "allow" : "block"}] [string trim $::tg::gui::v(listIp)]] ok
        if {$ok} { destroy $t; ::tg::gui::refresh }
    }} $t $key]
    pack $t.f.b.ok $t.f.b.c -side right -padx {8 0}
    pack $t.f.l -anchor w; pack $t.f.e -anchor w -pady {2 12}; pack $t.f.b -fill x
    modal $t
}

proc ::tg::gui::listDel {key lb} {
    set i [lindex [$lb curselection] 0]
    if {$i eq ""} return
    do [expr {$key eq "allowlist" ? "disallow" : "unblock"}] [$lb get $i]
    refresh
}

# ------------------------------------------------------------ firewall tab ----

proc ::tg::gui::buildFirewall {f} {
    variable P
    variable v
    ttk::label $f.t -text "Operating-system firewall" -style PH.TLabel
    ttk::label $f.s -style PSmall.TLabel -wraplength 980 -justify left -text \
        "A program like this can inspect thousands of connections a second, but a flood is millions of packets a second. The kernel firewall drops those for almost no CPU, so TclGuard hands every ban to it and can add per-address rate limits for your protected ports. Needs administrator / root rights."
    pack $f.t -anchor w -padx 16 -pady {14 2}
    pack $f.s -anchor w -padx 16 -pady {0 10}

    ttk::frame $f.st -style Card.TFrame -padding {16 12}
    foreach {k label} {backend "Firewall type" priv "Rights" inst "Rules installed" harden "Hardening" drops "Packets dropped by kernel" err "Last problem"} {
        ttk::label $f.st.l$k -text $label -style PanelMuted.TLabel
        ttk::label $f.st.v$k -text "-" -style Panel.TLabel -wraplength 700
    }
    set r 0
    foreach k {backend priv inst harden drops err} {
        grid $f.st.l$k -row $r -column 0 -sticky w -padx {0 24} -pady 3
        grid $f.st.v$k -row $r -column 1 -sticky w -pady 3
        incr r
    }
    pack $f.st -fill x -padx 16 -pady {0 10}

    ttk::frame $f.opt -style Panel.TFrame
    ttk::checkbutton $f.opt.h -text "Kernel hardening: rate-limit new connections and packets per address, drop malformed/fragmented packets" \
        -style Panel.TCheckbutton -variable ::tg::gui::v(fwHarden) -command ::tg::gui::fwHardenToggled
    tip $f.opt.h "Adds rules ahead of everything else: per-address SYN and UDP packet limits on your protected ports, ICMP rate limit, invalid-packet and fragment drops. Allowlisted addresses are exempt."
    pack $f.opt.h -anchor w
    pack $f.opt -fill x -padx 16 -pady {0 8}

    ttk::frame $f.b -style Panel.TFrame
    ttk::button $f.b.inst -text "Install / update rules" -style Accent.TButton -command ::tg::gui::fwInstall
    ttk::button $f.b.rm -text "Remove all rules" -command ::tg::gui::fwRemove
    pack $f.b.inst $f.b.rm -side left -padx {0 8}
    pack $f.b -fill x -padx 16 -pady {0 8}

    ttk::label $f.pt -text "Rules TclGuard installs" -style PH.TLabel
    pack $f.pt -anchor w -padx 16 -pady {8 4}
    text $f.tx -height 9 -wrap none -background $P(panel2) -foreground $P(text) -relief flat -borderwidth 0 \
        -highlightthickness 0 -padx 8 -pady 6 -font TkFixedFont -state disabled
    pack $f.tx -fill both -expand 1 -padx 16 -pady {0 14}
}

proc ::tg::gui::fwHardenToggled {} {
    variable v
    set c $::tg::cfg::current
    dict set c general harden $v(fwHarden)
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

# ----------------------------------------------------------------- log tab ----

proc ::tg::gui::buildLog {f} {
    variable P
    variable v
    ttk::frame $f.bar -style Panel.TFrame
    ttk::label $f.bar.l -text "Show" -style PanelMuted.TLabel
    set v(logLevel) info
    ttk::combobox $f.bar.lv -width 14 -state readonly -values {"Everything" "Info and up" "Warnings and up" "Alerts only"} -textvariable ::tg::gui::v(logLevelText)
    set v(logLevelText) "Info and up"
    set v(follow) 1
    ttk::checkbutton $f.bar.f -text "Follow" -style Panel.TCheckbutton -variable ::tg::gui::v(follow)
    ttk::button $f.bar.save -text "Save as..." -command ::tg::gui::saveLog
    ttk::button $f.bar.clear -text "Clear" -command [list ::tg::gui::clearLog]
    pack $f.bar.l -side left
    pack $f.bar.lv -side left -padx 8
    pack $f.bar.f -side left -padx 8
    pack $f.bar.clear $f.bar.save -side right -padx {8 0}
    pack $f.bar -fill x -padx 16 -pady {14 8}
    bind $f.bar.lv <<ComboboxSelected>> ::tg::gui::reloadLog

    ttk::frame $f.tw -style Panel.TFrame
    text $f.tw.tx -wrap word -background $P(panel) -foreground $P(text) -relief flat -borderwidth 0 -highlightthickness 0 \
        -padx 10 -pady 6 -state disabled -font TkFixedFont -cursor arrow
    ttk::scrollbar $f.tw.sb -orient vertical -command "$f.tw.tx yview"
    $f.tw.tx configure -yscrollcommand "$f.tw.sb set"
    $f.tw.tx tag configure debug -foreground $P(muted)
    $f.tw.tx tag configure info  -foreground $P(text)
    $f.tw.tx tag configure warn  -foreground $P(warn)
    $f.tw.tx tag configure alert -foreground $P(bad)
    $f.tw.tx tag configure time  -foreground $P(muted)
    pack $f.tw.sb -side right -fill y
    pack $f.tw.tx -fill both -expand 1
    pack $f.tw -fill both -expand 1 -padx 16 -pady {0 14}
    ::tg::log::addSink ::tg::gui::logSink
}

proc ::tg::gui::levelRank {l} { dict get {debug 0 info 1 warn 2 alert 3} $l }

proc ::tg::gui::minLogRank {} {
    variable v
    dict get {"Everything" 0 "Info and up" 1 "Warnings and up" 2 "Alerts only" 3} $v(logLevelText)
}

proc ::tg::gui::logSink {ms lvl text} {
    variable v
    set tx .nb.log.tw.tx
    if {![winfo exists $tx]} return
    if {[levelRank $lvl] < [minLogRank]} return
    $tx configure -state normal
    $tx insert end "[::tg::fmtTime $ms %H:%M:%S]  " time
    $tx insert end "[format %-5s [string toupper $lvl]]  $text\n" $lvl
    if {[$tx count -lines 1.0 end] > 3000} { $tx delete 1.0 500.0 }
    if {$v(follow)} { $tx see end }
    $tx configure -state disabled
}

proc ::tg::gui::reloadLog {} {
    set tx .nb.log.tw.tx
    $tx configure -state normal
    $tx delete 1.0 end
    $tx configure -state disabled
    foreach e [::tg::log::tail 3000 debug] { logSink {*}$e }
}

proc ::tg::gui::clearLog {} {
    set tx .nb.log.tw.tx
    $tx configure -state normal
    $tx delete 1.0 end
    $tx configure -state disabled
}

proc ::tg::gui::saveLog {} {
    set f [tk_getSaveFile -parent . -defaultextension .log -initialfile tclguard-log.txt]
    if {$f eq ""} return
    set fh [open $f w]
    puts -nonewline $fh [.nb.log.tw.tx get 1.0 end]
    close $fh
}

# ------------------------------------------------------------ settings tab ----

proc ::tg::gui::buildSettings {f} {
    variable P
    variable v
    ttk::label $f.t -text "Settings" -style PH.TLabel
    ttk::label $f.path -style PSmall.TLabel -text ""
    pack $f.t -anchor w -padx 16 -pady {14 0}
    pack $f.path -anchor w -padx 16 -pady {2 4}
    ttk::frame $f.g -style Panel.TFrame
    pack $f.g -fill x -padx 16

    set rows {
        {section Bans}
        {strikeThreshold "Strikes before a ban" int "Each limit violation adds a strike (bad requests add 1-2). At this many, the address is banned."}
        {strikeLeakPerSec "Strikes forgiven per second" num "Strikes fade over time so occasional slips are forgiven."}
        {banSteps "Ban lengths (seconds)" list "First ban, second ban, third ... Repeat offenders move down the list. Example: 60 600 3600 21600 86400"}
        {banResetAfter "Forget offences after (seconds)" int "An address that behaves for this long starts again from the first ban length."}
        {section "Threat level"}
        {autoLevel "Adjust automatically" bool "Tighten limits when traffic looks like an attack, relax when it ends."}
        {autoLockdown "Allow automatic lockdown" bool "At extreme load, only let in addresses that behaved well before. Can lock out new players - off by default."}
        {linkMbps "Your internet download speed (Mbit/s)" int "Used to judge how full your connection is."}
        {levelCalmSec "Calm seconds before relaxing" int "How long traffic must stay normal before the level drops one step."}
        {learnTrusted "Remember well-behaved visitors" bool "Addresses with long, healthy sessions are remembered for lockdown mode."}
        {section "Logging & control"}
        {logLevel "Log detail" choice "debug is very chatty." {debug info warn alert}}
        {controlEnable "Allow command-line control" bool "Lets 'tclguard ctl ...' manage this running instance (local computer only)."}
    }
    set r 0
    foreach row $rows {
        if {[lindex $row 0] eq "section"} {
            ttk::label $f.g.h$r -text [lindex $row 1] -style PH.TLabel -foreground $P(accent)
            grid $f.g.h$r -row $r -column 0 -columnspan 2 -sticky w -pady {14 4}
            incr r; continue
        }
        lassign $row key label kind hint choices
        set var ::tg::gui::v(set,$key)
        ttk::label $f.g.l$r -text $label -style Panel.TLabel
        switch -- $kind {
            bool   { ttk::checkbutton $f.g.e$r -variable $var -style Panel.TCheckbutton }
            choice { ttk::combobox $f.g.e$r -textvariable $var -values {debug info warn alert} -state readonly -width 12 }
            int - num { ttk::spinbox $f.g.e$r -from 0 -to 1000000000 -width 14 -textvariable $var }
            default { ttk::entry $f.g.e$r -width 34 -textvariable $var }
        }
        grid $f.g.l$r -row $r -column 0 -sticky w -padx {0 24} -pady 4
        grid $f.g.e$r -row $r -column 1 -sticky w -pady 4
        tip $f.g.l$r $hint
        tip $f.g.e$r $hint
        incr r
    }
    set v(settingsRows) $rows
    ttk::frame $f.b -style Panel.TFrame
    ttk::button $f.b.apply -text "Save and apply" -style Accent.TButton -command ::tg::gui::saveSettings
    ttk::button $f.b.reset -text "Revert" -command ::tg::gui::loadSettings
    pack $f.b.apply $f.b.reset -side left -padx {0 8}
    pack $f.b -fill x -padx 16 -pady {18 0}
    loadSettings
}

proc ::tg::gui::loadSettings {} {
    variable v
    foreach row $v(settingsRows) {
        if {[lindex $row 0] eq "section"} continue
        set key [lindex $row 0]
        set v(set,$key) [::tg::cfg::general $key]
        if {[lindex $row 2] eq "bool"} { set v(set,$key) [::tg::bool $v(set,$key)] }
    }
    .nb.settings.path configure -text "Configuration file: $::tg::cfg::path     State folder: [::tg::cfg::stateDir]"
}

proc ::tg::gui::saveSettings {} {
    variable v
    set c $::tg::cfg::current
    foreach row $v(settingsRows) {
        if {[lindex $row 0] eq "section"} continue
        lassign $row key label kind
        set val [set v(set,$key)]
        switch -- $kind {
            bool { set val [expr {[::tg::bool $val] ? 1 : 0}] }
            list { set val [::tg::ip::parseList $val] }
            default { set val [string trim $val] }
        }
        dict set c general $key $val
    }
    if {[applyConfig $c]} { loadSettings }
}

# ---------------------------------------------------------------- help tab ----

proc ::tg::gui::buildHelp {f} {
    variable P
    text $f.tx -wrap word -background $P(panel) -foreground $P(text) -relief flat -borderwidth 0 -highlightthickness 0 \
        -padx 24 -pady 16 -spacing3 4 -cursor arrow -state normal -font TkDefaultFont
    ttk::scrollbar $f.sb -orient vertical -command "$f.tx yview"
    $f.tx configure -yscrollcommand "$f.sb set"
    $f.tx tag configure h1 -font tgTitle -foreground $P(accent) -spacing1 14 -spacing3 6
    $f.tx tag configure h2 -font tgMed -foreground $P(text) -spacing1 14 -spacing3 4
    $f.tx tag configure b  -font tgBold
    $f.tx tag configure mono -font TkFixedFont -background $P(panel2)
    $f.tx tag configure warn -foreground $P(warn)
    pack $f.sb -side right -fill y
    pack $f.tx -fill both -expand 1
    foreach {tag text} [helpContent] { $f.tx insert end $text $tag }
    $f.tx configure -state disabled
}

proc ::tg::gui::helpContent {} {
    # alternating: tag text tag text ...
    list \
    h1 "Getting started\n" \
    {} "TclGuard sits in front of your game server or website. Visitors talk to TclGuard first; it throws out floods, broken requests and slow-drip attacks, and only passes good traffic on to your real server.\n" \
    h2 "1. Move your real server out of the way\n" \
    {} "Make your server listen on a private port (for example Minecraft on 25566 instead of 25565) or only on 127.0.0.1. TclGuard takes the public port. If the real server is still reachable directly, attackers can simply bypass TclGuard.\n" \
    h2 "2. Add protection\n" \
    {} "Open the Protection tab and press " \
    b "+ Add protection" \
    {} ". Pick your game or 'Website', check the two port numbers, and add it. Changes take effect immediately.\n" \
    h2 "3. Forward the public port on your router\n" \
    {} "Forward the public port (the first number) from your router to this computer. Test from outside your home network (mobile data), not from inside it.\n" \
    h2 "4. Turn on the kernel firewall (strongly recommended)\n" \
    {} "On the Firewall tab, install the rules. Start TclGuard as administrator (Windows) or with sudo (Linux) for this. It stops floods before they cost any CPU.\n" \
    h1 "What TclGuard can and cannot do\n" \
    {} "It " \
    b "can" \
    {} " stop: connection floods, request floods, slow-loris and slow-POST attacks, malformed or smuggled HTTP requests, UDP packet floods and login brute-forcing (with log watchers). It lets a small server survive attacks that would otherwise exhaust it.\n\n" \
    warn "It cannot stop a flood that fills your internet connection itself.\n" \
    {} "If an attacker sends more traffic than your home connection can carry (for example 500 Mbit/s into a 100 Mbit/s line), your router is overwhelmed before any software on your PC sees the packets. Only your ISP or a provider with a bigger network can fix that. Realistic options:\n" \
    {} "  \u2022 Run TclGuard on a cheap VPS that has DDoS protection, point your domain/game address at the VPS, and have it forward to your home server over a VPN such as WireGuard. The home server then hides behind the VPS and your home IP stays secret.\n" \
    {} "  \u2022 Put a website behind a CDN (e.g. Cloudflare) and add its addresses under 'Trusted proxies' in the website's settings.\n" \
    {} "  \u2022 Ask your ISP for a new IP address if you were hit, and keep your home IP private (never join a voice chat or site that shows it).\n" \
    h1 "Threat levels\n" \
    b "Normal" \
    {} ": standard limits.\n" \
    b "Elevated / Under attack" \
    {} ": per-visitor limits shrink automatically, and websites may ask unknown visitors to pass a cookie check.\n" \
    b "Lockdown" \
    {} ": only addresses that have behaved well before are let in. Use it as a last resort; new players cannot join.\n" \
    h1 "If you locked yourself out\n" \
    {} "Add your own address under Bans \u2192 'Never ban'. The default list already covers your home network (192.168.x.x, 10.x.x.x). Addresses on that list are never limited or banned.\n" \
    h1 "Command line\n" \
    {} "When TclGuard runs on a server without a screen it starts without this window. Manage it with:\n" \
    mono "tclguard ctl status\ntclguard ctl ban 203.0.113.5 3600 spamming\ntclguard ctl unban 203.0.113.5\ntclguard ctl level 2\n" \
    {} ""
}

# ---------------------------------------------------------------- refresh ----

proc ::tg::gui::refresh {} {
    variable P
    variable snap
    variable tab
    variable lastBanSig
    variable v
    if {[catch {set snap [::tg::engine::snapshot]} err]} return
    set s $snap
    set lv [dict get $s level]
    set lname [dict get $lv name]
    set colors [list $P(ok) $P(warn) $P(bad) #b03ad9]
    set lvl [dict get $lv level]
    .hdr.level configure -text " [string toupper $lname] [expr {[dict get $lv manual] ? {(manual)} : {}}] " -background [lindex $colors $lvl]
    if {[dict get $s running]} {
        .hdr.state configure -text " PROTECTED " -background $P(ok)
        .hdr.toggle configure -text "Pause protection"
    } else {
        .hdr.state configure -text " PAUSED " -background $P(warn)
        .hdr.toggle configure -text "Resume protection"
    }
    .hdr.up configure -text "up [::tg::fmtDuration [dict get $s uptime]]"

    set rates [dict get $s rates]
    set cnt [dict get $s counters]
    set fw [dict get $s firewall]
    set fwtxt [expr {[dict get $fw installed] ? "kernel firewall: [dict get $fw backend]" : "kernel firewall: off"}]
    .status configure -text "[dict get $s connections] connections • [dict get $s udpSessions] UDP sessions • $fwtxt • [dict get $s trusted] trusted visitors remembered • level reason: [expr {[dict get $lv reason] eq {} ? {n/a} : [dict get $lv reason]}]"

    switch -- $tab {
        dashboard {
            set d .nb.dashboard
            $d.cards.conns.v configure -text [expr {[dict get $s connections] + [dict get $s udpSessions]}]
            $d.cards.conns.s configure -text "[dict get $s connections] TCP • [dict get $s udpSessions] UDP"
            $d.cards.allowed.v configure -text [::tg::fmtRate [dict get $rates ok]]
            $d.cards.allowed.s configure -text "[::tg::fmtRate [dict get $cnt ok]] since start"
            $d.cards.blocked.v configure -text [::tg::fmtRate [dict get $rates blocked]]
            $d.cards.blocked.s configure -text "[::tg::fmtRate [dict get $cnt blocked]] since start"
            $d.cards.bans.v configure -text [dict get $s bans]
            $d.cards.bans.s configure -text "[dict get $cnt bans] banned since start"
            if {[dict get $rates blocked] > 0} {
                $d.cards.blocked.v configure -foreground $P(bad)
            } else {
                $d.cards.blocked.v configure -foreground $P(text)
            }
            drawChart
            # top sources
            set tv $d.low.l.tv
            $tv delete [$tv children {}]
            foreach row [dict get $s top] {
                lassign $row ip ok bl by
                $tv insert {} end -values [list $ip $ok $bl [::tg::fmtBytes $by]] -tags [expr {$bl > $ok && $bl > 20 ? "hot" : ""}]
            }
            # events
            set tx $d.low.r.tx
            $tx configure -state normal
            $tx delete 1.0 end
            set ev [::tg::log::tail 200 info]
            set shown 0
            foreach e [lreverse $ev] {
                lassign $e ms lvl text
                if {$lvl eq "info" && ![string match "*unbanned*" $text] && ![string match "*listening*" $text]} continue
                $tx insert end "[::tg::fmtTime $ms %H:%M:%S]  " time
                $tx insert end "$text\n" $lvl
                if {[incr shown] >= 7} break
            }
            if {$shown == 0} { $tx insert end "Nothing to report. All quiet." time }
            $tx configure -state disabled
        }
        protection {
            set tv .nb.protection.tvw.tv
            set seen {}
            foreach L [dict get $s listeners] {
                set n [dict get $L name]
                lappend seen $n
                set ty [string toupper [dict get $L type]]
                set state [expr {![::tg::bool [dict get $L enabled]] ? "disabled" : ([dict get $L running] ? "protecting" : "NOT RUNNING")}]
                set tag [expr {$state eq "protecting" ? "running" : ($state eq "disabled" ? "off" : "failed")}]
                set vals [list $n $ty [dict get $L port] [dict get $L backend] $state [dict get $L conns]]
                if {[$tv exists $n]} { $tv item $n -values $vals -tags $tag } else { $tv insert {} end -id $n -values $vals -tags $tag }
            }
            foreach n [$tv children {}] { if {$n ni $seen} { $tv delete $n } }
        }
        bans {
            set tv .nb.bans.tvw.tv
            set rows [::tg::ban::all]
            set sig [list]
            foreach b $rows { lappend sig [dict get $b key] [dict get $b until] }
            set now [::tg::now]
            if {$sig ne $lastBanSig} {
                set lastBanSig $sig
                set sel [$tv selection]
                $tv delete [$tv children {}]
                foreach b $rows {
                    set k [dict get $b key]
                    $tv insert {} end -id $k -values [list $k [dict get $b reason] [dict get $b source] [::tg::fmtTime [dict get $b since]] ""]
                }
                foreach k $sel { if {[$tv exists $k]} { $tv selection add $k } }
            }
            foreach b $rows {
                set until [dict get $b until]
                set left [expr {$until == 0 ? "forever" : [::tg::fmtDuration [expr {($until - $now) / 1000}]]}]
                catch { $tv set [dict get $b key] left $left }
            }
            foreach {id key} {allow allowlist block blocklist} {
                set lb .nb.bans.lists.$id.lb
                set items [::tg::cfg::general $key]
                if {[$lb get 0 end] ne $items} {
                    $lb delete 0 end
                    foreach i $items { $lb insert end $i }
                }
            }
        }
        firewall {
            set f .nb.firewall
            $f.st.vbackend configure -text [expr {[dict get $fw backend] eq "none" ? "none ([dict get $fw wanted] requested; available: [join [dict get $fw available] {, }])" : [dict get $fw backend]}]
            $f.st.vpriv configure -text [expr {[dict get $fw privileged] ? "administrator / root ✔" : "standard user - kernel rules unavailable. Restart TclGuard as administrator/root."}]
            $f.st.vinst configure -text [expr {[dict get $fw installed] ? "yes (bans enforced in the kernel)" : "no"}]
            $f.st.vharden configure -text [expr {[dict get $fw hardened] ? "on" : "off"}]
            $f.st.vdrops configure -text [::tg::fmtRate [dict get $cnt kernelDrop]]
            $f.st.verr configure -text [expr {[dict get $fw error] eq "" ? "none" : [dict get $fw error]}]
            if {![info exists v(fwHardenInit)]} {
                set v(fwHardenInit) 1
                set v(fwHarden) [::tg::bool [::tg::cfg::general harden]]
            }
        }
    }
}

proc ::tg::gui::refreshFwPreview {} {
    set tx .nb.firewall.tx
    $tx configure -state normal
    $tx delete 1.0 end
    $tx insert end [::tg::fw::preview]
    $tx configure -state disabled
}

proc ::tg::gui::tick {} {
    refresh
    after 1000 ::tg::gui::tick
}

proc ::tg::gui::toggleRun {} {
    if {$::tg::engine::running} {
        if {![ask "Pause protection" "While paused, nothing is checked or blocked and your server is exposed directly (if its port is reachable).\n\nPause?"]} return
        ::tg::engine::stop
    } else {
        ::tg::engine::start
    }
    refresh
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
    build
    ::tg::engine::start
    refreshFwPreview
    reloadLog
    tick
    if {[dict size [::tg::cfg::listeners]] == 0} {
        after 400 {
            if {[::tg::gui::ask "Welcome to TclGuard" "Nothing is protected yet.\n\nSet up protection for a game server or website now?"]} {
                .nb select .nb.protection
                ::tg::gui::addWizard
            }
        }
    }
    vwait ::tg::quit
}
