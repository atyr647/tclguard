# Widget gallery for the guikit: xvfb-run -a -s "-screen 0 1100x800x24" wish8.6 gallery.tcl outdir
set root [file normalize [file join [file dirname [info script]] .. ..]]
source -encoding utf-8 [file join $root tclguard.vfs lib tclguard util.tcl]
source -encoding utf-8 [file join $root tclguard.vfs lib tclguard guikit.tcl]
set out [lindex $argv 0]; file mkdir $out
proc build {theme} {
    foreach w [winfo children .] { destroy $w }
    ::tg::kit::init $theme
    wm geometry . 1040x780
    set C ::tg::kit::C
    frame .m -background $::tg::kit::C(bg); pack .m -fill both -expand 1 -padx 24 -pady 20
    ::tg::kit::lbl .m.h .m "Widget gallery ($theme)" -font h1; pack .m.h -anchor w -pady {0 14}
    set in [::tg::kit::card .m.c .m]; pack .m.c -fill x
    frame $in.r1 -background $::tg::kit::C(surface); pack $in.r1 -fill x -padx 16 -pady 16
    ::tg::kit::button $in.r1.a $in.r1 "Add protection" -style primary -icon plus
    ::tg::kit::button $in.r1.b $in.r1 "Edit" -style secondary -icon edit
    ::tg::kit::button $in.r1.c $in.r1 "Unban" -style ghost
    ::tg::kit::button $in.r1.d $in.r1 "Remove" -style danger -icon trash
    ::tg::kit::button $in.r1.e $in.r1 "Disabled" -style secondary
    ::tg::kit::btnConfigure $in.r1.e -state disabled
    pack $in.r1.a $in.r1.b $in.r1.c $in.r1.d $in.r1.e -side left -padx {0 10}
    frame $in.r2 -background $::tg::kit::C(surface); pack $in.r2 -fill x -padx 16 -pady {0 16}
    set ::g1 1; set ::g2 0
    ::tg::kit::toggle $in.r2.t1 $in.r2 ::g1; ::tg::kit::toggle $in.r2.t2 $in.r2 ::g2
    ::tg::kit::chip $in.r2.c1 $in.r2 "Protecting" -tone ok -dot 1
    ::tg::kit::chip $in.r2.c2 $in.r2 "Under attack" -tone bad -dot 1
    ::tg::kit::chip $in.r2.c3 $in.r2 "Elevated" -tone warn -dot 1
    ::tg::kit::chip $in.r2.c4 $in.r2 "TCP" -tone accent
    ::tg::kit::chip $in.r2.c5 $in.r2 "manual"
    ::tg::kit::chip $in.r2.c6 $in.r2 "Lockdown" -tone violet -dot 1
    pack $in.r2.t1 $in.r2.t2 -side left -padx {0 12}
    pack $in.r2.c1 $in.r2.c2 $in.r2.c3 $in.r2.c4 $in.r2.c5 $in.r2.c6 -side left -padx {0 8}
    frame $in.r3 -background $::tg::kit::C(surface); pack $in.r3 -fill x -padx 16 -pady {0 16}
    set ::sg auto; set ::txt "0.0.0.0"; set ::num 25565; set ::sel nft
    ::tg::kit::segment $in.r3.s $in.r3 ::sg {{auto Auto} {0 Normal} {1 Elevated} {2 "Under attack"} {3 Lockdown}}
    ::tg::kit::field $in.r3.f $in.r3 ::txt -width 16
    ::tg::kit::stepper $in.r3.n $in.r3 ::num -width 7
    ::tg::kit::select $in.r3.x $in.r3 ::sel {auto nft iptables none} -width 9
    pack $in.r3.s $in.r3.f $in.r3.n $in.r3.x -side left -padx {0 12}
    ::tg::kit::lbl $in.l $in "Icons" -font h3; pack $in.l -anchor w -padx 16
    frame $in.ic -background $::tg::kit::C(surface); pack $in.ic -fill x -padx 16 -pady {8 16}
    foreach {n col} {shield text shieldcheck ok shieldx bad shieldbolt warn overview accent server text ban bad wall text activity text sliders text info muted plus text close muted check ok chevron muted sun warn moon accent trash bad edit text globe accent gamepad accent terminal text lock text warn warn} {
        label $in.ic.$n -image [::tg::kit::icon $n 28 $col] -background $::tg::kit::C(surface)
        pack $in.ic.$n -side left -padx 8
    }
    frame .m.row -background $::tg::kit::C(bg); pack .m.row -fill x -pady {16 0}
    foreach {k c} {shield accent shieldcheck ok} {
        set cc [::tg::kit::card .m.row.$k .m.row -fill surface2]
        pack .m.row.$k -side left -padx {0 14}
        label $cc.i -image [::tg::kit::icon $k 64 $c] -background $::tg::kit::C(surface2)
        pack $cc.i -padx 24 -pady 24
    }
    set cc [::tg::kit::card .m.row.big .m.row -radius 18]
    pack .m.row.big -side left
    ::tg::kit::lbl $cc.a $cc "Protected" -font huge -fg ok; ::tg::kit::lbl $cc.b $cc "All quiet • no threats" -font body -fg muted
    pack $cc.a -anchor w -padx 24 -pady {16 0}; pack $cc.b -anchor w -padx 24 -pady {0 16}
    update idletasks; update
}
foreach t {dark light} {
    build $t
    after 300 {set ::go 1}; vwait ::go
    update; exec import -window root [file join $out gallery-$t.png]
}
exit
