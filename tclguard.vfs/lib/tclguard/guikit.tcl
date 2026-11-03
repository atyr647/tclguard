# guikit.tcl -- a small modern widget toolkit for Tk (no external files).
#
# Everything that must look smooth (icons, rounded corners, switch knobs) is
# rendered at runtime as an anti-aliased RGBA PNG and loaded as a photo image, so
# it composites correctly over any background in both light and dark themes.
# Sizes are expressed in "design pixels" and scaled by the display's DPI.

namespace eval ::tg::kit {
    variable theme dark
    variable C                 ;# current colour palette
    array set C {}
    variable F                 ;# fonts
    array set F {}
    variable imgCache
    array set imgCache {}
    variable seq 0
    variable tipWin ""
    variable tipJob ""
}

# ----------------------------------------------------------------- themes ----

proc ::tg::kit::palette {theme} {
    variable C
    array unset C
    if {$theme eq "light"} {
        array set C {
            bg #f3f5f9   side #ffffff   surface #ffffff   surface2 #f0f3f8   field #f5f7fb
            border #e3e7ef   text #111827   muted #6b7280   faint #9aa3b2
            accent #3b6cf6   accentText #ffffff   accentSoft #e6edff
            ok #12a36a   okSoft #def5ec   warn #c77700   warnSoft #fff1d6
            bad #d92d3f   badSoft #fde4e7   violet #7c3aed   violetSoft #efe6ff
            hover #eef1f7   active #e6edff   shadow #e9edf4   chart1 #3b6cf6   chart1Fill #dfe7ff
            chart2 #e5484d  track #d8dde7
        }
    } else {
        array set C {
            bg #0d0f14   side #0a0c10   surface #151922   surface2 #1c212c   field #11141b
            border #252b38   text #eef1f7   muted #8b94a7   faint #5b6477
            accent #5b8cff   accentText #ffffff   accentSoft #1d2a4a
            ok #34d399   okSoft #12332a   warn #fbbf24   warnSoft #3a2d0d
            bad #fb7185   badSoft #3b1822   violet #a78bfa   violetSoft #2a2147
            hover #1a1f2a   active #1d2a4a   shadow #0a0c10   chart1 #5b8cff   chart1Fill #1b2a4d
            chart2 #fb7185  track #2a3142
        }
    }
    set ::tg::kit::theme $theme
}

# Mix two #rrggbb colours: t=0 -> a, t=1 -> b
proc ::tg::kit::mix {a b t} {
    scan $a "#%2x%2x%2x" r1 g1 b1
    scan $b "#%2x%2x%2x" r2 g2 b2
    format "#%02x%02x%02x" [expr {int($r1 + ($r2 - $r1) * $t + 0.5)}] [expr {int($g1 + ($g2 - $g1) * $t + 0.5)}] [expr {int($b1 + ($b2 - $b1) * $t + 0.5)}]
}

proc ::tg::kit::col {name} {
    variable C
    if {[info exists C($name)]} { return $C($name) }
    return $name   ;# already a literal colour
}

# design pixels -> real pixels (96 dpi baseline = 1.333 px per point)
proc ::tg::kit::px {n} {
    expr {max(1, int($n * [tk scaling] / 1.3333 + 0.5))}
}

proc ::tg::kit::pickFont {candidates} {
    set have [font families]
    foreach c $candidates { if {$c in $have} { return $c } }
    return [lindex $candidates end]
}

proc ::tg::kit::fonts {} {
    variable F
    set sans [pickFont {"Segoe UI Variable Text" "Segoe UI" "SF Pro Text" "Helvetica Neue" Inter "Noto Sans" Cantarell "DejaVu Sans" Helvetica}]
    set mono [pickFont {"Cascadia Mono" Consolas "SF Mono" Menlo "JetBrains Mono" "DejaVu Sans Mono" Courier}]
    foreach {n size weight} {body 10 normal small 9 normal bold 10 bold h1 20 bold h2 13 bold h3 11 bold big 26 bold huge 34 bold tiny 8 bold} {
        catch {font delete tgk-$n}
        font create tgk-$n -family $sans -size $size -weight $weight
        set F($n) tgk-$n
    }
    catch {font delete tgk-mono}
    font create tgk-mono -family $mono -size 10
    set F(mono) tgk-mono
    catch {font delete tgk-monosm}
    font create tgk-monosm -family $mono -size 9
    set F(monosm) tgk-monosm
}

proc ::tg::kit::init {theme} {
    palette $theme
    fonts
    ttk::style theme use clam
    # the few native widgets we still use (scrollbars) get restyled
    set c ::tg::kit::C
    ttk::style configure Kit.Vertical.TScrollbar -troughcolor $::tg::kit::C(bg) -background $::tg::kit::C(border) \
        -bordercolor $::tg::kit::C(bg) -lightcolor $::tg::kit::C(border) -darkcolor $::tg::kit::C(border) \
        -arrowcolor $::tg::kit::C(bg) -gripcount 0 -relief flat -arrowsize 1
    ttk::style layout Kit.Vertical.TScrollbar {Vertical.Scrollbar.trough -sticky ns -children {Vertical.Scrollbar.thumb -expand 1 -sticky nswe}}
    ttk::style map Kit.Vertical.TScrollbar -background [list active $::tg::kit::C(faint) pressed $::tg::kit::C(faint)]
    option add *Menu.background $::tg::kit::C(surface2)
    option add *Menu.foreground $::tg::kit::C(text)
    option add *Menu.activeBackground $::tg::kit::C(accent)
    option add *Menu.activeForeground #ffffff
    option add *Menu.relief flat
    option add *Menu.borderWidth 0
    option add *Menu.font tgk-body
    . configure -background $::tg::kit::C(bg)
}

# ------------------------------------------------------- PNG / raster core ----

proc ::tg::kit::pngChunk {type data} {
    set body "$type$data"
    string cat [binary format I [string length $data]] $body [binary format I [zlib crc32 $body]]
}

# rows: list of lists of {r g b a} flattened bytes per row -> photo image
proc ::tg::kit::makePng {w h rowBytes} {
    set raw ""
    foreach r $rowBytes { append raw \x00 $r }
    set png "\x89PNG\r\n\x1a\n"
    append png [pngChunk IHDR [binary format IIccccc $w $h 8 6 0 0 0]]
    append png [pngChunk IDAT [zlib compress $raw]]
    append png [pngChunk IEND ""]
    image create photo -data $png -format png
}

# Coverage of a pixel given a signed distance (negative inside), 1px soft edge.
proc ::tg::kit::cover {d} {
    set a [expr {0.5 - $d}]
    expr {$a < 0 ? 0.0 : ($a > 1 ? 1.0 : $a)}
}

# Render a coverage function to an RGBA photo in one colour.
#   spec: list of ops evaluated per pixel in a 0..1 box (scaled by size).
# Ops (coordinates in a 24x24 design grid):
#   {add|sub circle cx cy r}  {add|sub ring cx cy r thick}  {add|sub cap x1 y1 x2 y2 halfwidth}
#   {add|sub rrect x y w h r}  {add|sub poly x1 y1 x2 y2 ...}
proc ::tg::kit::sdf {op px py} {
    switch -- [lindex $op 1] {
        circle { lassign [lrange $op 2 end] cx cy r; return [expr {hypot($px - $cx, $py - $cy) - $r}] }
        ring   { lassign [lrange $op 2 end] cx cy r t; return [expr {abs(hypot($px - $cx, $py - $cy) - $r) - $t / 2.0}] }
        cap {
            lassign [lrange $op 2 end] x1 y1 x2 y2 hw
            set dx [expr {$x2 - $x1}]; set dy [expr {$y2 - $y1}]
            set l2 [expr {$dx * $dx + $dy * $dy}]
            set t [expr {$l2 == 0 ? 0.0 : (($px - $x1) * $dx + ($py - $y1) * $dy) / $l2}]
            set t [expr {$t < 0 ? 0.0 : ($t > 1 ? 1.0 : $t)}]
            return [expr {hypot($px - ($x1 + $t * $dx), $py - ($y1 + $t * $dy)) - $hw}]
        }
        rrect {
            lassign [lrange $op 2 end] x y w h r
            set qx [expr {abs($px - ($x + $w / 2.0)) - ($w / 2.0 - $r)}]
            set qy [expr {abs($py - ($y + $h / 2.0)) - ($h / 2.0 - $r)}]
            set ox [expr {$qx > 0 ? $qx : 0}]; set oy [expr {$qy > 0 ? $qy : 0}]
            return [expr {hypot($ox, $oy) + min(max($qx, $qy), 0) - $r}]
        }
        poly {
            set pts [lrange $op 2 end]
            set n [expr {[llength $pts] / 2}]
            set best 1e9; set inside 0
            for {set i 0} {$i < $n} {incr i} {
                set j [expr {($i + 1) % $n}]
                set ax [lindex $pts [expr {2 * $i}]]; set ay [lindex $pts [expr {2 * $i + 1}]]
                set bx [lindex $pts [expr {2 * $j}]]; set by [lindex $pts [expr {2 * $j + 1}]]
                set dx [expr {$bx - $ax}]; set dy [expr {$by - $ay}]
                set l2 [expr {$dx * $dx + $dy * $dy}]
                set t [expr {$l2 == 0 ? 0.0 : (($px - $ax) * $dx + ($py - $ay) * $dy) / $l2}]
                set t [expr {$t < 0 ? 0.0 : ($t > 1 ? 1.0 : $t)}]
                set d [expr {hypot($px - ($ax + $t * $dx), $py - ($ay + $t * $dy))}]
                if {$d < $best} { set best $d }
                if {($ay > $py) != ($by > $py) && $px < ($bx - $ax) * ($py - $ay) / ($by - $ay) + $ax} { set inside [expr {!$inside}] }
            }
            return [expr {$inside ? -$best : $best}]
        }
    }
    return 1e9
}

proc ::tg::kit::maskImage {spec size color} {
    scan [col $color] "#%2x%2x%2x" r g b
    set sc [expr {$size / 24.0}]
    set rows {}
    for {set y 0} {$y < $size} {incr y} {
        set vals {}
        set py [expr {($y + 0.5) / $sc}]
        for {set x 0} {$x < $size} {incr x} {
            set px [expr {($x + 0.5) / $sc}]
            set d 1e9
            foreach op $spec {
                set dd [sdf $op $px $py]
                if {[lindex $op 0] eq "add"} { if {$dd < $d} { set d $dd } } else { if {-$dd > $d} { set d [expr {-$dd}] } }
            }
            set a [cover [expr {$d * $sc}]]
            lappend vals $r $g $b [expr {int($a * 255 + 0.5)}]
        }
        lappend rows [binary format c* $vals]
    }
    makePng $size $size $rows
}

# ----------------------------------------------------------------- icons ----

proc ::tg::kit::iconSpec {name} {
    switch -- $name {
        shield {
            return {{add poly 12 2  20.5 5.2  20.5 11.5  18.4 16.6  12 22  5.6 16.6  3.5 11.5  3.5 5.2}}
        }
        shieldcheck {
            return {{add poly 12 2  20.5 5.2  20.5 11.5  18.4 16.6  12 22  5.6 16.6  3.5 11.5  3.5 5.2}
                    {sub cap 8.2 12.2 10.9 14.9 1.15} {sub cap 10.9 14.9 16.0 9.2 1.15}}
        }
        shieldx {
            return {{add poly 12 2  20.5 5.2  20.5 11.5  18.4 16.6  12 22  5.6 16.6  3.5 11.5  3.5 5.2}
                    {sub cap 9 9 15 15 1.2} {sub cap 15 9 9 15 1.2}}
        }
        shieldbolt {
            return {{add poly 12 2  20.5 5.2  20.5 11.5  18.4 16.6  12 22  5.6 16.6  3.5 11.5  3.5 5.2}
                    {sub poly 13.2 6.2  8.6 12.6  11.6 12.6  10.8 17.8  15.6 11  12.5 11}}
        }
        overview {
            return {{add rrect 3.5 3.5 7.5 7.5 2} {add rrect 13 3.5 7.5 4.5 2} {add rrect 13 10 7.5 10.5 2} {add rrect 3.5 13 7.5 7.5 2}}
        }
        server {
            return {{add rrect 3.5 4 17 6.2 2.2} {add rrect 3.5 13.8 17 6.2 2.2}
                    {sub circle 7.2 7.1 1.1} {sub circle 7.2 16.9 1.1}}
        }
        ban {
            return {{add ring 12 12 8.2 2.4} {add cap 6.6 17.4 17.4 6.6 1.2}}
        }
        wall {
            return {{add rrect 3 4.5 18 4.2 1.3} {add rrect 3 10 8 4.2 1.3} {add rrect 13 10 8 4.2 1.3} {add rrect 3 15.5 18 4.2 1.3}}
        }
        activity {
            return {{add cap 4 7 20 7 1.2} {add cap 4 12 15 12 1.2} {add cap 4 17 18 17 1.2}}
        }
        sliders {
            return {{add cap 4 7 20 7 1.1} {add cap 4 17 20 17 1.1} {add circle 15 7 3.1} {add circle 9 17 3.1}
                    {sub circle 15 7 1.1} {sub circle 9 17 1.1}}
        }
        info {
            return {{add ring 12 12 8.4 2.2} {add circle 12 7.9 1.35} {add cap 12 11 12 16.6 1.15}}
        }
        plus {
            return {{add cap 12 5 12 19 1.4} {add cap 5 12 19 12 1.4}}
        }
        minus {
            return {{add cap 5 12 19 12 1.4}}
        }
        close {
            return {{add cap 6 6 18 18 1.4} {add cap 18 6 6 18 1.4}}
        }
        check {
            return {{add cap 5 12.5 10 17.5 1.6} {add cap 10 17.5 19 7 1.6}}
        }
        chevron {
            return {{add cap 7 9.5 12 14.5 1.5} {add cap 12 14.5 17 9.5 1.5}}
        }
        sun {
            return {{add circle 12 12 4.4}
                    {add cap 12 2.8 12 5.2 1.1} {add cap 12 18.8 12 21.2 1.1} {add cap 2.8 12 5.2 12 1.1} {add cap 18.8 12 21.2 12 1.1}
                    {add cap 5.5 5.5 7.2 7.2 1.1} {add cap 16.8 16.8 18.5 18.5 1.1} {add cap 5.5 18.5 7.2 16.8 1.1} {add cap 16.8 7.2 18.5 5.5 1.1}}
        }
        moon {
            return {{add circle 12 12 8.6} {sub circle 16.2 8.8 7.2}}
        }
        trash {
            return {{add rrect 6 8 12 12.5 2} {add cap 4.5 6 19.5 6 1.2} {add rrect 9.5 3 5 3.5 1.2}
                    {sub cap 10 11 10 17 0.9} {sub cap 14 11 14 17 0.9}}
        }
        edit {
            return {{add poly 15.5 4.2  19.8 8.5  9.5 18.8  4.6 19.4  5.2 14.5}}
        }
        dot {
            return {{add circle 12 12 6}}
        }
        globe {
            return {{add ring 12 12 8.5 2} {add ring 12 12 3.8 1.5} {add cap 3.6 12 20.4 12 0.8}}
        }
        gamepad {
            return {{add rrect 2.5 7 19 10 5} {sub cap 7.3 12 10.7 12 1} {sub cap 9 10.3 9 13.7 1} {sub circle 15.2 11 1.2} {sub circle 17.6 13.2 1.2}}
        }
        terminal {
            return {{add rrect 3 4.5 18 15 3} {sub cap 7 9.5 10 12 1} {sub cap 10 12 7 14.5 1} {sub cap 12 15 16.5 15 1}}
        }
        lock {
            return {{add rrect 5 10.5 14 10 2.5} {add ring 12 9 4.2 2.2} {sub rrect 5 4 14 6 0}}
        }
        warn {
            return {{add poly 12 3.5  21.3 19.5  2.7 19.5} {sub cap 12 9.5 12 14.2 1.05} {sub circle 12 16.9 1.2}}
        }
    }
    return {{add circle 12 12 5}}
}

# Cached anti-aliased icon in a given colour. size in design px.
proc ::tg::kit::icon {name size color} {
    variable imgCache
    set key "icon:$name:$size:[col $color]"
    if {![info exists imgCache($key)]} {
        set imgCache($key) [maskImage [iconSpec $name] [px $size] $color]
    }
    return $imgCache($key)
}

# Anti-aliased quarter circle (corner piece) in a single colour: which = tl tr bl br
proc ::tg::kit::corner {color r which {inverse 0}} {
    variable imgCache
    set key "corner:[col $color]:$r:$which:$inverse"
    if {[info exists imgCache($key)]} { return $imgCache($key) }
    scan [col $color] "#%2x%2x%2x" cr cg cb
    set rows {}
    for {set y 0} {$y < $r} {incr y} {
        set vals {}
        for {set x 0} {$x < $r} {incr x} {
            # distance from the arc centre, which sits at the inner corner of the piece
            switch -- $which {
                tl { set dx [expr {$r - $x - 0.5}]; set dy [expr {$r - $y - 0.5}] }
                tr { set dx [expr {$x + 0.5}];       set dy [expr {$r - $y - 0.5}] }
                bl { set dx [expr {$r - $x - 0.5}]; set dy [expr {$y + 0.5}] }
                br { set dx [expr {$x + 0.5}];       set dy [expr {$y + 0.5}] }
            }
            set a [cover [expr {hypot($dx, $dy) - $r}]]
            if {$inverse} { set a [expr {1.0 - $a}] }
            lappend vals $cr $cg $cb [expr {int($a * 255 + 0.5)}]
        }
        lappend rows [binary format c* $vals]
    }
    set imgCache($key) [makePng $r $r $rows]
}

# Opaque corner piece for a bordered card: outside the curve = outerBg, a 1px ring
# of border colour, interior = fill. One image, no transparency, no overlap.
proc ::tg::kit::cornerFull {outerBg border fill r which} {
    variable imgCache
    set key "cfull:[col $outerBg]:[col $border]:[col $fill]:$r:$which"
    if {[info exists imgCache($key)]} { return $imgCache($key) }
    scan [col $outerBg] "#%2x%2x%2x" or og ob
    scan [col $border] "#%2x%2x%2x" br bg_ bb
    scan [col $fill] "#%2x%2x%2x" fr fg fb
    set rows {}
    for {set y 0} {$y < $r} {incr y} {
        set vals {}
        for {set x 0} {$x < $r} {incr x} {
            switch -- $which {
                tl { set dx [expr {$r - $x - 0.5}]; set dy [expr {$r - $y - 0.5}] }
                tr { set dx [expr {$x + 0.5}];       set dy [expr {$r - $y - 0.5}] }
                bl { set dx [expr {$r - $x - 0.5}]; set dy [expr {$y + 0.5}] }
                br { set dx [expr {$x + 0.5}];       set dy [expr {$y + 0.5}] }
            }
            set dist [expr {hypot($dx, $dy)}]
            set ao [cover [expr {$dist - $r}]]          ;# inside the outer curve
            set ai [cover [expr {$dist - ($r - 1)}]]    ;# inside the inner curve
            set wo [expr {1.0 - $ao}]; set wb [expr {$ao - $ai}]; set wf $ai
            lappend vals [expr {int($or * $wo + $br * $wb + $fr * $wf + 0.5)}] \
                         [expr {int($og * $wo + $bg_ * $wb + $fg * $wf + 0.5)}] \
                         [expr {int($ob * $wo + $bb * $wb + $fb * $wf + 0.5)}] 255
        }
        lappend rows [binary format c* $vals]
    }
    set imgCache($key) [makePng $r $r $rows]
}

proc ::tg::kit::disc {color d} {
    variable imgCache
    set key "disc:[col $color]:$d"
    if {[info exists imgCache($key)]} { return $imgCache($key) }
    scan [col $color] "#%2x%2x%2x" cr cg cb
    set rows {}
    set r [expr {$d / 2.0}]
    for {set y 0} {$y < $d} {incr y} {
        set vals {}
        for {set x 0} {$x < $d} {incr x} {
            set a [cover [expr {hypot($x + 0.5 - $r, $y + 0.5 - $r) - $r}]]
            lappend vals $cr $cg $cb [expr {int($a * 255 + 0.5)}]
        }
        lappend rows [binary format c* $vals]
    }
    set imgCache($key) [makePng $d $d $rows]
}

# ------------------------------------------------------------ small utils ----

proc ::tg::kit::uid {prefix} {
    variable seq
    return "${prefix}[incr seq]"
}

proc ::tg::kit::bgOf {w} {
    if {[catch {$w cget -background} c]} { return [col bg] }
    return $c
}

# ----------------------------------------------------------------- card ----
# A rounded surface. Returns the path of the inner frame to pack content into.
#   -fill surface|surface2|...   -radius N   -border 1/0   -pad N
proc ::tg::kit::card {path parent args} {
    array set o {-fill surface -radius 12 -border 1 -pad 16 -bg ""}
    array set o $args
    set outerBg [expr {$o(-bg) ne "" ? [col $o(-bg)] : [bgOf $parent]}]
    set r [px $o(-radius)]
    set fill [col $o(-fill)]
    set border [expr {$o(-border) ? [col border] : $fill}]
    frame $path -background $border -borderwidth 0 -highlightthickness 0
    set pad [expr {$o(-border) ? 1 : 0}]
    frame $path.in -background $fill -borderwidth 0 -highlightthickness 0
    pack $path.in -fill both -expand 1 -padx $pad -pady $pad
    foreach {w rx ry anc} {tl 0 0 nw  tr 1 0 ne  bl 0 1 sw  br 1 1 se} {
        set l $path.o$w
        label $l -image [cornerFull $outerBg $border $fill $r $w] -borderwidth 0 -highlightthickness 0 -padx 0 -pady 0
        place $l -relx $rx -rely $ry -anchor $anc
    }
    bind $path <Map> [list ::tg::kit::cardRaise $path]
    return $path.in
}

proc ::tg::kit::cardRaise {path} {
    foreach w {tl tr bl br} { catch {raise $path.o$w} }
}

# ---------------------------------------------------------------- button ----
# styles: primary secondary ghost danger
proc ::tg::kit::button {path parent text args} {
    variable F
    array set o {-style secondary -icon "" -command "" -width 0 -height 36 -font bold -state normal -pad 16}
    array set o $args
    set bg [bgOf $parent]
    set ico ""
    set tw [font measure $F($o(-font)) $text]
    set iw [expr {$o(-icon) ne "" ? [px 18] + [px 8] : 0}]
    set w [expr {$o(-width) > 0 ? [px $o(-width)] : $tw + $iw + 2 * [px $o(-pad)]}]
    set h [px $o(-height)]
    canvas $path -width $w -height $h -background $bg -highlightthickness 0 -borderwidth 0 -cursor hand2
    set ::tg::kit::bst($path) [list $o(-style) $o(-icon) $text $o(-command) $o(-font) normal $o(-state) $w $h]
    bind $path <Enter> [list ::tg::kit::btnState $path hover]
    bind $path <Leave> [list ::tg::kit::btnState $path normal]
    bind $path <ButtonPress-1> [list ::tg::kit::btnState $path press]
    bind $path <ButtonRelease-1> [list ::tg::kit::btnRelease $path %x %y]
    btnDraw $path
    return $path
}

proc ::tg::kit::btnColors {style state} {
    switch -- $style {
        primary   { set fill accent;   set hov [mix [col accent] #ffffff 0.14]; set pre [mix [col accent] #000000 0.15]; set txt accentText; set brd accent }
        danger    { set fill bad;      set hov [mix [col bad] #ffffff 0.14];    set pre [mix [col bad] #000000 0.15];    set txt #ffffff;    set brd bad }
        ghost     { set fill ""; set hov hover; set pre [mix [col hover] [col text] 0.08]; set txt text; set brd "" }
        default   { set fill surface2; set hov [mix [col surface2] [col text] 0.07]; set pre [mix [col surface2] [col text] 0.14]; set txt text; set brd border }
    }
    switch -- $state {
        hover { set f $hov }
        press { set f $pre }
        default { set f $fill }
    }
    list $f $brd $txt
}

proc ::tg::kit::btnDraw {path} {
    variable F
    lassign $::tg::kit::bst($path) style icon text cmd font state enabled w h
    if {![winfo exists $path]} return
    $path delete all
    set r [expr {min([px 9], $h / 2)}]
    lassign [btnColors $style $state] fill brd txt
    set bg [bgOf [winfo parent $path]]
    if {$enabled eq "disabled"} {
        set fill [expr {$style eq "ghost" ? "" : [col surface2]}]; set brd ""; set txt faint
    }
    if {$fill ne ""} {
        if {$brd ne "" && $brd ne $fill && $style eq "secondary"} {
            roundRect $path 0 0 $w $h $r [col $brd] $bg
            roundRect $path 1 1 [expr {$w - 1}] [expr {$h - 1}] [expr {max(1, $r - 1)}] [col $fill] [col $brd]
        } else {
            roundRect $path 0 0 $w $h $r [col $fill] $bg
        }
    }
    set tc [col $txt]
    set tw [font measure $F($font) $text]
    set iw [expr {$icon ne "" ? [px 18] : 0}]
    set gap [expr {$icon ne "" && $text ne "" ? [px 8] : 0}]
    set x0 [expr {($w - ($iw + $gap + $tw)) / 2}]
    if {$icon ne ""} {
        $path create image $x0 [expr {$h / 2}] -anchor w -image [icon $icon 18 $tc]
    }
    if {$text ne ""} {
        $path create text [expr {$x0 + $iw + $gap}] [expr {$h / 2}] -anchor w -text $text -fill $tc -font $F($font)
    }
}

# Rounded rectangle on a canvas using flat rects + AA corner images (fill over bg).
proc ::tg::kit::roundRect {c x1 y1 x2 y2 r fill bg {tag ""}} {
    set w [expr {$x2 - $x1}]; set h [expr {$y2 - $y1}]
    if {$r * 2 > $h} { set r [expr {$h / 2}] }
    if {$r * 2 > $w} { set r [expr {$w / 2}] }
    set t [list rr {*}$tag]
    $c create rectangle [expr {$x1 + $r}] $y1 [expr {$x2 - $r}] $y2 -fill $fill -outline "" -tags $t
    if {$h > 2 * $r} {
        $c create rectangle $x1 [expr {$y1 + $r}] [expr {$x1 + $r}] [expr {$y2 - $r}] -fill $fill -outline "" -tags $t
        $c create rectangle [expr {$x2 - $r}] [expr {$y1 + $r}] $x2 [expr {$y2 - $r}] -fill $fill -outline "" -tags $t
    }
    $c create image $x1 $y1 -anchor nw -image [corner $fill $r tl] -tags $t
    $c create image $x2 $y1 -anchor ne -image [corner $fill $r tr] -tags $t
    $c create image $x1 $y2 -anchor sw -image [corner $fill $r bl] -tags $t
    $c create image $x2 $y2 -anchor se -image [corner $fill $r br] -tags $t
}

proc ::tg::kit::btnState {path state} {
    if {![info exists ::tg::kit::bst($path)]} return
    lset ::tg::kit::bst($path) 5 $state
    if {[lindex $::tg::kit::bst($path) 6] eq "disabled"} return
    btnDraw $path
}

proc ::tg::kit::btnRelease {path x y} {
    if {![info exists ::tg::kit::bst($path)]} return
    lassign $::tg::kit::bst($path) style icon text cmd font state enabled w h
    if {$enabled eq "disabled"} return
    btnState $path hover
    if {$x >= 0 && $y >= 0 && $x <= $w && $y <= $h && $cmd ne ""} { uplevel #0 $cmd }
}

proc ::tg::kit::btnConfigure {path args} {
    set l $::tg::kit::bst($path)
    foreach {k v} $args {
        switch -- $k {
            -text { lset l 2 $v }
            -state { lset l 6 $v; $path configure -cursor [expr {$v eq "disabled" ? "arrow" : "hand2"}] }
            -command { lset l 3 $v }
            -icon { lset l 1 $v }
        }
    }
    set ::tg::kit::bst($path) $l
    btnDraw $path
}

# ---------------------------------------------------------------- toggle ----
proc ::tg::kit::toggle {path parent var args} {
    array set o {-command ""}
    array set o $args
    set w [px 44]; set h [px 24]
    canvas $path -width $w -height $h -background [bgOf $parent] -highlightthickness 0 -borderwidth 0 -cursor hand2
    set init [expr {[uplevel #0 [list set $var]] ? 1.0 : 0.0}]
    set ::tg::kit::tgl($path) [list $var $o(-command) $init $init]
    toggleDraw $path
    bind $path <ButtonRelease-1> [list ::tg::kit::toggleClick $path]
    trace add variable $var write [list ::tg::kit::toggleTrace $path]
    bind $path <Destroy> [list catch [list trace remove variable $var write [list ::tg::kit::toggleTrace $path]]]
    return $path
}

proc ::tg::kit::toggleTrace {path args} {
    if {![winfo exists $path]} return
    lassign $::tg::kit::tgl($path) var cmd pos target
    set new [expr {[uplevel #0 [list set $var]] ? 1.0 : 0.0}]
    if {$new != $target} { lset ::tg::kit::tgl($path) 3 $new; toggleAnimate $path }
}

proc ::tg::kit::toggleClick {path} {
    lassign $::tg::kit::tgl($path) var cmd pos target
    set new [expr {[uplevel #0 [list set $var]] ? 0 : 1}]
    uplevel #0 [list set $var $new]
    if {$cmd ne ""} { uplevel #0 $cmd }
}

proc ::tg::kit::toggleAnimate {path} {
    if {![winfo exists $path]} return
    lassign $::tg::kit::tgl($path) var cmd pos target
    set d [expr {$target - $pos}]
    if {abs($d) < 0.05} { set pos $target } else { set pos [expr {$pos + $d * 0.45}] }
    lset ::tg::kit::tgl($path) 2 $pos
    toggleDraw $path
    if {$pos != $target} { after 16 [list ::tg::kit::toggleAnimate $path] }
}

proc ::tg::kit::toggleDraw {path} {
    lassign $::tg::kit::tgl($path) var cmd pos target
    set w [px 44]; set h [px 24]
    $path delete all
    set bg [bgOf [winfo parent $path]]
    set track [mix [col track] [col accent] $pos]
    roundRect $path 0 0 $w $h [expr {$h / 2}] $track $bg
    set d [expr {$h - 2 * [px 3]}]
    set x [expr {[px 3] + ($w - $d - 2 * [px 3]) * $pos}]
    $path create image [expr {int($x)}] [px 3] -anchor nw -image [disc #ffffff $d]
}

# ------------------------------------------------------------------ chip ----
# tones: muted accent ok warn bad violet
proc ::tg::kit::chip {path parent text args} {
    variable F
    array set o {-tone muted -font small -dot 0}
    array set o $args
    switch -- $o(-tone) {
        ok     { set fg ok;     set bgc okSoft }
        warn   { set fg warn;   set bgc warnSoft }
        bad    { set fg bad;    set bgc badSoft }
        accent { set fg accent; set bgc accentSoft }
        violet { set fg violet; set bgc violetSoft }
        default { set fg muted; set bgc surface2 }
    }
    set h [px 22]
    set tw [font measure $F($o(-font)) $text]
    set dot [expr {$o(-dot) ? [px 14] : 0}]
    set w [expr {$tw + $dot + 2 * [px 10]}]
    canvas $path -width $w -height $h -background [bgOf $parent] -highlightthickness 0 -borderwidth 0
    roundRect $path 0 0 $w $h [expr {$h / 2}] [col $bgc] [bgOf $parent]
    if {$o(-dot)} { $path create image [px 10] [expr {$h / 2}] -anchor w -image [disc [col $fg] [px 6]] }
    $path create text [expr {[px 10] + $dot}] [expr {$h / 2}] -anchor w -text $text -fill [col $fg] -font $F($o(-font))
    return $path
}

# ------------------------------------------------------------- segmented ----
# values: list of {id label}
proc ::tg::kit::segment {path parent var values args} {
    variable F
    array set o {-command ""}
    array set o $args
    set h [px 34]
    set pad [px 3]
    set x $pad
    set widths {}
    foreach v $values { lappend widths [expr {[font measure $F(bold) [lindex $v 1]] + 2 * [px 14]}] }
    set total [expr {[tcl::mathop::+ {*}$widths] + 2 * $pad}]
    canvas $path -width $total -height $h -background [bgOf $parent] -highlightthickness 0 -borderwidth 0 -cursor hand2
    set ::tg::kit::seg($path) [list $var $values $widths $o(-command)]
    segDraw $path
    bind $path <ButtonRelease-1> [list ::tg::kit::segClick $path %x]
    trace add variable $var write [list ::tg::kit::segTrace $path]
    bind $path <Destroy> [list catch [list trace remove variable $var write [list ::tg::kit::segTrace $path]]]
    return $path
}

proc ::tg::kit::segTrace {path args} { if {[winfo exists $path]} { segDraw $path } }

proc ::tg::kit::segDraw {path} {
    variable F
    lassign $::tg::kit::seg($path) var values widths cmd
    set cur [uplevel #0 [list set $var]]
    $path delete all
    set h [px 34]; set pad [px 3]
    set total [expr {[tcl::mathop::+ {*}$widths] + 2 * $pad}]
    set bg [bgOf [winfo parent $path]]
    roundRect $path 0 0 $total $h [px 10] [col surface2] $bg
    set x $pad
    foreach v $values w $widths {
        lassign $v id label
        if {$id eq $cur} {
            roundRect $path $x $pad [expr {$x + $w}] [expr {$h - $pad}] [px 8] [col accent] [col surface2]
            set tc accentText
        } else { set tc muted }
        $path create text [expr {$x + $w / 2}] [expr {$h / 2}] -text $label -fill [col $tc] -font $F(bold)
        incr x $w
    }
}

proc ::tg::kit::segClick {path px_} {
    lassign $::tg::kit::seg($path) var values widths cmd
    set x [px 3]
    foreach v $values w $widths {
        if {$px_ >= $x && $px_ < $x + $w} {
            uplevel #0 [list set $var [lindex $v 0]]
            if {$cmd ne ""} { uplevel #0 [list {*}$cmd [lindex $v 0]] }
            return
        }
        incr x $w
    }
}

# ----------------------------------------------------------------- field ----
# Text input: rounded field containing a native entry.
proc ::tg::kit::field {path parent var args} {
    variable F
    array set o {-width 24 -mono 0 -placeholder "" -state normal -justify left}
    array set o $args
    set font [expr {$o(-mono) ? $F(mono) : $F(body)}]
    set w [expr {[font measure $font 0] * $o(-width) + 2 * [px 12]}]
    set h [px 36]
    canvas $path -width $w -height $h -background [bgOf $parent] -highlightthickness 0 -borderwidth 0
    entry $path.e -textvariable $var -font $font -relief flat -borderwidth 0 -highlightthickness 0 \
        -background [col field] -foreground [col text] -insertbackground [col text] \
        -selectbackground [col accent] -selectforeground #ffffff -justify $o(-justify) -state $o(-state) \
        -disabledbackground [col field] -disabledforeground [col muted]
    $path create window [px 12] [expr {$h / 2}] -anchor w -window $path.e -width [expr {$w - 2 * [px 12]}] -tags ent
    fieldDraw $path $w $h 0
    bind $path.e <FocusIn> [list ::tg::kit::fieldDraw $path $w $h 1]
    bind $path.e <FocusOut> [list ::tg::kit::fieldDraw $path $w $h 0]
    bind $path <ButtonPress-1> [list focus $path.e]
    return $path
}

proc ::tg::kit::fieldDraw {path w h focus} {
    $path delete rr
    set bg [bgOf [winfo parent $path]]
    set brd [expr {$focus ? [col accent] : [col border]}]
    roundRect $path 0 0 $w $h [px 9] $brd $bg
    roundRect $path 1 1 [expr {$w - 1}] [expr {$h - 1}] [expr {max(1, [px 9] - 1)}] [col field] $brd
    $path lower rr
}

# ---------------------------------------------------------------- stepper ----
proc ::tg::kit::stepper {path parent var args} {
    variable F
    array set o {-min 0 -max 2147483647 -step 1 -width 8 -float 0}
    array set o $args
    set w [expr {[font measure $F(body) 0] * $o(-width) + 2 * [px 12] + 2 * [px 26]}]
    set h [px 36]
    canvas $path -width $w -height $h -background [bgOf $parent] -highlightthickness 0 -borderwidth 0
    entry $path.e -textvariable $var -font $F(body) -relief flat -borderwidth 0 -highlightthickness 0 \
        -background [col field] -foreground [col text] -insertbackground [col text] -justify center \
        -selectbackground [col accent] -selectforeground #ffffff
    $path create window [expr {$w / 2}] [expr {$h / 2}] -window $path.e -width [expr {$w - 2 * [px 30]}]
    set ::tg::kit::stp($path) [list $var $o(-min) $o(-max) $o(-step) $o(-float)]
    stepDraw $path $w $h 0
    bind $path.e <FocusIn> [list ::tg::kit::stepDraw $path $w $h 1]
    bind $path.e <FocusOut> [list ::tg::kit::stepDraw $path $w $h 0]
    bind $path <ButtonPress-1> [list ::tg::kit::stepClick $path %x $w]
    return $path
}

proc ::tg::kit::stepDraw {path w h focus} {
    $path delete all
    set bg [bgOf [winfo parent $path]]
    set brd [expr {$focus ? [col accent] : [col border]}]
    roundRect $path 0 0 $w $h [px 9] $brd $bg
    roundRect $path 1 1 [expr {$w - 1}] [expr {$h - 1}] [expr {max(1, [px 9] - 1)}] [col field] $brd
    $path create image [expr {[px 15]}] [expr {$h / 2}] -image [icon minus 16 muted]
    $path create image [expr {$w - [px 15]}] [expr {$h / 2}] -image [icon plus 16 muted]
    $path create window [expr {$w / 2}] [expr {$h / 2}] -window $path.e -width [expr {$w - 2 * [px 30]}]
}

proc ::tg::kit::stepClick {path x w} {
    lassign $::tg::kit::stp($path) var mn mx step float
    set cur [uplevel #0 [list set $var]]
    if {![string is double -strict $cur]} { set cur 0 }
    if {$x < [px 28]} { set new [expr {$cur - $step}] } elseif {$x > $w - [px 28]} { set new [expr {$cur + $step}] } else return
    set new [expr {max($mn, min($mx, $new))}]
    if {!$float} { set new [expr {int($new)}] } else { set new [format %g $new] }
    uplevel #0 [list set $var $new]
}

# ----------------------------------------------------------------- select ----
proc ::tg::kit::select {path parent var values args} {
    variable F
    array set o {-width 14 -command ""}
    array set o $args
    set w [expr {[font measure $F(body) 0] * $o(-width) + 2 * [px 12] + [px 20]}]
    set h [px 36]
    canvas $path -width $w -height $h -background [bgOf $parent] -highlightthickness 0 -borderwidth 0 -cursor hand2
    set ::tg::kit::sel($path) [list $var $values $o(-command) $w $h]
    selDraw $path
    bind $path <ButtonPress-1> [list ::tg::kit::selOpen $path]
    trace add variable $var write [list ::tg::kit::selTrace $path]
    bind $path <Destroy> [list catch [list trace remove variable $var write [list ::tg::kit::selTrace $path]]]
    return $path
}

proc ::tg::kit::selTrace {path args} { if {[winfo exists $path]} { selDraw $path } }

proc ::tg::kit::selDraw {path} {
    variable F
    lassign $::tg::kit::sel($path) var values cmd w h
    $path delete all
    set bg [bgOf [winfo parent $path]]
    roundRect $path 0 0 $w $h [px 9] [col border] $bg
    roundRect $path 1 1 [expr {$w - 1}] [expr {$h - 1}] [expr {max(1, [px 9] - 1)}] [col field] [col border]
    $path create text [px 12] [expr {$h / 2}] -anchor w -text [uplevel #0 [list set $var]] -fill [col text] -font $F(body)
    $path create image [expr {$w - [px 18]}] [expr {$h / 2}] -image [icon chevron 16 muted]
}

proc ::tg::kit::selOpen {path} {
    lassign $::tg::kit::sel($path) var values cmd w h
    set m $path.menu
    catch {destroy $m}
    menu $m -tearoff 0
    foreach v $values {
        $m add command -label $v -command [list apply {{var v cmd} {
            uplevel #0 [list set $var $v]
            if {$cmd ne ""} { uplevel #0 [list {*}$cmd $v] }
        }} $var $v $cmd]
    }
    tk_popup $m [winfo rootx $path] [expr {[winfo rooty $path] + $h + 2}]
}

# ---------------------------------------------------------------- tooltip ----
proc ::tg::kit::tip {w text} {
    bind $w <Enter> [list ::tg::kit::tipSchedule %W $text]
    bind $w <Leave> [list ::tg::kit::tipHide]
    bind $w <ButtonPress> [list ::tg::kit::tipHide]
}
proc ::tg::kit::tipSchedule {w text} {
    variable tipJob
    tipHide
    set tipJob [after 550 [list ::tg::kit::tipShow $w $text]]
}
proc ::tg::kit::tipShow {w text} {
    variable tipWin
    variable F
    if {![winfo exists $w]} return
    set tipWin .tgktip
    catch {destroy $tipWin}
    toplevel $tipWin -background [col border]
    wm overrideredirect $tipWin 1
    label $tipWin.l -text $text -justify left -wraplength 360 -background [col surface2] -foreground [col text] \
        -font $F(small) -padx 11 -pady 8 -borderwidth 0
    pack $tipWin.l -padx 1 -pady 1
    wm geometry $tipWin +[expr {[winfo pointerx .] + 14}]+[expr {[winfo pointery .] + 18}]
}
proc ::tg::kit::tipHide {} {
    variable tipWin
    variable tipJob
    if {$tipJob ne ""} { after cancel $tipJob; set tipJob "" }
    if {$tipWin ne ""} { catch {destroy $tipWin}; set tipWin "" }
}

# ------------------------------------------------------------- scroll area ----
# Vertical scroll container. Returns the inner frame path ($path.c.f).
proc ::tg::kit::scroll {path parent} {
    frame $path -background [bgOf $parent] -borderwidth 0 -highlightthickness 0
    canvas $path.c -background [bgOf $parent] -highlightthickness 0 -borderwidth 0
    ttk::scrollbar $path.sb -orient vertical -style Kit.Vertical.TScrollbar -command "$path.c yview"
    $path.c configure -yscrollcommand [list ::tg::kit::scrollSet $path]
    frame $path.c.f -background [bgOf $parent] -borderwidth 0 -highlightthickness 0
    set ::tg::kit::scrollWin($path) [$path.c create window 0 0 -anchor nw -window $path.c.f]
    pack $path.c -side left -fill both -expand 1
    bind $path.c <Configure> [list ::tg::kit::scrollFit $path %w]
    bind $path.c.f <Configure> [list ::tg::kit::scrollRegion $path]
    foreach w [list $path.c $path.c.f] {
        bind $w <Enter> [list ::tg::kit::scrollBind $path]
        bind $w <Leave> [list ::tg::kit::scrollUnbind]
    }
    return $path.c.f
}
proc ::tg::kit::scrollSet {path a b} {
    if {![winfo exists $path.sb]} return
    $path.sb set $a $b
    if {$a <= 0.0 && $b >= 1.0} { pack forget $path.sb } else {
        if {![winfo ismapped $path.sb]} { pack $path.sb -side right -fill y -before $path.c }
    }
}
proc ::tg::kit::scrollFit {path w} {
    $path.c itemconfigure $::tg::kit::scrollWin($path) -width $w
}
proc ::tg::kit::scrollRegion {path} {
    $path.c configure -scrollregion [$path.c bbox all]
}
proc ::tg::kit::scrollBind {path} {
    bind all <MouseWheel> [list ::tg::kit::wheel $path %D]
    bind all <Button-4> [list ::tg::kit::wheel $path 120]
    bind all <Button-5> [list ::tg::kit::wheel $path -120]
}
proc ::tg::kit::scrollUnbind {} {
    bind all <MouseWheel> {}
    bind all <Button-4> {}
    bind all <Button-5> {}
}
proc ::tg::kit::wheel {path d} {
    if {![winfo exists $path.c]} return
    set step [expr {$d > 0 ? -3 : 3}]
    if {abs($d) < 120 && abs($d) > 0} { set step [expr {$d > 0 ? -1 : 1}] }
    $path.c yview scroll $step units
}

# --------------------------------------------------------------- dialogs ----
# Modal window with a rounded surface look. Returns the content frame.
proc ::tg::kit::dialog {name title args} {
    array set o {-width 520}
    array set o $args
    set t .$name
    catch {destroy $t}
    toplevel $t -background [col bg]
    wm title $t $title
    wm transient $t .
    wm resizable $t 0 0
    frame $t.f -background [col surface] -borderwidth 0 -highlightthickness 0
    pack $t.f -fill both -expand 1
    return $t.f
}

proc ::tg::kit::modal {t} {
    update idletasks
    set w [winfo reqwidth $t]; set h [winfo reqheight $t]
    set x [expr {[winfo rootx .] + ([winfo width .] - $w) / 2}]
    set y [expr {[winfo rooty .] + ([winfo height .] - $h) / 3}]
    wm geometry $t +[expr {max(0, $x)}]+[expr {max(0, $y)}]
    wm deiconify $t
    catch {grab $t}
    focus $t
    tkwait window $t
}

# Simple labelled helper
proc ::tg::kit::lbl {path parent text args} {
    variable F
    array set o {-font body -fg text -bg "" -anchor w -wrap 0 -justify left}
    array set o $args
    set bg [expr {$o(-bg) ne "" ? [col $o(-bg)] : [bgOf $parent]}]
    ::label $path -text $text -font $F($o(-font)) -foreground [col $o(-fg)] -background $bg -anchor $o(-anchor) \
        -justify $o(-justify) -borderwidth 0 -highlightthickness 0 -padx 0 -pady 0
    if {$o(-wrap)} { $path configure -wraplength [px $o(-wrap)] }
    return $path
}
