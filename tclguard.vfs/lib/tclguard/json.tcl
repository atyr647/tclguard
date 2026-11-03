# json.tcl -- a small strict JSON reader/writer (Tcl 8.6 has none and tcllib is not in the starpack).
#
# parse: object -> dict, array -> list, string -> string, number -> number, true/false -> 1/0, null -> "".
# That loses the distinction between "" and null and between a one-element list and its element,
# which is irrelevant for the ACME and update documents this is used for; use the typed accessors
# in those modules.

namespace eval ::tg::json {}

proc ::tg::json::parse {text} {
    set pos 0
    set v [value $text pos]
    ws $text pos
    if {$pos < [string length $text]} { error "JSON: trailing data at offset $pos" }
    return $v
}

proc ::tg::json::ws {text posVar} {
    upvar 1 $posVar pos
    while {$pos < [string length $text] && [string first [string index $text $pos] " \t\r\n"] >= 0} { incr pos }
}

proc ::tg::json::value {text posVar {depth 0}} {
    upvar 1 $posVar pos
    if {$depth > 64} { error "JSON: nested too deeply" }
    ws $text pos
    set c [string index $text $pos]
    switch -- $c {
        \{ {
            incr pos
            set d {}
            ws $text pos
            if {[string index $text $pos] eq "\}"} { incr pos; return $d }
            while 1 {
                ws $text pos
                if {[string index $text $pos] ne "\""} { error "JSON: object key expected at $pos" }
                set k [string_ $text pos]
                ws $text pos
                if {[string index $text $pos] ne ":"} { error "JSON: ':' expected at $pos" }
                incr pos
                dict set d $k [value $text pos [expr {$depth + 1}]]
                ws $text pos
                set n [string index $text $pos]
                incr pos
                if {$n eq "\}"} { return $d }
                if {$n ne ","} { error "JSON: ',' or '\}' expected at [expr {$pos - 1}]" }
            }
        }
        \[ {
            incr pos
            set l {}
            ws $text pos
            if {[string index $text $pos] eq "\]"} { incr pos; return $l }
            while 1 {
                lappend l [value $text pos [expr {$depth + 1}]]
                ws $text pos
                set n [string index $text $pos]
                incr pos
                if {$n eq "\]"} { return $l }
                if {$n ne ","} { error "JSON: ',' or '\]' expected at [expr {$pos - 1}]" }
            }
        }
        \" { return [string_ $text pos] }
        default {
            if {[regexp -start $pos {\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?} $text num]} {
                incr pos [string length $num]
                return $num
            }
            foreach {lit val} {true 1 false 0 null {}} {
                if {[string range $text $pos [expr {$pos + [string length $lit] - 1}]] eq $lit} {
                    incr pos [string length $lit]
                    return $val
                }
            }
            error "JSON: unexpected character at offset $pos"
        }
    }
}

proc ::tg::json::string_ {text posVar} {
    upvar 1 $posVar pos
    incr pos                                   ;# opening quote
    set out ""
    while 1 {
        if {$pos >= [string length $text]} { error "JSON: unterminated string" }
        set c [string index $text $pos]
        if {$c eq "\""} { incr pos; return $out }
        if {$c eq "\\"} {
            incr pos
            set e [string index $text $pos]
            switch -- $e {
                b { append out \b } f { append out \f } n { append out \n } r { append out \r } t { append out \t }
                / - \\ - \" { append out $e }
                u {
                    set hex [string range $text [expr {$pos + 1}] [expr {$pos + 4}]]
                    if {![regexp {^[0-9a-fA-F]{4}$} $hex]} { error "JSON: bad \\u escape" }
                    set cp [scan $hex %x]
                    incr pos 4
                    if {$cp >= 0xD800 && $cp < 0xDC00} {              ;# surrogate pair
                        if {[string range $text [expr {$pos + 1}] [expr {$pos + 2}]] eq "\\u"} {
                            set lo [scan [string range $text [expr {$pos + 3}] [expr {$pos + 6}]] %x]
                            if {$lo >= 0xDC00 && $lo < 0xE000} {
                                set cp [expr {0x10000 + (($cp - 0xD800) << 10) + ($lo - 0xDC00)}]
                                incr pos 6
                            }
                        }
                    }
                    append out [format %c $cp]
                }
                default { error "JSON: bad escape \\$e" }
            }
            incr pos
            continue
        }
        if {[scan $c %c] < 0x20} { error "JSON: control character in string" }
        append out $c
        incr pos
    }
}

# ---- writing ----

proc ::tg::json::quote {s} {
    set out "\""
    foreach ch [split $s ""] {
        scan $ch %c n
        switch -- $ch {
            \" { append out {\"} } \\ { append out {\\} } \n { append out {\n} } \r { append out {\r} } \t { append out {\t} }
            default { if {$n < 0x20} { append out [format {\u%04x} $n] } else { append out $ch } }
        }
    }
    append out "\""
}

# Build a JSON object from key/value pairs where each value is already JSON text.
proc ::tg::json::object {args} {
    set parts {}
    foreach {k v} $args { lappend parts "[quote $k]:$v" }
    return "{[join $parts ,]}"
}
proc ::tg::json::array {args} { return "\[[join $args ,]\]" }

# Safe accessor: dict get with a default, walking a path.
proc ::tg::json::get {doc path {default ""}} {
    foreach k $path {
        if {![string is list -strict $doc] || [catch {dict exists $doc $k} ok] || !$ok} { return $default }
        set doc [dict get $doc $k]
    }
    return $doc
}
