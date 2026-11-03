#!/usr/bin/env tclsh8.6
# build.tcl -- package TclGuard as a starkit / starpack.
#
#   tclsh build.tcl [options]
#
#   --runtime FILE   a tclkit/basekit executable to prepend, producing a starpack
#                    (single self-contained program). Without it you get the
#                    payload only (tclguard.kit / tclguard.zip) which any
#                    compatible runtime can run:  tclkit tclguard.kit
#   --format F       mk4  Metakit payload (classic tclkit; needs the vfs::mk4
#                        package, i.e. run this script with a tclkit)
#                    zip  zip payload (zipkit; needs only Tcl 8.6 + tcllib)
#                    auto mk4 when vfs::mk4 is available, otherwise zip
#   --out FILE       output path (default dist/tclguard[.exe] | dist/tclguard.kit)
#   --check          after building, verify the payload by mounting it
#
# Typical use:
#   tclkit-8.6 build.tcl --runtime tclkit-8.6-linux-x86_64 --out dist/tclguard-linux
#   tclkit-8.6 build.tcl --runtime tclkit-8.6-win64.exe    --out dist/tclguard.exe
# (the payload is platform independent, so one machine can build both)

set here [file dirname [file normalize [info script]]]
set vfs [file join $here tclguard.vfs]

proc usage {} {
    puts "usage: tclsh build.tcl \[--runtime FILE\] \[--format mk4|zip|auto\] \[--out FILE\] \[--check\]"
    exit 1
}

array set opt {runtime "" format auto out "" check 0}
for {set i 0} {$i < [llength $argv]} {incr i} {
    switch -- [lindex $argv $i] {
        --runtime { set opt(runtime) [lindex $argv [incr i]] }
        --format  { set opt(format)  [lindex $argv [incr i]] }
        --out     { set opt(out)     [lindex $argv [incr i]] }
        --check   { set opt(check) 1 }
        -h - --help { usage }
        default { puts "unknown option [lindex $argv $i]"; usage }
    }
}

if {![file isdirectory $vfs]} { puts "cannot find $vfs"; exit 1 }
if {$opt(runtime) ne "" && ![file exists $opt(runtime)]} { puts "runtime $opt(runtime) not found"; exit 1 }

set haveMk4 [expr {![catch {package require vfs::mk4}]}]
if {$opt(format) eq "auto"} { set opt(format) [expr {$haveMk4 ? "mk4" : "zip"}] }
if {$opt(format) eq "mk4" && !$haveMk4} {
    puts "format mk4 needs the vfs::mk4 package: run this script with a tclkit (tclkit build.tcl ...)"
    exit 1
}
if {$opt(out) eq ""} {
    set ext [expr {$opt(runtime) eq "" ? ".kit" : ([string match *.exe $opt(runtime)] ? ".exe" : "")}]
    set opt(out) [file join $here dist tclguard$ext]
}
file mkdir [file dirname $opt(out)]

# ---- version stamp -------------------------------------------------------------
set vfile [file join $vfs lib tclguard util.tcl]
set fh [open $vfile r]; set txt [read $fh]; close $fh
regexp {variable VERSION (\S+)} $txt -> version
puts "TclGuard $version -> $opt(out)  (payload: $opt(format)[expr {$opt(runtime) ne {} ? {, runtime: } : {}}][file tail $opt(runtime)])"

# ---- stage: copy the vfs tree without junk --------------------------------------
set stage [file join $here dist stage]
file delete -force $stage
file mkdir $stage
proc copyTree {src dst} {
    foreach f [glob -nocomplain -directory $src *] {
        set name [file tail $f]
        if {[string match .* $name] || [string match *~ $name] || [string match *.bak $name]} continue
        if {[file isdirectory $f]} {
            file mkdir [file join $dst $name]
            copyTree $f [file join $dst $name]
        } else {
            file copy -force $f [file join $dst $name]
        }
    }
}
copyTree $vfs $stage

# ---- wrap ------------------------------------------------------------------------
switch -- $opt(format) {
    zip {
        package require zipfile::mkzip
        if {$opt(runtime) ne ""} {
            zipfile::mkzip::mkzip $opt(out) -runtime $opt(runtime) -directory $stage
        } else {
            zipfile::mkzip::mkzip $opt(out) -directory $stage
        }
    }
    mk4 {
        # Same steps sdx's "wrap" performs: runtime (or a minimal header) first,
        # then a Metakit-backed VFS appended and filled from the staging tree.
        if {$opt(runtime) ne ""} {
            file copy -force $opt(runtime) $opt(out)
        } else {
            set fh [open $opt(out) w]; fconfigure $fh -translation binary
            puts -nonewline $fh "#!/bin/sh\n# \\\nexec tclkit \"\$0\" \${1+\"\$@\"}\npackage require starkit\nstarkit::header mk4\n\x1a################################################################################\n"
            close $fh
        }
        vfs::mk4::Mount $opt(out) $opt(out)
        foreach f [glob -nocomplain -directory $stage *] { file copy -force $f $opt(out) }
        vfs::unmount $opt(out)
    }
    default { puts "unknown format $opt(format)"; exit 1 }
}
catch {file attributes $opt(out) -permissions 0755}
file delete -force $stage
puts "wrote $opt(out) ([expr {[file size $opt(out)] / 1024}] KB)"

# ---- optional verification --------------------------------------------------------
if {$opt(check)} {
    if {$opt(format) ne "zip"} { puts "--check currently verifies zip payloads only"; exit 0 }
    package require vfs::zip
    set mnt [file join $here dist mnt-check]
    set id [vfs::zip::Mount $opt(out) $mnt]
    set bad 0
    foreach must {main.tcl lib/tclguard/pkgIndex.tcl lib/tclguard/engine.tcl lib/tclguard/install.tcl lib/tclguard/update.tcl lib/tclguard/vendor/sha256.tcl lib/tclguard/vendor/update-key.pub} {
        if {![file exists [file join $mnt $must]]} { puts "MISSING in payload: $must"; incr bad }
    }
    vfs::zip::Unmount $id $mnt
    if {$bad} { exit 1 }
    puts "payload verified"
}

exit 0
