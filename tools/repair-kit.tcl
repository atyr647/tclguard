# Repairs lib/vfs/pkgIndex.tcl inside a freshly built macOS tclkit.
#   <the kit> tools/repair-kit.tcl <a COPY of the kit>
# KitCreator's tclvfs install step leaves an `ar` archive ("!<arch>") where that file should be on macOS, so every
# `package require` prints "error reading package index file ... invalid command name "!<arch>"". The correct file is a plain,
# platform-independent Tcl script (tools/vfs-pkgIndex.tcl, taken from the working Linux kit).
set kit [lindex $argv 0]
set good [file join [file dirname [info script]] vfs-pkgIndex.tcl]
package require vfs::mk4
vfs::mk4::Mount $kit $kit
set target [file join $kit lib vfs pkgIndex.tcl]
set fh [open $target rb]; set head [read $fh 8]; close $fh
if {[string match "!<arch>*" $head]} {
    file copy -force $good $target
    puts "repaired $target (it was an archive)"
} else {
    puts "$target is fine"
}
vfs::unmount $kit
exit 0
