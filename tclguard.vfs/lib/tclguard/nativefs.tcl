# nativefs.tcl -- file operations on the RUNNING PROGRAM'S OWN FILE.
#
# A starpack is mounted as a virtual folder over its own path, so Tcl's file commands applied to that path
# act on the files INSIDE it: `file copy` produces a folder of the contents, `file rename` "succeeds" without
# touching the real program, `file isfile` is false. The installer and the updater must operate on the real
# file, so they use the operating system's own tools here (cp / mv / cmp / test on Unix, PowerShell on
# Windows), which know nothing about Tcl's virtual file systems.
#
# Only use these for the program file itself; everything else (temp files next to it, downloads) is plain Tcl.
# Chosen by the real platform (not a simulated one).

namespace eval ::tg::nfs {
    variable realWin [expr {$::tcl_platform(platform) eq "windows"}]   ;# captured at load: tests simulate other platforms
}

proc ::tg::nfs::win {} { variable realWin; return $realWin }

proc ::tg::nfs::q {path} { ::tg::install::psq [file nativename $path] }

# Run a PowerShell script (Windows); raises with PowerShell's message on failure.
proc ::tg::nfs::ps {script} {
    if {[catch {exec {*}[::tg::install::psArgv "\$ErrorActionPreference='Stop'; $script"] 2>@1} out]} {
        error [string trim $out]
    }
    return $out
}

proc ::tg::nfs::copy {src dst} {
    if {[win]} { ps "Copy-Item -LiteralPath [q $src] -Destination [q $dst] -Force"; return }
    if {[catch {exec cp -- $src $dst 2>@1} out]} { error [string trim $out] }
}

# Rename, replacing dst.
proc ::tg::nfs::move {src dst} {
    if {[win]} { ps "Move-Item -LiteralPath [q $src] -Destination [q $dst] -Force"; return }
    if {[catch {exec mv -f -- $src $dst 2>@1} out]} { error [string trim $out] }
}

# Byte-for-byte equality of two files.
proc ::tg::nfs::same {a b} {
    if {[win]} {
        return [expr {![catch {ps "if ((Get-FileHash -LiteralPath [q $a]).Hash -ne (Get-FileHash -LiteralPath [q $b]).Hash) { exit 1 }"}]}]
    }
    expr {![catch {exec cmp -s -- $a $b 2>@1}]}
}

# Is it a regular file (the real one, not Tcl's virtual folder)?
proc ::tg::nfs::isFile {path} {
    if {[win]} {
        return [expr {![catch {ps "if (-not (Test-Path -LiteralPath [q $path] -PathType Leaf)) { exit 1 }"}]}]
    }
    expr {![catch {exec test -f $path 2>@1}]}
}
