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
    if {[win]} {
        ps [join [list \
            "for (\$i = 0; \$i -lt 8; \$i++) {" \
            "  try { Move-Item -LiteralPath [q $src] -Destination [q $dst] -Force -ErrorAction Stop; break }" \
            "  catch { if (\$i -eq 7) { throw }; Start-Sleep -Milliseconds 500 }" \
            "}"] "\n"]
        return
    }
    if {[catch {exec mv -f -- $src $dst 2>@1} out]} { error [string trim $out] }
}

# Byte-for-byte equality of two files. On Windows a file that was written a moment ago is often held open for a short
# while by the virus scanner (a 12 MB .exe always is), so reading it can fail with "being used by another process": retry.
# The reason of the last failure is kept in lastError for the messages of the callers.
namespace eval ::tg::nfs { variable lastError "" }
proc ::tg::nfs::same {a b} {
    variable lastError
    set lastError ""
    if {[win]} {
        # SHA-256 with .NET directly, not Get-FileHash: that cmdlet lives in an auto-loaded script module, and a PowerShell started
        # from a parent that set PSModulePath for another PowerShell edition (CI runners, some shells) does not find it.
        set script [join [list \
            "function TgHash(\$p) { \$s = \[System.IO.File]::Open(\$p, 'Open', 'Read', 'ReadWrite,Delete'); try { return \[System.BitConverter]::ToString(\[System.Security.Cryptography.SHA256]::Create().ComputeHash(\$s)) } finally { \$s.Close() } }" \
            "\$ha = \$null; \$hb = \$null; \$err = ''" \
            "for (\$i = 0; \$i -lt 40; \$i++) {" \
            "  try { \$ha = TgHash [q $a]; \$hb = TgHash [q $b]; break }" \
            "  catch { \$err = \$_.Exception.Message; \$ha = \$null; Start-Sleep -Milliseconds 500 }" \
            "}" \
            "if (\$ha -eq \$null) { Write-Output \"cannot read: \$err\"; exit 2 }" \
            "if (\$ha -ne \$hb) { Write-Output 'different'; exit 1 }"] "\n"]
        if {[catch {ps $script} out]} { set lastError $out; return 0 }
        return 1
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
