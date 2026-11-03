# Facts about a RUNNING starpack on Windows: which operations does the operating system allow on its file while it
# runs? (A starpack keeps its own file open to read the virtual file system it carries.)  Prints one line each.
#   powershell -File windows_lock_probe.ps1 <path-to-starpack-console.exe>
param([string]$Exe)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$w = Join-Path $env:RUNNER_TEMP 'lockprobe'
Remove-Item -Recurse -Force $w -ErrorAction SilentlyContinue
New-Item -ItemType Directory $w | Out-Null

function Try-Op([string]$name, [scriptblock]$op) {
    try { & $op | Out-Null; "probe: OK    $name" } catch { "probe: FAIL  $name  -> " + $_.Exception.Message.Trim() }
}

function Run-Probes([string]$label, [string]$path) {
    "probe: ---- $label"
    Try-Op "read it (Get-FileHash)"                    { Get-FileHash -LiteralPath $path -ErrorAction Stop }
    Try-Op "copy it (Copy-Item)"                       { Copy-Item -LiteralPath $path -Destination "$path.copy" -Force -ErrorAction Stop }
    Try-Op "the copy has the same hash as the original" { if ((Get-FileHash -LiteralPath $path).Hash -ne (Get-FileHash -LiteralPath "$path.copy").Hash) { throw "hashes differ" } }
    Try-Op "open for read, share Read only"            { $f = [IO.File]::Open($path, 'Open', 'Read', 'Read'); $f.Close() }
    Try-Op "open for read, share ReadWrite+Delete"     { $f = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite,Delete'); $f.Close() }
    Try-Op "rename it (Move-Item to .old)"             { Move-Item -LiteralPath $path -Destination "$path.old" -Force -ErrorAction Stop }
    if (Test-Path -LiteralPath "$path.old") {
        Try-Op "put a new file at the original name"   { Copy-Item -LiteralPath "$path.copy" -Destination $path -Force -ErrorAction Stop }
    } else {
        Try-Op "overwrite it in place (Copy-Item -Force)" { Copy-Item -LiteralPath "$path.copy" -Destination $path -Force -ErrorAction Stop }
        Try-Op "delete it (Remove-Item)"               { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
    }
}

# baseline: an ordinary running program
$base = Join-Path $w 'ping.exe'
Copy-Item "$env:SystemRoot\System32\PING.EXE" $base
$p0 = Start-Process -FilePath $base -ArgumentList '-n','30','127.0.0.1' -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
Run-Probes 'ordinary running program (baseline)' $base
Stop-Process -Id $p0.Id -Force -ErrorAction SilentlyContinue

# the starpack, running a script that just waits
$exe = Join-Path $w 'tg.exe'
Copy-Item -LiteralPath $Exe -Destination $exe
$script = Join-Path $w 'wait.tcl'
Set-Content -Path $script -Value 'after 40000 {set ::done 1}; vwait ::done' -Encoding ASCII
$p1 = Start-Process -FilePath $exe -ArgumentList 'eval',$script -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 4
"probe: starpack running: " + (-not $p1.HasExited)
Run-Probes 'running starpack' $exe
Stop-Process -Id $p1.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
"probe: ---- after it exits"
Try-Op "delete the .old left behind" { Remove-Item -LiteralPath "$exe.old" -Force -ErrorAction Stop }
