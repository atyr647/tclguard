# Run a program with a hard time limit and stream what it prints, so a hang shows
# exactly how far it got.  Used by CI.
#   pwsh -File tools/ci-bounded.ps1 -Exe path.exe -Seconds 120 eval script.tcl
param(
    [Parameter(Mandatory)][string]$Exe,
    [int]$Seconds = 120,
    [Parameter(ValueFromRemainingArguments)][string[]]$Arguments = @()
)
$tmp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$id = [guid]::NewGuid().ToString('N').Substring(0, 8)
$so = Join-Path $tmp "bounded-$id.out"
$se = Join-Path $tmp "bounded-$id.err"
$p = Start-Process -FilePath $Exe -ArgumentList $Arguments -NoNewWindow -PassThru `
    -RedirectStandardOutput $so -RedirectStandardError $se
$null = $p.Handle   # keep the handle so ExitCode is readable afterwards

# Read a file that another process still has open for writing.
function Open-Shared($path) {
    for ($i = 0; $i -lt 50; $i++) {
        if (Test-Path $path) {
            try {
                $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite,Delete')
                return New-Object IO.StreamReader($fs)
            } catch { }
        }
        Start-Sleep -Milliseconds 100
    }
    $null
}
function Drain($r) { if ($r) { $t = $r.ReadToEnd(); if ($t) { Write-Host -NoNewline $t } } }

$rOut = Open-Shared $so
$rErr = Open-Shared $se
$deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
while (-not $p.HasExited -and [DateTime]::UtcNow -lt $deadline) {
    Drain $rOut
    Start-Sleep -Milliseconds 250
}
$timedOut = -not $p.HasExited
if ($timedOut) {
    Write-Host "!! still running after $Seconds s - killing it"
    & taskkill /F /T /PID $p.Id 2>&1 | Out-Null
    $null = $p.WaitForExit(10000)
} else {
    $null = $p.WaitForExit()
}
Drain $rOut
$errText = if ($rErr) { $rErr.ReadToEnd() } else { '' }
if ($errText) { Write-Host '--- stderr'; Write-Host $errText }
if ($rOut) { $rOut.Dispose() }
if ($rErr) { $rErr.Dispose() }
if ($timedOut) { exit 124 }
exit $p.ExitCode
