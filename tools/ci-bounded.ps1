# Run a program with a hard time limit, capture stdout+stderr to files, always print them.
# Used by CI so a hang shows what the program printed before it stopped.
#   pwsh tools/ci-bounded.ps1 -Seconds 120 -Exe path.exe -Arguments 'eval','script.tcl'
param(
    [Parameter(Mandatory)][string]$Exe,
    [string[]]$Arguments = @(),
    [int]$Seconds = 120
)
$tmp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$id = [guid]::NewGuid().ToString('N').Substring(0, 8)
$so = Join-Path $tmp "bounded-$id.out"
$se = Join-Path $tmp "bounded-$id.err"
$p = Start-Process -FilePath $Exe -ArgumentList $Arguments -NoNewWindow -PassThru `
    -RedirectStandardOutput $so -RedirectStandardError $se
$null = $p.Handle   # keep the handle so ExitCode is readable afterwards
$done = $p.WaitForExit($Seconds * 1000)
if (-not $done) {
    Write-Host "!! still running after $Seconds s - killing it"
    & taskkill /F /T /PID $p.Id 2>&1 | Out-Null
}
Get-Content $so -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
if ((Get-Item $se -ErrorAction SilentlyContinue).Length -gt 0) {
    Write-Host '--- stderr'
    Get-Content $se | ForEach-Object { Write-Host $_ }
}
if (-not $done) { exit 124 }
exit $p.ExitCode
