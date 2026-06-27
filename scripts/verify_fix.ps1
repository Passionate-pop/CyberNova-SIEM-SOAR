$r = Invoke-WebRequest -Uri "http://localhost:8888/agent.ps1" -UseBasicParsing
$content = $r.Content

# Check for remaining 'exit' in the WINDOWS agent section (before LINUX_AGENT)
$exitLines = $content -split "`n" | Where-Object { $_ -match 'exit ' -and $_ -notmatch 'PSEOF|sys\.exit|subprocess\.run.*systemctl' }
if ($exitLines.Count -gt 0) {
    Write-Host "REMAINING EXIT CALLS:"
    $exitLines | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "NO exit calls in Windows agent section - GOOD"
}

# Parse for syntax errors
$errors = $null
[System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$errors)
if ($errors.Count -gt 0) {
    Write-Host "PARSE ERRORS: $($errors.Count)"
    $errors | ForEach-Object { Write-Host "  $($_.ToString())" }
} else {
    Write-Host "PARSE: NO SYNTAX ERRORS"
}

Write-Host "LENGTH: $($content.Length) chars"
