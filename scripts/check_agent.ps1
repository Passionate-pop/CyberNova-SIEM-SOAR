# Download agent.ps1 and check it
try {
    $r = Invoke-WebRequest -Uri "http://localhost:8888/agent.ps1" -UseBasicParsing
    $content = $r.Content
    Write-Host "TYPE: $($content.GetType().FullName)"
    Write-Host "LENGTH: $($content.Length) chars"
    Write-Host "--- FIRST 200 CHARS ---"
    Write-Host $content.Substring(0, [Math]::Min(200, $content.Length))
    Write-Host ""
    Write-Host "--- LAST 100 CHARS ---"
    Write-Host $content.Substring([Math]::Max(0, $content.Length - 100))
    Write-Host ""
    # Check for PowerShell syntax errors
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        Write-Host "PARSE ERRORS: $($parseErrors.Count)"
        $parseErrors | ForEach-Object { Write-Host "  $($_.ToString())" }
    } else {
        Write-Host "PARSE: NO SYNTAX ERRORS"
    }
} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
}
