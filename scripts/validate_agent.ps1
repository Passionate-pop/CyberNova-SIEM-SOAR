$ProgressPreference = "SilentlyContinue"
$resp = Invoke-WebRequest -Uri "http://localhost:8888/agent.ps1" -UseBasicParsing
$resp.Content | Out-File "C:\Users\HP\CYBERNOVA\agent_validated.ps1" -Encoding UTF8
$len = (Get-Item "C:\Users\HP\CYBERNOVA\agent_validated.ps1").Length
Write-Host "Downloaded agent.ps1: $len bytes"
$parseErrors = @()
$null = [System.Management.Automation.Language.Parser]::ParseFile("C:\Users\HP\CYBERNOVA\agent_validated.ps1", [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    Write-Host "PARSE ERRORS:"
    foreach ($e in $parseErrors) {
        Write-Host "  Line $($e.Extent.StartLineNumber): $($e.Message)"
    }
} else {
    Write-Host "SCRIPT VALIDATED - NO SYNTAX ERRORS"
}
