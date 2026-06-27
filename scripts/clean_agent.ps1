# Kill any old CyberNova agent processes and clean up
Write-Host "Killing old agent processes..."
Get-Process | Where-Object {
    $proc = $_
    try {
        $cmd = $proc.CommandLine
        return ($cmd -match 'CyberNova' -or $cmd -match 'hostdefender')
    } catch {
        return $false
    }
} | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "Unregistering old scheduled task..."
try {
    Unregister-ScheduledTask -TaskName "CyberNova-HostDefender" -Confirm:$false -ErrorAction Stop
    Write-Host "  Task unregistered"
} catch {
    Write-Host "  No existing task or already removed"
}

Write-Host "Cleaning install directory..."
Remove-Item "C:\Program Files\CyberNova" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Done - ready for fresh install"
