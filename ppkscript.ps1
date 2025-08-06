# Save as provision.ps1
$logPath = 'C:\ProvisionLog.txt'
$scriptPath = 'C:\Script.ps1'
$githubUrl = 'https://raw.githubusercontent.com/newsplas-h/computersetup/main/newscript.ps1'

# Start fresh log
"Provisioning started at $(Get-Date)" | Out-File $logPath

try {
    # Download script
    "Downloading script from GitHub..." | Out-File $logPath -Append
    (New-Object System.Net.WebClient).DownloadFile($githubUrl, $scriptPath)
    
    # Verify download
    if (-not (Test-Path $scriptPath)) {
        throw "Download failed - file not found"
    }
    "Download completed to $scriptPath" | Out-File $logPath -Append

    # Create a scheduled task to ensure execution policy bypass
    "Creating scheduled task for execution..." | Out-File $logPath -Append
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
    Register-ScheduledTask -Action $action -Trigger $trigger `
        -TaskName "ProvisionScript" -RunLevel Highest -Force | Out-Null
    
    "Starting scheduled task..." | Out-File $logPath -Append
    Start-ScheduledTask -TaskName "ProvisionScript"
    
    # Wait for task completion
    "Waiting for task completion..." | Out-File $logPath -Append
    do {
        Start-Sleep -Seconds 5
        $taskState = (Get-ScheduledTask -TaskName "ProvisionScript").State
        "Current task state: $taskState" | Out-File $logPath -Append
    } while ($taskState -eq 'Running')
    
    "Task completed with state: $taskState" | Out-File $logPath -Append
    exit 0
}
catch {
    $errorMsg = $_.Exception.Message
    "ERROR: $errorMsg" | Out-File $logPath -Append
    exit 1
}
finally {
    "Provisioning finished at $(Get-Date)" | Out-File $logPath -Append
}
