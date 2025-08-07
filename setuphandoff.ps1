$taskName = "Run System Setup"
$githubUrl = "https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/handoffa.ps1 # <-- IMPORTANT: URL for Script #2
$taskDescription = "Runs the main system configuration script as SYSTEM."

try {
    # This command downloads and runs the main SYSTEM script.
    $command = "Invoke-Expression (Invoke-RestMethod -Uri '$githubUrl')"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -NoProfile -Command `"$command`""

    # Configure the task to run at logon with the highest privileges.
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest

    # Register the new scheduled task.
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription -Force

    exit 0
}
catch {
    Write-Error "Failed to create initial scheduled task: $_"
    exit 1
}
```powershell
