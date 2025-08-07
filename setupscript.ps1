<#
.SYNOPSIS
    Creates a scheduled task to run a GitHub script at user logon.
    Intended for use in a Windows Provisioning Package.
#>

$taskName = "Run Setup Script at Logon"
$githubUrl = "https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/newscript.ps1"
$taskDescription = "Downloads and runs the latest setup script from GitHub at logon."

try {
    # This command downloads and runs the script from GitHub directly in memory.
    $command = "Invoke-Expression (Invoke-RestMethod -Uri '$githubUrl')"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -NoProfile -Command `"$command`""

    # Configure the task to run at logon with the highest privileges.
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest

    # Unregister the task if it already exists to ensure it's always up-to-date.
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    # Register the new scheduled task.
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription -Force

    # Exit with success code.
    exit 0
}
catch {
    # Exit with an error code if something goes wrong.
    Write-Error "Failed to create scheduled task: $_"
    exit 1
}