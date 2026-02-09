<#
.SYNOPSIS
    Creates a scheduled task to run a GitHub script at user logon.
    Intended for use in a Windows Provisioning Package.
#>

$taskName = "Run Setup Script at Logon"
$githubUrl = "https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/newscript.ps1"
$taskDescription = "Downloads and runs the latest setup script from GitHub at logon."
$logFile = "C:\Temp\SetupLog.txt" # All output from the GitHub script will be saved here.

try {
    # Create the directory for the log file if it doesn't exist.
    if (-not (Test-Path (Split-Path $logFile -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $logFile -Parent) -Force | Out-Null
    }

    # This command now includes logging. It will:
    # 1. Start a transcript (log) at the specified path.
    # 2. Download and run your script from GitHub.
    # 3. Stop the transcript.
    $commandToRun = "Start-Transcript -Path '$logFile' -Force; Invoke-Expression (Invoke-RestMethod -Uri '$githubUrl'); Stop-Transcript"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -NoProfile -Command `"$commandToRun`""

    # Configure the task to run at logon with the highest privileges.
    $trigger = @(
        New-ScheduledTaskTrigger -AtStartup
        New-ScheduledTaskTrigger -AtLogOn
    )
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest -LogonType ServiceAccount

    # Unregister the task if it already exists to ensure it's always up-to-date.
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    # Register the new scheduled task.
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription -Force
    Start-ScheduledTask -TaskName $taskName

    # Exit with success code.
    exit 0
}
catch {
    # Exit with an error code if something goes wrong.
    Write-Error "Failed to create scheduled task: $_"
    exit 1
}
