# Prompt the user to enter the full URL to the Default.ppkg file
$ppkgUrl = Read-Host "Please enter the full URL to the Default.ppkg file"

# Define the local path to save the .ppkg file
$ppkgPath = "$env:TEMP\Default.ppkg"

# Download the .ppkg file from the user-provided URL
Invoke-WebRequest -Uri $ppkgUrl -OutFile $ppkgPath

# Install the .ppkg silently
Add-ProvisioningPackage -PackagePath $ppkgPath -QuietInstall

# Define the path for Script 2 (must persist after reboot)
$script2Path = "C:\Windows\Temp\PostInstall.ps1"

# Create a scheduled task to run Script 2 at user logon
$taskName = "PostInstallTask"
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$script2Path`""
$taskTrigger = New-ScheduledTaskTrigger -AtLogon
$taskSettings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable
$taskPrincipal = New-ScheduledTaskPrincipal -GroupId "Users"  # Runs for any user in the Users group

# Register the scheduled task
Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Force

# Optional: Copy Script 2 to the target location if not already present
# Copy-Item -Path ".\PostInstall.ps1" -Destination $script2Path -Force
