# --- SYSTEM-WIDE PREFERENCES & APP INSTALLATION ---
Write-Host "Applying system-wide preferences..."
# Remove Shortcut Arrow
$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
Set-ItemProperty -Path $keyPath -Name "29" -Value "%SystemRoot%\System32\shell32.dll,-50" -Type String -Force

# Configure Power Settings
$activePlan = powercfg -getactivescheme
if ($activePlan -match '([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})') {
    $guid = $matches[1]
    powercfg /setacvalueindex $guid SUB_VIDEO VIDEOIDLE 0
    powercfg /setacvalueindex $guid SUB_SLEEP STANDBYIDLE 0
    powercfg /setdcvalueindex $guid SUB_VIDEO VIDEOIDLE 900
    powercfg /setdcvalueindex $guid SUB_SLEEP STANDBYIDLE 900
    powercfg /setactive $guid
}

Write-Host "Installing applications..."
Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-RestMethod [https://chocolatey.org/install.ps1](https://chocolatey.org/install.ps1) | Invoke-Expression
$env:Path += ";$env:ProgramData\chocolatey\bin"
$env:ChocolateyNonInteractive = 'true'
$apps = @("googlechrome", "firefox", "7zip", "windirstat", "everything", "notepadplusplus", "vlc")
foreach ($app in $apps) {
    Write-Host "Installing $app..."
    choco install $app -y --force --no-progress --ignore-checksums
}

# Cleanup DefaultUser0 profile if it exists
$defaultUserPath = "C:\Users\defaultuser0"
if (Test-Path $defaultUserPath) {
    Write-Host "Removing DefaultUser0 profile..."
    Remove-Item -Path $defaultUserPath -Recurse -Force -ErrorAction SilentlyContinue
}

# --- HANDOFF TO USER SCRIPT ---
Write-Host "Creating temporary handoff task to run user setup..."
try {
    # Find the active logged-on user
    $currentUser = (Get-WmiObject -Class Win32_LogonSession -Filter "LogonType=2" | ForEach-Object { Get-WmiObject -Query "Associators of {Win32_LogonSession.LogonId=$($_.LogonId)} Where AssocClass=Win32_LoggedOnUser Role=Dependent" } | Select-Object -First 1).Name
    
    if ($currentUser) {
        $userTaskName = "Run User Setup"
        $userScriptUrl = "[https://raw.githubusercontent.com/newsplas-h/computersetup/main/usrscript.ps1](https://raw.githubusercontent.com/newsplas-h/computersetup/main/usrscript.ps1)"
        $userCommand = "Invoke-Expression (Invoke-RestMethod -Uri '$userScriptUrl')"
        $userAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -NoProfile -Command `"$userCommand`""
        
        # Trigger this task to run 15 seconds from now.
        $userTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(15)
        
        Register-ScheduledTask -TaskName $userTaskName -Action $userAction -Trigger $userTrigger -User $currentUser -Force
        Write-Host "Successfully created handoff task for user: $currentUser"
    }
} catch {
    Write-Error "Handoff failed: $_"
}

# --- SELF-CLEANUP ---
Write-Host "System setup complete. Cleaning up system task..."
Unregister-ScheduledTask -TaskName "Run System Setup" -Confirm:$false -ErrorAction SilentlyContinue
