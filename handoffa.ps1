# --- PHASE 1: SYSTEM-WIDE PREFERENCES ---
Write-Host "Applying system-wide preferences..." -ForegroundColor Cyan
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

# --- PHASE 2: AUTOMATED HANDOFF (RUNS FIRST FOR RESPONSIVENESS) ---
Write-Host "Handing off to user-context script immediately..." -ForegroundColor Cyan
try {
    # Get the currently logged-in user
    $currentUser = (Get-WmiObject -Class Win32_LogonSession -Filter "LogonType=2" | ForEach-Object { Get-WmiObject -Query "Associators of {Win32_LogonSession.LogonId=$($_.LogonId)} Where AssocClass=Win32_LoggedOnUser Role=Dependent" } | Select-Object -First 1).Name

    if ($currentUser) {
        $userTaskName = "Run User Setup"
        $userScriptUrl = "[https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/handoffb.ps1](https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/handoffb.ps1)" # <-- IMPORTANT: URL for Script #3
        $userCommand = "Invoke-Expression (Invoke-RestMethod -Uri '$userScriptUrl')"
        $userAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -NoProfile -Command `"$userCommand`""
        
        # Trigger this task to run 15 seconds from now
        $userTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(15)
        
        # Register the task to run as the logged-in user
        Register-ScheduledTask -TaskName $userTaskName -Action $userAction -Trigger $userTrigger -User $currentUser -Force
        Write-Host "Successfully created handoff task for user: $currentUser"
    } else {
        Write-Warning "Could not find an active logged-in user to hand off to."
    }
} catch {
    Write-Error "Handoff failed: $_"
}

# --- PHASE 3: APPLICATION INSTALLATION (RUNS IN BACKGROUND) ---
Write-Host "Installing applications in the background..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-RestMethod [https://chocolatey.org/install.ps1](https://chocolatey.org/install.ps1) | Invoke-Expression
$env:Path += ";$env:ProgramData\chocolatey\bin"
$apps = @("googlechrome", "firefox", "7zip", "windirstat", "everything", "notepadplusplus", "vlc")
foreach ($app in $apps) {
    choco install $app -y --force --no-progress
}

# --- PHASE 4: FINAL SYSTEM CLEANUP ---
Write-Host "System setup complete. Cleaning up system task..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName "Run System Setup" -Confirm:$false -ErrorAction SilentlyContinue
```powershell
