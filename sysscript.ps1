# --- PHASE 1: SYSTEM-WIDE PREFERENCES ---
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

# --- PHASE 2: APPLICATION INSTALLATION ---
Write-Host "Installing applications..."
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-RestMethod [https://chocolatey.org/install.ps1](https://chocolatey.org/install.ps1) | Invoke-Expression
$env:Path += ";$env:ProgramData\chocolatey\bin"
$apps = @("googlechrome", "firefox", "7zip", "windirstat", "everything", "notepadplusplus", "vlc")
foreach ($app in $apps) {
    choco install $app -y --force --no-progress
}

# --- SELF-CLEANUP ---
Write-Host "System setup complete. Cleaning up system task..."
Unregister-ScheduledTask -TaskName "Run System Setup" -Confirm:$false -ErrorAction SilentlyContinue
```powershell
