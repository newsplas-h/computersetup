#Requires -RunAsAdministrator

# --- PHASE 1: SYSTEM CONTEXT ---
# 1. Install Chocolatey
Write-Host "Installing Chocolatey for all users..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-RestMethod https://chocolatey.org/install.ps1 | Invoke-Expression
$env:Path += ";$env:ProgramData\chocolatey\bin"

# 2. Install Applications via Chocolatey
Write-Host "Installing applications..." -ForegroundColor Cyan
$apps = @(
    "googlechrome",
    "7zip",
    "windirstat",
    "everything",
    "notepadplusplus",
    "vlc"
)

foreach ($app in $apps) {
    Write-Host "Installing $app..."
    choco install $app -y --force --no-progress
}

# 3. System-Wide Tweaks (HKLM)
Write-Host "Applying system-wide tweaks..." -ForegroundColor Cyan
# Remove Shortcut Overlay
$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
if (-not (Test-Path $keyPath)) {
    New-Item -Path $keyPath -Force | Out-Null
}
Set-ItemProperty -Path $keyPath -Name "29" -Value $null -Force

# 4. Configure Power Settings
Write-Host "Configuring power timeouts..." -ForegroundColor Cyan
# Get active power plan GUID
$activePlan = powercfg -getactivescheme
if ($activePlan -match '([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})') {
    $guid = $matches[1]
    
    # DC (Plugged in) - Unlimited timeout
    powercfg /setacvalueindex $guid SUB_VIDEO VIDEOIDLE 0
    powercfg /setacvalueindex $guid SUB_SLEEP STANDBYIDLE 0
    
    # Battery - 15 minute timeout
    powercfg /setdcvalueindex $guid SUB_VIDEO VIDEOIDLE 900
    powercfg /setdcvalueindex $guid SUB_SLEEP STANDBYIDLE 900
    
    # Apply changes
    powercfg /setactive $guid
    Write-Host "Power settings updated: DC=Unlimited, Battery=15 min" -ForegroundColor Green
} else {
    Write-Host "! Failed to detect active power plan" -ForegroundColor Red
}

# --- USER CONTEXT SETTINGS ---
Write-Host "Applying user preferences..." -ForegroundColor Cyan

# 1. Set Dark Mode
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force

# 2. Disable Snap Assist
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 0 -Force

# 3. Taskbar Configuration
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force  # Align left
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force

# 4. Classic Context Menu
$contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (-not (Test-Path $contextMenuPath)) {
    New-Item -Path $contextMenuPath -Force | Out-Null
}
Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force

# 5. Restart Explorer to apply changes
Write-Host "Restarting Explorer to apply changes..." -ForegroundColor Cyan
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
