#Requires -RunAsAdministrator
Start-Transcript -Path "$env:TEMP\PostLoginSetup.log" -Append

# 1. Install Chocolatey
Write-Host "Installing Chocolatey..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
RefreshEnv.cmd

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
    Start-Sleep -Seconds 2
}

# 3. Set Dark Mode
Write-Host "Configuring Dark Mode..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Type DWord

# 4. Remove Shortcut Overlay
Write-Host "Removing shortcut overlays..." -ForegroundColor Cyan
$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
if (-not (Test-Path $keyPath)) {
    New-Item -Path $keyPath -Force | Out-Null
}
Set-ItemProperty -Path $keyPath -Name "29" -Value "%SystemRoot%\system32\imageres.dll,-1015" -Type String

# 5. Snap Window Settings
Write-Host "Configuring Snap Assist..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WindowArrangementActive" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 0 -Type DWord

# 6. Taskbar Configuration
Write-Host "Configuring Taskbar..." -ForegroundColor Cyan
# Move to left
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Type DWord

# Disable Task View
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Type DWord

# Disable Widgets
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Type DWord

# Hide Search Bar
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Type DWord

# 7. Windows 10 Style Context Menu
Write-Host "Enabling Classic Context Menu..." -ForegroundColor Cyan
$contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
if (-not (Test-Path $contextMenuPath)) {
    New-Item -Path $contextMenuPath -Force | Out-Null
    New-Item -Path "$contextMenuPath\InprocServer32" -Force | Out-Null
}
Set-ItemProperty -Path "$contextMenuPath\InprocServer32" -Name "(Default)" -Value "" -Type String

# 8. Refresh Explorer
Write-Host "Applying changes..." -ForegroundColor Cyan
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# 9. Force Password Change
Write-Host "Configuring password policy..." -ForegroundColor Cyan
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
net user $currentUser /logonpasswordchg:yes

# Create scheduled task for password prompt
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command `"Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Your password must be changed for security. Please log out and change it now.', 'Security Notice', 'OK', 'Warning')`""

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "ForcePasswordChange" -Description "Prompt for password change" -Settings $settings -Force

Write-Host "Setup complete!" -ForegroundColor Green
Write-Host "Please sign out and change your password when prompted" -ForegroundColor Yellow

Stop-Transcript
