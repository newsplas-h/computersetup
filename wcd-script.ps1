#Requires -RunAsAdministrator
Start-Transcript -Path "$env:windir\Temp\ProvisioningSetup.log" -Append

# --- PHASE 1: SYSTEM CONTEXT ---

# Create a directory for our post-setup scripts
$SetupPath = "C:\TempSetup"
New-Item -Path $SetupPath -ItemType Directory -Force | Out-Null

# 1. Install Chocolatey
Write-Host "Installing Chocolatey for all users..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
# Add choco to the path for this session
$env:Path += ";$env:ProgramData\chocolatey\bin"

# 2. Install Applications via Chocolatey (for all users)
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
    # Use --params to ensure installation for all users where applicable
    choco install $app -y --force --no-progress --params="'/AllUsers'"
}

# 3. System-Wide Tweaks (HKLM)
Write-Host "Applying system-wide tweaks..." -ForegroundColor Cyan
# Remove Shortcut Overlay (This is an HKLM key, so it's fine here)
$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
if (-not (Test-Path $keyPath)) {
    New-Item -Path $keyPath -Force | Out-Null
}
# Set-ItemProperty -Path $keyPath -Name "29" -Value "%SystemRoot%\system32\imageres.dll,-1015" -Type String
# Note: A blank icon is often preferred to avoid a white square. Use an empty string for a transparent icon.
Set-ItemProperty -Path $keyPath -Name "29" -Value "%SystemRoot%\System32\shell32.dll,-50" -Type ExpandString -Force

# --- PREPARE FOR PHASE 2: USER CONTEXT ---

Write-Host "Creating First Logon script..." -ForegroundColor Cyan

# Create the user-context script that will run on first login
$FirstLogonScript = @"
#Requires -RunAsAdministrator
Start-Transcript -Path "`$env:TEMP\PostLoginSetup.log" -Append

# 1. Set Dark Mode
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force

# 2. Snap Window Settings
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WindowArrangementActive" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 0 -Force

# 3. Taskbar Configuration
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force

# 4. Windows 10 Style Context Menu
`$contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
if (-not (Test-Path `$contextMenuPath)) {
    New-Item -Path `$contextMenuPath -Force | Out-Null
    New-Item -Path "`$contextMenuPath\InprocServer32" -Force | Out-Null
}
Set-ItemProperty -Path "`$contextMenuPath\InprocServer32" -Name "(Default)" -Value "" -Type String -Force

# 5. Force Password Change on Next Logon
`$currentUser = `$env:USERNAME
net user `$currentUser /logonpasswordchg:yes

# 6. Restart Explorer to apply UI changes
Stop-Process -Name explorer -Force
# Explorer will restart automatically.

Stop-Transcript
"@

# Save the script to the temp setup folder
$FirstLogonScript | Out-File -FilePath "$SetupPath\FirstLogon.ps1" -Encoding utf8

# Set up the RunOnce registry key to execute our script at logon
$runOncePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
$command = "powershell.exe -ExecutionPolicy Bypass -File `"$SetupPath\FirstLogon.ps1`""
Set-ItemProperty -Path $runOncePath -Name "CustomUserSetup" -Value $command -Type String -Force

Write-Host "Provisioning complete. User-specific settings will be applied at first logon." -ForegroundColor Green
Stop-Transcript
