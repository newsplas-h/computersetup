#Requires -RunAsAdministrator
Start-Transcript -Path "$env:windir\Temp\ProvisioningSetup.log" -Append

Write-Host "Starting Complete Windows Setup..." -ForegroundColor Green

# --- SYSTEM-WIDE CONFIGURATION ---

Write-Host "Applying system-wide tweaks..." -ForegroundColor Cyan

# Remove Shortcut Overlay (HKLM)
Write-Host "Removing shortcut overlay arrows..."
$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
if (-not (Test-Path $keyPath)) {
    New-Item -Path $keyPath -Force | Out-Null
}
Set-ItemProperty -Path $keyPath -Name "29" -Value "" -Type String -Force

# Set Time Zone to Eastern Standard Time
Write-Host "Setting time zone to Eastern Standard Time..."
try {
    Set-TimeZone -Id "Eastern Standard Time" -PassThru
    Write-Host "Time zone set successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to set time zone: $($_.Exception.Message)" -ForegroundColor Red
}

# --- USER-SPECIFIC CONFIGURATION ---

Write-Host "Applying user-specific settings..." -ForegroundColor Cyan

# 1. Set Dark Mode
Write-Host "Setting Dark Mode..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force

# 2. Snap Window Settings
Write-Host "Configuring window snap settings..."
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WindowArrangementActive" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 0 -Force

# 3. Taskbar Configuration
Write-Host "Configuring taskbar..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force

# Remove Chat (Teams) icon from taskbar
Write-Host "Removing Chat icon from taskbar..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Force

# Remove Microsoft Store from taskbar
Write-Host "Removing Microsoft Store from taskbar..."
$storePinPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
if (Test-Path $storePinPath) {
    Set-ItemProperty -Path $storePinPath -Name "NumPinnedApps" -Value 0 -Force
}

# Unpin Microsoft Edge from taskbar (this requires more complex handling)
Write-Host "Removing Microsoft Edge from taskbar..."
$edgeAppId = "MSEdge"
$taskbarPinsPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
try {
    # This method works for some systems
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}')
    $item = $folder.Items() | Where-Object { $_.Name -like "*Edge*" }
    if ($item) {
        $item.InvokeVerb("Unpin from taskbar")
    }
} catch {
    Write-Host "Alternative method for Edge removal..." -ForegroundColor Yellow
}

# 4. Windows 10 Style Context Menu
Write-Host "Setting Windows 10 style context menu..."
$contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
if (-not (Test-Path $contextMenuPath)) {
    New-Item -Path $contextMenuPath -Force | Out-Null
    New-Item -Path "$contextMenuPath\InprocServer32" -Force | Out-Null
}
Set-ItemProperty -Path "$contextMenuPath\InprocServer32" -Name "(Default)" -Value "" -Type String -Force

# --- CHOCOLATEY AND APPLICATION INSTALLATION ---

Write-Host "Installing Chocolatey..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
try {
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    # Add choco to the path for this session
    $env:Path += ";$env:ProgramData\chocolatey\bin"
    Write-Host "Chocolatey installed successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to install Chocolatey: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Installing applications via Chocolatey..." -ForegroundColor Cyan
$apps = @(
    "googlechrome",
    "7zip",
    "windirstat",
    "everything",
    "notepadplusplus",
    "vlc"
)

foreach ($app in $apps) {
    Write-Host "Installing $app..." -ForegroundColor Yellow
    try {
        choco install $app -y --force --no-progress --params="'/AllUsers'"
        Write-Host "$app installed successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to install $app: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Pin Chrome to taskbar and position it first
Write-Host "Pinning Chrome to taskbar..." -ForegroundColor Cyan
try {
    # Wait a moment for Chrome installation to complete
    Start-Sleep -Seconds 3
    
    # Find Chrome executable
    $chromePath = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
    if (-not (Test-Path $chromePath)) {
        $chromePath = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    }
    
    if (Test-Path $chromePath) {
        # Pin Chrome to taskbar using COM object
        $shell = New-Object -ComObject Shell.Application
        $folder = $shell.NameSpace((Split-Path $chromePath))
        $item = $folder.ParseName((Split-Path $chromePath -Leaf))
        $item.InvokeVerb("Pin to taskbar")
        Write-Host "Chrome pinned to taskbar successfully." -ForegroundColor Green
        
        # Additional method to ensure Chrome is positioned first
        $taskbarLayout = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
        if (Test-Path $taskbarLayout) {
            # Reset taskbar layout to put Chrome first
            Remove-ItemProperty -Path $taskbarLayout -Name "Favorites" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $taskbarLayout -Name "FavoritesResolve" -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "Chrome executable not found for pinning." -ForegroundColor Red
    }
} catch {
    Write-Host "Failed to pin Chrome to taskbar: $($_.Exception.Message)" -ForegroundColor Red
}

# --- RESTART EXPLORER ---

Write-Host "Restarting Explorer to apply UI changes..." -ForegroundColor Cyan
Stop-Process -Name explorer -Force
Start-Sleep -Seconds 2
# Explorer will restart automatically

# --- PASSWORD CHANGE PROMPT ---

Write-Host "`n" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Yellow
Write-Host "IMPORTANT: PASSWORD CHANGE" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Yellow
Write-Host "Please change your password now for security." -ForegroundColor Yellow
Write-Host "Press any key to open the password change dialog..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Open the password change dialog
Start-Process "netplwiz.exe"

Write-Host "`nAfter changing your password, press any key to continue..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# --- REBOOT PROMPT ---

Write-Host "`n" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host "SETUP COMPLETE!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host "All configurations have been applied." -ForegroundColor Green
Write-Host "A reboot is recommended to ensure all changes take effect." -ForegroundColor Green
Write-Host "`n"

do {
    $rebootChoice = Read-Host "Would you like to reboot now? (Y/N)"
    $rebootChoice = $rebootChoice.ToUpper()
} while ($rebootChoice -ne "Y" -and $rebootChoice -ne "N")

if ($rebootChoice -eq "Y") {
    Write-Host "Rebooting in 10 seconds..." -ForegroundColor Yellow
    Write-Host "Press Ctrl+C to cancel the reboot." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Stop-Transcript
    Restart-Computer -Force
} else {
    Write-Host "Reboot skipped. Please reboot manually when convenient." -ForegroundColor Yellow
    Write-Host "Setup log saved to: $env:windir\Temp\ProvisioningSetup.log" -ForegroundColor Cyan
}

Stop-Transcript
