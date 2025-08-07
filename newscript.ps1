#Requires -RunAsAdministrator

# --- PHASE 1: SYSTEM-WIDE PREFERENCES ---
# These settings modify HKEY_LOCAL_MACHINE and apply to the whole system.
Write-Host "Applying system-wide preferences..." -ForegroundColor Cyan

# 1. Remove Shortcut Arrow (Transparent Method)
Write-Host "Removing shortcut arrows..."
$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
if (-not (Test-Path $keyPath)) {
    New-Item -Path $keyPath -Force | Out-Null
}
Set-ItemProperty -Path $keyPath -Name "29" -Value "%SystemRoot%\System32\shell32.dll,-50" -Type String -Force

# 2. Configure Power Settings
Write-Host "Configuring power timeouts..."
$activePlan = powercfg -getactivescheme
if ($activePlan -match '([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})') {
    $guid = $matches[1]
    powercfg /setacvalueindex $guid SUB_VIDEO VIDEOIDLE 0
    powercfg /setacvalueindex $guid SUB_SLEEP STANDBYIDLE 0
    powercfg /setdcvalueindex $guid SUB_VIDEO VIDEOIDLE 900
    powercfg /setdcvalueindex $guid SUB_SLEEP STANDBYIDLE 900
    powercfg /setactive $guid
    Write-Host "Power settings updated." -ForegroundColor Green
} else {
    Write-Host "! Failed to detect active power plan" -ForegroundColor Red
}

 "Failed to apply Default User settings: $_"
}
finally {
    # ALWAYS unload the hive, even if errors occurred.
    Write-Host "Unloading Default User hive."
    reg unload HKLM\DefaultUser
}

# --- PHASE 3: CURRENT USER PREFERENCES (if not SYSTEM) ---
# Apply settings to currently logged-in user if running in user context
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "Current user context: $currentUser" -ForegroundColor Yellow

if ($currentUser -notlike "*SYSTEM*" -and $currentUser -notlike "*SERVICE*") {
    Write-Host "Applying settings to current user: $currentUser" -ForegroundColor Cyan
    
    # Apply user-specific settings
    try {
        # Ensure HKCU paths exist
        $hkcuPaths = @(
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
            "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
        )
        
        foreach ($path in $hkcuPaths) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
        }

        # Dark Mode
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force

        # Snap Assist
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 0 -Force

        # Taskbar Configuration
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force

        # Classic Context Menu
        Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Value "" -Force

        Write-Host "Current user preferences applied successfully." -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to apply some current user settings: $_"
    }
} else {
    Write-Host "Running in SYSTEM context - user settings will be applied via Default User profile for new logins." -ForegroundColor Yellow
}

# --- PHASE 4: APPLICATION INSTALLATION ---
# 1. Install Chocolatey
Write-Host "Installing Chocolatey for all users..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
try {
    Invoke-RestMethod https://chocolatey.org/install.ps1 | Invoke-Expression
    $env:Path += ";$env:ProgramData\chocolatey\bin"
    $env:ChocolateyNonInteractive = 'true'
    Write-Host "Chocolatey installed successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to install Chocolatey: $_"
}

# 2. Install Applications via Chocolatey
Write-Host "Installing applications..." -ForegroundColor Cyan
$apps = @("googlechrome", "firefox", "7zip", "windirstat", "everything", "notepadplusplus", "vlc")
foreach ($app in $apps) {
    Write-Host "Installing $app..."
    try {
        choco install $app -y --force --no-progress --ignore-checksums
        Write-Host "$app installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to install $app`: $_"
    }
}

# --- PHASE 5: FINAL UI RESTART (only if not SYSTEM) ---
if ($currentUser -notlike "*SYSTEM*") {
    Write-Host "Restarting Explorer to apply all changes..."
    Remove-Item "$env:LocalAppData\IconCache.db" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process explorer.exe
}

# --- CLEANUP & COMPLETION ---
# Cleanup Default User Profile if it exists
$defaultUserPath = "C:\Users\defaultuser0"
if (Test-Path $defaultUserPath) {
    Write-Host "Removing DefaultUser0 profile..." -ForegroundColor Cyan
    try {
        Remove-Item -Path $defaultUserPath -Recurse -Force -ErrorAction Stop
        Write-Host "DefaultUser0 profile removed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to remove DefaultUser0 profile: $_" -ForegroundColor Red
    }
}

# Create desktop notice (only if not running as SYSTEM)
if ($currentUser -notlike "*SYSTEM*") {
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $noticePath = Join-Path -Path $desktopPath -ChildPath "Setup Complete.txt"
    @"
Setup complete!

Change the user password, and pin your browser of choice and Explorer to the taskbar.
"@ | Out-File -FilePath $noticePath -Encoding ASCII
    Start-Process notepad.exe $noticePath
}

# --- SELF-CLEANUP ---
Write-Host "Removing setup task..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName "Run Setup Script at Logon" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Setup task removed." -ForegroundColor Green

Write-Host "Script completed successfully!" -ForegroundColor Green
