#Requires -RunAsAdministrator

# --- PHASE 1: SYSTEM CONTEXT ---
# 1. Install Chocolatey with non-interactive mode
Write-Host "Installing Chocolatey for all users..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-RestMethod https://chocolatey.org/install.ps1 | Invoke-Expression
$env:Path += ";$env:ProgramData\chocolatey\bin"

# Enable non-interactive mode for Chocolatey
$env:ChocolateyNonInteractive = 'true'

# 2. Install Applications via Chocolatey (including Firefox)
Write-Host "Installing applications..." -ForegroundColor Cyan
$apps = @(
    "googlechrome",
    "firefox",          # Added Firefox
    "7zip",
    "windirstat",
    "everything",
    "notepadplusplus",
    "vlc"
)

foreach ($app in $apps) {
    Write-Host "Installing $app..."
    choco install $app -y --force --no-progress --ignore-checksums
}

# 3. Remove Shortcut Arrow (Transparent Method)
Write-Host "Removing shortcut arrows..." -ForegroundColor Cyan
$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
if (-not (Test-Path $keyPath)) {
    New-Item -Path $keyPath -Force | Out-Null
}
Set-ItemProperty -Path $keyPath -Name "29" -Value "%SystemRoot%\System32\shell32.dll,-50" -Type String -Force

# 4. Configure Power Settings
Write-Host "Configuring power timeouts..." -ForegroundColor Cyan
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
# Remove Chat icon
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Force
# Remove Widgets icon
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force

# 4. Classic Context Menu
$contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (-not (Test-Path $contextMenuPath)) {
    New-Item -Path $contextMenuPath -Force | Out-Null
}
Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force

# 5. Taskbar Pinning Configuration
Write-Host "Configuring taskbar pins..." -ForegroundColor Cyan

# Function to modify taskbar pins
function Set-TaskbarPins {
    param(
        [string]$Action,
        [string]$AppName,
        [string]$AppPath
    )
    
    $keyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
    if (-not (Test-Path $keyPath)) {
        New-Item -Path $keyPath -Force | Out-Null
    }
    
    # Get current pins
    $pins = (Get-ItemProperty -Path $keyPath -Name "Favorites" -ErrorAction SilentlyContinue).Favorites
    $newPins = @()
    
    if ($pins) {
        # Parse existing pins
        $currentPins = [System.Text.Encoding]::Unicode.GetString($pins) -split '\0' | Where-Object { $_ }
        
        # Process based on action
        foreach ($pin in $currentPins) {
            if ($Action -eq "Unpin" -and $pin -match $AppName) {
                Write-Host "Unpinning $AppName"
                continue
            }
            $newPins += $pin
        }
    }
    
    # Add new pin if pinning
    if ($Action -eq "Pin" -and $AppPath) {
        Write-Host "Pinning $AppName to front"
        $newPins = @($AppPath) + $newPins
    }
    
    # Convert back to binary format
    $newData = $newPins -join "`0" + "`0`0"
    $binData = [System.Text.Encoding]::Unicode.GetBytes($newData)
    
    # Save to registry
    Set-ItemProperty -Path $keyPath -Name "Favorites" -Value $binData -Type Binary -Force
}

# Unpin Microsoft Edge and Store
Set-TaskbarPins -Action "Unpin" -AppName "Microsoft Edge"
Set-TaskbarPins -Action "Unpin" -AppName "Microsoft Store"

# Pin Chrome to front
$chromePath = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
if (Test-Path $chromePath) {
    Set-TaskbarPins -Action "Pin" -AppName "Google Chrome" -AppPath $chromePath
} else {
    Write-Host "Chrome not found at $chromePath" -ForegroundColor Yellow
}

# 6. Restart Explorer to apply changes and rebuild icon cache
Write-Host "Restarting Explorer to apply changes..." -ForegroundColor Cyan
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue

# Short delay to ensure Explorer fully shuts down
Start-Sleep -Seconds 2

# Rebuild icon cache (required for shortcut arrow change)
Write-Host "Rebuilding icon cache..." -ForegroundColor Cyan
Remove-Item "$env:LocalAppData\IconCache.db" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:LocalAppData\Microsoft\Windows\Explorer\iconcache*" -Force -ErrorAction SilentlyContinue

# Start Explorer normally
Start-Process explorer.exe

# --- CLEANUP DEFAULT USER PROFILE ---
Write-Host "Cleaning up default user profile..." -ForegroundColor Cyan
$defaultUserPath = "C:\Users\defaultuser0"
if (Test-Path $defaultUserPath) {
    try {
        Write-Host "Removing DefaultUser0 profile..."
        Remove-Item -Path $defaultUserPath -Recurse -Force -ErrorAction Stop
        Write-Host "DefaultUser0 profile removed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to remove DefaultUser0 profile: $_" -ForegroundColor Red
        Write-Host "This is usually safe to ignore if Windows is still using it" -ForegroundColor Yellow
    }
}
else {
    Write-Host "DefaultUser0 profile not found - skipping removal" -ForegroundColor Green
}

# --- COMPLETION NOTICE ---
Write-Host "Creating completion notice..." -ForegroundColor Cyan

# Create desktop notice
$desktopPath = [Environment]::GetFolderPath("Desktop")
$noticePath = Join-Path -Path $desktopPath -ChildPath "Setup Complete.txt"
@"
Setup complete!

Change the user password, and pin your browser of choice and Explorer to the taskbar.
"@ | Out-File -FilePath $noticePath -Encoding ASCII

# Open the notice
Start-Process notepad.exe $noticePath

Write-Host "Script completed successfully!" -ForegroundColor Green
