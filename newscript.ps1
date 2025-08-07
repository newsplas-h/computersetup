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

# --- PHASE 2: USER-SPECIFIC PREFERENCES ---
# IMPORTANT: These settings modify HKEY_CURRENT_USER (HKCU). They will only work
# correctly when this script is run by the logged-in user. When run by the
# SYSTEM account (like in the scheduled task), these changes will likely fail
# or apply to the wrong user profile, which was the source of the original errors.
Write-Host "Applying user-specific preferences..." -ForegroundColor Cyan

# 3. Set Dark Mode
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force

# 4. Disable Snap Assist
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 0 -Force

# 5. Taskbar Configuration
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force  # Align left
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Force # Remove Chat icon
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force # Remove Widgets icon

# 6. Classic Context Menu
$contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (-not (Test-Path $contextMenuPath)) {
    New-Item -Path $contextMenuPath -Force | Out-Null
}
Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force

# 7. Unpin Default Taskbar Icons
Write-Host "Removing default taskbar pins..."
try {
    $taskbarPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    Get-ChildItem -Path $taskbarPath -Filter "*.lnk" | ForEach-Object {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($_.FullName)
        if ($shortcut.TargetPath -like "*msedge.exe*" -or $shortcut.TargetPath -like "*ms-windows-store*") {
            Write-Host "Unpinning default app: $($_.Name)"
            Remove-Item -Path $_.FullName -Force
        }
    }
} catch {
    Write-Warning "Could not unpin taskbar items. This is expected if run as SYSTEM."
}

# --- PHASE 3: APPLICATION INSTALLATION ---
# 1. Install Chocolatey
Write-Host "Installing Chocolatey for all users..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-RestMethod https://chocolatey.org/install.ps1 | Invoke-Expression
$env:Path += ";$env:ProgramData\chocolatey\bin"
$env:ChocolateyNonInteractive = 'true'

# 2. Install Applications via Chocolatey
Write-Host "Installing applications..." -ForegroundColor Cyan
$apps = @("googlechrome", "firefox", "7zip", "windirstat", "everything", "notepadplusplus", "vlc")
foreach ($app in $apps) {
    Write-Host "Installing $app..."
    choco install $app -y --force --no-progress --ignore-checksums
}

# --- PHASE 4: FINAL UI RESTART ---
# Restart Explorer to apply all changes
Write-Host "Restarting Explorer to apply all changes..."
Remove-Item "$env:LocalAppData\IconCache.db" -Force -ErrorAction SilentlyContinue
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process explorer.exe

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

# Create desktop notice
$desktopPath = [Environment]::GetFolderPath("Desktop")
$noticePath = Join-Path -Path $desktopPath -ChildPath "Setup Complete.txt"
@"
Setup complete!

Change the user password, and pin your browser of choice and Explorer to the taskbar.
"@ | Out-File -FilePath $noticePath -Encoding ASCII
Start-Process notepad.exe $noticePath

# --- SELF-CLEANUP ---
Write-Host "Removing setup task..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName "Run Setup Script at Logon" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Setup task removed." -ForegroundColor Green
Write-Host "Script completed successfully!" -ForegroundColor Green
