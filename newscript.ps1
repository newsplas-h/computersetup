#Requires -RunAsAdministrator

# This parameter allows the script to be called in two different phases.
# 'System' is run first by the scheduled task as NT AUTHORITY\SYSTEM.
# 'User' is run second via a RunOnce key, as the logged-in user.
param(
    [ValidateSet('System', 'User')]
    [string]$Phase = 'System'
)

# --- Function for System-Level Operations ---
function Start-SystemPhase {
    Write-Host "--- Starting Phase 1: SYSTEM-WIDE PREFERENCES ---" -ForegroundColor Cyan

    # 1. Remove Shortcut Arrow
    Write-Host "Removing shortcut arrows..."
    $keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
    if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
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

    # --- Phase 2: Apply settings to DEFAULT USER profile for all FUTURE users ---
    Write-Host "Applying preferences to the Default User profile..." -ForegroundColor Cyan
    try {
        reg load HKLM\DefaultUser C:\Users\Default\ntuser.dat
        $defaultUserRegPath = "HKLM:\DefaultUser"
        Set-ItemProperty -Path "$defaultUserRegPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
        $contextMenuPath = "$defaultUserRegPath\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
        if (-not (Test-Path $contextMenuPath)) { New-Item -Path $contextMenuPath -Force | Out-Null }
        Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force
        Write-Host "Default User preferences applied." -ForegroundColor Green
    }
    catch { Write-Error "Failed to apply Default User settings: $_" }
    finally {
        Write-Host "Unloading Default User hive."
        reg unload HKLM\DefaultUser
    }

    # --- Phase 3: APPLICATION INSTALLATION ---
    Write-Host "--- Starting Phase 3: APPLICATION INSTALLATION ---" -ForegroundColor Cyan
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    try {
        Invoke-RestMethod https://chocolatey.org/install.ps1 | Invoke-Expression
    } catch {
        Write-Error "FATAL: Failed to install Chocolatey. Cannot continue with application installs."
        # The script will continue to the cleanup phase from here.
    }

    $env:Path += ";$env:ProgramData\chocolatey\bin"
    $apps = @("googlechrome", "firefox", "7zip", "windirstat", "everything", "notepadplusplus", "vlc")
    
    # !! IMPROVEMENT: Added error handling for each app install !!
    foreach ($app in $apps) {
        try {
            Write-Host "Installing $app..."
            choco install $app -y --force --no-progress
        } catch {
            Write-Warning "Could not install '$app'. The script will continue with other applications. Error: $_"
        }
    }
    
    # --- Phase 4: STAGE USER-CONTEXT SCRIPT ---
    Write-Host "--- Staging User-Specific Setup ---" -ForegroundColor Cyan
    $scriptDirectory = "C:\Temp\Setup"
    if (-not (Test-Path $scriptDirectory)) { New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null }
    $localScriptPath = Join-Path -Path $scriptDirectory -ChildPath "usersetup.ps1"

    $MyInvocation.MyCommand.Definition | Out-File $localScriptPath -Encoding utf8

    $runOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $commandToRun = "powershell.exe -ExecutionPolicy Bypass -File `"$localScriptPath`" -Phase User"
    Set-ItemProperty -Path $runOnceKey -Name "ComputerUserSetup" -Value $commandToRun -Force
    Write-Host "User phase has been staged to run at the next logon." -ForegroundColor Green

    # --- Self-Cleanup (System Phase) ---
    Write-Host "Removing initial setup task..." -ForegroundColor Cyan
    Unregister-ScheduledTask -TaskName "Run Setup Script at Logon" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "System phase complete." -ForegroundColor Green
}

# --- Function for User-Specific Operations ---
function Start-UserPhase {
    # !! IMPROVEMENT: Added dedicated logging for the User Phase !!
    $userLogPath = "C:\Temp\UserSetupLog.txt"
    Start-Transcript -Path $userLogPath -Force
    
    Write-Host "--- Starting Phase: USER-SPECIFIC PREFERENCES ---" -ForegroundColor Cyan
    
    $regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion"

    # 1. Set Dark Mode for the current user
    Set-ItemProperty -Path "$regPath\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force

    # 2. Disable Snap Assist
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 0 -Force

    # 3. Taskbar Configuration
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force

    # 4. Classic Context Menu for the current user
    $contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    if (-not (Test-Path $contextMenuPath)) { New-Item -Path $contextMenuPath -Force | Out-Null }
    Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force
    
    Write-Host "User preferences applied successfully." -ForegroundColor Green

    # --- Final UI Restart ---
    Write-Host "Restarting Explorer to apply all changes..."
    Remove-Item "$env:LocalAppData\IconCache.db" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name explorer -Force

    # --- Cleanup & Completion Notice ---
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $noticePath = Join-Path -Path $desktopPath -ChildPath "Setup Complete.txt"
    @"
Setup complete!

Change the user password, and pin your browser of choice and Explorer to the taskbar.
This setup script has now been removed.
"@ | Out-File -FilePath $noticePath -Encoding ASCII
    Start-Process notepad.exe $noticePath

    # --- Self-Cleanup (User Phase) ---
    Remove-Item -Path "C:\Temp\Setup" -Recurse -Force -ErrorAction SilentlyContinue
    Stop-Transcript
}

# --- SCRIPT ENTRY POINT ---
try {
    if ($Phase -eq 'System') {
        Start-SystemPhase
    }
    elseif ($Phase -eq 'User') {
        Start-UserPhase
    }
}
catch {
    Write-Error "An unhandled error occurred in phase '$Phase': $_"
    "$(Get-Date): An unhandled error occurred in phase '$Phase': `n$_" | Out-File -FilePath "C:\Temp\SetupError.log" -Append
    if (Get-Transcript) { Stop-Transcript }
}
