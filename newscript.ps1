# This parameter allows the script to be called in two different phases.
param(
    [ValidateSet('System', 'User', 'Apps')]
    [string]$Phase = 'System'
)

# --- Helper: Require admin only when needed ---
function Assert-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This phase must be run as Administrator."
    }
}

# --- Function for System-Level Operations ---
function Start-SystemPhase {
    Assert-Admin

    # IMMEDIATE ACTION: Delete the scheduled task that launched this script.
    Write-Host "--- Deleting self-triggering scheduled task immediately ---" -ForegroundColor Cyan
    Unregister-ScheduledTask -TaskName "Run Setup Script at Logon" -Confirm:$false -ErrorAction SilentlyContinue
    
    Write-Host "--- Starting Phase 1: SYSTEM-WIDE PREFERENCES ---" -ForegroundColor Cyan

    $tempUsername = "NS"
    $tempPassword = "1234"
    $eventSource = "ComputerSetup"
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
            New-EventLog -LogName Application -Source $eventSource
        }
    } catch {
        Write-Warning "Could not create event log source '$eventSource': $_"
    }
    
    Write-Host "Setting system time zone to Eastern Time..."
    try {
        Set-TimeZone -Id "Eastern Standard Time"
        
        # !! NEW: Restart the time service to force the change to apply immediately. !!
        Write-Host "Restarting Windows Time service to apply time zone change..."
        Stop-Service -Name w32time -Force
        Start-Service -Name w32time
        
        # Force the clock to synchronize with the internet time server.
        Write-Host "Forcing time synchronization..."
        w32tm.exe /resync /force
    }
    catch {
        Write-Warning "Could not set or sync the time zone. Error: $_"
    }
    
    Write-Host "Removing shortcut arrows by downloading a blank icon from GitHub..."
    try {
        $iconUrl = "https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/blank.ico"
        $iconPath = Join-Path -Path $env:ProgramData -ChildPath "blank.ico"
        
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($iconUrl, $iconPath)

        $keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
        if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
        Set-ItemProperty -Path $keyPath -Name "29" -Value "$iconPath,0" -Type String -Force
    } catch {
        Write-Warning "Could not download or set blank icon for shortcut arrows. Error: $_"
    }

    $activePlan = powercfg -getactivescheme
    if ($activePlan -match '([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})') {
        $guid = $matches[1]
        powercfg /setacvalueindex $guid SUB_VIDEO VIDEOIDLE 0; powercfg /setacvalueindex $guid SUB_SLEEP STANDBYIDLE 0
        powercfg /setdcvalueindex $guid SUB_VIDEO VIDEOIDLE 900; powercfg /setdcvalueindex $guid SUB_SLEEP STANDBYIDLE 900
        powercfg /setactive $guid
    }
    try {
        reg load HKLM\DefaultUser C:\Users\Default\ntuser.dat
        $defaultUserRegPath = "HKLM:\DefaultUser"
        Set-ItemProperty -Path "$defaultUserRegPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
        $contextMenuPath = "$defaultUserRegPath\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
        if (-not (Test-Path $contextMenuPath)) { New-Item -Path $contextMenuPath -Force | Out-Null }
        Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force
    } catch { Write-Error "Failed to apply Default User settings: $_" }
    finally {
        Write-Host "Unloading Default User hive."
        [gc]::Collect()
        reg.exe unload HKLM\DefaultUser
    }

    # --- Phase 4: STAGE USER-CONTEXT SCRIPT ---
    Write-Host "--- Staging User-Specific Setup ---" -ForegroundColor Cyan
    $scriptDirectory = "C:\Temp\Setup"
    if (-not (Test-Path $scriptDirectory)) { New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null }
    $localPsScriptPath = Join-Path -Path $scriptDirectory -ChildPath "usersetup.ps1"
    $githubUrl = "https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/newscript.ps1"
    try {
        Write-Host "Downloading fresh script for User Phase from $githubUrl"
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($githubUrl, $localPsScriptPath)
    } catch {
        Write-Error "CRITICAL: Failed to download script for User Phase. Cannot continue."
        return
    }

    $localCmdScriptPath = Join-Path -Path $scriptDirectory -ChildPath "RunUserPhase.cmd"
    $batchFileContent = @"
@echo off
echo Batch file ran at %date% %time% >> C:\Temp\BatchLog.txt
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File "$localPsScriptPath" -Phase User
"@
    $batchFileContent | Out-File -FilePath $localCmdScriptPath -Encoding ASCII
    $runOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-ItemProperty -Path $runOnceKey -Name "ComputerUserSetup" -Value $localCmdScriptPath -Force
    Write-Host "User phase has been staged to run via batch file at the next logon." -ForegroundColor Green

    # --- STAGE APP INSTALLS (RUNS AFTER USER PHASE) ---
    $appsTaskName = "Run App Installs Once"
    $appsEventQuery = "<QueryList><Query Id='0' Path='Application'><Select Path='Application'>*[System[Provider[@Name='$eventSource'] and EventID=1001]]</Select></Query></QueryList>"
    $appsCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$localPsScriptPath`" -Phase Apps"
    Unregister-ScheduledTask -TaskName $appsTaskName -Confirm:$false -ErrorAction SilentlyContinue
    schtasks.exe /Create /TN $appsTaskName /SC ONEVENT /EC Application /MO $appsEventQuery /TR $appsCommand /RU SYSTEM /RL HIGHEST /F | Out-Null
    Write-Host "App install task has been staged to run after user preferences (event-triggered)." -ForegroundColor Green

    # --- STAGE AUTO-LOGON (HIGHLY INSECURE) ---
    Write-Host "Configuring automatic logon. This stores credentials in the registry." -ForegroundColor Red
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "1"
    Set-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -Value $tempUsername
    Set-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -Value $tempPassword
    
    # --- FINAL STEP: RESTART COMPUTER ---
    Write-Host "System phase complete. The computer will now restart in 5 seconds." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    shutdown.exe /r /f /t 0
}

# --- Function for User-Specific Operations ---
function Start-UserPhase {
    if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null }
    $userLogPath = "C:\Temp\UserSetupLog.txt"
    Start-Transcript -Path $userLogPath -Force
    Write-Host "--- Starting Phase: USER-SPECIFIC PREFERENCES ---" -ForegroundColor Cyan
    $regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion"
    Set-ItemProperty -Path "$regPath\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "SnapAssist" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "EnableSnapBar" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 1 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force
    $contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    if (-not (Test-Path $contextMenuPath)) { New-Item -Path $contextMenuPath -Force | Out-Null }
    Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force
    Write-Host "User preferences applied." -ForegroundColor Green
    
    Write-Host "Removing Microsoft Edge shortcut from the desktop..."
    $userDesktop = [Environment]::GetFolderPath("Desktop")
    $publicDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
    Remove-Item -Path "$userDesktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$publicDesktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue

    Remove-Item "$env:LocalAppData\IconCache.db" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name explorer -Force
    Start-Process explorer.exe -ErrorAction SilentlyContinue

    # Trigger app installs as soon as user prefs are done (no built-in delay).
    try {
        Write-EventLog -LogName Application -Source "ComputerSetup" -EventId 1001 -EntryType Information -Message "User phase complete. Trigger app installs."
    } catch {
        Write-Warning "Could not write event log to trigger app installs: $_"
    }
    
    Write-Host "Displaying final notice in a new command prompt window."
    $title = "title IMPORTANT - PASSWORD CHANGE REQUIRED"
    $line1 = "echo."
    $line2 = "echo *******************************************************************************"
    $line3 = "echo ** SETUP IS COMPLETE                               **"
    $line4 = "echo *******************************************************************************"
    $line5 = "echo."
    $line6 = "echo For security, your temporary password must be changed now."
    $line7 = "echo."
    $line8 = "echo Please press CTRL+ALT+DELETE and select 'Change a password'."
    $line9 = "echo."
    $line10 = "pause"
    $fullCommand = "$title & $line1 & $line2 & $line3 & $line4 & $line5 & $line6 & $line7 & $line8 & $line9 & $line10"
    $arguments = "/k $fullCommand"

    try {
        $process = Start-Process cmd.exe -ArgumentList $arguments -PassThru
        Start-Sleep -Seconds 1
        $wshell = New-Object -ComObject wscript.shell
        $wshell.AppActivate($process.Id) | Out-Null
    } catch {
        Start-Process cmd.exe -ArgumentList $arguments
    }

    # Kick off app installs only after user preferences are in place.
    try {
        Start-ScheduledTask -TaskName "Run App Installs Once"
    } catch {
        Write-Warning "Could not start app install task: $_"
    }

    Stop-Transcript
}

# --- Function for Application Installation (runs as SYSTEM) ---
function Start-AppsPhase {
    Assert-Admin

    $appsLogPath = "C:\Temp\SetupAppsLog.txt"
    Start-Transcript -Path $appsLogPath -Force
    Write-Host "--- Starting Phase: APPLICATION INSTALLATION ---" -ForegroundColor Cyan

    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    try { Invoke-RestMethod https://chocolatey.org/install.ps1 | Invoke-Expression } catch { Write-Error "FATAL: Failed to install Chocolatey." }
    $env:Path += ";$env:ProgramData\chocolatey\bin"
    $apps = @("googlechrome", "firefox", "7zip", "windirstat", "everything", "notepadplusplus", "vlc", "superf4", "steam", "discord")
    foreach ($app in $apps) {
        try { choco install $app -y --force --no-progress } catch { Write-Warning "Could not install '$app'." }
    }

    # --- SECURITY CLEANUP (requires admin) ---
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "0"
    Remove-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -ErrorAction SilentlyContinue

    # Cleanup: remove the task so it doesn't run again and delete staged files.
    Unregister-ScheduledTask -TaskName "Run App Installs Once" -Confirm:$false -ErrorAction SilentlyContinue
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
    elseif ($Phase -eq 'Apps') {
        Start-AppsPhase
    }
}
catch {
    $errorMsg = "An unhandled error occurred in phase '$Phase': $_"
    Write-Error $errorMsg
    "$(Get-Date): $errorMsg" | Add-Content -Path "C:\Temp\SetupError.log"
    try { Stop-Transcript } catch {}
}
