# This parameter allows the script to be called in two different phases.
param(
    [ValidateSet('System', 'User', 'Apps', 'Rename', 'Final')]
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

function Ensure-SetupDirs {
    if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null }
    if (-not (Test-Path "C:\Temp\Setup")) { New-Item -ItemType Directory -Path "C:\Temp\Setup" -Force | Out-Null }
}

function Prompt-DesiredUserName {
    param(
        [string]$DefaultName
    )
    while ($true) {
        $inputName = Read-Host "Enter desired account name (press Enter to keep '$DefaultName')"
        $name = $inputName.Trim()
        if ([string]::IsNullOrWhiteSpace($name)) { return $DefaultName }
        if ($name.Length -gt 20) {
            Write-Host "Name too long. Please use 20 characters or fewer." -ForegroundColor Yellow
            continue
        }
        if ($name -match '[\\\/\[\]:;\|=,\+\*\?<>\"]') {
            Write-Host "Name contains invalid characters. Try again." -ForegroundColor Yellow
            continue
        }
        if ($name.EndsWith('.') -or $name.EndsWith(' ')) {
            Write-Host "Name cannot end with a period or space. Try again." -ForegroundColor Yellow
            continue
        }
        return $name
    }
}

function Write-DesiredUserInfo {
    param(
        [string]$OldUser,
        [string]$NewUser
    )
    $path = "C:\Temp\Setup\DesiredUser.json"
    $info = [pscustomobject]@{
        OldUser = $OldUser
        NewUser = $NewUser
    }
    $info | ConvertTo-Json | Out-File -FilePath $path -Encoding ASCII -Force
}

function Read-DesiredUserInfo {
    $path = "C:\Temp\Setup\DesiredUser.json"
    if (Test-Path $path) {
        try { return (Get-Content -Raw $path | ConvertFrom-Json) } catch { return $null }
    }
    return $null
}

function Show-PasswordChangeNotice {
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
}

# --- Function for System-Level Operations ---
function Start-SystemPhase {
    Assert-Admin
    Ensure-SetupDirs

    # IMMEDIATE ACTION: Delete the scheduled task that launched this script.
    Write-Host "--- Deleting self-triggering scheduled task immediately ---" -ForegroundColor Cyan
    Unregister-ScheduledTask -TaskName "Run Setup Script at Logon" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "Cleanup Old Account" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "Rename Account and Reboot" -Confirm:$false -ErrorAction SilentlyContinue

    Write-Host "--- Starting Phase 1: SYSTEM-WIDE PREFERENCES ---" -ForegroundColor Cyan

    $tempUsername = "NS"
    $tempPassword = "1234"

    Write-Host "Setting system time zone to Eastern Time..."
    try {
        Set-TimeZone -Id "Eastern Standard Time"

        Write-Host "Restarting Windows Time service to apply time zone change..."
        Stop-Service -Name w32time -Force
        Start-Service -Name w32time

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
        Set-ItemProperty -Path "$defaultUserRegPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force

        $defaultAdvancedPath = "$defaultUserRegPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        if (-not (Test-Path $defaultAdvancedPath)) { New-Item -Path $defaultAdvancedPath -Force | Out-Null }
        Set-ItemProperty -Path $defaultAdvancedPath -Name "SnapAssist" -Value 0 -Force
        Set-ItemProperty -Path $defaultAdvancedPath -Name "EnableSnapBar" -Value 0 -Force
        Set-ItemProperty -Path $defaultAdvancedPath -Name "EnableSnapAssistFlyout" -Value 1 -Force
        Set-ItemProperty -Path $defaultAdvancedPath -Name "HideFileExt" -Value 0 -Force
        Set-ItemProperty -Path $defaultAdvancedPath -Name "Hidden" -Value 1 -Force
        Set-ItemProperty -Path $defaultAdvancedPath -Name "LaunchTo" -Value 1 -Force
        Set-ItemProperty -Path $defaultAdvancedPath -Name "TaskbarAl" -Value 0 -Force
        Set-ItemProperty -Path $defaultAdvancedPath -Name "ShowTaskViewButton" -Value 0 -Force
        Set-ItemProperty -Path $defaultAdvancedPath -Name "TaskbarMn" -Value 0 -Force
        Set-ItemProperty -Path $defaultAdvancedPath -Name "TaskbarDa" -Value 0 -Force

        $defaultSearchPath = "$defaultUserRegPath\Software\Microsoft\Windows\CurrentVersion\Search"
        if (-not (Test-Path $defaultSearchPath)) { New-Item -Path $defaultSearchPath -Force | Out-Null }
        Set-ItemProperty -Path $defaultSearchPath -Name "SearchboxTaskbarMode" -Value 0 -Force

        $defaultMousePath = "$defaultUserRegPath\Control Panel\Mouse"
        if (-not (Test-Path $defaultMousePath)) { New-Item -Path $defaultMousePath -Force | Out-Null }
        Set-ItemProperty -Path $defaultMousePath -Name "MouseSpeed" -Value "0" -Force
        Set-ItemProperty -Path $defaultMousePath -Name "MouseThreshold1" -Value "0" -Force
        Set-ItemProperty -Path $defaultMousePath -Name "MouseThreshold2" -Value "0" -Force

        $contextMenuPath = "$defaultUserRegPath\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
        if (-not (Test-Path $contextMenuPath)) { New-Item -Path $contextMenuPath -Force | Out-Null }
        Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force
    } catch { Write-Error "Failed to apply Default User settings: $_" }
    finally {
        Write-Host "Unloading Default User hive."
        [gc]::Collect()
        reg.exe unload HKLM\DefaultUser
    }

    # --- Phase 2: STAGE USER-CONTEXT SCRIPT ---
    Write-Host "--- Staging User-Specific Setup ---" -ForegroundColor Cyan
    $scriptDirectory = "C:\Temp\Setup"
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

    # --- STAGE APP INSTALLS (RUNS AT LOGON, SYSTEM) ---
    $appsTaskName = "Run App Installs Once"
    $appsAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$localPsScriptPath`" -Phase Apps"
    $appsTrigger = New-ScheduledTaskTrigger -AtLogOn
    $appsPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
    $appsSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Unregister-ScheduledTask -TaskName $appsTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $appsTaskName -Action $appsAction -Trigger $appsTrigger -Principal $appsPrincipal -Settings $appsSettings -Description "Installs applications after setup." -Force
    Disable-ScheduledTask -TaskName $appsTaskName -ErrorAction SilentlyContinue
    Write-Host "App install task has been staged to run at logon." -ForegroundColor Green

    # --- STAGE RENAME HANDLER (RUNS AT STARTUP, SYSTEM) ---
    $renameTaskName = "Rename Account and Reboot"
    $renameAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$localPsScriptPath`" -Phase Rename"
    $renameTrigger = New-ScheduledTaskTrigger -AtStartup
    $renamePrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
    $renameSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Unregister-ScheduledTask -TaskName $renameTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $renameTaskName -Action $renameAction -Trigger $renameTrigger -Principal $renamePrincipal -Settings $renameSettings -Description "Creates new admin account and reboots when requested." -Force
    Write-Host "Rename handler task has been staged (startup trigger)." -ForegroundColor Green

    # --- STAGE AUTO-LOGON (HIGHLY INSECURE) ---
    Write-Host "Configuring automatic logon. This stores credentials in the registry." -ForegroundColor Red
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "1"
    Set-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -Value $tempUsername
    Set-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -Value $tempPassword

    # --- FINAL STEP: RESTART COMPUTER ---
    Write-Host "System phase complete. The computer will now restart now." -ForegroundColor Yellow
    shutdown.exe /r /f /t 0
}

# --- Function for User-Specific Operations ---
function Start-UserPhase {
    Ensure-SetupDirs
    $userLogPath = "C:\Temp\UserSetupLog.txt"
    Start-Transcript -Path $userLogPath -Force

    Write-Host "--- Starting Phase: USER-SPECIFIC PREFERENCES ---" -ForegroundColor Cyan
    $regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion"
    Set-ItemProperty -Path "$regPath\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "SnapAssist" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "EnableSnapBar" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 1 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "Hidden" -Value 1 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Force

    $mousePath = "HKCU:\Control Panel\Mouse"
    if (-not (Test-Path $mousePath)) { New-Item -Path $mousePath -Force | Out-Null }
    Set-ItemProperty -Path $mousePath -Name "MouseSpeed" -Value "0" -Force
    Set-ItemProperty -Path $mousePath -Name "MouseThreshold1" -Value "0" -Force
    Set-ItemProperty -Path $mousePath -Name "MouseThreshold2" -Value "0" -Force
    try { rundll32.exe user32.dll,UpdatePerUserSystemParameters } catch {}

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

    $desiredName = Prompt-DesiredUserName -DefaultName $env:USERNAME
    if ($desiredName -and ($desiredName -ne $env:USERNAME)) {
        Write-DesiredUserInfo -OldUser $env:USERNAME -NewUser $desiredName
        Write-Host "Account rename requested. Rebooting now..." -ForegroundColor Yellow
        Stop-Transcript
        shutdown.exe /r /f /t 0
        return
    } else {
        Remove-Item -Path "C:\Temp\Setup\DesiredUser.json" -Force -ErrorAction SilentlyContinue
    }

    try {
        Enable-ScheduledTask -TaskName "Run App Installs Once" -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskName "Run App Installs Once"
        Write-Host "Triggered app install task." -ForegroundColor Green
    } catch {
        Write-Warning "Could not start app install task: $_"
    }

    Show-PasswordChangeNotice
    Stop-Transcript
}

# --- Function for Application Installation (runs as SYSTEM) ---
function Start-AppsPhase {
    Assert-Admin
    Ensure-SetupDirs

    $appsLogPath = "C:\Temp\SetupAppsLog.txt"
    Start-Transcript -Path $appsLogPath -Force
    Write-Host "--- Starting Phase: APPLICATION INSTALLATION ---" -ForegroundColor Cyan

    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    try { Invoke-RestMethod https://community.chocolatey.org/install.ps1 | Invoke-Expression } catch { Write-Error "FATAL: Failed to install Chocolatey." }

    $chocoPath = "$env:ProgramData\chocolatey\bin\choco.exe"
    if (Test-Path $chocoPath) { $choco = $chocoPath } else { $choco = "choco" }
    $apps = @("googlechrome", "firefox", "7zip", "windirstat", "everything", "notepadplusplus", "vlc", "superf4", "steam", "discord")
    foreach ($app in $apps) {
        try { & $choco install $app -y --force --no-progress } catch { Write-Warning "Could not install '$app'." }
    }

    # Cleanup: remove the task so it doesn't run again.
    Unregister-ScheduledTask -TaskName "Run App Installs Once" -Confirm:$false -ErrorAction SilentlyContinue

    # --- SECURITY CLEANUP (requires admin) ---
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "0"
    Remove-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -ErrorAction SilentlyContinue

    Stop-Transcript
}

# --- Function for Rename (runs as SYSTEM) ---
function Start-RenamePhase {
    Assert-Admin
    Ensure-SetupDirs

    $info = Read-DesiredUserInfo
    if (-not $info -or -not $info.NewUser) {
        return
    }

    $renameLogPath = "C:\Temp\RenameLog.txt"
    Start-Transcript -Path $renameLogPath -Force

    $newUser = $info.NewUser
    $oldUser = $info.OldUser
    $tempPassword = "1234"
    Write-Host "Creating or updating admin account '$newUser'..." -ForegroundColor Yellow
    try {
        $securePass = ConvertTo-SecureString $tempPassword -AsPlainText -Force
        $existingUser = Get-LocalUser -Name $newUser -ErrorAction SilentlyContinue
        if (-not $existingUser) {
            New-LocalUser -Name $newUser -Password $securePass -FullName $newUser -Description "Provisioned by setup"
        }
        Enable-LocalUser -Name $newUser -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "Administrators" -Member $newUser -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to create or update user '$newUser': $_"
    }

    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "1"
    Set-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -Value $newUser
    Set-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -Value $tempPassword

    $localPsScriptPath = "C:\Temp\Setup\usersetup.ps1"
    $runOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $finalCmd = "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File `"$localPsScriptPath`" -Phase Final"
    Set-ItemProperty -Path $runOnceKey -Name "ComputerSetupFinal" -Value $finalCmd -Force

    Enable-ScheduledTask -TaskName "Run App Installs Once" -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "Rename Account and Reboot" -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Temp\Setup\DesiredUser.json" -Force -ErrorAction SilentlyContinue

    if ($oldUser -and ($oldUser -ne $newUser)) {
        $protected = @("Administrator", "DefaultAccount", "WDAGUtilityAccount")
        if ($protected -notcontains $oldUser) {
            Write-Host "Removing old account '$oldUser' and profile..." -ForegroundColor Yellow
            try {
                $oldProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -ieq ("C:\Users\" + $oldUser) }
                if ($oldProfile) { $oldProfile | Remove-CimInstance }
            } catch {
                Write-Warning "Failed to remove profile for '$oldUser': $_"
            }
            try {
                Remove-LocalUser -Name $oldUser -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Failed to remove user '$oldUser': $_"
            }
            try {
                $oldPath = "C:\Users\$oldUser"
                if (Test-Path $oldPath) { Remove-Item -Path $oldPath -Recurse -Force -ErrorAction SilentlyContinue }
            } catch {
                Write-Warning "Failed to remove folder for '$oldUser': $_"
            }
        }
    }

    # Always attempt to remove the NS profile folder when a new username is chosen.
    if ($newUser -ne "NS") {
        try {
            $nsPath = "C:\Users\NS"
            if (Test-Path $nsPath) { Remove-Item -Path $nsPath -Recurse -Force -ErrorAction SilentlyContinue }
        } catch {
            Write-Warning "Failed to remove C:\\Users\\NS: $_"
        }

        try {
            Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "NS.*" } |
                ForEach-Object {
                    try { Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
                }
        } catch {
            Write-Warning "Failed to remove C:\\Users\\NS.*: $_"
        }
    }

    Write-Host "Rebooting into '$newUser' now..." -ForegroundColor Yellow
    Stop-Transcript
    shutdown.exe /r /f /t 0
}

# --- Function for Final notice (runs as user) ---
function Start-FinalPhase {
    Ensure-SetupDirs
    $finalLogPath = "C:\Temp\FinalLog.txt"
    Start-Transcript -Path $finalLogPath -Force
    Show-PasswordChangeNotice
    Unregister-ScheduledTask -TaskName "Rename Account and Reboot" -Confirm:$false -ErrorAction SilentlyContinue
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
    elseif ($Phase -eq 'Rename') {
        Start-RenamePhase
    }
    elseif ($Phase -eq 'Final') {
        Start-FinalPhase
    }
}
catch {
    $errorMsg = "An unhandled error occurred in phase '$Phase': $_"
    Write-Error $errorMsg
    "$(Get-Date): $errorMsg" | Add-Content -Path "C:\Temp\SetupError.log"
    try { Stop-Transcript } catch {}
}
