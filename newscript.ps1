#Requires -RunAsAdministrator

param(
    [ValidateSet('System', 'User')]
    [string]$Phase = 'System'
)

# --- SYSTEM-LEVEL SETUP ---
function Start-SystemPhase {
    # Remove scheduled task to avoid repeat runs
    Write-Host "--- Deleting self-triggering scheduled task immediately ---" -ForegroundColor Cyan
    Unregister-ScheduledTask -TaskName "Run Setup Script at Logon" -Confirm:$false -ErrorAction Continue

    Write-Host "--- SYSTEM-WIDE PREFERENCES ---" -ForegroundColor Cyan

    # Example: Set system-wide icon
    $keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
    if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
    Set-ItemProperty -Path $keyPath -Name "29" -Value "%SystemRoot%\System32\shell32.dll,-50" -Type String -Force

    # Set power plan settings for all users
    $activePlan = powercfg -getactivescheme
    if ($activePlan -match '([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})') {
        $guid = $matches[1]
        powercfg /setacvalueindex $guid SUB_VIDEO VIDEOIDLE 0
        powercfg /setacvalueindex $guid SUB_SLEEP STANDBYIDLE 0
        powercfg /setdcvalueindex $guid SUB_VIDEO VIDEOIDLE 900
        powercfg /setdcvalueindex $guid SUB_SLEEP STANDBYIDLE 900
        powercfg /setactive $guid
    }

    # Apply user-defaults for NEW accounts (does NOT affect existing accounts!)
    try {
        reg load HKLM\DefaultUser C:\Users\Default\ntuser.dat
        $defaultUserRegPath = "HKLM:\DefaultUser"
        $personalizePath = "$defaultUserRegPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        if (-not (Test-Path $personalizePath)) { New-Item -Path $personalizePath -Force | Out-Null }
        Set-ItemProperty -Path $personalizePath -Name "AppsUseLightTheme" -Value 0 -Force

        $contextMenuPath = "$defaultUserRegPath\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
        if (-not (Test-Path $contextMenuPath)) { New-Item -Path $contextMenuPath -Force | Out-Null }
        Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force
    } catch { Write-Error "Failed to apply Default User settings: $_" }
    finally {
        Write-Host "Unloading Default User hive."
        [gc]::Collect()
        reg.exe unload HKLM\DefaultUser | Out-Null
    }

    # --- APPLICATION INSTALLATION ---
    Write-Host "--- APPLICATION INSTALLATION ---" -ForegroundColor Cyan
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    try { Invoke-RestMethod https://chocolatey.org/install.ps1 | Invoke-Expression } catch { Write-Error "FATAL: Failed to install Chocolatey." }
    $env:Path += ";$env:ProgramData\chocolatey\bin"
    $apps = @("googlechrome", "firefox", "7zip", "windirstat", "everything", "notepadplusplus", "vlc")
    foreach ($app in $apps) {
        try { choco install $app -y --force --no-progress } catch { Write-Warning "Could not install '$app'." }
    }
    
    # --- STAGE USER-CONTEXT SCRIPT ---
    Write-Host "--- Staging User-Specific Setup ---" -ForegroundColor Cyan
    $scriptDirectory = "C:\Temp\Setup"
    if (-not (Test-Path $scriptDirectory)) { New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null }
    $localPsScriptPath = Join-Path -Path $scriptDirectory -ChildPath "usersetup.ps1"
    $MyInvocation.MyCommand.Definition | Out-File $localPsScriptPath -Encoding utf8
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

    # --- OPTIONAL: AUTO-LOGON (INSECURE: REMOVE IN PRODUCTION) ---
    Write-Host "Configuring automatic logon. This stores credentials in the registry." -ForegroundColor Red
    $tempUsername = "NS"
    $tempPassword = "1234"
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "1"
    Set-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -Value $tempUsername
    Set-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -Value $tempPassword
    
    # --- RESTART COMPUTER ---
    Write-Host "System phase complete. The computer will now restart in 5 seconds." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    shutdown.exe /r /f /t 0
}

# --- USER-LEVEL SETUP ---
function Start-UserPhase {
    # Remove auto-logon and password from Winlogon
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "0"
    Remove-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -ErrorAction SilentlyContinue

    $userLogPath = Join-Path -Path $env:TEMP -ChildPath "UserSetupLog.txt"
    Start-Transcript -Path $userLogPath -Force
    Write-Host "--- USER-SPECIFIC PREFERENCES ---" -ForegroundColor Cyan

    # Always operate on HKCU for user settings!
    $regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion"
    $personalizePath = "$regPath\Themes\Personalize"
    if (-not (Test-Path $personalizePath)) { New-Item -Path $personalizePath -Force | Out-Null }
    Set-ItemProperty -Path $personalizePath -Name "AppsUseLightTheme" -Value 0 -Force
    Set-ItemProperty -Path $personalizePath -Name "SystemUsesLightTheme" -Value 0 -Force

    $explorerAdvPath = "$regPath\Explorer\Advanced"
    if (-not (Test-Path $explorerAdvPath)) { New-Item -Path $explorerAdvPath -Force | Out-Null }
    Set-ItemProperty -Path $explorerAdvPath -Name "EnableSnapAssistFlyout" -Value 0 -Force
    Set-ItemProperty -Path $explorerAdvPath -Name "TaskbarAl" -Value 0 -Force
    Set-ItemProperty -Path $explorerAdvPath -Name "ShowTaskViewButton" -Value 0 -Force
    Set-ItemProperty -Path $explorerAdvPath -Name "TaskbarMn" -Value 0 -Force
    Set-ItemProperty -Path $explorerAdvPath -Name "TaskbarDa" -Value 0 -Force

    $searchPath = "$regPath\Search"
    if (-not (Test-Path $searchPath)) { New-Item -Path $searchPath -Force | Out-Null }
    Set-ItemProperty -Path $searchPath -Name "SearchboxTaskbarMode" -Value 0 -Force

    $contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    if (-not (Test-Path $contextMenuPath)) { New-Item -Path $contextMenuPath -Force | Out-Null }
    Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force

    Write-Host "User preferences applied." -ForegroundColor Green
    Remove-Item "$env:LocalAppData\IconCache.db" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name explorer -Force

    # Notify user and cleanup
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $noticePath = Join-Path -Path $desktopPath -ChildPath "Setup Complete.txt"
    "Setup complete!" | Out-File -FilePath $noticePath -Encoding ASCII
    Start-Process notepad.exe $noticePath
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
    $errorMsg = "An unhandled error occurred in phase '$Phase': $_"
    Write-Error $errorMsg
    "$(Get-Date): $errorMsg" | Add-Content -Path "C:\Temp\SetupError.log"
    if (Get-Transcript) { Stop-Transcript }
}
