#Requires -RunAsAdministrator

# This parameter allows the script to be called in two different phases.
param(
    [ValidateSet('System', 'User')]
    [string]$Phase = 'System'
)

# --- Function for System-Level Operations ---
function Start-SystemPhase {
    # IMMEDIATE ACTION: Delete the scheduled task that launched this script.
    Write-Host "--- Deleting self-triggering scheduled task immediately ---" -ForegroundColor Cyan
    Unregister-ScheduledTask -TaskName "Run Setup Script at Logon" -Confirm:$false -ErrorAction SilentlyContinue
    
    Write-Host "--- Starting Phase 1: SYSTEM-WIDE PREFERENCES ---" -ForegroundColor Cyan
    $keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
    if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
    Set-ItemProperty -Path $keyPath -Name "29" -Value "%SystemRoot%\System32\shell32.dll,-50" -Type String -Force
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

    Write-Host "--- Starting Phase 3: APPLICATION INSTALLATION ---" -ForegroundColor Cyan
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    try { Invoke-RestMethod https://chocolatey.org/install.ps1 | Invoke-Expression } catch { Write-Error "FATAL: Failed to install Chocolatey." }
    $env:Path += ";$env:ProgramData\chocolatey\bin"
    $apps = @("googlechrome", "firefox", "7zip", "windirstat", "everything", "notepadplusplus", "vlc")
    foreach ($app in $apps) {
        try { choco install $app -y --force --no-progress } catch { Write-Warning "Could not install '$app'." }
    }
    
    # --- Phase 4: STAGE USER-CONTEXT SCRIPT ---
    Write-Host "--- Staging User-Specific Setup ---" -ForegroundColor Cyan
    $scriptDirectory = "C:\Temp\Setup"
    if (-not (Test-Path $scriptDirectory)) { New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null }
    $localPsScriptPath = Join-Path -Path $scriptDirectory -ChildPath "usersetup.ps1"

    # !! FINAL FIX: Replace failing Invoke-RestMethod with a more reliable .NET WebClient downloader. !!
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

    # --- STAGE AUTO-LOGON (HIGHLY INSECURE) ---
    Write-Host "Configuring automatic logon. This stores credentials in the registry." -ForegroundColor Red
    $tempUsername = "NS"
    $tempPassword = "1234"
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
    # --- IMMEDIATE SECURITY CLEANUP ---
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "0"
    Remove-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -ErrorAction SilentlyContinue

    $userLogPath = Join-Path -Path $env:TEMP -ChildPath "UserSetupLog.txt"
    Start-Transcript -Path $userLogPath -Force
    Write-Host "--- Starting Phase: USER-SPECIFIC PREFERENCES ---" -ForegroundColor Cyan
    $regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion"
    Set-ItemProperty -Path "$regPath\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Force
    Set-ItemProperty -Path "$regPath\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force
    $contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    if (-not (Test-Path $contextMenuPath)) { New-Item -Path $contextMenuPath -Force | Out-Null }
    Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force
    Write-Host "User preferences applied." -ForegroundColor Green
    Remove-Item "$env:LocalAppData\IconCache.db" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name explorer -Force
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
