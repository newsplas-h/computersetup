#Requires -RunAsAdministrator
param(
    [string]$PPKGUrl
)

# Phase detection
$phaseMarker = "HKLM:\SOFTWARE\PPKGSetup"
$isPhase2 = Test-Path -Path $phaseMarker

if (-not $isPhase2) {
    # Phase 1: Apply PPKG and schedule Phase 2
    # --------------------------------------------------
    if (-not $PPKGUrl) {
        $PPKGUrl = Read-Host -Prompt "Enter the URL for your .ppkg file"
    }

    $tempDir = $env:TEMP
    $ppkgFile = Join-Path $tempDir "AutoSetup.ppkg"

    try {
        # Download PPKG
        Write-Host "Downloading PPKG package..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $PPKGUrl -OutFile $ppkgFile -UseBasicParsing

        # Apply PPKG
        Write-Host "Applying provisioning package..." -ForegroundColor Cyan
        Install-ProvisioningPackage -PackagePath $ppkgFile -ForceInstall -QuietInstall -ErrorAction Stop

        # Schedule Phase 2
        Write-Host "Scheduling post-reboot tasks..." -ForegroundColor Cyan
        $scriptPath = $MyInvocation.MyCommand.Path
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`" -PPKGUrl `"$PPKGUrl`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
        Register-ScheduledTask -TaskName "PPKGPhase2" -InputObject $task -ErrorAction Stop | Out-Null

        # Create phase marker
        New-Item -Path $phaseMarker -Force | Out-Null

        # Reboot
        Write-Host "Rebooting system to complete setup..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    }
    catch {
        Write-Host "Error in Phase 1: $_" -ForegroundColor Red
        exit 1
    }
}
else {
    # Phase 2: Install software and apply registry tweaks
    # --------------------------------------------------
    try {
        # Remove scheduled task
        Unregister-ScheduledTask -TaskName "PPKGPhase2" -Confirm:$false -ErrorAction SilentlyContinue

        # Install Chocolatey
        Write-Host "Installing Chocolatey..." -ForegroundColor Cyan
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        RefreshEnv

        # Install apps
        Write-Host "Installing applications..." -ForegroundColor Cyan
        $apps = @('7zip', 'googlechrome', 'everything', 'windirstat', 'notepadplusplus', 'vlc')
        foreach ($app in $apps) {
            choco install $app -y --force | Out-Null
        }

        # Apply registry tweaks
        Write-Host "Applying system tweaks..." -ForegroundColor Cyan

        # Load default user hive
        reg load "HKU\TempDefault" "C:\Users\Default\NTUSER.DAT" | Out-Null

        # Dark Mode
        $darkModeSettings = @{
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" = @{
                "SystemUsesLightTheme" = 0
                "AppsUseLightTheme"    = 0
            }
        }

        # Explorer and Taskbar settings
        $explorerSettings = @{
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
                "TaskbarAl"                 = 0    # Taskbar left-aligned
                "ShowTaskViewButton"        = 0    # Hide Task View
                "TaskbarDa"                 = 0    # Hide Widgets
                "EnableSnapAssistFlyout"    = 0    # Disable snap layouts
            }
            "HKCU:\Control Panel\Desktop" = @{
                "WindowArrangementActive"   = 0    # Disable snap suggestions
            }
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" = @{
                "SearchboxTaskbarMode"      = 0    # Hide search bar
            }
            "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" = @{
                "(Default)"                 = ""   # Classic context menu
            }
        }

        # Apply settings to default user
        foreach ($key in $darkModeSettings.Keys) {
            $tempKey = $key.Replace("HKCU:", "HKEY_USERS\TempDefault")
            foreach ($value in $darkModeSettings[$key].GetEnumerator()) {
                reg add "$tempKey" /v $value.Name /t REG_DWORD /d $value.Value /f | Out-Null
            }
        }

        foreach ($key in $explorerSettings.Keys) {
            $tempKey = $key.Replace("HKCU:", "HKEY_USERS\TempDefault")
            foreach ($value in $explorerSettings[$key].GetEnumerator()) {
                $type = if ($value.Value -is [int]) { "REG_DWORD" } else { "REG_SZ" }
                reg add "$tempKey" /v $value.Name /t $type /d $value.Value /f | Out-Null
            }
        }

        # Unload default user hive
        reg unload "HKU\TempDefault" | Out-Null

        # Remove shortcut arrow (system-wide)
        $explorerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
        $shellIcons = Join-Path $explorerKey "Shell Icons"
        if (-not (Test-Path $shellIcons)) {
            New-Item -Path $shellIcons -Force | Out-Null
        }
        Set-ItemProperty -Path $shellIcons -Name "29" -Value "" -Type String -Force

        # Cleanup
        Remove-Item -Path $phaseMarker -Recurse -Force

        Write-Host "Setup completed successfully! Final reboot in 5 seconds..." -ForegroundColor Green
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    }
    catch {
        Write-Host "Error in Phase 2: $_" -ForegroundColor Red
        exit 1
    }
}
