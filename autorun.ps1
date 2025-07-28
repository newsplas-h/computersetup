#Requires -RunAsAdministrator

# Function to convert GitHub URL to raw URL
function ConvertTo-RawGitHubUrl {
    param([string]$Url)
    
    # Check if it's already a raw URL
    if ($Url -like "*raw.githubusercontent.com*") {
        return $Url
    }
    
    # Convert standard GitHub URL to raw
    $pattern = 'https?://github.com/([^/]+)/([^/]+)/blob/(.*)'
    if ($Url -match $pattern) {
        $user = $Matches[1]
        $repo = $Matches[2]
        $path = $Matches[3]
        return "https://raw.githubusercontent.com/$user/$repo/$path"
    }
    
    # Return original if conversion fails
    return $Url
}

# Phase detection
$phaseMarker = "HKLM:\SOFTWARE\PPKGSetup"
$isPhase2 = Test-Path -Path $phaseMarker

if (-not $isPhase2) {
    # Phase 1: Get PPKG URL, apply package, and schedule Phase 2
    # ------------------------------------------------------------
    $PPKGUrl = Read-Host -Prompt "Enter the GitHub URL for your .ppkg file"
    
    # Convert to raw URL if needed
    $RawUrl = ConvertTo-RawGitHubUrl -Url $PPKGUrl
    if ($RawUrl -ne $PPKGUrl) {
        Write-Host "Converted GitHub URL to raw format: $RawUrl" -ForegroundColor Cyan
    }

    # Validate URL format
    if (-not ($RawUrl -like "http*://*")) {
        Write-Host "Invalid URL format. Please provide a valid URL." -ForegroundColor Red
        exit 1
    }

    $tempDir = $env:TEMP
    $ppkgFile = Join-Path $tempDir "AutoSetup.ppkg"

    try {
        # Download PPKG
        Write-Host "Downloading PPKG package from GitHub..." -ForegroundColor Cyan
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $RawUrl -OutFile $ppkgFile -UseBasicParsing -ErrorAction Stop
        }
        catch {
            Write-Host "Download failed: $_" -ForegroundColor Red
            Write-Host "Please verify: " -NoNewline
            Write-Host "1) URL is correct, 2) File exists, 3) GitHub URL format" -ForegroundColor Yellow
            Write-Host "Example URL format: https://github.com/username/repo/blob/main/package.ppkg" -ForegroundColor Yellow
            exit 1
        }

        # Verify downloaded file
        if (-not (Test-Path -Path $ppkgFile)) {
            Write-Host "Download failed: File not found" -ForegroundColor Red
            exit 1
        }
        
        $fileSize = (Get-Item $ppkgFile).Length
        if ($fileSize -lt 1024) {
            Write-Host "Download failed: File is too small ($fileSize bytes). Check URL." -ForegroundColor Red
            Write-Host "This usually means the URL conversion failed." -ForegroundColor Yellow
            Write-Host "Try using the raw URL directly: https://raw.githubusercontent.com/..." -ForegroundColor Yellow
            exit 1
        }

        Write-Host "PPKG downloaded successfully ($([math]::Round($fileSize/1KB)) KB)" -ForegroundColor Green

        # Apply PPKG with detailed error handling
        Write-Host "Applying provisioning package..." -ForegroundColor Cyan
        try {
            $result = Install-ProvisioningPackage -PackagePath $ppkgFile -ForceInstall -QuietInstall -ErrorAction Stop
            if ($result.Status -ne 'Success') {
                throw "Installation failed with status: $($result.Status)"
            }
        }
        catch {
            Write-Host "PPKG import error: $_" -ForegroundColor Red
            Write-Host "Common causes:" -ForegroundColor Yellow
            Write-Host "1. Corrupted or invalid PPKG file"
            Write-Host "2. Incorrect PPKG format"
            Write-Host "3. GitHub URL not converted properly"
            Write-Host "4. PPKG not properly signed"
            Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
            Write-Host "- Try manual conversion: Replace 'github.com' with 'raw.githubusercontent.com' and remove '/blob'"
            Write-Host "- Example: https://raw.githubusercontent.com/username/repo/main/package.ppkg"
            Write-Host "- Test download in browser: $RawUrl"
            exit 1
        }

        # Schedule Phase 2
        Write-Host "Scheduling post-reboot tasks..." -ForegroundColor Cyan
        $scriptPath = $MyInvocation.MyCommand.Path
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
        
        try {
            Register-ScheduledTask -TaskName "PPKGPhase2" -InputObject $task -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Host "Failed to schedule task: $_" -ForegroundColor Red
            exit 1
        }

        # Create phase marker
        New-Item -Path $phaseMarker -Force | Out-Null

        # Reboot
        Write-Host "Rebooting system to complete setup..." -ForegroundColor Yellow
        Write-Host "The system will reboot in 10 seconds (press Ctrl+C to cancel)..." -ForegroundColor Yellow
        Start-Sleep -Seconds 10
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
        Write-Host "Installing Chocolatey package manager..." -ForegroundColor Cyan
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')) -ErrorAction Stop
            refreshenv
        }
        catch {
            Write-Host "Chocolatey installation failed: $_" -ForegroundColor Red
            exit 1
        }

        # Install apps
        Write-Host "Installing applications..." -ForegroundColor Cyan
        $apps = @('7zip', 'googlechrome', 'everything', 'windirstat', 'notepadplusplus', 'vlc')
        foreach ($app in $apps) {
            try {
                choco install $app -y --force -ErrorAction Stop
            }
            catch {
                Write-Host "Failed to install $app: $_" -ForegroundColor Yellow
            }
        }

        # Apply registry tweaks
        Write-Host "Applying system tweaks..." -ForegroundColor Cyan

        # Load default user hive
        try {
            reg load "HKU\TempDefault" "C:\Users\Default\NTUSER.DAT" | Out-Null
        }
        catch {
            Write-Host "Failed to load default user registry hive: $_" -ForegroundColor Yellow
        }

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
        try {
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
        }
        catch {
            Write-Host "Registry tweak failed: $_" -ForegroundColor Yellow
        }

        # Unload default user hive
        try {
            reg unload "HKU\TempDefault" | Out-Null
        }
        catch {
            Write-Host "Failed to unload default user registry hive: $_" -ForegroundColor Yellow
        }

        # Remove shortcut arrow (system-wide)
        try {
            $explorerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
            $shellIcons = Join-Path $explorerKey "Shell Icons"
            if (-not (Test-Path $shellIcons)) {
                New-Item -Path $shellIcons -Force | Out-Null
            }
            Set-ItemProperty -Path $shellIcons -Name "29" -Value "" -Type String -Force
        }
        catch {
            Write-Host "Failed to remove shortcut arrows: $_" -ForegroundColor Yellow
        }

        # Cleanup
        Remove-Item -Path $phaseMarker -Recurse -Force -ErrorAction SilentlyContinue

        Write-Host "Setup completed successfully! Final reboot in 10 seconds..." -ForegroundColor Green
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
    catch {
        Write-Host "Error in Phase 2: $_" -ForegroundColor Red
        exit 1
    }
}
