# Windows 11 OOBE Automation Script
# This script is designed to be run during Windows 11 Out-of-Box Experience (OOBE)
# It requires an active internet connection for Chocolatey.
#
# HOW TO RUN: During OOBE (e.g., at the language selection screen), press Shift+F10
# to open Command Prompt. Type 'powershell' and press Enter. Then run the command
# to download and execute this script, e.g., irm https://your-link.com/script.ps1 | iex

#Requires -RunAsAdministrator

#region 1. Set Execution Policy and Initialize
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Write-Host "=== Windows 11 OOBE Automation Script ===" -ForegroundColor Green
Write-Host "Starting automated setup..." -ForegroundColor Yellow
#endregion

#region 2. Create Local Admin User and Prompt for Credentials
Write-Host "`n[STEP 1/10] Setting up local administrator user..." -ForegroundColor Cyan

# Get username
do {
    $Username = Read-Host "Please enter the desired username for the local administrator"
    if ([string]::IsNullOrWhiteSpace($Username)) {
        Write-Warning "Username cannot be empty. Please try again."
    } elseif ($Username.Length -gt 20) {
        Write-Warning "Username too long (max 20 characters). Please try again."
    } elseif ($Username -match '[<>:"/\\|?*]') {
        Write-Warning "Username contains invalid characters. Please use only letters, numbers, and basic symbols."
    }
} while ([string]::IsNullOrWhiteSpace($Username) -or $Username.Length -gt 20 -or $Username -match '[<>:"/\\|?*]')

Write-Host "Creating user account: $Username" -ForegroundColor Yellow

# Get password
while ($true) {
    $PasswordSecure = Read-Host -AsSecureString "Please enter a password for the user '$Username':"
    $ConfirmPasswordSecure = Read-Host -AsSecureString "Please confirm the password for the user '$Username':"

    try {
        $PasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
        $ConfirmPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))
    } catch {
        Write-Error "Failed to process password input. Error: $($_.Exception.Message)"
        continue
    }

    if ($PasswordPlain -eq $ConfirmPasswordPlain -and $PasswordPlain.Length -ge 1) {
        $Password = $PasswordSecure
        # Clear sensitive data from memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))
        $PasswordPlain = $null
        $ConfirmPasswordPlain = $null
        break
    } else {
        Write-Warning "Passwords do not match or are empty. Please try again."
        # Clear sensitive data from memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))
        $PasswordPlain = $null
        $ConfirmPasswordPlain = $null
    }
}

try {
    if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $Username -Password $Password -FullName "$Username Admin" -Description "Local Administrator" -PasswordNeverExpires
        Add-LocalGroupMember -Group "Administrators" -Member $Username
        Write-Host "✓ User '$Username' created and added to Administrators group successfully." -ForegroundColor Green
    } else {
        Write-Host "! User '$Username' already exists." -ForegroundColor Yellow
    }
} catch {
    Write-Error "Failed to create user or add to Administrators group: $($_.Exception.Message)"
    exit 1
}
#endregion

#region 3. Set Computer Name
Write-Host "`n[STEP 2/10] Setting the Computer Name..." -ForegroundColor Cyan
$ComputerName = Read-Host "Please enter the desired computer name (or press Enter for auto-generated name)"
if ([string]::IsNullOrWhiteSpace($ComputerName)) {
    $ComputerName = "DESKTOP-$Username-$(Get-Random -Maximum 9999)"
    Write-Host "Auto-generated computer name: $ComputerName" -ForegroundColor Yellow
}

try {
    Rename-Computer -NewName $ComputerName -Force
    Write-Host "✓ Computer name set to '$ComputerName'." -ForegroundColor Green
} catch {
    Write-Error "Failed to set computer name: $($_.Exception.Message)"
}
#endregion

#region 4. Complete OOBE Bypass Configuration
Write-Host "`n[STEP 3/10] Configuring OOBE bypass settings..." -ForegroundColor Cyan

try {
    # Create OOBE registry path if it doesn't exist
    $oobePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
    if (-not (Test-Path $oobePath)) { 
        New-Item -Path $oobePath -Force | Out-Null 
    }
    
    # Critical OOBE bypass keys
    Set-ItemProperty -Path $oobePath -Name "BypassNRO" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $oobePath -Name "OOBEComplete" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $oobePath -Name "UnattendDone" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $oobePath -Name "SetupDisplayedEula" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $oobePath -Name "SetupDisplayedPrivacyNotice" -Value 1 -Type DWord -Force
    
    # Skip Microsoft Account creation
    $accountsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE\UserOOBE"
    if (-not (Test-Path $accountsPath)) { 
        New-Item -Path $accountsPath -Force | Out-Null 
    }
    Set-ItemProperty -Path $accountsPath -Name "SkipMachineOOBE" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $accountsPath -Name "SkipUserOOBE" -Value 1 -Type DWord -Force
    
    # Disable Cortana during OOBE
    $cortanaPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE\Cortana"
    if (-not (Test-Path $cortanaPath)) { 
        New-Item -Path $cortanaPath -Force | Out-Null 
    }
    Set-ItemProperty -Path $cortanaPath -Name "DisableCortanaOOBE" -Value 1 -Type DWord -Force
    
    # Privacy settings - disable all by default
    $privacyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"
    if (-not (Test-Path $privacyPath)) { 
        New-Item -Path $privacyPath -Force | Out-Null 
    }
    Set-ItemProperty -Path $privacyPath -Name "DisablePrivacyExperience" -Value 1 -Type DWord -Force
    
    Write-Host "✓ OOBE bypass configuration completed." -ForegroundColor Green
} catch {
    Write-Error "Failed to configure OOBE bypass settings: $($_.Exception.Message)"
}
#endregion

#region 5. System-Level Registry Tweaks
Write-Host "`n[STEP 4/10] Applying system-level registry tweaks..." -ForegroundColor Cyan

try {
    # Disable UAC completely
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Force
    
    # Remove shortcut overlay on icons
    $ShellIconPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
    if (-not (Test-Path $ShellIconPath)) { 
        New-Item -Path $ShellIconPath -Force | Out-Null 
    }
    Set-ItemProperty -Path $ShellIconPath -Name "29" -Value "%windir%\System32\shell32.dll,-50" -Force
    
    # Disable Windows Defender (requires restart)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    
    # Disable automatic updates during OOBE
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (-not (Test-Path $wuPath)) { 
        New-Item -Path $wuPath -Force | Out-Null 
    }
    Set-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -Value 1 -Type DWord -Force
    
    Write-Host "✓ System-level registry tweaks applied." -ForegroundColor Green
} catch {
    Write-Error "Failed to apply system-level tweaks: $($_.Exception.Message)"
}
#endregion

#region 6. Configure Default User Profile
Write-Host "`n[STEP 5/10] Configuring default user profile..." -ForegroundColor Cyan

try {
    # Load default user hive
    $defaultUserPath = "C:\Users\Default\NTUSER.DAT"
    if (Test-Path $defaultUserPath) {
        & reg load "HKU\DefaultUser" $defaultUserPath 2>$null
        
        # Apply user settings to default profile
        Set-ItemProperty -Path "Registry::HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "Registry::HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "Registry::HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "Registry::HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "Registry::HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "Registry::HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SearchboxTaskbarMode" -Value 0 -Force -ErrorAction SilentlyContinue
        
        # Enable Windows 10 style context menu for default user
        $clsidPath = "Registry::HKU\DefaultUser\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
        if (-not (Test-Path $clsidPath)) { 
            New-Item -Path $clsidPath -Force | Out-Null 
        }
        Set-ItemProperty -Path $clsidPath -Name "(Default)" -Value "" -Force -ErrorAction SilentlyContinue
        
        # Unload default user hive
        & reg unload "HKU\DefaultUser" 2>$null
        
        Write-Host "✓ Default user profile configured." -ForegroundColor Green
    }
} catch {
    Write-Warning "Could not configure default user profile: $($_.Exception.Message)"
}
#endregion

#region 7. Install Chocolatey and Software
Write-Host "`n[STEP 6/10] Installing Chocolatey and essential software..." -ForegroundColor Cyan

if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..."
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Host "✓ Chocolatey installed successfully." -ForegroundColor Green
        
        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        Start-Sleep -Seconds 3
    } catch {
        Write-Error "Failed to install Chocolatey: $($_.Exception.Message)"
        Write-Host "Continuing without software installation..." -ForegroundColor Yellow
    }
}

function Install-ChocolateyPackage {
    param([string]$PackageId, [string]$PackageName)
    Write-Host "Installing $PackageName..."
    try {
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            $result = & choco install $PackageId -y --no-progress --limit-output 2>&1
            if ($LASTEXITCODE -eq 0) { 
                Write-Host "✓ $PackageName installed." -ForegroundColor Green 
            } else { 
                Write-Warning "Failed to install $PackageName (Exit code: $LASTEXITCODE)" 
            }
        }
    } catch { 
        Write-Warning "Error installing $PackageName`: $($_.Exception.Message)" 
    }
}

if (Get-Command choco -ErrorAction SilentlyContinue) {
    $packages = @(
        @{Id="googlechrome"; Name="Google Chrome"},
        @{Id="7zip"; Name="7-Zip"},
        @{Id="windirstat"; Name="WinDirStat"},
        @{Id="everything"; Name="Everything"},
        @{Id="notepadplusplus"; Name="Notepad++"},
        @{Id="vlc"; Name="VLC Media Player"}
    )
    
    foreach ($package in $packages) {
        Install-ChocolateyPackage -PackageId $package.Id -PackageName $package.Name
    }
}
#endregion

#region 8. Configure Power Settings
Write-Host "`n[STEP 7/10] Configuring power settings..." -ForegroundColor Cyan
try {
    # Set display timeout: Never on AC, 15 minutes on battery
    & powercfg /change monitor-timeout-ac 0
    & powercfg /change monitor-timeout-dc 15
    & powercfg /change standby-timeout-ac 0
    & powercfg /change standby-timeout-dc 30
    
    Write-Host "✓ Power settings configured." -ForegroundColor Green
} catch {
    Write-Warning "Failed to configure power settings: $($_.Exception.Message)"
}
#endregion

#region 9. Create User-Specific Startup Script
Write-Host "`n[STEP 8/10] Creating user-specific startup configuration..." -ForegroundColor Cyan

$SetupDir = "C:\TempSetup"
$FirstLogonScriptPath = Join-Path $SetupDir "FirstLogonSetup.ps1"

try {
    New-Item -Path $SetupDir -ItemType Directory -Force | Out-Null
    
    $FirstLogonScriptContent = @"
# First logon setup script - applies user-specific settings
`$ErrorActionPreference = 'SilentlyContinue'
Start-Sleep -Seconds 3

Write-Host "Applying user-specific settings..." -ForegroundColor Cyan

# Apply user interface settings
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SearchboxTaskbarMode" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableSnapAssist" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapOverlay" -Value 0 -Force

# Enable Windows 10 style context menu
`$CLSIDPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (-not (Test-Path `$CLSIDPath)) { New-Item -Path `$CLSIDPath -Force | Out-Null }
Set-ItemProperty -Path `$CLSIDPath -Name "(Default)" -Value "" -Force

# Restart Explorer to apply changes
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "User settings applied successfully!" -ForegroundColor Green

# Clean up - remove this script and its shortcuts
Start-Sleep -Seconds 2
Remove-Item -Path "`$PSCommandPath" -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path "`$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Filter "*FirstLogon*" | Remove-Item -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\TempSetup" -Recurse -Force -ErrorAction SilentlyContinue
"@

    $FirstLogonScriptContent | Out-File -FilePath $FirstLogonScriptPath -Encoding UTF8 -Force
    
    # Create scheduled task to run the script on first logon of the NS user
    $TaskName = "FirstLogonSetup"
    $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FirstLogonScriptPath`""
    $TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
    $TaskTrigger.UserId = $Username
    $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    
    Register-ScheduledTask -TaskName $TaskName -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -RunLevel Highest -Force | Out-Null
    
    Write-Host "✓ User-specific startup configuration created." -ForegroundColor Green
} catch {
    Write-Warning "Failed to create user-specific startup script: $($_.Exception.Message)"
}

# Create activation script file on user's desktop
try {
    $UserDesktopPath = "C:\Users\$Username\Desktop"
    New-Item -Path $UserDesktopPath -ItemType Directory -Force | Out-Null
    
    $ActivationScriptPath = Join-Path $UserDesktopPath "Windows_Activation.txt"
    $ActivationContent = "https://github.com/massgravel/Microsoft-Activation-Scripts"
    
    $ActivationContent | Out-File -FilePath $ActivationScriptPath -Encoding UTF8 -Force
    Write-Host "✓ Activation script link created on desktop." -ForegroundColor Green
} catch {
    Write-Warning "Failed to create activation script file: $($_.Exception.Message)"
}
#endregion

#region 10. Final OOBE Configuration and Autologon Setup
Write-Host "`n[STEP 9/10] Configuring autologon and final OOBE settings..." -ForegroundColor Cyan

try {
    # Configure autologon for the created user (one time only)
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "1" -Force
    Set-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -Value $Username -Force
    
    # Convert SecureString password to plain text for autologon (temporarily)
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    Set-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -Value $PlainPassword -Force
    Set-ItemProperty -Path $winlogonPath -Name "AutoLogonCount" -Value "1" -Force
    
    # Clear sensitive data
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    $PlainPassword = $null
    
    # Ensure Windows Setup State Machine completes
    Set-ItemProperty -Path "HKLM:\SYSTEM\Setup" -Name "SystemSetupInProgress" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\Setup" -Name "SetupPhase" -Value 0 -Type DWord -Force
    
    Write-Host "✓ Autologon configured for first boot." -ForegroundColor Green
} catch {
    Write-Error "Failed to configure autologon: $($_.Exception.Message)"
}
#endregion

#region 11. Cleanup and Reboot
Write-Host "`n[STEP 10/10] Finalizing setup and preparing for reboot..." -ForegroundColor Cyan

try {
    # Stop any running Windows setup processes
    Get-Process -Name "oobe*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process -Name "setup*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    
    # Clear any pending OOBE tasks
    Get-ScheduledTask -TaskName "*OOBE*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    
    Write-Host "✓ Setup cleanup completed." -ForegroundColor Green
} catch {
    Write-Warning "Some cleanup operations failed, but this is not critical."
}

Write-Host "`n=== SETUP COMPLETE ===" -ForegroundColor Green
Write-Host "The system will restart in 10 seconds..." -ForegroundColor Yellow
Write-Host "After restart, you should be automatically logged in as user: $Username" -ForegroundColor Cyan
Write-Host "All configured software and settings will be applied." -ForegroundColor Cyan
Write-Host "Windows activation script link will be available on the desktop." -ForegroundColor Cyan

# Final countdown and reboot
for ($i = 10; $i -gt 0; $i--) {
    Write-Host "Rebooting in $i seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}

# Force immediate restart
shutdown.exe /r /t 0 /f /c "OOBE automation complete - rebooting to desktop"
#endregion
