# This script is designed to be run during Windows 11 Out-of-Box Experience (OOBE)
# It requires an active internet connection for Chocolatey.
#
# HOW TO RUN: During OOBE (e.g., at the language selection screen), press Shift+F10
# to open Command Prompt. Type 'powershell' and press Enter. Then run the command
# to download and execute this script, e.g., irm https://your-link.com/script.ps1 | iex

#region 0. Setup Logging
$LogFile = "C:\Windows\Temp\OOBESetup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogFile -Append
Write-Host "Starting script execution. Log file: $LogFile"
#endregion

#region 1. Set Execution Policy for OOBE
Write-Host "Setting Execution Policy to Bypass for the current process."
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
#endregion

#region 2. Create Local Admin User 'NS' and Prompt for Password
Write-Host "Setting up local administrator user 'NS'."
$Username = "NS"

while ($true) {
    $PasswordSecure = Read-Host -AsSecureString "Please enter a password for the user '$Username':"
    $ConfirmPasswordSecure = Read-Host -AsSecureString "Please confirm the password for the user '$Username':"

    try {
        $PasswordPlain =::PtrToStringAuto(::SecureStringToBSTR($PasswordSecure))
        $ConfirmPasswordPlain =::PtrToStringAuto(::SecureStringToBSTR($ConfirmPasswordSecure))
    } catch {
        Write-Error "Failed to process password input. Error: $($_.Exception.Message)"
        exit 1
    }

    if ($PasswordPlain -eq $ConfirmPasswordPlain) {
        $Password = $PasswordSecure
       ::ZeroFreeBSTR(::SecureStringToBSTR($PasswordSecure))
       ::ZeroFreeBSTR(::SecureStringToBSTR($ConfirmPasswordSecure))
        break
    } else {
        Write-Warning "Passwords do not match. Please try again."
       ::ZeroFreeBSTR(::SecureStringToBSTR($PasswordSecure))
       ::ZeroFreeBSTR(::SecureStringToBSTR($ConfirmPasswordSecure))
    }
}

try {
    if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $Username -Password $Password -FullName "NS Admin" -Description "Local Administrator" -PasswordNeverExpires
        Add-LocalGroupMember -Group "Administrators" -Member $Username
        Write-Host "User '$Username' created and added to Administrators group successfully."
    } else {
        Write-Host "User '$Username' already exists."
        # Ensure the user is in Administrators group even if pre-existing
        Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction SilentlyContinue
        Write-Host "User '$Username' ensured to be in Administrators group."
    }
} catch {
    Write-Error "Failed to create user or add to Administrators group: $($_.Exception.Message)"
}
#endregion

#region 3. Set Computer Name
Write-Host "Setting the Computer Name..."
$ComputerName = Read-Host "Please enter the desired computer name (e.g., DESKTOP-NS01):"
if ([string]::IsNullOrWhiteSpace($ComputerName)) {
    Write-Warning "Computer name cannot be empty. Skipping computer rename."
} else {
    try {
        $currentComputerName = (Get-ComputerInfo).CsName
        if ($currentComputerName -ne $ComputerName) {
            Write-Host "Current computer name is '$currentComputerName'. Renaming to '$ComputerName'."
            Rename-Computer -NewName $ComputerName -Force
            Write-Host "Computer name set to '$ComputerName'. Requires reboot."
        } else {
            Write-Host "Computer name is already '$ComputerName'. No rename needed."
        }
    } catch {
        Write-Error "Failed to set computer name: $($_.Exception.Message)"
    }
}
#endregion

#region 4. Install Software using Chocolatey
Write-Host "Starting software installations using Chocolatey..."
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey is not installed. Installing Chocolatey..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force;::SecurityProtocol =::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Host "Chocolatey installed successfully."
        Start-Sleep -Seconds 5
    } catch {
        Write-Error "Failed to install Chocolatey: $($_.Exception.Message)"
    }
} else {
    Write-Host "Chocolatey is already installed."
}

function Install-ChocolateyPackage {
    param([string]$PackageId, [string]$PackageName)
    Write-Host "Attempting to install $PackageName (ID: $PackageId)..."
    try {
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            $installed = (choco list --local-only --limit-output | Select-String -Pattern "^$PackageId" -ErrorAction SilentlyContinue)
            if ($installed) {
                Write-Warning "$PackageName is already installed."
            } else {
                choco install "$PackageId" -y --no-progress
                if ($LASTEXITCODE -eq 0) { Write-Host "$PackageName installed successfully." }
                else { Write-Error "Failed to install $PackageName. Choco exit code: $LASTEXITCODE" }
            }
        } else { Write-Warning "Choco not found. Cannot install $PackageName." }
    } catch { Write-Error "An error occurred installing packages: $($_.Exception.Message)" }
}

if (Get-Command choco -ErrorAction SilentlyContinue) {
    Install-ChocolateyPackage -PackageName "Google Chrome" -PackageId "googlechrome"
    Install-ChocolateyPackage -PackageName "7-Zip" -PackageId "7zip"
    Install-ChocolateyPackage -PackageName "WinDirStat" -PackageId "windirstat"
    Install-ChocolateyPackage -PackageName "Everything" -PackageId "everything"
    Install-ChocolateyPackage -PackageName "Notepad++" -PackageId "notepadplusplus"
    Install-ChocolateyPackage -PackageName "VLC Media Player" -PackageId "vlc"
}
#endregion

#region 5. Create First-Logon Script for User-Specific Settings
Write-Host "Creating first-logon script for user '$Username'..."
$SetupDir = "C:\TempSetup"
$FirstLogonScriptPath = Join-Path $SetupDir "FirstLogonSetup.ps1"
$StartupFolderPath = "C:\Users\$Username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

# Create directories if they don't exist
New-Item -Path $SetupDir -ItemType Directory -Force -ErrorAction SilentlyContinue
New-Item -Path $StartupFolderPath -ItemType Directory -Force -ErrorAction SilentlyContinue

# Define the content for the first-logon script. This contains all HKCU changes.
$FirstLogonScriptContent = @"
# This script runs on the new user's first login to apply personal settings.
Start-Sleep -Seconds 5 # Give the desktop a moment to load

# Set Dark Mode
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force -ErrorAction SilentlyContinue

# Configure Snap Window settings
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableSnapAssist" -Value 1 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapOverlay" -Value 0 -Force -ErrorAction SilentlyContinue

# Move Taskbar to Left, Disable Task View, Widgets, and Hide Search Bar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SearchboxTaskbarMode" -Value 0 -Force -ErrorAction SilentlyContinue

# Enable Windows 10 Style Context Menu
`$CLSIDPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (-not (Test-Path `$CLSIDPath)) { New-Item -Path `$CLSIDPath -Force | Out-Null }
Set-ItemProperty -Path `$CLSIDPath -Name "(Default)" -Value "" -Force -ErrorAction SilentlyContinue

# Self-destruct this script and its startup shortcut after running
Remove-Item -Path "`$MyInvocation.MyCommand.Path" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ApplySettings.lnk" -Force -ErrorAction SilentlyContinue
"@

# Write the script content to the file
$FirstLogonScriptContent | Out-File -FilePath $FirstLogonScriptPath -Encoding utf8 -Force

# Create a shortcut in the user's startup folder to run the script silently
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut((Join-Path $StartupFolderPath "ApplySettings.lnk"))
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FirstLogonScriptPath`""
$Shortcut.Save()

Write-Host "First logon script created successfully."
#endregion

#region 6. User Account Control (UAC) Configuration
Write-Host "Configuring User Account Control (UAC) settings..."
# IMPORTANT SECURITY NOTE:
# The original script attempted to disable UAC completely by setting EnableLUA = 0.
# This is a severe security risk and is strongly discouraged for any system, especially one connected to the internet.
# UAC is a critical security feature that prevents unauthorized changes and privilege escalation.
# [1]
# Instead of disabling UAC, consider these alternatives to reduce prompts while maintaining security:
# - Set ConsentPromptBehaviorAdmin to 5 (Prompt for consent on the secure desktop) or 2 (Prompt for credentials on the secure desktop).
# - Set PromptOnSecureDesktop to 0 (to disable the secure desktop for prompts).
# These settings are typically found under HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System.
# Ensure EnableLUA remains 1 to keep UAC enabled.
#
# No changes are made to UAC in this script to avoid introducing a security vulnerability.
# If you wish to modify UAC behavior, please do so with careful consideration of security implications.
# Example (to reduce prompts, but still keep UAC enabled):
# try {
#     Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -Force -ErrorAction Stop
#     Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0 -Force -ErrorAction Stop
#     Write-Host "UAC prompt behavior adjusted to reduce prompts while keeping UAC enabled."
# } catch {
#     Write-Error "Failed to adjust UAC prompt behavior: $($_.Exception.Message)"
# }
Write-Host "UAC settings are not modified by this script to maintain system security."
#endregion

#region 7. Remove Shortcut Overlay on Icons
Write-Host "Removing shortcut overlay on icons..."
try {
    $ShellIconPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
    if (-not (Test-Path $ShellIconPath)) { New-Item -Path $ShellIconPath -Force | Out-Null }
    Set-ItemProperty -Path $ShellIconPath -Name "29" -Value "%windir%\System32\shell32.dll,-50" -Force -ErrorAction Stop
    Write-Host "Shortcut overlay removal setting applied. Explorer restart needed."
} catch {
    Write-Error "Failed to remove shortcut overlay: $($_.Exception.Message)"
}
#endregion

#region 8. Configure Display Power Settings
Write-Host "Configuring Display Power Settings..."
try {
    $activeScheme = (powercfg /getactivescheme) | Select-String -Pattern "Power Scheme GUID: ([\da-fA-F-]+)" | ForEach-Object { $_.Matches.Groups.[2]Value }
    if (-not [string]::IsNullOrWhiteSpace($activeScheme)) {
        & powercfg /setacvalueindex $activeScheme SUB_MONITOR VIDEOIDLE 0
        & powercfg /setdcvalueindex $activeScheme SUB_MONITOR VIDEOIDLE 900
        & powercfg /setactive $activeScheme
        Write-Host "Display power settings applied."
    } else {
        Write-Warning "Could not determine active power scheme."
    }
} catch {
    Write-Error "Failed to configure display power settings: $($_.Exception.Message)"
}
#endregion

#region 9. Bypass Remaining OOBE Screens (Registry Flags)
Write-Host "Applying registry keys to bypass remaining OOBE screens..."
$oobePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
try {
    if (-not (Test-Path $oobePath)) { New-Item -Path $oobePath -Force | Out-Null }

    # CRITICAL: This key tells setup to allow skipping the network connection screen. [3, 1]
    Set-ItemProperty -Path $oobePath -Name "BypassNRO" -Value 1 -Type DWord -Force
    
    # These keys signal to Windows that OOBE is complete. [4]
    Set-ItemProperty -Path $oobePath -Name "OOBEComplete" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $oobePath -Name "UnattendDone" -Value 1 -Type DWord -Force
    
    Write-Host "OOBE bypass keys set successfully."
} catch {
    Write-Error "Failed to set OOBE bypass registry keys: $($_.Exception.Message)"
}
#endregion

#region 10. Bypass Hardware Requirements (LabConfig)
Write-Host "Applying registry keys to bypass Windows 11 hardware requirements (if applicable)..."
# These keys are typically set *before* OOBE begins, often via manual regedit during Shift+F10. [5]
# They allow installation on hardware that does not officially meet Windows 11 minimum requirements.
$labConfigPath = "HKLM:\SYSTEM\Setup\LabConfig"
try {
    if (-not (Test-Path $labConfigPath)) { New-Item -Path $labConfigPath -Force | Out-Null }

    Set-ItemProperty -Path $labConfigPath -Name "BypassTPMCheck" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $labConfigPath -Name "BypassSecureBootCheck" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $labConfigPath -Name "BypassCPUCheck" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $labConfigPath -Name "BypassRAMCheck" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $labConfigPath -Name "BypassStorageCheck" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $labConfigPath -Name "BypassDiskCheck" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    
    Write-Host "Hardware requirement bypass keys applied (if needed)."
} catch {
    Write-Error "Failed to set hardware bypass registry keys: $($_.Exception.Message)"
}
#endregion

#region 11. Cleanup
Write-Host "Performing cleanup..."
try {
    # Remove temporary setup directory
    if (Test-Path $SetupDir) {
        Remove-Item -Path $SetupDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Removed temporary setup directory: $SetupDir"
    }
    # Remove the log file if desired after successful completion
    # Remove-Item -Path $LogFile -Force -ErrorAction SilentlyContinue
} catch {
    Write-Error "Failed to clean up temporary directory: $($_.Exception.Message)"
}
#endregion

#region 12. Auto Reboot
Write-Host "Script execution complete. System will now restart to apply all changes."
Start-Sleep -Seconds 5
shutdown.exe /r /t 5 /f /c "System configuration complete. Rebooting to apply changes."
#endregion

#region 13. Stop Logging
Stop-Transcript
Write-Host "Script execution finished. Log saved to $LogFile"
#endregion
