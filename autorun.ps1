# This script is designed to be run during Windows 11 Out-of-Box Experience (OOBE)
# It requires an active internet connection.
#
# IMPORTANT: Review and understand the script before running it.
# Security Note: Prompting for a password in a script pulled from a public source
# has security implications. Use with caution and for personal use only.
#
# OOBE Bypass Note: While this script attempts to bypass remaining OOBE screens,
# fully unattended OOBE is best achieved using an Autounattend.xml file applied
# to the installation media or during sysprep. This script acts as a post-OOBE
# intervention and may not suppress all prompts in all scenarios.

#region 1. Set Execution Policy for OOBE (if necessary)
# This is crucial for running the Chocolatey installation script.
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
#endregion

#region 2. Create Local Admin User 'NS' and Prompt for Password
Write-Host "Setting up local administrator user 'NS'."
$Username = "NS"

while ($true) {
    $PasswordSecure = Read-Host -AsSecureString "Please enter a password for the user '$Username':"
    $ConfirmPasswordSecure = Read-Host -AsSecureString "Please confirm the password for the user '$Username':"

    try {
        $PasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
        $ConfirmPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))
    } catch {
        Write-Error "Failed to process password input. Ensure PowerShell is running correctly. Error: $($_.Exception.Message)"
        exit 1
    }

    if ($PasswordPlain -eq $ConfirmPasswordPlain) {
        $Password = $PasswordSecure
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))
        break
    } else {
        Write-Warning "Passwords do not match. Please try again."
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))
    }
}

try {
    if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $Username -Password $Password -FullName "NS Admin" -Description "Local Administrator"
        Add-LocalGroupMember -Group "Administrators" -Member $Username
        Write-Host "User '$Username' created and added to Administrators group successfully."
    } else {
        Write-Host "User '$Username' already exists."
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
        Rename-Computer -NewName $ComputerName -Force
        Write-Host "Computer name set to '$ComputerName'. Requires reboot."
    } catch {
        Write-Error "Failed to set computer name: $($_.Exception.Message)"
    }
}
#endregion

#region 4. Install Software using Chocolatey
Write-Host "Starting software installations using Chocolatey..."

# Check and install Chocolatey if not present
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey is not installed. Installing Chocolatey..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Host "Chocolatey installed successfully."
        # Give it a moment to initialize in the current session
        Start-Sleep -Seconds 5
    } catch {
        Write-Error "Failed to install Chocolatey: $($_.Exception.Message)"
        Write-Warning "Skipping all Chocolatey-based software installations."
    }
} else {
    Write-Host "Chocolatey is already installed."
}

# Function to install a package using Chocolatey
function Install-ChocolateyPackage {
    param(
        [string]$PackageId,
        [string]$PackageName # For display purposes
    )

    Write-Host "Attempting to install $PackageName (ID: $PackageId) using Chocolatey..."
    try {
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            # Check if already installed
            $installed = (choco list --local-only --limit-output | Select-String -Pattern "^$PackageId" -ErrorAction SilentlyContinue)
            if ($installed) {
                Write-Warning "$PackageName (ID: $PackageId) is already installed."
            } else {
                & choco install "$PackageId" -y --no-progress 2>&1 | Write-Verbose
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "$PackageName installed successfully."
                } else {
                    Write-Error "Failed to install $PackageName (ID: $PackageId). Chocolatey exit code: $LASTEXITCODE"
                }
            }
        } else {
            Write-Warning "Chocolatey command not found. Cannot install $PackageName."
        }
    } catch {
        Write-Error "An error occurred while trying to install packages."
    }
}

# List of applications to install with their Chocolatey IDs
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Install-ChocolateyPackage -PackageName "Google Chrome" -PackageId "googlechrome"
    Install-ChocolateyPackage -PackageName "7-Zip" -PackageId "7zip"
    Install-ChocolateyPackage -PackageName "WinDirStat" -PackageId "windirstat"
    Install-ChocolateyPackage -PackageName "Everything" -PackageId "everything"
    Install-ChocolateyPackage -PackageName "Notepad++" -PackageId "notepadplusplus"
    Install-ChocolateyPackage -PackageName "VLC Media Player" -PackageId "vlc"
}

Write-Host "Software installations complete."
#endregion

#region 5. Set Dark Mode
Write-Host "Setting Dark Mode..."
try {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force -ErrorAction Stop
    Write-Host "Dark Mode enabled."
} catch {
    Write-Error "Failed to set Dark Mode: $($_.Exception.Message)"
}
#endregion

#region 6. Disable UAC Popups (Set to 'Never Notify')
Write-Host "Disabling UAC popups (setting to Never Notify)..."
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Force -ErrorAction Stop
    Write-Host "UAC popups disabled."
} catch {
    Write-Error "Failed to disable UAC popups: $($_.Exception.Message)"
}
#endregion

#region 7. Remove Shortcut Overlay on Icons
Write-Host "Removing shortcut overlay on icons..."
try {
    $ShellIconPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
    if (-not (Test-Path $ShellIconPath)) {
        New-Item -Path $ShellIconPath -Force | Out-Null
    }
    Set-ItemProperty -Path $ShellIconPath -Name "29" -Value "`%windir`%\System32\shell32.dll,-50" -Force -ErrorAction Stop
    Write-Host "Shortcut overlay removal setting applied. A restart/Explorer restart might be needed."
} catch {
    Write-Error "Failed to remove shortcut overlay: $($_.Exception.Message)"
}
#endregion

#region 8. Snap Window Settings
Write-Host "Configuring Snap Window settings..."
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableSnapAssist" -Value 1 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapOverlay" -Value 0 -Force -ErrorAction Stop
    Write-Host "Snap Window settings configured."
} catch {
    Write-Error "Failed to configure Snap Window settings: $($_.Exception.Message)"
}
#endregion

#region 9. Move Taskbar to Left, Disable Task View, Widgets, and Hide Search Bar
Write-Host "Configuring Taskbar settings..."
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force -ErrorAction Stop # Widgets button
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SearchboxTaskbarMode" -Value 0 -Force -ErrorAction Stop
    Write-Host "Taskbar settings configured. A restart/Explorer restart might be needed for full effect."
} catch {
    Write-Error "Failed to configure Taskbar settings: $($_.Exception.Message)"
}
#endregion

#region 10. Enable Windows 10 Style Context Menu
Write-Host "Enabling Windows 10 style context menu..."
try {
    $CLSIDPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    if (-not (Test-Path $CLSIDPath)) {
        New-Item -Path $CLSIDPath -Force | Out-Null
    }
    Set-ItemProperty -Path $CLSIDPath -Name "(Default)" -Value "" -Force -ErrorAction Stop
    Write-Host "Windows 10 style context menu enabled. A restart/Explorer restart might be needed."
} catch {
    Write-Error "Failed to enable Windows 10 style context menu: $($_.Exception.Message)"
}
#endregion

#region 11. Configure Display Power Settings
Write-Host "Configuring Display Power Settings..."
try {
    # Get the GUID of the active power scheme
    $activeScheme = (powercfg /getactivescheme) | Select-String -Pattern "Power Scheme GUID: ([\da-fA-F-]+)" | ForEach-Object { $_.Matches[0].Groups[1].Value }

    if (-not [string]::IsNullOrWhiteSpace($activeScheme)) {
        Write-Host "Active Power Scheme GUID: $activeScheme"
        # Turn off display: Never on AC power (0 minutes)
        # powercfg /setacvalueindex <SCHEME_GUID> <SUB_GROUP_GUID> <SETTING_GUID> <VALUE>
        # Monitor timeout subgroup GUID: 7516B95F-F776-4464-8C53-06167F40CC99
        # Display timeout setting GUID: 3C07ABF2-67EB-4BFC-8BB6-BFEA7D406798
        & powercfg /setacvalueindex $activeScheme SUB_MONITOR 3C07ABF2-67EB-4BFC-8BB6-BFEA7D406798 0
        Write-Host "Display will never turn off on AC power."

        # Turn off display: After 15 minutes on Battery power (15 minutes = 900 seconds)
        & powercfg /setdcvalueindex $activeScheme SUB_MONITOR 3C07ABF2-67EB-4BFC-8BB6-BFEA7D406798 900
        Write-Host "Display will turn off after 15 minutes on Battery power."

        # Apply the changes to the active power scheme
        & powercfg /setactive $activeScheme
        Write-Host "Display power settings applied."
    } else {
        Write-Warning "Could not determine active power scheme. Skipping display power settings."
    }
} catch {
    Write-Error "Failed to configure display power settings: $($_.Exception.Message)"
}
#endregion

#region 12. Bypass Remaining OOBE Screens (Attempt 2 - after name change, might be more effective)
Write-Host "Attempting to bypass remaining OOBE screens (final attempt)..."
try {
    # Set UnattendDone to signal OOBE completion (DWORD value 1)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "UnattendDone" -Value 1 -Force -ErrorAction Stop

    # Suppress OOBE UI (DWORD value 0)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE\Setup" -Name "SetupUI" -Value 0 -Force -ErrorAction Stop

    # Set OOBE to be "complete" (DWORD value 1)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "OOBEComplete" -Value 1 -Force -ErrorAction Stop

    Write-Host "OOBE bypass settings applied."
} catch {
    Write-Error "Failed to apply OOBE bypass settings: $($_.Exception.Message)"
}
#endregion

Write-Host "Script execution complete. The system will now restart to apply all changes."

#region 13. Auto Reboot
# Give the user a few seconds to see the completion message
Start-Sleep -Seconds 5

# Option B: Reboot with a countdown and force (recommended for OOBE unattended setup)
shutdown.exe /r /t 5 /f /c "System configuration complete. Rebooting to apply changes."
#endregion
