# This script is designed to be run during Windows 11 Out-of-Box Experience (OOBE)
# It requires an active internet connection.
#
# IMPORTANT: Review and understand the script before running it.
# Security Note: Prompting for a password in a script pulled from a public source
# has security implications. Use with caution and for personal use only.
#
# Winget Note: Winget is typically pre-installed on modern Windows 11 versions.
# If it's not available for some reason, the installations will fail.

#region 1. Set Execution Policy for OOBE (if necessary)
# This might be needed if running from a restricted environment during OOBE.
# It's good practice to set it back or let the system default later.
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
#endregion

#region 2. Create Local Admin User 'NS' and Prompt for Password
#region 2. Create Local Admin User 'NS' and Prompt for Password
Write-Host "Setting up local administrator user 'NS'."
$Username = "NS"

while ($true) {
    $PasswordSecure = Read-Host -AsSecureString "Please enter a password for the user '$Username':"
    $ConfirmPasswordSecure = Read-Host -AsSecureString "Please confirm the password for the user '$Username':"

    # Convert SecureString to plain text for comparison only
    # Note: This temporarily exposes the password in memory. For OOBE, where user
    # is physically present and interacting, this is generally acceptable for verification.
    $PasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
    $ConfirmPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))

    if ($PasswordPlain -eq $ConfirmPasswordPlain) {
        # If passwords match, use the SecureString for New-LocalUser
        $Password = $PasswordSecure # Assign the SecureString back to $Password for the New-LocalUser cmdlet
        # Clear plain text versions from memory immediately after comparison
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))
        break
    } else {
        Write-Warning "Passwords do not match. Please try again."
        # Clear plain text versions from memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))
    }
}

try {
    # Check if user already exists
    if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
        # Ensure $Password here is the SecureString version
        New-LocalUser -Name $Username -Password $Password -FullName "NS Admin" -Description "Local Administrator"
        Add-LocalGroupMember -Group "Administrators" -Member $Username
        Write-Host "User '$Username' created and added to Administrators group successfully."
    } else {
        Write-Host "User '$Username' already exists."
        # Optionally, you could update the password here if the user already exists
        # Get-LocalUser -Name $Username | Set-LocalUser -Password $Password
    }
} catch {
    Write-Error "Failed to create user or add to Administrators group: $($_.Exception.Message)"
}
#endregion

#region 3. Install Software using Winget
Write-Host "Starting software installations using Winget..."

# Function to install a package using Winget
function Install-WingetPackage {
    param(
        [string]$PackageId,
        [string]$PackageName # For display purposes
    )

    Write-Host "Attempting to install $PackageName (ID: $PackageId) using Winget..."
    try {
        # Check if winget is available
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Error "Winget is not found. Please ensure it's installed and in the PATH."
            return
        }

        # Attempt to install the package
        # /h means silent, /e means exact match, --accept-package-agreements and --accept-source-agreements
        # are crucial for non-interactive installs.
        $wingetOutput = & winget install --id "$PackageId" -h -e --accept-package-agreements --accept-source-agreements 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "$PackageName installed successfully."
        } elseif ($LASTEXITCODE -eq 1700) { # Winget exit code for already installed
            Write-Warning "$PackageName (ID: $PackageId) is already installed."
        } else {
            Write-Error "Failed to install $PackageName (ID: $PackageId). Winget output: $wingetOutput. Exit Code: $LASTEXITCODE"
        }
    } catch {
        Write-Error "An error occurred while trying to install a package."
    }
}

# List of applications to install with their Winget IDs
# You can find Package IDs by running 'winget search <AppName>'
Install-WingetPackage -PackageName "Google Chrome" -PackageId "Google.Chrome"
Install-WingetPackage -PackageName "7-Zip" -PackageId "7zip.7zip"
Install-WingetPackage -PackageName "WinDirStat" -PackageId "WinDirStat.WinDirStat"
Install-WingetPackage -PackageName "Everything" -PackageId "Voidtools.Everything"
Install-WingetPackage -PackageName "Notepad++" -PackageId "Notepad++.Notepad++"
Install-WingetPackage -PackageName "VLC Media Player" -PackageId "VideoLAN.VLC"

Write-Host "Software installations complete."
#endregion

#region 4. Set Dark Mode
Write-Host "Setting Dark Mode..."
try {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force -ErrorAction Stop
    Write-Host "Dark Mode enabled."
} catch {
    Write-Error "Failed to set Dark Mode: $($_.Exception.Message)"
}
#endregion

#region 5. Disable UAC Popups (Set to 'Never Notify')
Write-Host "Disabling UAC popups (setting to Never Notify)..."
try {
    # Setting EnableLUA to 0 effectively disables UAC. This is a significant security reduction.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Force -ErrorAction Stop
    # The following two keys are less critical if EnableLUA is 0, but included for completeness of "Never Notify" state.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Force -ErrorAction Stop
    Write-Host "UAC popups disabled."
} catch {
    Write-Error "Failed to disable UAC popups: $($_.Exception.Message)"
}
#endregion

#region 6. Remove Shortcut Overlay on Icons
Write-Host "Removing shortcut overlay on icons..."
try {
    # Registry path for shell icons
    $ShellIconPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
    # Create the path if it doesn't exist
    if (-not (Test-Path $ShellIconPath)) {
        New-Item -Path $ShellIconPath -Force | Out-Null
    }
    # Set the value for icon 29 (shortcut overlay) to a blank icon within shell32.dll
    Set-ItemProperty -Path $ShellIconPath -Name "29" -Value "`%windir`%\System32\shell32.dll,-50" -Force -ErrorAction Stop
    Write-Host "Shortcut overlay removal setting applied. A restart/Explorer restart might be needed."
} catch {
    Write-Error "Failed to remove shortcut overlay: $($_.Exception.Message)"
}
#endregion

#region 7. Snap Window Settings
Write-Host "Configuring Snap Window settings..."
try {
    # Don't suggest what can be snapped (DisableSnapAssist: 1 = Disabled)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableSnapAssist" -Value 1 -Force -ErrorAction Stop
    # Don't show snap layouts when window is dragged to the top of a screen (EnableSnapOverlay: 0 = Disabled)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapOverlay" -Value 0 -Force -ErrorAction Stop
    Write-Host "Snap Window settings configured."
} catch {
    Write-Error "Failed to configure Snap Window settings: $($_.Exception.Message)"
}
#endregion

#region 8. Move Taskbar to Left, Disable Task View, Widgets, and Hide Search Bar
Write-Host "Configuring Taskbar settings..."
try {
    # Move Taskbar to Left (TaskbarAl: 0 = Left, 1 = Center)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force -ErrorAction Stop

    # Disable Task View Button (ShowTaskViewButton: 0 = Hidden)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force -ErrorAction Stop

    # Disable Widgets Button (TaskbarDa: 0 = Hidden)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force -ErrorAction Stop

    # Hide Search Bar (SearchboxTaskbarMode: 0 = Hidden, 1 = Icon, 2 = Icon and Label, 3 = Search Bar)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SearchboxTaskbarMode" -Value 0 -Force -ErrorAction Stop

    Write-Host "Taskbar settings configured. A restart/Explorer restart might be needed for full effect."
} catch {
    Write-Error "Failed to configure Taskbar settings: $($_.Exception.Message)"
}
#endregion

#region 9. Enable Windows 10 Style Context Menu
Write-Host "Enabling Windows 10 style context menu..."
try {
    # This registry modification enables the legacy context menu by overriding the default behavior.
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

Write-Host "Script execution complete. The system will now restart to apply all changes."

#region 10. Auto Reboot
# Give the user a few seconds to see the completion message
Start-Sleep -Seconds 5

# --- Choose one of the following reboot options ---

# Option A: Force immediate reboot (no prompt)
# Restart-Computer -Force

# Option B: Reboot with a countdown and force (recommended for OOBE unattended setup)
# This will show a shutdown warning for 30 seconds before rebooting.
shutdown.exe /r /t 1 /f /c "System configuration complete. Rebooting to apply changes."

# Option C: Prompt for reboot (less ideal for OOBE automation unless you want intervention)
# $rebootChoice = Read-Host "Do you want to reboot now to apply all changes? (Y/N)"
# if ($rebootChoice -eq 'Y') {
#     Restart-Computer -Force
# } else {
#     Write-Host "Please remember to reboot the system manually for all changes to take effect."
# }
#endregion
