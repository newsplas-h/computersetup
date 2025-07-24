# This script is designed to be run during Windows 11 Out-of-Box Experience (OOBE)
# It requires an active internet connection for Chocolatey.
#
# HOW TO RUN: During OOBE (e.g., at the language selection screen), press Shift+F10
# to open Command Prompt. Type 'powershell' and press Enter. Then run the command
# to download and execute this script, e.g., irm https://your-link.com/script.ps1 | iex

#region 1. Set Execution Policy for OOBE
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
        Write-Error "Failed to process password input. Error: $($_.Exception.Message)"
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
        New-LocalUser -Name $Username -Password $Password -FullName "NS Admin" -Description "Local Administrator" -PasswordNeverExpires
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
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey is not installed. Installing Chocolatey..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
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

#region 6. Disable UAC Popups (Set to 'Never Notify')
Write-Host "Disabling UAC popups (setting to Never Notify)..."
try {
    # This setting, EnableLUA = 0, completely disables the UAC security boundary.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Force -ErrorAction Stop
    Write-Host "UAC popups disabled. A reboot is required for this to take effect."
} catch {
    Write-Error "Failed to disable UAC popups: $($_.Exception.Message)"
}
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
    $activeScheme = (powercfg /getactivescheme) | Select-String -Pattern "Power Scheme GUID: ([\da-fA-F-]+)" | ForEach-Object { $_.Matches[0].Groups[1].Value }
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

#region 9. Bypass Remaining OOBE Screens
Write-Host "Applying registry keys to bypass remaining OOBE screens..."
$oobePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
try {
    if (-not (Test-Path $oobePath)) { New-Item -Path $oobePath -Force | Out-Null }

    # CRITICAL: This key tells setup to allow skipping the network connection screen.
    Set-ItemProperty -Path $oobePath -Name "BypassNRO" -Value 1 -Type DWord -Force
    
    # These keys signal to Windows that OOBE is complete.
    Set-ItemProperty -Path $oobePath -Name "OOBEComplete" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $oobePath -Name "UnattendDone" -Value 1 -Type DWord -Force
    
    Write-Host "OOBE bypass keys set successfully."
} catch {
    Write-Error "Failed to set OOBE bypass registry keys: $($_.Exception.Message)"
}
#endregion

#region 10. Auto Reboot
Write-Host "Script execution complete. System will now restart to apply all changes."
Start-Sleep -Seconds 5
shutdown.exe /r /t 5 /f /c "System configuration complete. Rebooting to apply changes."
#endregion
