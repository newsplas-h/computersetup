# This script is designed to be run during Windows 11 Out-of-Box Experience (OOBE)
# It requires an active internet connection for Chocolatey.
#
# HOW TO RUN: During OOBE (e.g., at the language selection screen), press Shift+F10
# to open Command Prompt. Type 'powershell' and press Enter. Then run the command
# to download and execute this script, e.g., irm https://your-link.com/script.ps1 | iex

#region 0. Setup Logging
# Ensure the log directory exists before starting transcript
$LogDirectory = "C:\Windows\Temp"
if (-not (Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogDirectory "OOBESetup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogFile -Append
Write-Host "Starting script execution. Log file: $LogFile"
#endregion

#region 1. Set Execution Policy for OOBE
Write-Host "Setting Execution Policy to Bypass for the current process."
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
} catch {
    Write-Error "Failed to set execution policy: $($_.Exception.Message)"
}
#endregion

#region 2. Bypass Hardware Requirements (LabConfig) - Move to beginning
Write-Host "Applying registry keys to bypass Windows 11 hardware requirements (if applicable)..."
$labConfigPath = "HKLM:\SYSTEM\Setup\LabConfig"
try {
    if (-not (Test-Path $labConfigPath)) { New-Item -Path $labConfigPath -ItemType Directory -Force | Out-Null }

    # Ensure these are DWord values
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

#region 3. Apply OOBE Bypass Registry Keys FIRST
Write-Host "Applying OOBE bypass registry keys..."
$oobeMainPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
$oobeSetupPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE"

try {
    # Ensure both OOBE registry paths exist
    if (-not (Test-Path $oobeMainPath)) { New-Item -Path $oobeMainPath -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path $oobeSetupPath)) { New-Item -Path $oobeSetupPath -ItemType Directory -Force | Out-Null }

    # Core OOBE bypass keys
    Set-ItemProperty -Path $oobeMainPath -Name "BypassNRO" -Value 1 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path $oobeSetupPath -Name "SetupDisplayed" -Value 1 -Type DWord -Force -ErrorAction Stop
    
    Write-Host "OOBE bypass registry keys set successfully."
} catch {
    Write-Error "Failed to set OOBE bypass registry keys: $($_.Exception.Message)"
}
#endregion

#region 4. Create Local Admin User (User Input) and Prompt for Password
Write-Host "Setting up local administrator user."

# Get Username from user input
$Username = ""
while ([string]::IsNullOrWhiteSpace($Username)) {
    $Username = Read-Host "Please enter the desired local administrator username (e.g., NS, Admin, User):"
    if ([string]::IsNullOrWhiteSpace($Username)) {
        Write-Warning "Username cannot be empty. Please try again."
    }
    # Basic validation for common invalid characters in Windows usernames
    if ($Username -match '["/\[\]:;|,<>=+*?@ ]' -or $Username.Length -gt 20) {
        Write-Warning "Username contains invalid characters (e.g., space, \ / : * ? "" < > |) or is too long (max 20 chars). Please choose another."
        $Username = "" # Reset to prompt again
    }
}
Write-Host "Admin username set to: '$Username'."

# Using Add-Type for SecureString to String conversion, which is safer than direct memory manipulation
Add-Type -AssemblyName System.Security

# Variable to hold the plain text password temporarily for unattend.xml generation
$PasswordPlainForUnattend = ""

while ($true) {
    $PasswordSecure = Read-Host -AsSecureString "Please enter a password for the user '$Username':"
    $ConfirmPasswordSecure = Read-Host -AsSecureString "Please confirm the password for the user '$Username':"

    # Convert SecureString to plain string for comparison and unattend.xml.
    $PasswordPlainForUnattend = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
    $ConfirmPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))

    if ($PasswordPlainForUnattend -eq $ConfirmPasswordPlain) {
        $Password = $PasswordSecure # This is the SecureString for New-LocalUser
        # Securely clear plain text password variables immediately after comparison
        $ConfirmPasswordPlain = $null
        break
    } else {
        Write-Warning "Passwords do not match. Please try again."
        # Securely clear plain text password variables
        $PasswordPlainForUnattend = $null # Clear this if passwords don't match
        $ConfirmPasswordPlain = $null
    }
}

try {
    if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
        Write-Host "Creating user '$Username'..."
        New-LocalUser -Name $Username -Password $Password -FullName "$Username Admin" -Description "Local Administrator" -PasswordNeverExpires -ErrorAction Stop
        Write-Host "User '$Username' created."
    } else {
        Write-Host "User '$Username' already exists. Skipping user creation."
    }
    
    # Always ensure the user is in the Administrators group
    Write-Host "Adding user '$Username' to the Administrators group..."
    Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction SilentlyContinue
    Write-Host "User '$Username' successfully added to Administrators group."

} catch {
    Write-Error "Failed to manage user '$Username': $($_.Exception.Message)"
}
#endregion

#region 5. Set Computer Name Automatically
Write-Host "Setting the Computer Name automatically based on the user '$Username'..."
# Automatically generate a computer name, e.g., NS-PC, ADMIN-PC
$SanitizedUsername = ($Username -replace '[^a-zA-Z0-9]', '').ToUpper()

# Construct the computer name
$ComputerName = "$SanitizedUsername-PC"

# Ensure the computer name does not exceed the maximum length (15 characters for NetBIOS)
if ($ComputerName.Length -gt 15) {
    $ComputerName = $ComputerName.Substring(0, 15)
    Write-Warning "Generated computer name '$ComputerName' was truncated to 15 characters to meet NetBIOS limit."
}

Write-Host "Desired computer name set to: '$ComputerName'."

try {
    $currentComputerName = (Get-ComputerInfo).CsName
    if ($currentComputerName -ne $ComputerName) {
        Write-Host "Current computer name is '$currentComputerName'. Renaming to '$ComputerName'."
        Rename-Computer -NewName $ComputerName -Force -ErrorAction Stop
        Write-Host "Computer name set to '$ComputerName'. Requires reboot."
    } else {
        Write-Host "Computer name is already '$ComputerName'. No rename needed."
    }
} catch {
    Write-Error "Failed to set computer name: $($_.Exception.Message)"
}
#endregion

#region 6. Generate and Place Unattend.xml for OOBE Bypass - CORRECTED
Write-Host "Generating and placing unattend.xml for OOBE bypass..."

# Define the path for the unattend.xml file - Use C:\Windows\System32\Sysprep\
$UnattendFilePath = "C:\Windows\System32\Sysprep\unattend.xml"

# CORRECTED XML content - proper structure for OOBE bypass
$UnattendXmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Home</NetworkLocation>
                <SkipUserOOBE>true</SkipUserOOBE>
                <SkipMachineOOBE>true</SkipMachineOOBE>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
            </OOBE>
            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <DisplayName>$Username</DisplayName>
                        <Group>Administrators</Group>
                        <Name>$Username</Name>
                        <Password>
                            <PlainText>true</PlainText>
                            <Value>$PasswordPlainForUnattend</Value>
                        </Password>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
            <AutoLogon>
                <Enabled>true</Enabled>
                <LogonCount>1</LogonCount>
                <Username>$Username</Username>
                <Password>
                    <PlainText>true</PlainText>
                    <Value>$PasswordPlainForUnattend</Value>
                </Password>
            </AutoLogon>
            <TimeZone>Eastern Standard Time</TimeZone>
            <ComputerName>$ComputerName</ComputerName>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>en-US</UILanguageFallback>
            <UserLocale>en-US</UserLocale>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>$ComputerName</ComputerName>
        </component>
    </settings>
</unattend>
"@

try {
    # Ensure the Sysprep directory exists
    $SysprepDir = Split-Path $UnattendFilePath -Parent
    if (-not (Test-Path $SysprepDir)) {
        New-Item -Path $SysprepDir -ItemType Directory -Force | Out-Null
    }

    # Save the generated XML content to the file
    $UnattendXmlContent | Out-File -FilePath $UnattendFilePath -Encoding utf8 -Force -ErrorAction Stop
    Write-Host "Unattend.xml generated and placed at '$UnattendFilePath'."

    # Also place a copy in Panther for redundancy
    $PantherPath = "C:\Windows\Panther\unattend.xml"
    $PantherDir = Split-Path $PantherPath -Parent
    if (-not (Test-Path $PantherDir)) {
        New-Item -Path $PantherDir -ItemType Directory -Force | Out-Null
    }
    $UnattendXmlContent | Out-File -FilePath $PantherPath -Encoding utf8 -Force -ErrorAction Stop
    Write-Host "Unattend.xml also placed at '$PantherPath' for redundancy."

} catch {
    Write-Error "Failed to generate or place unattend.xml: $($_.Exception.Message)"
}
#endregion

#region 7. Install Software using Chocolatey
Write-Host "Starting software installations using Chocolatey..."

function Install-ChocolateyPackage {
    param(
        [Parameter(Mandatory=$true)][string]$PackageId,
        [Parameter(Mandatory=$true)][string]$PackageName
    )
    
    Write-Host "Attempting to install $PackageName (ID: $PackageId)..."
    try {
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Warning "Chocolatey is not installed. Cannot install $PackageName."
            return
        }

        # Check if the package is already installed
        $installedPackages = choco list --local-only --limit-output
        if ($installedPackages -match "(?i)^$([regex]::Escape($PackageId))") {
            Write-Warning "$PackageName is already installed."
        } else {
            Write-Host "Installing $PackageName..."
            choco install "$PackageId" -y --no-progress
            if ($LASTEXITCODE -eq 0) {
                Write-Host "$PackageName installed successfully."
            } else {
                Write-Error "Failed to install $PackageName. Choco exit code: $LASTEXITCODE"
            }
        }
    } catch {
        Write-Error "An error occurred installing '$PackageName': $($_.Exception.Message)"
    }
}

# Check and install Chocolatey if it's not present
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey is not installed. Installing Chocolatey..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force;
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12;
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Host "Chocolatey installed successfully."
        Start-Sleep -Seconds 5
    } catch {
        Write-Error "Failed to install Chocolatey: $($_.Exception.Message)"
        Write-Warning "Software installations will be skipped."
    }
} else {
    Write-Host "Chocolatey is already installed."
}

# Install packages only if Chocolatey is confirmed to be available
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Install-ChocolateyPackage -PackageName "Google Chrome" -PackageId "googlechrome"
    Install-ChocolateyPackage -PackageName "7-Zip" -PackageId "7zip"
    Install-ChocolateyPackage -PackageName "WinDirStat" -PackageId "windirstat"
    Install-ChocolateyPackage -PackageName "Everything" -PackageId "everything"
    Install-ChocolateyPackage -PackageName "Notepad++" -PackageId "notepadplusplus"
    Install-ChocolateyPackage -PackageName "VLC Media Player" -PackageId "vlc"
}
#endregion

#region 8. Create First-Logon Script for User-Specific Settings
Write-Host "Creating first-logon script for user '$Username'..."
$SetupDir = "C:\TempSetup"
$FirstLogonScriptPath = Join-Path $SetupDir "FirstLogonSetup.ps1"
$StartupFolderPath = Join-Path (Join-Path "C:\Users" $Username) "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

# Create directories if they don't exist
try {
    New-Item -Path $SetupDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    New-Item -Path $StartupFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Failed to create necessary directories for first logon script: $($_.Exception.Message)"
}

# Define the content for the first-logon script
$FirstLogonScriptContent = @"
# This script runs on the new user's first login to apply personal settings.
Start-Sleep -Seconds 5

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
Remove-Item -Path "`$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ApplySettings.lnk" -Force -ErrorAction SilentlyContinue
"@

# Write the script content to the file
try {
    $FirstLogonScriptContent | Out-File -FilePath $FirstLogonScriptPath -Encoding utf8 -Force -ErrorAction Stop
} catch {
    Write-Error "Failed to write first logon script content: $($_.Exception.Message)"
}

# Create a shortcut in the user's startup folder
try {
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut((Join-Path $StartupFolderPath "ApplySettings.lnk"))
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FirstLogonScriptPath`""
    $Shortcut.Save()
    Write-Host "First logon script created successfully."
} catch {
    Write-Error "Failed to create shortcut for first logon script: $($_.Exception.Message)"
}
#endregion

#region 9. Remove Shortcut Overlay on Icons
Write-Host "Removing shortcut overlay on icons..."
try {
    $ShellIconPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
    if (-not (Test-Path $ShellIconPath)) { New-Item -Path $ShellIconPath -ItemType Directory -Force | Out-Null }
    Set-ItemProperty -Path $ShellIconPath -Name "29" -Value "%windir%\System32\shell32.dll,-50" -Force -ErrorAction Stop
    Write-Host "Shortcut overlay removal setting applied."
} catch {
    Write-Error "Failed to remove shortcut overlay: $($_.Exception.Message)"
}
#endregion

#region 10. Configure Display Power Settings
Write-Host "Configuring Display Power Settings..."
try {
    $powerCfgOutput = powercfg /getactivescheme | Out-String
    $match = [regex]::Match($powerCfgOutput, 'Power Scheme GUID: ([\da-fA-F-]+)')
    $activeScheme = if ($match.Success) { $match.Groups[1].Value } else { $null }

    if (-not [string]::IsNullOrWhiteSpace($activeScheme)) {
        & powercfg /setacvalueindex $activeScheme SUB_MONITOR VIDEOIDLE 0
        & powercfg /setdcvalueindex $activeScheme SUB_MONITOR VIDEOIDLE 900
        & powercfg /setactive $activeScheme
        Write-Host "Display power settings applied (AC: Never, DC: 15 mins)."
    } else {
        Write-Warning "Could not determine active power scheme. Skipping display power settings."
    }
} catch {
    Write-Error "Failed to configure display power settings: $($_.Exception.Message)"
}
#endregion

#region 11. Final OOBE Completion Registry Keys
Write-Host "Setting final OOBE completion registry keys..."
try {
    # Mark OOBE as complete in multiple locations
    Set-ItemProperty -Path $oobeMainPath -Name "OOBEComplete" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $oobeMainPath -Name "UnattendDone" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $oobeMainPath -Name "PrivacySettingsDone" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    
    # Additional completion markers
    $setupCompletePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State"
    if (-not (Test-Path $setupCompletePath)) { New-Item -Path $setupCompletePath -ItemType Directory -Force | Out-Null }
    Set-ItemProperty -Path $setupCompletePath -Name "ImageState" -Value "IMAGE_STATE_COMPLETE" -Type String -Force -ErrorAction SilentlyContinue
    
    Write-Host "Final OOBE completion registry keys set."
} catch {
    Write-Error "Failed to set final OOBE completion keys: $($_.Exception.Message)"
}
#endregion

#region 12. Cleanup
Write-Host "Performing cleanup..."
try {
    # Clear the plain text password variable immediately
    $PasswordPlainForUnattend = $null
    
    Write-Host "Cleanup completed."
} catch {
    Write-Error "Failed during cleanup: $($_.Exception.Message)"
}
#endregion

#region 13. Stop Logging and Reboot
Stop-Transcript
Write-Host "Script execution complete. System will now restart to apply all changes."
Write-Host "After reboot, the system should bypass OOBE and go directly to the desktop."
Start-Sleep -Seconds 5
shutdown.exe /r /t 5 /f /c "OOBE bypass configuration complete. Rebooting to desktop."
#endregion
