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
    # Consider exiting here if execution policy is critical for subsequent steps
}
#endregion

#region 2. Create Local Admin User (User Input) and Prompt for Password
Write-Host "Setting up local administrator user."

# Get Username from user input
$Username = ""
while ([string]::IsNullOrWhiteSpace($Username)) {
    $Username = Read-Host "Please enter the desired local administrator username:"
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

while ($true) {
    $PasswordSecure = Read-Host -AsSecureString "Please enter a password for the user '$Username':"
    $ConfirmPasswordSecure = Read-Host -AsSecureString "Please confirm the password for the user '$Username':"

    # Convert SecureString to plain string for comparison only.
    # It's crucial not to store or log the plain text password.
    $PasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
    $ConfirmPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))

    if ($PasswordPlain -eq $ConfirmPasswordPlain) {
        $Password = $PasswordSecure
        # Securely clear plain text password variables immediately after comparison
        $PasswordPlain = $null
        $ConfirmPasswordPlain = $null
        break
    } else {
        Write-Warning "Passwords do not match. Please try again."
        # Securely clear plain text password variables
        $PasswordPlain = $null
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
    Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction Stop
    Write-Host "User '$Username' successfully added to Administrators group."

} catch {
    Write-Error "Failed to manage user '$Username': $($_.Exception.Message)"
    # Exit or handle error appropriately if user creation is critical
}
#endregion

#region 3. Set Computer Name Automatically
Write-Host "Setting the Computer Name automatically based on the user '$Username'..."
# Automatically generate a computer name, e.g., NS-PC, ADMIN-PC
# Ensure the username part is sanitized for a computer name (e.g., remove spaces or special chars if present)
$SanitizedUsername = ($Username -replace '[^a-zA-Z0-9]', '').ToUpper() # Remove non-alphanumeric, convert to uppercase

# Construct the computer name. You can adjust the suffix as desired.
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

#region 4. Install Software using Chocolatey
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
            return # Exit function if choco isn't present
        }

        # Check if the package is already installed more robustly
        $installedPackages = choco list --local-only --limit-output
        if ($installedPackages -match "(?i)^$([regex]::Escape($PackageId))") { # Case-insensitive regex match
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
        Start-Sleep -Seconds 5 # Give Chocolatey a moment to initialize
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

#region 5. Create First-Logon Script for User-Specific Settings
Write-Host "Creating first-logon script for user '$Username'..."
$SetupDir = "C:\TempSetup"
$FirstLogonScriptPath = Join-Path $SetupDir "FirstLogonSetup.ps1"
# Get the actual user profile path for the '$Username' user
$StartupFolderPath = Join-Path (Join-Path "C:\Users" $Username) "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

# Create directories if they don't exist
try {
    New-Item -Path $SetupDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    New-Item -Path $StartupFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Failed to create necessary directories for first logon script: $($_.Exception.Message)"
    # Consider exiting or skipping this section if directory creation fails
}

# Define the content for the first-logon script. This contains all HKCU changes.
# Escaping dollar signs for variables that should be evaluated by the inner script
$FirstLogonScriptContent = @"
# This script runs on the new user's first login to apply personal settings.
Start-Sleep -Seconds 5 # Give the desktop a moment to load

# Set Dark Mode
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force -ErrorAction SilentlyContinue

# Configure Snap Window settings
# Note: These values might be different or change with newer Windows versions.
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableSnapAssist" -Value 1 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapOverlay" -Value 0 -Force -ErrorAction SilentlyContinue

# Move Taskbar to Left, Disable Task View, Widgets, and Hide Search Bar
# These are Windows 11 specific settings and might require further research for exact values and paths
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force -ErrorAction SilentlyContinue # Taskbar alignment (0=Left, 1=Center)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force -ErrorAction SilentlyContinue # Widgets button
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SearchboxTaskbarMode" -Value 0 -Force -ErrorAction SilentlyContinue # Search icon

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

# Create a shortcut in the user's startup folder to run the script silently
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

#region 6. User Account Control (UAC) Configuration
Write-Host "Configuring User Account Control (UAC) settings..."
Write-Host "UAC settings are not modified by this script to maintain system security."
# As noted in your original script, disabling UAC (EnableLUA = 0) is a significant security risk.
# The script will continue to explicitly not modify UAC settings.
# If you decide to modify UAC, uncomment and adjust the example code with caution.
#
# Example (to reduce prompts, but still keep UAC enabled - use with caution):
# try {
#     Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -Force -ErrorAction Stop
#     Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0 -Force -ErrorAction Stop
#     Write-Host "UAC prompt behavior adjusted to reduce prompts while keeping UAC enabled."
# } catch {
#     Write-Error "Failed to adjust UAC prompt behavior: $($_.Exception.Message)"
# }
#endregion

#region 7. Remove Shortcut Overlay on Icons
Write-Host "Removing shortcut overlay on icons..."
try {
    $ShellIconPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
    if (-not (Test-Path $ShellIconPath)) { New-Item -Path $ShellIconPath -ItemType Directory -Force | Out-Null } # Ensure path is a directory
    Set-ItemProperty -Path $ShellIconPath -Name "29" -Value "%windir%\System32\shell32.dll,-50" -Force -ErrorAction Stop
    Write-Host "Shortcut overlay removal setting applied. Explorer restart needed for full effect."
} catch {
    Write-Error "Failed to remove shortcut overlay: $($_.Exception.Message)"
}
#endregion

#region 8. Configure Display Power Settings
Write-Host "Configuring Display Power Settings..."
try {
    # Using powercfg directly to get the active scheme GUID
    # The output of 'powercfg /getactivescheme' is like:
    # Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)
    $powerCfgOutput = powercfg /getactivescheme | Out-String
    $match = [regex]::Match($powerCfgOutput, 'Power Scheme GUID: ([\da-fA-F-]+)')
    $activeScheme = if ($match.Success) { $match.Groups[1].Value } else { $null }

    if (-not [string]::IsNullOrWhiteSpace($activeScheme)) {
        # VIDEOIDLE refers to 'Turn off display after'
        # Setting AC to 0 (Never)
        # Setting DC to 900 seconds (15 minutes)
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

#region 9. Bypass Remaining OOBE Screens (Registry Flags)
Write-Host "Applying registry keys to bypass remaining OOBE screens..."
$oobePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
try {
    if (-not (Test-Path $oobePath)) { New-Item -Path $oobePath -ItemType Directory -Force | Out-Null }

    # CRITICAL: This key tells setup to allow skipping the network connection screen.
    Set-ItemProperty -Path $oobePath -Name "BypassNRO" -Value 1 -Type DWord -Force -ErrorAction Stop
    
    # These keys signal to Windows that OOBE is complete.
    Set-ItemProperty -Path $oobePath -Name "OOBEComplete" -Value 1 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path $oobePath -Name "UnattendDone" -Value 1 -Type DWord -Force -ErrorAction Stop
    
    Write-Host "OOBE bypass keys set successfully."
} catch {
    Write-Error "Failed to set OOBE bypass registry keys: $($_.Exception.Message)"
}
#endregion

#region 10. Bypass Hardware Requirements (LabConfig)
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

#region 11. Cleanup
Write-Host "Performing cleanup..."
try {
    # Remove temporary setup directory
    if (Test-Path $SetupDir) {
        Remove-Item -Path $SetupDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Removed temporary setup directory: $SetupDir"
    }
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
