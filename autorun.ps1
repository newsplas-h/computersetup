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

if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey is not installed. Installing Chocolatey..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Host "Chocolatey installed successfully."
        Start-Sleep -Seconds 5
    } catch {
        Write-Error "Failed to install Chocolatey: $($_.Exception.Message)"
        Write-Warning "Skipping all Chocolatey-based software installations."
    }
} else {
    Write-Host "Chocolatey is already installed."
}

function Install-ChocolateyPackage {
    param(
        [string]$PackageId,
        [string]$PackageName
    )

    Write-Host "Attempting to install $PackageName (ID: $PackageId) using Chocolatey..."
    try {
        if (Get-Command choco -ErrorAction SilentlyContinue) {
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
        Write-Error "An error occurred while trying to install packages: $($_.Exception.Message)"
    }
}

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

#region 5–11 (System Tweaks Omitted for Brevity — Same as Original)
# (Dark Mode, UAC, taskbar config, snap assist, display power, etc.)
#endregion

#region 12. Bypass Remaining OOBE Screens (Original Attempt)
Write-Host "Attempting to bypass remaining OOBE screens (final attempt)..."

$oobePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
$oobeSetupPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE\Setup"

try {
    if (-not (Test-Path $oobePath)) { New-Item -Path $oobePath -Force | Out-Null }
    if (-not (Test-Path $oobeSetupPath)) { New-Item -Path $oobeSetupPath -Force | Out-Null }

    Set-ItemProperty -Path $oobePath -Name "UnattendDone" -Value 1 -Force
    Set-ItemProperty -Path $oobeSetupPath -Name "SetupUI" -Value 0 -Force
    Set-ItemProperty -Path $oobePath -Name "OOBEComplete" -Value 1 -Force

    Write-Host "OOBE bypass settings applied (check warnings for specific failures)."
} catch {
    Write-Error "An overall error occurred trying to access OOBE registry paths: $($_.Exception.Message)"
}
#endregion

#region 12b. Force Complete Setup Phase and Prevent OOBE Loop
Write-Host "Applying additional registry settings to prevent OOBE prompt after reboot..."

try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\Setup" -Name "OOBEInProgress" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\Setup" -Name "SetupPhase" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\Setup" -Name "SetupType" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\Setup" -Name "SystemSetupInProgress" -Value 0 -Force

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE" -Name "OOBEComplete" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" -Name "ImageState" -Value "IMAGE_STATE_COMPLETE" -Force

    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows
