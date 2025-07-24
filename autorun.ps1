# Windows 11 OOBE Automation Script
# HOW TO RUN:
# During OOBE (language screen), press Shift+F10, type:
# powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/YOUR_REPO/main/oobe.ps1 | iex"

# Ensure admin privileges
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Write-Host "=== Windows 11 OOBE Automation Script ===" -ForegroundColor Green

#region 1. Create Local Admin User
Write-Host "[1/8] Creating local administrator account..." -ForegroundColor Cyan

# Generate random username and password if not predefined
$Username = "User" + (Get-Random -Maximum 9999)
$PasswordPlain = [guid]::NewGuid().ToString("N").Substring(0,12) + "!"
$Password = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force

try {
    New-LocalUser -Name $Username -Password $Password -FullName "Local Admin" -Description "Auto-created Admin" -PasswordNeverExpires
    Add-LocalGroupMember -Group "Administrators" -Member $Username
    Write-Host "✓ Created user '$Username' with password '$PasswordPlain'" -ForegroundColor Green
} catch {
    Write-Error "Failed to create user: $($_.Exception.Message)"
    exit 1
}
#endregion

#region 2. Set Computer Name
Write-Host "[2/8] Setting computer name..." -ForegroundColor Cyan
$ComputerName = "PC-" + (Get-Random -Maximum 9999)
Rename-Computer -NewName $ComputerName -Force
Write-Host "✓ Computer name set to $ComputerName" -ForegroundColor Green
#endregion

#region 3. Force Local Account (OOBE Bypass)
Write-Host "Forcing Windows 11 OOBE to show local account setup..."
try {
    Start-Process "cmd.exe" -ArgumentList "/c start ms-cxh:localonly"
    Write-Host "Local account setup screen triggered successfully."
} catch {
    Write-Error "Failed to trigger local account setup: $($_.Exception.Message)"
}
#endregion

#region 4. Set Computer Name
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

#region 5. Install Software using Chocolatey
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

#region 6. Power Settings
Write-Host "[6/8] Setting power options..." -ForegroundColor Cyan
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0
Write-Host "✓ Power settings configured." -ForegroundColor Green
#endregion

#region 7. Cleanup & Logon Preparation
Write-Host "[7/8] Finalizing setup..." -ForegroundColor Cyan
# Mark OOBE as completed to skip remaining setup
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE" /v "SkipMachineOOBE" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE" /v "SkipUserOOBE" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" /v "ImageState" /t REG_SZ /d "IMAGE_STATE_COMPLETE" /f
#endregion

#region 8. Reboot
Write-Host "[8/8] Rebooting in 10 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 10
Restart-Computer -Force
#endregion
