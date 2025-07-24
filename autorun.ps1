# Windows 11 OOBE Setup Script with Unattend.xml Generator
# Run during OOBE (Shift+F10 > powershell > irm <URL> | iex)

#region 1. Set Execution Policy for OOBE
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
#endregion

#region 2. Prompt for Username, Password, and Computer Name
Write-Host "=== User Setup ==="
$Username = Read-Host "Enter the desired local username (e.g., NS)"

while ($true) {
    $PasswordSecure = Read-Host -AsSecureString "Enter a password for user '$Username':"
    $ConfirmPasswordSecure = Read-Host -AsSecureString "Confirm password for '$Username':"

    try {
        $PasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
        $ConfirmPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))
    } catch {
        Write-Error "Password input failed: $($_.Exception.Message)"
        exit 1
    }

    if ($PasswordPlain -eq $ConfirmPasswordPlain) {
        $Password = $PasswordSecure
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))
        break
    } else {
        Write-Warning "Passwords do not match. Try again."
    }
}

$ComputerName = Read-Host "Enter the desired computer name (e.g., DESKTOP-NS01)"
#endregion

#region 3. Create Local Admin User
Write-Host "Creating user '$Username'..."
try {
    if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $Username -Password $Password -FullName "$Username Admin" -Description "Local Administrator" -PasswordNeverExpires
        Add-LocalGroupMember -Group "Administrators" -Member $Username
        Write-Host "User '$Username' created and added to Administrators group."
    } else {
        Write-Host "User '$Username' already exists."
    }
} catch {
    Write-Error "Failed to create user or add to Administrators group: $($_.Exception.Message)"
}
#endregion

#region 4. Set Computer Name
Write-Host "Setting the computer name to '$ComputerName'..."
if (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
    try {
        Rename-Computer -NewName $ComputerName -Force
        Write-Host "Computer name set to '$ComputerName'. Reboot required."
    } catch {
        Write-Error "Failed to set computer name: $($_.Exception.Message)"
    }
} else {
    Write-Warning "Computer name not specified. Skipping rename."
}
#endregion

#region 5. Generate unattend.xml
Write-Host "Generating unattend.xml..."
$PasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
$UnattendPath = "C:\Windows\Panther\unattend.xml"

$UnattendXml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <NetworkLocation>Work</NetworkLocation>
        <ProtectYourPC>3</ProtectYourPC>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Password>
              <Value>$PasswordPlain</Value>
              <PlainText>true</PlainText>
            </Password>
            <Group>Administrators</Group>
            <Name>$Username</Name>
            <DisplayName>$Username</DisplayName>
            <Description>Local Administrator</Description>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <RegisteredOrganization>CustomSetup</RegisteredOrganization>
      <RegisteredOwner>$Username</RegisteredOwner>
      <TimeZone>UTC</TimeZone>
      <ComputerName>$ComputerName</ComputerName>
    </component>
  </settings>
</unattend>
"@

try {
    New-Item -Path (Split-Path $UnattendPath) -ItemType Directory -Force | Out-Null
    $UnattendXml | Out-File -FilePath $UnattendPath -Encoding utf8 -Force
    Write-Host "unattend.xml generated at $UnattendPath"
} catch {
    Write-Error "Failed to create unattend.xml: $($_.Exception.Message)"
}
#endregion

#region 6. Install Software with Chocolatey
Write-Host "Installing software using Chocolatey..."
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey not found. Installing..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        iex ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Host "Chocolatey installed successfully."
        Start-Sleep -Seconds 5
    } catch {
        Write-Error "Chocolatey install failed: $($_.Exception.Message)"
    }
}

function Install-ChocolateyPackage {
    param([string]$PackageId, [string]$PackageName)
    Write-Host "Installing $PackageName ($PackageId)..."
    try {
        if (choco list --local-only --limit-output | Select-String -Pattern "^$PackageId") {
            Write-Warning "$PackageName already installed."
        } else {
            choco install "$PackageId" -y --no-progress
            if ($LASTEXITCODE -eq 0) {
                Write-Host "$PackageName installed successfully."
            } else {
                Write-Error "Failed to install $PackageName (Exit code: $LASTEXITCODE)"
            }
        }
    } catch {
        Write-Error "Package install error for $PackageName: $($_.Exception.Message)"
    }
}

if (Get-Command choco -ErrorAction SilentlyContinue) {
    Install-ChocolateyPackage -PackageId "googlechrome" -PackageName "Google Chrome"
    Install-ChocolateyPackage -PackageId "7zip" -PackageName "7-Zip"
    Install-ChocolateyPackage -PackageId "windirstat" -PackageName "WinDirStat"
    Install-ChocolateyPackage -PackageId "everything" -PackageName "Everything"
    Install-ChocolateyPackage -PackageId "notepadplusplus" -PackageName "Notepad++"
    Install-ChocolateyPackage -PackageId "vlc" -PackageName "VLC Media Player"
}
#endregion

#region 7. System Tweaks (Dark Mode, Taskbar, Context Menu)
Write-Host "Applying Windows customization..."
$SetupDir = "C:\TempSetup"
$FirstLogonScriptPath = Join-Path $SetupDir "FirstLogonSetup.ps1"
$StartupFolderPath = "C:\Users\$Username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

New-Item -Path $SetupDir -ItemType Directory -Force | Out-Null
New-Item -Path $StartupFolderPath -ItemType Directory -Force | Out-Null

$FirstLogonScriptContent = @"
Start-Sleep -Seconds 5

# Dark Mode
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0

# Snap Settings
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableSnapAssist" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapOverlay" -Value 0

# Taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SearchboxTaskbarMode" -Value 0

# Old Context Menu
\$CLSIDPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (-not (Test-Path \$CLSIDPath)) { New-Item -Path \$CLSIDPath -Force | Out-Null }
Set-ItemProperty -Path \$CLSIDPath -Name "(Default)" -Value ""

# Cleanup
Remove-Item -Path "\$MyInvocation.MyCommand.Path" -Force
Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ApplySettings.lnk" -Force
"@

$FirstLogonScriptContent | Out-File -FilePath $FirstLogonScriptPath -Encoding utf8 -Force

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut((Join-Path $StartupFolderPath "ApplySettings.lnk"))
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FirstLogonScriptPath`""
$Shortcut.Save()
#endregion

#region 8. Disable UAC
Write-Host "Disabling UAC..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Force
#endregion

#region 9. OOBE Bypass
Write-Host "Bypassing OOBE..."
$oobePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
if (-not (Test-Path $oobePath)) { New-Item -Path $oobePath -Force | Out-Null }
Set-ItemProperty -Path $oobePath -Name "BypassNRO" -Value 1 -Type DWord
Set-ItemProperty -Path $oobePath -Name "OOBEComplete" -Value 1 -Type DWord
#endregion

#region 10. Auto Reboot
Write-Host "Setup complete. Rebooting..."
Start-Sleep -Seconds 5
shutdown.exe /r /t 5 /f /c "System configuration complete. Rebooting..."
#endregion
