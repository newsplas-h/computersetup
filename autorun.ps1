# Windows 11 OOBE Automation Script with Self-Update and Unattend.xml
# HOW TO RUN: Shift+F10 during OOBE > powershell >
# irm https://raw.githubusercontent.com/<your-username>/<your-repo>/main/oobe.ps1 | iex

#Requires -RunAsAdministrator

#region 0. Self-Update
function Self-Update {
    param (
        [string]$Url = "https://raw.githubusercontent.com/<your-username>/<your-repo>/main/oobe.ps1"
    )

    Write-Host "Checking for latest version from GitHub..." -ForegroundColor Yellow
    try {
        $latestScript = Invoke-RestMethod -Uri $Url -UseBasicParsing
        if ($latestScript) {
            Write-Host "Running the latest version of the script from GitHub..." -ForegroundColor Green
            Invoke-Expression $latestScript
            exit
        } else {
            Write-Warning "Failed to retrieve the script from GitHub. Running local copy instead."
        }
    } catch {
        Write-Warning "Error fetching script from GitHub: $($_.Exception.Message)"
    }
}

# Uncomment if you want to always self-update from GitHub
# Self-Update -Url "https://raw.githubusercontent.com/<your-username>/<your-repo>/main/oobe.ps1"
#endregion

#region 1. Initialization
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Write-Host "=== Windows 11 OOBE Automation Script ===" -ForegroundColor Green
Write-Host "Starting automated setup..." -ForegroundColor Yellow

$Username = "Admin" + (Get-Random -Maximum 9999)
$PasswordPlain = "P@ssw0rd123!"
$Password = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
$ComputerName = "DESKTOP-$((Get-Random -Maximum 9999))"
#endregion

#region 2. Create Local Admin User
Write-Host "`n[STEP 1/10] Creating local administrator user..." -ForegroundColor Cyan
try {
    if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $Username -Password $Password -FullName "$Username Admin" -Description "Local Administrator" -PasswordNeverExpires
        Add-LocalGroupMember -Group "Administrators" -Member $Username
        Write-Host "✓ User '$Username' created successfully." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to create local admin user: $($_.Exception.Message)"
    exit 1
}
#endregion

#region 3. Set Computer Name
Write-Host "`n[STEP 2/10] Setting the Computer Name..." -ForegroundColor Cyan
try {
    Rename-Computer -NewName $ComputerName -Force
    Write-Host "✓ Computer name set to '$ComputerName'." -ForegroundColor Green
} catch {
    Write-Error "Failed to rename computer: $($_.Exception.Message)"
}
#endregion

#region 4. Generate Unattend.xml
Write-Host "`n[STEP 3/10] Generating Unattend.xml..." -ForegroundColor Cyan

try {
    $UnattendPath = "C:\Windows\Panther\Unattend"
    New-Item -Path $UnattendPath -ItemType Directory -Force | Out-Null

    $UnattendXML = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <AutoLogon>
        <Password>
          <Value>$PasswordPlain</Value>
          <PlainText>true</PlainText>
        </Password>
        <Enabled>true</Enabled>
        <Username>$Username</Username>
      </AutoLogon>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>$Username</Name>
            <Password>
              <Value>$PasswordPlain</Value>
              <PlainText>true</PlainText>
            </Password>
            <Group>Administrators</Group>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <ProtectYourPC>1</ProtectYourPC>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <RegisteredOrganization>Custom Setup</RegisteredOrganization>
      <RegisteredOwner>Custom User</RegisteredOwner>
      <TimeZone>UTC</TimeZone>
      <ComputerName>$ComputerName</ComputerName>
    </component>
  </settings>
</unattend>
"@

    $UnattendXML | Out-File -FilePath "$UnattendPath\Unattend.xml" -Encoding UTF8 -Force
    Write-Host "✓ Unattend.xml created at $UnattendPath\Unattend.xml" -ForegroundColor Green
} catch {
    Write-Error "Failed to create Unattend.xml: $($_.Exception.Message)"
}
#endregion

#region 5. Registry Fixes for OOBE Completion
Write-Host "`n[STEP 4/10] Marking OOBE as complete..." -ForegroundColor Cyan
$setupKey = "HKLM:\SYSTEM\Setup"
Set-ItemProperty -Path $setupKey -Name "SetupType" -Value 0 -Force
Set-ItemProperty -Path $setupKey -Name "SystemSetupInProgress" -Value 0 -Force
Set-ItemProperty -Path $setupKey -Name "SetupPhase" -Value 0 -Force
Set-ItemProperty -Path $setupKey -Name "OOBEInProgress" -Value 0 -Force
Set-ItemProperty -Path $setupKey -Name "CmdLine" -Value "" -Force
Write-Host "✓ Registry updated for OOBE completion." -ForegroundColor Green
#endregion

#region 6. Install Chocolatey and Basic Software
Write-Host "`n[STEP 5/10] Installing Chocolatey and basic tools..." -ForegroundColor Cyan
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}
choco install googlechrome 7zip notepadplusplus vlc -y --no-progress
#endregion

#region 7. Configure Autologon (Backup)
Write-Host "`n[STEP 6/10] Configuring autologon (backup)..." -ForegroundColor Cyan
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "1" -Force
Set-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -Value $Username -Force
Set-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -Value $PasswordPlain -Force
#endregion

#region 8. Finalize and Reboot
Write-Host "`n=== SETUP COMPLETE ===" -ForegroundColor Green
Write-Host "System will reboot in 5 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 5
shutdown.exe /r /t 0 /f /c "OOBE automation complete - rebooting to desktop"
#endregion
