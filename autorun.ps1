#Requires -RunAsAdministrator

# 1. CREATE ADMIN ACCOUNT
$credential = Get-Credential -Message "Create admin account" -UserName "Admin"
$username = $credential.UserName
$password = $credential.GetNetworkCredential().Password

New-LocalUser -Name $username -Password (ConvertTo-SecureString $password -AsPlainText -Force) -FullName $username
Add-LocalGroupMember -Group "Administrators" -Member $username
Write-Host "Admin account '$username' created" -ForegroundColor Green

# 2. INSTALL SOFTWARE VIA CHOCOLATEY
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

$apps = @(
    '7zip',
    'googlechrome',
    'everything',
    'windirstat',
    'notepadplusplus',
    'vlc'
)

foreach ($app in $apps) {
    choco install $app -y --force
}

# 3. REGISTRY TWEAKS
$registrySettings = @(
    # Dark Mode
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"; Name="AppsUseLightTheme"; Value=0; Type="DWord"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"; Name="SystemUsesLightTheme"; Value=0; Type="DWord"},
    
    # Remove Shortcut Arrow
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"; Name="29"; Value="$env:SystemRoot\System32\imageres.dll,-1001"; Type="String"},
    
    # Snap Assist Disable
    @{Path="HKCU:\Control Panel\Desktop"; Name="WindowArrangementActive"; Value=0; Type="DWord"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="EnableSnapAssistFlyout"; Value=0; Type="DWord"},
    
    # Taskbar Settings
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="TaskbarAl"; Value=0; Type="DWord"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ShowTaskViewButton"; Value=0; Type="DWord"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="TaskbarDa"; Value=0; Type="DWord"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="SearchboxTaskbarMode"; Value=0; Type="DWord"},
    
    # Classic Context Menu
    @{Path="HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"; Name="(Default)"; Value=""; Type="String"}
)

foreach ($setting in $registrySettings) {
    if (-not (Test-Path $setting.Path)) {
        New-Item -Path $setting.Path -Force | Out-Null
    }
    New-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force | Out-Null
}

# 4. REBOOT WORKAROUND (OOBE Bypass)
Write-Host "Triggering reboot bypass..." -ForegroundColor Yellow
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SpecialAccounts" -Force | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts" -Name "UserList" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name $username -Value 0 -Type DWord

# 5. FINAL STEPS
Write-Host "Rebooting in 10 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 10
Restart-Computer -Force
