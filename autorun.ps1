#Requires -RunAsAdministrator

# 1. BYPASS OOBE INTERNET REQUIREMENT & PREVENT REBOOT LOOP
# ---------------------------------------------------------
# Force OOBE to allow local account creation
cmd /c "oobe\bypassnro"
Start-Sleep -Seconds 5

# Disable network interfaces to enforce offline setup
$interfaces = (netsh interface show interface | Where-Object { $_ -match 'Connected' -and $_ -notmatch 'Loopback' } | ForEach-Object { ($_ -split '\s+')[3] })
foreach ($iface in $interfaces) {
    netsh interface set interface name="$iface" admin=DISABLED
}

# 2. CREATE ADMIN ACCOUNT (HIDDEN UNTIL POST-REBOOT)
# --------------------------------------------------
$username = "LocalAdmin"  # Customize or prompt: Read-Host "Enter admin username"
$password = ConvertTo-SecureString "TempPassword123!" -AsPlainText -Force  # Replace with user input

New-LocalUser -Name $username -Password $password -FullName $username
Add-LocalGroupMember -Group "Administrators" -Member $username

# Hide account from login screen until reboot
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v $username /t REG_DWORD /d 0 /f

# 3. REGISTRY TWEAKS (APPLIED DURING OOBE)
# ----------------------------------------
$registrySettings = @(
    # Dark Mode
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"; Name="AppsUseLightTheme"; Value=0; Type="DWord"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"; Name="SystemUsesLightTheme"; Value=0; Type="DWord"},
    
    # Remove Shortcut Arrow
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"; Name="29"; Value="$env:SystemRoot\System32\imageres.dll,-1001"; Type="String"},
    
    # Disable Snap Assist & Layouts
    @{Path="HKCU:\Control Panel\Desktop"; Name="WindowArrangementActive"; Value=0; Type="DWord"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="EnableSnapAssistFlyout"; Value=0; Type="DWord"},
    
    # Taskbar: Left-align, hide buttons
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="TaskbarAl"; Value=0; Type="DWord"},  # Left-align
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ShowTaskViewButton"; Value=0; Type="DWord"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="TaskbarDa"; Value=0; Type="DWord"},  # Hide widgets
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="SearchboxTaskbarMode"; Value=0; Type="DWord"},  # Hide search
    
    # Classic Context Menu
    @{Path="HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"; Name="(Default)"; Value=""; Type="String"}
)

foreach ($setting in $registrySettings) {
    if (-not (Test-Path $setting.Path)) { New-Item -Path $setting.Path -Force | Out-Null }
    New-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force | Out-Null
}

# 4. POST-REBOOT AUTOMATION (VIA SCHEDULED TASK)
# ----------------------------------------------
$postRebootScript = {
    # Install Chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    
    # Install apps
    $apps = @('7zip', 'googlechrome', 'everything', 'windirstat', 'notepadplusplus', 'vlc')
    foreach ($app in $apps) { choco install $app -y }
    
    # Re-enable network
    $interfaces | ForEach-Object { netsh interface set interface name="$_" admin=ENABLED }
    
    # Rebuild icon cache (removes shortcut arrows)
    taskkill /f /im explorer.exe
    attrib -h -i "$env:LocalAppData\IconCache.db"
    Remove-Item "$env:LocalAppData\IconCache.db" -Force
    Start-Process explorer.exe
    
    # Delete itself from scheduled tasks
    Unregister-ScheduledTask -TaskName "OOBEAutomation" -Confirm:$false
}

$scriptBlock = $postRebootScript.ToString()
$scriptPath = "$env:ProgramData\postReboot.ps1"
$scriptBlock | Out-File -FilePath $scriptPath -Encoding UTF8

# Create scheduled task to run at first login
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -TaskName "OOBEAutomation" -User $username -Password "TempPassword123!"  # Match account password

# 5. FORCE OOBE COMPLETION & REBOOT
# ---------------------------------
# Bypass Microsoft account screen (works on Home/Pro)
Start-Process "cmd.exe" -ArgumentList "/c start ms-cxh:localonly" -Wait
shutdown /r /t 5
