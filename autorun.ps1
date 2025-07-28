# Prompt the user to enter the full URL to the Default.ppkg file
$ppkgUrl = Read-Host "Please enter the full URL to the Default.ppkg file"

# Define the local path to save the .ppkg file
$ppkgPath = "$env:TEMP\Default.ppkg"

# Download the .ppkg file from the user-provided URL
Invoke-WebRequest -Uri $ppkgUrl -OutFile $ppkgPath

# Install the .ppkg silently
Add-ProvisioningPackage -PackagePath $ppkgPath -QuietInstall

# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install specified applications using Chocolatey
choco install -y 7zip googlechrome everything windirstat notepadplusplus vlc

# Load the default user hive to apply settings to all new users
reg load HKU\DefaultUser C:\Users\Default\NTUSER.DAT

# Registry changes for Windows settings
# Enable dark mode
Set-ItemProperty -Path "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
Set-ItemProperty -Path "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0

# Adjust window snap settings (disable suggestions)
Set-ItemProperty -Path "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 0

# Customize taskbar: move to left, disable Task View and Widgets
Set-ItemProperty -Path "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0
Set-ItemProperty -Path "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0
Set-ItemProperty -Path "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0

# Hide search bar on taskbar
Set-ItemProperty -Path "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0

# Enable Windows 10-style context menu
New-Item -Path "HKU\DefaultUser\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force
Set-ItemProperty -Path "HKU\DefaultUser\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Value ""

# Unload the default user hive
reg unload HKU\DefaultUser

# Attempt to remove shortcut overlay on icons (may not work in Windows 11)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -Value ""
