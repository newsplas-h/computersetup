# Prompt user for the provisioning package URL
$ppkgUrl = Read-Host "Enter the direct URL to your .ppkg provisioning package file"

# Define local path to save the provisioning package
$localPath = "$env:SystemDrive\Temp\userpackage.ppkg"

# Create Temp directory if it doesn't exist
if (-not (Test-Path -Path "$env:SystemDrive\Temp")) {
    New-Item -ItemType Directory -Path "$env:SystemDrive\Temp" | Out-Null
}

try {
    Write-Host "Downloading provisioning package..."
    Invoke-WebRequest -Uri $ppkgUrl -OutFile $localPath -UseBasicParsing

    Write-Host "Installing provisioning package..."
    # Install silently, force install and skip integrity check if needed
    Install-ProvisioningPackage -PackagePath $localPath -ForceInstall -QuietInstall

    Write-Host "Provisioning package installed successfully."

    # Remove the provisioning package file after installation
    Remove-Item -Path $localPath -Force

    # Registry tweaks - Windows personalization and taskbar settings
    Write-Host "Applying Windows personalization and taskbar registry tweaks..."

    # Enable Dark mode (Apps and System)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0 -ErrorAction SilentlyContinue

    # Remove shortcut overlay icon on desktop shortcuts
    # Remove registry key that shows shortcut overlay
    $linkKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
    if (-not (Test-Path $linkKey)) {
        New-Item -Path $linkKey -Force | Out-Null
    }
    Set-ItemProperty -Path $linkKey -Name "29" -Value "$null" -ErrorAction SilentlyContinue
    # Setting the 29 value to empty disables shortcut overlay

    # Disable snap suggestions and snap layouts on top drag
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SnapAssistFlyoutEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SnapAssist" -Type DWord -Value 0 -ErrorAction SilentlyContinue

    # Move taskbar to left
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3" -Name "Settings" -Value (
        # Retrieve current value
        $bytes = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3").Settings
        # Modify the 13th byte for taskbar location:
        # 00 = left, 01 = top, 02 = right, 03 = bottom
        $bytes[12] = 0x00
        $bytes
    ) -ErrorAction SilentlyContinue

    # Disable Task View and Widgets buttons on taskbar
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0 -ErrorAction SilentlyContinue

    # Hide Search bar on taskbar (set to 0 hides)
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 -ErrorAction SilentlyContinue

    # Enable Windows 10 style classic context menu (disable Windows 11 new menu)
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Value "" -ErrorAction SilentlyContinue

    Write-Host "Registry tweaks applied."

    # Restart Explorer to apply some changes immediately
    Write-Host "Restarting Windows Explorer to apply changes..."
    Stop-Process -Name explorer -Force
    Start-Process explorer.exe

    # Install Chocolatey and programs
    Write-Host "Installing Chocolatey package manager..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

    Write-Host "Installing software packages via Chocolatey..."
    choco install -y 7zip googlechrome notepadplusplus vlc audacity shotcut

    Write-Host "All tasks complete."

} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}
