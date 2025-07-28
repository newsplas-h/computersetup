<#
.SYNOPSIS
    Windows 11 Complete OOBE Bypass and Setup Automation Script
.DESCRIPTION
    Bypasses all OOBE prompts and automates complete Windows 11 setup including 
    admin account creation, software installation, and system customizations.
.NOTES
    Run during OOBE using Shift+F10 or immediately after first login
#>

# Set error handling
$ErrorActionPreference = "Stop"

# Function to bypass OOBE prompts
function Invoke-OOBEBypass {
    Write-Host "Bypassing OOBE requirements..." -ForegroundColor Cyan
    
    try {
        # Method 1: Try the new ms-cxh:localonly approach
        Write-Host "Attempting new bypass method..." -ForegroundColor Yellow
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c start ms-cxh:localonly" -Wait -NoNewWindow
        
        # If that doesn't work, fall back to registry method
        Write-Host "Applying registry bypass..." -ForegroundColor Yellow
        
        # Create BypassNRO registry entry
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        Set-ItemProperty -Path $registryPath -Name "BypassNRO" -Value 1 -Type DWord -Force
        
        # Skip network requirement
        Set-ItemProperty -Path $registryPath -Name "NetworkLocation" -Value 1 -Type DWord -Force
        
        # Hide online account screens
        $shellSetupPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
        Set-ItemProperty -Path $shellSetupPath -Name "HideOnlineAccountScreens" -Value 1 -Type DWord -Force
        
        Write-Host "OOBE bypass configured successfully!" -ForegroundColor Green
        
    } catch {
        Write-Warning "Could not fully bypass OOBE: $($_.Exception.Message)"
    }
}

# Function to skip all OOBE prompts via registry
function Set-OOBESkipSettings {
    Write-Host "Configuring OOBE skip settings..." -ForegroundColor Green
    
    try {
        # Registry settings to skip various OOBE screens
        $oobeSettings = @{
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" = @{
                "ScoobeSystemSettingEnabled" = 0
            }
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" = @{
                "AllowCrossDeviceClipboard" = 0
                "EnableActivityFeed" = 0
                "PublishUserActivities" = 0
                "UploadUserActivities" = 0
            }
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" = @{
                "HideEULAPage" = 1
                "HideOEMRegistrationScreen" = 1
                "HideOnlineAccountScreens" = 1
                "HideWirelessSetupInOOBE" = 1
                "HideLocalAccountScreen" = 0
                "ProtectYourPC" = 3
            }
        }
        
        foreach ($path in $oobeSettings.Keys) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            
            foreach ($setting in $oobeSettings[$path].GetEnumerator()) {
                Set-ItemProperty -Path $path -Name $setting.Key -Value $setting.Value -Type DWord -Force
                Write-Host "Set $($setting.Key) = $($setting.Value)" -ForegroundColor Gray
            }
        }
        
        Write-Host "OOBE skip settings configured!" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to configure OOBE settings: $($_.Exception.Message)"
    }
}

# Function to create admin account automatically
function New-AutoAdminAccount {
    Write-Host "Creating automatic admin account..." -ForegroundColor Green
    
    try {
        # Use pre-defined credentials or prompt if needed
        $defaultUsername = "Admin"
        $defaultPassword = "TempPassword123!"
        
        # Check if we're in an interactive session
        if ([Environment]::UserInteractive) {
            $username = Read-Host "Enter username for admin account (default: $defaultUsername)"
            if ([string]::IsNullOrWhiteSpace($username)) { $username = $defaultUsername }
            
            $password = Read-Host "Enter password for admin account (default: $defaultPassword)" -AsSecureString
            if ($password.Length -eq 0) { 
                $password = ConvertTo-SecureString $defaultPassword -AsPlainText -Force 
            }
        } else {
            # Non-interactive mode - use defaults
            $username = $defaultUsername
            $password = ConvertTo-SecureString $defaultPassword -AsPlainText -Force
        }
        
        # Create the user account
        New-LocalUser -Name $username -Password $password -FullName $username -Description "Auto-created admin account" -PasswordNeverExpires:$true -ErrorAction SilentlyContinue
        
        # Add to administrators group
        Add-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction SilentlyContinue
        
        Write-Host "Admin account '$username' created successfully!" -ForegroundColor Green
        return $username
        
    } catch {
        Write-Warning "Could not create admin account: $($_.Exception.Message)"
        return $null
    }
}

# Enhanced software installation function
function Install-SoftwarePackages {
    Write-Host "Installing Chocolatey and software packages..." -ForegroundColor Green
    
    try {
        # Set TLS 1.2 for secure downloads
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        
        # Set execution policy
        Set-ExecutionPolicy Bypass -Scope Process -Force
        
        # Install Chocolatey with error handling
        $chocoInstallScript = (New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')
        Invoke-Expression $chocoInstallScript
        
        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        # Verify Chocolatey installation
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            Write-Host "Chocolatey installed successfully!" -ForegroundColor Green
            
            # Enable global confirmation
            & choco feature enable -n allowGlobalConfirmation
            
            # Install software packages with progress tracking
            $packages = @('7zip', 'googlechrome', 'everything', 'windirstat', 'notepadplusplus', 'vlc')
            
            foreach ($package in $packages) {
                Write-Host "Installing $package..." -ForegroundColor Yellow
                try {
                    & choco install $package -y --limit-output
                    Write-Host "$package installed successfully!" -ForegroundColor Green
                } catch {
                    Write-Warning "Failed to install $package`: $($_.Exception.Message)"
                }
            }
        } else {
            throw "Chocolatey installation failed"
        }
        
    } catch {
        Write-Error "Software installation failed: $($_.Exception.Message)"
    }
}

# Enhanced Windows customization function
function Set-WindowsCustomizations {
    Write-Host "Applying comprehensive Windows customizations..." -ForegroundColor Green
    
    try {
        # Dark mode configuration
        Write-Host "Setting Dark Mode..." -ForegroundColor Yellow
        $personalizePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        if (-not (Test-Path $personalizePath)) {
            New-Item -Path $personalizePath -Force | Out-Null
        }
        Set-ItemProperty -Path $personalizePath -Name "AppsUseLightTheme" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $personalizePath -Name "SystemUsesLightTheme" -Value 0 -Type DWord -Force
        
        # Remove shortcut overlay icons
        Write-Host "Removing shortcut overlay icons..." -ForegroundColor Yellow
        $shellIconsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons"
        if (-not (Test-Path $shellIconsPath)) {
            New-Item -Path $shellIconsPath -Force | Out-Null
        }
        
        # Create minimal blank icon
        $blankIconPath = "C:\Windows\System32\blank.ico"
        $blankIconBytes = [byte[]](0,0,1,0,1,0,1,1,0,0,0,0,0,0,40,0,0,0,22,0,0,0,40,0,0,0,1,0,0,0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255,255,255,0)
        [System.IO.File]::WriteAllBytes($blankIconPath, $blankIconBytes)
        Set-ItemProperty -Path $shellIconsPath -Name "29" -Value $blankIconPath -Force
        
        # Taskbar customizations
        Write-Host "Configuring taskbar settings..." -ForegroundColor Yellow
        $explorerAdvancedPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        if (-not (Test-Path $explorerAdvancedPath)) {
            New-Item -Path $explorerAdvancedPath -Force | Out-Null
        }
        
        # Move taskbar to left
        Set-ItemProperty -Path $explorerAdvancedPath -Name "TaskbarAl" -Value 0 -Type DWord -Force
        
        # Hide search bar
        $searchPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
        if (-not (Test-Path $searchPath)) {
            New-Item -Path $searchPath -Force | Out-Null
        }
        Set-ItemProperty -Path $searchPath -Name "SearchboxTaskbarMode" -Value 0 -Type DWord -Force
        
        # Disable task view and widgets
        Set-ItemProperty -Path $explorerAdvancedPath -Name "ShowTaskViewButton" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $explorerAdvancedPath -Name "TaskbarDa" -Value 0 -Type DWord -Force
        
        # Disable snap settings
        Write-Host "Adjusting window snap settings..." -ForegroundColor Yellow
        Set-ItemProperty -Path $explorerAdvancedPath -Name "EnableSnapAssist" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $explorerAdvancedPath -Name "EnableSnapBar" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $explorerAdvancedPath -Name "SnapFill" -Value 0 -Type DWord -Force
        
        # Enable Windows 10 context menu
        Write-Host "Enabling Windows 10 context menu..." -ForegroundColor Yellow
        $contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
        if (-not (Test-Path $contextMenuPath)) {
            New-Item -Path $contextMenuPath -Force | Out-Null
        }
        Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force
        
        Write-Host "Windows customizations applied successfully!" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to apply customizations: $($_.Exception.Message)"
    }
}

# Function to restart Explorer
function Restart-WindowsExplorer {
    Write-Host "Restarting Windows Explorer..." -ForegroundColor Yellow
    
    try {
        Get-Process -Name "explorer" | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Start-Process "explorer.exe"
        Write-Host "Explorer restarted successfully!" -ForegroundColor Green
    } catch {
        Write-Warning "Could not restart Explorer automatically"
    }
}

# Main execution function
function Start-CompleteSetup {
    Write-Host "=== Windows 11 Complete OOBE Bypass & Setup Automation ===" -ForegroundColor Cyan
    Write-Host "This script will:" -ForegroundColor White
    Write-Host "- Bypass all OOBE prompts and requirements" -ForegroundColor White
    Write-Host "- Skip Microsoft account creation" -ForegroundColor White
    Write-Host "- Create admin account automatically" -ForegroundColor White
    Write-Host "- Install software packages via Chocolatey" -ForegroundColor White
    Write-Host "- Apply comprehensive Windows customizations" -ForegroundColor White
    Write-Host ""
    
    # Detect if we're in OOBE
    $isOOBE = (Get-Process -Name "oobe*" -ErrorAction SilentlyContinue) -or 
              (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" -ErrorAction SilentlyContinue)
    
    if ($isOOBE) {
        Write-Host "OOBE detected - applying bypass methods..." -ForegroundColor Cyan
        Invoke-OOBEBypass
        Set-OOBESkipSettings
        
        # Create a scheduled task to continue setup after OOBE
        $scriptPath = $MyInvocation.MyCommand.Path
        if ($scriptPath) {
            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`" -ContinueSetup"
            $trigger = New-ScheduledTaskTrigger -AtLogOn
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName "CompleteWindowsSetup" -Action $action -Trigger $trigger -Principal $principal -Force
            
            Write-Host "Setup will continue automatically after OOBE completion" -ForegroundColor Green
        }
        
        # Restart to apply OOBE bypass
        Write-Host "Restarting to apply OOBE bypass..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        Restart-Computer -Force
        return
    }
    
    # Continue with full setup if not in OOBE or if ContinueSetup parameter is used
    if ($args -contains "-ContinueSetup" -or -not $isOOBE) {
        Write-Host "Continuing with full setup..." -ForegroundColor Cyan
        
        # Remove the scheduled task if it exists
        Unregister-ScheduledTask -TaskName "CompleteWindowsSetup" -Confirm:$false -ErrorAction SilentlyContinue
        
        # Execute all setup functions
        $adminUser = New-AutoAdminAccount
        Install-SoftwarePackages
        Set-WindowsCustomizations
        Restart-WindowsExplorer
        
        Write-Host ""
        Write-Host "=== Setup Complete! ===" -ForegroundColor Green
        Write-Host "All OOBE prompts bypassed and system configured successfully!" -ForegroundColor Green
        
        $reboot = Read-Host "Reboot now to finalize all changes? (Y/N)"
        if ($reboot -eq "Y" -or $reboot -eq "y") {
            Write-Host "Rebooting in 10 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 60
            Restart-Computer -Force
        }
    }
}

# Execute the main function
Start-CompleteSetup @args
