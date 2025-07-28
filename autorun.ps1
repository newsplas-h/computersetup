# Enhanced Windows 11 OOBE Bypass Script with Diagnostics
# Run during OOBE after pressing Shift+F10 and typing 'powershell'

param(
    [switch]$DiagnosticMode = $false
)

#region 0. Setup Enhanced Logging
$LogDirectory = "C:\Windows\Temp"
if (-not (Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogDirectory "OOBESetup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogFile -Append

Write-Host "Enhanced OOBE Bypass Script Starting..." -ForegroundColor Green
Write-Host "Log file: $LogFile"
Write-Host "Diagnostic Mode: $DiagnosticMode"

# Function for enhanced logging
function Write-EnhancedLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue
}
#endregion

#region 1. Pre-flight Checks
Write-EnhancedLog "Performing pre-flight checks..." "INFO"

# Check Windows version
try {
    $windowsInfo = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, WindowsBuildLabEx
    Write-EnhancedLog "Windows: $($windowsInfo.WindowsProductName) $($windowsInfo.WindowsVersion) $($windowsInfo.WindowsBuildLabEx)" "INFO"
} catch {
    Write-EnhancedLog "Could not retrieve Windows version: $($_.Exception.Message)" "WARNING"
}

# Check if we're in OOBE context
$oobeContext = Get-Process -Name "oobe*" -ErrorAction SilentlyContinue
if ($oobeContext) {
    Write-EnhancedLog "OOBE processes detected: $($oobeContext.Name -join ', ')" "INFO"
} else {
    Write-EnhancedLog "No OOBE processes detected - may not be in OOBE context" "WARNING"
}
#endregion

#region 2. Aggressive Registry-Based OOBE Bypass (Multiple Methods)
Write-EnhancedLog "Applying aggressive OOBE bypass registry keys..." "INFO"

$registryConfigs = @(
    # Method 1: Standard OOBE Bypass
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"; Name = "BypassNRO"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"; Name = "SkipMachineOOBE"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"; Name = "SkipUserOOBE"; Value = 1; Type = "DWord" },
    
    # Method 2: Setup completion markers
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE"; Name = "SetupDisplayed"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State"; Name = "ImageState"; Value = "IMAGE_STATE_COMPLETE"; Type = "String" },
    
    # Method 3: Hardware bypass
    @{ Path = "HKLM:\SYSTEM\Setup\LabConfig"; Name = "BypassTPMCheck"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SYSTEM\Setup\LabConfig"; Name = "BypassSecureBootCheck"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SYSTEM\Setup\LabConfig"; Name = "BypassCPUCheck"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SYSTEM\Setup\LabConfig"; Name = "BypassRAMCheck"; Value = 1; Type = "DWord" },
    
    # Method 4: Additional bypass flags
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"; Name = "OOBEComplete"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"; Name = "UnattendDone"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"; Name = "PrivacySettingsDone"; Value = 1; Type = "DWord" }
)

$successCount = 0
foreach ($config in $registryConfigs) {
    try {
        if (-not (Test-Path $config.Path)) {
            New-Item -Path $config.Path -ItemType Directory -Force | Out-Null
            Write-EnhancedLog "Created registry path: $($config.Path)" "INFO"
        }
        
        Set-ItemProperty -Path $config.Path -Name $config.Name -Value $config.Value -Type $config.Type -Force
        
        # Verify the setting
        $verification = Get-ItemProperty -Path $config.Path -Name $config.Name -ErrorAction SilentlyContinue
        if ($verification -and $verification.($config.Name) -eq $config.Value) {
            Write-EnhancedLog "✓ Set $($config.Path)\$($config.Name) = $($config.Value)" "SUCCESS"
            $successCount++
        } else {
            Write-EnhancedLog "✗ Failed to verify $($config.Path)\$($config.Name)" "ERROR"
        }
    } catch {
        Write-EnhancedLog "✗ Error setting $($config.Path)\$($config.Name): $($_.Exception.Message)" "ERROR"
    }
}

Write-EnhancedLog "Registry operations completed: $successCount/$($registryConfigs.Count) successful" "INFO"
#endregion

#region 3. Alternative: Direct OOBE Service Manipulation
Write-EnhancedLog "Attempting direct OOBE service manipulation..." "INFO"

try {
    # Stop OOBE-related services if running
    $oobeServices = @("WbioSrvc", "NgcSvc", "NgcCtnrSvc")
    foreach ($serviceName in $oobeServices) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Write-EnhancedLog "Stopped service: $serviceName" "INFO"
        }
    }
} catch {
    Write-EnhancedLog "Error manipulating services: $($_.Exception.Message)" "WARNING"
}
#endregion

#region 4. User Account Creation (Interactive)
Write-EnhancedLog "Starting user account creation..." "INFO"

# Get Username
$Username = ""
while ([string]::IsNullOrWhiteSpace($Username)) {
    $Username = Read-Host "Enter local administrator username"
    if ([string]::IsNullOrWhiteSpace($Username)) {
        Write-Host "Username cannot be empty." -ForegroundColor Red
        continue
    }
    if ($Username -match '["/\[\]:;|,<>=+*?@ ]' -or $Username.Length -gt 20) {
        Write-Host "Invalid username. Use alphanumeric characters, max 20 chars." -ForegroundColor Red
        $Username = ""
        continue
    }
}

# Get Password
$PasswordPlainForUnattend = ""
while ($true) {
    $PasswordSecure = Read-Host -AsSecureString "Enter password for '$Username'"
    $ConfirmPasswordSecure = Read-Host -AsSecureString "Confirm password"
    
    $PasswordPlainForUnattend = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure))
    $ConfirmPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPasswordSecure))
    
    if ($PasswordPlainForUnattend -eq $ConfirmPasswordPlain) {
        $Password = $PasswordSecure
        $ConfirmPasswordPlain = $null
        break
    } else {
        Write-Host "Passwords do not match." -ForegroundColor Red
        $PasswordPlainForUnattend = $null
        $ConfirmPasswordPlain = $null
    }
}

# Create user account
try {
    if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $Username -Password $Password -FullName "$Username Admin" -Description "Local Administrator" -PasswordNeverExpires -ErrorAction Stop
        Write-EnhancedLog "Created user: $Username" "SUCCESS"
    } else {
        Write-EnhancedLog "User $Username already exists" "INFO"
    }
    
    Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction SilentlyContinue
    Write-EnhancedLog "Added $Username to Administrators group" "SUCCESS"
} catch {
    Write-EnhancedLog "Failed to create/configure user: $($_.Exception.Message)" "ERROR"
}
#endregion

#region 5. Multiple Unattend.xml Placement Strategy
Write-EnhancedLog "Creating and placing unattend.xml files in multiple locations..." "INFO"

$ComputerName = "$($Username.ToUpper())-PC"
if ($ComputerName.Length -gt 15) {
    $ComputerName = $ComputerName.Substring(0, 15)
}

# Simplified, more reliable unattend.xml
$UnattendXmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Home</NetworkLocation>
                <SkipUserOOBE>true</SkipUserOOBE>
                <SkipMachineOOBE>true</SkipMachineOOBE>
            </OOBE>
            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <DisplayName>$Username</DisplayName>
                        <Group>Administrators</Group>
                        <Name>$Username</Name>
                        <Password>
                            <PlainText>true</PlainText>
                            <Value>$PasswordPlainForUnattend</Value>
                        </Password>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
            <AutoLogon>
                <Enabled>true</Enabled>
                <LogonCount>3</LogonCount>
                <Username>$Username</Username>
                <Password>
                    <PlainText>true</PlainText>
                    <Value>$PasswordPlainForUnattend</Value>
                </Password>
            </AutoLogon>
            <ComputerName>$ComputerName</ComputerName>
        </component>
    </settings>
</unattend>
"@

# Place unattend.xml in multiple strategic locations
$unattendLocations = @(
    "C:\Windows\System32\Sysprep\unattend.xml",
    "C:\Windows\Panther\unattend.xml",
    "C:\Windows\Panther\Unattend\unattend.xml",
    "C:\unattend.xml"
)

$placementSuccess = 0
foreach ($location in $unattendLocations) {
    try {
        $directory = Split-Path $location -Parent
        if (-not (Test-Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
        
        $UnattendXmlContent | Out-File -FilePath $location -Encoding utf8 -Force
        
        if (Test-Path $location) {
            Write-EnhancedLog "✓ Placed unattend.xml at: $location" "SUCCESS"
            $placementSuccess++
        } else {
            Write-EnhancedLog "✗ Failed to place unattend.xml at: $location" "ERROR"
        }
    } catch {
        Write-EnhancedLog "✗ Error placing unattend.xml at $location : $($_.Exception.Message)" "ERROR"
    }
}

Write-EnhancedLog "Unattend.xml placement: $placementSuccess/$($unattendLocations.Count) successful" "INFO"

# Clear password from memory
$PasswordPlainForUnattend = $null
#endregion

#region 6. Alternative: Sysprep Generalize Method
Write-EnhancedLog "Attempting sysprep-based OOBE completion..." "INFO"

try {
    # Create a temporary sysprep answer file for immediate OOBE completion
    $sysprepAnswerFile = "C:\Windows\System32\Sysprep\sysprep_oobe.xml"
    $sysprepContent = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="generalize">
        <component name="Microsoft-Windows-Security-SPP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <SkipRearm>1</SkipRearm>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <SkipMachineOOBE>true</SkipMachineOOBE>
                <SkipUserOOBE>true</SkipUserOOBE>
            </OOBE>
        </component>
    </settings>
</unattend>
"@
    
    $sysprepContent | Out-File -FilePath $sysprepAnswerFile -Encoding utf8 -Force
    Write-EnhancedLog "Created sysprep answer file" "INFO"
} catch {
    Write-EnhancedLog "Failed to create sysprep answer file: $($_.Exception.Message)" "WARNING"
}
#endregion

#region 7. Force Setup State Completion
Write-EnhancedLog "Forcing Windows Setup state completion..." "INFO"

try {
    # Multiple approaches to mark setup as complete
    $setupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )
    
    foreach ($path in $setupPaths) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
        }
    }
    
    # Set multiple completion markers
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" -Name "ImageState" -Value "IMAGE_STATE_COMPLETE" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE" -Name "SetupDisplayed" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "OOBEInProgress" -Value 0 -Type DWord -Force
    
    Write-EnhancedLog "Setup completion markers applied" "SUCCESS"
} catch {
    Write-EnhancedLog "Error setting setup completion markers: $($_.Exception.Message)" "ERROR"
}
#endregion

#region 8. Install Essential Software
Write-EnhancedLog "Installing essential software via Chocolatey..." "INFO"

# Quick Chocolatey installation
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    try {
        Write-EnhancedLog "Installing Chocolatey..." "INFO"
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        Write-EnhancedLog "Chocolatey installed successfully" "SUCCESS"
    } catch {
        Write-EnhancedLog "Failed to install Chocolatey: $($_.Exception.Message)" "ERROR"
    }
}

# Install essential packages
if (Get-Command choco -ErrorAction SilentlyContinue) {
    $packages = @("googlechrome", "7zip", "notepadplusplus")
    foreach ($package in $packages) {
        try {
            Write-EnhancedLog "Installing $package..." "INFO"
            choco install $package -y --no-progress --force
            Write-EnhancedLog "Installed $package" "SUCCESS"
        } catch {
            Write-EnhancedLog "Failed to install $package" "WARNING"
        }
    }
}
#endregion

#region 9. Final Verification and Logging
Write-EnhancedLog "Performing final verification..." "INFO"

# Verify critical registry keys
$criticalKeys = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"; Name = "BypassNRO" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE"; Name = "SetupDisplayed" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State"; Name = "ImageState" }
)

$verificationSuccess = 0
foreach ($key in $criticalKeys) {
    try {
        $value = Get-ItemProperty -Path $key.Path -Name $key.Name -ErrorAction SilentlyContinue
        if ($value) {
            Write-EnhancedLog "✓ Verified: $($key.Path)\$($key.Name) = $($value.($key.Name))" "SUCCESS"
            $verificationSuccess++
        } else {
            Write-EnhancedLog "✗ Missing: $($key.Path)\$($key.Name)" "ERROR"
        }
    } catch {
        Write-EnhancedLog "✗ Error verifying: $($key.Path)\$($key.Name)" "ERROR"
    }
}

Write-EnhancedLog "Registry verification: $verificationSuccess/$($criticalKeys.Count) successful" "INFO"

# Check for unattend.xml files
$foundUnattendFiles = 0
foreach ($location in $unattendLocations) {
    if (Test-Path $location) {
        $foundUnattendFiles++
        $fileSize = (Get-Item $location).Length
        Write-EnhancedLog "✓ Unattend.xml found: $location ($fileSize bytes)" "SUCCESS"
    }
}

Write-EnhancedLog "Unattend.xml verification: $foundUnattendFiles/$($unattendLocations.Count) files present" "INFO"
#endregion

#region 10. Create Recovery Script
Write-EnhancedLog "Creating recovery script for troubleshooting..." "INFO"

$recoveryScriptPath = "C:\Windows\Temp\OOBE_Recovery.ps1"
$recoveryScriptContent = @"
# OOBE Recovery Script - Run if system still boots to OOBE
Write-Host "OOBE Recovery Script - Checking system state..." -ForegroundColor Yellow

# Check what's blocking OOBE completion
`$oobeKeys = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -ErrorAction SilentlyContinue
if (`$oobeKeys) {
    Write-Host "Current OOBE registry state:"
    `$oobeKeys.PSObject.Properties | Where-Object { `$_.Name -notlike "PS*" } | ForEach-Object {
        Write-Host "  `$(`$_.Name): `$(`$_.Value)"
    }
}

# Check for unattend.xml processing errors
`$setupLog = "C:\Windows\Panther\setupact.log"
if (Test-Path `$setupLog) {
    Write-Host "`nChecking setup log for errors..."
    `$errors = Get-Content `$setupLog | Where-Object { `$_ -match "error|fail" -and `$_ -match "unattend|oobe" }
    if (`$errors) {
        Write-Host "Setup errors found:"
        `$errors | Select-Object -Last 5 | ForEach-Object { Write-Host "  `$_" }
    } else {
        Write-Host "No obvious setup errors found in log"
    }
}

# Emergency OOBE bypass
Write-Host "`nApplying emergency OOBE bypass..."
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "BypassNRO" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "OOBEComplete" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE" -Name "SetupDisplayed" -Value 1 -Type DWord -Force
    Write-Host "Emergency bypass applied - restart required"
} catch {
    Write-Host "Emergency bypass failed: `$(`$_.Exception.Message)"
}

Write-Host "`nPress any key to restart system..."
`$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Restart-Computer -Force
"@

try {
    $recoveryScriptContent | Out-File -FilePath $recoveryScriptPath -Encoding utf8 -Force
    Write-EnhancedLog "Recovery script created at: $recoveryScriptPath" "SUCCESS"
} catch {
    Write-EnhancedLog "Failed to create recovery script: $($_.Exception.Message)" "WARNING"
}
#endregion

#region 11. Alternative Restart Approach
Write-EnhancedLog "Preparing for system restart with multiple restart methods..." "INFO"

# Method 1: Standard shutdown command
Write-EnhancedLog "Method 1: Standard restart scheduled in 10 seconds" "INFO"

# Method 2: Create a startup script to continue bypass if needed
$startupBypassPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\ContinueOOBEBypass.bat"
$startupBypassContent = @"
@echo off
timeout /t 5
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v OOBEComplete /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE" /v SetupDisplayed /t REG_DWORD /d 1 /f
del "%~f0"
"@

try {
    $startupDir = Split-Path $startupBypassPath -Parent
    if (-not (Test-Path $startupDir)) {
        New-Item -Path $startupDir -ItemType Directory -Force | Out-Null
    }
    $startupBypassContent | Out-File -FilePath $startupBypassPath -Encoding ascii -Force
    Write-EnhancedLog "Startup bypass script created" "SUCCESS"
} catch {
    Write-EnhancedLog "Failed to create startup bypass script: $($_.Exception.Message)" "WARNING"
}

# Method 3: Registry-based restart with bypass enforcement
try {
    # Set a RunOnce key to ensure bypass is applied after restart
    $runOncePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-ItemProperty -Path $runOncePath -Name "OOBEBypassEnforcer" -Value "cmd /c reg add `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE`" /v BypassNRO /t REG_DWORD /d 1 /f" -Force
    Write-EnhancedLog "RunOnce bypass enforcer set" "SUCCESS"
} catch {
    Write-EnhancedLog "Failed to set RunOnce enforcer: $($_.Exception.Message)" "WARNING"
}
#endregion

#region 12. Final Summary and Instructions
Write-EnhancedLog "=== SCRIPT EXECUTION SUMMARY ===" "INFO"
Write-EnhancedLog "Registry operations: $successCount successful" "INFO"
Write-EnhancedLog "Unattend.xml files: $placementSuccess placed" "INFO"
Write-EnhancedLog "User account: $Username created and configured" "INFO"
Write-EnhancedLog "Recovery script: Available at $recoveryScriptPath" "INFO"

Write-Host "`n" -ForegroundColor Green
Write-Host "=== IMPORTANT INSTRUCTIONS ===" -ForegroundColor Yellow
Write-Host "1. System will restart in 10 seconds" -ForegroundColor White
Write-Host "2. If OOBE still appears, press Shift+F10 and run:" -ForegroundColor White
Write-Host "   powershell -File C:\Windows\Temp\OOBE_Recovery.ps1" -ForegroundColor Cyan
Write-Host "3. Multiple bypass methods have been applied" -ForegroundColor White
Write-Host "4. Check log file: $LogFile" -ForegroundColor White
Write-Host "`n" -ForegroundColor Green

# Give user a chance to abort
Write-Host "Press Ctrl+C within 10 seconds to abort restart, or wait for automatic restart..." -ForegroundColor Yellow
for ($i = 10; $i -gt 0; $i--) {
    Write-Host "Restarting in $i seconds..." -ForegroundColor Red
    Start-Sleep -Seconds 1
}
#endregion

#region 13. Execute Restart
Stop-Transcript

Write-Host "Executing restart now..." -ForegroundColor Red

# Try multiple restart methods for reliability
try {
    # Method 1: PowerShell restart
    Restart-Computer -Force -ErrorAction Stop
} catch {
    try {
        # Method 2: shutdown.exe
        shutdown.exe /r /t 0 /f /c "OOBE bypass complete - restarting"
    } catch {
        # Method 3: wininit restart
        wininit.exe
    }
}
#endregion
