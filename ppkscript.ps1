# Save as FirstLogonScript.ps1
# This script will run at first user logon after provisioning package installation

$logPath = 'C:\Windows\Temp\ProvisionLog.txt'
$scriptPath = 'C:\Windows\Temp\DownloadedScript.ps1'
$githubUrl = 'https://raw.githubusercontent.com/newsplas-h/computersetup/main/newscript.ps1'
$registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
$taskName = 'FirstLogonProvisioning'

# Function to write to log with timestamp
function Write-LogMessage {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] $Message" | Out-File $logPath -Append -Encoding UTF8
}

Write-LogMessage "First logon provisioning started"

try {
    # Check if running with admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-LogMessage "Script not running as administrator, attempting to elevate..."
        
        # Create a scheduled task to run with highest privileges
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($MyInvocation.MyCommand.Path)`""
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
        Write-LogMessage "Scheduled task created for elevation"
        
        # Clean up RunOnce entry since we're delegating to scheduled task
        if (Get-ItemProperty -Path $registryPath -Name "FirstLogonScript" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $registryPath -Name "FirstLogonScript" -Force
            Write-LogMessage "RunOnce registry entry cleaned up"
        }
        
        exit 0
    }
    
    Write-LogMessage "Running with administrative privileges"
    
    # Download script from GitHub
    Write-LogMessage "Downloading script from: $githubUrl"
    
    # Use Invoke-WebRequest for better error handling
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell")
        $webClient.DownloadFile($githubUrl, $scriptPath)
        
        # Verify download
        if (-not (Test-Path $scriptPath)) {
            throw "Download failed - file not found at $scriptPath"
        }
        
        $fileSize = (Get-Item $scriptPath).Length
        Write-LogMessage "Download completed successfully. File size: $fileSize bytes"
    }
    catch {
        Write-LogMessage "Download failed: $($_.Exception.Message)"
        throw
    }
    
    # Execute the downloaded script
    Write-LogMessage "Executing downloaded script..."
    
    try {
        # Run the script and capture output
        $output = & powershell.exe -ExecutionPolicy Bypass -File "$scriptPath" 2>&1
        $exitCode = $LASTEXITCODE
        
        Write-LogMessage "Script execution completed with exit code: $exitCode"
        Write-LogMessage "Script output: $output"
        
        if ($exitCode -ne 0 -and $null -ne $exitCode) {
            Write-LogMessage "Warning: Script exited with non-zero code: $exitCode"
        }
    }
    catch {
        Write-LogMessage "Error executing script: $($_.Exception.Message)"
        throw
    }
    
    # Clean up downloaded script
    if (Test-Path $scriptPath) {
        Remove-Item $scriptPath -Force
        Write-LogMessage "Cleaned up downloaded script file"
    }
    
    Write-LogMessage "Provisioning completed successfully"
    
}
catch {
    $errorMsg = $_.Exception.Message
    Write-LogMessage "ERROR: $errorMsg"
    Write-LogMessage "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}
finally {
    # Clean up scheduled task if it exists
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-LogMessage "Cleaned up scheduled task"
    }
    
    Write-LogMessage "First logon provisioning finished"
}
