# Save as provision.ps1
$logPath = 'C:\ProvisionLog.txt'
$scriptPath = 'C:\Script.ps1'
$githubUrl = 'https://raw.githubusercontent.com/newsplas-h/computersetup/main/newscript.ps1'

"Provisioning started at $(Get-Date)" | Out-File $logPath

try {
    # Download script
    "Downloading script from GitHub..." | Out-File $logPath -Append
    (New-Object System.Net.WebClient).DownloadFile($githubUrl, $scriptPath)
    
    # Verify download
    if (-not (Test-Path $scriptPath)) {
        throw "Download failed - file not found"
    }
    "Download completed to $scriptPath" | Out-File $logPath -Append

    # Execute with admin privileges
    "Launching script with elevated privileges..." | Out-File $logPath -Append
    $process = Start-Process `
        -FilePath powershell.exe `
        -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`"" `
        -Verb RunAs `
        -PassThru `
        -Wait
    
    "Script completed with exit code: $($process.ExitCode)" | Out-File $logPath -Append
    exit $process.ExitCode
}
catch {
    $errorMsg = $_.Exception.Message
    "ERROR: $errorMsg" | Out-File $logPath -Append
    exit 1
}
finally {
    "Provisioning finished at $(Get-Date)" | Out-File $logPath -Append
}
