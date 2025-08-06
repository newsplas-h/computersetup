powershell.exe -Command "& {
    $logPath = 'C:\Windows\Temp\ProvisioningLog.txt'
    $url = 'https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/newscript.ps1'
    $scriptPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'newscript.ps1')
    
    # Start logging
    '--- Provisioning Started ---' | Out-File $logPath
    "Timestamp: $(Get-Date)" | Out-File $logPath -Append
    
    try {
        # Download script
        "Downloading script from GitHub..." | Out-File $logPath -Append
        (New-Object System.Net.WebClient).DownloadFile($url, $scriptPath)
        "Download completed to: $scriptPath" | Out-File $logPath -Append
        
        # Execute script as admin
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'powershell.exe'
        $psi.Arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`""
        $psi.Verb = 'RunAs'
        $psi.UseShellExecute = $true
        
        "Starting main script..." | Out-File $logPath -Append
        $process = [System.Diagnostics.Process]::Start($psi)
        "Main script started successfully" | Out-File $logPath -Append
        
        # Wait for completion
        $process.WaitForExit(600000)  # 10-minute timeout
        "Main script completed with exit code: $($process.ExitCode)" | Out-File $logPath -Append
        exit $process.ExitCode
    }
    catch {
        "ERROR: $($_.Exception.Message)" | Out-File $logPath -Append
        exit 1
    }
    finally {
        "--- Provisioning Finished ---" | Out-File $logPath -Append
    }
}"
