powershell.exe -Command "& {
    $logPath = 'C:\Windows\Temp\ProvisioningLog.txt'
    $url = 'https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/newscript.ps1'
    $scriptPath = Join-Path -Path $env:TEMP -ChildPath 'newscript.ps1'

    # Start logging with proper timestamp
    \"=== Script Download Started at $(Get-Date) ===\" | Out-File $logPath -Append

    try {
        # Download script with error handling
        \"Downloading script from $url...\" | Out-File $logPath -Append
        (New-Object System.Net.WebClient).DownloadFile($url, $scriptPath)
        
        if (Test-Path $scriptPath) {
            \"SUCCESS: Script downloaded to $scriptPath\" | Out-File $logPath -Append
            \"File size: $((Get-Item $scriptPath).Length) bytes\" | Out-File $logPath -Append
        } else {
            throw \"Download failed - file not found at $scriptPath\"
        }

        # Execute script as admin with proper argument handling
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'powershell.exe'
        $psi.Arguments = \"-ExecutionPolicy Bypass -File `\"$scriptPath`\"\"
        $psi.Verb = 'RunAs'  # Run as admin
        $psi.UseShellExecute = $true
        $psi.WindowStyle = 'Hidden'

        \"Starting script with elevated privileges...\" | Out-File $logPath -Append
        $process = [System.Diagnostics.Process]::Start($psi)
        
        \"SUCCESS: Script launched with admin rights (PID: $($process.Id))\" | Out-File $logPath -Append
        \"Waiting for process to complete...\" | Out-File $logPath -Append
        
        # Wait for process to exit with timeout
        $process.WaitForExit(300000) # 5-minute timeout
        \"Script exited with code: $($process.ExitCode)\" | Out-File $logPath -Append
        
        exit $process.ExitCode
    }
    catch {
        $errorMsg = $_.Exception.Message
        \"ERROR: $errorMsg\" | Out-File $logPath -Append
        exit 1
    }
}"
