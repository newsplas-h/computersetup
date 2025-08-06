powershell.exe -Command "& {
    $logPath = 'C:\Windows\Temp\ProvisioningLog.txt'
    $url = 'https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/newscript.ps1'
    
    # Use .NET method for reliable temp path
    $tempDir = [System.IO.Path]::GetTempPath()
    $scriptPath = [System.IO.Path]::Combine($tempDir, 'newscript.ps1')

    # Start logging
    \"=== Provisioning Started: $(Get-Date) ===\" | Out-File $logPath -Append
    \"Temp directory: $tempDir\" | Out-File $logPath -Append
    \"Script path: $scriptPath\" | Out-File $logPath -Append

    try {
        # Download script with retry logic
        $retryCount = 0
        $maxRetries = 3
        $downloaded = $false
        
        while (-not $downloaded -and $retryCount -lt $maxRetries) {
            try {
                \"Download attempt $($retryCount + 1) of $maxRetries\" | Out-File $logPath -Append
                (New-Object System.Net.WebClient).DownloadFile($url, $scriptPath)
                $downloaded = $true
            }
            catch {
                $retryCount++
                \"Download failed: $($_.Exception.Message)\" | Out-File $logPath -Append
                if ($retryCount -lt $maxRetries) {
                    Start-Sleep -Seconds 10
                }
            }
        }

        if (-not (Test-Path -Path $scriptPath -PathType Leaf)) {
            throw \"Script download failed after $maxRetries attempts\"
        }

        \"SUCCESS: Script downloaded to $scriptPath\" | Out-File $logPath -Append
        \"File verified: $(Test-Path $scriptPath)\" | Out-File $logPath -Append
        \"File size: $((Get-Item $scriptPath).Length) bytes\" | Out-File $logPath -Append

        # Execute script as admin
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'powershell.exe'
        $psi.Arguments = \"-ExecutionPolicy Bypass -File `\"$scriptPath`\"\"
        $psi.Verb = 'RunAs'
        $psi.UseShellExecute = $true  # Required for elevation
        $psi.WindowStyle = 'Hidden'

        \"Starting script with elevated privileges...\" | Out-File $logPath -Append
        $process = [System.Diagnostics.Process]::Start($psi)
        
        \"SUCCESS: Script launched with admin rights (PID: $($process.Id))\" | Out-File $logPath -Append
        
        # Wait for completion with timeout
        \"Waiting for script completion (max 10 minutes)...\" | Out-File $logPath -Append
        $process.WaitForExit(600000)  # 10-minute timeout
        
        \"Script exited with code: $($process.ExitCode)\" | Out-File $logPath -Append
        exit $process.ExitCode
    }
    catch {
        $errorMsg = $_.Exception.Message
        \"FATAL ERROR: $errorMsg\" | Out-File $logPath -Append
        \"Error details: $($_.ScriptStackTrace)\" | Out-File $logPath -Append
        exit 1
    }
    finally {
        \"=== Provisioning Completed: $(Get-Date) ===\" | Out-File $logPath -Append
    }
}"
