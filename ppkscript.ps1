powershell.exe -Command "& {
    $logPath = 'C:\Windows\Temp\ProvisioningLog.txt'
    $url = 'https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/newscript.ps1'
    $scriptPath = '$env:TEMP\newscript.ps1'

    # Start logging
    '=== Script Download Started at $(Get-Date) ===' | Out-File $logPath -Append

    try {
        # Download script
        (New-Object Net.WebClient).DownloadFile($url, $scriptPath)
        'Success: Script downloaded to $scriptPath' | Out-File $logPath -Append

        # Execute script as admin
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'powershell.exe'
        $psi.Arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`""
        $psi.Verb = 'RunAs'  # Run as admin
        $psi.WindowStyle = 'Hidden'  # Optional: Hide the window

        $process = [System.Diagnostics.Process]::Start($psi)
        'Success: Script launched with admin rights (PID: $($process.Id))' | Out-File $logPath -Append
    }
    catch {
        "ERROR: $_" | Out-File $logPath -Append
        exit 1
    }
}"
