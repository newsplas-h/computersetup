powershell.exe -Command {
    # Set paths
    $log = 'C:\Windows\Temp\ProvisioningLog.txt'
    $url = 'https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/newscript.ps1'
    $target = "$env:TEMP\newscript.ps1"
    
    # Basic logging function
    function Log($msg) {
        "$(Get-Date -Format 'HH:mm:ss') - $msg" | Out-File $log -Append
    }
    
    # Start log
    "==== PROVISIONING STARTED ====" | Out-File $log
    Log "Using target path: $target"
    
    try {
        # Download file
        Log "Downloading script from GitHub"
        (New-Object System.Net.WebClient).DownloadFile($url, $target)
        Log "Download completed"
        
        # Run script as admin
        Log "Starting main script with admin rights"
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$target`"" -Verb RunAs -Wait
        Log "Main script completed"
    }
    catch {
        Log "ERROR: $($_.Exception.Message)"
        exit 1
    }
    finally {
        Log "==== PROVISIONING FINISHED ===="
    }
}
