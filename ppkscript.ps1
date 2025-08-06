powershell.exe -Command "& { 
    $url = 'https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/newscript.ps1';
    $scriptPath = '$env:TEMP\newscript.ps1';
    (New-Object Net.WebClient).DownloadFile($url, $scriptPath);
    Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File ""$env:TEMP\newscript.ps1""' -Verb RunAs
}"
