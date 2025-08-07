# --- PHASE 1: USER-SPECIFIC PREFERENCES (HKCU) ---
Write-Host "Applying user-specific preferences..." -ForegroundColor Cyan

# Set Dark Mode
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force

# Disable Snap Assist & Configure Taskbar
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapAssistFlyout" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force

# Classic Context Menu
$contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (-not (Test-Path $contextMenuPath)) { New-Item -Path $contextMenuPath -Force | Out-Null }
Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Force

# Unpin Default Taskbar Icons
(Get-Content "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*.lnk" -ErrorAction SilentlyContinue) | ForEach-Object {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($_.PSPath)
    if ($shortcut.TargetPath -like "*Microsoft Edge*" -or $shortcut.TargetPath -like "*ms-windows-store*") {
        Remove-Item $_.PSPath -Force
    }
}

# --- PHASE 2: RESTART EXPLORER & CLEANUP ---
Write-Host "Restarting Explorer to apply UI changes..."
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Process explorer.exe

# Create desktop notice
$desktopPath = [Environment]::GetFolderPath("Desktop")
$noticePath = Join-Path -Path $desktopPath -ChildPath "Setup Complete.txt"
"Setup complete! Your apps are installing in the background." | Out-File -FilePath $noticePath -Encoding ASCII
Start-Process notepad.exe $noticePath

# --- SELF-CLEANUP ---
Write-Host "User setup complete. Cleaning up user task..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName "Run User Setup" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Cleanup complete."
