$TempPath = "$env:windir\Temp\Provisioning"

# Create temp directory
New-Item -Path $TempPath -ItemType Directory -Force | Out-Null

Invoke-WebRequest -Uri "https://github.com/newsplas-h/computersetup/raw/refs/heads/main/default.ppkg" -OutFile "$TempPath\setup.ppkg" -UseBasicParsing
#Invoke-WebRequest -Uri "https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/autorun.ps1" -OutFile "$TempPath\install.ps1" -UseBasicParsing

# Apply ppkg
Install-ProvisioningPackage -PackagePath "$TempPath\setup.ppkg" -ForceInstall

# Run cleanup
Remove-Item -Path $TempPath -Recurse -Force
