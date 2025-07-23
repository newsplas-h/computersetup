# computersetup
Contains setup scripts for my computers. Currently holds a Powershell script for automating my Windows 11 installs, will hold scripts in the future for debian mint/debian.

How to use on Win 11 OOBE:
Shift + F10
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/newsplas-h/computersetup/refs/heads/main/autorun.ps1" -UseBasicParsing).Content
Follow prompts for password setup
