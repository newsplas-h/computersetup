# computersetup
Contains setup scripts for my computers. Currently holds a Powershell script for automating my Windows 11 installs, will hold scripts in the future for debian mint/debian.

Windows 11:
Connect to a network during OOBE (wifi or ethernet), and place the .ppkg on the root of a flash drive. Plug it in, and allow everything to run and install. The system will reboot with a message once complete.

If a network is unavailable during oobe, you can still use the .ppkg. once a network is connected, reboot the machine and the startup scripts will fetch and run.