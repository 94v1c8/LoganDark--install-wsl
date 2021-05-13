@echo off
powershell.exe -ExecutionPolicy ByPass "Import-Module %~dp0install-wsl.psm1; Install-WSLInteractive; pause"