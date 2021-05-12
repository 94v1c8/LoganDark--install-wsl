@echo off
powershell.exe -ExecutionPolicy ByPass "Import-Module %~dp0InstallWSL.psm1; Install-WSLInteractive; pause"