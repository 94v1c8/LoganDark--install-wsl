@echo off
powershell.exe -ExecutionPolicy ByPass "Import-Module %~dp0installWSL-2.psm1; Install-WSLInteractive; pause"