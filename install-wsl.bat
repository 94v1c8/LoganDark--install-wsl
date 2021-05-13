@echo off

if not "%1"=="" (
	if "%1"=="--help" (
		goto help
	)

	if "%1"=="--install" (
		if not "%2"=="" (
			if "%3"=="" (
				set extra=" -InformationAction Continue"
			) else (
				if "%3"=="--quiet" (
					set extra=" -InformationAction SilentlyContinue"
				) else (
					goto help
				)
			)
			
			if "%2"=="wslubuntu2004" ( goto :install )
			if "%2"=="wslubuntu2004arm" ( goto :install )
			if "%2"=="wsl-ubuntu-1804" ( goto :install )
			if "%2"=="wsl-ubuntu-1804-arm" ( goto :install )
			if "%2"=="wsl-ubuntu-1604" ( goto :install )
			if "%2"=="wsl-debian-gnulinux" ( goto :install )
			if "%2"=="wsl-kali-linux-new" ( goto :install )
			if "%2"=="wsl-opensuse-42" ( goto :install )
			if "%2"=="wsl-sles-12" ( goto :install )
		)
		
		goto :help
	)

	if "%1"=="--cancel" (
		if "%2"=="" (
			set extra=" -InformationAction Continue"
		) else (
			if "%2"=="--quiet" (
				set extra=" -InformationAction SilentlyContinue"
			) else (
				goto help
			)
		)
		
		goto :cancel
	)

	if "%1"=="--windows-terminal" (
		goto windowsterminal
	)
	
	goto help
)

goto default

:help
echo A wrapper script to help run the WSL installation with minimal effort.
echo.
echo Usage: install-wsl.bat --help
echo     Displays all possible invocations of this script and brief descriptions of
echo     each.
echo.
echo Usage: install-wsl.bat --install ^<distro^> [--quiet]
echo     Begins installing the given distribution. If the --quiet flag is given then
echo     no output will be printed. If the Windows Subsystem for Linux is not
echo     installed, it will be enabled and a startup item will be created to resume
echo     the installation on reboot.
echo.
echo     Valid distributions:
echo       wslubuntu2004, wslubuntu2004arm, wsl-ubuntu-1804, wsl-ubuntu-1804-arm,
echo       wsl-ubuntu-1604, wsl-debian-gnulinux, wsl-kali-linux-new, wsl-opensuse-42,
echo       wsl-sles-12
echo.
echo Usage: install-wsl.bat --cancel [--quiet]
echo     Cancels all pending installs. If the --quiet flag is given then no output
echo     will be printed.
echo.
echo Usage: install-wsl.bat --windows-terminal
echo     Installs Windows Terminal using scoop.
goto end

:install
powershell.exe -ExecutionPolicy ByPass "Import-Module %~dp0install-wsl.psm1; $a = Install-WSL -LinuxDistribution %2%extra%"
goto end

:cancel
powershell.exe -ExecutionPolicy ByPass "Import-Module %~dp0install-wsl.psm1; $a = Install-WSL -Cancel%extra%"
goto end

:windowsterminal
powershell.exe -ExecutionPolicy ByPass "Import-Module %~dp0install-wsl.psm1; $a = Install-WSL -InstallWindowsTerminal%extra%"
goto end

:default
powershell.exe -ExecutionPolicy ByPass "Import-Module %~dp0install-wsl.psm1; $a = Install-WSLInteractive"

:end