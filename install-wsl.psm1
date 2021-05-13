# https://stackoverflow.com/a/34559554/
function New-TemporaryDirectory {
	$parent = [System.IO.Path]::GetTempPath()
	$name = [System.IO.Path]::GetRandomFileName()
	New-Item -ItemType Directory -Path (Join-Path $parent $name)
}

Workflow Install-WSL {
	[CmdletBinding(DefaultParameterSetName='Installation')]
	param(
		[Parameter(Mandatory=$True,ParameterSetName='Installation',Position=0)]
		[ValidateSet(
			'wslubuntu2004',
			'wslubuntu2004arm',
			'wsl-ubuntu-1804',
			'wsl-ubuntu-1804-arm',
			'wsl-ubuntu-1604',
			'wsl-debian-gnulinux',
			'wsl-kali-linux-new',
			'wsl-opensuse-42',
			'wsl-sles-12'
		)]
		[string]$LinuxDistribution,
		
		[Parameter(Mandatory=$False,ParameterSetName='Installation')]
		[switch]$FeatureInstalled,
		
		[Parameter(Mandatory=$False,ParameterSetName='Installation')]
		[switch]$OmitWindowsTerminal,
		
		[Parameter(Mandatory=$True,ParameterSetName='Cancelation')]
		[switch]$Cancel,
		
		[Parameter(Mandatory=$False,ParameterSetName='WindowsTerminal')]
		[switch]$InstallWindowsTerminal
	)
	
	# The task scheduler is unreliable in AME
	$ShortcutPath = Join-Path $env:AppData 'Microsoft\Windows\Start Menu\Programs\Startup\Install WSL.lnk'
	
	if ($Cancel) {
		$Removed = Remove-Item -LiteralPath $ShortcutPath -ErrorAction SilentlyContinue
		$Removed = Get-Job -Command 'Install-WSL' | Where-Object {$_.State -eq 'Suspended'} | Remove-Job -Force
		Write-Information 'All pending WSL installations have been canceled.'
		return 'done'
	} elseif ($InstallWindowsTerminal) {
		InlineScript {
			$ExecutionPolicy = Get-ExecutionPolicy -Scope Process
			Set-ExecutionPolicy RemoteSigned -Scope Process
			Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://get.scoop.sh')
			Set-ExecutionPolicy $ExecutionPolicy -Scope Process
			scoop bucket add extras
			scoop install windows-terminal
		}
		
		return 'done'
	}
	
	# establish directory for WSL installations
	$AppDataFolder = Join-Path $env:LocalAppData 'WSL'
	$DistrosFolder = New-Item -ItemType Directory -Force -Path $AppDataFolder
	$DistroFolder = Join-Path $DistrosFolder $LinuxDistribution
	
	if (Test-Path -Path $DistroFolder -PathType Container) {
		return Write-Error 'Cannot install a distro twice! This will waste your internet data. Uninstall the existing version first.' -Category ResourceExists
	}
	
	Write-Information 'Creating startup item'
	
	InlineScript {
		$shell = New-Object -ComObject ('WScript.Shell')
		$shortcut = $shell.CreateShortcut($Using:ShortcutPath)
		$shortcut.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
		$shortcut.Arguments = "-WindowStyle Normal -NoLogo -NoProfile -Command `"& { Write-Output \`"Resuming installation...\`"; Get-Job -Command `'Install-WSL`' | Resume-Job | Receive-Job -Wait -InformationAction Continue; pause; exit }`""
		$shortcut.Save()
	}
	
	Write-Information ''
	Write-Information 'There will be a "Windows PowerShell" shortcut in your startup items until this'
	Write-Information 'script is complete. Please do not be alarmed, it will remove itself once the'
	Write-Information 'installation is complete.'
	Write-Information ''
	Write-Information 'Ensuring required features are enabled...'
	
	# using a named pipe to communicate between elevated process and not elevated one
	
	if ($FeatureInstalled) {
		$RestartNeeded = $False
	} else {
		try {
			# For various reasons this needs to be duplicated twice.
			# I hate it as much as you, but for some reason I can't put it in a function
			# It just refuses to work when I try to call it in the loop below
			$RestartNeeded = InlineScript {
				$PipeName = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 12 |%{[char]$_})
				
				$Enabled = Start-Process powershell -ArgumentList "`
				`$Enabled = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -WarningAction SilentlyContinue`
				`$RestartNeeded = `$Enabled.RestartNeeded`
				`
				`$pipe = New-Object System.IO.Pipes.NamedPipeServerStream `'$PipeName`',`'Out`'`
				`$pipe.WaitForConnection()`
				`$sw = New-Object System.IO.StreamWriter `$pipe`
				`$sw.AutoFlush = `$True`
				`$sw.WriteLine([string]`$RestartNeeded)`
				`$sw.Dispose()`
				`$pipe.Dispose()`
				" -Verb RunAs -WindowStyle Hidden -ErrorAction Stop
				
				$pipe = New-Object System.IO.Pipes.NamedPipeClientStream '.',$Using:PipeName,'In'
				$pipe.Connect()
				$sr = New-Object System.IO.StreamReader $pipe
				$data = $sr.ReadLine()
				$sr.Dispose()
				$pipe.Dispose()
				
				$data -eq [string]$True
			} -ErrorAction Stop
		} catch {
			return Write-Error 'Please accept the UAC prompt so that the WSL feature can be installed, or specify the -FeatureInstalled flag to skip'
		}
	}
	
	if ($RestartNeeded) {
		# TODO detect if we're already waiting for a reboot specifically
		# Maybe this can be done by checking for the scheduled task instead?
		# This feels messy which is why it's disabled, and it would also detect
		# the currently running task
		
		# Future Logan from the future!: I think the shortcut is more easily
		# detected, but there are reasons you might want to run this more than
		# once in a row. For example if you are installing multiple distros
		# Should work okay...
		
		Write-Information 'Restart your computer in 30 seconds or it will explode'
		
		'restart-needed'
		Suspend-Workflow
		
		# Wait for a logon where the feature is installed. This will be after at
		# least 1 reboot, but for various reasons (grumble grumble...) it might
		# be later. Every Suspend-Workflow is virtually guaranteed to be resumed
		# by a logon, or a manual resume (which is harmless in this case).
		$waiting = $True
		while ($waiting) {
			if ($FeatureInstalled) {
				$RestartNeeded = $False
			} else {
				try {
					$RestartNeeded = InlineScript {
						$PipeName = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 12 |%{[char]$_})
						
						$Enabled = Start-Process powershell -ArgumentList "`
						`$Enabled = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -WarningAction SilentlyContinue`
						`$RestartNeeded = `$Enabled.RestartNeeded`
						`
						`$pipe = New-Object System.IO.Pipes.NamedPipeServerStream `'$PipeName`',`'Out`'`
						`$pipe.WaitForConnection()`
						`$sw = New-Object System.IO.StreamWriter `$pipe`
						`$sw.AutoFlush = `$True`
						`$sw.WriteLine([string]`$RestartNeeded)`
						`$sw.Dispose()`
						`$pipe.Dispose()`
						" -Verb RunAs -WindowStyle Hidden -ErrorAction Stop
						
						$pipe = New-Object System.IO.Pipes.NamedPipeClientStream '.',$Using:PipeName,'In'
						$pipe.Connect()
						$sr = New-Object System.IO.StreamReader $pipe
						$data = $sr.ReadLine()
						$sr.Dispose()
						$pipe.Dispose()
						
						$data -eq [string]$True
					} -ErrorAction Stop
				} catch {
					# I decided that this is not always true and it would be
					# rude to assume that. So I give the user a choice and allow
					# them to continue without UAC
					## The user accepted the UAC prompt the first time, so they
					## can do it again. They cannot specify the -FeatureInstalled
					## flag at this point, unfortunately.
					#Write-Output 'Please accept the UAC prompt to continue installation.'
					
					# Try to get input from the user as a fallback
					$response = InlineScript {
						[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
						[System.Windows.Forms.Messagebox]::Show("Admin access is required to check the status of the WSL feature. If you can no longer grant admin access via UAC:`n`nIs the WSL feature installed and enabled?", 'WSL Installer', [System.Windows.Forms.MessageBoxButtons]::YesNo)
					}
					
					$RestartNeeded = $response -eq 7 # 7 is DialogResult.No
				}
			}
			
			if ($RestartNeeded) {
				Write-Information 'Looks like the WSL component is still not installed.'
				'still-waiting'
				Suspend-Workflow
			} else {
				$waiting = $False
			}
		}
	}
	
	Write-Information "`n`n`n`n`n`n`n"
	Write-Information 'It will take a few minutes to download the distribution. Most WSL distros are'
	Write-Information 'at or around 200 MB in size. Depending on your internet connection, you could be'
	Write-Information 'staring at this screen for 10 minutes. Sit back and relax, grab a cup of tea...'
	Write-Information ''
	
	$retrying = $True
	while ($retrying) {
		$tempFile = InlineScript { New-TemporaryFile }
		Remove-Item -LiteralPath $tempFile
		$tempFile = $tempFile.FullName -replace '$','.zip'
		
		try {
			Write-Information "Attempting to download distribution to $tempFile..."
			
			$data = InlineScript {
				$PipeName = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 12 |%{[char]$_})
				
				Start-Process powershell -ArgumentList "`
				Try {`
					Invoke-WebRequest -Uri `"https://aka.ms/$Using:LinuxDistribution`" -OutFile `"$Using:tempFile`" -ErrorAction Stop -UseBasicParsing`
					`$Result = 'Success'`
				} Catch {`
					`$Result = `"Failed to download file: `$(`$PSItem.Message)`"`
				}`
				`
				`$pipe = New-Object System.IO.Pipes.NamedPipeServerStream `'$PipeName`',`'Out`'`
				`$pipe.WaitForConnection()`
				`$sw = New-Object System.IO.StreamWriter `$pipe`
				`$sw.AutoFlush = `$True`
				`$sw.WriteLine([string]`$Result)`
				`$sw.Dispose()`
				`$pipe.Dispose()`
				" -WindowStyle Hidden -ErrorAction Stop
				
				$pipe = New-Object System.IO.Pipes.NamedPipeClientStream '.',$PipeName,'In'
				$pipe.Connect()
				$sr = New-Object System.IO.StreamReader $pipe
				$data = $sr.ReadLine()
				$sr.Dispose()
				$pipe.Dispose()
				
				$data
			} -ErrorAction Stop
			
			if ($data -ne 'Success') {
				Write-Error $data -ErrorAction Stop
			}
			
			$retrying = $False
			Write-Information 'Done!'
		} catch {
			Remove-Item -LiteralPath $tempFile -ErrorAction SilentlyContinue
			
			# PSItem is contextual and can't be read from the InlineScript
			$theError = $PSItem
			
			Write-Information "Error: $theError"
			
			$response = InlineScript {
				[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
				[System.Windows.Forms.Messagebox]::Show("The WSL package '$Using:LinuxDistribution' could not be downloaded from Microsoft's servers.`n`nError: $Using:theError`n`nYou may abort the install, and restart it at any time using the wizard. Clicking Ignore will cause a retry the next time you log in.", 'Could not download WSL package', [System.Windows.Forms.MessageBoxButtons]::AbortRetryIgnore)
			}
			
			if ($response -eq 3) { # Abort
				Write-Information 'Aborting'
				$retrying = $False
				Write-Information 'Removing startup item...'
				Remove-Item -LiteralPath $ShortcutPath -ErrorAction SilentlyContinue
				return 'aborted'
			} elseif ($response -eq 5) { # Ignore
				Write-Information 'Ignoring'
				'still-waiting'
				Suspend-Workflow # Wait for next logon
			}
			
			Write-Information 'Retrying'
			
			# If retry just loop again /shrug
		}
	}
	
	Write-Information 'Removing startup item...'
	Remove-Item -LiteralPath $ShortcutPath -ErrorAction SilentlyContinue
	
	$tempDir = New-TemporaryDirectory
	Expand-Archive -LiteralPath $tempFile -DestinationPath $tempDir -ErrorAction Stop
	Remove-Item -LiteralPath $tempFile -ErrorAction SilentlyContinue
	
	Write-Information 'Distribution bundle extracted'
	
	$theDir = $tempDir
	$Executable = Get-ChildItem $tempDir | Where-Object {$_.Name -match '.exe$'} | Select-Object -First 1
	
	if ($Executable -eq $null) {
		$Package = Get-ChildItem $tempDir | Where-Object {$_.Name -match '_x64.appx$'} | Select-Object -First 1
		
		if ($Package -eq $null) {
			return Write-Error 'Could not find the package containing the installer :(' -Category NotImplemented
		}
		
		$Package = Rename-Item -LiteralPath ($Package.FullName) -NewName ($Package.Name -replace '.appx$','.zip') -PassThru
		Write-Information "Distribution package: $($Package.Name)"
		$InnerPackageTemp = New-TemporaryDirectory
		Expand-Archive -LiteralPath $Package -DestinationPath $InnerPackageTemp
		Remove-Item -LiteralPath $tempDir -Recurse
		$Executable = Get-ChildItem $InnerPackageTemp | Where-Object {$_.Name -match '.exe$'} | Select-Object -First 1
		$theDir = $InnerPackageTemp
		
		if ($Executable -eq $null) {
			return Write-Error 'Could not find an executable inside the x64 package :(' -Category NotImplemented
		}
	} else {
		Write-Information 'Root package contains the installer'
	}
	
	# this is going to have to stick around forever if the wsl install is going to stay intact
	$theDir = Move-Item -LiteralPath $theDir -Destination $DistroFolder -PassThru
	$Executable = Get-ChildItem $theDir | Where-Object {$_.Name -match '.exe$'} | Select-Object -First 1
	
	Write-Information "Executing installer: $($Executable.Name)"
	InlineScript { wsl --set-default-version 1 }
	Start-Process -FilePath ($Executable.FullName) -Wait
	
	if (!$OmitWindowsTerminal) {
		Write-Information 'Installing Windows Terminal...'
		
		InlineScript {
			$ExecutionPolicy = Get-ExecutionPolicy -Scope Process
			Set-ExecutionPolicy RemoteSigned -Scope Process
			Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://get.scoop.sh')
			Set-ExecutionPolicy $ExecutionPolicy -Scope Process
			scoop bucket add extras
			scoop install windows-terminal
		}
	}
	
	Write-Information 'Everything should be in order now. Enjoy!'
	
	# We done
	
	return 'done'
}

function Install-WSLInteractive {
	$Distros = @(
		[PSCustomObject]@{Slug = 'wslubuntu2004';       Name = 'Ubuntu 20.04';  Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wsl-ubuntu-1804';     Name = 'Ubuntu 18.04';  Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wsl-ubuntu-1604';     Name = 'Ubuntu 16.04';  Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wsl-debian-gnulinux'; Name = 'Debian Stable'; Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wsl-kali-linux-new';  Name = 'Kali Linux';    Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wsl-opensuse-42';     Name = 'OpenSUSE 4.2';  Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wsl-sles-12';         Name = 'SLES 12';       Arch = 'x64'}
	)
	
	$Menu = 'main'
	
	if ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544') {
		$Menu = 'admin'
	}
	
	while ($Menu -ne 'exit') {
		Clear-Host
		# 80 chars:  '                                                                                '
		Write-Host ' :: WSL INSTALL SCRIPT FOR WINDOWS 10 AME'
		Write-Host ''
		Write-Host '    This script will help you install Windows Subsystem for Linux on your'
		Write-Host '    ameliorated installation of Windows 10'
		Write-Host ''
		Write-Host ' :: NOTE: Tested on Windows 10 1909, and Windows 10 AME 20H2'
		
		switch ($menu) {
			'main' {
				Write-Host ''
				Write-Host ' :: Please enter a number from 1-3 to select an option from the list below'
				Write-Host ''
				Write-Host ' 1) Install a new WSL distro'
				Write-Host ' 2) Cancel a pending WSL installation'
				Write-Host ' 3) Exit'
				Write-Host ''
				Write-Host ' >> ' -NoNewLine
				$Input = $Host.UI.ReadLine()
				
				switch ($Input) {
					'1' {
						$Menu = 'select-distro'
					}
					'2' {
						$Menu = 'cancel'
					}
					'3' {
						$Menu = 'exit'
					}
					default {
						Write-Host ''
						Write-Host ' !! Invalid option selected' -ForegroundColor red
						Write-Host ''
						Write-Host '    Press enter to continue...' -NoNewLine
						$Host.UI.ReadLine()
					}
				}
			}
			'select-distro' {
				Write-Host ''
				Write-Host ' :: Please enter a number from the list to select a distro to install'
				Write-Host ''
				
				$Max = 1
				
				$Distros | ForEach-Object {
					Add-Member -InputObject $_ -NotePropertyName Option -NotePropertyValue ([string]$Max) -Force
					Write-Host " $Max) $($_.Name)"
					$Max += 1
				}
				
				Write-Host " $Max) Return to main menu"
				Write-Host ''
				Write-Host ' >> ' -NoNewLine
				$Input = $Host.UI.ReadLine()
				
				if ($Input -eq ([string]$Max)) {
					$Menu = 'main'
				} else {
					$Distro = $Distros | Where-Object -Property Option -eq -Value $Input
					
					if ($Distro -eq $null) {
						Write-Host ''
						Write-Host ' !! Invalid option selected' -ForegroundColor Red
						Write-Host ''
						Write-Host '    Press enter to continue...' -NoNewLine
						$Host.UI.ReadLine()
					} else {
						$Menu = 'install-distro-confirm'
					}
				}
			}
			'install-distro-confirm' {
				Write-Host ''
				Write-Host " :: WARNING: Are you sure you want to install $($Distro.Name)? (yes/no) " -NoNewLine
				$Input = $Host.UI.ReadLine()
				
				switch ($Input) {
					'yes' {
						$Menu = 'install-distro'
					}
					'no' {
						$Menu = 'select-distro'
					}
					default {
						Write-Host ''
						Write-Host ' !! Invalid input' -ForegroundColor Red
						Write-Host ''
						Write-Host '    Press enter to continue...' -NoNewLine
						$Host.UI.ReadLine()
						$Menu = 'select-distro'
					}
				}
			}
			'install-distro' {
				Write-Host ''
				Write-Host "Installing $($Distro.Name)..."
				
				try {
					$Menu = ('result-' + (Install-WSL -LinuxDistribution ($Distro.Slug) -InformationAction Continue -ErrorAction Stop | Select-Object -First 1 -Wait))
				} catch {
					Write-Host ''
					Write-Host ' !! An error occurred during the installation' -ForegroundColor Red
					Write-Host " !! The error is: $PSItem" -ForegroundColor Red
					Write-Host ''
					Write-Host '    Your chosen distro could not be installed.'
					Write-Host ''
					Write-Host '    Press enter to continue...' -NoNewLine
					$Host.UI.ReadLine()
					$Menu = 'select-distro'
				}
			}
			'cancel' {
				Write-Host ''
				Write-Host ' :: WARNING: Are you sure you want to cancel all pending installs? (yes/no) ' -NoNewLine
				$Input = $Host.UI.ReadLine()
				
				switch ($Input) {
					'yes' {
						Write-Host ''
						Install-WSL -Cancel
					}
					'no' {
						Write-Host ''
						Write-Host '    Returning to main menu.'
					}
					default {
						Write-Host ''
						Write-Host ' !! Invalid input' -ForegroundColor Red
					}
				}
				
				Write-Host ''
				Write-Host '    Press enter to continue...' -NoNewLine
				$Host.UI.ReadLine()
				$Menu = 'main'
			}
			'admin' {
				Write-Host ''
				Write-Host ' !! This script should NOT be run as Administrator' -ForegroundColor Red
				Write-Host ' !! Please close this window and run the script normally' -ForegroundColor Red
				Write-Host ''
				Write-Host '    Press enter to continue...' -NoNewLine
				$Host.UI.ReadLine()
				$Menu = 'exit'
			}
			'result-restart-needed' {
				Clear-Host
				Write-Host ' !! WSL installation will resume once you restart Windows'
				Write-Host ''
				Write-Host '    Please ensure you stay connected to the Internet.'
				Write-Host ''
				Write-Host '    Press enter to continue...' -NoNewLine
				$Host.UI.ReadLine()
				$Menu = 'exit'
			}
			'result-done' {
				Clear-Host
				Write-Host ' :: Installation done!'
				Write-Host ''
				Write-Host '    The WSL feature was already installed and enabled on your system, so we were'
				Write-Host '    able to install your distro right away.'
				Write-Host ''
				Write-Host '    Enjoy!'
				Write-Host ''
				Write-Host '    Press enter to continue...' -NoNewLine
				$Host.UI.ReadLine()
				$Menu = 'exit'
			}
			default {
				Write-Host ''
				Write-Host " !! Invalid menu encountered ($Menu). Exiting" -ForegroundColor Red
				Write-Host ' !! THIS IS A BUG, PLEASE REPORT IT TO THE AME DEVS' -ForegroundColor Red
				$Menu = 'exit'
			}
		}
	}
}
