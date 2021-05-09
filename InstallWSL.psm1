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
		
		[Parameter(Mandatory=$True,ParameterSetName='Cancelation')]
		[switch]$Cancel
	)
	
	# The task scheduler is unreliable in AME
	#Write-Output 'Scheduling task'
	#
	#$action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument "-NonInteractive -WindowStyle Normal -NoLogo -NoProfile -Command `"& { Write-Output \`"Don```'t close this PowerShell window! This is your WSL installer! Just give it a minute...\`"; Get-Job -Command `'Install-WSL`' | Resume-Job | Receive-Job -Wait; pause; exit }`""
	#$logon = New-ScheduledTaskTrigger -AtLogOn
	#$task = Register-ScheduledTask -TaskName 'InstallWSL' -Action $action -Trigger $logon -RunLevel Highest
	
	## Where ShortcutPath is placed is honestly an implementation detail. It will
	## be run as administrator by the elevator, which is what gets run at startup
	#$ShortcutPath = Join-Path $env:ProgramData 'Microsoft\Windows\Install WSL.lnk'
	#$ElevatorPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup\Install WSL.lnk'
	$ShortcutPath = Join-Path $env:AppData 'Microsoft\Windows\Start Menu\Programs\Startup\Install WSL.lnk'
	
	if ($Cancel) {
		$Removed = Remove-Item -LiteralPath $ShortcutPath -ErrorAction SilentlyContinue
		$Removed = Get-Job -Command 'Install-WSL' | Where-Object {$_.State -eq 'Suspended'} | Remove-Job -Force
		return Write-Output 'All pending WSL installations have been canceled.'
	}
	
	# establish directory for WSL installations
	$AppDataFolder = Join-Path $env:LocalAppData 'WSL'
	$DistrosFolder = New-Item -ItemType Directory -Force -Path $AppDataFolder
	$DistroFolder = Join-Path $DistrosFolder $LinuxDistribution
	
	if (Test-Path -Path $DistroFolder -PathType Container) {
		return Write-Error 'Cannot install a distro twice! This will waste your internet data. Uninstall the existing version first.' -Category ResourceExists
	}
	
	Write-Output 'Creating startup item'
	
	InlineScript {
		$shell = New-Object -ComObject ('WScript.Shell')
		$shortcut = $shell.CreateShortcut($Using:ShortcutPath)
		$shortcut.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
		$shortcut.Arguments = "-WindowStyle Normal -NoLogo -NoProfile -Command `"& { Write-Output \`"Resuming installation...\`"; Get-Job -Command `'Install-WSL`' | Resume-Job | Receive-Job -Wait; pause; exit }`""
		$shortcut.Save()
		
		#$elevator = $shell.CreateShortcut($Using:ElevatorPath)
		#$elevator.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
		#$elevator.Arguments = "-WindowStyle Normal -NoLogo -NoProfile -Command `"Write-Output \`"The WSL installation can now be started. Please accept the UAC prompt to proceed\`"; pause; Start-Process -FilePath '$Using:ShortcutPath' -Verb Runas`""
		#$elevator.Save()
	}
	
	# This didn't work.
	## This is the exact same shortcut as above, but with 'Run As Administrator' set, encoded in Base64.
	## [Convert]::ToBase64String((Get-Content 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Install WSL.lnk' -Encoding Byte))
	## This is needed because that flag cannot be checked programmatically.
	#$Base64 = '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'
	#Set-Content -LiteralPath $ShortcutPath -Value ([Convert]::FromBase64String($Base64)) -Encoding Byte
	
	Write-Output 'There will be a "Windows PowerShell" shortcut in your startup items until this script is complete. Please do not be alarmed, it will remove itself once the installation is complete.'
	
	Write-Output 'Ensuring required features are enabled'
	
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
		
		#$Job = Get-Job -Name 'Install-WSL'
		#
		#if ($Job) {
		#	Write-Output 'Already waiting for the WSL feature to be enabled'
		#	return
		#}
		
		# Future Logan from the future!: I think the shortcut is more easily
		# detected, but there are reasons you might want to run this more than
		# once in a row. For example if you are installing multiple distros
		# Should work okay...
		
		Write-Output 'Restart your computer in 30 seconds or it will explode'
		
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
				Write-Output 'Looks like the WSL component is still not installed.'
				Suspend-Workflow
			} else {
				$waiting = $False
			}
		}
	}
	
	Write-Output "`n`n`n`n`n`n`n`n`n`nWarning: The PowerShell window will display the download process for longer than usual. This is a Windows bug, and is only visual.`n"
	
	$retrying = $True
	while ($retrying) {
		$tempFile = InlineScript { New-TemporaryFile }
		Remove-Item -LiteralPath $tempFile
		$tempFile = $tempFile.FullName -replace '$','.zip'
		
		try {
			Write-Output "Attempting to download distribution to $tempFile..."
			Invoke-WebRequest -Uri "https://aka.ms/$LinuxDistribution" -OutFile $tempFile -ErrorAction Stop -UseBasicParsing
			#InlineScript {
			#	(New-Object System.Net.WebClient).DownloadFile("https://aka.ms/$Using:LinuxDistribution", $tempFile.FullName)
			#}
			#Start-BitsTransfer -DisplayName 'WSL Package Download' -Source "https://aka.ms/$LinuxDistribution" -Destination $tempFile -ErrorAction Stop
			$retrying = $False
			Write-Output 'Done!'
		} catch {
			#Get-BitsTransfer -Name 'WSL Package Download' | Remove-BitsTransfer -ErrorAction SilentlyContinue
			Remove-Item -LiteralPath $tempFile -ErrorAction SilentlyContinue
			
			# PSItem is contextual and can't be read from the InlineScript
			$theError = $PSItem.Message
			
			Write-Output "Error: $theError"
			
			$response = InlineScript {
				[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
				[System.Windows.Forms.Messagebox]::Show("The WSL package '$Using:LinuxDistribution' could not be downloaded from Microsoft's servers.`n`nError: $Using:theError`n`nYou may abort the install, and restart it at any time using the wizard. Clicking Ignore will cause a retry the next time you log in.", 'Could not download WSL package', [System.Windows.Forms.MessageBoxButtons]::AbortRetryIgnore)
			}
			
			if ($response -eq 3) { # Abort
				Write-Output 'Aborting'
				$retrying = $False
				Unregister-ScheduledTask -TaskName 'InstallWSL' -Confirm:$False
				return
			} elseif ($response -eq 5) { # Ignore
				Write-Output 'Ignoring'
				Suspend-Workflow # Wait for next logon
			}
			
			Write-Output 'Retrying'
			
			# If retry just loop again /shrug
		}
	}
	
	#Write-Output 'Unscheduling task...'
	#
	#Unregister-ScheduledTask -TaskName 'InstallWSL' -Confirm:$False
	
	Write-Output 'Removing startup item...'
	Remove-Item -LiteralPath $ShortcutPath -ErrorAction SilentlyContinue
	#Remove-Item -LiteralPath $ElevatorPath -ErrorAction SilentlyContinue
	
	$tempDir = New-TemporaryDirectory
	Expand-Archive -LiteralPath $tempFile -DestinationPath $tempDir
	Remove-Item -LiteralPath $tempFile
	
	Write-Output 'Distribution bundle extracted'
	
	# Thought we might need to support ARM64, turns out artrons doesn't want it.
	# Leaving this (and the comment) here just in case.
	
	## This appx package contains inner appx packages for each architecture.
	## This information is encoded in an XML manifest file.
	## I want to use the XML manifest to find the right package, unzip that, and
	## then find the executable inside.
	## This allows compatibility with both x86 and ARM
	#$RootManifest = Join-Path $tempDir 'AppxMetadata\AppxBundleManifest.xml'
	#$Package = Select-Xml -Path $RootManifest -XPath '/Bundle/Packages/Package' | Where-Object {$_.Node.Type -eq 'Application' -and $_.Node.Architecture -eq 'x64'} | Select-Object -First 1
	
	$theDir = $tempDir
	$Executable = Get-ChildItem $tempDir | Where-Object {$_.Name -match '.exe$'} | Select-Object -First 1
	
	if ($Executable -eq $null) {
		$Package = Get-ChildItem $tempDir | Where-Object {$_.Name -match '_x64.appx$'} | Select-Object -First 1
		
		if ($Package -eq $null) {
			return Write-Error 'Could not find the package containing the installer :(' -Category NotImplemented
		}
		
		$Package = Rename-Item -LiteralPath ($Package.FullName) -NewName ($Package.Name -replace '.appx$','.zip') -PassThru
		Write-Output "Distribution package: $($Package.Name)"
		$InnerPackageTemp = New-TemporaryDirectory
		Expand-Archive -LiteralPath $Package -DestinationPath $InnerPackageTemp
		Remove-Item -LiteralPath $tempDir -Recurse
		$Executable = Get-ChildItem $InnerPackageTemp | Where-Object {$_.Name -match '.exe$'} | Select-Object -First 1
		$theDir = $InnerPackageTemp
		
		if ($Executable -eq $null) {
			return Write-Error 'Could not find an executable inside the x64 package :(' -Category NotImplemented
		}
	} else {
		Write-Output 'Root package contains the installer'
	}
	
	# this is going to have to stick around forever if the wsl install is going to stay intact
	$theDir = Move-Item -LiteralPath $theDir -Destination $DistroFolder -PassThru
	$Executable = Get-ChildItem $theDir | Where-Object {$_.Name -match '.exe$'} | Select-Object -First 1
	
	Write-Output "Executing installer: $($Executable.Name)"
	InlineScript { wsl --set-default-version 1 }
	Start-Process -FilePath ($Executable.FullName) -Wait
	# ruins the WSL install
	#Remove-Item -LiteralPath $theDir -Recurse -ErrorAction SilentlyContinue
	
	Write-Output 'Everything should be in order now. Enjoy!'
	
	# We done
}

function Install-WSLInteractive {
	$Distros = @(
		[PSCustomObject]@{Slug = 'wslubuntu2004';       Name = 'Ubuntu 20.04';  Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wslubuntu2004arm';    Name = 'Ubuntu 20.04';  Arch = 'ARM64'}
		[PSCustomObject]@{Slug = 'wsl-ubuntu-1804';     Name = 'Ubuntu 18.04';  Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wsl-ubuntu-1804-arm'; Name = 'Ubuntu 18.04';  Arch = 'ARM64'}
		[PSCustomObject]@{Slug = 'wsl-ubuntu-1604';     Name = 'Ubuntu 16.04';  Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wsl-debian-gnulinux'; Name = 'Debian Stable'; Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wsl-kali-linux-new';  Name = 'Kali Linux';    Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wsl-opensuse-42';     Name = 'OpenSUSE 4.2';  Arch = 'x64'}
		[PSCustomObject]@{Slug = 'wsl-sles-12';         Name = 'SLES 12';       Arch = 'x64'}
	)
	
	$Menu = 'main'
	
	while ($Menu -ne 'exit') {
		Clear-Host
		# 80 chars:  '                                                                                '
		Write-Output ' :: WSL INSTALL SCRIPT FOR WINDOWS 10 AME'
		Write-Output ''
		Write-Output '    This script will help you install Windows Subsystem for Linux on your'
		Write-Output '    ameliorated installation of Windows 10'
		Write-Output ''
		Write-Output ' :: NOTE: Tested on Windows 10 1909, and Windows 10 AME 20H2'
		
		switch ($menu) {
			'main' {
				Write-Output ''
				Write-Output ' :: Please enter a number from 1-3 to select an option from the list below'
				Write-Output ''
				Write-Output ' 1) Install a new WSL distro'
				Write-Output ' 2) Cancel a pending WSL installation'
				Write-Output ' 3) Exit'
				Write-Output ''
				Write-Host   ' >> ' -NoNewLine
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
						Write-Output ''
						Write-Host ' !! Invalid option selected' -ForegroundColor red
						Write-Output ''
						Write-Host '    Press enter to continue...' -NoNewLine
						$Host.UI.ReadLine()
					}
				}
			}
			'select-distro' {
				Write-Output ''
				Write-Output ' :: Please enter a number from the list to select a distro to install'
				Write-Output ''
				
				$Max = 1
				
				$Distros | ForEach-Object {
					Add-Member -InputObject $_ -NotePropertyName Option -NotePropertyValue ([string]$Max) -Force
					Write-Output " $Max) $($_.Name) ($($_.Arch))"
					$Max += 1
				}
				
				Write-Output " $Max) Return to main menu"
				Write-Output ''
				Write-Host   ' >> ' -NoNewLine
				$Input = $Host.UI.ReadLine()
				
				if ($Input -eq ([string]$Max)) {
					$Menu = 'main'
				} else {
					$Distro = $Distros | Where-Object -Property Option -eq -Value $Input
					
					if ($Distro -eq $null) {
						Write-Output ''
						Write-Host   ' !! Invalid option selected' -ForegroundColor Red
						Write-Output ''
						Write-Host   '    Press enter to continue...' -NoNewLine
						$Host.UI.ReadLine()
					} else {
						$Menu = 'install-distro-confirm'
					}
				}
			}
			'install-distro-confirm' {
				Write-Output ''
				Write-Host   " :: WARNING: Are you sure you want to install $($Distro.Name) ($($Distro.Arch))? (yes/no) " -NoNewLine
				$Input = $Host.UI.ReadLine()
				
				switch ($Input) {
					'yes' {
						$Menu = 'install-distro'
					}
					'no' {
						$Menu = 'select-distro'
					}
					default {
						Write-Output ''
						Write-Host   ' !! Invalid input' -ForegroundColor Red
						Write-Output ''
						Write-Host   '    Press enter to continue...' -NoNewLine
						$Host.UI.ReadLine()
						$Menu = 'select-distro'
					}
				}
			}
			'install-distro' {
				Write-Output ''
				Write-Output "Installing $($Distro.Name) ($($Distro.Arch))..."
				Install-WSL -LinuxDistribution ($Distro.Slug)
				$Menu = 'exit'
			}
			'cancel' {
				Write-Output ''
				Write-Host   ' :: WARNING: Are you sure you want to cancel all pending installs? (yes/no) ' -NoNewLine
				$Input = $Host.UI.ReadLine()
				
				switch ($Input) {
					'yes' {
						Write-Output ''
						Install-WSL -Cancel
					}
					'no' {
						Write-Output ''
						Write-Output '    Returning to main menu.'
					}
					default {
						Write-Output ''
						Write-Host   ' !! Invalid input' -ForegroundColor Red
					}
				}
				
				Write-Output ''
				Write-Host   '    Press enter to continue...' -NoNewLine
				$Host.UI.ReadLine()
				$Menu = 'main'
			}
			default {
				Write-Output ''
				Write-Host   " !! Invalid menu encountered ($Menu). Exiting" -ForegroundColor Red
				$Menu = 'exit'
			}
		}
	}
}
