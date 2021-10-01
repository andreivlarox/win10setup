Write-Host ""
Write-Host ""
Write-Host "+-------------------------------------------------------------+"
Write-Host "| ##     ## ##          ###    ########   #######  ##     ##  |"
Write-Host "| ##     ## ##         ## ##   ##     ## ##     ##  ##   ##   |"
Write-Host "| ##     ## ##        ##   ##  ##     ## ##     ##   ## ##    |"
Write-Host "| ##     ## ##       ##     ## ########  ##     ##    ###     |"
Write-Host "|  ##   ##  ##       ######### ##   ##   ##     ##   ## ##    |"
Write-Host "|   ## ##   ##       ##     ## ##    ##  ##     ##  ##   ##   |"
Write-Host "|    ###    ######## ##     ## ##     ##  #######  ##     ##  |"
Write-Host "|                                                             |"
Write-Host "|                      Script instalare si configurare rapida |"
Write-Host "|                               Andrei/VLAROX FISCAL SRL 2021 |"
Write-Host "+-------------------------------------------------------------+"
Write-Host ""
Write-Host ""
Write-Host "Setare nume PC"
$numepc = Read-Host 'Nume PC'
Rename-Computer -NewName $numepc -LocalCredential Administrator

## Data Ora
Write-Host "Se seteaza data si ora"
TZUTIL /s "GTB Standard Time"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortTime" -Value "HH:mm"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sLongTime" -Value "HH:mm:SS"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortDate" -Value "dd.MM.yyyy"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sLongDate" -Value "dddd, dd MMMM, yyyy"
net start w32time
w32tm /resync /force

## Setare IP
$yesdescription = "Seteaza IP-ul calculatorului"
$nodescription = "Sarim peste setarea IP-ului"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Da", $yesdescription
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&Nu", $nodescription
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$title = "Setare IP"
$message = "Vrei sa setam IP-ul calculatorului?"
$result = $host.ui.PromptForChoice($title, $message, $options, 1)
switch ($result) {
  0{
    $IP = Read-Host -Prompt "Introduceti IP-ul (192.168.XXX.XXX)"
    $DG = Read-Host -Prompt "Introduceti Gateway-ul (192.168.XXX.XXX)"
    $MaskBits = "24"
    $DNS = "1.1.1.1"
    $IPType = "IPv4"
    $dnsserver = $DG,$DNS

    # Cauta adaptorul de retea
    $adapter = Get-NetAdapter | ? {$_.Status -eq "up"}

    # Sterge adrese de IP existente
    If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
        $adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false
    }

    If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
        $adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false
    }

    # Configureaza adresa de IP
    $adapter | New-NetIPAddress `
        -AddressFamily $IPType `
        -IPAddress $IP `
        -PrefixLength $MaskBits `
        -DefaultGateway $DG

    # Configureaza DNS-ul
    $adapter | Set-DnsClientServerAddress -ServerAddresses $dnsserver
	Write-Host "IP setat cu success"
  }
  1{
    Write-Host "Sarit peste setarea IP-ului"
   }
}

Write-Host "Se porneste network discovery..."
netsh advfirewall firewall set rule group=”network discovery” new enable=yes

# Instalare net framework 3.5

Write-Host "Instalare .netFramework 3.5"
& "$PSScriptRoot\dotnetfx35.exe" | Out-Null

Write-Host "Checking winget..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowAllTrustedApps" /d "1"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"

Try{
	# Check if winget is already installed
	$er = (invoke-expression "winget -v") 2>&1
	if ($lastexitcode) {throw $er}
	Write-Host "winget is already installed."
}
Catch{
	# winget is not installed. Install it from the Github release
	Write-Host "winget is not found, installing it right now."
	
	Import-Module Appx
	$downloadvc = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
	$outputvc = $PSScriptRoot + "\vclibs.appx"
	Invoke-WebRequest -Uri $downloadvc -OutFile $outputvc
	
	Write-Host "Installing the package"
	Add-AppxPackage -Path $outputvc
	
	$download = "https://github.com/microsoft/winget-cli/releases/download/v1.0.11692/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
	$output = $PSScriptRoot + "\winget-latest.appxbundle"
	Write-Host "Dowloading latest release"
	Invoke-WebRequest -Uri $download -OutFile $output
	
	Write-Host "Installing the package"
	Add-AppxPackage -Path $output
}


# Instalare Windows Terminal

Write-Host "Se instaleaza New Windows Terminal"
winget install --id Microsoft.WindowsTerminal --accept-package-agreements
if($?) { Write-Host "New Windows Terminal instalat!" }

if ($isPreview)
{
$file = "$env:LocalAppData\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json"
$backupfile = "$env:LocalAppData\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json_BACKUP"
} 

else 
{

$file = "$env:LocalAppData\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
$backupfile = "$env:LocalAppData\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json_BACKUP"
}

if (Test-Path $file) {
    Copy-Item $file -Destination $backupfile
    Write-Host "Your original settings file was backed up as $backupfile"
}

(New-Object System.Net.WebClient).Downloadfile("https://raw.githubusercontent.com/andreivlarox/windowsterminal-shell/master/helpers/settings.json", $file)
Write-Host "Windows Terminal installed to Windows Explorer context menu."
Write-Host "Settings file downloaded and imported from Github."


# Instalare Dude

Write-Host "Instalare Dude"
& "$PSScriptRoot\DUDE_setup.exe" /S | Out-Null


# Instalare Firefox

Write-Host "Se instaleaza Firefox"
winget install --id Mozilla.Firefox --accept-package-agreements
if($?) { Write-Host "Firefox instalat!" }
cmd /C "$PSScriptRoot\SetDefaultBrowser.exe HKLM Firefox-308046B0AF4A39CB"

# Instalare Adobe Reader

Write-Host "Se instaleaza Adobe Reader DC"
winget install --id Adobe.AdobeAcrobatReaderDC --accept-package-agreements
if($?) { Write-Host "Adobe Reader DC instalat!" }

# Instalare WinRAR

Write-Host "Se instaleaza WinRAR"
winget install --id RARLab.WinRAR --accept-package-agreements
if($?) { Write-Host "WinRAR instalat!" }

# Instalare Notepad++

Write-Host "Se instaleaza Notepad++"
winget install --id Notepad++.Notepad++
if($?) { Write-Host "Notepad++ instalat!" }

# Instalare Anydesk

Write-Host "Se instaleaza Anydesk"
winget install --id AnyDeskSoftwareGmbH.AnyDesk --accept-package-agreements
if($?) { Write-Host "Anydesk instalat!" }
cmd /C "echo Vlarox2014 | `"C:\Program Files (x86)\AnyDesk\anydesk.exe`" --set-password"

## Remotely
$yesdescription = "Instaleaza Remotely"
$nodescription = "Sarim peste instalarea Remotely"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Da", $yesdescription
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&Nu", $nodescription
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$title = "Remotely"
$message = "Vrei sa instalam remotely?"
$result = $host.ui.PromptForChoice($title, $message, $options, 1)
switch ($result) {
  0{
  	$pcname = Read-Host 'Introduceti alias-ul (numele) calculatorului: '
   	 ## Grup clienti
	$clientdescription = "Clienti"
	$abadescription = "Aba Flor"
	$interndescription = "Intern"
	$client = New-Object System.Management.Automation.Host.ChoiceDescription "&Client", $clientdescription
	$aba = New-Object System.Management.Automation.Host.ChoiceDescription "&Aba Flor", $abadescription
	$intern = New-Object System.Management.Automation.Host.ChoiceDescription "&Intern", $interndescription
	$options = [System.Management.Automation.Host.ChoiceDescription[]]($client, $aba, $intern)
	$title = "Grup Client"
	$message = "In ce grup adaugam pc-ul?"
	$result = $host.ui.PromptForChoice($title, $message, $options, 0)
	switch ($result) {
  	0{
   	 $grup = "Clienti"
 	 }
 	 1{
   	 $grup = "Aba Flor"
  	 }
	 2{
	 $grup = "Intern"
	 }
	}
	
	$path = "C:\Remotely"
	If(!(test-path $path))
	{
       New-Item -ItemType Directory -Force -Path $path
	}
	Copy-Item -Path "$PSScriptRoot\Remotely_Install.exe" -Destination "C:\Remotely\Remotely_Install.exe"
	cmd.exe /c "start /wait C:\Remotely\Remotely_Install.exe -install -quiet -organizationid "50a754e7-e194-436e-8887-677f19059382" -serverurl "https://remote.vlarox.ro" -devicegroup "$grup" -devicealias "$pcname""

		If((test-path $path))
	{
       Remove-Item -Recurse -Force -Path $path -ErrorAction SilentlyContinue
	}
	
	  }
  1{
    Write-Host "Sarit peste Instalarea Remotely"
   }
}


## Folder scales
$yesdescription = "Copiaza folderul scales"
$nodescription = "Sarim peste copierea folderuli scales"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Da", $yesdescription
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&Nu", $nodescription
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$title = "Folder Scales"
$message = "Vrei sa copiem folderul scales?"
$result = $host.ui.PromptForChoice($title, $message, $options, 1)
switch ($result) {
  0{
    Copy-Item -Path "$PSScriptRoot\scales" -Destination "C:\scales" -Recurse
	Write-Host "Folder scales copiat"
  }
  1{
    Write-Host "Sarit peste copierea folderului scales"
   }
}


## Instalare TW13
$yesdescription = "Instaleaza TeamViewer 13"
$nodescription = "Sarim peste instalare TeamViewer 13"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Da", $yesdescription
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&Nu", $nodescription
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$title = "Teamviewer 13"
$message = "Vrei sa instalam TeamViewer 13?"
$result = $host.ui.PromptForChoice($title, $message, $options, 1)
switch ($result) {
  0{
    & "$PSScriptRoot\teamviewer13_HOST.exe" /S /norestart | Out-Null
	Write-Host "TeamViewer 13 instalat!"
  }
  1{
    Write-Host "Sarit peste instalarea TeamViewer 13"
   }
}


## Instalare LibreOffice
$yesdescription = "Instaleaza LibreOffice"
$nodescription = "Sarim peste instalare LibreOffice"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Da", $yesdescription
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&Nu", $nodescription
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$title = "LibreOffice"
$message = "Vrei sa instalam LibreOffice?"
$result = $host.ui.PromptForChoice($title, $message, $options, 0)
switch ($result) {
  0{
    winget install --id LibreOffice.LibreOffice --accept-package-agreements
    if($?) { Write-Host "LibreOffice instalat!" }
  }
  1{
    Write-Host "Sarit peste instalarea LibreOffice"
   }
}


Write-Host "Adaugare cantare digi in HOSTS..."

"#-----------------------------------------------------" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"#IP-uri cantare DIGI" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"192.168.1.101 S0101" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"192.168.1.102 S0102" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"192.168.1.103 S0103" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"192.168.1.104 S0104" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"192.168.1.105 S0105" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"192.168.1.106 S0106" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"192.168.1.107 S0107" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"192.168.1.108 S0108" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"192.168.1.109 S0109" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"#final IP-uri cantare DIGI" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii
"#-----------------------------------------------------" | Out-File -Append $env:windir\System32\Drivers\Etc\Hosts -enc ascii

Write-Host "Setari power config"

powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /change monitor-timeout-ac 0
powercfg /change monitor-timeout-dc 0
powercfg /change hibernate-timeout-ac 0
powercfg /change hibernate-timeout-dc 0
powercfg /change disk-timeout-ac 0
powercfg /change disk-timeout-dc 0

Write-Host "Dezactivare notificari. Dezactivare UAC"

If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient")) {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 0


Write-Host "Adaugare reguli Firewall"
New-NetFirewallRule -DisplayName "Firebird in" -Direction Inbound -LocalPort 3050 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Firebird out" -Direction Outbound -LocalPort 3050 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "S2S API in" -Direction Inbound -LocalPort 8888 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "S2S API out" -Direction Outbound -LocalPort 8888 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "MySQL in" -Direction Inbound -LocalPort 3306 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "MySQL out" -Direction Outbound -LocalPort 3306 -Protocol TCP -Action Allow

Write-Host "Se dezactiveaza serviciile de Telemetry..."

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

Write-Host "Se dezactiveaza sugestiile de aplicatii..."

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

Write-Host "Se dezactiveaza istoricul de activitati..."

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

Write-Host "Se dezactiveaza Location Tracking..."

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
Stop-Service "DiagTrack" -WarningAction SilentlyContinue
Set-Service "DiagTrack" -StartupType Disabled
bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null

Write-Host "Se dezactiveaza serviciul de hibernare..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
If (!(Test-Path "HKU:")) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}
Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
Add-Type -AssemblyName System.Windows.Forms
If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
    $wsh = New-Object -ComObject WScript.Shell
    $wsh.SendKeys('{NUMLOCK}')
}

If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0

Write-Host "Se dezactiveaza OneDrive..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
Write-Host "Uninstalling OneDrive..."
Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
Start-Sleep -s 2
$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
If (!(Test-Path $onedrive)) {
    $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
}
Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
Start-Sleep -s 2
Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
Start-Sleep -s 2
Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
If (!(Test-Path "HKCR:")) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
Write-Host "Disabled OneDrive"

Write-Host "Oprire Windows Updates"
& "$PSScriptRoot\Wub\Wub.exe" /D /P
Copy-Item -Path "$PSScriptRoot\Wub" -Destination "C:\Wub" -Recurse

Write-Host ""
Write-Host ""
Write-Host "+-------------------------------------------------------------+"
Write-Host "| ##     ## ##          ###    ########   #######  ##     ##  |"
Write-Host "| ##     ## ##         ## ##   ##     ## ##     ##  ##   ##   |"
Write-Host "| ##     ## ##        ##   ##  ##     ## ##     ##   ## ##    |"
Write-Host "| ##     ## ##       ##     ## ########  ##     ##    ###     |"
Write-Host "|  ##   ##  ##       ######### ##   ##   ##     ##   ## ##    |"
Write-Host "|   ## ##   ##       ##     ## ##    ##  ##     ##  ##   ##   |"
Write-Host "|    ###    ######## ##     ## ##     ##  #######  ##     ##  |"
Write-Host "|                                                             |"
Write-Host "|                      Script instalare si configurare rapida |"
Write-Host "|                               Andrei/VLAROX FISCAL SRL 2021 |"
Write-Host "+-------------------------------------------------------------+"
Write-Host ""
Write-Host ""

Copy-Item -Path "$PSScriptRoot\remove.bat" -Destination "$env:USERPROFILE\Desktop\remove.bat"

Write-Host "Verificare conexiune router!"
ping $DG
Write-Host "Verificare conexiune internet!"
ping 1.1.1.1
ping google.com

Write-Host "Calculatorul se va restarta in 10 secunde! Apasati CTRL+C sa renuntati."
ping -n 10 127.0.0.1>nul
shutdown /r /t 0
