# Variables
$anyDeskWindowsUrl = "https://download.anydesk.com/AnyDesk.exe"
$anyDeskDownloadFolder = $env:TEMP
$anyDeskFileName = "anydesk.exe"
$downloadedAnydeskFile = "$anyDeskDownloadFolder\$anyDeskFileName"

$programFilesDirectories = @($Env:Programfiles, ${env:ProgramFiles(x86)})
$anyDeskTargetinstallDirectory = "${env:ProgramFiles(x86)}\AnyDesk"
$installedAnyDeskBin = "$anyDeskTargetinstallDirectory\AnyDesk.exe"
$anyDeskConfigDirectory = "C:\ProgramData\AnyDesk"

If ($WhatIfPreference) {
    Write-Host "Skript wurde mit -Whatif gestartet und Ausführung wird nur simuliert"
}

function removeInstallations() {
    foreach ($directory in $programFilesDirectories) {
        Get-ChildItem "$directory" -Filter AnyDesk* | ForEach-Object {
            $directoryName = $_.Name

            Write-Host "AnyDesk installation in Ordner [$directory/$directoryName] gefunden"

            Get-ChildItem "$directory/$directoryName" -Filter AnyDesk*.exe | ForEach-Object {
                $anyDeskBin = $_.Name

                # Kill task
                if ($WhatIfPreference) {
                   Write-Host "AnyDesk Prozess [$anyDeskBin] wird nicht beendet, da mit -Whatif gestartet"
                } else {
                   Write-Host "AnyDesk Prozess [$anyDeskBin] wird beendet"
                   taskkill /IM $anyDeskBin /F 
                   Write-Host "AnyDesk Prozess [$anyDeskBin] wurde beendet"
                }

                if ($WhatIfPreference) {
                    Write-Host "AnyDesk Deinstallation würde mit [$directory/$directoryName/$anyDeskBin --silent --remove] versucht werden, wird jedoch nicht ausgeführt, da Skript mit -Whatif gestartet" 
                } else {
                    Write-Host "Deinstalliere Anydesk mit Befehl [$directory/$directoryName/$anyDeskBin --silent --remove]" 
                    Start-Process -NoNewWindow -FilePath `"$directory/$directoryName/$anyDeskBin`" -ArgumentList "--silent --remove"  -Wait
  
                    Write-Host "Entferne verbleibende Einträge in Programme und Funktionen"
                    $paths  = @("HKLM:\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall","HKLM:\SOFTWARE\\Wow6432node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")   

                    # Find installations with uninstallstring
                    foreach ($path in $paths) {
                        $msiInstallations = Get-Childitem -recurse -Path $path | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object {($_.Publisher -like "AnyDesk*") -or ($_.Publisher -like "philandro*")} | Where-Object UninstallString -like "MsiExec.exe*"

                        # Try to uninstall them using msiexec
                        foreach($msiInstallation in $msiInstallations) {
                            Start-Process -NoNewWindow -FilePath "msiexec.exe" -ArgumentList "/X `"$msiInstallation.PSChildName`" /qn"  -Wait
                        }
                    }

                    foreach ($path in $paths) {
                        Get-Childitem -recurse -Path $path | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object {($_.Publisher -like "AnyDesk*") -or ($_.Publisher -like "philandro*")} | Remove-Item -Force
                    }
                    
                    Write-Host "Stoppe und entferne verbleibende AnyDesk Dienste"
                    removeAnyDeskServices
                    
                    taskkill /IM $anyDeskBin /F 
                    
                    Write-Host "Entferne Programmverzeichnis"
                    Remove-Item -Path $directory/$directoryName -Recurse -Force
                }
            }
        }
    }
}

function restartAnyDeskService() {
    Get-Service | where-object {$_.name -like '*AnyDesk*'} | ForEach-Object {
        Restart-Service -Name $_.Name -Force
    }
}

function configureForegroundAccess() {
    (Get-Content -Path $anyDeskConfigDirectory\system.conf) | Where-Object { $_ -notmatch "ad.security.interactive_access" } | set-content $anyDeskConfigDirectory\system.conf
    Add-Content -Path $anyDeskConfigDirectory\system.conf -Value "ad.security.interactive_access=1"
}

function addAcl() {
    $ids = $acl.Split(",")
    
    $line = ''
    
    foreach($id in $ids) {
        $line = $line + $id + ':true'
        
        if ($id -ne $ids[-1]) {
             $line = $line + ';'
        }
    }
    
    (Get-Content -Path $anyDeskConfigDirectory\system.conf) | Where-Object { $_ -notmatch "ad.security.acl_enabled" } | set-content $anyDeskConfigDirectory\system.conf
    (Get-Content -Path $anyDeskConfigDirectory\system.conf) | Where-Object { $_ -notmatch "ad.security.acl_list" }  | set-content $anyDeskConfigDirectory\system.conf
    Add-Content -Path $anyDeskConfigDirectory\system.conf -Value "ad.security.acl_enabled=true"
    Add-Content -Path $anyDeskConfigDirectory\system.conf -Value "ad.security.acl_list=$line"
}

function removeAnyDeskServices() {
    Get-Service | where-object {$_.name -like '*AnyDesk*'} | ForEach-Object {
        Stop-Service -Name $_.Name -Force
        sc.exe delete "$_.Name"
    }
}

function downloadAnydesk() {
    Invoke-WebRequest -Uri $anyDeskWindowsUrl -OutFile $downloadedAnydeskFile

    if ((Get-AuthenticodeSignature $downloadedAnydeskFile).Status -ne 'Valid') {
        Write-Host "Anydesk hat ungültige Signature. Skript abgebrochen"

        Remove-Item -Path $downloadedAnydeskFile -Force

        exit
    }
}

function installAnyDesk($download) {
    if ($download -eq $true) {
        Write-Host "Downloade Anydesk"
        downloadAnydesk
    }

    if ($WhatIfPreference) {
       Write-Host "AnyDesk Installation würde mit [$downloadedAnydeskFile --install $anyDeskTargetinstallDirectory --start-with-win --create-desktop-icon --create-shortcuts --silent --update-auto] versucht werden, wird jedoch nicht ausgeführt, da Skript mit -Whatif gestartet" 
    } else {
       Write-Host "Installiere Anydesk mit [$downloadedAnydeskFile --install "$anyDeskTargetinstallDirectory" --start-with-win --create-desktop-icon --create-shortcuts --silent --update-auto]"
       Start-Process -NoNewWindow -FilePath $downloadedAnydeskFile -ArgumentList "--install `"$anyDeskTargetinstallDirectory`" --start-with-win --create-desktop-icon --create-shortcuts --silent --update-auto" -Wait

       sleep(10)

       if ($license) {
           Write-Host "Registriere Anydesk Lizenz"
           (echo $license | cmd /c "`"$installedAnyDeskBin`" --register-license") 
       }
       
       if ($onlyForegroundAccess) {
            configureForegroundAccess
       }
       
       if ($acl) {
           addAcl         
       }
    }
    
    sleep(5)

    Remove-Item -Path $downloadedAnydeskFile
}

function retainId() {
    Get-Childitem -Path $anyDeskConfigDirectory -Recurse -Include "service.conf" | sort LastWriteTime | select -last 1 | Move-Item -Destination $anyDeskConfigDirectory\service.conf
}

function removeAndInstall() {
    downloadAnydesk

    removeInstallations

    retainId

    installAnyDesk $false
}

Switch($mode) {
    "remove" {
        removeInstallations
    }
    "download" {
        downloadAnydesk
    }
    "install" {
        installAnyDesk $true
    }
    "remove_and_install" {
        removeAndInstall
    }
}
