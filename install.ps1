$FolderPath = "$($env:USERPROFILE)\OneDrive - Rader Solutions\Documents"
$Url = "https://github.com/xBurningGiraffe/RaderSecOps/archive/refs/heads/main.zip"
$DownloadPath = "$folderPath\RaderSecOps.zip"
Invoke-WebRequest -Uri $Url -OutFile $DownloadPath
$FileCheck = Test-Path $FolderPath\WindowsPowerShell
$ModuleCheck = Test-Path $FileCheck\Modules

if ($FileCheck) {
  New-Item -ItemType Directory -Path $FolderPath\WindowsPowerShell -Force
}
if ($ModuleCheck) {
  New-Item -ItemType Directory -Path $FolderPath\WindowsPowerShell\Modules -Force
}

Expand-Archive -Path $DownloadPath -DestinationPath $FolderPath\WindowsPowerShell\Modules -Force
Move-Item '.\OneDrive - Rader Solutions\Documents\WindowsPowerShell\Modules\RaderSecOps-main\' '.\OneDrive - Rader Solutions\Documents\WindowsPowerShell\Modules\RaderSecOps'
Import-Module $FolderPath\WindowsPowerShell\Modules\RaderSecOps\Invoke-RaderSec.psm1
