$FolderPath = "$($env:USERPROFILE)\OneDrive - Rader Solutions\Documents"

$Url = "https://github.com/xBurningGiraffe/RaderSecOps/archive/refs/heads/main.zip"
$DownloadPath = "$folderPath\RaderSecOps.zip"
Invoke-WebRequest -Uri $Url -OutFile $DownloadPath
Expand-Archive -Path $DownloadPath -DestinationPath $FolderPath -Force


Import-Module $FolderPath\RaderSecOps\Invoke-RaderSec.psm1
