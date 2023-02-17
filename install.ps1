$FolderPath = "$($env:ProgramFiles)\WindowsPowerShell\Modules"
$Url = "https://github.com/xBurningGiraffe/RaderSecOps/archive/refs/heads/main.zip"
$DownloadPath = "$folderPath\RaderSecOps.zip"
Invoke-WebRequest -Uri $Url -OutFile $DownloadPath

Expand-Archive $FolderPath\RaderSecOps.zip -DestinationPath $FolderPath -Force
Move-Item $FolderPath\RaderSecOps-main $FolderPath\RaderSecOps
echo 'Import-Module -Name RaderSecOps' >> $Profile
Import-Module -Name RaderSecOps
