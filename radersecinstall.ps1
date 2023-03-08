    $FolderPath = "$env:ProgramFiles\WindowsPowerShell\Modules"
    $Url = "https://github.com/xBurningGiraffe/RaderSecOps/archive/refs/heads/main.zip"
    $DownloadPath = "$FolderPath\RaderSecOps.zip"
    Invoke-WebRequest -Uri $Url -OutFile $DownloadPath
    Expand-Archive $FolderPath\RaderSecOps.zip -DestinationPath $FolderPath -Force
    Remove-Item $FolderPath\RaderSecOps -Recurse -Force -ErrorAction SilentlyContinue
    Move-Item $FolderPath\RaderSecOps-main $FolderPath\RaderSecOps -Force
   $ImportRadersec = 'Import-Module -Name RaderSecOps'
   $ImportIntune = 'Import-Module -Name "$env:ProgramFiles\WindowsPowerShell\Modules\RaderSecOps\Start-IntuneManagement.psm1"'
   $CheckProfile = (Get-Content $Profile)
   if ($CheckProfile -notcontains $ImportRadersec -or $ImportIntune) {
    Write-Output 'Import-Module -Name RaderSecOps' > $Profile
    Write-Output 'Import-Module -Name "$env:ProgramFiles\WindowsPowerShell\Modules\RaderSecOps\Start-IntuneManagement.psm1"' >> $Profile
}
Remove-Item $DownloadPath
