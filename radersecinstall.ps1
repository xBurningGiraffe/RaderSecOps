    
    
    $FolderPath = "$($env:ProgramFiles)\WindowsPowerShell\Modules"
    $Url = "https://github.com/xBurningGiraffe/RaderSecOps/archive/refs/heads/main.zip"
    $DownloadPath = "$FolderPath\RaderSecOps.zip"
    $ExtractPath = "$FolderPath\RaderSecOps"

    # Check if the RaderSecOps folder exists and remove it if it does
    if (Test-Path "$FolderPath\RaderSecOps") {
        Remove-Item "$FolderPath\RaderSecOps" -Recurse -Force
    }
    
    # Download the RaderSecOps module from the URL
    Invoke-WebRequest -Uri $Url -OutFile $DownloadPath

    # Extract the contents of the .zip file to a temporary folder
    $TempPath = "$FolderPath\RaderSecOps-main"
    Expand-Archive -Path $DownloadPath -DestinationPath $TempPath

# If the extracted folder is named "RaderSecOps-main", move its contents to $ExtractPath
    if (Test-Path "$TempPath\RaderSecOps-main") {
        Move-Item "$TempPath\RaderSecOps-main\*" -Destination $ExtractPath
    }

# Remove the temporary folder
    Remove-Item $TempPath -Recurse -Force

    $ProfilePath = "$($env:USERPROFILE)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
      if (!(Get-Content $ProfilePath | Select-String -SimpleMatch 'Import-Module -Name RaderSecOps') -or !(Get-Content $ProfilePath | Select-String -SimpleMatch 'Import-Module -Name "$env:ProgramFiles\WindowsPowerShell\Modules\RaderSecOps\Start-IntuneManagement.psm1"')) {
    Write-Output 'Import-Module -Name RaderSecOps' >> $ProfilePath
    Write-Output 'Import-Module -Name "$env:ProgramFiles\WindowsPowerShell\Modules\RaderSecOps\Start-IntuneManagement.psm1"' >> $ProfilePath
    Write-Output 'Import-Module -Name Hawk' >> $ProfilePath
    }

    Import-Module -Name RaderSecOps





