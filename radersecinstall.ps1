  # Pull RaderSecOps from GitHub
    Invoke-WebRequest -Uri https://github.com/xBurningGiraffe/RaderSecOps/archive/refs/heads/main.zip -OutFile main.zip
    Expand-Archive main.zip -DestinationPath $env:ProgramFiles\WindowsPowerShell\Modules\main -Force
    if (Get-ChildItem -Path 'C:\Program Files\windowspowershell\Modules\RaderSecOps') {
    try {
     Remove-Item 'C:\Program Files\windowspowershell\Modules\RaderSecOps' -Recurse -ErrorAction SilentlyContinue
     }
     catch {
     Write-Error "Error: $($_.Exception.Message)"
     }
    Move-Item 'C:\Program Files\windowspowershell\Modules\main\RaderSecOps-main' 'C:\Program Files\windowspowershell\Modules\RaderSecOps' -Force
    Remove-Item 'C:\Program Files\windowspowershell\Modules\main' -Recurse
    # Import new modules
    Import-Module -Name RaderSecOps
    Import-Module -Name 'C:\Program Files\WindowsPowerShell\Modules\RaderSecOps\IntuneManagement.psd1'
    # Add module imports to $Profile
   $ImportRadersec = 'Import-Module -Name RaderSecOps'
   $ImportIntune = 'Import-Module -Name "C:\Program Files\WindowsPowerShell\Modules\RaderSecOps\IntuneManagement.psd1"'
   $CheckProfile = (Get-Content $Profile)
   if ($CheckProfile -notcontains $ImportRadersec -or $ImportIntune) {
    Write-Output 'Import-Module -Name RaderSecOps' > $Profile
    Write-Output 'Import-Module -Name "$env:ProgramFiles\WindowsPowerShell\Modules\RaderSecOps\Start-IntuneManagement.psm1"' >> $Profile
    }
    Remove-Item main.zip
    try {
    Remove-Item radersecinstall.ps1
    }
    catch {
    Write-Error "Error "Error: $($_.Exception.Message)"
    }
