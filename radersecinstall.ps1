  # Pull RaderSecOps from GitHub
$RaderSec_Path = "$env:ProgramFiles\WindowsPowershell\Modules\RaderSecOps"  
  Invoke-WebRequest -Uri https://github.com/xBurningGiraffe/RaderSecOps/archive/refs/heads/main.zip -OutFile main.zip -ErrorAction SilentlyContinue
    Expand-Archive main.zip -DestinationPath "$env:ProgramFiles\WindowsPowerShell\Modules\main" -Force -ErrorAction SilentlyContinue
    if (Get-ChildItem -Path "$env:ProgramFiles\WindowsPowerShell\Modules\main") {
    try {
     Remove-Item $RaderSec_Path -Recurse -ErrorAction SilentlyContinue
     } catch {
     Write-Error "Error: $($_.Exception.Message)"
     }
}
    Move-Item 'C:\Program Files\windowspowershell\Modules\main\RaderSecOps-main' 'C:\Program Files\windowspowershell\Modules\RaderSecOps' -Force
    Remove-Item 'C:\Program Files\windowspowershell\Modules\main' -Recurse -ErrorAction SilentlyContinue
    # Import new modules
    Import-Module -Name RaderSecOps
    Import-Module -Name 'C:\Program Files\WindowsPowerShell\Modules\RaderSecOps\IntuneManagement.psd1'
    # Add module imports to $Profile
   $ImportRadersec = 'Import-Module -Name RaderSecOps'
   $ImportIntune = 'Import-Module -Name "C:\Program Files\WindowsPowerShell\Modules\RaderSecOps\IntuneManagement.psd1"'
   $CheckProfile = (Get-Content $Profile)
   if ($CheckProfile -notcontains $ImportRadersec -or $ImportIntune) {
    Write-Output 'Import-Module -Name RaderSecOps' > $Profile
    Write-Output "Import-Module -Name $($ImportIntune)" >> $Profile
    }
