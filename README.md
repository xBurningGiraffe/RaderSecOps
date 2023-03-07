# RaderSecOps
RaderSecOps Powershell module



The Swiss Army knife module for RaderSecOps

Install w/PowerShell


cd $env:USERPROFILE
Invoke-WebRequest -Uri https://raw.githubusercontent.com/xBurningGiraffe/RaderSecOps/main/radersecinstall.ps1 -OutFile radersecinstall.ps1; .\radersecinstall.ps1


v1.0.0
Still has plenty of work to do, functions to add, and changes to make thanks to Microsoft shifting around
their cmdlets...but this will do for now

v1.0.1
- Integrated IntuneManagement from Micke-K

v1.1.0
- Removed switches, will write alternative module with switches and no menu
- Configured logout function to check for existing connections
