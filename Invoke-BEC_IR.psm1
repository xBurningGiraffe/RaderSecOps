Function Invoke-BEC_IR {

     # Check for HAWK
    if (!(Get-Module -ListAvailable | Where-Object {$_.Name -eq "Hawk"})) {
      ModuleInstalls
    } else {
      Import-Module Hawk
    }

  Function BEC_Menu {
    Write-Host "------------ BEC_IR Menu ------------" -ForegroundColor DarkGreen
    Write-Host ""
    Write-Host "  [0] Post to Compromises Teams channel" -ForegroundColor DarkMagenta
    Write-Host "  [1] Start Hawk Investigation" -ForegroundColor DarkMagenta
    Write-Host "  [2] Generate BEC IR report" -ForegroundColor DarkMagenta
    Write-Host "  [A] Run all functions" -ForegroundColor DarkMagenta
    Write-Host "  [R] Return to RaderSecOps menu" -ForegroundColor DarkRed
    Write-Host ""

    $input = Read-Host "Select an option"

    switch ($input) {
      '0' {
        PwnPost
        Start-Sleep -Seconds 2
      }
      '1' {
        Hawk
        Start-Sleep -Seconds 2
      }
      '2' {
        BEC_IR
        Start-Sleep -Seconds 2
      }
      'A' {
        AllFunctions
        Start-Sleep -Seconds 2
      }
      'R' {
        return
      }
    }
  }
    # Post alert to compromises channel
    Function PwnPost {
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "First, connect to your Rader Solutions account: "
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Connect-AzAccount
    Start-Sleep -s 15
    $Pwned = Read-Host  'Enter the compromised user email address'
    try {
      $PwnData = @{
        Company = Read-Host 'Enter the company name '
        User    = $Pwned
        Ticket  = Read-Host 'Enter the ticket number '
        IOC     = Read-Host 'Enter the IOC '
      }
      $PwnMessage = @{
        "text"     = "Alert: Security Incident"
        "sections" = @(
          @{
            "facts" = $PwnData.GetEnumerator() | ForEach-Object {
              @{
                "name"  = $_.Key
                "value" = $_.Value
              }
            }
          }
        )
      }
      $message = $PwnMessage | ConvertTo-Json -Depth 99

      $PwnHook = Get-AzKeyVaultSecret -VaultName 'raderseckeys' -Name 'pwn-webhook' -AsPlainText
        
      Invoke-RestMethod -Uri $PwnHook -Method Post -Body $message -ContentType "Application/Json"
    }
    catch { 
      Write-Error "Error posting message in Compromises Team channel: $($_.Exception.Message)"
    }
  }

  Function Hawk {
    try {

    Start-HawkUserInvestigation -UserPrincipalName $Pwned
    
    } catch {

      Write-Error "Error starting Hawk investigation for user account: $($_.Exception.Message)"
    
    }
  }

  Function BEC_IR {

    try {
    # Creating BEC_IR Report via Python (bec_report.py)

   
    $CurrPath = "$env:PROGRAMFILES\WindowsPowershell\Modules\RaderSecOps"
    $DocPath = "$env:PROGRAMFILES\WindowsPowershell\Modules\RaderSecOps\BEC_IR_REPORT.docx"

    # Check for bec_report.py
    if (!(Test-Path "$FilePath\bec_report.py")) {

      Write-Host "bec_report.py was not detected in this directory. Downloading from Github..." -ForegroundColor DarkRed
      Invoke-WebRequest -Uri "https://raw.githubusercontent.com/xBurningGiraffe/RaderSecOps/main/bec_report.py" -OutFile "$env:PROGRAMFILES\WindowsPowershell\Modules\RaderSecOps\bec_report.py"
      Unblock-File -Path "$env:PROGRAMFILES\WindowsPowershell\Modules\RaderSecOps\bec_report.py"

    } elseif (!(Test-Path "$FilePath\BEC_IR_REPORT.docx")) {
      
      Write-Host "BEC_IR_REPORT not detected. Downloading from Github..." 
      Invoke-WebRequest -Uri "https://github.com/xBurningGiraffe/RaderSecOps/raw/main/BEC_IR_REPORT.docx" -OutFile "$FilePath\BEC_IR_REPORT.docx"
      Unblock-File -Path "$FilePath\BEC_IR_REPORT.docx"
    
    }

    $Company = $PwnData.Company
    $User = $Pwned
    $Ticket = $PwnData.Ticket

    $PythonPath = (Get-Command python3).Source
    $PythonScript = "$CurrPath\bec_report.py"

    Start-Process -FilePath $PythonPath -ArgumentList $PythonScript, "-CurrPath", $CurrPath, "-User", $User, "-Company", $Company, "-Ticket", $Ticket -NoNewWindow -Wait
    
  } catch {

      Write-Error "Error creating BEC IR report: $($_.Exception.Message)"

    }

  }

  Function AllFunctions {
    PwnPost
    Hawk
    BEC_IR
  }

  BEC_Menu
}