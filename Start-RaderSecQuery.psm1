Function Start-RaderSecQuery {
Write-Host "Initializing...one moment" -ForegroundColor DarkMagenta
# Start transcript for reference
try {
    Stop-Transcript *> $null
}
catch [System.InvalidOperationException] {
    # Caught error
}
$LogDate = (Get-Date | select-object day, month, year)
$LogName = "RaderSecQuery_$($LogDate.day)_$($LogDate.month)_$($LogDate.year)"
try {
    Start-Transcript -Path $env:USERPROFILE\$LogName.log -Append *> $null
}
catch {
    # Caught message
}

<#function ExecuteMultiLineCommand {
    param([string]$commandText)

    $commandText = $commandText -replace '\r?\n', '; '
    $commands = $commandText -split "; "

    foreach ($cmd in $commands) {
        if ($cmd.Trim() -ne "") {
            # Write-Host "Executing: $cmd"
            Invoke-Expression $cmd
        }
    }
}#>

# Import and install missing modules

$Modules = @('PartnerCenter', 'Az.Accounts', 'Az.KeyVault', 'ConnectwiseManageAPI')
foreach ($Module in $Modules) {
    if (-not (Get-Module -ListAvailable -Name "$Module")) {
        Write-Host "Installing the $Module module..." -ForegroundColor DarkMagenta
        Install-Module -Name "$Module" -Repository "PSGallery" -Scope "CurrentUser"
        if (Get-Module -ListAvailable -Name "$Module") {
            Import-Module -Name $Module
        }
    }
}

# Connect to Rader AzAccount #

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    Write-Host "To begin, connect to your Rader Azure account when prompted..." -ForegroundColor DarkGreen
    Start-Sleep -Seconds 15
    Connect-AzAccount
}


# ---------------------Connect to PartnerCenter -----------#
## PartnerCenter Connection and Loop Section ##
$ApplicationId = Get-AzKeyVaultSecret -VaultName 'azb-keys' -Name 'cspWebAppID' -AsPlainText
$ApplicationSecret = Get-AzKeyVaultSecret -VaultName 'azb-keys' -Name 'cspAppSecret' -AsPlainText | Convertto-SecureString -AsPlainText -Force
$TenantID = Get-AzKeyVaultSecret -VaultName 'azb-keys' -Name 'tenantId' -AsPlainText
$RefreshToken = Get-AzKeyVaultSecret -VaultName 'azb-keys' -Name 'cspAppRefreshToken' -AsPlainText
$ExchangeRefreshToken = Get-AzKeyVaultSecret -VaultName 'azb-keys' -Name 'exoRefreshToken' -AsPlainText
$credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $ApplicationSecret)
$UPN = "cfontenot@radersolutions.com"


$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID
function getPartnerToken { 
    return New-PartnerAccessToken -ApplicationId $ApplicationId -RefreshToken $RefreshToken -Scopes 'https://api.partnercenter.microsoft.com/user_impersonation' -ServicePrincipal -Credential $credential -Tenant $tenantId
}
$token = (getPartnerToken).AccessToken

$PCAccessToken = getPartnerToken
Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken
Connect-PartnerCenter -AccessToken $PCAccessToken.AccessToken

# --------------------- Connect to CW Manage API ----------------------- #

$CWMConnectionInfo = @{
    Server     = 'api-na.myconnectwise.net'
    Company    = 'rader'
    PrivateKey = Get-AzKeyVaultSecret -VaultName 'raderseckeys' -Name 'cwmprivkey' -AsPlainText
    PubKey     = Get-AzKeyVaultSecret -VaultName 'raderseckeys' -Name 'cwmpubkey' -AsPlainText
    clientId   = Get-AzKeyVaultSecret -VaultName 'raderseckeys' -name 'cwm-clientid' -AsPlainText
}

Connect-CWM @CWMConnectionInfo

# ------------------------ Initial Menu ------------------------- #

Function SingleClient {
    param(
        [string]$command, [string]$clientName
    )
    try { 
        $SingleClientDomain = $matchedClient.Domain
        Write-host "Connecting to the Exchange managed console for $($matchedclient.name)" -ForegroundColor DarkCyan
    
        Write-host "Executing commands for $($matchedclient.Name)" -ForegroundColor DarkGreen
        $token = New-PartnerAccessToken -ApplicationId 'a0c73c16-a7e3-4564-9a95-2bdf47383716'-RefreshToken $ExchangeRefreshToken -Scopes 'https://outlook.office365.com/.default' -Tenant $matchedclient.tenantId *> $null
        $tokenValue = ConvertTo-SecureString "Bearer $($token.AccessToken)" -AsPlainText -Force
        $credentialExchange = New-Object System.Management.Automation.PSCredential($upn, $tokenValue)
    
        $ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://ps.outlook.com/powershell-liveid?DelegatedOrg=$($SingleClientDomain)&BasicAuthToOAuthConversion=true" -Credential $credentialExchange -Authentication Basic -AllowRedirection -erroraction Stop *> $null
        Import-PSSession -Session $ExchangeOnlineSession -AllowClobber -DisableNameChecking
        ##
        Write-Host "$matchedclient.Name Results"
        & $command
        
        ##
        Remove-PSSession $ExchangeOnlineSession
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)"
        # continue
    }
}
<#Function AllClients {
    param ([string]$command) 
    try {
        Write-Host "Starting execution of commands for all clients." -ForegroundColor DarkMagenta
        foreach ($AllSecurityClient in $AllSecurityClients) {
            $CustomerDomain = $AllSecurityClient.Domain

            Write-host "Executing commands for $($AllSecurityClient.Name)" -ForegroundColor DarkYellow
            try {
                $token = New-PartnerAccessToken -ApplicationId 'a0c73c16-a7e3-4564-9a95-2bdf47383716'-RefreshToken $ExchangeRefreshToken -Scopes 'https://outlook.office365.com/.default' -Tenant $AllSecurityClient.tenantId
                $tokenValue = ConvertTo-SecureString "Bearer $($token.AccessToken)" -AsPlainText -Force
                $credentialExchange = New-Object System.Management.Automation.PSCredential($upn, $tokenValue)

                $ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://ps.outlook.com/powershell-liveid?DelegatedOrg=$($CustomerDomain)&BasicAuthToOAuthConversion=true" -Credential $credentialExchange -Authentication Basic -AllowRedirection -erroraction Stop
                Import-PSSession -Session $ExchangeOnlineSession -AllowClobber -DisableNameChecking

                ExecuteMultiLineCommand $command

                Remove-PSSession $ExchangeOnlineSession
            }
            catch {
                Write-Host "An error occurred during the execution of the commands or the PowerShell session operations: $($_.Exception.Message)" -ForegroundColor DarkRed
            }
        }
        Write-Host "Finished executing commands for all clients." -ForegroundColor DarkGreen
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        continue
    }
}#>

Function AllClients {
    param ([string]$command) 
    try {
        Write-Host "Starting execution of commands for all clients." -ForegroundColor DarkMagenta
        foreach ($AllSecurityClient in $AllSecurityClients) {
            $CustomerDomain = $AllSecurityClient.Domain
            Write-host "Executing commands for $($AllSecurityClient.Name)" -ForegroundColor DarkYellow
            Write-Output "Executing commands for $($AllSecurityClient.Name)" | Out-File -FilePath "$env:USERPROFILE\AllClientsQuery_$LogName.log" -Append
            try {
                $token = New-PartnerAccessToken -ApplicationId 'a0c73c16-a7e3-4564-9a95-2bdf47383716'-RefreshToken $ExchangeRefreshToken -Scopes 'https://outlook.office365.com/.default' -Tenant $AllSecurityClient.tenantId
                $tokenValue = ConvertTo-SecureString "Bearer $($token.AccessToken)" -AsPlainText -Force
                $credentialExchange = New-Object System.Management.Automation.PSCredential($upn, $tokenValue)

                $ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://ps.outlook.com/powershell-liveid?DelegatedOrg=$($CustomerDomain)&BasicAuthToOAuthConversion=true" -Credential $credentialExchange -Authentication Basic -AllowRedirection -erroraction Stop
                Import-PSSession -Session $ExchangeOnlineSession -AllowClobber -DisableNameChecking

                Write-Host "$AllSecurityClient.Name Results"
                & $command

                Remove-PSSession $ExchangeOnlineSession
            }
            catch {
                Write-Host "An error occurred during the execution of the commands or the PowerShell session operations: $($_.Exception.Message)" -ForegroundColor DarkRed
            }
        }
        Write-Host "Finished executing commands for all clients." -ForegroundColor DarkGreen
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
    }
}

Function AllPartnerCustomers {
    param ([string]$command)
    $customers = Get-PartnerCustomer
    try {
        foreach ($customer in $customers) {
            try {
                $CustomerDomain = $customer.Domain
                Write-host "Connecting to the Exchange managed console for client $($customer.name)"

                Write-host "Running for $($Customer.Name)" -ForegroundColor Green
                $token = New-PartnerAccessToken -ApplicationId 'a0c73c16-a7e3-4564-9a95-2bdf47383716'-RefreshToken $ExchangeRefreshToken -Scopes 'https://outlook.office365.com/.default' -Tenant $customer.customerId
                $tokenValue = ConvertTo-SecureString "Bearer $($token.AccessToken)" -AsPlainText -Force
                $credentialExchange = New-Object System.Management.Automation.PSCredential($upn, $tokenValue)

                $ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://ps.outlook.com/powershell-liveid?DelegatedOrg=$($CustomerDomain)&BasicAuthToOAuthConversion=true" -Credential $credentialExchange -Authentication Basic -AllowRedirection -erroraction Stop
                Import-PSSession -Session $ExchangeOnlineSession -AllowClobber -DisableNameChecking
                ##

                Write-Host "$Customer.Name Results"
                & $command
    

                ##
                Remove-PSSession $ExchangeOnlineSession
            }
            catch {
                Write-Host "Error: $($_.Exception.Message)"
                continue
            }
        } 
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
    }

}




Function ExecuteCommands {
    $Customers = Get-PartnerCustomer
    $continueLoop = $true
    while ($continueLoop) {
        $CWSecurityClients = @{
            childconditions = "types/name='Security - Baseline' OR types/name='Security - Light' OR types/name='Security - Enhanced'"
            fields = "id,name,types/name,userdefinedfield10"
            pageSize = "1000"
        }

        $AllSecurityClients = Get-CWMCompany @CWSecurityClients | ForEach-Object {
            $matchedStackType = $_.types | Where-Object { $_ -like "*Security - *" }
            $tenantId = ($_.UserDefinedField10 -replace '^\s+', '') -replace '\s+$', ''
            $Customer = $Customers | Where-Object { $_.customerId -eq $tenantId }
            if ($Customer) {
                [PSCustomObject]@{
                    Name      = $_.Name
                    CWID      = $_.Id
                    StackType = $matchedStackType -replace '.*Security - (.*)}', '$1'
                    TenantId  = $tenantId
                    Domain    = $Customer.Domain
                }
            }
        }

        $validChoices = @('1', '2', '3', 'q')
        $selectedChoice = $null

        while ($selectedChoice -notin $validChoices) {
            Clear-Host
            Write-Host "Please select an option:" -ForegroundColor DarkYellow
            Write-Host "1. Execute command for a single client" -ForegroundColor DarkMagenta
            Write-Host "2. Execute command for all RADER Security clients" -ForegroundColor DarkMagenta
            Write-Host "3. Execute command for all customers in PartnerCenter" -ForegroundColor DarkMagenta
            Write-Host "q. Quit" -ForegroundColor DarkRed
            $selectedChoice = Read-Host "Enter your choice"
        }

        switch ($selectedChoice) {
            '1' {
                $clientName = Read-Host "Enter the name of the client"
                $matchedClient = $AllSecurityClients | Where-Object { $_.Name -eq $clientName }
                if ($matchedClient) {
                    $confirmationMessage = "Did you mean $($matchedClient.Name)? (y/n)"
                    $confirm = Read-Host $confirmationMessage
                    if ($confirm -eq 'y') {
                        Write-Host "Enter the commands to execute for $($matchedClient.Name), press enter on a blank line to finish" -ForegroundColor DarkGreen
                        $command = ""
                        do {
                            $inputLine = Read-Host
                            if ($inputLine -ne "") {
                                $command += $inputLine + "`n"
                            }
                        } while ($inputLine -ne "")
                        $commandBlock = [scriptblock]::Create($command)
                        SingleClient -command $commandBlock -clientname $matchedClient.Name
                    }
                    elseif ($confirm -eq 'n') {
                        $suggestion = $AllSecurityClients | Where-Object { $_.Name -like "*$clientName*" }
                        if ($suggestion) {
                            Write-Host "Client '$clientName' not found. Did you mean $($suggestion.Name)?" -ForegroundColor DarkRed
                            $confirm = Read-Host "(y/n)"
                            if ($confirm -eq 'y') {
                                Write-Host "Enter the commands to execute for $($suggestion.Name). Press enter on a blank line to finish"
                                $command = ""
                                do {
                                    $inputLine = Read-Host
                                    if ($inputLine -ne "") {
                                        $command += $inputLine + "`n"
                                    }
                                } while ($inputLine -ne "")
                                $commandBlock = [scriptblock]::Create($command)
                                SingleClient -command $commandBlock -clientname $matchedClient.Name
                            }
                        }
                        else {
                            Write-Host "Client '$clientname' not found"
                        }
                    }
                }
            }                        
            '2' {
                Write-Host "Enter the command to execute for all clients. Press enter on a blank line to finish"
            
                # Collect user input as a string
                $commandString = ""
                do {
                    $inputLine = Read-Host
                    if ($inputLine -ne "") {
                        $commandString += $inputLine + "`n"
                    }
                } while ($inputLine -ne "")
            
                # Convert the string to a script block
                $command = [scriptblock]::Create($commandString)
            
                # Execute the command
                AllSecurityClients -command $command
            
                $continueLoop = $false
                break
            }
            '3' {
                Write-Host "Enter the command to execute for all PartnerCenter clients. Press enter on a blank line to finish"

                $commandString = ""
                do {
                    $inputLine = Read-Host
                    if ($inputLine -ne "") {
                        $commandString += $inputLine + "`n"
                    }
                } while ($inputLine -ne "")

                $command = [scriptblock]::Create($commandString)

                PCClients -command $command

                $continueLoop = $false
                break
            }                        
            'q' {
                $continueLoop = $false
                Disconnect-AzAccount
            }
        }

        $prompt = "Do you want to return to the main menu? (y/n)"
        $choice = Read-Host $prompt
        if ($choice -ne 'y') {
            $continueLoop = $false
        }
    }
}

ExecuteCommands
}



