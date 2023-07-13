Function Start-RaderSecQuery {
# $LogDate = (Get-Date | select-object day, month, year)
# $LogName = "RaderSecQuery_$($LogDate.day)_$($LogDate.month)_$($LogDate.year)"

<#function ExecuteMultiLineCommand {
    param([string]$commandText)

    # Create a script block from the command text
    $scriptBlock = [scriptblock]::Create($commandText)

    # Execute the script block
    Invoke-Expression $scriptBlock
}#>


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

$Keys = @{
    AppId = Get-AzKeyVaultSecret -VaultName 'azb-keys' -Name 'cspWebAppID' -AsPlainText
    AppSecret = Get-AzKeyVaultSecret -VaultName 'azb-keys' -Name 'cspAppSecret' -AsPlainText
    PartnerTenantID = Get-AzKeyVaultSecret -VaultName 'azb-keys' -Name 'tenantId' -AsPlainText
    RefreshToken = Get-AzKeyVaultSecret -VaultName 'azb-keys' -Name 'cspAppRefreshToken' -AsPlainText
    UPN = "cfontenot@radersolutions.com"
    ConsentScope = 'https://api.partnercenter.microsoft.com/user_impersonation'
    AppDisplayName = 'Partner Center Web App'
}

$AppCredential = (New-Object System.Management.Automation.PSCredential ($Keys.AppId, (ConvertTo-SecureString $Keys.AppSecret -AsPlainText -Force)))

# Connect to MsolService
$aadGraphToken = New-PartnerAccessToken -ApplicationId $Keys.AppId -Credential $Appcredential -RefreshToken $Keys.refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $Keys.PartnerTenantID
$graphToken = New-PartnerAccessToken -ApplicationId $Keys.AppId -Credential $Appcredential -RefreshToken $Keys.refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $Keys.PartnerTenantID
Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken

# Connect to PC
$PartnerAccessToken = New-PartnerAccessToken -ApplicationId $Keys.AppId -RefreshToken $Keys.RefreshToken -Scopes $Keys.ConsentScope -ServicePrincipal -Credential $AppCredential -Tenant $Keys.PartnerTenantID
Connect-PartnerCenter -AccessToken $PartnerAccessToken.AccessToken

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

Function AllSecurityClients {
    param ([scriptblock]$command) 
    try {
        foreach ($AllSecurityClient in $AllSecurityClients) {
            $CustomerTenantId = $AllSecurityClient.tenantId
            $Domain = $AllSecurityClient.Domain
            Write-Host "Executing commands for $($AllSecurityClient.Name)`r`n" -ForegroundColor DarkGreen
            try {
                $token = New-PartnerAccessToken -ApplicationId $Keys.AppId -Scopes 'https://outlook.office365.com/.default' -ServicePrincipal -Credential $Appcredential -Tenant $CustomerTenantId -RefreshToken $PartnerAccessToken.RefreshToken
                Connect-ExchangeOnline -DelegatedOrganization $CustomerTenantId -AccessToken $token.AccessToken

                & $command

                Disconnect-ExchangeOnline -Confirm:$false
            }
            catch {
                Write-Host "Error for $($AllSecurityClient.Name): $($_.Exception.Message)`r`n" -ForegroundColor DarkRed
                continue
            }
        }
        Write-Host "Finished executing commands for all clients." -ForegroundColor DarkGreen
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        "Error: $($_.Exception.Message)`r`n"
    }
}



Function SingleClient {
    param(
        [scriptblock]$command, 
        [string]$clientName
    )
    try { 
        $Domain = $matchedClient.Domain
        $SingleClientId = $matchedClient.tenantId
        Write-host "Connecting to the Exchange managed console for $($matchedclient.name)" -ForegroundColor DarkCyan
        Write-host "Executing commands for $($matchedclient.Name)" -ForegroundColor DarkGreen
        $token = New-PartnerAccessToken -ApplicationId $Keys.AppId -Scopes 'https://outlook.office365.com/.default' -ServicePrincipal -Credential $Appcredential -Tenant $CustomerTenantId -RefreshToken $PartnerAccessToken.RefreshToken
        Connect-ExchangeOnline -DelegatedOrganization $SingleClientId -AccessToken $token.AccessToken
        ##
        & $command

        Write-host "Commands for $($matchedclient.Name) have been executed successfully" -ForegroundColor DarkGreen
        Disconnect-ExchangeOnline -Confirm:$false
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        "Error: $($_.Exception.Message)`r`n"
    }
}

Function PCClients {
    param(
        [scriptblock]$command
    )
    try {
        foreach ($Customer in $Customers) {
            $Domain = $Customer.Domain
            $CustomerTenantId = $Customer.customerId
            Write-Host "Executing commands for $($Customer.Name)" -ForegroundColor DarkGreen
            $token = New-PartnerAccessToken -ApplicationId $keys.AppId -Scopes 'https://outlook.office365.com/.default' -ServicePrincipal -Credential $AppCredential -Tenant $CustomerTenantId -RefreshToken $PartnerAccessToken.RefreshToken
            Connect-ExchangeOnline -DelegatedOrganization $CustomerTenantId -AccessToken $token.AccessToken
            ##

            & $command
            Write-Host "Commands successful for $($Customer.name). Disconnecting" -ForegroundColor DarkGreen
            Disconnect-ExchangeOnline -Confirm:$false
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        "Error: $($_.Exception.Message)`r`n"
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
                } else {
                    Write-Host "No matching client found for the name: $ClientName" -ForegroundColor DarkRed
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


