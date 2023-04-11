param (
    [switch]$SortName,
    [switch]$SortStack,
    [switch]$SortCW_ID
)

# Check for AzAccount, Az.KeyVault and PartnerCenter modules

$Modules = @('PartnerCenter','Az.Accounts','Az.KeyVault')

foreach ($Module in $Modules) {
    if (-not (Get-Module -ListAvailable -Name "$Module")) {
        Install-Module -Name "$Module" -Repository "PSGallery" -Scope "CurrentUser"
        if (Get-Module -ListAvailable -Name "$Module") {
            Import-Module -Name $Module
        }
    }
}


# Check for existing AzAccount, AzKeyVault and PartnerCenter connections

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    Connect-AzAccount
}

if (-not (Get-PartnerCustomer -ErrorAction SilentlyContinue)) {
    Connect-PartnerCenter
}


$CWMApi = Get-AzKeyVaultSecret -VaultName 'azb-keys' -Name 'cwmapikey' -AsPlainText
$CWMId = Get-AzKeyVaultSecret -VaultName 'raderseckeys' -Name 'cwm-clientid' -AsPlainText
$CWAccept = "application/vnd.connectwise.com+json; version=v2022_2"
$CWCompanies = "https://api-na.myconnectwise.net/v2022_2/apis/3.0/company/companies"

$Headers = @{
    Authorization = $CWMApi
    clientId = $CWMId
    Accept = $CWAccept
}

$CWParams = @{
    orderBy = "name"
    pageSize = "1000"
}

# Get all CW clients
$GetCWClients = Invoke-RestMethod -Uri $CWCompanies -Method Get -Headers $Headers -Body $CWParams

# Get PartnerCenter clients

$GetPCClients = Get-PartnerCustomer

# Add missing security clients
#$MissingCWIds = "19844"
#$MissingPCs = $PC_Customers | Where-Object { $_.customerId -in $MissingPCIds }
#$MissingCWs = $AllCWClients | Where-Object {$_.Id -in $MissingCWIds}
# $AllCWClients = $GetCWClients | Select-Object Name, ID, UserDefinedField10, Types

$PC_Customers.customerId | Where-Object { $_ -in $AllCWClients.UserDefinedField10 }

# Filter and sort Security clients from CW list

$CW_SecClients = $GetCWClients | Where-Object { $_.types.name -like 'Security*' } | foreach {
    [PSCustomObject]@{
        Name = $_.Name
        CWId = $_.ID
        SecType = $_.types.name
        CUID = $_.UserDefinedField10
    }
}

$PC_SecClients = $GetPCClients | Where-Object { ($CW_SecClients.Name -like "$($_.Name)*") } | ForEach-Object {
    $PCClient = $_
    $MatchingCWClient = $CW_SecClients | Where-Object { $PCClient.customerId -eq $_.CUID -or $PCClient.Name -like "$($_.Name)*" }
    [PSCustomObject]@{
        Name = $MatchingCWClient.Name
        CWId = $MatchingCWClient.CWId
        SecType = $MatchingCWClient.SecType
        customerId = $PCClient.CustomerId
    }
}

$MissingPC_SecClients = Compare-Object -ReferenceObject $CW_SecClients -DifferenceObject $PC_SecClients -Property Name, SecType, customerId -PassThru | Where-Object { $_.SideIndicator -eq '<=' }

# Combine $PC_SecClients with $MissingPC_SecClients without adding redundancies

$CombinedPC_SecClients = @()
$UniqueNames = @{}

foreach ($Client in ($PC_SecClients + $MissingPC_SecClients)) {
    if ($null -ne $Client.Name -and -not ($UniqueNames.Keys -contains $Client.Name)) {
        $UniqueNames[$Client.Name] = $true

        if ($Client.CUID) {
            $customerId = $Client.CUID
        } else {
            $customerId = $Client.customerId
        }

        $CombinedClient = [PSCustomObject]@{
            Name       = $Client.Name
            CWId       = $Client.CWId
            SecType    = $Client.SecType
            customerId = $customerId
        }

        $CombinedPC_SecClients += $CombinedClient
    }
}

$CombinedPC_SecClients



# Compare CW Security client count with PartnerCenter comparison

Write-Host "Security clients in CW = " = $CW_SecClients.Count

Write-Host "Security clients in PartnerCenter " = $CombinedPC_SecClients.Count

$table = New-Object System.Data.DataTable

$table.Columns.Add("Name", [string])
# 
$table.Columns.Add("CustomerId", [string])
$table.Columns.Add("SecType", [string])

foreach ($Client in $CombinedPC_SecClients) {
    $row = $table.NewRow()
    $row["Name"] = $Client.Name
    $row["CUID"] = $Client.CUID
    $row["CustomerID"] = $Client.customerId
    
    # Remove everything except the "Security - .*" portion from the SecType property
    $secTypeFiltered = $Client.SecType -replace "^(?!Security - ).*|(?<=Security - ).*$", ""
    $row["SecType"] = $secTypeFiltered
    
    $table.Rows.Add($row)
}

# Display the DataTable
$table | Format-Table



if ($SortName) {
    $CombinedPC_SecClients | Sort-Object -Property Name
}

if ($SortStack) {
    $CombinedPC_SecClients | Sort-Object -Property SecType
}

if ($SortCW_Id) {
    $CombinedPC_SecClients | Sort-Object -Property CustomerId
}

# ------------------------------------------------------------------------------

# Correlate UserDefinedField10 IDs with PartnerCustomer Ids

# $GetParterCustomer = (Get-PartnerCustomer)

<#$CW_PCs = foreach ($GetPartnerCustomer in $GetParterCustomers) {
    [PSCustomObject]@{
        PC_CustomerName = $GetPartnerCustomer.Name
        PC_CustomerID = $GetPartnerCustomer.customerId
        PC_Domain = $GetPartnerCustomer.Domain
    }#>







$CW_PC_Match = $CW_PC | Select-Object Unique

$CW_PC_Match | Format-Table #>