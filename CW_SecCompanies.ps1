param (
    [switch]$SortName,
    [switch]$SortStack,
    [switch]$SortCW_ID
)

# Check AzAccount connection

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    Write-Host "No AzAccount connection detected. Connecting..."
    Connect-AzAccount
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

$AllCWClients = Invoke-RestMethod -Uri $CWCompanies -Method Get -Headers $Headers -Body $CWParams

$GetSecClients = foreach($AllCWClient in $AllCWClients) {
    if ($AllCWClient.types.name -eq "Security - Baseline") {
        [PSCustomObject]@{
            Name = $AllCWClient.name
            CW_Id = $AllCWClient.id
            Stack_Type = "Baseline"
            ID = $AllCWClient.UserDefinedField10
        }
    } elseif ($AllCWClient.types.name -eq "Security - Light") {
        [PSCustomObject]@{
            Name = $AllCWClient.name
            CW_Id = $AllCWClient.id
            Stack_Type = "Light"
            ID = $AllCWClient.UserDefinedField10
            
        }
    } elseif ($AllCWClient.types.name -eq "Security - Enhanced") {
        [PSCustomObject]@{
            Name = $AllCWClient.name
            CW_Id = $AllCWClient.id
            Stack_Type = "Enhanced"
            ID = $AllCWClient.UserDefinedField10
        }
    }
}

if ($SortName) {
    $GetSecClients | Sort-Object -Property Name
}

if ($SortStack) {
    $GetSecClients | Sort-Object -Property Stack_Type
}

if ($SortCW_Id) {
    $GetSecClients | Sort-Object -Property Id
}


# Correlate UserDefinedField10 IDs with PartnerCustomer Ids


Function CorrelateCustomers {

foreach ($GetSecClient in $GetSecClients) {
    $CheckName = Get-PartnerCustomer | Where-Object { $_.Name -like $GetSecClient.Name }
    $CheckId =Get-PartnerCustomer | Where-Object { $_.customerId -like $GetSecClient.Id }
    if ($CheckName){
    [PSCustomObject]@{
        Client_Name = $CheckName.Name 
    }
} elseif ($CheckId) {
    [PSCustomObject]@{
        Client_Id = $CheckId.customerId
        }
    }
}
}

CorrelateCustomers | Sort-Object -Unique