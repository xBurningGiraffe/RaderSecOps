
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
        }
    } elseif ($AllCWClient.types.name -eq "Security - Light") {
        [PSCustomObject]@{
            Name = $AllCWClient.name
            CW_Id = $AllCWClient.id
            Stack_Type = "Light"
        }
    } elseif ($AllCWClient.types.name -eq "Security - Enhanced") {
        [PSCustomObject]@{
            Name = $AllCWClient.name
            CW_Id = $AllCWClient.id
            Stack_Type = "Enhanced"
        }
    }
}

$GetSecClients

