Function Invoke-RaderIP_Hunter {
# $SearchEmail = Read-Host "Enter an email"
# $SearchDomain = Read-Host "Enter a domain"
# Check for AZ.KeyVault


$ModuleCheck = Get-Module -ListAvailable | Where-Object {$_.Name -eq "Az.KeyVault"}

if (!$ModuleCheck) {
    Write-Host "You don't have the Az.KeyVault PS Module. Let me get that for you..." -ForegroundColor DarkBlue
    Install-Module -Name Az.KeyVault -Repository PSGallery -Scope CurrentUser -Force
}

# Collect API keys for search tools
$APIKeys = @(
    "be-api",
    "Shodan-api", 
    "censys-api-id",
    "censys-api-secret",
    "securityTrails-api",
    "ipstack-api",
    "zoomeye-api"
)

foreach ($APIKey in $APIKeys) {
    $secretValue = Get-AzKeyVaultSecret -VaultName 'raderseckeys' -Name $APIKey -AsPlainText
    $secretName = $APIKey.Replace("-", "_")  # Replace hyphens with underscores
    Set-Variable -Name $secretName -Value $secretValue
}

$SearchIP = Read-Host "Enter the IP to search: "

# Output file information
$FileData = (Get-Date | select-object day,month,year)
$FileName = "$($FileData.day)-$($FileData.month)-$($FileData.year)"

# Output directory
$NewDir = "$env:USERPROFILE\$($FileName)-IP_Hunter"
$GetDir = Get-Item -Path "$NewDir"
$MakeDir = New-Item -Type Directory -path "$NewDir"


# Directory Check
if (!$GetDir) {
    $MakeDir
}

Write-Host ""
Write-Host "Starting Rader_IPHunter search on $($SearchIP)" -ForegroundColor DarkGreen
Write-Host ""

# Binary_Edge search

Write-Host "Searching BinaryEdge for $($SearchIP)"

$be_url = "https://api.binaryedge.io/v2/query/ip/$SearchIP"

$be_header = @{
"X-KEY" = $be_api
}

try {
    $be_searchresults = "BinaryEdge_$($SearchResults.FileName).txt"
    $BinaryEdgeSearch = Invoke-WebRequest -Uri $be_url -Method GET -Headers $be_header
    $BEJson = $BinaryEdgeSearch.Content | ConvertFrom-Json

    $BinaryEdgeData = @{
    IP = $BEJson.query
    Origin = ($BEJson.events.results.origin | head -4)
    }

    Write-Host "BinaryEdge search results for $($SearchIP):" -ForegroundColor DarkGreen
    $BinaryEdgeData
    $BinaryEdgeData | Out-File -FilePath "$($SearchResults.NewDir)\$($be_searchresults)"

    Write-Host "BinaryEdge search results saved to $($SearchResults.NewDir)/$($be_searchresults)" -ForegroundColor DarkGreen

    } catch {
        Write-Host "An error occurred while searching BinaryEdge:" -ForegroundColor DarkRed
        Write-Host $_.Exception.Message -ForegroundColor DarkRed
}
Start-Sleep -Seconds 15


# Search with Censys


Write-Host "Searching Censys.io for $($SearchIP)" -ForegroundColor DarkBlue

$censys_url = "https://search.censys.io/api/v2/hosts/$($SearchIP)"

$censys_searchresults = "CensysSearch_$($SearchResults.FileName).txt"


$censys_header =  @{
        Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($censys_api_id):$($censys_api_secret)")))"
}
try {
$CensysSearch = Invoke-WebRequest -Uri $censys_url -Method GET -Headers $censys_header
$CensysJson = ($CensysSearch.content | ConvertFrom-Json)
 $CensysData = @{
    IP = $CensysJson.result.ip
    Country = $CensysJson.result.location.registered_country
    Country_Code = $CensysJson.result.location.registered_country_code
    Last_Update = $CensysJson.result.last_updated_at
}
$CensysResults = $CensysData | Format-List
$CensysResults | Out-File -FilePath $SearchResults.MakeDir/$censys_searchresults

Write-Host "Censys.io search results saved to $($SearchResults.MakeDir)/$($censys_searchresults)" -ForegroundColor DarkGreen
} catch {
        Write-Host "An error occurred while searching Censys.io:" -ForegroundColor DarkRed
        Write-Host $_.Exception.Message -ForegroundColor DarkRed
}
Start-Sleep -Seconds 15
#Shodan search

    Write-Host "Searching Shodan.io for $SearchIP" -ForegroundColor DarkGreen

    $shodan_url = "https://api.shodan.io/shodan/host/$($SearchIP)?key=$($shodan_api)"
    try {
    $ShodanSearch = Invoke-RestMethod -Uri $shodan_url
    $ShodanResults = "ShodanSearch_$($SearchResults.FileName).txt"

    $Shodata = @('ip_str','city','region_code','isp','Domains')

    Write-Host "Shodan.io results for $($SearchIP):" -ForegroundColor DarkGreen
    Write-Host ""
    $ShoSearch = $ShodanSearch | Format-List $Shodata
    $ShoSearch | Out-File -FilePath "$($SearchResults.MakeDir)/$($ShodanResults)"
    Write-Host "Shodan.io results saved in $($SearchResults.NewDir)\$($ShodanResults)"
    }
    catch {
        Write-Host "An error occurred while searching Shodan.io:" -ForegroundColor DarkRed
        Write-Host $_.Exception.Message -ForegroundColor DarkRed
    }
Start-Sleep -Seconds 15
# FullHunt - Can search for Domain(s) and subdomains
<#Function FullHunt {


    "Searching FullHunt for $($SearchDomain)"


    $FullHunt_DomainUrl = "https://fullhunt.io/api/v1/domain/$($SearchDomain)/details"

    $FullHunt_Headers = @{
        "X-API-KEY" = "$($FullHunt_API)"
    }

    # $FullHunt_DomainSearch = Invoke-WebRequest -Uri $FullHunt_URL -Headers $FullHunt_Headers

    $FullHunt_DomainSearch = Invoke-WebRequest -Uri $FullHunt_DomainUrl -Headers $FullHunt_Headers
    # $FullHunt_DomainSearch | ConvertFrom-Json
    
    $FullHunt_json = $FullHunt_DomainSearch | ConvertFrom-Json

    $FullHunt_json

}#>



# SecurityTrails Search

    Write-Host "Searching SecurityTrails for $($SearchIP)"

    $securityTrails_url = "https://api.securitytrails.com/v1/ips/nearby/$($SearchIP)"
    # $securityTrails_domainurl = "https://api.securitytrails.com/v1/domain/$SearchDomain"
    $securityTrails_searchresults = "SecurityTrailsSearch_$($SearchResults.FileName).txt"
    $securityTrails_headers = @{
        APIKEY = $securityTrails_api
    }

    <#$securityTrails_domainheaders = @{
        APIKEY = securityTrails_api
        Accept = 'application/json'
    }#>
    try {
    $securityTrails_search = Invoke-RestMethod -Uri $securityTrails_url -Headers $securityTrails_headers
    
    Write-Host "SecurityTrails results for $($SearchIP):" -ForegroundColor DarkMagenta
    $ST_Response = ($securityTrails_search).blocks | head -20
    $ST_Response | Out-File -Path "($SearchResults.MakeDir)\$($securityTrails_searchresults)"
    Write-Host "IP search results saved to $($SearchResults.NewDir)\$($securityTrails_searchresults)"

    # $securityTrails_DomainSearch = Invoke-RestMethod -Uri $securityTrails_domainurl -Headers $securityTrails_domainheaders

    }   catch {
    Write-Host "An error occurred while searching SecurityTrails:"
    Write-Host $_.Exception.Message -ForegroundColor DarkRed
}
Start-Sleep -Seconds 15

# IPStack search

    Write-Host "Searching IPStack for $($SearchIP)"

    $SearchIPstack_url = "http://api.ipstack.com/$($SearchIP)?access_key=$($ipstack_api)"

    try {

        $SearchIPstack_results = "IPStack_$($SearchResults.FileName).txt"
    
    $SearchIPstack_search = Invoke-RestMethod -Uri "$SearchIPstack_url"

    Write-Host "IPStack results for $($SearchIP):" -ForegroundColor DarkMagenta
    $SearchIPstack_search
    $SearchIPstack_search | Out-File -FilePath "$($SearchResults.NewDir)\$($SearchIPstack_results)"

    Write-Host "IPStack search results saved to $($SearchResults.NewDir)\$($SearchIPstack_results)"
    
    } catch 
    {
        Write-Host "An error occurred while searching IPStack:"
        Write-Host $_.Exception.Message -ForegroundColor DarkRed
}
Start-Sleep -Seconds 15

# ZoomEye search

    Write-Host "Searching ZoomEye for $($SearchIP)"

$zoomeye_headers = @{
    "API-KEY" = "$($zoomeye_api)"
    }

    $zoomeye_url = "https://api.zoomeye.org/host/search?query=ip:$($SearchIP)"

    $zoomeye_results = "ZoomEye_$($SearchResults.FileName).txt"

    try {
    $zoomeye_search = Invoke-RestMethod -Uri $zoomeye_url -Headers $zoomeye_headers
    $zoomeye_hashtable = $zoomeye_search | ConvertTo-Hashtable

    Write-Host "ZoomEye search results for $($SearchIP):" -ForegroundColor DarkMagenta
    $zoomeye_hashtable.matches.ip, $zoomeye_hashtable.matches.portinfo, $zoomeye_hashtable.matches.geoinfo

    $ZoomEye_Data = @{
        IP_Match = $zoomeye_hashtable.matches.ip
        PortInfo = $zoomeye_hashtable.matches.portinfo
        GeoInfo = $zoomeye_hashtable.matches.geoinfo
    }

    $ZoomEye_Data | Out-File -FilePath "$($SearchResults.NewDir)\$($zoomeye_results)"
    Write-Host "ZoomEye results saved to $($SearchResults.NewDir)\$($zoomeye_results)"
    }
    catch {
        Write-Host "An error occurred while searching Zoomeye:"
        Write-Host $_.Exception.Message -ForegroundColor DarkRed
}

}
