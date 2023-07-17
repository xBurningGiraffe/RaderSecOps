#   O365 Compliance Search and Destroy
# Finds specified email content through compliance search and executes a soft delete of results
Function Invoke-RaderSnD {
Write-Host "================================================================================================" -ForegroundColor DarkCyan
Write-Host "================================================================================================" -ForegroundColor DarkYellow
Write-Host "================================================================================================" -ForegroundColor DarkGreen
Write-Host "   _____                     _                      _____            _                   " -ForegroundColor DarkRed
Write-Host "  / ____|                   | |          ___       |  __ \          | |                    " -ForegroundColor DarkRed
Write-Host " | (___   ___  __ _ _ __ ___| |__       ( _ )      | |  | | ___  ___| |_ _ __ ___  _   _   " -ForegroundColor DarkRed
Write-Host "  \___ \ / _ \/ _' | '__/ __| '_ \      / _ \/\    | |  | |/ _ \/ __| __| '__/ _ \| | | |  " -ForegroundColor DarkRed
Write-Host "  ____) |  __/ (_| | | | (__| | | |    | (_>  <    | |__| |  __/\__ \ |_| | | (_) | |_| |  " -ForegroundColor DarkRed
Write-Host " |_____/ \___|\__,_|_|  \___|_| |_|     \___/\/    |_____/ \___||___/\__|_|  \___/ \__, |  " -ForegroundColor DarkRed
Write-Host "                                                                                     / /  " -ForegroundColor DarkRed
Write-Host "                                                                                    /_/  " -ForegroundColor DarkRed
Write-Host " @xBurningGiraffe" -ForegroundColor DarkRed                                                                                
Write-Host "================================================================================================" -ForegroundColor DarkCyan
Write-Host "================================================================================================" -ForegroundColor DarkYellow
Write-Host "================================================================================================" -ForegroundColor DarkGreen


Write-Host "================================================================================================" -ForegroundColor DarkCyan
Write-Host "================================================================================================" -ForegroundColor DarkGreen
Write-Host "O365 Compliance Search Info:" -ForegroundColor DarkYellow
Write-Host "O365s Compliance Search Purge Action moves items to the users Recoverable Items folder and remain there based on the Retention Period that is configured for the mailbox." -ForegroundColor DarkGreen
Write-Host "O365s Compliance Search results will return Items that were already purged (and are located in the Recoverable Items folder)." -ForegroundColor DarkGreen
Write-Host "================================================================================================" -ForegroundColor DarkCyan
Write-Host "================================================================================================" -ForegroundColor DarkGreen

$GetName = (Get-Date -Format "yyyy-MM-dd")
$SearchName = $GetName
$EmailSender = Read-Host -Prompt 'Please enter the exact Sender (From:) address of the Email you would like to search for'
$Subject = Read-Host -Prompt 'Please enter the exact Subject of the Email you would like to search for'
$DateStart = Read-Host -Prompt 'Please enter the Beginning Date for your Date Range (ex. MM/DD/YYYY)'
$DateEnd = Read-Host -Prompt 'Please enter the Ending Date for your Date Range (ex. MM/DD/YYYY)'
$DateRangeSeparator = ".."
$DateRange = $DateStart + $DateRangeSeparator + $DateEnd
$Search = "(Received:$DateRange) AND (From:$EmailSender) AND (Subject:'$Subject')"

# Search Creation
New-ComplianceSearch -Name $SearchName -ExchangeLocation All -ContentMatchQuery $Search

# Search
Write-Host "================================================================================================"
Write-Host "Starting Search and Destroy...please wait for results." -ForegroundColor DarkYellow
Write-Host "If the wait for results takes too long, you can press Enter to continue the script."
Write-Host "================================================================================================"
Start-ComplianceSearch -Identity $SearchName
$ThisSearch = Get-ComplianceSearch -Identity $SearchName
do {
    # Check if a key has been pressed
    if ( $host.UI.RawUI.KeyAvailable -and ($host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").VirtualKeyCode -eq 13)) {
        Write-Host "Continuing with script"
        
    }
    Start-Sleep -Seconds 30
    $ThisSearch = Get-ComplianceSearch -Identity $SearchName
} until ($ThisSearch.status -eq "Completed")

$ThisSearchResults = $ThisSearch.SuccessResults;
    if (($ThisSearch.Items -le 0) -or ([string]::IsNullOrWhiteSpace($ThisSearchResults))){
            Write-Host "Whoops...no useful results were found!" -ForegroundColor DarkYellow
    }
    $mailboxes = @() #create an empty array for mailboxes
    $ThisSearchResultsLines = $ThisSearchResults -split '[\r\n]+'; #Split up the Search Results at carriage return and line feed
    foreach ($ThisSearchResultsLine in $ThisSearchResultsLines){
            # If the Search Results Line matches the regex, and $matches[2] (the value of "Item count: n") is greater than 0)
    if ($ThisSearchResultsLine -match 'Location: (\S+),.+Item count: (\d+)' -and $matches[2] -gt 0){ 
                # Add the Location: (email address) for that Search Results Line to the $mailboxes array
    $mailboxes += $matches[1]; 
    }
    }
    Write-Host "Number of mailboxes that have Search Hits..."
    Write-Host $mailboxes.Count -ForegroundColor DarkYellow
    Write-Host "List of mailboxes that have Search Hits..."
    Write-Host $mailboxes -ForegroundColor DarkYellow
    Write-Host "================================================================================================"

    $CheckDelete = Read-Host -Prompt "Please review the results above. Do you want to proceed with the soft delete? [Y]es or [N]o"
    if ($CheckDelete -eq 'Y'){
        Write-Host "==========================================================================="
        Write-Host "Running Search and Destroy...."
        Write-Host "==========================================================================="
        $PurgeSuffix = "_purge"
		$PurgeName = $SearchName + $PurgeSuffix
        New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType SoftDelete
        do{
			$ThisPurge = Get-ComplianceSearchAction -Identity $PurgeName
            Start-Sleep 15
            Write-Host "Destruction in progress...please wait" -ForegroundColor DarkGreen
		}until ($ThisPurge.Status -match "Completed")
            $ThisPurge | Format-List
            $ThisPurgeResults = $ThisPurge.Results
            $ThisPurgeResultsMatches = $ThisPurgeResults -match 'Purge Type: SoftDelete; Item count: (\d*); Total size (\d*);.*'
        if ($ThisPurgeResultsMatches){
            $ThisPurgeResultsItemCount = $Matches[1]
            $ThisPurgeResultsTotalSize = $matches[2]
        }
    Write-Host "Finishing up...with your mom LOL" -ForegroundColor DarkGreen
    Write-Host "==========================================================="
    Write-Host "Search and Destroy complete! You removed the chosen email from a total of: "  -ForeGround DarkGreen                         
    Write-Host $ThisPurgeResultsItemCount -ForegroundColor Yellow
    Write-Host "Mailboxes" -ForeGround Green
    Write-Host "==========================================================================="
    Write-Host "and the total size of the purge was: " -ForeGround DarkGreen
    Write-Host $ThisPurgeResultsTotalSize -ForegroundColor Yellow
    Write-Host "==========================================================================="
    Remove-ComplianceSearch -Identity $SearchName
    Write-Host "================================================================================================"
    Write-Host "My work here is finished. If yours isn't, please rerun Search and Destroy. This ain't no picnic b**tch!" -ForeGround DarkGreen
    Write-Host "================================================================================================" -Foreground DarkGreen             
    }elseif ($CheckDelete -eq 'N'){
        Write-Host "==========================================================================="
        Write-Host "Exiting Search and Destroy...go review the results in the Compliance Center! :)" -ForeGround DarkGreen
        Remove-ComplianceSearch -Identity $SearchName
        Write-Host "==========================================================================="
    }
}