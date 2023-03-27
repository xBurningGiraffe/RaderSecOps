Function Invoke-Rader_Recon {

# Check for AzureADPreview module
$ADPreviewCheck = Get-Module -ListAvailable | Where-Object -Property Name -eq "AzureADPreview"

if(-not ($ADPreviewCheck)) {
    Install-Module AzureADPreview -AllowClobber
}

Function ReportMenu {
        Write-Host "_____________________________________________" -ForegroundColor DarkGreen
        Write-Host "_____________________________________________" -ForegroundColor DarkYellow
        Write-Host "_____________________________________________" -ForegroundColor DarkBlue
        Write-Host "------------ O365 Recon Report ------------" -ForegroundColor DarkGreen
        Write-Host ""
        Write-Host "    [1] Full O365 Recon Report " -ForegroundColor DarkMagenta
        Write-Host "    [2] Gather Azure Administrators" -ForegroundColor DarkMagenta
        Write-Host "    [3] Gather Exchange Administrators" -ForegroundColor DarkMagenta
        Write-Host "    [4] Gather Email Forwards" -ForegroundColor DarkMagenta
        Write-Host "    [5] Gather User Inbox Rules" -ForegroundColor DarkMagenta
        Write-Host "    [6] Gather Tenant Transport Rules" -ForegroundColor DarkMagenta
        Write-Host "    [7] Gather MFA statuses (per user)" -ForegroundColor DarkMagenta
        Write-Host "    [8] Gather Licensed Shared Mailboxes" -ForegroundColor DarkMagenta
        Write-Host "    [9] Gather Stale Accounts" -ForegroundColor DarkMagenta
        Write-Host "    [10] Gather Blocked Login Accounts" -ForegroundColor DarkMagenta
        Write-Host "    [11] Gather 50GB+ Mailboxes" -ForegroundColor DarkMagenta
        Write-Host "    [12] Gather Guest Accounts" -ForegroundColor DarkMagenta
        Write-Host "    [13] Get Password Policies" -ForegroundColor DarkMagenta
        Write-Host "    [14] Get Technical Contact(s)" -ForegroundColor DarkMagenta
        Write-Host "    [15] Get Directory Sync Accounts" -ForegroundColor DarkMagenta
        Write-Host ""
        Write-Host "    [Q] Quit" -ForegroundColor DarkRed
        Write-Host "_____________________________________________" -ForegroundColor DarkGreen
        Write-Host "_____________________________________________" -ForegroundColor DarkYellow
        Write-Host "_____________________________________________" -ForegroundColor DarkBlue

}

Function ReportOption {
    Do {
        ReportMenu
        $script:ReportType = Read-Host -Prompt "Choose an option from the menu and enter here "
        switch ($script:ReportType){
            '1'{
                FullReport
            }
            '2'{
                GatherAzureAdmins
            }
            '3'{
                GatherExchangeAdmins
            }
            '4'{
                GatherMailForwards
            }
            '5'{
                GatherUserInboxRules
            }
            '6'{
                GatherTenantMailRules
            }
            '7'{
                GatherMFAstatus
            }
            '8'{
                GatherLicenseShared
            }
            '9'{
                GatherStaleAccounts
            }
            '10'{
                GatherBlockedLogins
            }
            '11'{
                GatherMailOver50
            }
            '12'{
                GatherGuestAccounts
            }
            '13'{
                GatherPwPolicy
            }
            '14'{
                GatherTechContact
            }
            '15'{
                GatherDirSync
            }
        }
    } until ($script:ReportType -eq 'Q')
}

Connect-ExchangeOnline
Connect-AzureAD
Connect-MsolService

# Set the output file name
$DomainName = (Get-AcceptedDomain).Name | Where-Object { $_ -notlike "*onmicrosoft.com" }

# Get the current date
$ReportDate = (Get-Date | select-object day,month,year)
$ReportName = "$($DomainName)_$($ReportDate.day)_$($ReportDate.month)_$($ReportDate.year)"

# Create output directory
$ReportDir = "O365_Recon_Report"
$OutReport = "$($env:USERPROFILE)\$($DomainName)_$($ReportDir)"

# Check if the directory already exists
if (-not (Test-Path $OutReport)) {
    # Create the directory if it doesn't exist
    New-Item -ItemType Directory -Path $OutReport
}
# Set the output directory variable
$OutReport = $OutReport


Function FullReport {
GatherAzureAdmins
GatherExchangeAdmins
GatherMailForwards
GatherUserInboxRules
GatherTenantMailRules
GatherMFAstatus
GatherLicenseShared
GatherStaleAccounts
GatherBlockedLogins
GatherMailOver50
GatherGuestAccounts
GatherPwPolicy
GatherTechContact
GatherDirSync
}

# Get Azure AD Administrators
Function GatherAzureAdmins {
Write-Host "Gathering Azure Active Directory Administrators for $($DomainName)..." -ForegroundColor DarkGreen

$Roles = foreach ($role in Get-AzureADDirectoryRole) {
    $Admins = (Get-AzureADDirectoryRoleMember -ObjectId $Role.ObjectId).userprincipalname
    if ([string]::IsNullOrWhiteSpace($admins)) {
        [PSCustomObject]@{
            AdminGroupName = $role.DisplayName
            Members = "No Members"
        }
    }
foreach ($admin in $admins){
    [PSCustomObject]@{
        AdminGroupName = $role.DisplayName
        Members = $admin
        }
    }
}

Write-Host "Saving results to $($OutReport)..." -ForegroundColor DarkBlue

$roles | Export-Csv -Path  "$($OutReport)\AZ_Admins_$($ReportName).csv" -Force -ErrorAction SilentlyContinue
}
# Get Exchange Administrators

Function GatherExchangeAdmins {
Write-Host "Gathering Exchange Online Administrators for $($DomainName)..." -ForegroundColor DarkGreen

$ExoRoles = foreach ($ExoRole in Get-RoleGroup){
    $ExchangeAdmins = Get-RoleGroupMember -Identity $ExoRole.Identity | Select-Object -Property *
    foreach ($admin in $ExchangeAdmins){
        if([string]::IsNullOrWhiteSpace($admin.WindowsLiveId)){
            [PSCustomObject]@{
                ExchangeAdminGroup = $ExoRole.Name
                Members = $Admin.DisplayName
                RecipientType = $admin.RecipientType
            }
        } else{
        [PSCustomObject]@{
            ExchangeAdminGroup = $ExoRole.Name
            Members = $admin.WindowsLiveId
            RecipientType = $Admin.RecipientType
            }
        }
    }
}

Write-Host "Saving results to $($OutReport)..." -ForegroundColor DarkBlue

$ExoRoles | Export-Csv -Path "$($OutReport)\Exo_Admins_$($ReportName).csv" -Force -ErrorAction SilentlyContinue
}

# Get all users with email forwards

Function GatherMailForwards {
Write-Host "Gathering Email forwards for $($DomainName)..." -ForegroundColor DarkGreen
$Mailboxes = Get-Mailbox -ResultSize Unlimited
foreach ($Mailbox in $Mailboxes) {
    $ForwardingSMTPAddress = $Mailbox.ForwardingSMTPAddress
    $externalRecipient = $null
    if ($ForwardingSMTPAddress) {
        $Email = ($ForwardingSMTPAddress -split "SMTP:")[1]
        $Domain = ($Email -split "@")[1]
        if ($Domains.DomainName -notcontains $Domain) {
            $ExternalRecipient = $Email
        }

        if ($ExternalRecipient) {
            Write-Host "$($mailbox.displayName) - $($mailbox.primarysmtpaddress) forwards to $externalRecipient" -ForegroundColor DarkYellow

            $ForwardHash = $null
            $ForwardHash = [ordered]@{
                PrimarySMTPAddress = $Mailbox.PrimarySMTPAddress
                DisplayName = $Mailbox.DisplayName
                ExternalRecipient = $ExternalRecipient
            }
            $RuleObject = New-Object PSObject -Property $ForwardHash
        }
    }
}

Write-Host "Saving results to $($OutReport)..." -ForegroundColor DarkBlue

$RuleObject | Export-Csv -Path "$($OutReport)\Email_Forwards_$($ReportName)" -Force -ErrorAction SilentlyContinue
}

# Gather per user Inbox Rules

Function GatherUserInboxRules {
$Mailboxes = Get-Mailbox -ResultSize Unlimited
Write-Host "Gathering all inbox rules for $($DomainName)..." -ForegroundColor DarkGreen
$InboxRules = foreach ($Mailbox in $Mailboxes) {
   Get-InboxRule -Mailbox $Mailbox.EmailAddress | Select-Object MailboxOwnerID,Name,Enabled,Description,Actions | Format-Table -AutoSize
}

Write-Host "Saving results to $($OutReport)..." -ForegroundColor DarkBlue

$InboxRules | Export-Csv -Path "$($OutReport)\Inbox_Rules_$($ReportName)" -Force -ErrorAction SilentlyContinue
}
# Gather full tenant mail rules

Function GatherTenantMailRules {
Write-Host "Gathering Transport Rules for $($DomainName)..." -ForegroundColor DarkGreen

$TransportRules = (Get-TransportRule | fl)

$TransportRuleInfo = foreach ($TransportRule in $TransportRules) {
    [PSCustomObject]@{
        Name = $TransportRule.Name
        Description = $TransportRule.Description
        Conditions = $TransportRule.Conditions
        Exceptions = $TransportRule.Exceptions
        Actions = $TransportRule.Actions
        State = $TransportRule.State
        Mode = $TransportRule.Mode

    }
}

$TransportRuleInfo | Export-Csv -Path "$($OutReport)\Transport_Rules_Details_$($ReportName)" -Force -ErrorAction SilentlyContinue

}
# Get all users MFA registration status

Function GatherMFAstatus {

Write-Host "Gathering MFA Registration Details for users in $($DomainName)..." -ForegroundColor DarkGreen

$MFAUsers = Get-MsolUser -All | Select-Object SignInName,StrongAuthenticationMethods,StrongAuthenticationRequirements,StrongAuthenticationUserDetails,ValidationStatus

$MFADetails = foreach ($MFAUser in $MFAUsers) {
        [PSCustomObject]@{
        Name = $MFAUser.SignInName
        Auth_Method = $MFAUser.StrongAuthenticationMethods | Where-Object {$_.IsDefault -eq $True}
        Requirements = $MFAUser.StrongAuthenticationRequirements
        Details = $MFAUser.StrongAuthenticationUserDetails
        Validation_Status = $MFAUser.ValidationStatus
    }
}

 Write-Host "Saving MFA Registration Results to $($OutReport)..." -ForegroundColor DarkBlue

 $MFADetails | Export-Csv -Path "$($OutReport)\MFA_Details_$($ReportName)" -Force -ErrorAction SilentlyContinue
}
 # Gather all licensed shared mailboxes

 Function GatherLicenseShared {
 Write-Host "Gathering Licensed Shared Mailboxes for $($DomainName)..." -ForegroundColor DarkGreen

 $SharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox

 $SharedUsers = Get-MsolUser -All

 $LicensedShared = foreach ($SharedMailbox in $SharedMailboxes) {
    $SharedUser = $SharedUsers | Where-Object {$_.UserPrincipalName -eq $SharedMailbox.UserPrincipalName}
    if ($SharedUser.Licenses.Count -gt 0){
        Write-Output "$($SharedMailbox.PrimarySmtpAddress) is licensed"
 }
}
Write-Host "Saving Licensed Shared Mailbox results to $($OutReport)" -ForegroundColor DarkBlue

 $LicensedShared | Export-Csv -Path "$($OutReport)\Licensed_Shared_Mbox_$($ReportName)" -Force -ErrorAction SilentlyContinue
 }

 # Get Azure and Exchange stale accounts

 Function GatherStaleAccounts {
 Write-Host "Gathering Stale Azure Accounts for $($DomainName)..." -ForegroundColor DarkGreen

 $StaleTime = 180

 $CurrentDate = Get-Date

 $InactiveDate = $CurrentDate.AddDays(-$StaleTime)

 $ADUsers = Get-AzureADUser -All $true
 $ExchangeUsers = Get-ExoMailboxStatistics

 $StaleADAccounts = foreach ($ADUser in $ADUsers) {
    if (($User.LastPasswordChangeDateTime -lt $InactiveDate) -and ($User.LastSignInDateTime -lt $InactiveDate)) {
        Write-Output "$($User.UserPrincipalName) is a stale Azure account"
    }
 }

 $StaleExchangeAccounts = foreach ($ExchangeUser in $ExchangeUsers) {
    if (($User.LastLogonDate -lt $InactiveDate) -and ($User.Enabled -eq $True)) {
        Write-Output "$($User.UserPrincipalName) is a stale Exchange account"
    }
 }


 Write-Host "Saving Stale Azure Accounts results to $($OutReport)..." -ForegroundColor DarkBlue

 $StaleADAccounts | Export-Csv -Path "$($OutReport)\Stale_AD_Users_$($ReportName)" -Force -ErrorAction SilentlyContinue

Write-Host "Saving Stale Exchange Accounts results to $($OutReport)..." -ForegroundColor DarkBlue

$StaleExchangeAccounts | Export-Csv -Path "$($OutReport)\Stale_Exchange_Users_$($ReportName)" -Force -ErrorAction SilentlyContinue
 }

 # Get licensed accounts with blocked sign-ins
Function GatherBlockedLogins {

 Write-Host "Gathering Licensed Users with blocked sign-ins..." -ForegroundColor DarkGreen

 $LicensedUsers = Get-MsolUser -All | Where-Object {$_.IsLicensed -eq $True}
 
$BlockedUsers = foreach ($LicensedUser in $LicensedUsers) {
    if (($LicensedUser.BlockCredential -eq "BlockSignIn") -or ($LicensedUser.BlockCredential -eq "BlockSignInWithIntune")) {
        Write-Output "$($LicensedUser.UserPrincipalName) has blocked sign-in."
    }
 }

 Write-Host "Saving blocked sign-in results to $($OutReport)..." -ForegroundColor DarkBlue

 $BlockedUsers | Export-Csv -Path "$($OutReport)\Blocked_Signins_$($ReportName)" -Force -ErrorAction SilentlyContinue

}
# Get mailboxes over 50GB

Function GatherMailOver50 {

Write-Host "Gathering mailboxes over 50GB..." -ForegroundColor DarkGreen

# Set the mailbox size limit to 50 GB
$MailboxSizeLimit = 50GB

$50GBUsers = try {
    # Get mailbox statistics for all mailboxes
    $Mailboxes = Get-EXOMailbox | Select-Object -ExpandProperty UserPrincipalName

    # Iterate over the mailboxes and filter for large mailboxes
    $Mailboxes | ForEach-Object {
        try {
            $MailboxStats = Get-EXOMailboxStatistics -Identity $_ -ErrorAction Stop
            if ($MailboxStats.TotalItemSize.Value.ToBytes() -gt $MailboxSizeLimit) {
                # Output the userprincipalname and TotalItemSize for each large mailbox
                Write-Output "$($_): $($MailboxStats.TotalItemSize)"
            }
        } 
        catch {
            Write-Warning "An error occurred while retrieving mailbox statistics for mailbox $_. Details: $_"
            # You can add more code here to handle the error, such as logging or sending an email notification.
        }
    }
} 
catch {
    Write-Warning "An error occurred while retrieving the list of mailboxes. Details: $_"
    # You can add more code here to handle the error, such as logging or sending an email notification.
}


Write-Host "Saving 50Gb+ mailbox results to $($OutReport)..." -ForegroundColor DarkBlue

$50GBUsers | Export-Csv -Path "$($OutReport)\50GB+_Mboxes_$($ReportName)" -Force -ErrorAction SilentlyContinue

}

# Gather guest accounts

Function GatherGuestAccounts {

Write-Host "Gathering Guest Accounts for $($DomainName)..." -ForegroundColor DarkGreen

$GuestAzUsers = Get-AzureADUser -All $true
$GuestExUsers = Get-User -ResultSize Unlimited

$GuestAzs = foreach ($GuestAzUser in $GuestAzUsers) {
    if ($GuestAzUser.UserType -eq "Guest") {
        Write-Output "$($GuestAzUser.DisplayName) is a guest account"
    }
}

Write-Host "Saving Guest Azure Results to $($OutReport)..." -ForegroundColor DarkBlue

$GuestAzs | Export-Csv -Path "$($OutReport)\Guest_Az_Users$($ReportName)" -Force -ErrorAction SilentlyContinue

$Guestexs = foreach ($GuestExUser in $GuestExUsers) {
    if ($GuestExUser.RecipientTypeDetails -eq "GuestMailUser") {
        Write-Output "$($GuestExUser.DisplayName) is a guest account"
    }
}

Write-Host "Saving Guest Exchange Results to $($OutReport)..." -ForegroundColor DarkGreen

$GuestExs | Export-Csv -Path "$($OutReport)\Guest_Ex_Users_$($ReportName)" -Force -ErrorAction SilentlyContinue
}
# Get Password Expiration Policy

# Check Azure for password policy

Function GatherPwPolicy {

$AzureADPasswordPolicy = Get-AzureADPolicy -Id "PasswordPolicy"
if($AzureADPasswordPolicy) {
    Write-Host "Azure AD password policy settings:"
    $AzureADPasswordPolicy.PasswordPolicy | Format-List
    Write-Host "Saving Azure AD Password Policy to $($OutReport)..." -ForegroundColor DarkBlue
    Export-Csv -Path "$($OutReport)\AzAD_Password_Policy_$($ReportName)" -Force -ErrorAction SilentlyContinue
}else {
    Write-Warning "No password policy found in AzureAD"
}

$MsolPasswordPolicy = Get-MsolPasswordPolicy -DomainName $DomainName
$O365PassPolicy = if ($MsolPasswordPolicy.ValidityPeriod) {
    $ValidityPeriod = New-TimeSpan -Seconds $MsolPasswordPolicy.ValidityPeriod

    Write-Host "Maximum password validity period: $($ValidityPeriod.Days) days, $($ValidityPeriod.Hours) hours, $($ValidityPeriod.Minutes) minutes"
}else {
    Write-Warning "The password policy does not specify a maximum password validity period."
}

Write-Host "Saving O365 Password Policy to $($OutReport)..." -ForegroundColor DarkBlue
$O365PassPolicy | Export-Csv -Path "$($OutReport)\Msol_Password_Policy_$($ReportName)" -Force -ErrorAction SilentlyContinue
}

# Gather technical contacts from Azure AD


# Get technical contact

Function GatherTechContact {
$TechContact = Get-AzureADTenantDetail

Write-Output "Technical Contact for $($DomainName): $($TechContact.TechnicalNotificationMails)" | Export-Csv -Path "$($OutReport)\Tech_Contact_$($ReportName)" -Force -ErrorAction SilentlyContinue
}
# Get directory sync accounts

Function GatherDirSync {

Write-Host "Gathering Directory Sync Accounts for $($DomainName)..." -ForegroundColor DarkGreen

$DirSyncs = Get-AzureADSyncAccount

$GetSync = foreach ($DirSync in $DirSyncs) {
    Write-Output "The directory synchronization account name is $($DirSyncAccount.AccountName)."
}

Write-Host "Saving Directory Sync Account Results to $($OutReport)..." -ForegroundColor DarkBlue

$GetSync | Export-Csv -Path "$($OutReport)\Directory_Sync_Accts_$($ReportName)" -Force -ErrorAction SilentlyContinue
}


# Disconnect from modules

Function Goodbye {

try {
    if (Get-ConnectionInformation) {
        Disconnect-ExchangeOnline -Confirm:$false
        }
    }
    catch {
        Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor DarkRed
    }
    # Check AIPService Connection
    try {
        if (Get-AipService) {
            Disconnect-AipService
        }
    }
    catch {
        Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor DarkRed
    }
# Check AzureAD Connection
    try {
        if (Get-AzureADConnection -ErrorAction SilentlyContinue) {
            # Disconnect from the AzureAD module
            Disconnect-AzureAD
        }
    }
    catch {
        Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor DarkRed
    }
}

Goodbye
}
