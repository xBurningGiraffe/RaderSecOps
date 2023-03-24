# RaderSecOps Script

Function Invoke-RaderSec {
    param(
            [switch]$Updates
    )
    
    
    Function WelcomeBanner {
            Start-Sleep -m 200
            Write-Host " NOTE: Run this with elevated privileges" -ForegroundColor DarkRed
            Write-Host "===============================================================" -ForegroundColor DarkCyan
            Write-Host "===============================================================" -ForegroundColor DarkYellow
            Write-Host "===============================================================" -ForegroundColor DarkGreen
            Write-Host " RaderSec Operations " -ForegroundColor DarkYellow
            Write-Host "===============================================================" -ForegroundColor DarkCyan
            Write-Host "===============================================================" -ForegroundColor DarkYellow
            Write-Host "===============================================================" -ForegroundColor DarkGreen
            OnboardOption
        }
        
        # Function for choosing onboard options
        Function OnboardMenu {
            Write-Host " # # # ######     #    ######  ####### ######" -ForegroundColor DarkGreen
            Write-Host " # # # #     #   # #   #     # #       #     #" -ForegroundColor DarkGreen
            Write-Host " # # # #     #  #   #  #     # #       #      #" -ForegroundColor DarkGreen
            Write-Host " # # # ######  #     # #     # #####   ######" -ForegroundColor DarkGreen
            Write-Host " # # # #   #   ####### #     # #       #   # " -ForegroundColor DarkGreen
            Write-Host " # # # #    #  #     # #     # #       #    #" -ForegroundColor DarkGreen
            Write-Host " # # # #     # #     # ######  ####### #     #" -ForegroundColor DarkGreen
            Write-Host "_____________________________________________" -ForegroundColor DarkGreen
            Write-Host "_____________________________________________" -ForegroundColor DarkYellow
            Write-Host "_____________________________________________" -ForegroundColor DarkBlue
            Write-Host "Thanks for all you do. - Chris Rader" -ForegroundColor DarkYellow
            Write-Host "------------ General ------------" -ForegroundColor DarkGreen
            Write-Host "    [0] Powershell Module Installer" -ForegroundColor DarkYellow
            Write-Host ""
            Write-Host "----------- Onboarding -----------" -ForegroundColor DarkGreen
            Write-Host "    [1] New Client Onboard" -ForegroundColor DarkGreen
            Write-Host "    [2] Organization Customization" -ForegroundColor DarkYellow
            Write-Host "    [3] Organization-wide Auditing" -ForegroundColor DarkYellow
            Write-Host "    [4] Mailbox Auditing" -ForegroundColor DarkYellow
            Write-Host "    [5] O365 Outbound Spam Policy" -ForegroundColor DarkYellow
            Write-Host "    [6] O365 Anti-Spam Policy" -ForegroundColor DarkYellow
            Write-Host "    [7] O365 Anti-Phish Policy" -ForegroundColor DarkYellow
            Write-Host "    [8] O365 Anti-Malware Policy" -ForegroundColor DarkYellow
            Write-Host "    [9] O365 Safe Attachments" -ForegroundColor DarkYellow
            Write-Host "    [10] O365 Safe Links" -ForegroundColor DarkYellow
            Write-Host "    [11] MFA Conditional Access Policy" -ForegroundColor DarkYellow
            Write-Host "    [12] AIP Encryption Rule" -ForegroundColor DarkYellow
            Write-Host "    [13] Phin M365 Policies" -ForegroundColor DarkYellow
            Write-Host "    [14] North-America Only Conditional Access Policy" -ForegroundColor DarkYellow
            Write-Host "    [15] Intune Policies" -ForegroundColor DarkYellow
            Write-Host " "
            Write-Host "----------- Office365 -----------" -ForegroundColor DarkGreen
            Write-Host "    [O] Get Mailboxes over 50 GB" -ForegroundColor Cyan
            Write-Host "    [T] Full O365 ATP/AIP setup" -ForegroundColor Cyan
            Write-Host "    [D] DMARC/DKIM setup (Azure DNS Only)" -ForegroundColor Cyan
            Write-Host "    [M] Enable MFA Conditional Access Policy" -ForegroundColor Cyan
            Write-Host "    [H] Disable AdHoc Subscriptions" -ForegroundColor Cyan
            Write-Host " "
            Write-Host "-------BEC Incident Response-------" -ForegroundColor DarkGreen
            Write-Host "    [S] Search & Destroy" -ForegroundColor Magenta
            Write-Host "    [P] PwnedUser Log Collection" -ForegroundColor Magenta
            Write-Host "    [I] IPHunter - Extensive IP search tool" -ForegroundColor Magenta
            Write-Host ""
            Write-Host "------------- Other --------------" -ForegroundColor DarkGreen
            Write-Host "    [B] Add Cofense Protect 'Report Phishing' Button" -ForegroundColor Magenta
            Write-Host " "
            Write-Host "------------- Quit --------------" -ForegroundColor DarkGreen
            Write-Host "    [Q] Quit"  -ForegroundColor DarkRed
            Write-Host "---------------------------------" -ForegroundColor DarkGreen
        }
        
        # Action execution function for menu options
    Function OnboardOption {
        Do {
            OnboardMenu
            $script:OnboardType = Read-Host -Prompt "Choose a task from the menu and enter here: "
            switch ($script:OnboardType){
                '0'{
                    ModuleInstalls
                }
                '1'{
                    Connect-ExchangeOnline 
                    Connect-AzureAD 
                    Connect-MsolService 
                    Connect-AIPService
                    Connect-IPPSSession
                    FullOnboard
                }
                '2'{
                    Connect-ExchangeOnline
                    OrgCustomization
                    OrgCustomizationCheck
                }
                '3'{
                    Connect-ExchangeOnline
                    OrgAuditing
                }
                    <# '4'{
                        Connect-MsolService
                        Connect-ExchangeOnline
                        LitHold
                    } #>
                '4'{
                    Connect-ExchangeOnline
                    Connect-MsolService
                    MboxAudit
                }
                '5'{
                    Connect-ExchangeOnline
                    Connect-IPPSSession
                    O365OutboundSpam
                }
                '6'{
                    Connect-ExchangeOnline
                    Connect-IPPSSession
                    O365AntiSpam
                }
                '7'{
                    Connect-ExchangeOnline
                    Connect-IPPSSession
                    O365AntiPhish
                }
                '8'{
                    Connect-ExchangeOnline
                    Connect-IPPSSession
                    O365AntiMal
                        
                        
                }
                '9'{
                    Connect-ExchangeOnline
                    Connect-IPPSSession
                    O365SafeAttach
                        
                }
                '10'{
                    Connect-ExchangeOnline
                    Connect-IPPSSession
                    O365SafeLinks
                        
                        
                }
                '11'{
                    Connect-ExchangeOnline
                    Connect-AzureAD
                    MFAPolicy
                }
                '12'{
                    Connect-ExchangeOnline
                    Connect-AipService
                    AIPPolicy
                        
                }
                '13'{
                    Connect-ExchangeOnline
                    Connect-IPPSSession
                    PhinRule
                    PhinAllows
                    PhinSim
                        
                        
                }
                '14'{
                    Connect-AzureAD
                        NAOnlyPolicy
                        
                    }
                '15'{
                    Intune
                }
        <#            'L'{
                        Connect-ExchangeOnline
                        Connect-PartnerCenter
                        LicenseCheck
        #            } #>
                'S'{
                    Connect-IPPSSession
                    SearchnDestroy
                    Logout
                }
                'P'{
                    PwnedUser
                }
                'D'{
                    Connect-AzAccount
                    Connect-ExchangeOnline
                    Connect-AzureAD
                    DMARCDKIM
                        
                }
                'B'{
                    Connect-ExchangeOnline
                    Connect-OrganizationAddInService
                    PhishButton
                        
                }
                'M'{
                    Connect-AzureAD
                    EnableMFA
                    Logout
                }
                'H'{
                    Connect-MsolService
                    AdHocSub
                    Logout
                }
                'L'{
                    Connect-MsolService
                    Connect-ExchangeOnline
                    DisableLit
                    Logout
                }
                'T'{
                    Connect-ExchangeOnline
                    Connect-IPPSSession
                    O365OutboundSpam
                    O365AntiSpam
                    O365AntiPhish
                    O365AntiMal
                    O365SafeAttach
                    O365SafeLinks
                    Logout
                }
                'O'{
                    Connect-ExchangeOnline
                    Over50GB
                    Logout
                }
                'I'{
                    Rader_IPHunter
                }
                'Q'{
                    Goodbye
                }
            }
        } until ($script:OnboardType -eq 'Q')
}
        
    
        # PowerShell Module Installs
        Function ModuleInstalls {
            $Modules = @("ExchangeOnlineManagement","AzureAD","AIPService","MSOnline","PartnerCenter","Az.KeyVault","OrganizationAddInService")
            foreach ($Module in $Modules){
                if (-not(Get-Module -Name $Module -ListAvailable)) {
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                    Write-Host "Importing required Powershell modules..." -ForegroundColor DarkYellow
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                    Install-Module -Name $Module -Force
                        try {
                            Import-Module -Name $Module
                        }
                        catch {
                            Write-Host "Failed to import module $Module. Error message: $_" -ForegroundColor Red
                        }
                        else {
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                    Write-Host "$Module is already imported" -ForegroundColor DarkYellow
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                        }
                    }
            }
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "All Powershell modules are installed" -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
        
        # New client onboarding
        Function FullOnboard {
            OrgCustomization
            OrgAuditing
            PhinRule
            PhinAllows
            PhinSim
            MboxAudit
            O365OutboundSpam
            O365AntiSpam
            O365AntiPhish
            O365AntiMal
            O365SafeAttach
            O365SafeLinks
            MFAPolicy
            AIPPolicy
            NAOnlyPolicy
            AdHocSub
        }
        
        # Enable Organization Customization
        Function OrgCustomization {
        $GetOrgCust = (Get-OrganizationConfig).IsDehydrated
        if ($true -eq $GetOrgCust) {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Enabling Organization Customization..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            try {
                Enable-OrganizationCustomization
            }
            catch {
                if ($_.Exception.GetType().FullName -eq 'System.InvalidOperationException' -and $_.Exception.Message -match 'This operation is not required. Organization is already enabled') {
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                    Write-Host "Organization is already enabled for customization." -ForegroundColor DarkGreen
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                }
                else {
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                    Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor DarkRed
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                }
            }else {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Organization Customization is now enabled" -ForegroundColor DarkGreen
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
    }
    }
        # Enable Org-Wide Auditing
        Function OrgAuditing {
        $CheckAuditing = Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
        $EnableAuditing = Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Write-Host "Enabling Organization-Wide Auditing" -ForegroundColor DarkYellow 
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        if ($CheckAuditing -eq $false) {
            try {
                $EnableAuditing
            }
            catch {
                Write-Error "Error: $($_.Exception.Message)"
            }
        } else {
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Write-Host "Organization-wide auditing is now enabled" -ForegroundColor DarkGreen
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
    }
        
        # Enable Litigation Hold for licensed users
        <#Function LitHold {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Enabling litigation hold for all licensed users..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            $GetUsers = (Get-Mailbox -ResultSize Unlimited -Filter {RecipientTypeDetails -eq "UserMailbox"})
            $Licenses = (Get-MsolUser | Where-Object {$_.IsLicensed -eq $true}).UserPrincipalName
            $LicensedUsers = ($GetUsers.UserPrincipalName | Where-Object -FilterScript { $_ -in $Licenses})
            foreach ($LicensedUser in $LicensedUsers){
                Set-Mailbox -Identity $LicensedUser -LitigationHoldEnabled $True
            }
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Litigation hold is now enabled" -ForegroundColor DarkGreen
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        } #>
        
        Function PhinRule {
            $PhinRule = "Bypass Spam Filtering & SafeLinks (Phin)"
            $SenderIPs = "54.84.153.58","107.21.104.73","198.2.177.227"
            $BypassSpam = (Get-TransportRule).Name | Where-Object -FilterScript {$_ -eq $PhinRule}
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Creating Phin bypass spam filtering rule..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            if ($BypassSpam) {
                try {
                    New-TransportRule -Name $PhinRule -Priority 0 -SenderIpRanges $SenderIPs -SetAuditSeverity DoNotAudit -SetSCL -1 -SetHeaderName "X-MS-Exchange-Organization-BypassFocusedInbox" -SetHeaderValue 1 -StopRuleProcessing $True
    
                } catch [System.ArgumentNullException] {
                    Write-Error "Error: ExchangeConfigUnit parameter cannot be null."
                } catch {
                    Write-Error "Error: $($_.Exception.Message)"
                }
            } else {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "$BypassSpam has been created" -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            }
    }
            
        
        Function PhinAllows {
            $PhinAllows = @("~betterphish.com~","~shippingalerts.com~","~amazingdealz.net~","~berrysupply.net~","~coronacouncil.org~","~couponstash.net~","~creditsafetyteam.com~","~autheticate.com~","~notificationhandler.com~")
            $Phins = Get-TenantAllowBlockListItems -ListType Url -ListSubType AdvancedDelivery
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Adding Phin tenants to the allow list" -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            if ($PhinAllows -notmatch $Phins.Value) {
                try {
                    New-TenantAllowBlockListItems -Allow -ListType Url -ListSubType AdvancedDelivery -Entries $PhinAllows -NoExpiration
            }
                catch [System.ArgumentException]{
                    Write-Host "Tenant is already added to allow list"
            } else {
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                Write-Host "Phin allowed tenants have been added" -ForegroundColor DarkYellow
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            }
        } 
        }
        Function PhinSim {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Creating Phin phishing override policy" -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            $PhinDomains = @("betterphish.com","shippingalerts.com","amazingdealz.net","berrysupply.net","coronacouncil.org","couponstash.net","creditsafetyteam.com","autheticate.com","notificationhandler.com")
            $SimCheck = Get-PhishSimOverridePolicy -Identity PhishSimOverridePolicy
            if ($SimCheck) {
            try {
                New-PhishSimOverrideRule -Name PhishSimOverrideRule -Policy PhishSimOverridePolicy -Domains $PhinDomains -SenderIpRanges 198.2.177.227
            }
            catch {
                Write-Host "PhishSimOverridePolicy already exists"
            }
            }
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Phin phishing override policy has been created" -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    }
    
        
        # Mailbox Auditing
        Function MboxAudit {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Enabling mailbox auditing for all licensed users..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            $GetUsers = (Get-Mailbox -ResultSize Unlimited -Filter {RecipientTypeDetails -eq "UserMailbox"})
            $Licenses = (Get-MsolUser | Where-Object {$_.IsLicensed -eq $true}).UserPrincipalName
            $LicensedUsers = ($GetUsers.UserPrincipalName | Where-Object -FilterScript { $_ -in $Licenses})
            foreach ($LicensedUser in $LicensedUsers){
                Write-Host "Auditing enabled for " $LicensedUser
                Set-Mailbox -Identity $LicensedUser -AuditEnabled $true
            }
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Mailbox auditing is now enabled" -ForegroundColor DarkGreen
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
    
        
        
        
        # OrganizationCustomization Check 2
        Function OrgCustomizationCheck {
        if ($False -eq $GetOrgCustom) {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Making sure Organization Customization is enabled..." -ForegroundColor DarkGreen
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            try {
                Enable-OrganizationCustomization
            }
            catch {
                if ($_.Exception.GetType().FullName -eq 'System.InvalidOperationException' -and $_.Exception.Message -match 'This operation is not required. Organization is already enabled') {
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                    Write-Host "Organization is already enabled for customization." -ForegroundColor DarkGreen
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                }
                else {
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                    Write-Host "Enabling Organization Customization can take quite a while to propagate." -Foreground DarkMagenta
                    Write-Host "If you're seeing this error, re-run this script in 24 hours." -Foreground DarkMagenta
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                }
            } else {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Enabling Organization Customization can take quite a while to propagate." -Foreground DarkMagenta
            Write-Host "If you receive an error about organization customization in the next section, re-run this script in 24 hours" -Foreground DarkMagenta
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            }
        }
    }
        
        # Function for Outbound Spam Policy
        Function O365OutboundSpam {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Editing Office365 Outbound Spam Policy..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            $Outbound = (Get-HostedOutboundSpamFilterPolicy).Name
            try {
                Set-HostedOutboundSpamFilterPolicy $Outbound -RecipientLimitExternalPerHour 400 -RecipientLimitInternalPerHour 800 -RecipientLimitPerDay 800 -ActionWhenThresholdReached Alert
            } catch [System.Management.Automation.ParameterBindingException] {
                # This catch block will execute if the error is of type 'System.Management.Automation.ParameterBindingException'
                Write-Error "Cannot process argument transformation on parameter 'Identity'."
                Write-Error $_.Exception.Message
            } catch {
                # This catch block will execute for any other type of error
                Write-Error $_.Exception.Message
            }
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Office365 Outbound Spam Policy configuration complete" -ForegroundColor DarkYellow
            Write-Host  "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
    
        
        
        # Function for Anti-Spam
        Function O365AntiSpam {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Editing Office365 Anti-spam Policy..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            $Junk = "MoveToJmf"
            $Policy = (Get-HostedContentFilterPolicy).Name
            try {
                Set-HostedContentFilterPolicy $Policy -BulkThreshold 7 -HighConfidenceSpamAction $Junk -HighConfidencePhishAction Quarantine -PhishSpamAction $Junk -PhishZapEnable $true -QuarantineRetentionPeriod 30 -EnableRegionBlockList $true -RegionBlockList @{Add="CN","RU","IR","KP","TR","TW","BR","RO","CZ","JP"} -SpamAction $Junk -SpamZapEnabled $true -InlineSafetyTipsEnabled $true
            } catch [System.Management.Automation.ParameterBindingException] {
                # This catch block will execute for any type of error that occurs
                Write-Error "Cannot process argument transformation on parameter 'Identity'."
                Write-Error $_.Exception.Message
            } catch {
                # This catch block will execute for any other type of error
                Write-Error $_.Exception.Message
            }
        
            Write-Host "Office365 Anti-spam Policy configuration complete" -ForegroundColor DarkGreen
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
    
        
        
        # Default Anti-Phish Policy #
        Function O365AntiPhish {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Editing Office365 AntiPhish Policy..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        
            $Policy = "Office365 AntiPhish Default"
            Set-AntiPhishPolicy -Identity $Policy -EnableOrganizationDomainsProtection $true -EnableMailboxIntelligence $true -EnableMailboxIntelligenceProtection $true -EnableSimilarUsersSafetyTips $True -MailboxIntelligenceProtectionAction Quarantine -EnableSpoofIntelligence $true -EnableViaTag $true -EnableUnauthenticatedSender $true -TargetedUserProtectionAction MoveToJmf -TargetedDomainProtectionAction MoveToJmf
        
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Office365 AntiPhish Policy configuration complete" -ForegroundColor DarkGreen
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
    
        
        
        # Default Anti-Malware Policy #\
        Function O365AntiMal {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Configuring Office365 Anti-Malware Policy..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            $AntiMal = "Default"
            Set-MalwareFilterPolicy $AntiMal -EnableFileFilter $true -FileTypeAction "Quarantine" -ZapEnabled $true
        # Error checking and printing relevant results?
        # Write-Host -ForegroundColor DarkGreen $Color "Anti-Malware complete. Results: "
        # $GetAM | Format-List
        
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Office365 Anti-Malware Policy configuration complete" -ForegroundColor DarkGreen
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
    
        
        
        # Safe Attachments Policy
        Function O365SafeAttach {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Creating Safe Attachments Policy" -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            $Domains = (Get-AcceptedDomain).Name
            $SafeAttach = "Safe Attachments"
        
            New-SafeAttachmentPolicy -Name $SafeAttach -Enable $true -Redirect $false -QuarantineTag AdminOnlyAccessPolicy
            New-SafeAttachmentRule -Name $SafeAttach -SafeAttachmentPolicy $SafeAttach -RecipientDomainIs $Domains
        
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Safe Attachments policy has been created" -ForegroundColor DarkGreen
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
    
        
        
        # Safe Links Policy
        Function O365SafeLinks {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Creating Safe Links Policy" -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            $SafeLinks = "Safe Links"
            $Domains = (Get-AcceptedDomain).Name
            New-SafeLinksPolicy -Name $SafeLinks -EnableSafeLinksForEmail $True -DeliverMessageAfterScan $True -DisableUrlRewrite $False -EnableForInternalSenders $True -EnableSafeLinksForTeams $True -EnableSafeLinksForOffice $True  -TrackClicks $False -AllowClickThrough $False
            New-SafeLinksRule -Name $SafeLinks -SafeLinksPolicy $SafeLinks -RecipientDomainIs $Domains    
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Safe Links policy has been created" -ForegroundColor DarkGreen
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
        
        # Azure Conditional Access Policy - Any user exclusions other than the ones below should be added afterward (see Exclude Users from CA Policy)
        Function MFAPolicy {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Creating MFA Conditional Access Policy..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            $ExcludedUsers = Get-User | Where-Object {($_.UserPrincipalName -like "rs@*" -or $_.UserPrincipalName -like "scanner@*" -or $_.UserPrincipalName -like "admin@*" -or $_.UserPrincipalName -like "rsadmin@*")}
            $conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
            $conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
            $conditions.Applications.IncludeApplications = "All"
            $conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
            $conditions.Users.IncludeUsers = "All"
            $conditions.Users.ExcludeUsers = $ExcludedUsers.ExternalDirectoryObjectId
            $conditions.ClientAppTypes = "All"
            $controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
            $controls._Operator = "OR"
            $controls.BuiltInControls = @('MFA')
            $GetMFAPolicy = Get-AzureADMSConditionalAccessPolicy
            if ($GetMFAPolicy.DisplayName -notcontains "Require MFA"){
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                Write-Host "Creating MFA Conditional Access Policy..." -ForegroundColor DarkYellow
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                New-AzureADMSConditionalAccessPolicy -DisplayName "Require MFA" -State "enabledForReportingButNotEnforced" -Conditions $conditions -GrantControls $controls
        }   else {
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                Write-Host "MFA Conditional Access Policy has been created." -ForegroundColor DarkYellow
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
        }
    
        
        # N.America Logins Only Policy
        Function NAOnlyPolicy {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Creating N.America Logins Only Conditional Access Policy..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            # Creates NamedLocations Group
            $NALocations = "CA","US","MX"
            $NAPolicy = New-AzureADMSNamedLocationPolicy -OdataType "#microsoft.graph.countryNamedLocation" -DisplayName "North America" -CountriesAndRegions $NALocations -IncludeUnknownCountriesAndRegions $false
            $NAPolicy
            #Creates CA Policy
            $conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
            $conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
            $conditions.Applications.IncludeApplications = "all"
            $conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
            $conditions.Users.IncludeUsers = "all"
            $conditions.Locations = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
            $conditions.Locations.IncludeLocations = "All"
            $conditions.Locations.ExcludeLocations = $NAPolicy.Id
            $controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
            $controls._Operator = "OR"
            $controls.BuiltInControls = "block"
            New-AzureADMSConditionalAccessPolicy -DisplayName "Block logins outside North America" -State "enabledForReportingButNotEnforced" -Conditions $conditions -GrantControls $controls
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "N.America Logins Only Conditional Access Policy has been created." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
        
        #AIP Configuration
        Function AIPPolicy {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Configuring AIP settings..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        
            $AzureRMS = Set-IrmConfiguration -AzureRMSLicensingEnabled $true
            $RMSEnable = Enable-Aadrm
            $RMS = Get-AadrmConfiguration
            $License = $RMS.LicensingIntranetDistributionPointUrl
            $AzureRMS
            $RMSEnable
            $RMS
            $License
            Set-IRMConfiguration -LicensingLocation $License
            Set-IRMConfiguration -InternalLicensingEnabled $true
        
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Creating AIP email encryption rule..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            $CheckRMS = (Get-RMSTemplate).Name | Where-Object -FilterScript {$_ -eq "Encrypt"}
            $CheckRule = (Get-TransportRule).Name
            $Keywords = "securemail","encryptmail"
            if ($CheckRMS -ne "Encrypt"){
            do {
                $AzureRMS
                $RMSEnable
                $RMS
                $License
                Set-IRMConfiguration -LicensingLocation $License
                Set-IRMConfiguration -InternalLicensingEnabled $true
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkRed
                Write-Host "RMS Encryption Template not available yet. Verify that M365 Business Premium Licensing has been applied to the tenant."
                Write-Host ""
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkRed
                Start-Sleep -Seconds 60
            }until ($CheckRMS -eq "Encrypt")
            } elseif ($CheckRule -contains "Use Office365 Encryption") {
            Write-Host "'Use Office365 Encryption' rule already exists...check the mail flow rules in Exchange"
            }else {
            New-TransportRule -Name "Use Office365 Encryption" -ApplyRightsProtectionTemplate "Encrypt" -SentToScope NotInOrganization -SubjectOrBodyContainsWords  $Keywords -ExceptIfRecipientDomainIs "radersolutions.com" -Mode Enforce -Enabled $true
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "Email encryption rule has been created. AIP configuration is complete"
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
        }
    
        # Function LicenseCheck {
        #    foreach ($Domain in $Domains){
        #        $GetPartner = Get-PartnerCustomer -domain $Domain
        #        $GetLicense = (Get-PartnerCustomerSubscribedSku -customerid $CustomerId)
        #        if ($GetPartner.AllowDelegatedAccess -eq $true) {
        #            $CustomerId = $GetPartner.CustomerId
        #            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        #            Write-Host "M365 Business Premium licensing status: "
        #            Start-Sleep -Seconds 30
        #            Get-PartnerCustomerSubscribedSku -customerid $CustomerId | Where-Object {$_.ProductName -match "Microsoft 365 Business Premium" -and $_.CapabilityStatus -match "Enable"}
        #            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        #        } elseif ($GetLicense.ProductName -notcontains "Microsoft 365 Business Premium") {
        #            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkRed
        #            Write-Host "M365 Business Premium licensing not found. Current active licenses are: "
        #            $GetLicense | Where-Object {$_.CapabilityStatus -match "Enabled" -and $_.ActiveUnits -ne "0"}
        #            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkRed
        #        }
        
        #        }
        # }
        
        Function PwnedUser {
            $HawkCheck = Get-Module -ListAvailable -Name Hawk
                if ($HawkCheck) {
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                    Write-Host "Checking for HAWK module..." -ForegroundColor DarkYellow
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                    $Pwned = Read-Host  'Enter the compromised user email address'
                    Start-HawkUserInvestigation -UserPrincipalName $Pwned
                } else {
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                    Write-Host  "Starting Hawk User Investigation..."
                    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                    Set-ExecutionPolicy RemoteSigned -Confirm:$false
                    Invoke-WebRequest -Uri https://raw.githubusercontent.com/T0pCyber/hawk/master/install.ps1 -OutFile .\hawkinstall.ps1
                    Unblock-File -Path .\hawkinstall.ps1
                    .\hawkinstall.ps1
                }
        }
    
    
        Function DMARCDKIM {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host  "Setting up DKIM..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            $DNSDomain = Read-Host "Enter domain name:"
            $ResGrp = (Get-AzDnsZone | Where-Object{$_.Name -match $DNSDomain})
            $GrpName = $ResGrp.ResourceGroupName
            $Zone = $ResGrp.Name
            $Selector = Get-DkimSigningConfig $DNSDomain
            $Selector1 = $Selector.Selector1CNAME
            $Selector2 = $Selector.Selector2CNAME
            $DKIM1 = New-AzDnsRecordConfig -Cname $Selector1
            $DKIM2 = New-AzDnsRecordConfig -Cname $Selector2
        
            New-AzDnsRecordSet -Name "selector1._domainkey" -RecordType CNAME -ResourceGroupName $GrpName -Ttl 3600 -ZoneName $Zone -DnsRecords $DKIM1
        
            New-AzDnsRecordSet -Name "selector2._domainkey" -RecordType CNAME -ResourceGroupName $GrpName -Ttl 3600 -ZoneName $Zone -DnsRecords $DKIM2
        
        
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host  "DKIM keys have been published. DKIM may now be enabled. If you receive an error, try enabling DKIM again in 24 hours. "
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host  "Setting up DMARC..." -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        
            $DMARC = New-AzDnsRecordConfig -Value "v=DMARC1; p=quarantine; pct=100"
        
            New-AzDnsRecordSet -Name "_dmarc" -RecordType TXT -ResourceGroupName $GrpName -Ttl 3600 -ZoneName $Zone -DnsRecords $DMARC
        
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host  "DMARC policy has been published in DNS records. You can verify this with https://dmarcanalyzer.com" -ForegroundColor DarkYellow
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
        
        
        # Add Cofense Protect 'Report Phishing' button as organization add-in
    Function PhishButton {
        $Manifest = Read-Host "Download the Cofense Protect file and enter the file path here: (ex. c:\users\user\Downloads\manifest_BJLbbVDGL.xml) "
        $AddButton = New-OrganizationAddIn -ManifestPath $Manifest -Locale 'en-US' -AssignToEveryone -UserDefault Mandatory
        if ($AddButton) {
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Write-Host  "Adding the Cofense Protect 'Report Phishing' button..."
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        $AddButton
        } else {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host  "Cofense Protect 'Report Phishing' was added successfully." -ForegroundColor DarkGreen
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        }
    }

# EnableMFA Function        
# Enable Conditional Access policy - Make sure users are appropriately added
    Function EnableMFA{
        $GetMFAPolicy = Get-AzureADMSConditionalAccessPolicy -DisplayName "Require MFA"
        Write-Host "NOTE: All user configuration in this policy should be done BEFORE RUNNING THIS" -ForegroundColor DarkRed
        Write-Host "                                                           ___________________" -ForegroundColor DarkRed
        if ($GetMFAPolicy.DisplayName -notcontains "Require MFA"){
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            Write-Host "MFA conditional access Policy has not been created. The current conditional access policies are: " -ForegroundColor DarkYellow
            $GetMFAPolicy.DisplayName
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            } elseif (($GetMFAPolicy -contains "Require MFA") -and ($GetMFAPolicy.State -ne "Enabled")) {
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                Write-Host "Enabling MFA conditional access policy..." -ForegroundColor DarkYellow
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                Set-AzureADMSConditionalAccessPolicy -DisplayName "Require MFA" -State "enabled"
            } else {
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
                Write-Host "MFA conditional access policy is now enabled." -ForegroundColor DarkGreen
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            }
}
# End of MFA function

# Over50GB Function
# Used to find any mailboxes that are over 50GB in size for EOP2 licensing
    Function Over50GB {
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Write-Host "Getting mailboxes larger than 50 GB..." -ForegroundColor DarkYellow
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        $Mailboxes = Get-EXOMailbox
        foreach ($Mailbox in $Mailboxes) { 
            try {
                Get-EXOMailboxStatistics -Identity $Mailbox | Where-Object {[int64]($PSItem.TotalItemSize.Value -replace '.+\(|bytes\)') -gt "50GB"}
            } catch {
                Write-Host "There was an issue with " $Mailbox
        }
    }
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Write-Host "50 GB mailbox pull is complete" -ForegroundColor DarkYellow
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
}
# End of Over50GB function
    
# Updates Function
# Used by added -Update switch with Invoke-RaderSec
    Function Updates{
        # Pull RaderSecOps from GitHub
        Invoke-WebRequest -Uri https://github.com/xBurningGiraffe/RaderSecOps/archive/refs/heads/main.zip -OutFile main.zip
        Expand-Archive main.zip -DestinationPath $env:ProgramFiles\WindowsPowerShell\Modules\main -Force
        if (Get-ChildItem -Path 'C:\Program Files\windowspowershell\Modules\RaderSecOps') {
        try {
         Remove-Item 'C:\Program Files\windowspowershell\Modules\RaderSecOps' -Recurse -ErrorAction SilentlyContinue
         } catch {
         Write-Error "Error: $($_.Exception.Message)"
         }
    }
    Move-Item 'C:\Program Files\windowspowershell\Modules\main\RaderSecOps-main' 'C:\Program Files\windowspowershell\Modules\RaderSecOps' -Force -ErrorAction SilentlyContinue
    Remove-Item 'C:\Program Files\windowspowershell\Modules\main' -Recurse -ErrorAction SilentlyContinue
    # Import new modules
    Import-Module -Name RaderSecOps
    Import-Module -Name 'C:\Program Files\WindowsPowerShell\Modules\RaderSecOps\Core.psm1'
    # Add module imports to $Profile
    $ImportRadersec = 'Import-Module -Name RaderSecOps'
    $CheckProfile = (Get-Content $Profile)
        if ($CheckProfile -notcontains $ImportRadersec -or $ImportIntune) {
            Write-Output 'Import-Module -Name RaderSecOps' > $Profile
        }
            Remove-Item main.zip -Force -ErrorAction SilentlyContinue
}
    # Trigger for update switch
    if ($Updates) {
            Updates
    }
# End of Updates Function

# Intune Management Function
# Triggers Start-IntuneManagement PS
    Function Intune {
        Start-IntuneManagement
    }
# End of Intune Management Function

# SearchnDestroy Function
# Triggers SearchnDestroy for IR procedures
Function SearchnDestroy {
    Invoke-RaderSnD
}
# End of SearchnDestroy function

# AdHocSub Function
# Disables users from starting trials on behalf of organization
Function AdHocSub {
    # Check AdHocSubscriptions status
    $AHSubscriptions = Get-MsolCompanyInformation | Select-Object AllowAdHocSubscriptions
    if ($AHSubscriptions -ne $False) {
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "Disabling AdHoc Subscriptions..." -ForegroundColor DarkCyan
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Set-MsolCompanySettings -AllowAdHocSubscriptions $false
    }
    else {
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "AdHoc Subscriptions have been disabled" -ForegroundColor DarkCyan
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    }

}

Function Rader_IPHunter {
    Invoke-RaderIP_Hunter
}
# End of AdHocSub Function

# Logout Function
# Prompts user for logout and triggers Goodbye function if yes
Function Logout {
    Write-Host "-------- Return Menu ----------" -ForegroundColor DarkMagenta
    Write-Host "    [Y] Return to main menu" -ForegroundColor DarkGreen
    Write-Host "    [N] Log out " -ForegroundColor DarkRed
    Write-Host "-------------------------------" -ForegroundColor DarkMagenta
    Write-Host ""
    $script:LogoutMenu = Read-Host -Prompt "Would you like to stay logged in?: " -ForegroundColor DarkGreen
    switch ($script:OnboardMenu){
    'Y' {
        OnboardMenu
        }
    'N' {
        Goodbye
        exit
        }
    }
}
# End of Logout function
    
# Goodbye Function
# Used to fully disconnect from existing PS module connections
    Function Goodbye {
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Write-Host "Disconnecting from sessions and closing. L8er boi." -ForegroundColor DarkRed
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
            # Check Exchange Online connection
        try {
            if (Get-ConnectionInformation) {
                Disconnect-ExchangeOnline -Confirm:$false
                }
            }
            catch {
                Write-Host "An error occurred: $($_.Exception.Message)"
            }
            # Check AIPService Connection
            try {
                if (Get-AipService) {
                    Disconnect-AipService
                }
            }
            catch {
                Write-Host "An error occurred: $($_.Exception.Message)"
            }
        # Check AzureAD Connection
            try {
                if (Get-AzureADConnection -ErrorAction SilentlyContinue) {
                    # Disconnect from the AzureAD module
                    Disconnect-AzureAD
                }
            }
            catch {
                Write-Host "An error occurred: $($_.Exception.Message)"
            }
}
# End of Goodbye function

WelcomeBanner
}