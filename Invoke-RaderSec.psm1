# RaderSecOps Script
Function Invoke-RaderSec {
  try {
    Stop-Transcript
  }
  catch [System.InvalidOperationException] {
    # Error caught, no action required
  }    
  $LogDate = (Get-Date | select-object day, month, year)
  $LogName = "RaderSecLog_$($LogDate.day)_$($LogDate.month)_$($LogDate.year)"
  Start-Transcript -Path $env:USERPROFILE\$LogName.log -Append
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
    Write-Host "----------- Onboarding -----------" -ForegroundColor DarkGreen
    Write-Host "    [1] Full Client Onboard" -ForegroundColor DarkGreen
    Write-Host "    [2] Organization Customization" -ForegroundColor DarkYellow
    Write-Host "    [3] Organization-wide Auditing" -ForegroundColor DarkYellow
    Write-Host "    [4] Litigation Hold (no longer SOP)" -ForegroundColor DarkRed
    Write-Host "    [5] Mailbox Auditing" -ForegroundColor DarkYellow
    Write-Host "    [6] O365 Outbound Spam Policy" -ForegroundColor DarkYellow
    Write-Host "    [7] O365 Anti-Spam Policy" -ForegroundColor DarkYellow
    Write-Host "    [8] O365 Anti-Phish Policy" -ForegroundColor DarkYellow
    Write-Host "    [9] O365 Anti-Malware Policy" -ForegroundColor DarkYellow
    Write-Host "    [10] O365 Safe Attachments" -ForegroundColor DarkYellow
    Write-Host "    [11] O365 Safe Links" -ForegroundColor DarkYellow
    Write-Host "    [12] MFA Conditional Access Policy" -ForegroundColor DarkYellow
    Write-Host "    [13] AIP Encryption Rule" -ForegroundColor DarkYellow
    Write-Host "    [14] Phin M365 Policies" -ForegroundColor DarkYellow
    Write-Host "    [15] North-America Only Conditional Access Policy" -ForegroundColor DarkYellow
    Write-Host " "
    Write-Host "------- Misc. O365 Options -------" -ForegroundColor DarkGreen
    Write-Host "    [O] Get Mailboxes over 50 GB" -ForegroundColor Cyan
    Write-Host "    [T] Full O365 ATP/AIP setup" -ForegroundColor Cyan
    Write-Host "    [D] DMARC/DKIM setup (Azure DNS Only)" -ForegroundColor Cyan
    Write-Host "    [M] Enable MFA Conditional Access Policy" -ForegroundColor Cyan
    Write-Host "    [G] Get RaderSec Client Data & run comands" -ForegroundColor Cyan
    Write-Host " "
    Write-Host "------------- Other --------------" -ForegroundColor DarkGreen
    Write-Host "    [V] VirusTotal Hash Search" -ForegroundColor Magenta
    Write-Host "    [R] O365 Onboarding Recon Report" -ForegroundColor Magenta
    Write-Host "    [P] BEC Incident Response" -ForegroundColor Magenta
    Write-Host "    [B] Add Cofense Protect 'Report Phishing' Button" -ForegroundColor Magenta
    Write-Host "    [I] IPHunter - Extensive IP search tool" -ForegroundColor Magenta
    Write-Host "    [IN] Deploy Intune Policies" -ForegroundColor Magenta
    Write-Host "    [U] Update RaderSecOps" -ForegroundColor Magenta
    Write-Host " "
    Write-Host "------------- Quit --------------" -ForegroundColor DarkGreen
    Write-Host "    [Q] Quit"  -ForegroundColor DarkRed
    Write-Host "---------------------------------" -ForegroundColor DarkGreen
  }
    
  # Action execution function for menu options
  Function OnboardOption {
    Do {
      OnboardMenu
      $script:OnboardType = Read-Host -Prompt "Choose a task from the menu and enter here "
      switch ($script:OnboardType) {
        '0' {
          ModuleInstalls
        }
        '1' {
          Connect-ExchangeOnline 
          Connect-AzureAD 
          Connect-MsolService 
          Connect-AIPService
          Connect-IPPSSession
          FullOnboard
        }
        '2' {
          Connect-ExchangeOnline
          OrgCustomization
          OrgCustomizationCheck
                    
        }
        '3' {
          Connect-ExchangeOnline
          OrgAuditing
                    
        }
        <#'4'{
                    Connect-MsolService
                    Connect-ExchangeOnline
                    LitHold
                }#>
        '5' {
          Connect-ExchangeOnline
          Connect-MsolService
          MboxAudit
        }
        '6' {
          Connect-ExchangeOnline
          Connect-IPPSSession
          O365OutboundSpam
        }
        '7' {
          Connect-ExchangeOnline
          Connect-IPPSSession
          O365AntiSpam
        }
        '8' {
          Connect-ExchangeOnline
          Connect-IPPSSession
          O365AntiPhish
        }
        '9' {
          Connect-ExchangeOnline
          Connect-IPPSSession
          O365AntiMal
                    
        }
        '10' {
          Connect-ExchangeOnline
          Connect-IPPSSession
          O365SafeAttach
        }
        '11' {
          Connect-ExchangeOnline
          Connect-IPPSSession
          O365SafeLinks
                    
        }
        '12' {
          Connect-ExchangeOnline
          Connect-AzureAD
          MFAPolicy
                    
                    
        }
        '13' {
          Connect-ExchangeOnline
          Connect-AipService
          AIPPolicy
        }
        '14' {
          Connect-IPPSSession
          Connect-ExchangeOnline
          PhinRule
          PhinAllows
          PhinSim
          Disconnect-ExchangeOnline
                    
        }
        '15' {
          Connect-AzureAD
          NAOnlyPolicy
          Disconnect-AzureAD
        }
        #            'L'{
        #                Connect-ExchangeOnline
        #               Connect-PartnerCenter
        #                LicenseCheck
        #            }
        'V' {
          VTSearch
        }
        'R' {
          Connect-AzureAD
          Connect-ExchangeOnline
          Connect-MsolService 
          Invoke-Rader_Recon
        }
        'P' {
          PwnUser
          Disconnect-AzAccount -Confirm:$False -ErrorAction SilentlyContinue
        }
        'D' {
          Connect-AzAccount
          Connect-ExchangeOnline
          Connect-AzureAD
          DMARCDKIM
        }
        'B' {
          Connect-ExchangeOnline
          PhishButton
        }
        'M' {
          Connect-AzureAD
          EnableMFA
        }
        'G' {
          RaderClientData
        }
        'L' {
          Connect-MsolService
          Connect-ExchangeOnline
          DisableLit
        }
        'T' {
          Connect-ExchangeOnline
          Connect-IPPSSession
          O365OutboundSpam
          O365AntiSpam
          O365AntiPhish
          O365AntiMal
          O365SafeAttach
          O365SafeLinks
        }
        'O' {
          Connect-ExchangeOnline
          Over50GB
        }
        'I' {
          Rader_IPHunter
        }
        'IN' {
          Start-IntuneManagement
        }
        'U' {
          UpdateRaderSec
        }
        'Q' {
          Goodbye
        }
      }
    } until ($script:OnboardType -eq 'Q')
  }
    
    
  # PowerShell Module Installs
  Function ModuleInstalls {
    $Modules = @("ExchangeOnlineManagement", "AzureAD", "AIPService", "MSOnline", "PartnerCenter", "OrganizationAddInService", "AzureADPreview", "Az.KeyVault")
    foreach ($Module in $Modules) {
      if ( ! ( Get-Module -Name "$Module" ) ) {
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Write-Host "Importing required Powershell modules..." -ForegroundColor DarkYellow
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Import-Module -Name $Module
        $HawkCheck = Get-Module -ListAvailable | Where-Object {$_.Name -eq "Hawk"}
        if (!$HawkCheck) {
          Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
          Write-Host "Installing HAWK module..." -ForegroundColor DarkYellow
          Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
          Set-ExecutionPolicy RemoteSigned -Confirm:$false
          Invoke-WebRequest -Uri https://raw.githubusercontent.com/T0pCyber/hawk/master/install.ps1 -OutFile .\hawkinstall.ps1
          Unblock-File -Path .\hawkinstall.ps1
          .\hawkinstall.ps1
        }
      }
      else {
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Write-Host "Installing required Powershell modules.." -ForegroundColor DarkYellow
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Install-Module -Name $Module -Force
      }
    }
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "Required Powershell modules have been installed" -ForegroundColor DarkYellow
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
    OrgCustomizationCheck
    O365OutboundSpam
    O365AntiSpam
    O365AntiPhish
    O365AntiMal
    O365SafeAttach
    O365SafeLinks
    MFAPolicy
    AIPPolicy
    NAOnlyPolicy
  }
    
  # Enable Organization Customization
  Function OrgCustomization {
    $GetOrgCust = (Get-OrganizationConfig).IsDehydrated
    try {
      if ($GetOrgCust -ne $True) {
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Write-Host "Enabling Organization Customization..." -ForegroundColor DarkYellow
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Enable-OrganizationCustomization
      }
      else {
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
        Write-Host "Organization Customization is now enabled" -ForegroundColor DarkGreen
        Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      } 
    }
    catch {
      Write-Host "An error occurred: $($_.Exception.Message)"
    }
  }
    
  # Enable Org-Wide Auditing
  Function OrgAuditing {
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "Enabling Organization-Wide Auditing" -ForegroundColor DarkYellow 
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor
    $CheckAuditing = Get-AdminAuditLogConfig
    $EnableAuditing = Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
    if (!$CheckAuditing.AdminAuditLogEnabled) {
      $EnableAuditing
    }
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "Organization-wide auditing is now enabled" -ForegroundColor DarkGreen
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
  }
    
  Function PhinRule {
    $PhinRule = "Bypass Focused Inbox for Phin"
    $SenderIPs = "198.2.177.227"
    $BypassSpam = Get-TransportRule | Where-Object { $_.Name -eq $PhinRule }
    if (!$BypassSpam) {
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host "Creating Phin bypass spam filter..." -ForegroundColor DarkYellow
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      New-TransportRule -Name $PhinRule -Priority 0 -SenderIpRanges $SenderIPs -SetAuditSeverity DoNotAudit -SetSCL -1 -SetHeaderName "X-MS-Exchange-Organization-BypassFocusedInbox" -SetHeaderValue "True" -StopRuleProcessing $True
      Start-Sleep -Seconds 15
    }
    else {
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host "Phin bypass spam filter rule already exists" -ForegroundColor DarkYellow
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    }
  } 
    
  Function PhinAllows {
    $Phins = @("*.betterphish.com/*", "*.shippingalerts.com/*", "*.amazingdealz.net/*", "*.berrysupply.net/*", "*.coronacouncil.org/*", "*.couponstash.net/*", "*.creditsafetyteam.com/*", "*.authenticate.com/*", "*.notificationhandler.com/*")
    $GetPhins = foreach ($Phin in $Phins) {
      Get-TenantAllowBlockListItems -ListType Url -ListSubType AdvancedDelivery | Where-Object { $_.Value -eq $Phin }
    }
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "Adding Phin URLs to the allowlist" -ForegroundColor DarkYellow
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    if (-not ($GetPhins)) {
      New-TenantAllowBlockListItems -ListType Url -ListSubType AdvancedDelivery -Allow -Entries $Phins -NoExpiration
    }
    else {
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host "Phin allowed URLs have been added" -ForegroundColor DarkYellow
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    }
  }
    
  Function PhinSim {
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "Creating Phin phishing override policy" -ForegroundColor DarkYellow
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    $PhinAllows = @(
      "betterphish.com",
      "shippingalerts.com",
      "amazingdealz.net",
      "berrysupply.net",
      "coronacouncil.org",
      "couponstash.net",
      "creditsafetyteam.com",
      "autheticate.com",
      "notificationhandler.com",
      "phinsecurity.com"
    )
    $PhishPolicy = "PhishSimOverridePolicy"
    $PhishRule = "PhishSimOverrideRule"
    $SenderIPs = "198.2.177.227"
    $SimCheck = Get-PhishSimOverridePolicy -Identity $PhishPolicy
    # $RuleChecks = Get-PhishSimOverrideRule.Domains
    if (!$SimCheck) {
      try {
        New-PhishSimOverridePolicy -Name $PhishPolicy
        Start-Sleep -Seconds 15
        New-PhishSimOverrideRule -Name $PhishRule -Policy $PhishPolicy -Domains $PhinAllows -SenderIpRanges $SenderIPs
      }
      catch {
        Write-Host "An error occurred while checking or creating the PhishSimOverridePolicy: $($_.Exception.Message)" -ForegroundColor DarkRed
      }
    }
    else {           
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host "Phin phishing override policy has been created" -ForegroundColor DarkYellow
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    }
  }

    
  # Mailbox Auditing
  Function MboxAudit {
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "Enabling mailbox auditing for all licensed users..." -ForegroundColor DarkYellow
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    $GetUsers = (Get-Mailbox -ResultSize Unlimited -Filter { RecipientTypeDetails -eq "UserMailbox" })
    $Licenses = (Get-MsolUser | Where-Object { $_.IsLicensed -eq $true }).UserPrincipalName
    $LicensedUsers = ($GetUsers.UserPrincipalName | Where-Object -FilterScript { $_ -in $Licenses })
    foreach ($LicensedUser in $LicensedUsers) {
      Write-Host "Auditing enabled for " $LicensedUser
      Set-Mailbox -Identity $LicensedUser -AuditEnabled $true
    }
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "Mailbox auditing is now enabled" -ForegroundColor DarkGreen
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
  }
    
    
    
  # OrganizationCustomization Check 2
  Function OrgCustomizationCheck {
    if ($GetOrgCust -eq $False) {
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host "Making sure Organization Customization is enabled..." -ForegroundColor DarkGreen
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Enable-OrganizationCustomization
    }
    elseif ($GetOrgCustom -eq $True) {
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host "Organization Customization is now enabled" -ForegroundColor DarkGreen
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    }
    else {
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host "Enabling Organization Customization can take quite a while to propagate." -Foreground DarkMagenta
      Write-Host "If you receive an error about organization customization in the next section, re-run this script in 24 hours" -Foreground DarkMagenta
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    }
  }
    
  # Function for Outbound Spam Policy
  Function O365OutboundSpam {
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "Editing Office365 Outbound Spam Policy..." -ForegroundColor DarkYellow
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    $Outbound = (Get-HostedOutboundSpamFilterPolicy).Name
    Set-HostedOutboundSpamFilterPolicy $Outbound -RecipientLimitExternalPerHour 400 -RecipientLimitInternalPerHour 800 -RecipientLimitPerDay 800 -ActionWhenThresholdReached Alert
    
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
    Set-HostedContentFilterPolicy $Policy -BulkThreshold 7 -HighConfidenceSpamAction $Junk -HighConfidencePhishAction Quarantine -PhishSpamAction $Junk -PhishZapEnable $true -QuarantineRetentionPeriod 30 -EnableRegionBlockList $true -RegionBlockList @{Add = "CN", "RU", "IR", "KP", "TR", "TW", "BR", "RO", "CZ", "JP" } -SpamAction $Junk -SpamZapEnabled $true -InlineSafetyTipsEnabled $true
    
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
    $ExcludedUsers = Get-User | Where-Object { ($_.UserPrincipalName -like "rs@*" -or $_.UserPrincipalName -like "scanner@*" -or $_.UserPrincipalName -like "admin@*" -or $_.UserPrincipalName -like "rsadmin@*") }
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
    if ($GetMFAPolicy.DisplayName -notcontains "Require MFA") {
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host "Creating MFA Conditional Access Policy..." -ForegroundColor DarkYellow
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      New-AzureADMSConditionalAccessPolicy -DisplayName "Require MFA" -State "enabledForReportingButNotEnforced" -Conditions $conditions -GrantControls $controls
    }
    else {
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
    $NALocations = "CA", "US", "MX"
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
    $CheckRMS = (Get-RMSTemplate).Name | Where-Object -FilterScript { $_ -eq "Encrypt" }
    $CheckRule = (Get-TransportRule).Name
    $Keywords = "securemail", "encryptmail"
    if ($CheckRMS -ne "Encrypt") {
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
    }
    elseif ($CheckRule -contains "Use Office365 Encryption") {
      Write-Host "'Use Office365 Encryption' rule already exists...check the mail flow rules in Exchange"
    }
    else {
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

  Function PwnUser {

Invoke-BEC_IR

}

  Function DMARCDKIM {
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host  "Setting up DKIM..." -ForegroundColor DarkYellow
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    $DNSDomain = Read-Host "Enter domain name:"
    $ResGrp = (Get-AzDnsZone | Where-Object { $_.Name -match $DNSDomain })
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
      Connect-OrganizationAddInService
      $AddButton
    }
    else {
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host  "Cofense Protect 'Report Phishing' was added successfully." -ForegroundColor DarkGreen
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    }
  }
    
  # Enable Conditional Access policy - Make sure users are appropriately added
  Function EnableMFA {
    $GetMFAPolicy = Get-AzureADMSConditionalAccessPolicy -DisplayName "Require MFA"
    Write-Host "NOTE: All user configuration in this policy should be done BEFORE RUNNING THIS" -ForegroundColor DarkRed
    Write-Host "                                                           ___________________" -ForegroundColor DarkRed
    if ($GetMFAPolicy.DisplayName -notcontains "Require MFA") {
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host "MFA conditional access Policy has not been created. The current conditional access policies are: " -ForegroundColor DarkYellow
      $GetMFAPolicy.DisplayName
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    }
    elseif (($GetMFAPolicy -contains "Require MFA") -and ($GetMFAPolicy.State -ne "Enabled")) {
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host "Enabling MFA conditional access policy..." -ForegroundColor DarkYellow
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Set-AzureADMSConditionalAccessPolicy -DisplayName "Require MFA" -State "enabled"
    }
    else {
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
      Write-Host "MFA conditional access policy is now enabled." -ForegroundColor DarkGreen
      Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    }
  }

    
    
  Function Over50GB {
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "Getting mailboxes larger than 50 GB..." -ForegroundColor DarkYellow
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    $Mailboxes = Get-EXOMailbox
    foreach ($Mailbox in $Mailboxes) { 
      try {
        Get-EXOMailboxStatistics -Identity $Mailbox | Where-Object { [int64]($PSItem.TotalItemSize.Value -replace '.+\(|bytes\)') -gt "50GB" }
      }
      catch {
        Write-Host "There was an issue with " $Mailbox
      }
    }
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "50 GB mailbox pull is complete" -ForegroundColor DarkYellow
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
  }

  Function Rader_IPHunter {
    Invoke-RaderIP_Hunter
  }

  #Function CAUserExclusion {
  #    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
  #    $UserExclusions = Read-Host "Enter the email address for each user you'd like to exclude from the conditional access policy "
  #    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
  #    $GetPolicy = Get-AzureADMSConditionalAccessPolicy | where {$_.DisplayName -eq "Require MFA"}
  #    foreach ($UserExclusion in $UserExclusions) {
  #        $ExID = Get-User -Identity $UserExclusion
  #       $conditions.Users.ExcludeUsers = $ExID.ExternalDirectoryObjectId
  #        Set-AzureADMSConditionalAccessPolicy -PolicyId $GetPolicy.Id -Conditions $conditions
  #   }
  #
  #}

  Function VTSearch {
    $AzCheck = Get-AzContext

    if ($null -eq $AzCheck) {
      Write-Host "Connect to your Rader Solutions account"
      Connect-AzAccount
    }
    else {
      $SearchHash = Read-Host 'Enter the file hash to search '
      Get-VTHashSearch $SearchHash
    }
  }
    
  Function UpdateRaderSec {
    $ModulePath = "$($env:ProgramFiles)\WindowsPowerShell\Modules"
    $Url = "https://github.com/xBurningGiraffe/RaderSecOps/archive/refs/heads/main.zip"
    $RaderSecPath = "$($ModulePath)\RaderSecOps"

    # Remove the RaderSecOps folder if it exists
    if (Test-Path $RaderSecPath) {
        Remove-Item $RaderSecPath -Recurse -Force
    }

    # Download the RaderSecOps module from the URL
    Invoke-WebRequest -Uri $Url -OutFile main.zip

    # Extract the contents of the .zip file to the Modules folder
    Expand-Archive .\main.zip -DestinationPath $ModulePath -Force

    # Change Module Name
    Move-item "$($ModulePath)\RaderSecOps-main" "$($ModulePath)\RaderSecOps"

    # Remove the .zip file
    Remove-Item main.zip -Force

<#     $ProfilePath = "$($env:USERPROFILE)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    if (!(Select-String -Path $ProfilePath -Pattern 'Import-Module -Name RaderSecOps') -or !(Select-String -Path $ProfilePath -Pattern 'Import-Module -Name $env:ProgramFiles\WindowsPowerShell\Modules\RaderSecOps\Start-IntuneManagement.psm1')) {
        'Import-Module -Name RaderSecOps' | Add-Content -Path $ProfilePath
        'Import-Module -Name $env:ProgramFiles\WindowsPowerShell\Modules\RaderSecOps\Start-IntuneManagement.psm1' | Add-Content -Path $ProfilePath
    } #>

    $ProfilePath = "$($env:USERPROFILE)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    $ReadPath = type $ProfilePath
    $RaderSecOps = "Import-Module -Name RaderSecOps"
    $IntuneModule = "Import-Module -Name $env:ProgramFiles\WindowsPowerShell\Modules\RaderSecOps\Start-IntuneManagement.psm1"

    if ($ReadPath -notcontains $RaderSecOps -or $ReadPath -notcontains $IntuneModule) {
      echo "$($RaderSecOps)" >> $ProfilePath
      echo "$($IntuneModule)" >> $ProfilePath
    }

    Write-Host "RaderSecOps has been updated. Restart RaderSecOps in a new tab or PowerShell window." -ForegroundColor DarkGreen
}




  Function Intune {
    Start-IntuneManagement
  }

  Function RaderClientData {
    Start-RaderSecQuery
  }
    
    
  # Clear variables
  Function NullVariables {
    $ClearVars = "Domains"
    foreach ($ClearVar in $ClearVars) {
      Clear-Variable -Name $ClearVar -Scope script
    }
  }


  # Function for disconnecting and breaking
  Function Goodbye {
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host "Disconnecting from sessions and closing. L8er boi."
    Write-Host "----------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen

    try {
      Get-ExoMailbox -ResultSize 1
    }
    catch [Microsoft.Exchange.Management.RestApiClient.RestClientException] {
      Write-Output 'Disconnecting from Exchange Online...'
      Disconnect-ExchangeOnline -Confirm:$false
    }


    try {
      Disconnect-AipService
    }
    catch {
      Write-Output 'An error occurred while disconnecting from the Azure Information Protection service.'
    }

    try {
      Disconnect-AzureAD -ErrorAction SilentlyContinue
      Write-Output 'Disconnected from Azure AD.'
    }
    catch [System.NullReferenceException] {
      Write-Output 'Disconnected from Azure AD.' 
    }
        
    try {
      Disconnect-AzAccount -ErrorAction SilentlyContinue
      Write-Output "Disconnected from AzAccount"
    }
    catch {
      Write-Output "Disconnected from AzAccount."
    }
  }
  WelcomeBanner
}
