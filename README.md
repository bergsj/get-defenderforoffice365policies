# Get-DefenderForOffice365Policies

Script to get the Exchange Online Protection policies and store the information in a JSON and Excel files.

# Exchange Policy Information
Information on the cmdlets the script uses and where to find corresponding configuration  in the Microsoft Security (Defender) portal.

## EOP policies
### Anti-phising policies
**UI:** _Policies & rules > Threat policies > Anti-phishing_

`Get-AntiPhishPolicy`

> Use the Get-AntiPhishPolicy cmdlet to view antiphish policies in your cloud-based organization. This cmdlet returns results only in Exchange Online PowerShell.

### Anti-spam policies
**UI:** _Policies & rules > Threat policies > Anti-spam_

`Get-HostedContentFilterPolicy`
> Use the Get-HostedContentFilterPolicy cmdlet to view the settings of spam filter policies (content filter policies) in your cloud-based organization.
Get-HostedOutboundSpamFilterPolicy
> Use the Get-HostedOutboundSpamFilterPolicy cmdlet to view outbound spam filter policies in your cloud-based organization.

### Anti-malware policies
**UI:** _Policies & rules > Threat policies > Anti-malware_

`Get-MalwareFilterPolicy`

> Use the Get-MalwareFilterPolicy cmdlet to view the malware filter policies in your organization.

### Quarantine policies
**UI:** _Policies & rules > Threat policies > Quarantine policies_

`Get-QuarantinePolicy`

> Use the Get-QuarantinePolicy cmdlet to view quarantine policies in your cloud-based organization.

## Defender for Office 365 policies:
### SafeAttachment policies
**UI:** _Policies & rules > Threat policies > Safe Attachments_

`Get-SafeAttachmentPolicy`

> Use the Get-SafeAttachmentPolicy cmdlet to view safe attachment policies in your cloud-based organization.

### SafeLinks policies
**UI:** _Policies & rules > Threat policies > Safe Links_

`Get-SafeLinksPolicy`

> Use the Get-SafeLinksPolicy cmdlet to view Safe Links policies in your cloud-based organization.

## Rules for Exchange Online Protection (EOP) protections: 

`Get-EOPProtectionPolicyRule`

**UI:** _Policies & rules > Threat policies > Preset security policies > Standard/Strict Protection > Manage protection settings > Exchange online protection_
> Use the Get-EOPProtectionPolicyRule cmdlet to view rules for Exchange Online Protection (EOP) protections in preset security policies. The rules specify recipient conditions and exceptions for the protection, and also allow you to turn on and turn off the associated preset security policies.

## Policy and rules for Teams protection
**UI:** _Settings > Email & collaboration > Microsoft Teams Protection_

`Get-TeamsProtectionPolicy`

> Use the Get-TeamsProtectionPolicy cmdlet to view Microsoft Teams protection policies

`Get-TeamsProtectionPolicyRule`

> Use the Get-TeamsProtectionPolicyRule cmdlet to view Microsoft Teams protection policy rules.

## Rules for Defender for Office 365 protections:

`Get-ATPProtectionPolicyRule`

**UI:** _Policies & rules > Threat policies > Preset security policies > Standard/Strict Protection > Manage protection settings > Defender for Office 365 protection_
> Use the Get-ATPProtectionPolicyRule cmdlet to view rules for Microsoft Defender for Office 365 protections in preset security policies. The rules specify recipient conditions and exceptions for the protection, and also allow you to turn on and turn off the associated preset security policies.

`Get-ATPBuiltInProtectionRule`

**UI:** _Settings > Email & collaboration > Preset security policies > Built-in protection > Add exclusions (Not recommended)_
> Use the Get-ATPBuiltInProtectionRule cmdlet to view the rule for the Built-in protection preset security policy that effectively provides default policies for Safe Links and Safe Attachments in Microsoft Defender for Office 365. The rule specifies exceptions to the policy.

`Get-AtpPolicyForO365`

**UI:** _Policies & rules > Threat policies > Safe attachments > Global settings_
> Use the Get-AtpPolicyForO365 cmdlet to view the settings for the following features in Microsoft Defender for Office 365:
> - Safe Links protection for supported Office 365 apps.
> -  Safe Documents: Uses Microsoft Defender for Endpoint to scan documents and files that are opened in Protected View in Microsoft 365 apps for enterprise.
> -  Safe Attachments for SharePoint, OneDrive, and Microsoft Teams.

# Tenant Allow/Block List items
`Get-TenantAllowBlockListItems -ListType Sender` [Feature not yet enabled for: BulkSender, Recipient, IP]

**UI:** _Policies & rules > Threat policies > Tenant Allow/Block List > Domains & addresses_

`Get-TenantAllowBlockListItems -ListType Url` [Feature not yet enabled for: BulkSender, Recipient, IP])

**UI:** _Policies & rules > Threat policies > Tenant Allow/Block List > Urls_

`Get-TenantAllowBlockListItems -ListType FileHash` [Feature not yet enabled for: BulkSender, Recipient, IP])

**UI:** _Policies & rules > Threat policies > Tenant Allow/Block List > Files_

> Use the Get-TenantAllowBlockListItems cmdlet to view entries in the Tenant Allow/Block List in the Microsoft 365 Defender portal.

`Get-TenantAllowBlockListSpoofItems`

**UI:** _Policies & rules > Threat policies > Tenant Allow/Block List > Spoofed Senders_

> Use the Get-TenantAllowBlockListSpoofItems cmdlet to view spoofed sender entries in the Tenant Allow/Block List.

# TODO
- Add retrieval of domains
- Get the current Rule configuration