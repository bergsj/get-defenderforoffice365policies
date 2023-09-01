# Install and import the module ExchangeOnlineManagement
if(-not (Get-Module ExchangeOnlineManagement -ListAvailable)){
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
    Import-Module ExchangeOnlineManagement
}
# Install and import the module ImportExcel (https://github.com/dfinke/ImportExcel)
if(-not (Get-Module ImportExcel -ListAvailable)){
    Install-Module ImportExcel -Scope CurrentUser -Force
    Import-Module ImportExcel
}
# Login to the Exchange Online tenant of the customer
$testdata = (Get-EXOMailbox -ResultSize 1 -ErrorAction SilentlyContinue)
if (-not $testdata){
    $tenant = Read-Host -Prompt "Enter tenant name (eg: customer.onmicrosoft.com"
    Import-Module ExchangeOnlineManagement
    Connect-ExchangeOnline -DelegatedOrganization $tenant
}

# All these types are effectively turned into the PowerShell cmdlet: Get-PolicyType
# If there is a PowerShell cmdlet that does not have accompanying New-PolicyType version, then add ?? at the end
# If the Get cmdlet requires parameters to get the information then add | at then end followed by the arguments seperated by !
$policyTypes =  "AntiPhishPolicy",
                "HostedContentFilterPolicy",
                "HostedConnectionFilterPolicy",
                "HostedOutboundSpamFilterPolicy",
                "MalwareFilterPolicy",
                "SafeAttachmentPolicy",
                "SafeLinksPolicy",
                "QuarantinePolicy",
                "HostedOutboundSpamFilterPolicy",
                "EOPProtectionPolicyRule",
                "TeamsProtectionPolicy",
                "TeamsProtectionPolicyRule",
                "ATPProtectionPolicyRule",
                "ATPBuiltInProtectionRule",
                "AtpPolicyForO365??",
                "TenantAllowBlockListItems|ListType!Sender",
                "TenantAllowBlockListItems|ListType!Url",
                "TenantAllowBlockListItems|ListType!FileHash"
$helpDescriptions = @()
$data = @()

foreach ($policyType in $policyTypes){

    $descriptionsForPolicy = @()
    $getHelp = $true    
    $command = "Get-$policyType"
    
    if ($policyType -match "\|"){
        $policyTypeAndArgument = $policyType.Split("|")
        $argumentAndValue = $policyTypeAndArgument[1].Split("!")
        $policyType = $policyTypeAndArgument[0]
        $command = "Get-$policyType -$($argumentAndValue[0]) $($argumentAndValue[1])"
    }
    if ($policyType -match "\?"){
        $command = $command.Trim("??")
        $getHelp = $false
    }
    
    Write-Host "Get information for Policy Type: $policyType"
    Write-Verbose "Run command [$command]"
    # Get all policies from a specific policy type
    $output = Invoke-Expression $command
    if ($null -ne $output){

        if ($getHelp){
            # With the first policy (there is always one policy available) get the descriptions from the policy property by getting the help-details from the cmdlet New-'PolicyType'
            $output[0] | Get-Member -MemberType Property | ForEach-Object {
                $command = "Get-Help `"New-$policyType`" -Parameter $($_.Name) -ErrorAction SilentlyContinue"
                Write-Verbose "Run command [$command]"
                $description = (Get-Help "New-$policyType" -Parameter $_.Name -ErrorAction SilentlyContinue).Description.Text -join ""
                $descriptionsForPolicy += @{
                    Name = $_.Name;
                    Description = $(@{$true = $description; $false = "Property $($_.Name) has no corresponding attribute in New-$policyType cmdlet"}[$description -ne ""]);
                    PolicyType = $policyType
                }
            }
            $helpDescriptions += $descriptionsForPolicy
        }
        # Go through all policies and arrange the information into the final array which will be written to JSON
        
        foreach ($record in $output){

            foreach ($member in ($record | Get-Member -MemberType Property)){
                $value = $record.($member.Name)
                if ($null -ne $value){
                if ($value.GetType().Name -eq "ArrayList"){
                    $value = $value -join ","
                }}
                $data += @{
                    CustomerName = $customerName
                    PolicyType = $policyType
                    Policy = $record.Name
                    Property = $member.Name
                    Value = $value
                    Description = ($helpDescriptions | Where-Object { $_.policyType -eq $policyType -and $_.name -eq $member.Name}).Description
                }
            }

        }

    }
    else{
        Write-Warning "Expression Get-$policyType did not yield any results"
    }
    
}

# Convert data and export to JSON, then import back (seems redundant, but this is due to a weird bug when directly exporting to Excel) and export to Excel
$sortedData = $data | Select-Object CustomerName, PolicyType, Policy, Property, Value, Description
$sortedData | ConvertTo-Json -Depth 2 | Out-File "defender-office365-policies.json"
$excel = Get-Content "defender-office365-policies.json" | ConvertFrom-Json | Export-Excel -Path "defender-office365-policies.xlsx" -Autosize -Table definitions -FreezeTopRow -PassThru
$sheet = $excel.Workbook.Worksheets["Sheet1"]
$sheet.Column(6) | Set-ExcelRange -width 100 -WrapText
$sheet.Column(5) | Set-ExcelRange -width 100 -WrapText -HorizontalAlignment Left
Export-Excel -ExcelPackage $excel

$helpDescriptions | ConvertTo-Json -Depth 2 | Out-File "helpdescriptions.json"
$excel = Get-Content "helpdescriptions.json" | ConvertFrom-Json | Export-Excel -Path "helpdescriptions.xlsx" -Autosize -Table descriptions -Freezetoprow -PassThru
$sheet = $excel.Workbook.Worksheets["Sheet1"]
$sheet.Column(3) | Set-ExcelRange -width 100 -WrapText
Export-Excel -ExcelPackage $excel


<#

### Information on the cmdlets and where to find this in the portal ###

## EOP policies:
# Anti-phising policies (Policies & rules > Threat policies > Anti-phishing)
Get-AntiPhishPolicy 
# Use the Get-AntiPhishPolicy cmdlet to view antiphish policies in your cloud-based organization. This cmdlet returns results only in Exchange Online PowerShell.

# Anti-spam policies (Policies & rules > Threat policies > Anti-spam)
Get-HostedContentFilterPolicy 
# Use the Get-HostedContentFilterPolicy cmdlet to view the settings of spam filter policies (content filter policies) in your cloud-based organization.
Get-HostedOutboundSpamFilterPolicy
# Use the Get-HostedOutboundSpamFilterPolicy cmdlet to view outbound spam filter policies in your cloud-based organization.

# Anti-malware policies (Policies & rules > Threat policies > Anti-malware)
Get-MalwareFilterPolicy
# Use the Get-MalwareFilterPolicy cmdlet to view the malware filter policies in your organization.

#Quarantine policies (Policies & rules > Threat policies > Quarantine policies)
Get-QuarantinePolicy
# Use the Get-QuarantinePolicy cmdlet to view quarantine policies in your cloud-based organization.

## Defender for Office 365 policies:
# SafeAttachment policies (Policies & rules > Threat policies > Safe Attachments)
Get-SafeAttachmentPolicy
# Use the Get-SafeAttachmentPolicy cmdlet to view safe attachment policies in your cloud-based organization.

# SafeLinks policies (Policies & rules > Threat policies > Safe Links)
Get-SafeLinksPolicy
# Use the Get-SafeLinksPolicy cmdlet to view Safe Links policies in your cloud-based organization.

## Rules for Exchange Online Protection (EOP) protections: 
Get-EOPProtectionPolicyRule (Policies & rules > Threat policies > Preset security policies > Standard/Strict Protection > Manage protection settings > Exchange online protection)
# Use the Get-EOPProtectionPolicyRule cmdlet to view rules for Exchange Online Protection (EOP) protections in preset security policies. 
# The rules specify recipient conditions and exceptions for the protection, and also allow you to turn on and turn off the associated preset
# security policies.

## Policy and rules for Teams protection (Settings > Email & collaboration > Microsoft Teams Protection)
Get-TeamsProtectionPolicy
# Use the Get-TeamsProtectionPolicy cmdlet to view Microsoft Teams protection policies
Get-TeamsProtectionPolicyRule
# Use the Get-TeamsProtectionPolicyRule cmdlet to view Microsoft Teams protection policy rules.

## Rules for Defender for Office 365 protections:
Get-ATPProtectionPolicyRule (Policies & rules > Threat policies > Preset security policies > Standard/Strict Protection > Manage protection settings > Defender for Office 365 protection)
# Use the Get-ATPProtectionPolicyRule cmdlet to view rules for Microsoft Defender for Office 365 protections in preset security policies. 
# The rules specify recipient conditions and exceptions for the protection, and also allow you to turn on and turn off the associated preset
# security policies.

Get-ATPBuiltInProtectionRule (Settings > Email & collaboration > Preset security policies > Built-in protection > Add exclusions (Not recommended))
# Use the Get-ATPBuiltInProtectionRule cmdlet to view the rule for the Built-in protection preset security policy that effectively provides 
# default policies for Safe Links and Safe Attachments in Microsoft Defender for Office 365. The rule specifies exceptions to the policy.

Get-AtpPolicyForO365 (Policies & rules > Threat policies > Safe attachments > Global settings)
# Use the Get-AtpPolicyForO365 cmdlet to view the settings for the following features in Microsoft Defender for Office 365:
# Safe Links protection for supported Office 365 apps.
# Safe Documents: Uses Microsoft Defender for Endpoint to scan documents and files that are opened in Protected View in Microsoft 365 apps for enterprise.
# Safe Attachments for SharePoint, OneDrive, and Microsoft Teams.

# Tenant Allow/Block List items
Get-TenantAllowBlockListItems -ListType Sender [Feature not yet enabled for: BulkSender, Recipient, IP] (Policies & rules > Threat policies > Tenant Allow/Block List > Domains & addresses)
Get-TenantAllowBlockListItems -ListType Url [Feature not yet enabled for: BulkSender, Recipient, IP]) (Policies & rules > Threat policies > Tenant Allow/Block List > Urls)
Get-TenantAllowBlockListItems -ListType FileHash [Feature not yet enabled for: BulkSender, Recipient, IP]) (Policies & rules > Threat policies > Tenant Allow/Block List > Files)
# Use the Get-TenantAllowBlockListItems cmdlet to view entries in the Tenant Allow/Block List in the Microsoft 365 Defender portal.

Get-TenantAllowBlockListSpoofItems (Policies & rules > Threat policies > Tenant Allow/Block List > Spoofed Senders)
# Use the Get-TenantAllowBlockListSpoofItems cmdlet to view spoofed sender entries in the Tenant Allow/Block List.

#>