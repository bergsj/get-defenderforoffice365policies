# Install and import the module ExchangeOnlineManagement
if(-not (Get-Module ExchangeOnlineManagement -ListAvailable)){
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
    Import-Module ExchangeOnlineManagement -DisableNameChecking
}
# Install and import the module ImportExcel (https://github.com/dfinke/ImportExcel)
if(-not (Get-Module ImportExcel -ListAvailable)){
    Install-Module ImportExcel -Scope CurrentUser -Force
    Import-Module ImportExcel -DisableNameChecking
}
# Login to the Exchange Online tenant of the customer
Write-Host "Login to the Exchange Online"
$testdata = (Get-EXOMailbox -ResultSize 1 -ErrorAction SilentlyContinue)
if (-not $testdata){
    $tenant = Read-Host -Prompt "Enter tenant name (eg: customer.onmicrosoft.com"
    Import-Module ExchangeOnlineManagement -DisableNameChecking
    Connect-ExchangeOnline -DelegatedOrganization $tenant
}

#TODO; test if we need to login
Write-Host "Login to the Exchange Online for Security & Compliance PowerShell"
Connect-IPPSSession

# All these types are effectively turned into the PowerShell cmdlet: Get-PolicyType
# If there is a PowerShell cmdlet that does not have accompanying 'New-PolicyType' cmdlet (used to get parameter descriptions), then add ?? at the end
# If the 'Get-' cmdlet requires parameters to get the information then add | at then end followed by the arguments seperated by !

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
                "TenantAllowBlockListItems|ListType!FileHash",
                "ProtectionAlert@"
$helpDescriptions = @()
$data = @()

foreach ($policyType in $policyTypes){

    $descriptionsForPolicy = @()
    $getHelp = $true
    $command = "Get-$policyType"
    $alertPolicies = $false
    
    if ($policyType -match "\|"){
        $policyTypeAndArgument = $policyType.Split("|")
        $argumentAndValue = $policyTypeAndArgument[1].Split("!")
        $policyType = $policyTypeAndArgument[0]
        $command = "Get-$policyType -$($argumentAndValue[0]) $($argumentAndValue[1])"
    }
    if ($policyType -match "\?"){
        $command = $command.Trim("??")
        $policyType = $policyType.Trim("??")
        $getHelp = $false
    }
    if ($policyType -match "\@"){
        $command = $command.Trim("@")
        $policyType = $policyType.Trim("@")
        $getHelp = $false
        $alertPolicies = $true
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
        
        if ($alertPolicies){
            foreach ($record in $output){

                $data += @{
                    CustomerName = $customerName
                    PolicyType = $policyType
                    Policy = $record.Name
                    Property = ""
                    Value = $(@{$true = "Disabled"; $false = "Enabled"}[$record.Disabled])
                    Description = $record.Comment
                    Category = $record.Category
                    Severity = $record.Severity
                }

            }
        }
        else{
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
                        Category = ""
                        Severity = ""
                    }
                }

            }
        }

    }
    else{
        Write-Warning "Expression Get-$policyType did not yield any results"
    }
    
}

# Convert data and export to JSON, then import back (seems redundant, but this is due to a weird bug when directly exporting to Excel) and export to Excel
$sortedData = $data | Select-Object CustomerName, PolicyType, Policy, Property, Value, Description, Category, Severity
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
