# Login to the Exchange Online tenant of the customer
#Connect-ExchangeOnline
$customerName = (Get-OrganizationConfig | Select-Object identity).Identity

$policyTypes = "AntiPhishPolicy","HostedContentFilterPolicy","HostedConnectionFilterPolicy","HostedOutboundSpamFilterPolicy","MalwareFilterPolicy","SafeAttachmentPolicy","SafeLinksPolicy"
$helpDescriptions = @()
$data = @()

foreach ($policyType in $policyTypes){

    $descriptionsForPolicy = @()

    # Get all policies from a specific policy type
    $output = Invoke-Expression "Get-$policyType"
    if ($null -ne $output){

        # With the first policy (there is always one policy available) get the descriptions from the policy property by getting the help-details from the cmdlet New-'PolicyType'
        $output[0] | Get-Member -MemberType Property | ForEach-Object {
            $description = (Get-Help "New-$policyType" -Parameter $_.Name -ErrorAction SilentlyContinue).Description.Text -join ""
            $descriptionsForPolicy += @{
                Name = $_.Name;
                Description = $(@{$true = $description; $false = "Property $($_.Name) has no corresponding attribute in New-$policyType cmdlet"}[$description -ne ""]);
                PolicyType = $policyType
            }
        }
        $helpDescriptions += $descriptionsForPolicy
        
        # Go through all policies and arrange the information into the final array which will be written to JSON
        
        foreach ($record in $output){

            foreach ($member in ($record | Get-Member -MemberType Property)){
                $value = $record.($member.Name)
                $data += @{
                    CustomerName = $customerName;
                    PolicyType = $policyType;
                    Policy = $record.Name;
                    Property = $member.Name;
                    Value = $value;
                    Description = ($helpDescriptions | Where-Object { $_.policyType -eq $policyType -and $_.name -eq $member.Name}).Description;
                }
            }

        }

    }
    else{
        Write-Warning "Expression Get-$policyType did not yield any results"
    }
    
}
$data | ConvertTo-Json -Depth 2 | Out-File "EOP-policies.json"
$helpDescriptions | ConvertTo-Json -Depth 2 | Out-File "HelpDescriptions.json"