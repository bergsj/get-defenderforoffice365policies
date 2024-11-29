Connect-MgGraph
Connect-ExchangeOnline

$domains = Get-MgDomain | Select-Object Id
$policyName = "Standard Preset Security Policy - <CUSTOMERNAME>"
$policyTypes =  "AntiPhish",
                "HostedContentFilter",
                "MalwareFilter",
                "SafeAttachment",
                "SafeLinks"

foreach ($policyType in $policyTypes){

    $getCommand = ("Get-{0}Rule" -f $policyType)
    $setCommand = ("Set-{0}Rule" -f $policyType)

    $command = $getCommand + " -Identity `"$policyName`" | $setCommand -RecipientDomainIs " + ($domains.id -join ",")
    #Invoke-Expression $command
    $command
}