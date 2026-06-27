param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('internet-test', 'lan-only')]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$ProgramPath,

    [int]$Port = 8080,

    [switch]$RemoveOnly
)

$ErrorActionPreference = 'Stop'

$rulePrefix = 'WebsiteBuu'
$programFullPath = (Resolve-Path $ProgramPath).Path
$managedRules = @(
    "$rulePrefix Allow Inbound LAN",
    "$rulePrefix Block Inbound Public",
    "$rulePrefix Allow Outbound LAN",
    "$rulePrefix Block Outbound Internet"
)

function Remove-ManagedRules {
    foreach ($ruleName in $managedRules) {
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule | Out-Null
    }
}

Remove-ManagedRules

if ($RemoveOnly) {
    Write-Host 'Removed WebsiteBuu firewall rules.'
    exit 0
}

if ($Mode -eq 'internet-test') {
    Write-Host 'Internet-test mode selected. No restrictive WebsiteBuu firewall rules were applied.'
    exit 0
}

New-NetFirewallRule -DisplayName "$rulePrefix Allow Inbound LAN" \
    -Direction Inbound \
    -Action Allow \
    -Program $programFullPath \
    -Protocol TCP \
    -LocalPort $Port \
    -RemoteAddress LocalSubnet | Out-Null

New-NetFirewallRule -DisplayName "$rulePrefix Block Inbound Public" \
    -Direction Inbound \
    -Action Block \
    -Program $programFullPath \
    -Protocol TCP \
    -LocalPort $Port \
    -RemoteAddress Any | Out-Null

New-NetFirewallRule -DisplayName "$rulePrefix Allow Outbound LAN" \
    -Direction Outbound \
    -Action Allow \
    -Program $programFullPath \
    -Protocol Any \
    -RemoteAddress LocalSubnet | Out-Null

New-NetFirewallRule -DisplayName "$rulePrefix Block Outbound Internet" \
    -Direction Outbound \
    -Action Block \
    -Program $programFullPath \
    -Protocol Any \
    -RemoteAddress Any | Out-Null

Write-Host "Applied lan-only firewall policy for $programFullPath on port $Port"