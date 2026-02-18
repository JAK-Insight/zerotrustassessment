# src\powershell\tests\Test-Assessment.35040.ps1

<#
.SYNOPSIS
    DLP policies are configured for Exchange Online
#>

function Test-Assessment-35040 {
    [ZtTest(
        Category = 'Data Loss Prevention (DLP)',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Microsoft 365 E3'),
        Pillar = 'Data',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 35040,
        Title = 'DLP policies are configured for Exchange Online',
        UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking DLP policy coverage for Exchange Online'
    Write-ZtProgress -Activity $activity -Status 'Getting DLP policies'

    $errorMsg = $null
    $dlpPolicies = @()

    try {
        $dlpPolicies = Get-DlpCompliancePolicy -ErrorAction Stop
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage "Error querying DLP policies: $_" -Level Error
    }
    #endregion Data Collection

    #region Assessment Logic
    $exchangePolicies = @()
    $exchangeEnabledPolicies = @()
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine DLP policy coverage for Exchange Online due to permissions issues or query failure.`n`n"
        $customStatus = 'Investigate'
    }
    else {
        # Filter policies that include Exchange Online as a location
        foreach ($policy in $dlpPolicies) {
            $hasExchange = $false
            if ($policy.ExchangeLocation) {
                $locations = @($policy.ExchangeLocation)
                if ($locations.Count -gt 0) {
                    $hasExchange = $true
                }
            }

            if ($hasExchange) {
                $exchangePolicies += $policy
                if ($policy.Mode -eq 'Enable') {
                    $exchangeEnabledPolicies += $policy
                }
            }
        }

        if ($exchangeEnabledPolicies.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ $($exchangeEnabledPolicies.Count) DLP policy(ies) are configured and enabled for Exchange Online.`n`n%TestResult%"
        }
        elseif ($exchangePolicies.Count -gt 0) {
            $passed = $false
            $testResultMarkdown = "❌ $($exchangePolicies.Count) DLP policy(ies) include Exchange Online but none are in enforcement mode.`n`n%TestResult%"
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ No DLP policies are configured that include Exchange Online as a protected location. Sensitive data can be sent via email without detection or prevention.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($exchangePolicies.Count -gt 0) {
        $mdInfo += "`n`n### [DLP Policies covering Exchange Online](https://purview.microsoft.com/datalossprevention/policies)`n"
        $mdInfo += "| Policy Name | Mode | Exchange Location | Created |`n"
        $mdInfo += "| :--- | :--- | :--- | :--- |`n"

        foreach ($policy in $exchangePolicies) {
            $policyName = Get-SafeMarkdown -Text $policy.Name
            $icon = if ($policy.Mode -eq 'Enable') { '✅' } else { '⚠️' }
            $modeDisplay = switch ($policy.Mode) {
                'Enable' { 'Enforcing' }
                'TestWithNotifications' { 'Simulation (with tips)' }
                'TestWithoutNotifications' { 'Simulation (no tips)' }
                default { $policy.Mode }
            }
            $exchangeLoc = ($policy.ExchangeLocation | ForEach-Object { $_.Name }) -join ', '
            $created = Get-FormattedDate -Date $policy.WhenCreatedUTC
            $mdInfo += "| $icon $policyName | $modeDisplay | $exchangeLoc | $created |`n"
        }
    }

    if ($dlpPolicies.Count -gt 0 -and $exchangePolicies.Count -eq 0) {
        $mdInfo += "`n`n### Note`n"
        $mdInfo += "$($dlpPolicies.Count) DLP policy(ies) exist in the tenant but none include Exchange Online as a location.`n"
    }

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Total DLP policies in tenant | $($dlpPolicies.Count) |`n"
    $mdInfo += "| DLP policies covering Exchange Online | $($exchangePolicies.Count) |`n"
    $mdInfo += "| DLP policies enforcing on Exchange Online | $($exchangeEnabledPolicies.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35040'
        Title  = 'DLP policies are configured for Exchange Online'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
