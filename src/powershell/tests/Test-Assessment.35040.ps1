<#
.SYNOPSIS
    DLP policies are configured for Exchange Online
.DESCRIPTION
    Checks whether Data Loss Prevention (DLP) policies are configured and enforced
    for Exchange Online. At least one policy should be in enforcement mode to provide
    active protection against sensitive data loss via email.
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
        $dlpPolicies = @(Get-DlpCompliancePolicy -ErrorAction Stop)
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage "Error querying DLP policies: $_" -Level Error
    }
    #endregion Data Collection

    #region Assessment Logic
    $exchangePolicies = [System.Collections.Generic.List[object]]::new()
    $exchangeEnabledPolicies = [System.Collections.Generic.List[object]]::new()
    $exchangeSimulationPolicies = [System.Collections.Generic.List[object]]::new()
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine DLP policy coverage for Exchange Online due to permissions issues or query failure.`n`n"
        $customStatus = 'Investigate'
    }
    else {
        # Filter policies that include Exchange Online as a location
        foreach ($policy in $dlpPolicies) {
            if ($policy.ExchangeLocation -and @($policy.ExchangeLocation).Count -gt 0) {
                $exchangePolicies.Add($policy)

                switch ($policy.Mode) {
                    'Enable' {
                        $exchangeEnabledPolicies.Add($policy)
                    }
                    { $_ -in 'TestWithNotifications', 'TestWithoutNotifications' } {
                        $exchangeSimulationPolicies.Add($policy)
                    }
                }
            }
        }

        if ($exchangeEnabledPolicies.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ $($exchangeEnabledPolicies.Count) DLP policy(ies) are configured and actively enforcing on Exchange Online.`n`n"

            # Surface simulation-mode policies as an improvement opportunity
            if ($exchangeSimulationPolicies.Count -gt 0) {
                $testResultMarkdown += "⚠️ **Improvement opportunity:** $($exchangeSimulationPolicies.Count) additional policy(ies) are in simulation mode. "
                $testResultMarkdown += "Review match reports in [DLP Activity Explorer](https://purview.microsoft.com/datalossprevention/activityexplorer) and consider promoting to enforcement.`n`n"
            }

            $testResultMarkdown += "%TestResult%"
        }
        elseif ($exchangePolicies.Count -gt 0) {
            $passed = $false
            $testResultMarkdown = "❌ $($exchangePolicies.Count) DLP policy(ies) include Exchange Online but none are in enforcement mode.`n`n"
            $testResultMarkdown += "Policies in simulation mode detect sensitive content but **do not block or protect it**. "
            $testResultMarkdown += "Review match reports and promote at least one policy to enforcement.`n`n"
            $testResultMarkdown += "%TestResult%"
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ No DLP policies are configured that include Exchange Online as a protected location. "
            $testResultMarkdown += "Sensitive data can be sent via email without detection or prevention.`n`n"
            $testResultMarkdown += "%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($exchangePolicies.Count -gt 0) {
        $mdInfo += "`n`n### [DLP Policies covering Exchange Online](https://purview.microsoft.com/datalossprevention/policies)`n"
        $mdInfo += "| | Policy Name | Mode | Exchange Scope | Created |`n"
        $mdInfo += "| :---: | :--- | :--- | :--- | :--- |`n"

        # Sort: enforcing first, then simulation, then other
        $sortedPolicies = $exchangePolicies | Sort-Object @{
            Expression = {
                switch ($_.Mode) {
                    'Enable'                   { 0 }
                    'TestWithNotifications'    { 1 }
                    'TestWithoutNotifications' { 2 }
                    default                    { 3 }
                }
            }
        }

        foreach ($policy in $sortedPolicies) {
            $policyName = Get-SafeMarkdown -Text $policy.Name
            $icon = switch ($policy.Mode) {
                'Enable'                   { '✅' }
                'TestWithNotifications'    { '🧪' }
                'TestWithoutNotifications' { '🧪' }
                default                    { '⚠️' }
            }
            $modeDisplay = switch ($policy.Mode) {
                'Enable'                   { 'Enforcing' }
                'TestWithNotifications'    { 'Simulation (with tips)' }
                'TestWithoutNotifications' { 'Simulation (no tips)' }
                default                    { $policy.Mode }
            }
            $exchangeLoc = ($policy.ExchangeLocation | ForEach-Object {
                if ($_.Name) { $_.Name } else { $_.ToString() }
            }) -join ', '
            $created = Get-FormattedDate -Date $policy.WhenCreatedUTC
            $mdInfo += "| $icon | $policyName | $modeDisplay | $exchangeLoc | $created |`n"
        }
    }

    if ($dlpPolicies.Count -gt 0 -and $exchangePolicies.Count -eq 0) {
        $mdInfo += "`n`n### Note`n"
        $mdInfo += "Your tenant has $($dlpPolicies.Count) DLP policy(ies), but none include Exchange Online as a protected location.`n"
    }

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | ---: |`n"
    $mdInfo += "| Total DLP policies in tenant | $($dlpPolicies.Count) |`n"
    $mdInfo += "| Policies covering Exchange Online | $($exchangePolicies.Count) |`n"
    $mdInfo += "| ✅ Enforcing | $($exchangeEnabledPolicies.Count) |`n"
    $mdInfo += "| 🧪 Simulation mode | $($exchangeSimulationPolicies.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    #region Output
    $params = @{
        TestId = '35040'
        Title  = 'DLP policies are configured for Exchange Online'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
    #endregion Output
}
