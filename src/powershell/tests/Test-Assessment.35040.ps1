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

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35040
    $title    = 'DLP policies are configured for Exchange Online'
    $activity = 'Checking DLP policy coverage for Exchange Online'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    #region Data Collection
    Write-ZtProgress -Activity $activity -Status 'Getting DLP policies'

    $errorMsg = $null
    $dlpPolicies = @()

    if (-not (Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)) {
        $errorMsg = "Get-DlpCompliancePolicy cmdlet not found. Ensure Security & Compliance (IPPS) session is connected."
        Write-PSFMessage $errorMsg -Level Warning
    }
    else {
        try {
            $dlpPolicies = @(Get-DlpCompliancePolicy -ErrorAction Stop)
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-PSFMessage ("Error querying DLP policies: {0}" -f $_) -Level Error
        }
    }
    #endregion Data Collection

    #region Assessment Logic
    $exchangePolicies           = New-Object System.Collections.Generic.List[object]
    $exchangeEnabledPolicies    = New-Object System.Collections.Generic.List[object]
    $exchangeSimulationPolicies = New-Object System.Collections.Generic.List[object]

    $passed = $false
    $customStatus = $null
    $leadText = ""

    if ($errorMsg) {
        $customStatus = 'Investigate'
        $leadText = "⚠️ Unable to determine DLP policy coverage for Exchange Online due to permissions issues or query failure.`n`n**Details:** $errorMsg`n"
    }
    else {
        foreach ($policy in $dlpPolicies) {
            if ($policy.ExchangeLocation -and @($policy.ExchangeLocation).Count -gt 0) {
                $exchangePolicies.Add($policy)

                switch ($policy.Mode) {
                    'Enable' { $exchangeEnabledPolicies.Add($policy) }
                    { $_ -in 'TestWithNotifications', 'TestWithoutNotifications' } { $exchangeSimulationPolicies.Add($policy) }
                }
            }
        }

        if ($exchangeEnabledPolicies.Count -gt 0) {
            $passed = $true
            $leadText = "✅ $($exchangeEnabledPolicies.Count) DLP policy(ies) are configured and actively enforcing on Exchange Online.`n"

            if ($exchangeSimulationPolicies.Count -gt 0) {
                $leadText += "⚠️ **Improvement opportunity:** $($exchangeSimulationPolicies.Count) additional policy(ies) are in simulation mode. Review match reports in https://purview.microsoft.com/datalossprevention/activityexplorer and consider promoting to enforcement.`n"
            }
        }
        elseif ($exchangePolicies.Count -gt 0) {
            $passed = $false
            $leadText = "❌ $($exchangePolicies.Count) DLP policy(ies) include Exchange Online but none are in enforcement mode.`n"
            $leadText += "Simulation mode detects sensitive content but **does not block or protect it**. Promote at least one policy to enforcement.`n"
        }
        else {
            $passed = $false
            $leadText = "❌ No DLP policies are configured that include Exchange Online as a protected location. Sensitive data can be sent via email without detection or prevention.`n"
        }
    }
    #endregion Assessment Logic

    #region Evidence Markdown
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if (-not $errorMsg) {
        if ($exchangePolicies.Count -gt 0) {
            $lines.Add("### [DLP Policies covering Exchange Online](https://purview.microsoft.com/datalossprevention/policies)")
            $lines.Add("")
            $lines.Add("Policy Name | Mode | Exchange Scope | Created")
            $lines.Add(":---|:---|:---|:---")

            $sorted = $exchangePolicies | Sort-Object @{
                Expression = {
                    switch ($_.Mode) {
                        'Enable' { 0 }
                        'TestWithNotifications' { 1 }
                        'TestWithoutNotifications' { 2 }
                        default { 3 }
                    }
                }
            }, @{
                Expression = { $_.Name }
            }

            foreach ($policy in $sorted) {
                $policyName = Get-SafeMarkdown -Text $policy.Name

                $icon = switch ($policy.Mode) {
                    'Enable' { '✅' }
                    'TestWithNotifications' { '🧪' }
                    'TestWithoutNotifications' { '🧪' }
                    default { '⚠️' }
                }

                $modeDisplay = switch ($policy.Mode) {
                    'Enable' { 'Enforcing' }
                    'TestWithNotifications' { 'Simulation (with tips)' }
                    'TestWithoutNotifications' { 'Simulation (no tips)' }
                    default { $policy.Mode }
                }

                $exchangeLoc = ($policy.ExchangeLocation | ForEach-Object {
                    if ($_.Name) { $_.Name } else { $_.ToString() }
                }) -join ', '

                $exchangeLoc = if ([string]::IsNullOrWhiteSpace($exchangeLoc)) { 'All' } else { $exchangeLoc }
                $exchangeLoc = Get-SafeMarkdown -Text $exchangeLoc

                $created = Get-FormattedDate -Date $policy.WhenCreatedUTC

                $lines.Add(("$icon $policyName | $modeDisplay | $exchangeLoc | $created"))
            }

            $lines.Add("")
        }
        elseif ($dlpPolicies.Count -gt 0) {
            $lines.Add("### Note")
            $lines.Add(("Your tenant has {0} DLP policy(ies), but none include Exchange Online as a protected location." -f $dlpPolicies.Count))
            $lines.Add("")
        }

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|---:")
        $lines.Add(("Total DLP policies in tenant | {0}" -f $dlpPolicies.Count))
        $lines.Add(("Policies covering Exchange Online | {0}" -f $exchangePolicies.Count))
        $lines.Add(("✅ Enforcing | {0}" -f $exchangeEnabledPolicies.Count))
        $lines.Add(("🧪 Simulation mode | {0}" -f $exchangeSimulationPolicies.Count))
    }

    $mdInfo = ($lines -join "`n")
    #endregion Evidence Markdown

    # Ensure the markdown description file exists (does not affect pass/fail)
    if (-not (Test-Path $mdPath)) {
        $customStatus = 'Investigate'
        Write-PSFMessage ("Missing markdown file: {0}" -f $mdPath) -Level Warning
    }

    #region Output
    $params = @{
        TestId = "$testId"
        Title  = $title
        Status = $passed
        Result = $mdInfo   # evidence block only; TestDescription carries the narrative
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }

    Add-ZtTestResultDetail @params
    #endregion Output
}
