# src\powershell\tests\Test-Assessment.35042.ps1

<#
.SYNOPSIS
    DLP policies are configured for Microsoft Teams
#>

function Test-Assessment-35042 {
    [ZtTest(
        Category = 'Data Loss Prevention (DLP)',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Microsoft 365 E5'),
        Pillar = 'Data',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 35042,
        Title = 'DLP policies are configured for Microsoft Teams',
        UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking DLP policy coverage for Microsoft Teams'
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
    $teamsPolicies = @()
    $teamsEnabledPolicies = @()
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine DLP policy coverage for Microsoft Teams due to permissions issues or query failure.`n`n"
        $customStatus = 'Investigate'
    }
    else {
        foreach ($policy in $dlpPolicies) {
            $hasTeams = $false
            if ($policy.TeamsLocation) {
                $locations = @($policy.TeamsLocation)
                if ($locations.Count -gt 0) { $hasTeams = $true }
            }

            if ($hasTeams) {
                $teamsPolicies += $policy
                if ($policy.Mode -eq 'Enable') {
                    $teamsEnabledPolicies += $policy
                }
            }
        }

        if ($teamsEnabledPolicies.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ $($teamsEnabledPolicies.Count) DLP policy(ies) are configured and enabled for Microsoft Teams chat and channel messages.`n`n%TestResult%"
        }
        elseif ($teamsPolicies.Count -gt 0) {
            $passed = $false
            $testResultMarkdown = "❌ $($teamsPolicies.Count) DLP policy(ies) include Teams but none are in enforcement mode.`n`n%TestResult%"
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ No DLP policies are configured that include Microsoft Teams. Sensitive data shared in chat and channel messages is not monitored or protected.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($teamsPolicies.Count -gt 0) {
        $mdInfo += "`n`n### [DLP Policies covering Microsoft Teams](https://purview.microsoft.com/datalossprevention/policies)`n"
        $mdInfo += "| Policy Name | Mode | Teams Location | Created |`n"
        $mdInfo += "| :--- | :--- | :--- | :--- |`n"

        foreach ($policy in $teamsPolicies) {
            $policyName = Get-SafeMarkdown -Text $policy.Name
            $icon = if ($policy.Mode -eq 'Enable') { '✅' } else { '⚠️' }
            $modeDisplay = switch ($policy.Mode) {
                'Enable' { 'Enforcing' }
                'TestWithNotifications' { 'Simulation (with tips)' }
                'TestWithoutNotifications' { 'Simulation (no tips)' }
                default { $policy.Mode }
            }
            $teamsLoc = ($policy.TeamsLocation | ForEach-Object { $_.Name }) -join ', '
            $created = Get-FormattedDate -Date $policy.WhenCreatedUTC
            $mdInfo += "| $icon $policyName | $modeDisplay | $teamsLoc | $created |`n"
        }
    }

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Total DLP policies in tenant | $($dlpPolicies.Count) |`n"
    $mdInfo += "| DLP policies covering Teams | $($teamsPolicies.Count) |`n"
    $mdInfo += "| DLP policies enforcing on Teams | $($teamsEnabledPolicies.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35042'
        Title  = 'DLP policies are configured for Microsoft Teams'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
