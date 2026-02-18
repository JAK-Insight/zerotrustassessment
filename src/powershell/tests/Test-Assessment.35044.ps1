# src\powershell\tests\Test-Assessment.35044.ps1

<#
.SYNOPSIS
    DLP policies are in enforcement mode
#>

function Test-Assessment-35044 {
    [ZtTest(
        Category = 'Data Loss Prevention (DLP)',
        ImplementationCost = 'Low',
        MinimumLicense = ('Microsoft 365 E3'),
        Pillar = 'Data',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 35044,
        Title = 'DLP policies are in enforcement mode',
        UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking DLP policy enforcement status'
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
    $enforcingPolicies = @()
    $simulationPolicies = @()
    $disabledPolicies = @()
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine DLP policy enforcement status due to permissions issues or query failure.`n`n"
        $customStatus = 'Investigate'
    }
    elseif ($dlpPolicies.Count -eq 0) {
        $passed = $false
        $testResultMarkdown = "❌ No DLP policies are configured in the tenant.`n`n%TestResult%"
    }
    else {
        foreach ($policy in $dlpPolicies) {
            switch ($policy.Mode) {
                'Enable' { $enforcingPolicies += $policy }
                'TestWithNotifications' { $simulationPolicies += $policy }
                'TestWithoutNotifications' { $simulationPolicies += $policy }
                default { $disabledPolicies += $policy }
            }
        }

        # Pass if ALL policies are enforcing (no simulation-only policies)
        if ($simulationPolicies.Count -eq 0 -and $enforcingPolicies.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ All $($enforcingPolicies.Count) DLP policy(ies) are in enforcement mode.`n`n%TestResult%"
        }
        elseif ($enforcingPolicies.Count -gt 0 -and $simulationPolicies.Count -gt 0) {
            $passed = $false
            $testResultMarkdown = "❌ $($simulationPolicies.Count) DLP policy(ies) are still in simulation/test mode and are not actively preventing data loss. $($enforcingPolicies.Count) policy(ies) are enforcing.`n`n%TestResult%"
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ All $($simulationPolicies.Count) DLP policy(ies) are in simulation/test mode. No policies are actively preventing data loss.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($dlpPolicies.Count -gt 0) {
        $mdInfo += "`n`n### [DLP Policy Enforcement Status](https://purview.microsoft.com/datalossprevention/policies)`n"
        $mdInfo += "| Policy Name | Mode | Locations | Created |`n"
        $mdInfo += "| :--- | :--- | :--- | :--- |`n"

        foreach ($policy in $dlpPolicies) {
            $policyName = Get-SafeMarkdown -Text $policy.Name
            $icon = switch ($policy.Mode) {
                'Enable' { '✅' }
                'TestWithNotifications' { '⚠️' }
                'TestWithoutNotifications' { '⚠️' }
                default { '❌' }
            }
            $modeDisplay = switch ($policy.Mode) {
                'Enable' { 'Enforcing' }
                'TestWithNotifications' { 'Simulation (with tips)' }
                'TestWithoutNotifications' { 'Simulation (no tips)' }
                default { $policy.Mode }
            }

            # Build locations list
            $locations = @()
            if ($policy.ExchangeLocation) { $locations += 'Exchange' }
            if ($policy.SharePointLocation) { $locations += 'SharePoint' }
            if ($policy.OneDriveLocation) { $locations += 'OneDrive' }
            if ($policy.TeamsLocation) { $locations += 'Teams' }
            if ($policy.EndpointDlpLocation) { $locations += 'Endpoints' }
            $locationDisplay = if ($locations.Count -gt 0) { $locations -join ', ' } else { 'None' }

            $created = Get-FormattedDate -Date $policy.WhenCreatedUTC
            $mdInfo += "| $icon $policyName | $modeDisplay | $locationDisplay | $created |`n"
        }

        $mdInfo += "`n`n### Summary`n"
        $mdInfo += "| Metric | Count |`n"
        $mdInfo += "| :--- | :--- |`n"
        $mdInfo += "| Total DLP policies | $($dlpPolicies.Count) |`n"
        $mdInfo += "| Enforcing | $($enforcingPolicies.Count) |`n"
        $mdInfo += "| Simulation/Test mode | $($simulationPolicies.Count) |`n"
        $mdInfo += "| Disabled/Other | $($disabledPolicies.Count) |"
    }

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35044'
        Title  = 'DLP policies are in enforcement mode'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
