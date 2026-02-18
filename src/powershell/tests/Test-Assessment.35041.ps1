# src\powershell\tests\Test-Assessment.35041.ps1

<#
.SYNOPSIS
    DLP policies are configured for SharePoint Online and OneDrive
#>

function Test-Assessment-35041 {
    [ZtTest(
        Category = 'Data Loss Prevention (DLP)',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Microsoft 365 E3'),
        Pillar = 'Data',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 35041,
        Title = 'DLP policies are configured for SharePoint Online and OneDrive',
        UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking DLP policy coverage for SharePoint Online and OneDrive'
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
    $spoPolicies = @()
    $spoEnabledPolicies = @()
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine DLP policy coverage for SharePoint/OneDrive due to permissions issues or query failure.`n`n"
        $customStatus = 'Investigate'
    }
    else {
        foreach ($policy in $dlpPolicies) {
            $hasSPO = $false
            $hasODB = $false

            if ($policy.SharePointLocation) {
                $locations = @($policy.SharePointLocation)
                if ($locations.Count -gt 0) { $hasSPO = $true }
            }
            if ($policy.OneDriveLocation) {
                $locations = @($policy.OneDriveLocation)
                if ($locations.Count -gt 0) { $hasODB = $true }
            }

            if ($hasSPO -or $hasODB) {
                $spoPolicies += [PSCustomObject]@{
                    Policy = $policy
                    HasSharePoint = $hasSPO
                    HasOneDrive = $hasODB
                }
                if ($policy.Mode -eq 'Enable') {
                    $spoEnabledPolicies += $policy
                }
            }
        }

        if ($spoEnabledPolicies.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ $($spoEnabledPolicies.Count) DLP policy(ies) are configured and enabled for SharePoint Online and/or OneDrive for Business.`n`n%TestResult%"
        }
        elseif ($spoPolicies.Count -gt 0) {
            $passed = $false
            $testResultMarkdown = "❌ $($spoPolicies.Count) DLP policy(ies) include SharePoint/OneDrive but none are in enforcement mode.`n`n%TestResult%"
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ No DLP policies are configured that include SharePoint Online or OneDrive for Business. Sensitive files can be stored and shared without detection or restriction.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($spoPolicies.Count -gt 0) {
        $mdInfo += "`n`n### [DLP Policies covering SharePoint/OneDrive](https://purview.microsoft.com/datalossprevention/policies)`n"
        $mdInfo += "| Policy Name | Mode | SharePoint | OneDrive | Created |`n"
        $mdInfo += "| :--- | :--- | :--- | :--- | :--- |`n"

        foreach ($item in $spoPolicies) {
            $policy = $item.Policy
            $policyName = Get-SafeMarkdown -Text $policy.Name
            $icon = if ($policy.Mode -eq 'Enable') { '✅' } else { '⚠️' }
            $modeDisplay = switch ($policy.Mode) {
                'Enable' { 'Enforcing' }
                'TestWithNotifications' { 'Simulation (with tips)' }
                'TestWithoutNotifications' { 'Simulation (no tips)' }
                default { $policy.Mode }
            }
            $spoIcon = if ($item.HasSharePoint) { '✅' } else { '❌' }
            $odbIcon = if ($item.HasOneDrive) { '✅' } else { '❌' }
            $created = Get-FormattedDate -Date $policy.WhenCreatedUTC
            $mdInfo += "| $icon $policyName | $modeDisplay | $spoIcon | $odbIcon | $created |`n"
        }
    }

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Total DLP policies in tenant | $($dlpPolicies.Count) |`n"
    $mdInfo += "| DLP policies covering SharePoint/OneDrive | $($spoPolicies.Count) |`n"
    $mdInfo += "| DLP policies enforcing on SharePoint/OneDrive | $($spoEnabledPolicies.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35041'
        Title  = 'DLP policies are configured for SharePoint Online and OneDrive'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
