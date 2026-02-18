# src\powershell\tests\Test-Assessment.35043.ps1

<#
.SYNOPSIS
    Endpoint DLP is enabled
#>

function Test-Assessment-35043 {
    [ZtTest(
        Category = 'Data Loss Prevention (DLP)',
        ImplementationCost = 'High',
        MinimumLicense = ('Microsoft 365 E5'),
        Pillar = 'Data',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 35043,
        Title = 'Endpoint DLP is enabled',
        UserImpact = 'High'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking Endpoint DLP configuration'
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
    $endpointPolicies = @()
    $endpointEnabledPolicies = @()
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine Endpoint DLP status due to permissions issues or query failure.`n`n"
        $customStatus = 'Investigate'
    }
    else {
        foreach ($policy in $dlpPolicies) {
            $hasEndpoint = $false
            if ($policy.EndpointDlpLocation) {
                $locations = @($policy.EndpointDlpLocation)
                if ($locations.Count -gt 0) { $hasEndpoint = $true }
            }

            if ($hasEndpoint) {
                $endpointPolicies += $policy
                if ($policy.Mode -eq 'Enable') {
                    $endpointEnabledPolicies += $policy
                }
            }
        }

        if ($endpointEnabledPolicies.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ $($endpointEnabledPolicies.Count) DLP policy(ies) are configured and enabled for Endpoint DLP (Devices).`n`n%TestResult%"
        }
        elseif ($endpointPolicies.Count -gt 0) {
            $passed = $false
            $testResultMarkdown = "❌ $($endpointPolicies.Count) DLP policy(ies) include Devices but none are in enforcement mode.`n`n%TestResult%"
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ No DLP policies include Devices (Endpoint DLP) as a protected location. Sensitive data can be exfiltrated from managed devices via USB, print, clipboard, or unauthorized cloud uploads.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($endpointPolicies.Count -gt 0) {
        $mdInfo += "`n`n### [DLP Policies covering Endpoints](https://purview.microsoft.com/datalossprevention/policies)`n"
        $mdInfo += "| Policy Name | Mode | Endpoint Location | Created |`n"
        $mdInfo += "| :--- | :--- | :--- | :--- |`n"

        foreach ($policy in $endpointPolicies) {
            $policyName = Get-SafeMarkdown -Text $policy.Name
            $icon = if ($policy.Mode -eq 'Enable') { '✅' } else { '⚠️' }
            $modeDisplay = switch ($policy.Mode) {
                'Enable' { 'Enforcing' }
                'TestWithNotifications' { 'Simulation (with tips)' }
                'TestWithoutNotifications' { 'Simulation (no tips)' }
                default { $policy.Mode }
            }
            $endpointLoc = ($policy.EndpointDlpLocation | ForEach-Object { $_.Name }) -join ', '
            $created = Get-FormattedDate -Date $policy.WhenCreatedUTC
            $mdInfo += "| $icon $policyName | $modeDisplay | $endpointLoc | $created |`n"
        }
    }

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Total DLP policies in tenant | $($dlpPolicies.Count) |`n"
    $mdInfo += "| DLP policies covering Endpoints | $($endpointPolicies.Count) |`n"
    $mdInfo += "| DLP policies enforcing on Endpoints | $($endpointEnabledPolicies.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35043'
        Title  = 'Endpoint DLP is enabled'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
