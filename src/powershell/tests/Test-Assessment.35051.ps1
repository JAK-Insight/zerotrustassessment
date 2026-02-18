# src\powershell\tests\Test-Assessment.35051.ps1

<#
.SYNOPSIS
    Insider Risk Management policies are configured
#>

function Test-Assessment-35051 {
    [ZtTest(
        Category = 'Data Security Posture Management',
        ImplementationCost = 'High',
        MinimumLicense = ('Microsoft 365 E5'),
        Pillar = 'Data',
        RiskLevel = 'High',
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 35051,
        Title = 'Insider Risk Management policies are configured',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking Insider Risk Management policy configuration'
    Write-ZtProgress -Activity $activity -Status 'Getting Insider Risk Management policies'

    $errorMsg = $null
    $irmPolicies = @()

    try {
        # Query IRM policies via the Compliance PowerShell cmdlet
        $irmPolicies = Get-InsiderRiskPolicy -ErrorAction Stop
    }
    catch {
        # If the cmdlet is not available, try alternative approach
        $errorMsg = $_
        Write-PSFMessage "Error querying Insider Risk Management policies: $_" -Level Error
    }
    #endregion Data Collection

    #region Assessment Logic
    $enabledPolicies = @()
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        # IRM cmdlets may not be available in all environments or may require specific permissions
        # Check if this is a permissions/licensing issue vs. a real error
        $errorString = $errorMsg.ToString()

        if ($errorString -match 'not recognized' -or $errorString -match 'CommandNotFoundException') {
            $testResultMarkdown = "⚠️ Unable to assess Insider Risk Management policies. The `Get-InsiderRiskPolicy` cmdlet is not available.`n`n"
            $testResultMarkdown += "This may indicate:`n"
            $testResultMarkdown += "- Insider Risk Management is not licensed (requires Microsoft 365 E5 or E5 Compliance add-on)`n"
            $testResultMarkdown += "- The Security & Compliance PowerShell module does not include IRM cmdlets in this environment`n"
            $testResultMarkdown += "- Insufficient permissions to query IRM policies`n`n"
            $testResultMarkdown += "**Manual verification:** Navigate to [Microsoft Purview Insider Risk Management](https://purview.microsoft.com/insiderriskmanagement/policies) to verify policy configuration.`n`n%TestResult%"
            $customStatus = 'Investigate'
        }
        else {
            $testResultMarkdown = "⚠️ Unable to determine Insider Risk Management policy configuration due to an error: $errorString`n`n%TestResult%"
            $customStatus = 'Investigate'
        }
    }
    else {
        $enabledPolicies = @($irmPolicies | Where-Object { $_.IsEnabled -eq $true -or $_.Enabled -eq $true })

        if ($enabledPolicies.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ $($enabledPolicies.Count) Insider Risk Management policy(ies) are configured and enabled, providing detection of risky user behaviors that may lead to data theft or leakage.`n`n%TestResult%"
        }
        elseif ($irmPolicies.Count -gt 0) {
            $passed = $false
            $testResultMarkdown = "❌ $($irmPolicies.Count) Insider Risk Management policy(ies) exist but none are enabled. Policies must be enabled to detect insider threats.`n`n%TestResult%"
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ No Insider Risk Management policies are configured. The organization lacks the ability to detect and respond to risky user behaviors such as data theft, data leakage, or security policy violations by insiders.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($irmPolicies.Count -gt 0) {
        $mdInfo += "`n`n### [Insider Risk Management Policies](https://purview.microsoft.com/insiderriskmanagement/policies)`n"
        $mdInfo += "| Policy Name | Enabled | Template | Created |`n"
        $mdInfo += "| :--- | :--- | :--- | :--- |`n"

        foreach ($policy in $irmPolicies) {
            $policyName = Get-SafeMarkdown -Text $policy.Name
            $isEnabled = if ($policy.IsEnabled -eq $true -or $policy.Enabled -eq $true) { $true } else { $false }
            $enabledIcon = if ($isEnabled) { '✅' } else { '❌' }

            # Try to get the template name
            $templateName = if ($policy.InsiderRiskScenario) {
                $policy.InsiderRiskScenario
            }
            elseif ($policy.Template) {
                $policy.Template
            }
            else {
                'N/A'
            }

            $created = if ($policy.WhenCreatedUTC) {
                Get-FormattedDate -Date $policy.WhenCreatedUTC
            }
            elseif ($policy.CreatedDate) {
                Get-FormattedDate -Date $policy.CreatedDate
            }
            else {
                'N/A'
            }

            $mdInfo += "| $enabledIcon $policyName | $isEnabled | $templateName | $created |`n"
        }
    }

    $mdInfo += "`n`n### Recommended Policy Templates`n"
    $mdInfo += "| Template | Description | Priority |`n"
    $mdInfo += "| :--- | :--- | :--- |`n"
    $mdInfo += "| Data theft by departing users | Detects data exfiltration patterns by users who have submitted resignation or are being terminated | High |`n"
    $mdInfo += "| Data leaks | Detects unusual sharing, downloading, or exfiltration of sensitive data | High |`n"
    $mdInfo += "| Data leaks by priority users | Focused monitoring on users with access to sensitive data or elevated privileges | Medium |`n"
    $mdInfo += "| Data leaks by risky users | Triggered by HR events, performance issues, or other risk indicators | Medium |`n"
    $mdInfo += "| Security policy violations | Detects actions that violate security policies such as disabling security tools | Medium |"

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Total IRM policies | $($irmPolicies.Count) |`n"
    $mdInfo += "| Enabled IRM policies | $($enabledPolicies.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35051'
        Title  = 'Insider Risk Management policies are configured'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
