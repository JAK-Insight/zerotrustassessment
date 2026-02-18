# src\powershell\tests\Test-Assessment.35050.ps1

<#
.SYNOPSIS
    Audit log retention is extended beyond default
#>

function Test-Assessment-35050 {
    [ZtTest(
        Category = 'Data Security Posture Management',
        ImplementationCost = 'Low',
        MinimumLicense = ('Microsoft 365 E5'),
        Pillar = 'Data',
        RiskLevel = 'Medium',
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 35050,
        Title = 'Audit log retention is extended beyond default',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking audit log retention configuration'
    Write-ZtProgress -Activity $activity -Status 'Getting audit retention policies'

    $errorMsg = $null
    $retentionPolicies = @()

    try {
        $retentionPolicies = Get-UnifiedAuditLogRetentionPolicy -ErrorAction Stop
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage "Error querying audit log retention policies: $_" -Level Error
    }
    #endregion Data Collection

    #region Assessment Logic
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine audit log retention configuration. This may indicate Audit Premium (E5) is not licensed or permissions are insufficient.`n`n"
        $testResultMarkdown += "Default audit log retention periods apply:`n"
        $testResultMarkdown += "- **E3 license**: 90 days`n"
        $testResultMarkdown += "- **E5 license**: 180 days`n`n"
        $testResultMarkdown += "Extended retention (up to 10 years) requires Microsoft 365 E5 Compliance or E5 eDiscovery and Audit add-on.`n`n%TestResult%"
        $customStatus = 'Investigate'
    }
    else {
        if ($retentionPolicies.Count -gt 0) {
            # Check for policies with retention longer than default (180 days)
            $extendedPolicies = @($retentionPolicies | Where-Object {
                $_.RetentionDuration -and $_.RetentionDuration -ne 'None'
            })

            if ($extendedPolicies.Count -gt 0) {
                $passed = $true
                $testResultMarkdown = "✅ $($extendedPolicies.Count) custom audit log retention policy(ies) are configured, extending retention beyond the default period.`n`n%TestResult%"
            }
            else {
                $passed = $false
                $testResultMarkdown = "❌ Audit log retention policies exist but none specify an extended retention duration.`n`n%TestResult%"
            }
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ No custom audit log retention policies are configured. The default retention period applies (90 days for E3, 180 days for E5). Historical audit data may not be available for incident investigations or compliance audits that require longer lookback periods.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($retentionPolicies.Count -gt 0) {
        $mdInfo += "`n`n### [Audit Log Retention Policies](https://purview.microsoft.com/audit/auditretentionpolicy)`n"
        $mdInfo += "| Policy Name | Retention Duration | Record Types | Priority | Enabled |`n"
        $mdInfo += "| :--- | :--- | :--- | :--- | :--- |`n"

        foreach ($policy in $retentionPolicies) {
            $policyName = Get-SafeMarkdown -Text $policy.Name

            # Format retention duration
            $durationDisplay = switch ($policy.RetentionDuration) {
                'ThreeMonths' { '3 months' }
                'SixMonths' { '6 months' }
                'NineMonths' { '9 months' }
                'TwelveMonths' { '1 year' }
                'TenYears' { '10 years' }
                'FiveYears' { '5 years' }
                'ThreeYears' { '3 years' }
                'SevenYears' { '7 years' }
                default { $policy.RetentionDuration }
            }

            # Format record types
            $recordTypes = if ($policy.RecordTypes -and $policy.RecordTypes.Count -gt 0) {
                ($policy.RecordTypes | Select-Object -First 3) -join ', '
                if ($policy.RecordTypes.Count -gt 3) { " (+$($policy.RecordTypes.Count - 3) more)" }
            }
            else {
                'All record types'
            }

            $priority = if ($policy.Priority) { $policy.Priority } else { 'Default' }
            $enabledIcon = if ($policy.Enabled -ne $false) { '✅' } else { '❌' }

            $mdInfo += "| $policyName | $durationDisplay | $recordTypes | $priority | $enabledIcon |`n"
        }
    }

    $mdInfo += "`n`n### Guidance`n"
    $mdInfo += "| Consideration | Recommendation |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Regulatory requirements | Align retention periods with your industry's compliance requirements (e.g., HIPAA, PCI-DSS, SOX) |`n"
    $mdInfo += "| Incident investigation | Advanced threats have average dwell times of 200+ days — ensure retention covers this window |`n"
    $mdInfo += "| High-value record types | Prioritize extended retention for: Exchange admin, SharePoint file operations, Azure AD sign-ins |`n"
    $mdInfo += "| Cost optimization | Use targeted policies for specific record types rather than extending all records |"

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Custom audit retention policies | $($retentionPolicies.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35050'
        Title  = 'Audit log retention is extended beyond default'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
