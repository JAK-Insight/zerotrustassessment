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

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35050
    $title    = 'Audit log retention is extended beyond default'
    $activity = 'Checking audit log retention configuration'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    #region Data Collection
    Write-ZtProgress -Activity $activity -Status 'Getting audit retention policies'

    $errorMsg = $null
    $retentionPolicies = @()

    if (-not (Get-Command Get-UnifiedAuditLogRetentionPolicy -ErrorAction SilentlyContinue)) {
        $errorMsg = "Get-UnifiedAuditLogRetentionPolicy cmdlet not found. Ensure Security & Compliance (IPPS) session is connected and Audit features are available."
        Write-PSFMessage $errorMsg -Level Warning
    }
    else {
        try {
            $retentionPolicies = @(Get-UnifiedAuditLogRetentionPolicy -ErrorAction Stop)
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-PSFMessage ("Error querying audit log retention policies: {0}" -f $_) -Level Error
        }
    }
    #endregion Data Collection

    #region Assessment Logic
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $customStatus = 'Investigate'
        $leadText  = "⚠️ Unable to determine audit log retention configuration. This may indicate Audit Premium (E5) is not licensed or permissions are insufficient.`n`n"
        $leadText += "Default audit log retention periods apply:`n"
        $leadText += "- **E3 license**: 90 days`n"
        $leadText += "- **E5 license**: 180 days`n`n"
        $leadText += "Extended retention (up to 10 years) requires Microsoft 365 E5 Compliance or E5 eDiscovery and Audit add-on.`n"
        $leadText += "`n**Details:** $errorMsg`n"
    }
    else {
        if ($retentionPolicies.Count -gt 0) {
            $extendedPolicies = @(
                $retentionPolicies | Where-Object { $_.RetentionDuration -and $_.RetentionDuration -ne 'None' }
            )

            if ($extendedPolicies.Count -gt 0) {
                $passed = $true
                $leadText = "✅ $($extendedPolicies.Count) custom audit log retention policy(ies) are configured, extending retention beyond the default period.`n"
            }
            else {
                $passed = $false
                $leadText = "❌ Audit log retention policies exist but none specify an extended retention duration.`n"
            }
        }
        else {
            $passed = $false
            $leadText = "❌ No custom audit log retention policies are configured. The default retention period applies (90 days for E3, 180 days for E5). Historical audit data may not be available for incident investigations or compliance audits that require longer lookback periods.`n"
        }
    }
    #endregion Assessment Logic

    #region Evidence Markdown
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if (-not $errorMsg) {
        if ($retentionPolicies.Count -gt 0) {
            $lines.Add("### Audit Log Retention Policies")
            $lines.Add("")
            $lines.Add("Policy Name | Retention Duration | Record Types | Priority | Enabled")
            $lines.Add(":---|:---|:---|:---:|:---:")

            $sorted = $retentionPolicies | Sort-Object @{
                Expression = { if ($_.Enabled -ne $false) { 0 } else { 1 } }
            }, @{
                Expression = { $_.Priority }
            }, @{
                Expression = { $_.Name }
            }

            foreach ($policy in $sorted) {
                $policyName = Get-SafeMarkdown -Text $policy.Name

                $durationDisplay = switch ($policy.RetentionDuration) {
                    'ThreeMonths'  { '3 months' }
                    'SixMonths'    { '6 months' }
                    'NineMonths'   { '9 months' }
                    'TwelveMonths' { '1 year' }
                    'ThreeYears'   { '3 years' }
                    'FiveYears'    { '5 years' }
                    'SevenYears'   { '7 years' }
                    'TenYears'     { '10 years' }
                    default        { $policy.RetentionDuration }
                }

                $recordTypes = if ($policy.RecordTypes -and $policy.RecordTypes.Count -gt 0) {
                    $top = ($policy.RecordTypes | Select-Object -First 3) -join ', '
                    if ($policy.RecordTypes.Count -gt 3) { "$top (+$($policy.RecordTypes.Count - 3) more)" } else { $top }
                }
                else {
                    'All record types'
                }

                $priority = if ($policy.Priority) { $policy.Priority } else { 'Default' }
                $enabledIcon = if ($policy.Enabled -ne $false) { '✅' } else { '❌' }

                $lines.Add(("$policyName | $durationDisplay | $recordTypes | $priority | $enabledIcon"))
            }

            $lines.Add("")
        }

        $lines.Add("### Guidance")
        $lines.Add("")
        $lines.Add("Consideration | Recommendation")
        $lines.Add(":---|:---")
        $lines.Add("Regulatory requirements | Align retention periods with your industry's compliance requirements (e.g., HIPAA, PCI-DSS, SOX)")
        $lines.Add("Incident investigation | Advanced threats have average dwell times of 200+ days — ensure retention covers this window")
        $lines.Add("High-value record types | Prioritize extended retention for: Exchange admin, SharePoint file operations, Azure AD sign-ins")
        $lines.Add("Cost optimization | Use targeted policies for specific record types rather than extending all records")
        $lines.Add("")

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|---:")
        $lines.Add(("Custom audit retention policies | {0}" -f $retentionPolicies.Count))
    }
    else {
        # Even on Investigate, still show a small summary section to keep formatting consistent
        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|---:")
        $lines.Add(("Custom audit retention policies | {0}" -f $retentionPolicies.Count))
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
