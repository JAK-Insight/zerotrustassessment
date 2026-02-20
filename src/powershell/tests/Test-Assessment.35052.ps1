<#
.SYNOPSIS
 Microsoft Purview alert policies are configured for data events
#>
function Test-Assessment-35052 {
    [ZtTest(
        Category = 'Data Security Posture Management',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Microsoft 365 E3'),
        Pillar = 'Data',
        RiskLevel = 'Medium',
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 35052,
        Title = 'Microsoft Purview alert policies are configured for data events',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35052
    $title    = 'Microsoft Purview alert policies are configured for data events'
    $activity = 'Checking Purview alert policy configuration for data events'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    #region Data Collection
    Write-ZtProgress -Activity $activity -Status 'Getting alert policies'

    $errorMsg = $null
    $alertPolicies = @()

    if (-not (Get-Command Get-ProtectionAlert -ErrorAction SilentlyContinue)) {
        $errorMsg = "Get-ProtectionAlert cmdlet not found. Ensure Security & Compliance (IPPS) session is connected."
        Write-PSFMessage $errorMsg -Level Warning
    }
    else {
        try {
            $alertPolicies = @(Get-ProtectionAlert -ErrorAction Stop)
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-PSFMessage ("Error querying alert policies: {0}" -f $_) -Level Error
        }
    }
    #endregion Data Collection

    #region Assessment Logic
    $dataAlertPolicies = @()
    $customDataAlertPolicies = @()
    $enabledDataAlertPolicies = @()

    $passed = $false
    $customStatus = $null
    $leadText = ""

    # Data-related categories and operations to look for (same as your original). [1](https://insightonline-my.sharepoint.com/personal/joshua_kaye_insight_com/Documents/Microsoft%20Copilot%20Chat%20Files/Test-Assessment.35052.ps1.txt)
    $dataCategories = @(
        'DataLossPrevention',
        'DataGovernance',
        'InformationGovernance',
        'ThreatManagement'
    )

    $dataOperationKeywords = @(
        'DLP',
        'Sharing',
        'Download',
        'FileAccess',
        'FileMalware',
        'FileDeleted',
        'SensitiveInfo',
        'Label',
        'Retention',
        'eDiscovery'
    )

    if ($errorMsg) {
        $customStatus = 'Investigate'
        $leadText = "⚠️ Unable to determine alert policy configuration due to permissions issues or query failure.`n`n**Details:** $errorMsg`n"
    }
    elseif ($alertPolicies.Count -eq 0) {
        $passed = $false
        $leadText = "❌ No alert policies are configured in the tenant.`n"
    }
    else {
        foreach ($policy in $alertPolicies) {
            $isDataRelated = $false

            if ($policy.Category -and $dataCategories -contains $policy.Category) {
                $isDataRelated = $true
            }

            if (-not $isDataRelated -and $policy.Operation) {
                foreach ($keyword in $dataOperationKeywords) {
                    if ($policy.Operation -match $keyword) { $isDataRelated = $true; break }
                }
            }

            if (-not $isDataRelated -and $policy.Name) {
                $nameKeywords = @('DLP', 'data', 'sharing', 'sensitive', 'label', 'retention', 'malware', 'download')
                foreach ($keyword in $nameKeywords) {
                    if ($policy.Name -match $keyword) { $isDataRelated = $true; break }
                }
            }

            if ($isDataRelated) {
                $dataAlertPolicies += $policy

                if ($policy.IsEnabled -eq $true -or $policy.Disabled -eq $false) {
                    $enabledDataAlertPolicies += $policy
                }

                if ($policy.IsSystemRule -eq $false -or $policy.Source -eq 'Custom') {
                    $customDataAlertPolicies += $policy
                }
            }
        }

        if ($customDataAlertPolicies.Count -gt 0) {
            $passed = $true
            $leadText = "✅ $($customDataAlertPolicies.Count) custom data-related alert policy(ies) are configured, supplementing the $($dataAlertPolicies.Count - $customDataAlertPolicies.Count) built-in data alert policies.`n"
        }
        elseif ($enabledDataAlertPolicies.Count -gt 0) {
            $passed = $false
            $leadText = "❌ $($enabledDataAlertPolicies.Count) built-in data-related alert policy(ies) are enabled, but no custom alert policies have been created for organization-specific data scenarios (e.g., mass file downloads, external sharing of labeled content, unusual data access patterns).`n"
        }
        else {
            $passed = $false
            $leadText = "❌ No data-related alert policies are enabled. Critical data activities such as mass file downloads, external sharing of sensitive content, or unusual data access patterns will go undetected.`n"
        }
    }
    #endregion Assessment Logic

    #region Evidence Markdown
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if (-not $errorMsg -and $alertPolicies.Count -gt 0) {

        if ($dataAlertPolicies.Count -gt 0) {
            $lines.Add("### Data-Related Alert Policies")
            $lines.Add("")
            $lines.Add("Alert Policy Name | Category | Enabled | Custom | Severity | Notification")
            $lines.Add(":---|:---|:---:|:---|:---|:---:")

            # Sort: custom first then name (same intent as your original). [1](https://insightonline-my.sharepoint.com/personal/joshua_kaye_insight_com/Documents/Microsoft%20Copilot%20Chat%20Files/Test-Assessment.35052.ps1.txt)
            $sortedPolicies = $dataAlertPolicies | Sort-Object @{
                Expression = { $_.IsSystemRule -eq $false }; Descending = $true
            }, @{
                Expression = { $_.Name }
            }

            foreach ($policy in $sortedPolicies) {
                $policyName = Get-SafeMarkdown -Text $policy.Name

                $isEnabled = if ($policy.IsEnabled -eq $true -or $policy.Disabled -eq $false) { $true } else { $false }
                $enabledIcon = if ($isEnabled) { '✅' } else { '❌' }

                $isCustom = if ($policy.IsSystemRule -eq $false -or $policy.Source -eq 'Custom') { '🔧 Custom' } else { 'Built-in' }
                $category = if ($policy.Category) { $policy.Category } else { 'N/A' }

                $severity = if ($policy.Severity) { $policy.Severity } else { 'N/A' }
                $severityDisplay = switch ($severity) {
                    'High' { '🔴 High' }
                    'Medium' { '🟡 Medium' }
                    'Low' { '🟢 Low' }
                    'Informational' { 'ℹ️ Info' }
                    default { $severity }
                }

                $hasNotification = $false
                if ($policy.NotifyUser -and $policy.NotifyUser.Count -gt 0) { $hasNotification = $true }
                if ($policy.NotifyUserOnFilterMatch -eq $true) { $hasNotification = $true }
                $notificationIcon = if ($hasNotification) { '✅' } else { '❌' }

                $lines.Add(("$enabledIcon $policyName | $category | $isEnabled | $isCustom | $severityDisplay | $notificationIcon"))
            }

            $lines.Add("")
        }

        $lines.Add("### Recommended Custom Alert Policies")
        $lines.Add("")
        $lines.Add("Scenario | Description | Severity")
        $lines.Add(":---|:---|:---")
        $lines.Add("Mass file download | Alert when a user downloads an unusually large number of files in a short period | High")
        $lines.Add("External sharing of labeled content | Alert when content with Confidential or Highly Confidential labels is shared externally | High")
        $lines.Add("Unusual data access pattern | Alert when a user accesses data repositories they don't normally access | Medium")
        $lines.Add("DLP policy override spike | Alert when DLP override justifications exceed a threshold in a time window | Medium")
        $lines.Add("Sensitivity label downgrade | Alert when users downgrade sensitivity labels on documents (beyond normal patterns) | Medium")
        $lines.Add("")

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|---:")
        $lines.Add(("Total alert policies in tenant | {0}" -f $alertPolicies.Count))
        $lines.Add(("Data-related alert policies | {0}" -f $dataAlertPolicies.Count))
        $lines.Add(("Enabled data alert policies | {0}" -f $enabledDataAlertPolicies.Count))
        $lines.Add(("Custom data alert policies | {0}" -f $customDataAlertPolicies.Count))
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
