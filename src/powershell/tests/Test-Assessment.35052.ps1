# src\powershell\tests\Test-Assessment.35052.ps1

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

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking Purview alert policy configuration for data events'
    Write-ZtProgress -Activity $activity -Status 'Getting alert policies'

    $errorMsg = $null
    $alertPolicies = @()

    try {
        $alertPolicies = Get-ProtectionAlert -ErrorAction Stop
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage "Error querying alert policies: $_" -Level Error
    }
    #endregion Data Collection

    #region Assessment Logic
    $dataAlertPolicies = @()
    $customDataAlertPolicies = @()
    $enabledDataAlertPolicies = @()
    $passed = $false
    $customStatus = $null

    # Data-related categories and operations to look for
    $dataCategories = @(
        'DataLossPrevention',
        'DataGovernance',
        'InformationGovernance',
        'ThreatManagement'
    )

    # Data-related operation keywords
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
        $testResultMarkdown = "⚠️ Unable to determine alert policy configuration due to permissions issues or query failure.`n`n%TestResult%"
        $customStatus = 'Investigate'
    }
    elseif ($alertPolicies.Count -eq 0) {
        $passed = $false
        $testResultMarkdown = "❌ No alert policies are configured in the tenant.`n`n%TestResult%"
    }
    else {
        # Identify data-related alert policies
        foreach ($policy in $alertPolicies) {
            $isDataRelated = $false

            # Check by category
            if ($policy.Category -and $dataCategories -contains $policy.Category) {
                $isDataRelated = $true
            }

            # Check by operation keywords
            if (-not $isDataRelated -and $policy.Operation) {
                foreach ($keyword in $dataOperationKeywords) {
                    if ($policy.Operation -match $keyword) {
                        $isDataRelated = $true
                        break
                    }
                }
            }

            # Check by name keywords
            if (-not $isDataRelated -and $policy.Name) {
                $nameKeywords = @('DLP', 'data', 'sharing', 'sensitive', 'label', 'retention', 'malware', 'download')
                foreach ($keyword in $nameKeywords) {
                    if ($policy.Name -match $keyword) {
                        $isDataRelated = $true
                        break
                    }
                }
            }

            if ($isDataRelated) {
                $dataAlertPolicies += $policy

                if ($policy.IsEnabled -eq $true -or $policy.Disabled -eq $false) {
                    $enabledDataAlertPolicies += $policy
                }

                # Check if this is a custom (non-system) policy
                if ($policy.IsSystemRule -eq $false -or $policy.Source -eq 'Custom') {
                    $customDataAlertPolicies += $policy
                }
            }
        }

        if ($customDataAlertPolicies.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ $($customDataAlertPolicies.Count) custom data-related alert policy(ies) are configured, supplementing the $($dataAlertPolicies.Count - $customDataAlertPolicies.Count) built-in data alert policies.`n`n%TestResult%"
        }
        elseif ($enabledDataAlertPolicies.Count -gt 0) {
            $passed = $false
            $testResultMarkdown = "❌ $($enabledDataAlertPolicies.Count) built-in data-related alert policy(ies) are enabled, but no custom alert policies have been created for organization-specific data scenarios (e.g., mass file downloads, external sharing of labeled content, unusual data access patterns).`n`n%TestResult%"
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ No data-related alert policies are enabled. Critical data activities such as mass file downloads, external sharing of sensitive content, or unusual data access patterns will go undetected.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($dataAlertPolicies.Count -gt 0) {
        $mdInfo += "`n`n### [Data-Related Alert Policies](https://purview.microsoft.com/alertpolicies)`n"
        $mdInfo += "| Alert Policy Name | Category | Enabled | Custom | Severity | Notification |`n"
        $mdInfo += "| :--- | :--- | :--- | :--- | :--- | :--- |`n"

        # Sort: custom policies first, then by name
        $sortedPolicies = $dataAlertPolicies | Sort-Object @{Expression = { $_.IsSystemRule -eq $false }; Descending = $true }, Name

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

            # Check notification configuration
            $hasNotification = $false
            if ($policy.NotifyUser -and $policy.NotifyUser.Count -gt 0) { $hasNotification = $true }
            if ($policy.NotifyUserOnFilterMatch -eq $true) { $hasNotification = $true }
            $notificationIcon = if ($hasNotification) { '✅' } else { '❌' }

            $mdInfo += "| $enabledIcon $policyName | $category | $isEnabled | $isCustom | $severityDisplay | $notificationIcon |`n"
        }
    }

    $mdInfo += "`n`n### Recommended Custom Alert Policies`n"
    $mdInfo += "| Scenario | Description | Severity |`n"
    $mdInfo += "| :--- | :--- | :--- |`n"
    $mdInfo += "| Mass file download | Alert when a user downloads an unusually large number of files in a short period | High |`n"
    $mdInfo += "| External sharing of labeled content | Alert when content with Confidential or Highly Confidential labels is shared externally | High |`n"
    $mdInfo += "| Unusual data access pattern | Alert when a user accesses data repositories they don't normally access | Medium |`n"
    $mdInfo += "| DLP policy override spike | Alert when DLP override justifications exceed a threshold in a time window | Medium |`n"
    $mdInfo += "| Sensitivity label downgrade | Alert when users downgrade sensitivity labels on documents (beyond normal patterns) | Medium |"

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Total alert policies in tenant | $($alertPolicies.Count) |`n"
    $mdInfo += "| Data-related alert policies | $($dataAlertPolicies.Count) |`n"
    $mdInfo += "| Enabled data alert policies | $($enabledDataAlertPolicies.Count) |`n"
    $mdInfo += "| Custom data alert policies | $($customDataAlertPolicies.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35052'
        Title  = 'Microsoft Purview alert policies are configured for data events'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
