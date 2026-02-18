# src\powershell\tests\Test-Assessment.35048.ps1

<#
.SYNOPSIS
    Retention policies are configured
#>

function Test-Assessment-35048 {
    [ZtTest(
        Category = 'Data Governance',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Microsoft 365 E3'),
        Pillar = 'Data',
        RiskLevel = 'Medium',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 35048,
        Title = 'Retention policies are configured',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking retention policy configuration'
    Write-ZtProgress -Activity $activity -Status 'Getting retention policies'

    $errorMsg = $null
    $retentionPolicies = @()

    try {
        $retentionPolicies = Get-RetentionCompliancePolicy -ErrorAction Stop
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage "Error querying retention policies: $_" -Level Error
    }
    #endregion Data Collection

    #region Assessment Logic
    $enabledPolicies = @()
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine retention policy configuration due to permissions issues or query failure.`n`n"
        $customStatus = 'Investigate'
    }
    else {
        $enabledPolicies = @($retentionPolicies | Where-Object { $_.Enabled -eq $true })

        if ($enabledPolicies.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ $($enabledPolicies.Count) retention policy(ies) are configured and enabled.`n`n%TestResult%"
        }
        else {
            $passed = $false
            if ($retentionPolicies.Count -gt 0) {
                $testResultMarkdown = "❌ $($retentionPolicies.Count) retention policy(ies) exist but none are enabled. Data lifecycle is not being managed.`n`n%TestResult%"
            }
            else {
                $testResultMarkdown = "❌ No retention policies are configured. Data may be retained indefinitely or deleted prematurely, increasing breach exposure and compliance risk.`n`n%TestResult%"
            }
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($retentionPolicies.Count -gt 0) {
        $mdInfo += "`n`n### [Retention Policies](https://purview.microsoft.com/datalifecyclemanagement/retentionpolicies)`n"
        $mdInfo += "| Policy Name | Enabled | Workloads | Created |`n"
        $mdInfo += "| :--- | :--- | :--- | :--- |`n"

        foreach ($policy in $retentionPolicies) {
            $policyName = Get-SafeMarkdown -Text $policy.Name
            $icon = if ($policy.Enabled) { '✅' } else { '❌' }

            $workloads = @()
            if ($policy.ExchangeLocation) { $workloads += 'Exchange' }
            if ($policy.SharePointLocation) { $workloads += 'SharePoint' }
            if ($policy.OneDriveLocation) { $workloads += 'OneDrive' }
            if ($policy.SkypeLocation) { $workloads += 'Skype/Teams' }
            if ($policy.ModernGroupLocation) { $workloads += 'M365 Groups' }
            $workloadDisplay = if ($workloads.Count -gt 0) { $workloads -join ', ' } else { 'None specified' }

            $created = Get-FormattedDate -Date $policy.WhenCreatedUTC
            $mdInfo += "| $icon $policyName | $($policy.Enabled) | $workloadDisplay | $created |`n"
        }
    }

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Total retention policies | $($retentionPolicies.Count) |`n"
    $mdInfo += "| Enabled retention policies | $($enabledPolicies.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35048'
        Title  = 'Retention policies are configured'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
