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

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35048
    $title    = 'Retention policies are configured'
    $activity = 'Checking retention policy configuration'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    #region Data Collection
    Write-ZtProgress -Activity $activity -Status 'Getting retention policies'

    $errorMsg = $null
    $retentionPolicies = @()

    if (-not (Get-Command Get-RetentionCompliancePolicy -ErrorAction SilentlyContinue)) {
        $errorMsg = "Get-RetentionCompliancePolicy cmdlet not found. Ensure Security & Compliance (IPPS) session is connected."
        Write-PSFMessage $errorMsg -Level Warning
    }
    else {
        try {
            $retentionPolicies = @(Get-RetentionCompliancePolicy -ErrorAction Stop)
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-PSFMessage ("Error querying retention policies: {0}" -f $_) -Level Error
        }
    }
    #endregion Data Collection

    #region Assessment Logic
    $enabledPolicies = @()
    $passed = $false
    $customStatus = $null
    $leadText = ''

    if ($errorMsg) {
        $customStatus = 'Investigate'
        $leadText = "⚠️ Unable to determine retention policy configuration due to permissions issues or query failure.`n`n**Details:** $errorMsg`n"
    }
    else {
        $enabledPolicies = @($retentionPolicies | Where-Object { $_.Enabled -eq $true })

        if ($enabledPolicies.Count -gt 0) {
            $passed = $true
            $leadText = "✅ $($enabledPolicies.Count) retention policy(ies) are configured and enabled.`n"
        }
        else {
            $passed = $false
            if ($retentionPolicies.Count -gt 0) {
                $leadText = "❌ $($retentionPolicies.Count) retention policy(ies) exist but none are enabled. Data lifecycle is not being managed.`n"
            }
            else {
                $leadText = "❌ No retention policies are configured. Data may be retained indefinitely or deleted prematurely, increasing breach exposure and compliance risk.`n"
            }
        }
    }
    #endregion Assessment Logic

    #region Evidence Markdown
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if (-not $errorMsg) {
        if ($retentionPolicies.Count -gt 0) {
            $lines.Add("### Retention Policies")
            $lines.Add("")
            $lines.Add("Policy Name | Enabled | Workloads | Created")
            $lines.Add(":---|:---:|:---|:---")

            $sorted = $retentionPolicies | Sort-Object @{
                Expression = { if ($_.Enabled) { 0 } else { 1 } }
            }, @{
                Expression = { $_.Name }
            }

            foreach ($policy in $sorted) {
                $policyName = Get-SafeMarkdown -Text $policy.Name
                $icon = if ($policy.Enabled) { '✅' } else { '❌' }

                $workloads = @()
                if ($policy.ExchangeLocation)     { $workloads += 'Exchange' }
                if ($policy.SharePointLocation)  { $workloads += 'SharePoint' }
                if ($policy.OneDriveLocation)    { $workloads += 'OneDrive' }
                if ($policy.SkypeLocation)       { $workloads += 'Skype/Teams' }
                if ($policy.ModernGroupLocation) { $workloads += 'M365 Groups' }

                $workloadDisplay = if ($workloads.Count -gt 0) { $workloads -join ', ' } else { 'None specified' }
                $created = Get-FormattedDate -Date $policy.WhenCreatedUTC

                $lines.Add(("$icon $policyName | $($policy.Enabled) | $workloadDisplay | $created"))
            }

            $lines.Add("")
        }

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|---:")
        $lines.Add(("Total retention policies | {0}" -f $retentionPolicies.Count))
        $lines.Add(("Enabled retention policies | {0}" -f $enabledPolicies.Count))
    }

    $mdInfo = ($lines -join "`n")
    #endregion Evidence Markdown

    #region Load MD and Inject Evidence
    $resultMarkdown = $null

    if (Test-Path $mdPath) {
        $baseMd = Get-Content -Path $mdPath -Raw
        if ($baseMd -match '%TestResult%') {
            $resultMarkdown = $baseMd -replace '%TestResult%', $mdInfo
        }
        else {
            $resultMarkdown = $baseMd + "`n`n<!--- Results (auto-appended; missing %TestResult% token) --->`n" + $mdInfo
            $customStatus = 'Investigate'
        }
    }
    else {
        $resultMarkdown = "⚠️ Missing markdown file: $mdPath`n`n$mdInfo"
        $customStatus = 'Investigate'
    }
    #endregion Load MD and Inject Evidence

    #region Output
    $params = @{
        TestId = "$testId"
        Title  = $title
        Status = $passed
        Result = $resultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }

    Add-ZtTestResultDetail @params
    #endregion Output
}
