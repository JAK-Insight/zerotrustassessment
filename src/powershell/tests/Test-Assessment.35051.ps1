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

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35051
    $title    = 'Insider Risk Management policies are configured'
    $activity = 'Checking Insider Risk Management policy configuration'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    #region Data Collection
    Write-ZtProgress -Activity $activity -Status 'Getting Insider Risk Management policies'

    $errorMsg = $null
    $irmPolicies = @()

    try {
        if (-not (Get-Command Get-InsiderRiskPolicy -ErrorAction SilentlyContinue)) {
            throw [System.Management.Automation.CommandNotFoundException]::new("Get-InsiderRiskPolicy cmdlet not found.")
        }

        # Query IRM policies via the Compliance PowerShell cmdlet
        $irmPolicies = @(Get-InsiderRiskPolicy -ErrorAction Stop)
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage ("Error querying Insider Risk Management policies: {0}" -f $_) -Level Error
    }
    #endregion Data Collection

    #region Assessment Logic
    $enabledPolicies = @()
    $passed = $false
    $customStatus = $null
    $leadText = ""

    if ($errorMsg) {
        # IRM cmdlets may not be available in all environments or may require specific permissions
        $errorString = $errorMsg.ToString()

        if ($errorString -match 'not recognized' -or $errorString -match 'CommandNotFoundException' -or $errorString -match 'Get-InsiderRiskPolicy') {
            $leadText  = "⚠️ Unable to assess Insider Risk Management policies. The `Get-InsiderRiskPolicy` cmdlet is not available.`n`n"
            $leadText += "This may indicate:`n"
            $leadText += "- Insider Risk Management is not licensed (requires Microsoft 365 E5 or E5 Compliance add-on)`n"
            $leadText += "- The Security & Compliance PowerShell module does not include IRM cmdlets in this environment`n"
            $leadText += "- Insufficient permissions to query IRM policies`n`n"
            $leadText += "**Manual verification:** Navigate to https://purview.microsoft.com/insiderriskmanagement/policies to verify policy configuration.`n"
            $customStatus = 'Investigate'
        }
        else {
            $leadText = "⚠️ Unable to determine Insider Risk Management policy configuration due to an error: $errorString`n"
            $customStatus = 'Investigate'
        }
    }
    else {
        $enabledPolicies = @($irmPolicies | Where-Object { $_.IsEnabled -eq $true -or $_.Enabled -eq $true })

        if ($enabledPolicies.Count -gt 0) {
            $passed = $true
            $leadText = "✅ $($enabledPolicies.Count) Insider Risk Management policy(ies) are configured and enabled, providing detection of risky user behaviors that may lead to data theft or leakage.`n"
        }
        elseif ($irmPolicies.Count -gt 0) {
            $passed = $false
            $leadText = "❌ $($irmPolicies.Count) Insider Risk Management policy(ies) exist but none are enabled. Policies must be enabled to detect insider threats.`n"
        }
        else {
            $passed = $false
            $leadText = "❌ No Insider Risk Management policies are configured. The organization lacks the ability to detect and respond to risky user behaviors such as data theft, data leakage, or security policy violations by insiders.`n"
        }
    }
    #endregion Assessment Logic

    #region Evidence Markdown
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if ($irmPolicies.Count -gt 0) {
        $lines.Add("### Insider Risk Management Policies")
        $lines.Add("")
        $lines.Add("Policy Name | Enabled | Template | Created")
        $lines.Add(":---|:---:|:---|:---")

        $sorted = $irmPolicies | Sort-Object @{
            Expression = { if ($_.IsEnabled -eq $true -or $_.Enabled -eq $true) { 0 } else { 1 } }
        }, @{
            Expression = { $_.Name }
        }

        foreach ($policy in $sorted) {
            $policyName = Get-SafeMarkdown -Text $policy.Name

            $isEnabled = if ($policy.IsEnabled -eq $true -or $policy.Enabled -eq $true) { $true } else { $false }
            $enabledIcon = if ($isEnabled) { '✅' } else { '❌' }

            $templateName = if ($policy.InsiderRiskScenario) {
                $policy.InsiderRiskScenario
            }
            elseif ($policy.Template) {
                $policy.Template
            }
            else { 'N/A' }

            $created = if ($policy.WhenCreatedUTC) {
                Get-FormattedDate -Date $policy.WhenCreatedUTC
            }
            elseif ($policy.CreatedDate) {
                Get-FormattedDate -Date $policy.CreatedDate
            }
            else { 'N/A' }

            $lines.Add(("$enabledIcon $policyName | $isEnabled | $templateName | $created"))
        }

        $lines.Add("")
    }

    # Recommended templates (always show)
    $lines.Add("### Recommended Policy Templates")
    $lines.Add("")
    $lines.Add("Template | Description | Priority")
    $lines.Add(":---|:---|:---")
    $lines.Add("Data theft by departing users | Detects data exfiltration patterns by users who have submitted resignation or are being terminated | High")
    $lines.Add("Data leaks | Detects unusual sharing, downloading, or exfiltration of sensitive data | High")
    $lines.Add("Data leaks by priority users | Focused monitoring on users with access to sensitive data or elevated privileges | Medium")
    $lines.Add("Data leaks by risky users | Triggered by HR events, performance issues, or other risk indicators | Medium")
    $lines.Add("Security policy violations | Detects actions that violate security policies such as disabling security tools | Medium")
    $lines.Add("")

    $lines.Add("### Summary")
    $lines.Add("")
    $lines.Add("Metric | Count")
    $lines.Add(":---|---:")
    $lines.Add(("Total IRM policies | {0}" -f $irmPolicies.Count))
    $lines.Add(("Enabled IRM policies | {0}" -f $enabledPolicies.Count))

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
