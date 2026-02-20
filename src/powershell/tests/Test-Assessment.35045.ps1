<#
.SYNOPSIS
 DLP alerts are configured and routed
#>
function Test-Assessment-35045 {
    [ZtTest(
        Category = 'Data Loss Prevention (DLP)',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Microsoft 365 E3'),
        Pillar = 'Data',
        RiskLevel = 'Medium',
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 35045,
        Title = 'DLP alerts are configured and routed',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35045
    $title    = 'DLP alerts are configured and routed'
    $activity = 'Checking DLP alert configuration'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    #region Data Collection
    Write-ZtProgress -Activity $activity -Status 'Getting DLP compliance rules'

    $errorMsg = $null
    $dlpRules = @()

    if (-not (Get-Command Get-DlpComplianceRule -ErrorAction SilentlyContinue)) {
        $errorMsg = "Get-DlpComplianceRule cmdlet not found. Ensure Security & Compliance (IPPS) session is connected."
        Write-PSFMessage $errorMsg -Level Warning
    }
    else {
        try {
            $dlpRules = @(Get-DlpComplianceRule -ErrorAction Stop)
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-PSFMessage ("Error querying DLP rules: {0}" -f $_) -Level Error
        }
    }
    #endregion Data Collection

    #region Assessment Logic
    $rulesWithAlerts = New-Object System.Collections.Generic.List[object]
    $rulesWithoutAlerts = New-Object System.Collections.Generic.List[object]

    $passed = $false
    $customStatus = $null
    $leadText = ''

    if ($errorMsg) {
        $customStatus = 'Investigate'
        $leadText = "⚠️ Unable to determine DLP alert configuration due to permissions issues or query failure.`n`n**Details:** $errorMsg`n"
    }
    elseif ($dlpRules.Count -eq 0) {
        $passed = $false
        $leadText = "❌ No DLP compliance rules are configured in the tenant.`n"
    }
    else {
        foreach ($rule in $dlpRules) {
            $hasAlert = $false

            # Current behavior preserved: alerting if GenerateAlert/GenerateIncidentReport is present and not None. [1](https://insightonline-my.sharepoint.com/personal/joshua_kaye_insight_com/Documents/Microsoft%20Copilot%20Chat%20Files/Test-Assessment.35045.ps1.txt)
            if ($rule.GenerateAlert -and $rule.GenerateAlert -ne 'None') { $hasAlert = $true }
            if ($rule.GenerateIncidentReport -and $rule.GenerateIncidentReport -ne 'None') { $hasAlert = $true }

            if ($hasAlert) { $rulesWithAlerts.Add($rule) }
            else { $rulesWithoutAlerts.Add($rule) }
        }

        if ($rulesWithAlerts.Count -gt 0) {
            $passed = $true
            $leadText = "✅ $($rulesWithAlerts.Count) DLP rule(s) are configured to generate alerts or incident reports.`n"
            if ($rulesWithoutAlerts.Count -gt 0) {
                $leadText += "⚠️ $($rulesWithoutAlerts.Count) rule(s) do not generate alerts/incident reports (review for monitoring gaps).`n"
            }
        }
        else {
            $passed = $false
            $leadText = "❌ No DLP rules are configured to generate alerts or incident reports. DLP violations may go undetected by the security team.`n"
        }
    }
    #endregion Assessment Logic

    #region Evidence Markdown
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if (-not $errorMsg -and $dlpRules.Count -gt 0) {

        # Optional detail table for "rules without alerts"
        if ($rulesWithoutAlerts.Count -gt 0) {
            $lines.Add("### Rules without alerts / incident reports")
            $lines.Add("")
            $lines.Add("Rule Name | Policy Name | GenerateAlert | GenerateIncidentReport")
            $lines.Add(":---|:---|:---|:---")

            $sortedNoAlert = $rulesWithoutAlerts | Sort-Object @{
                Expression = { $_.ParentPolicyName }
            }, @{
                Expression = { $_.Name }
            }

            foreach ($r in $sortedNoAlert) {
                $ruleName = Get-SafeMarkdown -Text $r.Name
                $policyName = if ($r.PSObject.Properties.Name -contains 'ParentPolicyName') {
                    Get-SafeMarkdown -Text ($r.ParentPolicyName)
                } else { 'Unknown' }

                $ga = if ($r.GenerateAlert) { $r.GenerateAlert } else { 'None' }
                $gir = if ($r.GenerateIncidentReport) { $r.GenerateIncidentReport } else { 'None' }

                $lines.Add("$ruleName | $policyName | $ga | $gir")
            }

            $lines.Add("")
        }

        # Summary
        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|---:")
        $lines.Add(("Total DLP rules | {0}" -f $dlpRules.Count))
        $lines.Add(("Rules with alerts/incident reports | {0}" -f $rulesWithAlerts.Count))
        $lines.Add(("Rules without alerts | {0}" -f $rulesWithoutAlerts.Count))
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
