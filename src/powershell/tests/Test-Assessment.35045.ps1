# src\powershell\tests\Test-Assessment.35045.ps1

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

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking DLP alert configuration'
    Write-ZtProgress -Activity $activity -Status 'Getting DLP compliance rules'

    $errorMsg = $null
    $dlpRules = @()

    try {
        $dlpRules = Get-DlpComplianceRule -ErrorAction Stop
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage "Error querying DLP rules: $_" -Level Error
    }
    #endregion Data Collection

    #region Assessment Logic
    $rulesWithAlerts = @()
    $rulesWithoutAlerts = @()
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine DLP alert configuration due to permissions issues or query failure.`n`n"
        $customStatus = 'Investigate'
    }
    elseif ($dlpRules.Count -eq 0) {
        $passed = $false
        $testResultMarkdown = "❌ No DLP compliance rules are configured in the tenant.`n`n%TestResult%"
    }
    else {
        foreach ($rule in $dlpRules) {
            $hasAlert = $false

            # Check if the rule generates alerts or incident reports
            if ($rule.GenerateAlert -and $rule.GenerateAlert -ne 'None') {
                $hasAlert = $true
            }
            if ($rule.GenerateIncidentReport -and $rule.GenerateIncidentReport -ne 'None') {
                $hasAlert = $true
            }

            if ($hasAlert) {
                $rulesWithAlerts += $rule
            }
            else {
                $rulesWithoutAlerts += $rule
            }
        }

        if ($rulesWithAlerts.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ $($rulesWithAlerts.Count) DLP rule(s) are configured to generate alerts or incident reports.`n`n%TestResult%"
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ No DLP rules are configured to generate alerts or incident reports. DLP violations will go undetected by the security team.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Total DLP rules | $($dlpRules.Count) |`n"
    $mdInfo += "| Rules with alerts/incident reports | $($rulesWithAlerts.Count) |`n"
    $mdInfo += "| Rules without alerts | $($rulesWithoutAlerts.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35045'
        Title  = 'DLP alerts are configured and routed'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
