<#
.SYNOPSIS
 DLP policies are configured for Microsoft Teams
#>
function Test-Assessment-35042 {
    [ZtTest(
        Category = 'Data Loss Prevention (DLP)',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Microsoft 365 E5'),
        Pillar = 'Data',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 35042,
        Title = 'DLP policies are configured for Microsoft Teams',
        UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35042
    $title    = 'DLP policies are configured for Microsoft Teams'
    $activity = 'Checking DLP policy coverage for Microsoft Teams'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    #region Data Collection
    Write-ZtProgress -Activity $activity -Status 'Getting DLP policies'

    $errorMsg = $null
    $dlpPolicies = @()

    if (-not (Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)) {
        $errorMsg = "Get-DlpCompliancePolicy cmdlet not found. Ensure Security & Compliance (IPPS) session is connected."
        Write-PSFMessage $errorMsg -Level Warning
    }
    else {
        try {
            $dlpPolicies = @(Get-DlpCompliancePolicy -ErrorAction Stop)
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-PSFMessage ("Error querying DLP policies: {0}" -f $_) -Level Error
        }
    }
    #endregion Data Collection

    #region Assessment Logic
    $teamsPolicies = New-Object System.Collections.Generic.List[object]
    $teamsEnabledPolicies = New-Object System.Collections.Generic.List[object]

    $passed = $false
    $customStatus = $null
    $leadText = ''

    if ($errorMsg) {
        $customStatus = 'Investigate'
        $leadText = "⚠️ Unable to determine DLP policy coverage for Microsoft Teams due to permissions issues or query failure.`n`n**Details:** $errorMsg`n"
    }
    else {
        foreach ($policy in $dlpPolicies) {
            $hasTeams = $false

            if ($policy.TeamsLocation) {
                if (@($policy.TeamsLocation).Count -gt 0) { $hasTeams = $true }
            }

            if ($hasTeams) {
                $teamsPolicies.Add($policy)

                if ($policy.Mode -eq 'Enable') {
                    $teamsEnabledPolicies.Add($policy)
                }
            }
        }

        if ($teamsEnabledPolicies.Count -gt 0) {
            $passed = $true
            $leadText = "✅ $($teamsEnabledPolicies.Count) DLP policy(ies) are configured and enabled for Microsoft Teams chat and channel messages.`n"
        }
        elseif ($teamsPolicies.Count -gt 0) {
            $passed = $false
            $leadText = "❌ $($teamsPolicies.Count) DLP policy(ies) include Teams but none are in enforcement mode.`n"
        }
        else {
            $passed = $false
            $leadText = "❌ No DLP policies are configured that include Microsoft Teams. Sensitive data shared in chat and channel messages is not monitored or protected.`n"
        }
    }
    #endregion Assessment Logic

    #region Evidence Markdown
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if (-not $errorMsg) {

        if ($teamsPolicies.Count -gt 0) {
            $lines.Add("### DLP Policies covering Microsoft Teams")
            $lines.Add("")
            $lines.Add("Policy Name | Mode | Teams Location | Created")
            $lines.Add(":---|:---|:---|:---")

            # Sort: enforcing first, then simulation, then other; stable by name
            $sorted = $teamsPolicies | Sort-Object @{
                Expression = {
                    switch ($_.Mode) {
                        'Enable' { 0 }
                        'TestWithNotifications' { 1 }
                        'TestWithoutNotifications' { 2 }
                        default { 3 }
                    }
                }
            }, @{
                Expression = { $_.Name }
            }

            foreach ($policy in $sorted) {
                $policyName = Get-SafeMarkdown -Text $policy.Name
                $icon = if ($policy.Mode -eq 'Enable') { '✅' } else { '⚠️' }

                $modeDisplay = switch ($policy.Mode) {
                    'Enable' { 'Enforcing' }
                    'TestWithNotifications' { 'Simulation (with tips)' }
                    'TestWithoutNotifications' { 'Simulation (no tips)' }
                    default { $policy.Mode }
                }

                $teamsLoc = ($policy.TeamsLocation | ForEach-Object {
                    if ($_.Name) { $_.Name } else { $_.ToString() }
                }) -join ', '

                $teamsLoc = if ([string]::IsNullOrWhiteSpace($teamsLoc)) { 'All' } else { $teamsLoc }
                $teamsLoc = Get-SafeMarkdown -Text $teamsLoc

                $created = Get-FormattedDate -Date $policy.WhenCreatedUTC

                $lines.Add(("$icon $policyName | $modeDisplay | $teamsLoc | $created"))
            }

            $lines.Add("")
        }
        elseif ($dlpPolicies.Count -gt 0) {
            $lines.Add("### Note")
            $lines.Add(("Your tenant has {0} DLP policy(ies), but none include Microsoft Teams as a protected location." -f $dlpPolicies.Count))
            $lines.Add("")
        }

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|---:")
        $lines.Add(("Total DLP policies in tenant | {0}" -f $dlpPolicies.Count))
        $lines.Add(("DLP policies covering Teams | {0}" -f $teamsPolicies.Count))
        $lines.Add(("DLP policies enforcing on Teams | {0}" -f $teamsEnabledPolicies.Count))
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
