<#
.SYNOPSIS
 DLP policies are configured for SharePoint Online and OneDrive
#>
function Test-Assessment-35041 {
    [ZtTest(
        Category = 'Data Loss Prevention (DLP)',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Microsoft 365 E3'),
        Pillar = 'Data',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 35041,
        Title = 'DLP policies are configured for SharePoint Online and OneDrive',
        UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35041
    $title    = 'DLP policies are configured for SharePoint Online and OneDrive'
    $activity = 'Checking DLP policy coverage for SharePoint Online and OneDrive'
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
    $spoPolicies = New-Object System.Collections.Generic.List[object]
    $spoEnabledPolicies = New-Object System.Collections.Generic.List[object]

    $passed = $false
    $customStatus = $null
    $leadText = ''

    if ($errorMsg) {
        $customStatus = 'Investigate'
        $leadText = "⚠️ Unable to determine DLP policy coverage for SharePoint/OneDrive due to permissions issues or query failure.`n`n**Details:** $errorMsg`n"
    }
    else {
        foreach ($policy in $dlpPolicies) {
            $hasSPO = $false
            $hasODB = $false

            # Same basic logic as your current script: location exists + has entries means enabled for that workload. [1](https://insightonline-my.sharepoint.com/personal/joshua_kaye_insight_com/Documents/Microsoft%20Copilot%20Chat%20Files/Test-Assessment.35041.ps1.txt)
            if ($policy.SharePointLocation) {
                if (@($policy.SharePointLocation).Count -gt 0) { $hasSPO = $true }
            }
            if ($policy.OneDriveLocation) {
                if (@($policy.OneDriveLocation).Count -gt 0) { $hasODB = $true }
            }

            if ($hasSPO -or $hasODB) {
                $spoPolicies.Add([PSCustomObject]@{
                    Policy       = $policy
                    HasSharePoint = $hasSPO
                    HasOneDrive   = $hasODB
                })

                # Enforcing mode is Mode = Enable (matches your current behavior). [1](https://insightonline-my.sharepoint.com/personal/joshua_kaye_insight_com/Documents/Microsoft%20Copilot%20Chat%20Files/Test-Assessment.35041.ps1.txt)
                if ($policy.Mode -eq 'Enable') {
                    $spoEnabledPolicies.Add($policy)
                }
            }
        }

        if ($spoEnabledPolicies.Count -gt 0) {
            $passed = $true
            $leadText = "✅ $($spoEnabledPolicies.Count) DLP policy(ies) are configured and enabled for SharePoint Online and/or OneDrive for Business.`n"
        }
        elseif ($spoPolicies.Count -gt 0) {
            $passed = $false
            $leadText = "❌ $($spoPolicies.Count) DLP policy(ies) include SharePoint/OneDrive but none are in enforcement mode.`n"
        }
        else {
            $passed = $false
            $leadText = "❌ No DLP policies are configured that include SharePoint Online or OneDrive for Business. Sensitive files can be stored and shared without detection or restriction.`n"
        }
    }
    #endregion Assessment Logic

    #region Report Generation (Evidence)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if (-not $errorMsg) {

        if ($spoPolicies.Count -gt 0) {
            $lines.Add("### DLP Policies covering SharePoint/OneDrive")
            $lines.Add("")
            $lines.Add("Policy Name | Mode | SharePoint | OneDrive | Created")
            $lines.Add(":---|:---|:---:|:---:|:---")

            # Sort: enforcing first, then simulation, then other; stable by name
            $sorted = $spoPolicies | Sort-Object @{
                Expression = {
                    switch ($_.Policy.Mode) {
                        'Enable' { 0 }
                        'TestWithNotifications' { 1 }
                        'TestWithoutNotifications' { 2 }
                        default { 3 }
                    }
                }
            }, @{
                Expression = { $_.Policy.Name }
            }

            foreach ($item in $sorted) {
                $policy = $item.Policy
                $policyName = Get-SafeMarkdown -Text $policy.Name

                $modeDisplay = switch ($policy.Mode) {
                    'Enable' { 'Enforcing' }
                    'TestWithNotifications' { 'Simulation (with tips)' }
                    'TestWithoutNotifications' { 'Simulation (no tips)' }
                    default { $policy.Mode }
                }

                # Keep icons as requested
                $spoIcon = if ($item.HasSharePoint) { '✅' } else { '❌' }
                $odbIcon = if ($item.HasOneDrive)   { '✅' } else { '❌' }

                $created = Get-FormattedDate -Date $policy.WhenCreatedUTC

                $lines.Add(("$policyName | $modeDisplay | $spoIcon | $odbIcon | $created"))
            }

            $lines.Add("")
        }
        elseif ($dlpPolicies.Count -gt 0) {
            $lines.Add("### Note")
            $lines.Add(("Your tenant has {0} DLP policy(ies), but none include SharePoint Online or OneDrive for Business as protected locations." -f $dlpPolicies.Count))
            $lines.Add("")
        }

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|---:")
        $lines.Add(("Total DLP policies in tenant | {0}" -f $dlpPolicies.Count))
        $lines.Add(("DLP policies covering SharePoint/OneDrive | {0}" -f $spoPolicies.Count))
        $lines.Add(("DLP policies enforcing on SharePoint/OneDrive | {0}" -f $spoEnabledPolicies.Count))
    }

    $mdInfo = ($lines -join "`n")
    #endregion Report Generation

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
