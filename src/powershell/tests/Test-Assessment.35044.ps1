<#
.SYNOPSIS
 DLP policies are in enforcement mode
#>
function Test-Assessment-35044 {
    [ZtTest(
        Category = 'Data Loss Prevention (DLP)',
        ImplementationCost = 'Low',
        MinimumLicense = ('Microsoft 365 E3'),
        Pillar = 'Data',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 35044,
        Title = 'DLP policies are in enforcement mode',
        UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35044
    $title    = 'DLP policies are in enforcement mode'
    $activity = 'Checking DLP policy enforcement status'
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
    $enforcingPolicies  = New-Object System.Collections.Generic.List[object]
    $simulationPolicies = New-Object System.Collections.Generic.List[object]
    $disabledPolicies   = New-Object System.Collections.Generic.List[object]

    $passed = $false
    $customStatus = $null
    $leadText = ''

    if ($errorMsg) {
        $customStatus = 'Investigate'
        $leadText = "⚠️ Unable to determine DLP policy enforcement status due to permissions issues or query failure.`n`n**Details:** $errorMsg`n"
    }
    elseif ($dlpPolicies.Count -eq 0) {
        $passed = $false
        $leadText = "❌ No DLP policies are configured in the tenant.`n"
    }
    else {
        foreach ($policy in $dlpPolicies) {
            switch ($policy.Mode) {
                'Enable' { $enforcingPolicies.Add($policy) }
                'TestWithNotifications' { $simulationPolicies.Add($policy) }
                'TestWithoutNotifications' { $simulationPolicies.Add($policy) }
                default { $disabledPolicies.Add($policy) }
            }
        }

        # UPDATED LOGIC (realistic baseline):
        # Pass if at least one DLP policy is enforcing.
        if ($enforcingPolicies.Count -gt 0) {
            $passed = $true
            if ($simulationPolicies.Count -gt 0) {
                $leadText = "✅ $($enforcingPolicies.Count) DLP policy(ies) are enforcing. ⚠️ $($simulationPolicies.Count) policy(ies) remain in simulation/test mode (visibility only).`n"
            }
            else {
                $leadText = "✅ All $($enforcingPolicies.Count) DLP policy(ies) are in enforcement mode.`n"
            }
        }
        else {
            $passed = $false
            if ($simulationPolicies.Count -gt 0) {
                $leadText = "❌ $($simulationPolicies.Count) DLP policy(ies) are in simulation/test mode and none are enforcing. No policies are actively preventing data loss.`n"
            }
            else {
                $leadText = "❌ No enforcing DLP policies were found.`n"
            }
        }
    }
    #endregion Assessment Logic

    #region Evidence Markdown
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if (-not $errorMsg -and $dlpPolicies.Count -gt 0) {

        $lines.Add("### DLP Policy Enforcement Status")
        $lines.Add("")
        $lines.Add("Policy Name | Mode | Locations | Created")
        $lines.Add(":---|:---|:---|:---")

        # Sort: enforcing first, then simulation, then disabled/other; stable by name
        $sorted = $dlpPolicies | Sort-Object @{
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

            $icon = switch ($policy.Mode) {
                'Enable' { '✅' }
                'TestWithNotifications' { '⚠️' }
                'TestWithoutNotifications' { '⚠️' }
                default { '❌' }
            }

            $modeDisplay = switch ($policy.Mode) {
                'Enable' { 'Enforcing' }
                'TestWithNotifications' { 'Simulation (with tips)' }
                'TestWithoutNotifications' { 'Simulation (no tips)' }
                default { $policy.Mode }
            }

            $locations = @()
            if ($policy.ExchangeLocation)     { $locations += 'Exchange' }
            if ($policy.SharePointLocation)  { $locations += 'SharePoint' }
            if ($policy.OneDriveLocation)    { $locations += 'OneDrive' }
            if ($policy.TeamsLocation)       { $locations += 'Teams' }
            if ($policy.EndpointDlpLocation) { $locations += 'Endpoints' }

            $locationDisplay = if ($locations.Count -gt 0) { $locations -join ', ' } else { 'None' }
            $created = Get-FormattedDate -Date $policy.WhenCreatedUTC

            $lines.Add(("$icon $policyName | $modeDisplay | $locationDisplay | $created"))
        }

        $lines.Add("")
        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|:---")
        $lines.Add(("Total DLP policies | {0}" -f $dlpPolicies.Count))
        $lines.Add(("Enforcing | {0}" -f $enforcingPolicies.Count))
        $lines.Add(("Simulation/Test mode | {0}" -f $simulationPolicies.Count))
        $lines.Add(("Disabled/Other | {0}" -f $disabledPolicies.Count))
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
