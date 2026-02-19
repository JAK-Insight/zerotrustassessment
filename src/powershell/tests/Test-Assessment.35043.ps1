<#
.SYNOPSIS
 Endpoint DLP is enabled
#>
function Test-Assessment-35043 {
    [ZtTest(
        Category = 'Data Loss Prevention (DLP)',
        ImplementationCost = 'High',
        MinimumLicense = ('Microsoft 365 E5'),
        Pillar = 'Data',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 35043,
        Title = 'Endpoint DLP is enabled',
        UserImpact = 'High'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35043
    $title    = 'Endpoint DLP is enabled'
    $activity = 'Checking Endpoint DLP configuration'
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
    $endpointPolicies = New-Object System.Collections.Generic.List[object]
    $endpointEnabledPolicies = New-Object System.Collections.Generic.List[object]

    $passed = $false
    $customStatus = $null
    $leadText = ''

    if ($errorMsg) {
        $customStatus = 'Investigate'
        $leadText = "⚠️ Unable to determine Endpoint DLP status due to permissions issues or query failure.`n`n**Details:** $errorMsg`n"
    }
    else {
        foreach ($policy in $dlpPolicies) {
            $hasEndpoint = $false

            if ($policy.EndpointDlpLocation) {
                if (@($policy.EndpointDlpLocation).Count -gt 0) { $hasEndpoint = $true }
            }

            if ($hasEndpoint) {
                $endpointPolicies.Add($policy)

                if ($policy.Mode -eq 'Enable') {
                    $endpointEnabledPolicies.Add($policy)
                }
            }
        }

        if ($endpointEnabledPolicies.Count -gt 0) {
            $passed = $true
            $leadText = "✅ $($endpointEnabledPolicies.Count) DLP policy(ies) are configured and enabled for Endpoint DLP (Devices).`n"
        }
        elseif ($endpointPolicies.Count -gt 0) {
            $passed = $false
            $leadText = "❌ $($endpointPolicies.Count) DLP policy(ies) include Devices but none are in enforcement mode.`n"
        }
        else {
            $passed = $false
            $leadText = "❌ No DLP policies include Devices (Endpoint DLP) as a protected location. Sensitive data can be exfiltrated from managed devices via USB, print, clipboard, or unauthorized cloud uploads.`n"
        }
    }
    #endregion Assessment Logic

    #region Evidence Markdown
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if (-not $errorMsg) {

        if ($endpointPolicies.Count -gt 0) {
            $lines.Add("### DLP Policies covering Endpoints")
            $lines.Add("")
            $lines.Add("Policy Name | Mode | Endpoint Location | Created")
            $lines.Add(":---|:---|:---|:---")

            $sorted = $endpointPolicies | Sort-Object @{
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

                $endpointLoc = ($policy.EndpointDlpLocation | ForEach-Object {
                    if ($_.Name) { $_.Name } else { $_.ToString() }
                }) -join ', '

                $endpointLoc = if ([string]::IsNullOrWhiteSpace($endpointLoc)) { 'All' } else { $endpointLoc }
                $endpointLoc = Get-SafeMarkdown -Text $endpointLoc

                $created = Get-FormattedDate -Date $policy.WhenCreatedUTC

                $lines.Add(("$icon $policyName | $modeDisplay | $endpointLoc | $created"))
            }

            $lines.Add("")
        }
        elseif ($dlpPolicies.Count -gt 0) {
            $lines.Add("### Note")
            $lines.Add(("Your tenant has {0} DLP policy(ies), but none include Devices (Endpoint DLP) as a protected location." -f $dlpPolicies.Count))
            $lines.Add("")
        }

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|---:")
        $lines.Add(("Total DLP policies in tenant | {0}" -f $dlpPolicies.Count))
        $lines.Add(("DLP policies covering Endpoints | {0}" -f $endpointPolicies.Count))
        $lines.Add(("DLP policies enforcing on Endpoints | {0}" -f $endpointEnabledPolicies.Count))
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
