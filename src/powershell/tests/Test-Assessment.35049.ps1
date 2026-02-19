<#
.SYNOPSIS
 Data access reviews are configured for sensitive resources
#>
function Test-Assessment-35049 {
    [ZtTest(
        Category = 'Access Control',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Microsoft Entra ID P2'),
        Pillar = 'Data',
        RiskLevel = 'Medium',
        SfiPillar = 'Protect identities and secrets',
        TenantType = ('Workforce'),
        TestId = 35049,
        Title = 'Data access reviews are configured for sensitive resources',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param(
        $Database
    )

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35049
    $title    = 'Data access reviews are configured for sensitive resources'
    $activity = 'Checking access review configuration'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    Write-ZtProgress -Activity $activity -Status 'Getting access review definitions (Graph)'

    $errorMsg = $null
    $customStatus = $null
    $passed = $false

    $definitions = @()
    $recurringDefinitions = @()
    $activeInstancesCount = 0

    try {
        # Definitions: configuration objects (do not reliably have runtime status)
        $resp = Invoke-ZtGraphRequest -Uri '/v1.0/identityGovernance/accessReviews/definitions' -ErrorAction Stop
        $definitions = if ($resp.value) { @($resp.value) } else { @($resp) }
    }
    catch {
        $customStatus = 'Investigate'
        $errorMsg = $_.Exception.Message

        # Add a helpful hint; most failures here are missing Graph scopes/permissions for Identity Governance
        $errorMsg += "`n`nHint: This check requires Graph permissions for Identity Governance Access Reviews (Entra ID P2). Ensure the account/app has the required scopes and that you are connected with Connect-ZtAssessment -Service Graph."
    }

    if (-not $errorMsg) {
        # Determine which definitions are recurring
        $recurringDefinitions = @(
            $definitions | Where-Object {
                $_.settings -and $_.settings.recurrence
            }
        )

        # OPTIONAL: determine if there are any active instances for any definitions
        # Keep it light: only check first N definitions to avoid long runs.
        $maxInstanceChecks = 10
        $checked = 0

        foreach ($def in $definitions) {
            if ($checked -ge $maxInstanceChecks) { break }
            if (-not $def.id) { continue }

            try {
                $inst = Invoke-ZtGraphRequest -Uri ("/v1.0/identityGovernance/accessReviews/definitions/{0}/instances" -f $def.id) -ErrorAction Stop
                $instances = if ($inst.value) { @($inst.value) } else { @($inst) }

                $activeInstancesCount += @(
                    $instances | Where-Object { $_.status -in @('InProgress', 'NotStarted', 'Starting') }
                ).Count

                $checked++
            }
            catch {
                # If instances query fails, don't fail the whole test; just continue
                Write-PSFMessage ("Warning: failed to query instances for access review definition {0}: {1}" -f $def.id, $_.Exception.Message) -Level Warning
            }
        }

        # Pass/Fail logic (reasonable baseline):
        # Pass if there is at least one recurring access review definition.
        if ($recurringDefinitions.Count -gt 0) {
            $passed = $true
        }
        else {
            $passed = $false
        }
    }

    # --- Evidence markdown (injected into MD) ---
    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add("⚠️ Unable to determine access review configuration due to permissions issues or query failure.")
        $lines.Add("")
        $lines.Add("**Details:** $errorMsg")
    }
    else {
        if ($passed) {
            $lines.Add(("✅ {0} access review definition(s) are configured as recurring reviews." -f $recurringDefinitions.Count))
            if ($activeInstancesCount -gt 0) {
                $lines.Add(("✅ {0} active access review instance(s) were detected (sampled from first {1} definitions)." -f $activeInstancesCount, [Math]::Min($definitions.Count, 10)))
            }
            else {
                $lines.Add(("ℹ️ No active access review instances were detected in the sampled definitions (this may be normal if reviews are scheduled but not currently running)."))
            }
        }
        else {
            if ($definitions.Count -gt 0) {
                $lines.Add(("❌ {0} access review definition(s) exist but none are configured as recurring reviews." -f $definitions.Count))
                $lines.Add("Access reviews should be recurring to continuously validate entitlements over time.")
            }
            else {
                $lines.Add("❌ No access reviews are configured. Users may retain access to sensitive resources longer than necessary, violating least-privilege principles.")
            }
        }

        $lines.Add("")
        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|---:")
        $lines.Add(("Total access review definitions | {0}" -f $definitions.Count))
        $lines.Add(("Recurring access review definitions | {0}" -f $recurringDefinitions.Count))
        $lines.Add(("Active access review instances (sampled) | {0}" -f $activeInstancesCount))

        # Optional: show a short list of recurring review names (top 10)
        if ($recurringDefinitions.Count -gt 0) {
            $lines.Add("")
            $lines.Add("### Recurring access reviews (sample)")
            $lines.Add("")
            $lines.Add("Review Name | Scope")
            $lines.Add(":---|:---")

            foreach ($d in ($recurringDefinitions | Select-Object -First 10)) {
                $name = Get-SafeMarkdown -Text ($d.displayName)
                $scope = if ($d.scope) { ($d.scope.PSObject.Properties.Name -join ', ') } else { 'Unknown' }
                $lines.Add(("$name | $scope"))
            }
        }
    }

    $mdInfo = ($lines -join "`n")

    # --- Load MD and inject evidence ---
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

    $params = @{
        TestId = "$testId"
        Title  = $title
        Status = $passed
        Result = $resultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }

    Add-ZtTestResultDetail @params
}
