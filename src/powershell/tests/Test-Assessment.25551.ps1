<#
.SYNOPSIS
 Named locations are defined and used in Conditional Access policies
#>
function Test-Assessment-25551 {
    [ZtTest(
        Category = 'Access control',
        ImplementationCost = 'Low',
        MinimumLicense = ('AAD_PREMIUM'),
        Pillar = 'Network',
        RiskLevel = 'Medium',
        SfiPillar = 'Protect networks',
        TenantType = ('Workforce'),
        TestId = 25551,
        Title = 'Named locations are defined and used in Conditional Access policies',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param(
        $Database
    )

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 25551
    $title    = 'Named locations are defined and used in Conditional Access policies'
    $activity = 'Checking named locations and Conditional Access policy usage'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    Write-ZtProgress -Activity $activity -Status 'Getting named locations (Graph)'

    $passed              = $false
    $errorMsg            = $null
    $customStatus        = $null
    $namedLocations      = @()
    $enabledPolicies     = @()

    # ------------------------------------------------------------------
    # 1. Collect named locations
    # ------------------------------------------------------------------
    try {
        $namedLocations = @(Invoke-ZtGraphRequest -RelativeUri 'identity/conditionalAccess/namedLocations' -ApiVersion 'v1.0')
    }
    catch {
        $errorMsg    = $_.Exception.Message
        $customStatus = 'Investigate'
    }

    # ------------------------------------------------------------------
    # 2. Collect enabled CA policies
    # ------------------------------------------------------------------
    if (-not $errorMsg) {
        Write-ZtProgress -Activity $activity -Status 'Getting enabled Conditional Access policies (Graph)'
        try {
            $enabledPolicies = @(Invoke-ZtGraphRequest -RelativeUri "identity/conditionalAccess/policies" -Filter "state eq 'enabled'" -ApiVersion 'v1.0')
        }
        catch {
            $errorMsg    = $_.Exception.Message
            $customStatus = 'Investigate'
        }
    }

    # ------------------------------------------------------------------
    # 3. Evaluate
    # ------------------------------------------------------------------
    $ipNamedLocations      = @()
    $countryNamedLocations = @()
    $otherNamedLocations   = @()
    $locationIdSet         = @{}
    $policiesUsingLocations = @()

    if (-not $errorMsg) {
        foreach ($loc in $namedLocations) {
            $odata = [string]$loc.'@odata.type'
            $locationIdSet[$loc.id] = $loc.displayName
            if ($odata -like '*ipNamedLocation') {
                $ipNamedLocations += $loc
            }
            elseif ($odata -like '*countryNamedLocation') {
                $countryNamedLocations += $loc
            }
            else {
                $otherNamedLocations += $loc
            }
        }

        # Find enabled policies that reference at least one named location by GUID
        foreach ($policy in $enabledPolicies) {
            $incl = @()
            $excl = @()
            try { $incl = @($policy.conditions.locations.includeLocations) } catch { }
            try { $excl = @($policy.conditions.locations.excludeLocations) } catch { }

            $allRefs = @($incl + $excl) | Where-Object {
                $_ -and $_ -notin @('All', 'AllTrusted', 'AllCompliant') -and $locationIdSet.ContainsKey($_)
            }

            if ($allRefs.Count -gt 0) {
                $resolvedNames = $allRefs | ForEach-Object { $locationIdSet[$_] } | Where-Object { $_ }
                $policiesUsingLocations += [pscustomobject]@{
                    PolicyName         = $policy.displayName
                    ReferencedNames    = ($resolvedNames -join ', ')
                }
            }
        }

        $hasIpNamedLocations       = ($ipNamedLocations.Count -gt 0)
        $hasPoliciesUsingLocations = ($policiesUsingLocations.Count -gt 0)
        $passed = $hasIpNamedLocations -and $hasPoliciesUsingLocations
    }

    # ------------------------------------------------------------------
    # 4. Evidence markdown
    # ------------------------------------------------------------------
    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add("Unable to retrieve named location or Conditional Access policy data.")
        $lines.Add("")
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add("")
        $lines.Add("Ensure the assessment account has the **Policy.Read.All** Graph permission.")
    }
    else {
        # Lead line
        if ($passed) {
            $lines.Add(("{0} IP-based named location(s) are defined and referenced in {1} enabled Conditional Access policy(ies)." -f $ipNamedLocations.Count, $policiesUsingLocations.Count))
        }
        elseif (-not $hasIpNamedLocations) {
            $lines.Add("No IP-based named locations are defined. Conditional Access policies cannot enforce IP-based network controls.")
        }
        else {
            $lines.Add(("{0} IP-based named location(s) are defined but none are referenced in any enabled Conditional Access policy." -f $ipNamedLocations.Count))
        }
        $lines.Add("")

        # Named Locations table
        if ($namedLocations.Count -gt 0) {
            $lines.Add("### Named Locations")
            $lines.Add("")
            $lines.Add("| Name | Type | Trusted | IP Ranges |")
            $lines.Add("|:---|:---|:---:|---:|")

            foreach ($loc in ($namedLocations | Sort-Object displayName)) {
                $odata = [string]$loc.'@odata.type'

                if ($odata -like '*ipNamedLocation') {
                    $typeName  = "IP Ranges"
                    $trusted   = if ($loc.isTrusted) { "Yes" } else { "No" }
                    $ipCount   = if ($loc.ipRanges) { ($loc.ipRanges | Measure-Object).Count } else { 0 }
                    $ipDisplay = $ipCount
                }
                elseif ($odata -like '*countryNamedLocation') {
                    $typeName  = "Countries"
                    $trusted   = "N/A"
                    $ipDisplay = "N/A"
                }
                else {
                    $typeName  = "Compliant Network"
                    $trusted   = "N/A"
                    $ipDisplay = "N/A"
                }

                $name = if ($loc.displayName) { [string]$loc.displayName } else { $loc.id }
                $lines.Add(("| {0} | {1} | {2} | {3} |" -f $name, $typeName, $trusted, $ipDisplay))
            }
            $lines.Add("")
        }
        else {
            $lines.Add("No named locations are defined in this tenant.")
            $lines.Add("")
        }

        # Policies using named locations table
        if ($policiesUsingLocations.Count -gt 0) {
            $lines.Add("### Conditional Access Policies Using Named Locations")
            $lines.Add("")
            $lines.Add("| Policy Name | Referenced Locations |")
            $lines.Add("|:---|:---|")

            foreach ($p in ($policiesUsingLocations | Sort-Object PolicyName)) {
                $lines.Add(("| {0} | {1} |" -f $p.PolicyName, $p.ReferencedNames))
            }
            $lines.Add("")
        }
        elseif ($namedLocations.Count -gt 0) {
            $lines.Add("No enabled Conditional Access policies reference any named location.")
            $lines.Add("")
        }

        # Summary table
        $trustedCount = ($ipNamedLocations | Where-Object { $_.isTrusted }).Count
        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("| Metric | Count |")
        $lines.Add("|:---|---:|")
        $lines.Add(("| Total named locations | {0} |" -f $namedLocations.Count))
        $lines.Add(("| IP-based named locations | {0} |" -f $ipNamedLocations.Count))
        $lines.Add(("| Trusted IP named locations | {0} |" -f $trustedCount))
        $lines.Add(("| Country-based named locations | {0} |" -f $countryNamedLocations.Count))
        $lines.Add(("| Enabled CA policies using named locations | {0} |" -f $policiesUsingLocations.Count))
        $lines.Add("")
    }

    $mdInfo = ($lines -join "`n")

    # ------------------------------------------------------------------
    # 5. Emit result
    # ------------------------------------------------------------------
    if (-not (Test-Path $mdPath)) {
        $customStatus = 'Investigate'
        Write-PSFMessage ("Missing markdown file: {0}" -f $mdPath) -Level Warning
    }

    $params = @{
        TestId = "$testId"
        Title  = $title
        Status = $passed
        Result = $mdInfo
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }

    Add-ZtTestResultDetail @params
}
