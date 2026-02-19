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

    $errorMsg            = $null
    $customStatus        = $null
    $passed              = $false
    $definitions         = @()
    $recurringDefinitions = @()
    $activeInstancesCount = 0

    # Evidence transparency (typed-first, REST fallback)
    $typedUsed = $false

    # Caches to avoid repeated Graph lookups
    $spNameCache   = @{} # servicePrincipalId => displayName
    $roleNameCache = @{} # roleDefinitionId => displayName

    # -----------------------------
    # Helpers (Graph lookups)
    # -----------------------------
    function Get-ZtServicePrincipalName {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string] $ServicePrincipalId
        )

        if ($spNameCache.ContainsKey($ServicePrincipalId)) {
            return $spNameCache[$ServicePrincipalId]
        }

        try {
            $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId?`$select=displayName"
            $sp  = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $name = if ($sp.displayName) { [string]$sp.displayName } else { "servicePrincipal:$ServicePrincipalId" }
            $spNameCache[$ServicePrincipalId] = $name
            return $name
        }
        catch {
            $fallback = "servicePrincipal:$ServicePrincipalId"
            $spNameCache[$ServicePrincipalId] = $fallback
            return $fallback
        }
    }

    function Get-ZtDirectoryRoleDefinitionName {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string] $RoleDefinitionId
        )

        if ($roleNameCache.ContainsKey($RoleDefinitionId)) {
            return $roleNameCache[$RoleDefinitionId]
        }

        try {
            $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$RoleDefinitionId?`$select=displayName"
            $rd  = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $name = if ($rd.displayName) { [string]$rd.displayName } else { "roleDefinition:$RoleDefinitionId" }
            $roleNameCache[$RoleDefinitionId] = $name
            return $name
        }
        catch {
            $fallback = "roleDefinition:$RoleDefinitionId"
            $roleNameCache[$RoleDefinitionId] = $fallback
            return $fallback
        }
    }

    # -----------------------------
    # Helper: executive-friendly scope summary
    # -----------------------------
    function Get-ZtScopeSummary {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $false)]
            $Scope
        )

        if ($null -eq $Scope) { return "Scope: Unknown" }

        $Shorten = {
            param([string]$s, [int]$max = 120)
            if (-not $s) { return $null }
            if ($s.Length -gt $max) { return ($s.Substring(0, $max) + "…") }
            return $s
        }

        # Robust reads (works for PSCustomObject/hashtable-ish shapes)
        $q = $null
        try { $q = [string]$Scope.query } catch { $q = $null }

        $odata = $null
        try { $odata = [string]$Scope.'@odata.type' } catch { $odata = $null }

        # CASE 1: AccessReviewQueryScope objects (query string)
        if ($q) {
            if ($q -match '/servicePrincipals/([0-9a-fA-F-]{36})') {
                $spId = $Matches[1]
                $appName = Get-ZtServicePrincipalName -ServicePrincipalId $spId
                return ("Enterprise App access review: Users → {0}" -f $appName)
            }

            if ($q -match '/roleManagement/directory/roleDefinitions/([0-9a-fA-F-]{36})') {
                $roleId = $Matches[1]
                $roleName = Get-ZtDirectoryRoleDefinitionName -RoleDefinitionId $roleId
                return ("Directory role access review: Users → {0}" -f $roleName)
            }

            if ($q -match '/identityGovernance/entitlementManagement/accessPackageAssignments') {
                return ("Entitlement review: Access package assignments – {0}" -f (& $Shorten $q 120))
            }

            if ($q -match "userType eq 'Guest'") {
                if ($q -match '/groups/' -and $q -match 'transitiveMembers') {
                    return "Guest access review: Guests in M365 Groups (transitive members)"
                }
                if ($q -match '\./members/microsoft\.graph\.user') {
                    return "Guest access review: Guests in group membership"
                }
                return ("Guest access review: {0}" -f (& $Shorten $q 120))
            }

            return ("Graph scope query: {0}" -f (& $Shorten $q 120))
        }

        # CASE 2: principalResourceMembershipsScope (complex object with principalScopes/resourceScopes)
        if ($odata -and $odata -like '*principalResourceMembershipsScope*') {
            $resourceQueries  = @()
            $principalQueries = @()

            try {
                foreach ($rs in @($Scope.resourceScopes)) {
                    if ($rs -and $rs.query) { $resourceQueries += [string]$rs.query }
                }
            } catch { }

            try {
                foreach ($ps in @($Scope.principalScopes)) {
                    if ($ps -and $ps.query) { $principalQueries += [string]$ps.query }
                }
            } catch { }

            foreach ($rq in $resourceQueries) {
                if ($rq -match '/servicePrincipals/([0-9a-fA-F-]{36})') {
                    $spId = $Matches[1]
                    $appName = Get-ZtServicePrincipalName -ServicePrincipalId $spId
                    return ("Enterprise App access review: Users → {0}" -f $appName)
                }
                if ($rq -match '/roleManagement/directory/roleDefinitions/([0-9a-fA-F-]{36})') {
                    $roleId = $Matches[1]
                    $roleName = Get-ZtDirectoryRoleDefinitionName -RoleDefinitionId $roleId
                    return ("Directory role access review: Users → {0}" -f $roleName)
                }
            }

            $resShort = if ($resourceQueries.Count -gt 0) { (& $Shorten ($resourceQueries -join '; ') 120) } else { 'Unknown resources' }
            $priShort = if ($principalQueries.Count -gt 0) { (& $Shorten ($principalQueries -join '; ') 120) } else { 'Unknown principals' }

            return ("Access relationship review: {0} → {1}" -f $priShort, $resShort)
        }

        # CASE 3: resourceId if present
        try {
            if ($Scope.resourceId) {
                return ("Resource review: {0}" -f [string]$Scope.resourceId)
            }
        } catch { }

        # Last resort: compact raw (trimmed)
        try {
            $json = ($Scope | ConvertTo-Json -Depth 6 -Compress)
            return ("Scope (raw): {0}" -f (& $Shorten $json 160))
        }
        catch {
            return "Scope: Unknown"
        }
    }

    # -----------------------------
    # Typed-first, REST fallback for definitions
    # -----------------------------
    $gotDefs    = $false
    $typedError = $null

    # 1) Try typed cmdlet first
    try {
        if (-not (Get-Module -Name Microsoft.Graph.Identity.Governance -ErrorAction SilentlyContinue)) {
            Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop
        }
        $null = Get-Command -Name Get-MgIdentityGovernanceAccessReviewDefinition -ErrorAction Stop
        $definitions = @(Get-MgIdentityGovernanceAccessReviewDefinition -All)
        $gotDefs   = $true
        $typedUsed = $true
    }
    catch {
        $typedError = $_.Exception
        $gotDefs    = $false
        $typedUsed  = $false
    }

    # 2) REST fallback using Invoke-MgGraphRequest
    if (-not $gotDefs) {
        try {
            $uri  = "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions"
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $definitions = if ($resp -and $resp.value) { @($resp.value) } else { @() }
            $gotDefs = $true

            if ($typedError) {
                Write-Verbose ("[35049] Typed cmdlet path failed; REST fallback succeeded. Typed error: {0}" -f $typedError.Message)
            }
        }
        catch {
            $customStatus = 'Investigate'
            $errorMsg     = $_.Exception.Message

            if ($typedError) {
                $errorMsg += "`n`nTyped cmdlet path also failed: {0}" -f $typedError.Message
                if ($typedError.Message -match 'Method not found' -or $typedError.Message -match 'AuthProviderType') {
                    $errorMsg += "`n`nNote: This can indicate Microsoft.Graph module version mismatch (mixed major versions)."
                }
            }

            $errorMsg += "`n`nHint: This check requires Graph permissions for Access Reviews (AccessReview.Read.All or AccessReview.ReadWrite.All) and an active Graph connection."
        }
    }

    # -----------------------------
    # Evaluate pass/fail
    # -----------------------------
    if (-not $errorMsg) {
        # Determine recurring definitions (strict-ish, then fallback)
        $recurringDefinitions = @(
            $definitions | Where-Object {
                $_.settings -and $_.settings.recurrence -and (
                    $_.settings.recurrence.pattern -or
                    $_.settings.recurrence.range   -or
                    $_.settings.recurrence.type    -or
                    $_.settings.recurrence.interval
                )
            }
        )

        if ($recurringDefinitions.Count -eq 0) {
            $recurringDefinitions = @(
                $definitions | Where-Object { $_.settings -and $_.settings.recurrence }
            )
        }

        # OPTIONAL: sample instances (does not affect pass/fail)
        $maxInstanceChecks = 10
        $checked = 0

        foreach ($def in $definitions) {
            if ($checked -ge $maxInstanceChecks) { break }
            if (-not $def.id) { continue }

            try {
                $instUri  = "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/$($def.id)/instances"
                $instResp = Invoke-MgGraphRequest -Method GET -Uri $instUri -ErrorAction Stop
                $instances = if ($instResp -and $instResp.value) { @($instResp.value) } else { @() }

                $activeInstancesCount += @(
                    $instances | Where-Object { $_.status -in @('InProgress', 'NotStarted', 'Starting') }
                ).Count

                $checked++
            }
            catch {
                Write-PSFMessage ("Warning: failed to query instances for access review definition {0}: {1}" -f $def.id, $_.Exception.Message) -Level Warning
            }
        }

        $passed = ($recurringDefinitions.Count -gt 0)
    }

    # -----------------------------
    # Evidence markdown
    # -----------------------------
    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add("⚠️ Unable to determine access review configuration due to permissions issues, module mismatch, or query failure.")
        $lines.Add("")
        $lines.Add("**Details:** $errorMsg")
        $lines.Add("")
        $lines.Add("**Name resolution note:**")
        $lines.Add("- Enterprise app names require Graph permission to read service principals (e.g., Application.Read.All).")
        $lines.Add("- Directory role names require RoleManagement.Read.Directory or Directory.Read.All.")
        $lines.Add("")
    }
    else {
        if ($passed) {
            $lines.Add(("✅ {0} access review definition(s) are configured as recurring reviews." -f $recurringDefinitions.Count))
            if ($activeInstancesCount -gt 0) {
                $lines.Add(("✅ {0} active access review instance(s) were detected (sampled from first {1} definitions)." -f $activeInstancesCount, [Math]::Min($definitions.Count, 10)))
            }
            else {
                $lines.Add("ℹ️ No active access review instances were detected in the sampled definitions (this may be normal if reviews are scheduled but not currently running).")
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
        $lines.Add("| Metric | Count |")
        $lines.Add("|:---|---:|")
        $lines.Add(("| Total access review definitions | {0} |" -f $definitions.Count))
        $lines.Add(("| Recurring access review definitions | {0} |" -f $recurringDefinitions.Count))
        $lines.Add(("| Active access review instances (sampled) | {0} |" -f $activeInstancesCount))

        $methodText = if ($typedUsed) { "Graph SDK cmdlet" } else { "Graph REST (Invoke-MgGraphRequest)" }
        $lines.Add(("| Graph query method | {0} |" -f $methodText))
        $lines.Add("")

        if ($recurringDefinitions.Count -gt 0) {
            $lines.Add("### Recurring access reviews (sample)")
            $lines.Add("")
            $lines.Add("| Review Name | Scope (executive summary) |")
            $lines.Add("|:---|:---|")

            foreach ($d in ($recurringDefinitions | Select-Object -First 10)) {
                $name = Get-SafeMarkdown -Text ($d.displayName)
                $scopeSummary = Get-ZtScopeSummary -Scope $d.scope
                $scopeSummary = Get-SafeMarkdown -Text $scopeSummary

                $lines.Add(("| {0} | {1} |" -f $name, $scopeSummary))
            }

            $lines.Add("")
        }
    }

    $mdInfo = ($lines -join "`n")

    # ---- Optional: ensure the markdown description file exists (does not affect pass/fail) ----
    if (-not (Test-Path $mdPath)) {
        # Keep this as 'Investigate' if your process expects the description file to exist
        $customStatus = 'Investigate'
        Write-PSFMessage ("Missing markdown file: {0}" -f $mdPath) -Level Warning
    }

    # ---- Emit result (evidence-only; avoids repeating TestDescription) ----
    $params = @{
        TestId  = "$testId"
        Title   = $title
        Status  = $passed
        Result  = $mdInfo   # evidence block only
    }

    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }

    Add-ZtTestResultDetail @params

    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }

    Add-ZtTestResultDetail @params
}
