<#
.SYNOPSIS
 Azure subscriptions have no permanent Owner role assignments to individual users
#>
function Test-Assessment-36002 {
    [ZtTest(
        Category = 'Privileged access',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Free'),
        Pillar = 'Infrastructure',
        RiskLevel = 'High',
        SfiPillar = 'Protect identities and secrets',
        TenantType = ('Workforce'),
        TestId = 36002,
        Title = 'Azure subscriptions have no permanent Owner role assignments to individual users',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 36002
    $title    = 'Azure subscriptions have no permanent Owner role assignments to individual users'
    $activity = 'Checking Azure subscription Owner role assignments'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    # ------------------------------------------------------------------
    # 1. Check Azure connection
    # ------------------------------------------------------------------
    try {
        $accessToken = Get-AzAccessToken -AsSecureString -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    catch [Management.Automation.CommandNotFoundException] {
        Write-PSFMessage $_.Exception.Message -Tag Test -Level Error
    }

    if (!$accessToken) {
        Add-ZtTestResultDetail -SkippedBecause NotConnectedAzure
        return
    }

    Write-ZtProgress -Activity $activity -Status 'Querying Owner role assignments (Resource Graph)'

    $passed         = $false
    $errorMsg       = $null
    $customStatus   = $null
    $ownerAssignments = @()

    # Owner built-in role definition GUID (same across all Azure environments)
    $ownerRoleGuid = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'

    # ------------------------------------------------------------------
    # 2. Query Owner role assignments on subscriptions via Resource Graph
    # ------------------------------------------------------------------
    try {
        $query = @"
authorizationresources
| where type == 'microsoft.authorization/roleassignments'
| extend principalType    = tostring(properties.principalType)
| extend roleDefinitionId = tostring(properties.roleDefinitionId)
| extend scope            = tostring(properties.scope)
| extend principalId      = tostring(properties.principalId)
| where roleDefinitionId contains '$ownerRoleGuid'
| where principalType == 'User'
| where scope matches regex '^/subscriptions/[^/]+$'
| project principalId, principalType, scope, subscriptionId
"@
        $ownerAssignments = @(Invoke-ZtAzureResourceGraphRequest -Query $query)
    }
    catch {
        $errorMsg     = $_.Exception.Message
        $customStatus = 'Investigate'
    }

    # ------------------------------------------------------------------
    # 3. Resolve principal display names via Graph (best-effort)
    # ------------------------------------------------------------------
    $resolvedPrincipals = @{}
    if (-not $errorMsg -and $ownerAssignments.Count -gt 0) {
        $uniquePrincipalIds = @($ownerAssignments | Select-Object -ExpandProperty principalId -Unique)
        foreach ($pid in $uniquePrincipalIds) {
            try {
                $obj = Invoke-ZtGraphRequest -RelativeUri "users/$pid" -ApiVersion 'v1.0' -ErrorAction SilentlyContinue
                if ($obj) {
                    $resolvedPrincipals[$pid] = if ($obj.userPrincipalName) { $obj.userPrincipalName } else { $obj.displayName }
                }
            }
            catch {
                # Principal may be a guest or not accessible; fall back to ID
            }
            if (-not $resolvedPrincipals.ContainsKey($pid)) {
                $resolvedPrincipals[$pid] = $pid
            }
        }
    }

    # ------------------------------------------------------------------
    # 4. Resolve subscription names
    # ------------------------------------------------------------------
    $subscriptionNames = @{}
    if (-not $errorMsg -and $ownerAssignments.Count -gt 0) {
        $uniqueSubIds = @($ownerAssignments | Select-Object -ExpandProperty subscriptionId -Unique)
        foreach ($sid in $uniqueSubIds) {
            try {
                $rmUrl = (Get-AzContext).Environment.ResourceManagerUrl
                $subResponse = Invoke-AzRestMethod -Method GET -Uri ($rmUrl + "subscriptions/$sid`?api-version=2022-01-01") -ErrorAction SilentlyContinue
                if ($subResponse -and $subResponse.StatusCode -eq 200) {
                    $subObj = ($subResponse.Content | ConvertFrom-Json)
                    $subscriptionNames[$sid] = $subObj.displayName
                }
            }
            catch { }
            if (-not $subscriptionNames.ContainsKey($sid)) {
                $subscriptionNames[$sid] = $sid
            }
        }
    }

    # ------------------------------------------------------------------
    # 5. Build evidence markdown
    # ------------------------------------------------------------------
    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add("Unable to retrieve Azure role assignment data.")
        $lines.Add("")
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add("")
        $lines.Add("Ensure the assessment account has **Reader** access to Azure subscriptions and the **authorizationresources** Resource Graph table is accessible.")
    }
    else {
        if ($ownerAssignments.Count -eq 0) {
            $passed = $true
            $lines.Add("No individual users have a permanent Owner role assignment on any Azure subscription. Owner access is appropriately controlled via groups or Privileged Identity Management.")
        }
        else {
            $passed = $false
            $lines.Add(("{0} user(s) have a permanent Owner role assignment on Azure subscription(s). These should be converted to eligible PIM assignments or reassigned to groups." -f $ownerAssignments.Count))
        }
        $lines.Add("")

        if ($ownerAssignments.Count -gt 0) {
            $lines.Add("### Permanent Owner Assignments")
            $lines.Add("")
            $lines.Add("| User | Subscription |")
            $lines.Add("|:---|:---|")

            foreach ($assignment in ($ownerAssignments | Sort-Object principalId)) {
                $displayName = $resolvedPrincipals[$assignment.principalId]
                $subName     = $subscriptionNames[$assignment.subscriptionId]
                $lines.Add(("| {0} | {1} |" -f $displayName, $subName))
            }
            $lines.Add("")
        }

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("| Metric | Count |")
        $lines.Add("|:---|---:|")
        $lines.Add(("| Users with permanent Owner on a subscription | {0} |" -f $ownerAssignments.Count))
        $lines.Add("")
    }

    $mdInfo = ($lines -join "`n")

    # ------------------------------------------------------------------
    # 6. Emit result
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
