<#
.SYNOPSIS
 Microsoft Cloud Security Benchmark policy initiative is assigned on Azure subscriptions
#>
function Test-Assessment-36008 {
    [ZtTest(
        Category = 'Monitoring',
        ImplementationCost = 'Low',
        MinimumLicense = ('Free'),
        Pillar = 'Infrastructure',
        RiskLevel = 'High',
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 36008,
        Title = 'Microsoft Cloud Security Benchmark policy initiative is assigned on Azure subscriptions',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 36008
    $title    = 'Microsoft Cloud Security Benchmark policy initiative is assigned on Azure subscriptions'
    $activity = 'Checking Microsoft Cloud Security Benchmark policy assignments'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    # Built-in policy set definition ID for Microsoft Cloud Security Benchmark (stable across tenants)
    $mcsbInitiativeId = '1f3afdf9-d0c9-4c3d-847f-89da613e70a8'

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

    Write-ZtProgress -Activity $activity -Status 'Getting Azure subscriptions'

    $passed        = $false
    $errorMsg      = $null
    $customStatus  = $null
    $subscriptions = @()
    $subResults    = [System.Collections.Generic.List[pscustomobject]]::new()

    # ------------------------------------------------------------------
    # 2. List accessible subscriptions
    # ------------------------------------------------------------------
    try {
        $rmUrl = (Get-AzContext).Environment.ResourceManagerUrl
        $subResponse = Invoke-AzRestMethod -Method GET -Uri ($rmUrl + 'subscriptions?api-version=2022-01-01') -ErrorAction Stop
        if ($subResponse.StatusCode -eq 200) {
            $subscriptions = @(($subResponse.Content | ConvertFrom-Json).value | Where-Object { $_.state -eq 'Enabled' })
        }
        else {
            $errorMsg     = "Subscription list returned HTTP $($subResponse.StatusCode)"
            $customStatus = 'Investigate'
        }
    }
    catch {
        $errorMsg     = $_.Exception.Message
        $customStatus = 'Investigate'
    }

    # ------------------------------------------------------------------
    # 3. Check policy assignments per subscription (atScope includes MG-inherited)
    # ------------------------------------------------------------------
    if (-not $errorMsg -and $subscriptions.Count -gt 0) {
        Write-ZtProgress -Activity $activity -Status 'Checking policy assignments'
        foreach ($sub in $subscriptions) {
            $policyUri = $rmUrl + "subscriptions/$($sub.subscriptionId)/providers/Microsoft.Authorization/policyAssignments?`$filter=atScope()&api-version=2022-06-01"
            $mcsbAssignment = $null

            try {
                $policyResp = Invoke-AzRestMethod -Method GET -Uri $policyUri -ErrorAction Stop
                if ($policyResp.StatusCode -eq 200) {
                    $assignments = @(($policyResp.Content | ConvertFrom-Json).value)
                    $mcsbAssignment = $assignments | Where-Object {
                        $_.properties.policyDefinitionId -like "*$mcsbInitiativeId*"
                    } | Select-Object -First 1
                }
                elseif ($policyResp.StatusCode -eq 403) {
                    $subResults.Add([pscustomobject]@{
                        SubscriptionName = $sub.displayName
                        AssignmentName   = '(access denied)'
                        Scope            = 'N/A'
                        EnforcementMode  = 'N/A'
                        HasMcsb          = $false
                    })
                    continue
                }
            }
            catch {
                Write-PSFMessage "Failed to get policy assignments for $($sub.subscriptionId): $_" -Level Warning
            }

            if ($mcsbAssignment) {
                $scope = $mcsbAssignment.properties.scope
                $scopeLabel = if ($scope -like '*/providers/Microsoft.Management/managementGroups/*') {
                    "Management Group"
                } elseif ($scope -like '*/subscriptions/*') {
                    "Subscription"
                } else {
                    $scope
                }
                $subResults.Add([pscustomobject]@{
                    SubscriptionName = $sub.displayName
                    AssignmentName   = $mcsbAssignment.properties.displayName
                    Scope            = $scopeLabel
                    EnforcementMode  = $mcsbAssignment.properties.enforcementMode
                    HasMcsb          = $true
                })
            }
            else {
                $subResults.Add([pscustomobject]@{
                    SubscriptionName = $sub.displayName
                    AssignmentName   = 'Not assigned'
                    Scope            = 'N/A'
                    EnforcementMode  = 'N/A'
                    HasMcsb          = $false
                })
            }
        }
    }

    # ------------------------------------------------------------------
    # 4. Evaluate and build evidence markdown
    # ------------------------------------------------------------------
    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add("Unable to retrieve Azure subscription or policy assignment data.")
        $lines.Add("")
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add("")
        $lines.Add("Ensure the assessment account has **Reader** access to Azure subscriptions.")
    }
    elseif ($subscriptions.Count -eq 0) {
        $lines.Add("No enabled Azure subscriptions found. This test requires at least one accessible Azure subscription.")
        $lines.Add("")
        $customStatus = 'Investigate'
    }
    else {
        $failingSubs = @($subResults | Where-Object { -not $_.HasMcsb })
        $passed = ($failingSubs.Count -eq 0)

        if ($passed) {
            $lines.Add(("All {0} subscription(s) have the Microsoft Cloud Security Benchmark initiative assigned." -f $subscriptions.Count))
        }
        else {
            $lines.Add(("{0} of {1} subscription(s) do not have the Microsoft Cloud Security Benchmark initiative assigned." -f $failingSubs.Count, $subscriptions.Count))
        }
        $lines.Add("")

        $lines.Add("### Subscriptions")
        $lines.Add("")
        $lines.Add("| Subscription | MCSB Assignment | Scope | Enforcement Mode | Status |")
        $lines.Add("|:---|:---|:---|:---:|:---:|")

        foreach ($result in ($subResults | Sort-Object SubscriptionName)) {
            $status = if ($result.HasMcsb) { "Pass" } else { "Fail" }
            $lines.Add(("| {0} | {1} | {2} | {3} | {4} |" -f $result.SubscriptionName, $result.AssignmentName, $result.Scope, $result.EnforcementMode, $status))
        }
        $lines.Add("")

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("| Metric | Count |")
        $lines.Add("|:---|---:|")
        $lines.Add(("| Subscriptions evaluated | {0} |" -f $subscriptions.Count))
        $lines.Add(("| MCSB assigned | {0} |" -f ($subResults.Count - $failingSubs.Count)))
        $lines.Add(("| MCSB not assigned | {0} |" -f $failingSubs.Count))
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
