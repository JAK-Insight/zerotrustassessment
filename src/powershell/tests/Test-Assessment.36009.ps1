<#
.SYNOPSIS
 Log Analytics workspaces retain data for at least 90 days
#>
function Test-Assessment-36009 {
    [ZtTest(
        Category = 'Monitoring',
        ImplementationCost = 'Low',
        MinimumLicense = ('Free'),
        Pillar = 'Infrastructure',
        RiskLevel = 'Medium',
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 36009,
        Title = 'Log Analytics workspaces retain data for at least 90 days',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 36009
    $title    = 'Log Analytics workspaces retain data for at least 90 days'
    $activity = 'Checking Log Analytics workspace retention settings'
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

    Write-ZtProgress -Activity $activity -Status 'Querying Log Analytics workspaces (Resource Graph)'

    $passed       = $false
    $errorMsg     = $null
    $customStatus = $null
    $workspaces   = @()

    # ------------------------------------------------------------------
    # 2. Query Log Analytics workspaces via Resource Graph
    # ------------------------------------------------------------------
    try {
        $query = "Resources | where type == 'microsoft.operationalinsights/workspaces' | project name, resourceGroup, subscriptionId, retentionInDays = properties.retentionInDays | order by name asc"
        $workspaces = @(Invoke-ZtAzureResourceGraphRequest -Query $query)
    }
    catch {
        $errorMsg     = $_.Exception.Message
        $customStatus = 'Investigate'
    }

    # ------------------------------------------------------------------
    # 3. Evaluate and build evidence markdown
    # ------------------------------------------------------------------
    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add("Unable to retrieve Log Analytics workspace data.")
        $lines.Add("")
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add("")
        $lines.Add("Ensure the assessment account has **Reader** access to Azure subscriptions.")
    }
    elseif ($workspaces.Count -eq 0) {
        $passed = $true
        $lines.Add("No Log Analytics workspaces found in accessible Azure subscriptions. This test passes when none are present.")
        $lines.Add("")
    }
    else {
        $failingWorkspaces = @($workspaces | Where-Object { [int]$_.retentionInDays -lt 90 })
        $passed = ($failingWorkspaces.Count -eq 0)

        if ($passed) {
            $lines.Add(("{0} Log Analytics workspace(s) evaluated. All have a retention period of at least 90 days." -f $workspaces.Count))
        }
        else {
            $lines.Add(("{0} of {1} Log Analytics workspace(s) have a retention period below 90 days." -f $failingWorkspaces.Count, $workspaces.Count))
        }
        $lines.Add("")

        $lines.Add("### Log Analytics Workspaces")
        $lines.Add("")
        $lines.Add("| Workspace | Resource Group | Retention (days) | Status |")
        $lines.Add("|:---|:---|---:|:---:|")

        foreach ($ws in ($workspaces | Sort-Object name)) {
            $days   = [int]$ws.retentionInDays
            $status = if ($days -ge 90) { "Pass" } else { "Fail" }
            $lines.Add(("| {0} | {1} | {2} | {3} |" -f $ws.name, $ws.resourceGroup, $days, $status))
        }
        $lines.Add("")

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("| Metric | Count |")
        $lines.Add("|:---|---:|")
        $lines.Add(("| Total workspaces | {0} |" -f $workspaces.Count))
        $lines.Add(("| Retention >= 90 days | {0} |" -f ($workspaces.Count - $failingWorkspaces.Count)))
        $lines.Add(("| Retention < 90 days | {0} |" -f $failingWorkspaces.Count))
        $lines.Add("")
    }

    $mdInfo = ($lines -join "`n")

    # ------------------------------------------------------------------
    # 4. Emit result
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
