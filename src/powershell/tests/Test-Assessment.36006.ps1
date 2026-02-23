<#
.SYNOPSIS
 Azure subscription activity logs are forwarded to a Log Analytics workspace
#>
function Test-Assessment-36006 {
    [ZtTest(
        Category = 'Monitoring',
        ImplementationCost = 'Low',
        MinimumLicense = ('Free'),
        Pillar = 'Infrastructure',
        RiskLevel = 'High',
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 36006,
        Title = 'Azure subscription activity logs are forwarded to a Log Analytics workspace',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 36006
    $title    = 'Azure subscription activity logs are forwarded to a Log Analytics workspace'
    $activity = 'Checking subscription activity log diagnostic settings'
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
    # 3. Check diagnostic settings per subscription
    # ------------------------------------------------------------------
    if (-not $errorMsg -and $subscriptions.Count -gt 0) {
        Write-ZtProgress -Activity $activity -Status 'Checking diagnostic settings'
        foreach ($sub in $subscriptions) {
            $diagUri         = $rmUrl + "subscriptions/$($sub.subscriptionId)/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
            $hasWorkspace    = $false
            $enabledLogCount = 0

            try {
                $diagResp = Invoke-AzRestMethod -Method GET -Uri $diagUri -ErrorAction Stop
                if ($diagResp.StatusCode -eq 200) {
                    $settings = @(($diagResp.Content | ConvertFrom-Json).value)
                    foreach ($setting in $settings) {
                        if ($setting.properties.workspaceId) {
                            $hasWorkspace    = $true
                            $enabledLogCount = @($setting.properties.logs | Where-Object { $_.enabled -eq $true }).Count
                            break
                        }
                    }
                }
                elseif ($diagResp.StatusCode -eq 403) {
                    $hasWorkspace    = $false
                    $enabledLogCount = -1  # Signals access denied
                }
            }
            catch {
                Write-PSFMessage "Failed to get diagnostic settings for $($sub.subscriptionId): $_" -Level Warning
            }

            $subResults.Add([pscustomobject]@{
                SubscriptionId   = $sub.subscriptionId
                SubscriptionName = $sub.displayName
                HasWorkspace     = $hasWorkspace
                EnabledLogs      = $enabledLogCount
            })
        }
    }

    # ------------------------------------------------------------------
    # 4. Evaluate and build evidence markdown
    # ------------------------------------------------------------------
    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add("Unable to retrieve Azure subscription or diagnostic settings data.")
        $lines.Add("")
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add("")
        $lines.Add("Ensure the assessment account has **Reader** and **Monitoring Reader** access to Azure subscriptions.")
    }
    elseif ($subscriptions.Count -eq 0) {
        $lines.Add("No enabled Azure subscriptions found. This test requires at least one accessible Azure subscription.")
        $lines.Add("")
        $customStatus = 'Investigate'
    }
    else {
        $failingSubs = @($subResults | Where-Object { -not $_.HasWorkspace -or $_.EnabledLogs -le 0 })
        $passed = ($failingSubs.Count -eq 0)

        if ($passed) {
            $lines.Add(("All {0} subscription(s) forward activity logs to a Log Analytics workspace." -f $subscriptions.Count))
        }
        else {
            $lines.Add(("{0} of {1} subscription(s) are not forwarding activity logs to a Log Analytics workspace." -f $failingSubs.Count, $subscriptions.Count))
        }
        $lines.Add("")

        $lines.Add("### Subscriptions")
        $lines.Add("")
        $lines.Add("| Subscription | Workspace Configured | Log Categories Enabled | Status |")
        $lines.Add("|:---|:---:|---:|:---:|")

        foreach ($result in ($subResults | Sort-Object SubscriptionName)) {
            $wsIcon  = if ($result.HasWorkspace) { "Yes" } else { "No" }
            $logText = if ($result.EnabledLogs -eq -1) { "(access denied)" } elseif ($result.HasWorkspace) { "$($result.EnabledLogs)" } else { "N/A" }
            $status  = if ($result.HasWorkspace -and $result.EnabledLogs -gt 0) { "Pass" } else { "Fail" }
            $lines.Add(("| {0} | {1} | {2} | {3} |" -f $result.SubscriptionName, $wsIcon, $logText, $status))
        }
        $lines.Add("")

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("| Metric | Count |")
        $lines.Add("|:---|---:|")
        $lines.Add(("| Subscriptions evaluated | {0} |" -f $subscriptions.Count))
        $lines.Add(("| Forwarding to Log Analytics | {0} |" -f ($subResults.Count - $failingSubs.Count)))
        $lines.Add(("| Not configured | {0} |" -f $failingSubs.Count))
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
