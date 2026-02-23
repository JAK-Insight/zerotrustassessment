<#
.SYNOPSIS
 Just-In-Time VM access is configured for virtual machines
#>
function Test-Assessment-36007 {
    [ZtTest(
        Category = 'Privileged access',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Free'),
        Pillar = 'Infrastructure',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 36007,
        Title = 'Just-In-Time VM access is configured for virtual machines',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 36007
    $title    = 'Just-In-Time VM access is configured for virtual machines'
    $activity = 'Checking Just-In-Time VM access policies'
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

    Write-ZtProgress -Activity $activity -Status 'Querying virtual machines (Resource Graph)'

    $passed        = $false
    $errorMsg      = $null
    $customStatus  = $null
    $subResults    = [System.Collections.Generic.List[pscustomobject]]::new()

    # ------------------------------------------------------------------
    # 2. Get VM count per subscription via Resource Graph
    # ------------------------------------------------------------------
    $vmsBySubscription = @{}
    try {
        $vmQuery = "Resources | where type == 'microsoft.compute/virtualmachines' | summarize vmCount = count() by subscriptionId"
        $vmData  = @(Invoke-ZtAzureResourceGraphRequest -Query $vmQuery)
        foreach ($row in $vmData) {
            $vmsBySubscription[$row.subscriptionId] = [int]$row.vmCount
        }
    }
    catch {
        $errorMsg     = $_.Exception.Message
        $customStatus = 'Investigate'
    }

    # ------------------------------------------------------------------
    # 3. List accessible subscriptions and check JIT policies
    # ------------------------------------------------------------------
    if (-not $errorMsg) {
        Write-ZtProgress -Activity $activity -Status 'Getting Azure subscriptions'
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

        if (-not $errorMsg) {
            Write-ZtProgress -Activity $activity -Status 'Checking JIT policies'
            foreach ($sub in $subscriptions) {
                $vmCount   = if ($vmsBySubscription.ContainsKey($sub.subscriptionId)) { $vmsBySubscription[$sub.subscriptionId] } else { 0 }
                $jitCount  = 0
                $jitStatus = 'No VMs'

                if ($vmCount -gt 0) {
                    $jitUri = $rmUrl + "subscriptions/$($sub.subscriptionId)/providers/Microsoft.Security/jitNetworkAccessPolicies?api-version=2020-01-01"
                    try {
                        $jitResp = Invoke-AzRestMethod -Method GET -Uri $jitUri -ErrorAction Stop
                        if ($jitResp.StatusCode -eq 200) {
                            $jitPolicies = @(($jitResp.Content | ConvertFrom-Json).value)
                            $jitCount    = $jitPolicies.Count
                            $jitStatus   = if ($jitCount -gt 0) { 'Configured' } else { 'Not configured' }
                        }
                        elseif ($jitResp.StatusCode -eq 403) {
                            $jitStatus = 'Access denied'
                        }
                        elseif ($jitResp.StatusCode -eq 404) {
                            # Defender for Servers not enabled on this subscription
                            $jitStatus = 'Defender not enabled'
                        }
                    }
                    catch {
                        Write-PSFMessage "Failed to get JIT policies for $($sub.subscriptionId): $_" -Level Warning
                        $jitStatus = 'Error'
                    }
                }

                $subResults.Add([pscustomobject]@{
                    SubscriptionName = $sub.displayName
                    VmCount          = $vmCount
                    JitPolicies      = $jitCount
                    Status           = $jitStatus
                })
            }
        }
    }

    # ------------------------------------------------------------------
    # 4. Evaluate and build evidence markdown
    # ------------------------------------------------------------------
    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add("Unable to retrieve virtual machine or JIT policy data.")
        $lines.Add("")
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add("")
        $lines.Add("Ensure the assessment account has **Reader** and **Security Reader** access to Azure subscriptions.")
    }
    elseif ($subResults.Count -eq 0) {
        $lines.Add("No enabled Azure subscriptions found. This test requires at least one accessible Azure subscription.")
        $lines.Add("")
        $customStatus = 'Investigate'
    }
    else {
        $subsWithVms    = @($subResults | Where-Object { $_.VmCount -gt 0 })
        $subsWithoutJit = @($subsWithVms | Where-Object { $_.JitPolicies -eq 0 -and $_.Status -ne 'Access denied' })

        if ($subsWithVms.Count -eq 0) {
            $passed = $true
            $lines.Add("No virtual machines found in any accessible subscription. This test passes when no VMs are present.")
        }
        elseif ($subsWithoutJit.Count -eq 0) {
            $passed = $true
            $lines.Add(("All {0} subscription(s) with virtual machines have Just-In-Time access policies configured." -f $subsWithVms.Count))
        }
        else {
            $passed = $false
            $lines.Add(("{0} of {1} subscription(s) with virtual machines have no JIT access policies configured." -f $subsWithoutJit.Count, $subsWithVms.Count))
        }
        $lines.Add("")

        $lines.Add("### Subscriptions")
        $lines.Add("")
        $lines.Add("| Subscription | VMs | JIT Policies | Status |")
        $lines.Add("|:---|---:|---:|:---|")

        foreach ($result in ($subResults | Sort-Object SubscriptionName)) {
            $statusLabel = switch ($result.Status) {
                'Configured'           { 'Configured' }
                'No VMs'               { 'No VMs' }
                'Not configured'       { 'Not configured' }
                'Defender not enabled' { 'Defender for Servers not enabled' }
                'Access denied'        { 'Access denied' }
                default                { $result.Status }
            }
            $lines.Add(("| {0} | {1} | {2} | {3} |" -f $result.SubscriptionName, $result.VmCount, $result.JitPolicies, $statusLabel))
        }
        $lines.Add("")

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("| Metric | Count |")
        $lines.Add("|:---|---:|")
        $lines.Add(("| Subscriptions evaluated | {0} |" -f $subResults.Count))
        $lines.Add(("| Subscriptions with VMs | {0} |" -f $subsWithVms.Count))
        $lines.Add(("| Subscriptions with JIT configured | {0} |" -f ($subsWithVms.Count - $subsWithoutJit.Count)))
        $lines.Add(("| No JIT configured | {0} |" -f $subsWithoutJit.Count))
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
