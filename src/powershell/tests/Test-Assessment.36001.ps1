<#
.SYNOPSIS
 Microsoft Defender for Cloud is enabled on Azure subscriptions
#>
function Test-Assessment-36001 {
    [ZtTest(
        Category = 'Threat protection',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Free'),
        Pillar = 'Infrastructure',
        RiskLevel = 'High',
        SfiPillar = 'Monitor and detect cyberthreats',
        TenantType = ('Workforce'),
        TestId = 36001,
        Title = 'Microsoft Defender for Cloud is enabled on Azure subscriptions',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 36001
    $title    = 'Microsoft Defender for Cloud is enabled on Azure subscriptions'
    $activity = 'Checking Microsoft Defender for Cloud plans'
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

    $passed         = $false
    $errorMsg       = $null
    $customStatus   = $null
    $subscriptions  = @()
    $allPricingData = [System.Collections.Generic.List[pscustomobject]]::new()

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
    # 3. Query Defender for Cloud pricing per subscription
    # ------------------------------------------------------------------
    if (-not $errorMsg -and $subscriptions.Count -gt 0) {
        Write-ZtProgress -Activity $activity -Status 'Getting Defender for Cloud plans'
        foreach ($sub in $subscriptions) {
            try {
                $pricingUri  = $rmUrl + "subscriptions/$($sub.subscriptionId)/providers/Microsoft.Security/pricings?api-version=2024-01-01"
                $pricingResp = Invoke-AzRestMethod -Method GET -Uri $pricingUri -ErrorAction Stop
                if ($pricingResp.StatusCode -eq 200) {
                    $plans = @(($pricingResp.Content | ConvertFrom-Json).value)
                    foreach ($plan in $plans) {
                        $allPricingData.Add([pscustomobject]@{
                            SubscriptionId   = $sub.subscriptionId
                            SubscriptionName = $sub.displayName
                            PlanName         = $plan.name
                            PricingTier      = $plan.properties.pricingTier
                        })
                    }
                }
                elseif ($pricingResp.StatusCode -eq 403) {
                    $allPricingData.Add([pscustomobject]@{
                        SubscriptionId   = $sub.subscriptionId
                        SubscriptionName = $sub.displayName
                        PlanName         = '(access denied)'
                        PricingTier      = 'Unknown'
                    })
                }
            }
            catch {
                Write-PSFMessage "Failed to get Defender pricings for subscription $($sub.subscriptionId): $_" -Level Warning
            }
        }
    }

    # ------------------------------------------------------------------
    # 4. Evaluate
    # ------------------------------------------------------------------
    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add("Unable to retrieve Azure subscription or Defender for Cloud data.")
        $lines.Add("")
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add("")
        $lines.Add("Ensure the assessment account has **Reader** and **Security Reader** access to Azure subscriptions.")
    }
    elseif ($subscriptions.Count -eq 0) {
        $lines.Add("No enabled Azure subscriptions found. This test requires at least one accessible Azure subscription.")
        $lines.Add("")
        $customStatus = 'Investigate'
    }
    else {
        $paidPlans = @($allPricingData | Where-Object { $_.PricingTier -eq 'Standard' })
        $passed    = ($paidPlans.Count -gt 0)

        if ($passed) {
            $lines.Add(("{0} paid Defender for Cloud plan(s) are enabled across {1} subscription(s)." -f $paidPlans.Count, $subscriptions.Count))
        }
        else {
            $lines.Add(("All Defender for Cloud plans are on the Free tier across {0} subscription(s). Enable paid Defender plans to gain threat protection and security posture management." -f $subscriptions.Count))
        }
        $lines.Add("")

        # Table grouped by subscription
        $subGroups = $allPricingData | Group-Object SubscriptionName | Sort-Object Name
        foreach ($group in $subGroups) {
            $lines.Add(("### {0}" -f $group.Name))
            $lines.Add("")
            $lines.Add("| Defender Plan | Tier |")
            $lines.Add("|:---|:---:|")
            foreach ($plan in ($group.Group | Sort-Object PlanName)) {
                $tier = $plan.PricingTier
                $icon = if ($tier -eq 'Standard') { "✅ Standard" } elseif ($tier -eq 'Free') { "❌ Free" } else { "⚠️ $tier" }
                $lines.Add(("| {0} | {1} |" -f $plan.PlanName, $icon))
            }
            $lines.Add("")
        }

        $totalPlans     = $allPricingData.Count
        $freePlansCount = ($allPricingData | Where-Object { $_.PricingTier -eq 'Free' }).Count

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("| Metric | Count |")
        $lines.Add("|:---|---:|")
        $lines.Add(("| Subscriptions evaluated | {0} |" -f $subscriptions.Count))
        $lines.Add(("| Total Defender plans | {0} |" -f $totalPlans))
        $lines.Add(("| Plans on Standard (paid) tier | {0} |" -f $paidPlans.Count))
        $lines.Add(("| Plans on Free tier | {0} |" -f $freePlansCount))
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
