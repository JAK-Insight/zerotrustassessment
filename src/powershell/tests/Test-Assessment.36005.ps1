<#
.SYNOPSIS
 Key Vaults have soft delete and purge protection enabled
#>
function Test-Assessment-36005 {
    [ZtTest(
        Category = 'Data protection',
        ImplementationCost = 'Low',
        MinimumLicense = ('Free'),
        Pillar = 'Infrastructure',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 36005,
        Title = 'Key Vaults have soft delete and purge protection enabled',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 36005
    $title    = 'Key Vaults have soft delete and purge protection enabled'
    $activity = 'Checking Key Vault soft delete and purge protection settings'
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

    Write-ZtProgress -Activity $activity -Status 'Querying Key Vaults (Resource Graph)'

    $passed       = $false
    $errorMsg     = $null
    $customStatus = $null
    $keyVaults    = @()

    # ------------------------------------------------------------------
    # 2. Query Key Vaults via Resource Graph
    # ------------------------------------------------------------------
    try {
        $query = "Resources | where type == 'microsoft.keyvault/vaults' | project name, resourceGroup, subscriptionId, softDelete = properties.enableSoftDelete, purgeProtection = properties.enablePurgeProtection | order by name asc"
        $keyVaults = @(Invoke-ZtAzureResourceGraphRequest -Query $query)
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
        $lines.Add("Unable to retrieve Key Vault data.")
        $lines.Add("")
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add("")
        $lines.Add("Ensure the assessment account has **Reader** access to Azure subscriptions.")
    }
    elseif ($keyVaults.Count -eq 0) {
        $passed = $true
        $lines.Add("No Key Vaults found in accessible Azure subscriptions. This test passes when none are present.")
        $lines.Add("")
    }
    else {
        $failingVaults = @($keyVaults | Where-Object {
            ($_.softDelete -ne $true) -or ($_.purgeProtection -ne $true)
        })
        $passed = ($failingVaults.Count -eq 0)

        if ($passed) {
            $lines.Add(("{0} Key Vault(s) evaluated. All have soft delete and purge protection enabled." -f $keyVaults.Count))
        }
        else {
            $lines.Add(("{0} of {1} Key Vault(s) are missing soft delete or purge protection." -f $failingVaults.Count, $keyVaults.Count))
        }
        $lines.Add("")

        $lines.Add("### Key Vaults")
        $lines.Add("")
        $lines.Add("| Key Vault | Resource Group | Soft Delete | Purge Protection |")
        $lines.Add("|:---|:---|:---:|:---:|")

        foreach ($kv in ($keyVaults | Sort-Object name)) {
            $sdIcon = if ($kv.softDelete -eq $true) { "✅" } else { "❌" }
            $ppIcon = if ($kv.purgeProtection -eq $true) { "✅" } else { "❌" }
            $lines.Add(("| {0} | {1} | {2} | {3} |" -f $kv.name, $kv.resourceGroup, $sdIcon, $ppIcon))
        }
        $lines.Add("")

        $noSoftDelete      = ($keyVaults | Where-Object { $_.softDelete -ne $true }).Count
        $noPurgeProtection = ($keyVaults | Where-Object { $_.purgeProtection -ne $true }).Count

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("| Metric | Count |")
        $lines.Add("|:---|---:|")
        $lines.Add(("| Total Key Vaults | {0} |" -f $keyVaults.Count))
        $lines.Add(("| Soft delete not enabled | {0} |" -f $noSoftDelete))
        $lines.Add(("| Purge protection not enabled | {0} |" -f $noPurgeProtection))
        $lines.Add(("| Fully protected | {0} |" -f ($keyVaults.Count - $failingVaults.Count)))
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
