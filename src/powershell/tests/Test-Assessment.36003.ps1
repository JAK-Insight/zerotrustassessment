<#
.SYNOPSIS
 Storage accounts block public blob access
#>
function Test-Assessment-36003 {
    [ZtTest(
        Category = 'Data protection',
        ImplementationCost = 'Low',
        MinimumLicense = ('Free'),
        Pillar = 'Infrastructure',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 36003,
        Title = 'Storage accounts block public blob access',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 36003
    $title    = 'Storage accounts block public blob access'
    $activity = 'Checking storage account public blob access settings'
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

    Write-ZtProgress -Activity $activity -Status 'Querying storage accounts (Resource Graph)'

    $passed         = $false
    $errorMsg       = $null
    $customStatus   = $null
    $storageAccounts = @()

    # ------------------------------------------------------------------
    # 2. Query storage accounts via Resource Graph
    # ------------------------------------------------------------------
    try {
        $query = "Resources | where type == 'microsoft.storage/storageaccounts' | project name, resourceGroup, subscriptionId, allowPublicAccess = properties.allowBlobPublicAccess | order by name asc"
        $storageAccounts = @(Invoke-ZtAzureResourceGraphRequest -Query $query)
    }
    catch {
        $errorMsg     = $_.Exception.Message
        $customStatus = 'Investigate'
    }

    # ------------------------------------------------------------------
    # 3. Build evidence markdown
    # ------------------------------------------------------------------
    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add("Unable to retrieve storage account data.")
        $lines.Add("")
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add("")
        $lines.Add("Ensure the assessment account has **Reader** access to Azure subscriptions.")
    }
    elseif ($storageAccounts.Count -eq 0) {
        $passed = $true
        $lines.Add("No storage accounts found in accessible Azure subscriptions. This test passes when none are present.")
        $lines.Add("")
    }
    else {
        $failingAccounts = @($storageAccounts | Where-Object { $_.allowPublicAccess -eq $true })
        $passed = ($failingAccounts.Count -eq 0)

        if ($passed) {
            $lines.Add(("{0} storage account(s) evaluated. All block public blob access." -f $storageAccounts.Count))
        }
        else {
            $lines.Add(("{0} of {1} storage account(s) allow public blob access and must be remediated." -f $failingAccounts.Count, $storageAccounts.Count))
        }
        $lines.Add("")

        $lines.Add("### Storage Accounts")
        $lines.Add("")
        $lines.Add("| Storage Account | Resource Group | Public Blob Access |")
        $lines.Add("|:---|:---|:---:|")

        foreach ($sa in ($storageAccounts | Sort-Object name)) {
            $isPublic = ($sa.allowPublicAccess -eq $true)
            $icon     = if ($isPublic) { "❌ Allowed" } else { "✅ Blocked" }
            $lines.Add(("| {0} | {1} | {2} |" -f $sa.name, $sa.resourceGroup, $icon))
        }
        $lines.Add("")

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("| Metric | Count |")
        $lines.Add("|:---|---:|")
        $lines.Add(("| Total storage accounts | {0} |" -f $storageAccounts.Count))
        $lines.Add(("| Public blob access allowed | {0} |" -f $failingAccounts.Count))
        $lines.Add(("| Public blob access blocked | {0} |" -f ($storageAccounts.Count - $failingAccounts.Count)))
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
