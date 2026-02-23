<#
.SYNOPSIS
 Storage accounts enforce HTTPS-only traffic and minimum TLS 1.2
#>
function Test-Assessment-36004 {
    [ZtTest(
        Category = 'Encryption',
        ImplementationCost = 'Low',
        MinimumLicense = ('Free'),
        Pillar = 'Infrastructure',
        RiskLevel = 'Medium',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 36004,
        Title = 'Storage accounts enforce HTTPS-only traffic and minimum TLS 1.2',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 36004
    $title    = 'Storage accounts enforce HTTPS-only traffic and minimum TLS 1.2'
    $activity = 'Checking storage account transport security settings'
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
        $query = "Resources | where type == 'microsoft.storage/storageaccounts' | project name, resourceGroup, subscriptionId, httpsOnly = properties.supportsHttpsTrafficOnly, minTls = properties.minimumTlsVersion | order by name asc"
        $storageAccounts = @(Invoke-ZtAzureResourceGraphRequest -Query $query)
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
        $acceptableTlsVersions = @('TLS1_2', 'TLS1_3')
        $failingAccounts = @($storageAccounts | Where-Object {
            ($_.httpsOnly -ne $true) -or ([string]$_.minTls -notin $acceptableTlsVersions)
        })
        $passed = ($failingAccounts.Count -eq 0)

        if ($passed) {
            $lines.Add(("{0} storage account(s) evaluated. All enforce HTTPS-only traffic and TLS 1.2 or higher." -f $storageAccounts.Count))
        }
        else {
            $lines.Add(("{0} of {1} storage account(s) do not meet transport security requirements." -f $failingAccounts.Count, $storageAccounts.Count))
        }
        $lines.Add("")

        $lines.Add("### Storage Accounts")
        $lines.Add("")
        $lines.Add("| Storage Account | Resource Group | HTTPS Only | Min TLS Version |")
        $lines.Add("|:---|:---|:---:|:---:|")

        foreach ($sa in ($storageAccounts | Sort-Object name)) {
            $tlsVersion  = if ($sa.minTls) { [string]$sa.minTls -replace 'TLS1_', 'TLS 1.' } else { 'Not set' }
            $httpsOk     = ($sa.httpsOnly -eq $true)
            $tlsOk       = ([string]$sa.minTls -in $acceptableTlsVersions)
            $httpsIcon   = if ($httpsOk) { "✅" } else { "❌" }
            $tlsIcon     = if ($tlsOk) { "✅" } else { "❌" }
            $lines.Add(("| {0} | {1} | {2} | {3} {4} |" -f $sa.name, $sa.resourceGroup, $httpsIcon, $tlsIcon, $tlsVersion))
        }
        $lines.Add("")

        $httpsFailCount = ($storageAccounts | Where-Object { $_.httpsOnly -ne $true }).Count
        $tlsFailCount   = ($storageAccounts | Where-Object { [string]$_.minTls -notin $acceptableTlsVersions }).Count

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("| Metric | Count |")
        $lines.Add("|:---|---:|")
        $lines.Add(("| Total storage accounts | {0} |" -f $storageAccounts.Count))
        $lines.Add(("| HTTPS-only not enforced | {0} |" -f $httpsFailCount))
        $lines.Add(("| TLS below 1.2 | {0} |" -f $tlsFailCount))
        $lines.Add(("| Fully compliant | {0} |" -f ($storageAccounts.Count - $failingAccounts.Count)))
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
