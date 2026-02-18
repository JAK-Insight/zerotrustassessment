# src\powershell\tests\Test-Assessment.35046.ps1

<#
.SYNOPSIS
    TLS enforcement is configured for Exchange Online
#>

function Test-Assessment-35046 {
    [ZtTest(
        Category = 'Encryption',
        ImplementationCost = 'Low',
        MinimumLicense = ('Microsoft 365 E3'),
        Pillar = 'Data',
        RiskLevel = 'Medium',
        SfiPillar = 'Protect networks',
        TenantType = ('Workforce'),
        TestId = 35046,
        Title = 'TLS enforcement is configured for Exchange Online',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking TLS enforcement for Exchange Online'
    Write-ZtProgress -Activity $activity -Status 'Getting outbound connectors'

    $errorMsg = $null
    $connectors = @()

    try {
        $connectors = Get-OutboundConnector -ErrorAction Stop
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage "Error querying outbound connectors: $_" -Level Error
    }
    #endregion Data Collection

    #region Assessment Logic
    $tlsConnectors = @()
    $nonTlsConnectors = @()
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine TLS enforcement status due to permissions issues or query failure.`n`n"
        $customStatus = 'Investigate'
    }
    else {
        foreach ($connector in $connectors) {
            if ($connector.Enabled -ne $true) { continue }

            if ($connector.TlsSettings -eq 'EncryptionOnly' -or
                $connector.TlsSettings -eq 'CertificateValidation' -or
                $connector.TlsSettings -eq 'DomainValidation') {
                $tlsConnectors += $connector
            }
            else {
                $nonTlsConnectors += $connector
            }
        }

        if ($tlsConnectors.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ $($tlsConnectors.Count) outbound connector(s) enforce TLS encryption for mail flow.`n`n%TestResult%"
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ No outbound connectors enforce TLS encryption. Exchange Online relies on opportunistic TLS which does not guarantee encryption if the receiving server doesn't support it.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    $enabledConnectors = $connectors | Where-Object { $_.Enabled -eq $true }
    if ($enabledConnectors.Count -gt 0) {
        $mdInfo += "`n`n### [Outbound Connectors](https://admin.exchange.microsoft.com/#/connectors)`n"
        $mdInfo += "| Connector Name | Enabled | TLS Settings | Recipient Domains |`n"
        $mdInfo += "| :--- | :--- | :--- | :--- |`n"

        foreach ($connector in $enabledConnectors) {
            $connectorName = Get-SafeMarkdown -Text $connector.Name
            $icon = if ($connector.TlsSettings -and $connector.TlsSettings -ne 'None') { '✅' } else { '⚠️' }
            $tlsDisplay = if ($connector.TlsSettings) { $connector.TlsSettings } else { 'Opportunistic (default)' }
            $domains = if ($connector.RecipientDomains) { ($connector.RecipientDomains -join ', ') } else { 'All' }
            $mdInfo += "| $icon $connectorName | $($connector.Enabled) | $tlsDisplay | $domains |`n"
        }
    }

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Total outbound connectors | $($connectors.Count) |`n"
    $mdInfo += "| Connectors enforcing TLS | $($tlsConnectors.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35046'
        Title  = 'TLS enforcement is configured for Exchange Online'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
