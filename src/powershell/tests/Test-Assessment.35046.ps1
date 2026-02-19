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

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35046
    $title    = 'TLS enforcement is configured for Exchange Online'
    $activity = 'Checking TLS enforcement for Exchange Online'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    #region Data Collection
    Write-ZtProgress -Activity $activity -Status 'Getting outbound connectors'

    $errorMsg = $null
    $connectors = @()

    if (-not (Get-Command Get-OutboundConnector -ErrorAction SilentlyContinue)) {
        $errorMsg = "Get-OutboundConnector cmdlet not found. Ensure Exchange Online session is connected (Connect-ExchangeOnline / Connect-ZtAssessment -Service ExchangeOnline)."
        Write-PSFMessage $errorMsg -Level Warning
    }
    else {
        try {
            $connectors = @(Get-OutboundConnector -ErrorAction Stop)
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-PSFMessage ("Error querying outbound connectors: {0}" -f $_) -Level Error
        }
    }
    #endregion Data Collection

    #region Assessment Logic
    $tlsConnectors    = New-Object System.Collections.Generic.List[object]
    $nonTlsConnectors = New-Object System.Collections.Generic.List[object]

    $passed = $false
    $customStatus = $null
    $leadText = ''

    if ($errorMsg) {
        $customStatus = 'Investigate'
        $leadText = "⚠️ Unable to determine TLS enforcement status due to permissions issues or query failure.`n`n**Details:** $errorMsg`n"
    }
    else {
        foreach ($connector in $connectors) {
            # Only consider enabled connectors (matches your current behavior). [1](https://insightonline-my.sharepoint.com/personal/joshua_kaye_insight_com/Documents/Microsoft%20Copilot%20Chat%20Files/Test-Assessment.35046.ps1.txt)
            if ($connector.Enabled -ne $true) { continue }

            if ($connector.TlsSettings -in @('EncryptionOnly', 'CertificateValidation', 'DomainValidation')) {
                $tlsConnectors.Add($connector)
            }
            else {
                $nonTlsConnectors.Add($connector)
            }
        }

        if ($tlsConnectors.Count -gt 0) {
            $passed = $true
            $leadText = "✅ $($tlsConnectors.Count) outbound connector(s) enforce TLS encryption for mail flow.`n"
        }
        else {
            $passed = $false
            $leadText = "❌ No outbound connectors enforce TLS encryption. Exchange Online relies on opportunistic TLS which does not guarantee encryption if the receiving server doesn't support it.`n"
        }
    }
    #endregion Assessment Logic

    #region Evidence Markdown
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if (-not $errorMsg) {
        $enabledConnectors = @($connectors | Where-Object { $_.Enabled -eq $true })

        if ($enabledConnectors.Count -gt 0) {
            $lines.Add("### Outbound Connectors")
            $lines.Add("")
            $lines.Add("Connector Name | Enabled | TLS Settings | Recipient Domains")
            $lines.Add(":---|:---:|:---|:---")

            # Sort: TLS-enforcing first, then others; stable by name
            $sorted = $enabledConnectors | Sort-Object @{
                Expression = {
                    if ($_.TlsSettings -in @('EncryptionOnly','CertificateValidation','DomainValidation')) { 0 } else { 1 }
                }
            }, @{
                Expression = { $_.Name }
            }

            foreach ($connector in $sorted) {
                $connectorName = Get-SafeMarkdown -Text $connector.Name

                $icon = if ($connector.TlsSettings -and $connector.TlsSettings -ne 'None') { '✅' } else { '⚠️' }
                $tlsDisplay = if ($connector.TlsSettings) { $connector.TlsSettings } else { 'Opportunistic (default)' }

                $domains = if ($connector.RecipientDomains -and $connector.RecipientDomains.Count -gt 0) {
                    ($connector.RecipientDomains -join ', ')
                }
                else { 'All' }

                $domains = Get-SafeMarkdown -Text $domains

                $lines.Add(("$icon $connectorName | $($connector.Enabled) | $tlsDisplay | $domains"))
            }

            $lines.Add("")
        }

        $lines.Add("### Summary")
        $lines.Add("")
        $lines.Add("Metric | Count")
        $lines.Add(":---|---:")
        $lines.Add(("Total outbound connectors | {0}" -f $connectors.Count))
        $lines.Add(("Connectors enforcing TLS | {0}" -f $tlsConnectors.Count))
    }

    $mdInfo = ($lines -join "`n")
    #endregion Evidence Markdown

    #region Load MD and Inject Evidence
    $resultMarkdown = $null

    if (Test-Path $mdPath) {
        $baseMd = Get-Content -Path $mdPath -Raw
        if ($baseMd -match '%TestResult%') {
            $resultMarkdown = $baseMd -replace '%TestResult%', $mdInfo
        }
        else {
            $resultMarkdown = $baseMd + "`n`n<!--- Results (auto-appended; missing %TestResult% token) --->`n" + $mdInfo
            $customStatus = 'Investigate'
        }
    }
    else {
        $resultMarkdown = "⚠️ Missing markdown file: $mdPath`n`n$mdInfo"
        $customStatus = 'Investigate'
    }
    #endregion Load MD and Inject Evidence

    #region Output
    $params = @{
        TestId = "$testId"
        Title  = $title
        Status = $passed
        Result = $resultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }

    Add-ZtTestResultDetail @params
    #endregion Output
}
