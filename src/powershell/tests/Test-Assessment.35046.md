Transport Layer Security (TLS) helps protect email in transit by encrypting the connection between Exchange Online and external mail systems. Without TLS enforcement, mail flow may rely on opportunistic TLS, which does not guarantee encryption if the receiving server does not support TLS or negotiates weaker settings.

This check evaluates whether Exchange Online outbound connectors are configured to enforce TLS (for example, certificate validation or domain validation) for partner mail flow. Enforced TLS reduces the risk of sensitive information being intercepted or modified in transit.

**Remediation action**
1. In the Exchange admin center, go to **Mail flow** > **Connectors**
2. Create or edit an outbound connector for partner domains
3. Enable the connector and configure TLS:
   - Require TLS
   - Use **CertificateValidation** or **DomainValidation** where appropriate
4. Add the recipient domain(s) that should require enforced TLS
5. Test mail flow with the partner and validate TLS negotiation

**Query via PowerShell**
```powershell
Connect-ExchangeOnline

Get-OutboundConnector |
  Where-Object { $_.Enabled -eq $true } |
  Select-Object Name, Enabled, TlsSettings, RecipientDomains |
  Format-Table -AutoSize
```
<!--- Results --->
%TestResult%
