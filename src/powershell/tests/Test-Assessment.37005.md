Power Platform Dataverse environments accept connections from any IP address by default. This means that a user with stolen credentials — including credentials obtained through phishing, password spray, or credential stuffing — can access the Dataverse API and extract data from anywhere on the internet. Without IP-based restrictions, there is no network-layer control preventing unauthorized access to business data stored in Dataverse, even when the attacker does not have access to corporate network resources.

IP firewall in Managed Environments restricts Dataverse connections to a configured list of trusted IP ranges, such as corporate network CIDRs, VPN egress IPs, or Azure datacenter ranges used by Power Platform connectors. Connections from IP addresses outside the allowlist are rejected at the platform level, before authentication is even evaluated. This defense-in-depth control significantly reduces the risk of credential-based attacks against Dataverse, particularly from off-network attackers.

The IP firewall operates independently of Conditional Access policies applied to Azure AD sign-in. It provides a complementary control specifically for Dataverse API access, which may not always traverse the same authentication path as browser-based access.

**Remediation action**

1. Sign in to the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com)
2. Navigate to **Environments** and select a Managed Environment
3. Click **Edit Managed Environments**
4. Under **IP firewall**, enable **Turn on IP address-based firewall rule** and enter your trusted IP ranges (CIDR notation)
5. Optionally enable **Audit-only mode** first to observe which IPs are blocked before enforcing
6. Click **Save**
7. Repeat for each Managed Environment

**Query via PowerShell**

```powershell
# Requires Az module and Power Platform Admin access
Connect-AzAccount

$token   = Get-AzAccessToken -ResourceUrl 'https://service.powerapps.com/' -AsSecureString
$plain   = [System.Net.NetworkCredential]::new('', $token.Token).Password
$headers = @{ Authorization = "Bearer $plain"; Accept = 'application/json' }

$envs = Invoke-RestMethod -Uri 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2023-06-01' `
    -Headers $headers -Method GET |
    Select-Object -ExpandProperty value

$envs | Where-Object { $_.properties.governanceConfiguration.protectionLevel -eq 'Standard' } |
    Select-Object @{N='Name'; E={ $_.properties.displayName }},
                  @{N='IPFirewallEnabled'; E={ $_.properties.governanceConfiguration.settings.ipFirewallSettings.enableIpBasedFirewall }},
                  @{N='AllowedRanges'; E={ $_.properties.governanceConfiguration.settings.ipFirewallSettings.allowedIpRanges }}
```

<!--- Results --->
%TestResult%
