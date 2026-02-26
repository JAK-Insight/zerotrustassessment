Session tokens for Dataverse are typically not bound to the originating IP address, making them susceptible to session token replay attacks. If an attacker can steal a valid session cookie — through malware on an endpoint, a man-in-the-middle attack, or browser vulnerability exploitation — they can replay that cookie from any location to authenticate to Dataverse and access business data, even if the user has since logged out or changed their password. This type of attack bypasses multi-factor authentication entirely because the token was obtained after a legitimate MFA challenge.

IP-based cookie binding in Managed Environments ties each Dataverse session cookie to the IP address that initiated the session. Any subsequent request using that cookie from a different IP address is rejected, rendering stolen session tokens unusable. This is an effective mitigation against post-authentication credential theft scenarios, including attacks carried out by malware running on compromised endpoints that capture browser session state.

Cookie binding works in conjunction with IP firewall controls: IP firewall restricts which IPs can initiate new sessions, while cookie binding ensures existing sessions cannot be reused from different IPs. Together they substantially reduce the window of opportunity for session-based attacks against Dataverse.

**Remediation action**

1. Sign in to the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com)
2. Navigate to **Environments** and select a Managed Environment
3. Click **Edit Managed Environments**
4. Under **IP firewall**, ensure IP firewall is enabled (required for cookie binding)
5. Enable **Enable IP address-based cookie binding**
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
                  @{N='CookieBinding'; E={ $_.properties.governanceConfiguration.settings.ipFirewallSettings.enableIpBasedCookieBinding }}
```

<!--- Results --->
%TestResult%
