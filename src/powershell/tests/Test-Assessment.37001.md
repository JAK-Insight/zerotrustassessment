Power Platform tenant isolation controls whether connectors in your tenant can establish connections to resources in other Azure Active Directory tenants, and whether connectors in external tenants can connect to your resources. Without tenant isolation, any Power Platform connector configured by a user in your organization can freely communicate with external tenants, and external tenants can connect back into your environment. This creates a significant data exfiltration risk: a malicious insider or compromised account can create a flow that reads SharePoint data and sends it to a connector endpoint in an attacker-controlled tenant.

When tenant isolation is enabled, inbound and outbound cross-tenant connections are blocked by default. Administrators can maintain an allowlist of trusted partner tenants for specific integration scenarios, enabling secure collaboration without opening the door to arbitrary cross-tenant data movement. This is analogous to network perimeter controls for your Power Platform environment.

Tenant isolation is available to all Power Platform tenants at no additional cost and does not affect same-tenant connections or connections using service principal authentication within the same tenant. Enabling it is a low-risk, high-value control that closes a frequently overlooked lateral movement path.

**Remediation action**

1. Sign in to the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com)
2. Navigate to **Policies** > **Tenant isolation**
3. Set tenant isolation to **On**
4. Optionally add trusted partner tenants to the allowlist for legitimate cross-tenant integrations
5. Click **Save**

**Query via PowerShell**

```powershell
# Requires Az module and Power Platform Admin access
Connect-AzAccount

$token   = Get-AzAccessToken -ResourceUrl 'https://service.powerapps.com/' -AsSecureString
$plain   = [System.Net.NetworkCredential]::new('', $token.Token).Password
$headers = @{ Authorization = "Bearer $plain"; Accept = 'application/json' }

Invoke-RestMethod -Uri 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/tenantSettings?api-version=2023-06-01' `
    -Headers $headers -Method GET |
    Select-Object -ExpandProperty properties |
    Select-Object -ExpandProperty tenantIsolationSettings
```

<!--- Results --->
%TestResult%
