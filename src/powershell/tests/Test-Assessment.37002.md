Data Loss Prevention (DLP) policies in Power Platform act as guardrails by classifying connectors into Business, Non-Business, and Blocked categories. Without at least one tenant-level DLP policy, users can freely combine any connector in their flows and apps, including pairing a SharePoint connector (accessing corporate data) with an HTTP connector (sending data to an arbitrary external endpoint). This unrestricted connector combinability is one of the most common ways that Power Platform becomes an unintentional data exfiltration channel.

A tenant-level DLP policy applies to all environments in the organization, establishing a baseline security posture. Organizations can then layer more restrictive environment-specific policies on top for sensitive workloads. The critical gap to prevent is the complete absence of any tenant-level policy, which leaves default environments and developer environments without governance controls. Malicious or simply careless flows can then extract corporate data to unauthorized external services.

At minimum, a tenant-level policy should place commonly exploited connectors (HTTP, HTTP with Azure AD, Custom connectors) in the Blocked or Non-Business category while keeping productivity connectors (Microsoft 365, SharePoint, Teams, Outlook) in Business. This does not prevent legitimate automation and significantly reduces data exfiltration risk.

**Remediation action**

1. Sign in to the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com)
2. Navigate to **Policies** > **Data policies**
3. Click **New policy**
4. Name the policy (for example, "Tenant Baseline DLP")
5. In **Assign connectors**, move high-risk connectors (HTTP, HTTP with Azure AD, SMTP) to **Blocked** and Microsoft 365 connectors to **Business**
6. Under **Define policy scope**, select **Add all environments** to apply to the entire tenant
7. Click **Create policy**

**Query via PowerShell**

```powershell
# Requires Az module and Power Platform Admin access
Connect-AzAccount

$token   = Get-AzAccessToken -ResourceUrl 'https://service.powerapps.com/' -AsSecureString
$plain   = [System.Net.NetworkCredential]::new('', $token.Token).Password
$headers = @{ Authorization = "Bearer $plain"; Accept = 'application/json' }

Invoke-RestMethod -Uri 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies?api-version=2016-11-01' `
    -Headers $headers -Method GET |
    Select-Object -ExpandProperty value |
    Select-Object displayName, @{N='Scope'; E={ $_.properties.environmentType }}
```

<!--- Results --->
%TestResult%
