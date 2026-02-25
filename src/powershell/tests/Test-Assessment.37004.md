Canvas apps in Power Platform can be shared with any user or group in the organization. Without sharing limits, a maker can share an app that accesses sensitive Dataverse data or business APIs with "Everyone in the organization" — effectively granting all licensed users access to potentially sensitive functionality or data connections. This is a frequent misconfiguration that expands the blast radius of a compromised app or a poorly designed access control model.

Managed Environments provide a governance control called sharing limits that restricts how widely a canvas app can be shared. Administrators can configure a maximum number of users or groups an app can be shared with, or restrict sharing to security group members only. When this limit is in place, makers cannot accidentally (or intentionally) share broadly scoped apps across the entire organization without administrator approval.

This control is part of the Managed Environments premium governance suite and requires a Power Platform Premium, Power Apps per-app, or Managed Environment license for the environments in question. Without this control, even well-intentioned makers can inadvertently create wide attack surfaces through broad app sharing.

**Remediation action**

1. Sign in to the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com)
2. Ensure the target environments are Managed Environments (the shield icon should be visible)
3. Navigate to **Environments** and select a Managed Environment
4. Click **Edit Managed Environments**
5. Under **Limit sharing**, select **Exclude sharing with security groups** or set a **Limit total individuals who can be shared to** value
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
                  @{N='SharingLimitMode'; E={ $_.properties.governanceConfiguration.settings.limitSharingMode }}
```

<!--- Results --->
%TestResult%
