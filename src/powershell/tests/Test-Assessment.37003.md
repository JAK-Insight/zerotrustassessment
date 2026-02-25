By default, any user in your Azure Active Directory tenant who has a Power Apps or Power Automate license can access a Power Platform environment and its apps, flows, and data. Without a security group assigned to a Production or Sandbox environment, this means that every licensed employee — including temporary workers, contractors, and users whose roles have changed — can potentially interact with business-critical applications and their underlying Dataverse data.

Assigning an Azure AD security group to an environment restricts access to only the members of that group. Users outside the group cannot see the environment in their app lists or access its Dataverse tables. This is an essential control for environments that host sensitive business processes such as finance approvals, HR workflows, or customer-facing operations. It is especially important because Power Platform environments often inherit broad permissions by design (to make it easy to get started), requiring explicit opt-in to restrict access.

Environment-level security groups work in conjunction with Dataverse security roles: the security group gates who can enter the environment, while Dataverse roles control what they can do once inside. Both layers are needed for a complete access control model.

**Remediation action**

1. Create an Azure AD security group for each Production or Sandbox environment that lacks one (e.g., "PowerPlatform-Env-Finance")
2. Add the appropriate licensed users to each group
3. Sign in to the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com)
4. Navigate to **Environments** and select the target environment
5. Click **Edit** and under **Security group**, search for and select the Azure AD group
6. Click **Save**
7. Repeat for each Production and Sandbox environment listed below

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

$envs | Where-Object { $_.properties.environmentSku -in 'Production','Sandbox' } |
    Select-Object @{N='Name'; E={ $_.properties.displayName }},
                  @{N='Type'; E={ $_.properties.environmentSku }},
                  @{N='SecurityGroup'; E={ $_.properties.addGroupTeamConfiguration.groupTeamMetadata.securityGroupId }}
```

<!--- Results --->
%TestResult%
