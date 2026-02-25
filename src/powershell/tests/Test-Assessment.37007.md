Azure AD guest accounts (B2B users from partner organizations or external collaborators) can, by default, create canvas apps and Power Automate flows in Power Platform environments they have access to. This presents a data governance risk: an external guest user granted environment access to collaborate on a specific project can create automation that reads from unrelated Dataverse tables or SharePoint libraries, exfiltrating data to their home tenant without the data owner's knowledge. Guest makers operate under the same permissions as internal makers but with significantly less accountability and monitoring.

Disabling guest maker access is a straightforward control that prevents guest users from creating new Power Platform resources in an environment while still allowing them to use apps shared with them. Organizations that need guests to collaborate on Power Platform development should create a dedicated, tightly scoped developer environment for that purpose rather than granting guest maker rights across Production environments.

This setting does not affect guest users who are assigned Azure AD Dataverse security roles directly — those explicit permissions are maintained regardless of the guest maker setting. It specifically prevents the ad-hoc creation of new apps and flows by guest accounts.

**Remediation action**

1. Sign in to the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com)
2. Navigate to **Environments** and select a Production or Sandbox environment
3. Click **Settings** > **Features**
4. Under **Guest maker**, disable **Enable guests to make apps in this environment**
5. Click **Save**
6. Repeat for each Production and Sandbox environment

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
                  @{N='GuestMakerEnabled'; E={ $_.properties.guestMakerSettings.isGuestMakerEnabled }}
```

<!--- Results --->
%TestResult%
