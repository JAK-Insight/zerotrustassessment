By default, Power Platform connectors and Dataverse APIs communicate over Microsoft-managed shared network infrastructure. This means that outbound traffic from Power Automate flows to your internal APIs, or from Power Apps to backend services, traverses the public internet rather than your private corporate network. Organizations with strict network perimeter requirements — particularly those in regulated industries or those operating internal APIs that should never be internet-facing — cannot enforce network-level controls (firewall rules, private endpoints, NSG rules) against this traffic.

Azure Virtual Network data gateway integration for Managed Environments allows Power Platform to route connector traffic through a subnet in your Azure Virtual Network. This enables Power Platform flows and apps to access on-premises resources via ExpressRoute or VPN, reach private endpoints without public internet exposure, and be subject to the same NSG and Azure Firewall policies that govern other Azure workloads. It effectively brings Power Platform into the same network security perimeter as the rest of your Azure estate.

VNet integration is an advanced control that requires Azure Virtual Network infrastructure and subnets delegated to Power Platform. It is most critical for organizations running Power Platform alongside sensitive internal APIs or operating in environments with regulatory requirements for network isolation of data processing workloads.

**Remediation action**

1. Ensure you have an Azure Virtual Network with a subnet available for Power Platform delegation
2. Delegate the subnet to `Microsoft.PowerPlatform/enterprisePolicies`
3. Sign in to the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com)
4. Navigate to **Environments** and select a Managed Environment
5. Click **Edit Managed Environments**
6. Under **Network**, configure the Azure VNet policy by selecting your subscription, VNet, and subnet
7. Click **Save**
8. Repeat for each Managed Environment requiring network isolation

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
                  @{N='VNetSubnetId'; E={ $_.properties.governanceConfiguration.settings.networkSettings.subnetId }}
```

<!--- Results --->
%TestResult%
