Azure Storage accounts can be configured to accept both HTTP and HTTPS traffic, and to support legacy TLS protocol versions as low as 1.0. HTTP transmits credentials and data in plaintext, exposing them to interception on any network path between the client and Azure. TLS 1.0 and 1.1 are deprecated protocols with known cryptographic weaknesses that can be exploited by attackers capable of intercepting traffic. Both settings together define the minimum transport security posture for all data moving to and from Azure Blob, Table, Queue, and File storage.

When storage accounts do not enforce HTTPS-only traffic, applications or services that accidentally connect via HTTP will transmit storage account keys, SAS tokens, or data without encryption. This can happen silently — the connection succeeds, no error is returned, and the exposure goes unnoticed. Similarly, allowing TLS 1.0 or 1.1 means that older clients or misconfigured services can negotiate a downgraded, insecure connection even when HTTPS is used, undermining the value of the encryption entirely.

Enforcing HTTPS-only and requiring a minimum TLS version of 1.2 are low-risk, no-downtime changes for any modern application. Azure Storage has supported TLS 1.2 since 2017, and all current Microsoft SDKs and the Azure Portal use TLS 1.2 or higher by default. These settings should be treated as baseline hygiene for every storage account in the tenant.

**Remediation action**

1. Sign in to the [Azure portal](https://portal.azure.com)
2. For each storage account identified below, navigate to **Settings** > **Configuration**
3. Set **Secure transfer required** to **Enabled** (enforces HTTPS-only)
4. Set **Minimum TLS version** to **TLS 1.2**
5. Click **Save**

**Query via PowerShell**

```powershell
Connect-AzAccount

# List storage accounts not enforcing HTTPS or using TLS below 1.2
Get-AzStorageAccount | Where-Object {
    -not $_.EnableHttpsTrafficOnly -or $_.MinimumTlsVersion -notin 'TLS1_2','TLS1_3'
} | Select-Object StorageAccountName, ResourceGroupName, EnableHttpsTrafficOnly, MinimumTlsVersion
```

<!--- Results --->
%TestResult%
