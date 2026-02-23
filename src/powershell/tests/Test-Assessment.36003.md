Azure Blob Storage supports optional public anonymous read access to containers and blobs. When public blob access is allowed on a storage account, any user who knows the URL can read container contents without authentication — no Azure credentials required. This capability exists to support intentionally public-facing static content, but when enabled on general-purpose storage accounts, it creates risk: sensitive files, backups, and configuration data may be inadvertently exposed if a container is set to anonymous access.

In a Zero Trust model, no storage resource should allow unauthenticated access unless explicitly and intentionally designed for that purpose. Every access to a storage account should be authenticated, authorized, and logged. Allowing public blob access at the storage account level removes the authentication gate entirely for any container that an administrator subsequently makes public — which can happen by accident through automation, scripts, or misconfiguration.

Disabling public blob access at the storage account level is a simple, low-impact change that enforces the Zero Trust principle of "never trust, always verify." It prevents any container in the account from being configured for anonymous access, even if someone attempts to enable it later. Microsoft now defaults new storage accounts to public access disabled.

**Remediation action**

1. Sign in to the [Azure portal](https://portal.azure.com) or use Azure CLI/PowerShell
2. For each storage account identified below, navigate to **Settings** > **Configuration**
3. Set **Allow Blob public access** to **Disabled**
4. Click **Save**
5. Verify that no containers in the account rely on anonymous access before disabling

**Query via PowerShell**

```powershell
Connect-AzAccount

# List all storage accounts and their public access setting
Get-AzStorageAccount | Select-Object StorageAccountName, ResourceGroupName,
    @{N='AllowBlobPublicAccess'; E={ $_.AllowBlobPublicAccess }}
```

<!--- Results --->
%TestResult%
