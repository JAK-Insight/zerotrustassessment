Azure Key Vault stores an organization's most sensitive assets — cryptographic keys, TLS certificates, API secrets, connection strings, and passwords used by applications and services across the environment. When soft delete is disabled on a Key Vault, any key, secret, or certificate that is deleted is immediately and permanently destroyed. There is no recovery window: if a secret is accidentally deleted, if an administrator makes an error, or if an attacker with Key Vault access destroys secrets as part of a ransomware or sabotage campaign, the data is gone with no recourse.

Soft delete provides a configurable retention period (7 to 90 days, default 90) during which deleted objects can be recovered. However, soft delete alone is not sufficient protection against a determined attacker or malicious insider who has Key Vault Contributor access — they can still permanently delete (purge) soft-deleted objects before the retention window expires. Purge protection prevents this by disabling the purge operation for the duration of the retention period, ensuring that even a privileged attacker cannot immediately destroy secrets.

Together, soft delete and purge protection provide ransomware resilience for credential material. They ensure that even a complete takeover of the Azure subscription cannot immediately destroy an organization's secrets beyond recovery — the retention window provides time to detect the compromise, revoke access, and restore from the soft-deleted state.

**Remediation action**

1. Sign in to the [Azure portal](https://portal.azure.com)
2. For each Key Vault identified below, navigate to **Settings** > **Properties**
3. Enable **Soft delete** if not already enabled (note: as of February 2025, soft delete cannot be disabled on existing vaults)
4. Enable **Purge protection** — note that once enabled, this setting cannot be reversed
5. Review the **Soft delete retention period** and set it to an appropriate value (90 days recommended)

**Query via PowerShell**

```powershell
Connect-AzAccount

# List Key Vaults missing soft delete or purge protection
Get-AzKeyVault | ForEach-Object {
    $kv = Get-AzKeyVault -VaultName $_.VaultName -ResourceGroupName $_.ResourceGroupName
    [pscustomobject]@{
        Name            = $kv.VaultName
        ResourceGroup   = $kv.ResourceGroupName
        SoftDelete      = $kv.EnableSoftDelete
        PurgeProtection = $kv.EnablePurgeProtection
    }
} | Where-Object { -not $_.SoftDelete -or -not $_.PurgeProtection }
```

<!--- Results --->
%TestResult%
