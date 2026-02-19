Restricting external sharing in SharePoint Online reduces the risk of sensitive data being shared to unauthorized users. Overly permissive settings (such as “Anyone” links) allow anonymous access to shared content and increase the risk of accidental exposure and data leakage.

This check evaluates the tenant-wide SharePoint sharing configuration, including the external sharing capability, anonymous link expiration, default link type, and default permission level.

**Recommended baseline**
- Prefer **Existing guests only** or **Only people in your organization** for high-sensitivity environments.
- Avoid **Anyone (anonymous)** sharing for sensitive tenants.
- If external sharing is required, ensure anonymous link expiration and least-privilege defaults.

**Remediation action**
1. Go to Microsoft 365 admin center > SharePoint admin center
2. Navigate to **Policies** > **Sharing**
3. Set SharePoint external sharing to:
   - **Existing guests only** (or stricter), or
   - **New and existing guests** (authenticated) if business requires
4. Configure:
   - Anonymous link expiration (if anonymous links allowed)
   - Default sharing link type to **Specific people**
   - Default permission to **View**

**PowerShell validation**
```powershell
# Requires SharePoint Online Management Shell
Connect-SPOService -Url https://<tenant>-admin.sharepoint.com
Get-SPOTenant | Select SharingCapability, RequireAnonymousLinksExpireInDays, DefaultSharingLinkType, DefaultLinkPermission
```
<!--- Results --->
%TestResult%
