Retention policies help manage the lifecycle of data by ensuring content is retained for the required duration and disposed of appropriately. Proper retention reduces compliance risk (eDiscovery, regulatory obligations) and limits breach exposure by preventing unnecessary long-term retention of sensitive data.

This check evaluates whether retention policies exist and whether at least one retention policy is enabled. It also highlights which workloads (Exchange, SharePoint, OneDrive, Teams/Skype, Microsoft 365 Groups) are included in the configured policies.

**Remediation action**
1. Sign in to the Microsoft Purview portal
2. Navigate to Data lifecycle management > Retention policies
3. Create a retention policy or edit an existing one
4. Select the relevant locations (Exchange, SharePoint, OneDrive, Teams, M365 Groups)
5. Configure retention settings (retain, delete, or retain then delete) aligned to business/regulatory requirements
6. Enable and publish the policy

**Query via PowerShell**
```powershell
Connect-IPPSSession

Get-RetentionCompliancePolicy |
  Select-Object Name, Enabled, ExchangeLocation, SharePointLocation, OneDriveLocation, SkypeLocation, ModernGroupLocation, WhenCreatedUTC |
  Format-Table -AutoSize
```
<!--- Results --->
%TestResult%
