Data Loss Prevention (DLP) policies for SharePoint Online and OneDrive for Business help prevent sensitive files from being stored or shared in ways that violate policy or regulatory requirements. Because SharePoint and OneDrive are commonly used for collaboration and external sharing, they represent a major data leakage risk if DLP is not enabled and enforcing.

DLP policies scoped to SharePoint and OneDrive can scan file contents for Sensitive Information Types (SITs) and enforce controls such as restricting access, blocking external sharing, applying policy tips, or generating alerts. Policies running only in simulation mode provide visibility but do not prevent data loss.

At least one DLP policy should be actively enforcing on SharePoint Online and/or OneDrive for Business to provide baseline protection for content stored and shared in these services.

**Remediation action**
To configure DLP policies for SharePoint Online and OneDrive:

**Option 1: Create a new DLP policy from a template**
1. Sign in as Global Administrator or Compliance Administrator to the [Microsoft Purview portal](https://purview.microsoft.com)
2. Navigate to [DLP Policies](https://purview.microsoft.com/datalossprevention/policies)
3. Select **Create policy**
4. Choose a regulatory template (e.g., PII, financial, HIPAA, GDPR) or a custom policy
5. On the **Locations** page, ensure **SharePoint sites** and/or **OneDrive accounts** are toggled **On**
6. Configure rules with appropriate sensitive information types and thresholds
7. Configure actions (restrict access, block sharing, notify user, send alert)
8. Start in **simulation mode** to validate impact
9. Promote at least one policy to **enforcement mode**

**Option 2: Add SharePoint/OneDrive to an existing DLP policy**
1. Navigate to [DLP Policies](https://purview.microsoft.com/datalossprevention/policies)
2. Select an existing policy and click **Edit policy**
3. On the **Locations** page, toggle **SharePoint sites** and/or **OneDrive accounts** to **On**
4. Review and save the policy

**Query via PowerShell**
```powershell
Connect-IPPSSession

# List DLP policies covering SharePoint/OneDrive and their mode
Get-DlpCompliancePolicy |
  Where-Object { $_.SharePointLocation -or $_.OneDriveLocation } |
  Select-Object Name, Mode,
    @{N='SharePointScope';E={(@($_.SharePointLocation) | ForEach-Object Name) -join ', '}},
    @{N='OneDriveScope';E={(@($_.OneDriveLocation) | ForEach-Object Name) -join ', '}} |
  Format-Table -AutoSize
```
<!--- Results --->
%TestResult%
