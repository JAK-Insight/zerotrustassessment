Endpoint Data Loss Prevention (Endpoint DLP) helps prevent sensitive information from being exfiltrated from managed Windows devices through risky channels such as USB removable media, printing, clipboard transfers, screen captures, or uploads to unauthorized cloud services.

Endpoint DLP policies in Microsoft Purview extend DLP beyond cloud workloads (Exchange, SharePoint, OneDrive, Teams) to include device-based activities. When Endpoint DLP is enabled and enforcing, organizations gain the ability to block or audit risky actions, show user notifications, and generate alerts for investigation.

Policies running only in simulation mode provide visibility but do not prevent data loss. At least one policy should be actively enforcing on Endpoint DLP (Devices), ideally aligned to the organization’s most sensitive data types and business processes.

**Remediation action**
To configure Endpoint DLP policies:

1. Sign in as Global Administrator or Compliance Administrator to the [Microsoft Purview portal](https://e to [DLP Policies](https://purew policy or edit an existing policy
4. On the **Locations** page, toggle **Devices (Endpoint DLP)** to **On**
5. Configure rules using appropriate Sensitive Information Types (SITs) and thresholds
6. Configure actions (block, audit, override with justification, notify user, alert)
7. Start in **simulation mode** to validate impact
8. Promote at least one policy to **enforcement mode**

**Query via PowerShell**
```powershell
Connect-IPPSSession

# List DLP policies covering Endpoint DLP (Devices) and their mode
Get-DlpCompliancePolicy |
  Where-Object { $_.EndpointDlpLocation } |
  Select-Object Name, Mode,
    @{N='EndpointScope';E={(@($_.EndpointDlpLocation) | ForEach-Object Name) -join ', '}} |
  Format-Table -AutoSize
```
<!--- Results --->
%TestResult%
