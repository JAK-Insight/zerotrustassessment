Data Loss Prevention (DLP) policies for Microsoft Teams help detect and prevent sensitive information from being shared in Teams chat and channel messages. Teams is a high-volume collaboration platform, and sensitive information can be exposed through pasted text, file sharing links, or message content.

When Teams is included as a DLP location, policies can detect Sensitive Information Types (SITs) in chat/channel messages and take actions such as warning users, blocking sharing, requiring justification, encrypting, or sending alerts to compliance and security teams. Policies in simulation mode provide visibility but do not prevent data loss.

At least one DLP policy should be actively enforcing on Microsoft Teams to provide baseline protection against accidental or intentional disclosure of sensitive data through Teams communications.

**Remediation action**
To configure DLP policies for Microsoft Teams:

**Option 1: Create a new DLP policy**
1. Sign in as Global Administrator or Compliance Administrator to the [Microsoft Purview portal](https://e to DLP Policies
3. Select **Create policy**
4. Choose a template (PII, financial, HIPAA, GDPR) or create a custom policy
5. On the **Locations** page, toggle **Microsoft Teams chat and channel messages** to **On**
6. Configure rules (SITs + thresholds) and actions (policy tips, block, override, alert)
7. Start in **simulation mode** to validate impact
8. Promote at least one policy to **enforcement mode**

**Option 2: Add Microsoft Teams to an existing DLP policy**
1. Navigate to [DLPPolicies
2. Select an existing policy and click **Edit policy**
3. On the **Locations** page, toggle **Microsoft Teams** to **On**
4. Review and save the policy

**Query via PowerShell**
```powershell
Connect-IPPSSession

# List DLP policies covering Microsoft Teams and their mode
Get-DlpCompliancePolicy |
  Where-Object { $_.TeamsLocation } |
  Select-Object Name, Mode,
    @{N='TeamsScope';E={(@($_.TeamsLocation) | ForEach-Object Name) -join ', '}} |
  Format-Table -AutoSize
  ```
<!--- Results --->
%TestResult%
