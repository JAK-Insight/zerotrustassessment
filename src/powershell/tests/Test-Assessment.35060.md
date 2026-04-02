Data Loss Prevention (DLP) policies for Exchange Online detect and prevent the inadvertent or intentional sharing of sensitive information via email. Exchange Online is one of the most common vectors for data exfiltration—whether through accidental attachment of files containing PII, forwarding of financial records to external recipients, or deliberate insider threats. Without DLP coverage on Exchange, sensitive data such as Social Security numbers, credit card numbers, health records, and proprietary business information can leave the organization undetected and unprotected.

DLP policies scoped to Exchange Online can inspect email body content, attachments, and subject lines for sensitive information types (SITs). When a match is detected, the policy can notify the user, require justification, block the message, encrypt the content, or alert compliance administrators. Policies can operate in simulation mode (test without enforcement) to assess impact before being promoted to full enforcement. At least one DLP policy should be actively enforcing on Exchange Online to provide baseline protection against data loss via email.

Organizations should review policies in simulation mode periodically and promote them to enforcement once match reports confirm acceptable false-positive rates. Having policies only in simulation mode does not prevent data loss—it only logs potential violations.

**Remediation action**

To configure DLP policies for Exchange Online:

**Option 1: Create a new DLP policy from a template**
1. Sign in as Global Administrator or Compliance Administrator to the [Microsoft Purview portal](https://purview.microsoft.com)
2. Navigate to [DLP Policies](https://purview.microsoft.com/datalossprevention/policies)
3. Select **Create policy**
4. Choose a regulatory template (e.g., *U.S. Personally Identifiable Information (PII) Data*, *U.S. Financial Data*, *GDPR*) or start with a custom policy
5. On the **Locations** page, ensure **Exchange email** is toggled **On**
6. Configure rules with appropriate sensitive information types and thresholds
7. Set actions: notify user via policy tip, block sending, require override with justification, or encrypt
8. Deploy in **simulation mode** first to review match reports
9. After validating results, switch to **enforcement mode**

**Option 2: Add Exchange Online to an existing DLP policy**
1. Navigate to [DLP Policies](https://purview.microsoft.com/datalossprevention/policies)
2. Select an existing policy and click **Edit policy**
3. On the **Locations** page, toggle **Exchange email** to **On**
4. Review and save the policy

**Promote simulation-mode policies to enforcement:**
1. Navigate to [DLP Policies](https://purview.microsoft.com/datalossprevention/policies)
2. Select the policy in simulation mode
3. Click **Edit policy** and change the status from **Run the policy in simulation mode** to **Turn it on right away**
4. Save the policy

**Query via PowerShell:**
```powershell
Connect-IPPSSession
# List all DLP policies covering Exchange Online and their mode
Get-DlpCompliancePolicy | Where-Object { $_.ExchangeLocation } |
    Select-Object Name, Mode, @{N='ExchangeScope';E={($_.ExchangeLocation).Name -join ', '}} |
    Format-Table -AutoSize
```
<!--- Results --->
%TestResult%
