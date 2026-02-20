DLP alerts and incident reports ensure that Data Loss Prevention policy matches and violations are visible to security and compliance teams. Without alerting, DLP can detect sensitive data activity but the organization may not notice or respond to risky behavior.

This check evaluates whether DLP compliance rules are configured to generate alerts and/or incident reports when policy conditions are met. Alerts and incident reporting enable workflows such as triage, investigation, and escalation to SOC or compliance responders.

At least one DLP rule should generate alerts or incident reports, and organizations should review rules that lack alerting to ensure monitoring coverage aligns with risk.

**Remediation action**
1. Sign in to the [Microsoft Purview portal](https://purview.microsoft.com)
2. Navigate to [DLP Policies](https://purview.microsoft.com/datalossprevention/policies)
3. Open the desired DLP policy and edit its compliance rules
4. Enable alerting and/or incident reporting:
   - Configure alerts for policy matches/violations
   - Configure incident reports and recipients (security/compliance mailbox)
5. Validate alert routing (mailbox, ticketing, SIEM) and response procedures

**Query via PowerShell**
```powershell
Connect-IPPSSession

Get-DlpComplianceRule |
  Select-Object Name, ParentPolicyName, GenerateAlert, GenerateIncidentReport |
  Format-Table -AutoSize
```
<!--- Results --->
%TestResult%
