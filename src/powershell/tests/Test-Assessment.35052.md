Microsoft Purview alert policies help detect and notify responders about important security and compliance events. Data-related alert policies are especially important to monitor behaviors that can lead to data theft or leakage, such as DLP rule matches, unusual sharing patterns, large downloads, label changes, and other sensitive data operations.

This check evaluates whether data-related alert policies exist and are enabled, and whether the organization has created custom alert policies to supplement built-in detections. Custom alert policies are recommended for tenant-specific risks and operational needs (e.g., mass downloads of sensitive data, external sharing of labeled content, unusual access patterns).

**Remediation action**
1. Sign in to the [Microsoft Purview portal](httpsgate to Alert policies
3. Review built-in alert policies and ensure they are enabled where appropriate
4. Create custom alert policies for organization-specific scenarios:
   - Mass file downloads
   - External sharing of labeled content
   - DLP overrides and spikes
   - Sensitivity label downgrade events
5. Configure notification recipients and operational routing (SOC mailbox, ticketing, SIEM)

**PowerShell validation**
```powershell
Connect-IPPSSession
Get-ProtectionAlert | Select Name, Category, Severity, IsEnabled, Disabled, IsSystemRule, Source
```
<!--- Results --->
%TestResult%
