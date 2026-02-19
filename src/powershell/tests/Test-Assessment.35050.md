Audit logs provide critical visibility into user and administrative activity across Microsoft 365 services. Extending audit log retention beyond default periods improves the organization’s ability to investigate incidents, meet regulatory requirements, and support long lookback windows for advanced threats.

This check evaluates whether custom audit log retention policies are configured. Custom policies can extend retention beyond default limits and can be targeted to specific high-value record types for cost optimization and investigation effectiveness.

**Remediation action**
1. Sign in to the Microsoft Purview portal
2. Navigate to Audit > Audit retention policies
3. Create or update an audit retention policy
4. Choose the appropriate retention duration and scope (record types)
5. Ensure the policy is enabled and prioritized appropriately

**PowerShell validation**
```powershell
Connect-IPPSSession

Get-UnifiedAuditLogRetentionPolicy |
  Select-Object Name, RetentionDuration, RecordTypes, Priority, Enabled |
  Format-Table -AutoSize
```
<!--- Results --->
%TestResult%
