Insider Risk Management (IRM) in Microsoft Purview helps identify and investigate risky user behaviors that can lead to data theft, data leakage, or security policy violations. Insider risks may be intentional (malicious insiders) or unintentional (careless sharing), and often require dedicated detection and investigation workflows beyond traditional DLP.

This check evaluates whether Insider Risk Management policies exist and whether at least one policy is enabled. If the IRM PowerShell cmdlets are not available, manual verification in the Purview portal may be required.

**Remediation action**
1. Sign in to the Microsoft Purview portal
2. Navigate to [Insider Risk Management > Policies](https://purview.microsoft.com/insiderriskmanagement/policies)
3. Create one or more policies using recommended templates (e.g., departing user data theft, data leaks)
4. Configure indicators, thresholds, and scopes (users/groups)
5. Enable the policy and validate that alerts and investigations can be performed by the appropriate team

**PowerShell validation**
```powershell
Connect-IPPSSession

# List IRM policies (requires IRM cmdlets to be available in the environment)
Get-InsiderRiskPolicy
```
<!--- Results --->
%TestResult%
