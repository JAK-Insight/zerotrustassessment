Microsoft Defender for Cloud is a cloud-native application protection platform (CNAPP) that provides security posture management, threat protection, and workload protection across Azure subscriptions. When Defender for Cloud is operating on its Free tier, the organization receives only the Foundational Cloud Security Posture Management (CSPM) features: a basic security score and a limited set of security recommendations, but no active threat detection, no just-in-time VM access controls, no file integrity monitoring, no adaptive application controls, and no alerts for active attacks targeting Azure resources. An organization running entirely on the Free tier has no real-time visibility into infrastructure-level threats.

Microsoft Defender for Cloud's paid plans (collectively called "Defender for X") provide workload-specific protection for servers, databases, storage accounts, containers, App Service, Key Vault, and more. Each plan independently activates detection capabilities for that resource type. Without these plans enabled, a threat actor who compromises Azure credentials can move laterally through Azure resources, exfiltrate data from storage accounts, elevate privileges via role assignments, and maintain persistence — all without generating any security alerts visible to the organization. The Security Center dashboard will show a healthy-looking security score while active attacks proceed undetected.

Enabling at minimum Defender for Servers and Defender for Key Vault on all subscriptions provides a meaningful baseline of threat detection for the most commonly attacked Azure resource types. Organizations handling sensitive data should also enable Defender for Storage, Defender for SQL, and Defender for Containers. The Defender plans are subscription-scoped, so each subscription must be enabled independently.

**Remediation action**

1. Sign in to the [Azure portal](https://portal.azure.com) and navigate to [Microsoft Defender for Cloud](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0)
2. Select **Environment settings** in the left navigation
3. For each subscription, click on the subscription name
4. Under **Defender plans**, enable the plans relevant to your workloads (at minimum: **Servers**, **Key Vault**, **Storage**)
5. Click **Save**
6. Repeat for each subscription listed below

**Query via PowerShell**

```powershell
Connect-AzAccount

# List Defender for Cloud plan status across all subscriptions
Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' } | ForEach-Object {
    $sub = $_
    Set-AzContext -SubscriptionId $sub.Id | Out-Null
    Get-AzSecurityPricing | Select-Object Name, PricingTier,
        @{N='Subscription'; E={ $sub.Name }}
} | Sort-Object Subscription, Name | Format-Table -AutoSize
```

<!--- Results --->
%TestResult%
