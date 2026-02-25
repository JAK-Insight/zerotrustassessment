# Zero Trust Assessment — Test Reference

All tests supported by the Zero Trust Assessment module, grouped by pillar.

**Graph Reader scopes** refers to the permissions returned by `Get-ZtGraphScope`.

## Identity (135 tests)

| Test ID | Test Title | Role / Scope Required | Works in GCC? |
|:---|:---|:---|:---|
| 21770 | Inactive applications don’t have highly privileged Microsoft Graph API permissions | Graph Reader scopes | Yes |
| 21771 | Inactive applications don’t have highly privileged built-in roles | Graph Reader scopes | Yes |
| 21772 | Applications don't have client secrets configured | Graph Reader scopes | Yes |
| 21773 | Applications don't have certificates with expiration longer than 180 days | Graph Reader scopes | Yes |
| 21774 | Microsoft services applications don't have credentials configured | Graph Reader scopes | Yes |
| 21775 | Enforce standards for app secrets and certificates | Graph Reader scopes | Yes |
| 21776 | User consent settings are restricted | Graph Reader scopes | Yes |
| 21777 | App instance property lock is configured for all multitenant applications | Graph Reader scopes | Yes |
| 21780 | No usage of ADAL in the tenant | Graph Reader scopes | Yes |
| 21781 | Privileged users sign in with phishing-resistant methods | Graph Reader scopes | Yes |
| 21782 | Privileged accounts have phishing-resistant methods registered | Graph Reader scopes | Yes |
| 21783 | Privileged Microsoft Entra built-in roles are targeted with Conditional Access policies to enforce phishing-resistant methods | Graph Reader scopes | Yes |
| 21784 | All user sign in activity uses phishing-resistant authentication methods | Graph Reader scopes | Yes |
| 21786 | User sign-in activity uses token protection | Graph Reader scopes | Yes |
| 21787 | Permissions to create new tenants are limited to the Tenant Creator role | Graph Reader scopes | Yes |
| 21788 | Global Administrators don't have standing access to Azure subscriptions | Graph Reader scopes + Azure Reader | Partial (Azure portion requires Azure Government) |
| 21790 | Outbound cross-tenant access settings are configured | Graph Reader scopes | Yes |
| 21791 | Guests can’t invite other guests | Graph Reader scopes | Yes |
| 21792 | Guests have restricted access to directory objects | Graph Reader scopes | Yes |
| 21793 | Tenant restrictions v2 policy is configured | Graph Reader scopes | Yes |
| 21795 | No legacy authentication sign-in activity | Graph Reader scopes | Yes |
| 21796 | Block legacy authentication policy is configured | Graph Reader scopes | Yes |
| 21797 | Restrict access to high risk users | Graph Reader scopes | Yes |
| 21798 | ID Protection notifications are enabled | Graph Reader scopes | Yes |
| 21799 | Restrict high risk sign-ins | Graph Reader scopes | Yes |
| 21800 | All user sign-in activity uses strong authentication methods | Graph Reader scopes | Yes |
| 21801 | Users have strong authentication methods configured | Graph Reader scopes | Yes |
| 21802 | Microsoft Authenticator app shows sign-in context | Graph Reader scopes (includes beta API) | Partial (beta Graph APIs may not be available in all GCC tiers) |
| 21803 | Migrate from legacy MFA and SSPR policies | Graph Reader scopes | Yes |
| 21804 | SMS and Voice Call authentication methods are disabled | Graph Reader scopes | Yes |
| 21806 | Secure the MFA registration (My Security Info) page | Graph Reader scopes | Yes |
| 21807 | Creating new applications and service principals is restricted to privileged users | Graph Reader scopes | Yes |
| 21808 | Restrict device code flow | Graph Reader scopes (includes beta API) | Partial (beta Graph APIs may not be available in all GCC tiers) |
| 21809 | Admin consent workflow is enabled | Graph Reader scopes | Yes |
| 21810 | Resource-specific consent is restricted | Graph Reader scopes | Yes |
| 21811 | Password expiration is disabled | Graph Reader scopes | Yes |
| 21812 | Maximum number of Global Administrators doesn't exceed five users | Graph Reader scopes | Yes |
| 21813 | High Global Administrator to privileged user ratio | Graph Reader scopes | Yes |
| 21814 | Privileged accounts are cloud native identities | Graph Reader scopes | Yes |
| 21815 | All privileged role assignments are activated just in time and not permanently active | Graph Reader scopes | Yes |
| 21816 | All Microsoft Entra privileged role assignments are managed with PIM | Graph Reader scopes | Yes |
| 21817 | Global Administrator role activation triggers an approval workflow | Graph Reader scopes | Yes |
| 21818 | Privileged role activations have monitoring and alerting configured | Graph Reader scopes | Yes |
| 21819 | Activation alert for Global Administrator role assignment | Graph Reader scopes | Yes |
| 21820 | Activation alert for all privileged role assignments | Graph Reader scopes | Yes |
| 21821 | Guest access is restricted | Graph Reader scopes | Yes |
| 21822 | Guest access is limited to approved tenants | Graph Reader scopes | Yes |
| 21823 | Guest self-service sign-up via user flow is disabled | Graph Reader scopes | Yes |
| 21824 | Guests don't have long lived sign-in sessions | Graph Reader scopes | Yes |
| 21825 | Privileged users have short-lived sign-in sessions | Graph Reader scopes | Yes |
| 21828 | Authentication transfer is blocked | Graph Reader scopes | Yes |
| 21829 | Use cloud authentication | Graph Reader scopes | Yes |
| 21830 | Conditional Access policies for Privileged Access Workstations are configured | Graph Reader scopes | Yes |
| 21831 | Protected actions are enabled for high-impact management tasks | Graph Reader scopes | Yes |
| 21832 | All groups in Conditional Access policies belong to a restricted management administrative unit | Graph Reader scopes | Yes |
| 21833 | Directory Sync account credentials haven't been rotated recently | Graph Reader scopes | Yes |
| 21834 | Directory sync account is locked down to specific named location | Graph Reader scopes | Yes |
| 21835 | Emergency access accounts are configured appropriately | Graph Reader scopes | Yes |
| 21836 | Workload Identities are not assigned privileged roles | Graph Reader scopes | Yes |
| 21837 | Limit the maximum number of devices per user to 10 | Graph Reader scopes (includes beta API) | Partial (beta Graph APIs may not be available in all GCC tiers) |
| 21838 | Security key authentication method enabled | Graph Reader scopes | Yes |
| 21839 | Passkey authentication method enabled | Graph Reader scopes | Yes |
| 21840 | Security key attestation is enforced | Graph Reader scopes | Yes |
| 21841 | Microsoft Authenticator app report suspicious activity setting is enabled | Graph Reader scopes (includes beta API) | Partial (beta Graph APIs may not be available in all GCC tiers) |
| 21842 | Block administrators from using SSPR | Graph Reader scopes | Yes |
| 21843 | Block legacy Microsoft Online PowerShell module | Graph Reader scopes | Yes |
| 21844 | Block legacy Azure AD PowerShell module | Graph Reader scopes | Yes |
| 21845 | Temporary access pass is enabled | Graph Reader scopes | Yes |
| 21846 | Restrict Temporary Access Pass to Single Use | Graph Reader scopes | Yes |
| 21847 | Password protection for on-premises is enabled | Graph Reader scopes | Yes |
| 21848 | Add organizational terms to the banned password list | Graph Reader scopes | Yes |
| 21849 | Smart lockout duration is set to a minimum of 60 | Graph Reader scopes | Yes |
| 21850 | Smart lockout threshold set to 10 or less | Graph Reader scopes | Yes |
| 21851 | Guest access is protected by strong authentication methods | Graph Reader scopes | Yes |
| 21854 | Privileged roles aren't assigned to stale identities | Graph Reader scopes | Yes |
| 21855 | Privileged roles have access reviews | Graph Reader scopes | Yes |
| 21857 | Guest identities are lifecycle managed with access reviews | Graph Reader scopes | Yes |
| 21858 | Inactive guest identities are disabled or removed from the tenant | Graph Reader scopes | Yes |
| 21859 | GDAP admin least privilege | Graph Reader scopes | Yes |
| 21860 | Diagnostic settings are configured for all Microsoft Entra logs | Graph Reader scopes + Azure Reader | Partial (Azure portion requires Azure Government) |
| 21861 | All high-risk users are triaged | Graph Reader scopes | Yes |
| 21862 | All risky workload identities are triaged | Graph Reader scopes | Yes |
| 21863 | All high-risk sign-ins are triaged | Graph Reader scopes | Yes |
| 21864 | All risk detections are triaged | Graph Reader scopes | Yes |
| 21865 | Named locations are configured | Graph Reader scopes | Yes |
| 21866 | All Microsoft Entra recommendations are addressed | Graph Reader scopes | Yes |
| 21867 | Enterprise applications with high privilege Microsoft Graph API permissions have owners | Graph Reader scopes | Yes |
| 21868 | Guests do not own apps in the tenant | Graph Reader scopes | Yes |
| 21869 | Enterprise applications must require explicit assignment or scoped provisioning | Graph Reader scopes | Yes |
| 21870 | Enable self-service password reset | Graph Reader scopes | Yes |
| 21872 | Require multifactor authentication for device join and device registration using user action | Graph Reader scopes | Yes |
| 21874 | Guest access is limited to approved tenants | Graph Reader scopes | Yes |
| 21875 | All entitlement management assignment policies that apply to external users require connected organizations | Graph Reader scopes | Yes |
| 21876 | Use PIM for Microsoft Entra privileged roles | Graph Reader scopes | Yes |
| 21877 | All guests have a sponsor | Graph Reader scopes | Yes |
| 21878 | All entitlement management policies have an expiration date | Graph Reader scopes | Yes |
| 21879 | All entitlement management policies that apply to External users require approval | Graph Reader scopes | Yes |
| 21881 | Azure subscriptions used by Identity Governance are secured consistently with Identity Governance roles | Graph Reader scopes | Yes |
| 21882 | No nested groups in PIM for groups | Graph Reader scopes | Yes |
| 21883 | Workload Identities are configured with risk-based policies | Graph Reader scopes | Yes |
| 21884 | Conditional Access policies for workload identities based on known networks are configured | Graph Reader scopes (includes beta API) | Partial (beta Graph APIs may not be available in all GCC tiers) |
| 21885 | App registrations use safe redirect URIs | Graph Reader scopes | Yes |
| 21886 | Applications are configured for automatic user provisioning | Graph Reader scopes | Yes |
| 21887 | All registered redirect URIs must have proper DNS records and ownerships | Graph Reader scopes | Yes |
| 21888 | App registrations must not have dangling or abandoned domain redirect URIs | Graph Reader scopes | Yes |
| 21889 | Reduce the user-visible password surface area | Graph Reader scopes | Yes |
| 21890 | Require password reset notifications for user roles | Graph Reader scopes | Yes |
| 21891 | Require password reset notifications for administrator roles | Graph Reader scopes | Yes |
| 21892 | All sign-in activity comes from managed devices | Graph Reader scopes | Yes |
| 21893 | All users are required to register for MFA | Graph Reader scopes | Yes |
| 21894 | All certificates Microsoft Entra Application Registrations and Service Principals must be issued by an approved certification authority | Graph Reader scopes | Yes |
| 21895 | Application Certificate Credentials are managed using HSM | Graph Reader scopes | Yes |
| 21896 | Service principals don't have certificates or credentials associated with them | Graph Reader scopes | Yes |
| 21897 | All app assignment and group membership is governed | Graph Reader scopes | Yes |
| 21898 | All supported access lifecycle resources are managed with entitlement management packages | Graph Reader scopes | Yes |
| 21899 | All privileged role assignments have a recipient that can receive notifications | Graph Reader scopes | Yes |
| 21912 | Azure resources used by Microsoft Entra only allow access from privileged roles | Graph Reader scopes | Yes |
| 21929 | All entitlement management packages that apply to guests have expirations or access reviews configured in their assignment policies | Graph Reader scopes | Yes |
| 21941 | Token protection policies are configured | Graph Reader scopes (includes beta API) | Partial (beta Graph APIs may not be available in all GCC tiers) |
| 21953 | Local Admin Password Solution is deployed | Graph Reader scopes | Yes |
| 21954 | Restrict non-administrator users from recovering the BitLocker keys for their owned devices | Graph Reader scopes | Yes |
| 21955 | Manage the local administrators on Microsoft Entra joined devices | Graph Reader scopes | Yes |
| 21964 | Enable protected actions to secure Conditional Access policy creation and changes | Graph Reader scopes | Yes |
| 21983 | No Active Medium priority Entra recommendations found | Graph Reader scopes | Yes |
| 21984 | No Active low priority Entra recommendations found | Graph Reader scopes | Yes |
| 21985 | Turn off Seamless SSO if there is no usage | Graph Reader scopes | Yes |
| 21992 | Application certificates must be rotated on a regular basis | Graph Reader scopes | Yes |
| 21993 | AI agent identities have sponsors assigned | Graph Reader scopes + AgentIdentity.Read.All (preview) | Unknown (preview feature; GCC availability unconfirmed) |
| 22072 | Self-service password reset doesn't use security questions | Graph Reader scopes | Yes |
| 22124 | High priority Microsoft Entra recommendations are addressed | Graph Reader scopes | Yes |
| 22128 | Guests are not assigned high privileged directory roles | Graph Reader scopes | Yes |
| 22659 | All risky workload identity sign-ins are triaged | Graph Reader scopes (includes beta API) | Partial (beta Graph APIs may not be available in all GCC tiers) |
| 23183 | Service principals use safe redirect URIs | Graph Reader scopes | Yes |
| 24518 | Enterprise applications have owners | Graph Reader scopes | Yes |
| 24570 | Entra Connect Sync is configured with Service Principal Credentials | Graph Reader scopes | Yes |

## Devices (36 tests)

| Test ID | Test Title | Role / Scope Required | Works in GCC? |
|:---|:---|:---|:---|
| 24540 | Windows Firewall policies protect against unauthorized network access | Graph Reader scopes | Yes |
| 24541 | Compliance policies protect Windows devices | Graph Reader scopes | Yes |
| 24542 | Compliance policies protect macOS devices | Graph Reader scopes | Yes |
| 24543 | Compliance policies protect iOS/iPadOS devices | Graph Reader scopes | Yes |
| 24545 | Compliance policies protect fully managed and corporate-owned Android devices | Graph Reader scopes | Yes |
| 24546 | Windows automatic device enrollment is enforced to eliminate risks from unmanaged endpoints | Graph Reader scopes | Yes |
| 24547 | Compliance policies protect personally owned Android devices | Graph Reader scopes | Yes |
| 24548 | Data on iOS/iPadOS is protected by app protection policies | Graph Reader scopes | Yes |
| 24549 | Data on Android is protected by app protection policies | Graph Reader scopes | Yes |
| 24550 | Data on Windows is protected by BitLocker encryption | Graph Reader scopes | Yes |
| 24551 | Authentication on Windows uses Windows Hello for Business | Graph Reader scopes | Yes |
| 24552 | macOS Firewall policies protect against unauthorized network access | Graph Reader scopes | Yes |
| 24553 | Windows Update policies are enforced to reduce risk from unpatched vulnerabilities | Graph Reader scopes | Yes |
| 24554 | Update policies for iOS/iPadOS are enforced to reduce risk from unpatched vulnerabilities | Graph Reader scopes | Yes |
| 24555 | Scope tag configuration is enforced to support delegated administration and least-privilege access | Graph Reader scopes (includes beta API) | Partial (beta Graph APIs may not be available in all GCC tiers) |
| 24560 | Local administrator credentials on Windows are protected by Windows LAPS | Graph Reader scopes | Yes |
| 24561 | A macOS Cloud LAPS Policy is Created and Assigned | Graph Reader scopes | Yes |
| 24564 | Local account usage on Windows is restricted to reduce unauthorized access | Graph Reader scopes | Yes |
| 24568 | Platform SSO is configured to strengthen authentication on macOS devices | Graph Reader scopes | Yes |
| 24569 | FileVault encryption protects data on macOS devices | Graph Reader scopes | Yes |
| 24572 | Device enrollment notifications are enforced to ensure user awareness and secure onboarding | Graph Reader scopes | Yes |
| 24573 | Security baselines are applied to Windows devices to strengthen security posture | Graph Reader scopes | Yes |
| 24574 | Attack Surface Reduction rules are applied to Windows devices to prevent exploitation of vulnerable system components | Graph Reader scopes | Yes |
| 24575 | Defender Antivirus policies protect Windows devices from malware | Graph Reader scopes | Yes |
| 24576 | Endpoint Analytics is enabled to help identify risks on Windows devices | Graph Reader scopes | Yes |
| 24690 | Update policies for macOS are enforced to reduce risk from unpatched vulnerabilities | Graph Reader scopes | Yes |
| 24784 | Defender Antivirus policies protect macOS devices from malware | Graph Reader scopes | Yes |
| 24794 | Terms and Conditions policies protect access to sensitive data | Graph Reader scopes (includes beta API) | Partial (beta Graph APIs may not be available in all GCC tiers) |
| 24802 | Device cleanup rules maintain tenant hygiene by hiding inactive devices | Graph Reader scopes (includes beta API) | Partial (beta Graph APIs may not be available in all GCC tiers) |
| 24823 | Company Portal branding and support settings enhance user experience and trust | Graph Reader scopes | Yes |
| 24824 | Conditional Access policies block access from noncompliant devices | Graph Reader scopes | Yes |
| 24827 | Conditional Access policies block access from unmanaged apps | Graph Reader scopes | Yes |
| 24839 | Secure Wi-Fi profiles protect iOS devices from unauthorized network access | Graph Reader scopes | Yes |
| 24840 | Secure Wi-Fi profiles protect Android devices from unauthorized network access | Graph Reader scopes | Yes |
| 24870 | Secure Wi-Fi profiles protect macOS devices from unauthorized network access | Graph Reader scopes | Yes |
| 24871 | Defender for Endpoint automatic enrollment is enforced to reduce risk from unmanaged Android threats | Graph Reader scopes (includes beta API) | Partial (beta Graph APIs may not be available in all GCC tiers) |

## Network (40 tests)

| Test ID | Test Title | Role / Scope Required | Works in GCC? |
|:---|:---|:---|:---|
| 25370 | User source IP addresses are preserved for Conditional Access and risk detection | Graph Reader scopes | Yes |
| 25371 | Network access is validated in real-time through Universal Continuous Access Evaluation | Graph Reader scopes | Yes |
| 25372 | Global Secure Access (GSA) client is deployed on all managed endpoints | Graph Reader scopes | Yes |
| 25376 | Microsoft 365 traffic is actively flowing through Global Secure Access | Graph Reader scopes | Yes |
| 25377 | Users accessing external applications from corporate devices are blocked unless explicitly authorized by tenant restrictions policies | Graph Reader scopes | Yes |
| 25378 | External collaboration is governed by explicit Cross-Tenant Access Policies | Graph Reader scopes | Yes |
| 25379 | Compliant network controls are used in conditional access policies | Graph Reader scopes | Yes |
| 25381 | Network traffic is routed through Global Secure Access for security policy enforcement | Graph Reader scopes | Yes |
| 25382 | Traffic forwarding profiles are scoped to appropriate users and groups for controlled deployment | Graph Reader scopes | Yes |
| 25383 | Global and GSA admin privileges are tightly limited to prevent tenant-wide compromise | Graph Reader scopes | Yes |
| 25384 | Application admin rights are constrained to specific Private Access apps, not tenant-wide | Graph Reader scopes | Yes |
| 25391 | Private network connectors are active and healthy to maintain Zero Trust access to internal resources | Graph Reader scopes | Yes |
| 25392 | Private Access Connectors are running the latest version | Graph Reader scopes | Yes |
| 25394 | Quick Access is bound to a Conditional Access policy | Graph Reader scopes | Yes |
| 25395 | Private Access application segments enforce least-privilege access | Graph Reader scopes | Yes |
| 25396 | Conditional Access policies enforce strong authentication for private apps | Graph Reader scopes | Yes |
| 25399 | Private DNS is configured for internal name resolution | Graph Reader scopes | Yes |
| 25403 | DC Agent is deployed and enforcing strong authentication policies | Graph Reader scopes | Yes |
| 25405 | Intelligent Local Access is enabled and configured | Graph Reader scopes | Yes |
| 25406 | Internet access forwarding profile is enabled | Graph Reader scopes | Yes |
| 25407 | Internet Access security policies are enforced through Conditional Access for user-aware protection | Graph Reader scopes | Yes |
| 25408 | Global Secure Access web content filtering is enabled and configured | Graph Reader scopes | Yes |
| 25409 | Global Secure Access Web content filtering controls internet access based on website categories | Graph Reader scopes | Yes |
| 25410 | Internet traffic is protected by web content filtering policies in Global Secure Access | Graph Reader scopes | Yes |
| 25411 | TLS inspection is enabled and correctly configured for outbound traffic in Global Secure Access | Graph Reader scopes | Yes |
| 25415 | Enterprise generative AI applications are protected from prompt injection attacks through AI Gateway | Graph Reader scopes | Yes |
| 25416 | Branch office internet traffic is protected by Cloud Firewall policies through Global Secure Access | Graph Reader scopes | Yes |
| 25419 | Network access activity is visible to security operations for threat detection and response | Graph Reader scopes + Azure Reader | Partial (Azure Named Locations via Azure requires Azure Government) |
| 25420 | Network access logs are retained for security analysis and compliance requirements | Graph Reader scopes + Azure Reader | Partial (Azure Named Locations via Azure requires Azure Government) |
| 25422 | GSA Deployment logs are populated and reviewed | Graph Reader scopes | Yes |
| 25480 | Quick Access has assigned users or groups | Graph Reader scopes | Yes |
| 25481 | All Private Access applications have assigned users or groups | Graph Reader scopes | Yes |
| 25535 | Outbound traffic from VNET integrated workloads is routed through Azure Firewall | Graph Reader scopes + Azure Reader | Partial (Azure Named Locations via Azure requires Azure Government) |
| 25537 | Threat intelligence is Enabled in Deny Mode on Azure Firewall | Graph Reader scopes + Azure Reader | Partial (Azure Named Locations via Azure requires Azure Government) |
| 25539 | IDPS Inspection is Enabled in Deny Mode on Azure Firewall | Graph Reader scopes + Azure Reader | Partial (Azure Named Locations via Azure requires Azure Government) |
| 25541 | Application Gateway WAF is Enabled in Prevention mode | Graph Reader scopes | Yes |
| 25543 | Azure Front Door WAF is Enabled in Prevention Mode | Graph Reader scopes + Azure Reader | Partial (Azure Named Locations via Azure requires Azure Government) |
| 25550 | Inspection of Outbound TLS Traffic is Enabled on Azure Firewall | Graph Reader scopes + Azure Reader | Partial (Azure Named Locations via Azure requires Azure Government) |
| 25551 | Named locations are defined and used in Conditional Access policies | Graph Reader scopes | Yes |
| 26889 | Diagnostic logging is enabled in Azure Front Door WAF | Graph Reader scopes + Azure Reader | Partial (Azure Named Locations via Azure requires Azure Government) |

## Data (49 tests)

| Test ID | Test Title | Role / Scope Required | Works in GCC? |
|:---|:---|:---|:---|
| 35001 | Conditional Access RMS Exclusions | Graph Reader scopes | Yes |
| 35002 | Cross-Tenant Access Policy (XTAP) RMS Inbound/Outbound Settings | Graph Reader scopes | Yes |
| 35003 | Total Sensitivity Labels Configured | Graph Reader scopes + Purview / AIP Reader | Partial (AIP/Purview uses different endpoints in GCC) |
| 35004 | Published Label Policies | Graph Reader scopes + Purview / AIP Reader | Partial (AIP/Purview uses different endpoints in GCC) |
| 35005 | Sensitivity Labels Enabled in SharePoint Online | Graph Reader scopes + SharePoint Reader | Yes |
| 35006 | PDF Labeling Support in SharePoint Online | Graph Reader scopes + SharePoint Reader | Yes |
| 35007 | Information Rights Management (IRM) Enabled in SharePoint Online | Graph Reader scopes + SharePoint Reader | Yes |
| 35008 | SPO Default Document Library Label (Tenant-Wide) | Graph Reader scopes + SharePoint Reader | Yes |
| 35009 | Co-Authoring Enabled for Encrypted Documents | Graph Reader scopes | Yes |
| 35010 | Double Key Encryption (DKE) Labels | Graph Reader scopes + Purview / AIP Reader | Partial (AIP/Purview uses different endpoints in GCC) |
| 35011 | Super User Membership Configuration | Graph Reader scopes (includes beta API) + Purview / AIP Reader | Partial (AIP/Purview uses different endpoints in GCC) |
| 35012 | Container labels are configured for Teams, Groups, and Sites | Graph Reader scopes + Purview / AIP Reader | Partial (AIP/Purview uses different endpoints in GCC) |
| 35013 | Encryption-Enabled Labels | Graph Reader scopes + Purview / AIP Reader | Partial (AIP/Purview uses different endpoints in GCC) |
| 35014 | Email label inheritance from attachments configured | Graph Reader scopes + Purview / AIP Reader | Partial (AIP/Purview uses different endpoints in GCC) |
| 35015 | Global Scope Label Count | Graph Reader scopes + Purview / AIP Reader | Partial (AIP/Purview uses different endpoints in GCC) |
| 35016 | Mandatory labeling enabled for sensitivity labels | Graph Reader scopes + Purview / AIP Reader | Partial (AIP/Purview uses different endpoints in GCC) |
| 35017 | Default label configured for sensitivity labels | Graph Reader scopes + Purview / AIP Reader | Partial (AIP/Purview uses different endpoints in GCC) |
| 35018 | Downgrade Justification Required for Sensitivity Labels | Graph Reader scopes + Purview / AIP Reader | Partial (AIP/Purview uses different endpoints in GCC) |
| 35019 | Auto-Labeling Policies Configured (All Workloads) | Graph Reader scopes | Yes |
| 35020 | Auto-labeling enforcement mode enabled | Graph Reader scopes | Yes |
| 35021 | Auto-Labeling Policies Enabled for SharePoint and OneDrive | Graph Reader scopes | Yes |
| 35022 | On-Demand scans configured for sensitive information discovery | Graph Reader scopes | Yes |
| 35024 | Azure RMS Licensing Enabled | Graph Reader scopes | Yes |
| 35025 | Internal RMS Licensing Enabled | Graph Reader scopes | Yes |
| 35026 | Office 365 Message Encryption (OME) - SimplifiedClientAccessEnabled | Graph Reader scopes | Yes |
| 35027 | OME Custom Branding Templates | Graph Reader scopes | Yes |
| 35029 | Mail flow rules with rights protection | Graph Reader scopes | Yes |
| 35030 | DLP Policies Enabled | Graph Reader scopes | Yes |
| 35032 | Adaptive Protection in DLP Policies | Graph Reader scopes | Yes |
| 35033 | Custom Sensitive Information Types (SITs) Configured | Graph Reader scopes | Yes |
| 35034 | Exact Data Match (EDM) Configurations | Graph Reader scopes | Yes |
| 35035 | Named Entity SITs usage in Auto-Labeling and DLP policies | Graph Reader scopes | Yes |
| 35036 | Trainable Classifiers Usage in Policies | Graph Reader scopes | Yes |
| 35037 | Purview audit logging enabled | Graph Reader scopes | Yes |
| 35038 | Insider Risk Management Policies Enabled for Risky AI Usage | Graph Reader scopes | Yes |
| 35039 | Copilot Communication Compliance Monitoring Configured | Graph Reader scopes | Yes |
| 35040 | DLP policies are configured for Exchange Online | Graph Reader scopes | Yes |
| 35041 | DLP policies are configured for SharePoint Online and OneDrive | Graph Reader scopes | Yes |
| 35042 | DLP policies are configured for Microsoft Teams | Graph Reader scopes | Yes |
| 35043 | Endpoint DLP is enabled | Graph Reader scopes | Yes |
| 35044 | DLP policies are in enforcement mode | Graph Reader scopes | Yes |
| 35045 | DLP alerts are configured and routed | Graph Reader scopes | Yes |
| 35046 | TLS enforcement is configured for Exchange Online | Graph Reader scopes | Yes |
| 35047 | External sharing for SharePoint is restricted | Graph Reader scopes + SharePoint Reader | Yes |
| 35048 | Retention policies are configured | Graph Reader scopes | Yes |
| 35049 | Data access reviews are configured for sensitive resources | Graph Reader scopes | Yes |
| 35050 | Audit log retention is extended beyond default | Graph Reader scopes | Yes |
| 35051 | Insider Risk Management policies are configured | Graph Reader scopes | Yes |
| 35052 | Microsoft Purview alert policies are configured for data events | Graph Reader scopes | Yes |

## Infrastructure (9 tests)

| Test ID | Test Title | Role / Scope Required | Works in GCC? |
|:---|:---|:---|:---|
| 36001 | Microsoft Defender for Cloud is enabled on Azure subscriptions | Azure Reader (subscription-level) | Partial (requires Azure Government endpoint config) |
| 36002 | Azure subscriptions have no permanent Owner role assignments to individual users | Azure Reader (subscription-level) | Partial (requires Azure Government endpoint config) |
| 36003 | Storage accounts block public blob access | Azure Reader (subscription-level) | Partial (requires Azure Government endpoint config) |
| 36004 | Storage accounts enforce HTTPS-only traffic and minimum TLS 1.2 | Azure Reader (subscription-level) | Partial (requires Azure Government endpoint config) |
| 36005 | Key Vaults have soft delete and purge protection enabled | Azure Reader (subscription-level) | Partial (requires Azure Government endpoint config) |
| 36006 | Azure subscription activity logs are forwarded to a Log Analytics workspace | Azure Reader (subscription-level) | Partial (requires Azure Government endpoint config) |
| 36007 | Just-In-Time VM access is configured for virtual machines | Azure Reader (subscription-level) | Partial (requires Azure Government endpoint config) |
| 36008 | Microsoft Cloud Security Benchmark policy initiative is assigned on Azure subscriptions | Azure Reader (subscription-level) | Partial (requires Azure Government endpoint config) |
| 36009 | Log Analytics workspaces retain data for at least 90 days | Azure Reader (subscription-level) | Partial (requires Azure Government endpoint config) |

## PowerPlatform (8 tests)

| Test ID | Test Title | Role / Scope Required | Works in GCC? |
|:---|:---|:---|:---|
| 37001 | Tenant isolation is enabled in Power Platform | Power Platform Admin or Global Admin + Azure Reader | No (commercial BAP endpoint hardcoded) |
| 37002 | A tenant-level DLP policy is configured in Power Platform | Power Platform Admin or Global Admin + Azure Reader | No (commercial BAP endpoint hardcoded) |
| 37003 | Production and sandbox environments have security groups assigned | Power Platform Admin or Global Admin + Azure Reader | No (commercial BAP endpoint hardcoded) |
| 37004 | Managed Environments have canvas app sharing limits configured | Power Platform Admin or Global Admin + Azure Reader | No (commercial BAP endpoint hardcoded) |
| 37005 | Managed Environments have IP firewall configured | Power Platform Admin or Global Admin + Azure Reader | No (commercial BAP endpoint hardcoded) |
| 37006 | Managed Environments have IP cookie binding enabled | Power Platform Admin or Global Admin + Azure Reader | No (commercial BAP endpoint hardcoded) |
| 37007 | Environments restrict guest user access | Power Platform Admin or Global Admin + Azure Reader | No (commercial BAP endpoint hardcoded) |
| 37008 | Managed Environments have an Azure Virtual Network policy configured | Power Platform Admin or Global Admin + Azure Reader | No (commercial BAP endpoint hardcoded) |

## Uncategorised

| Test ID | Test Title | Role / Scope Required | Works in GCC? |
|:---|:---|:---|:---|
| 21778 | Line-of-business and partner apps use MSAL | Graph Reader scopes | Yes |
| 21779 | Use recent versions of Microsoft Applications | Graph Reader scopes | Yes |
| 21789 | Tenant creation events are triaged | Graph Reader scopes | Yes |
