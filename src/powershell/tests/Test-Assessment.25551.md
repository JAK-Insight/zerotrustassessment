Named locations in Microsoft Entra ID Conditional Access allow organizations to define specific IP address ranges or countries that represent known, trusted network boundaries — such as corporate office egress IPs, VPN exit points, or headquarters subnets. When named locations are absent or unused in Conditional Access policies, the organization has no IP-based network perimeter enforcement: every authentication request is treated identically regardless of whether it originates from a controlled corporate network or an attacker-controlled endpoint anywhere on the internet.

Without IP-based named locations in Conditional Access, a threat actor who obtains valid user credentials through phishing or credential theft can authenticate from any network location without triggering additional scrutiny. Conditional Access policies that should require multifactor authentication from untrusted networks, block access from high-risk geographies, or enforce device compliance from unknown locations cannot function correctly. Sign-in risk detection also loses a key signal: anomalous network location cannot be identified if all locations are treated as equivalent.

Defining IP-based named locations and referencing them in at least one active Conditional Access policy is a foundational Zero Trust network control. It establishes the concept of a trusted network perimeter within the identity plane, enables location-aware MFA step-up requirements, and provides the baseline for more advanced controls such as Global Secure Access compliant network enforcement.

**Remediation action**

1. Sign in as Global Administrator or Conditional Access Administrator to the [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Protection** > **Conditional Access** > [Named locations](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/NamedLocations)
3. Select **+ IP ranges location** and define your corporate egress IP ranges (IPv4 or IPv6 CIDR notation)
4. Mark well-known corporate ranges as **Trusted** to enable trusted IP-based MFA bypass and risk signal tuning
5. Navigate to **Policies** and edit or create a Conditional Access policy that includes or excludes the named location in its **Network** conditions
6. Common patterns:
   - Require MFA for all access **except** from trusted named locations
   - Block access from specific countries using country-based named locations
   - Require compliant device from unnamed/untrusted locations

**Query via PowerShell**

```powershell
Connect-MgGraph -Scopes "Policy.Read.All"

# List all named locations
Get-MgIdentityConditionalAccessNamedLocation | Select-Object DisplayName, Id,
    @{N='Type';E={$_.'@odata.type'}},
    @{N='Trusted';E={$_.AdditionalProperties.isTrusted}}

# List enabled CA policies that reference named locations
Get-MgIdentityConditionalAccessPolicy -Filter "state eq 'enabled'" |
    Where-Object {
        $_.Conditions.Locations.IncludeLocations -or
        $_.Conditions.Locations.ExcludeLocations
    } |
    Select-Object DisplayName, @{N='IncludeLocations';E={$_.Conditions.Locations.IncludeLocations -join ', '}},
        @{N='ExcludeLocations';E={$_.Conditions.Locations.ExcludeLocations -join ', '}}
```

<!--- Results --->
%TestResult%
