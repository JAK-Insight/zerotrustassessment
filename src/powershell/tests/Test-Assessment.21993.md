Microsoft Entra Agent ID (introduced in 2025) allows organizations to register AI agents as first-class identities in Entra ID. These agent identities are specialized service principals that AI workloads use to authenticate and access Microsoft resources, including Microsoft Graph, SharePoint, Teams, and external APIs. Without proper governance, agent identities can accumulate excessive permissions, remain active after their purpose has ended, or operate without any human accountability — creating a significant and rapidly growing attack surface.

The sponsorship model in Microsoft Entra Agent ID addresses the accountability gap by requiring every agent identity to have a designated human sponsor. The sponsor is the internal user responsible for the agent's access, permissions, and lifecycle. When a sponsor leaves the organization, Entra ID automatically transfers sponsorship to the departing user's manager, ensuring continuity of accountability. Sponsors can also request access on behalf of the agent identity through the entitlement management system. Without a sponsor, an agent identity can become an orphaned identity with unchecked access to sensitive resources.

Assigning sponsors to all agent identities establishes clear human oversight for every AI agent operating in your tenant. This is a foundational control for governing the growing number of AI workloads in enterprise environments and aligns with Zero Trust principles by ensuring that no identity — human or AI — operates without explicit accountability.

**Remediation action**

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Applications** > **Agent ID** (or browse to the Entra Agent ID blade)
3. For each agent identity listed, select the agent and navigate to its **Properties** or **Governance** section
4. Under **Sponsors**, click **Add** and select the internal user or group responsible for this agent
5. Save the changes
6. Repeat for all agent identities that lack a sponsor

**Permissions required**

This check requires the **AgentIdentity.Read.All** permission (currently in preview) to list agent identities and their sponsors via the Microsoft Graph Beta API.

**Query via PowerShell**

```powershell
# Requires Microsoft Graph PowerShell with AgentIdentity.Read.All permission
Connect-MgGraph -Scopes 'AgentIdentity.Read.All'

# List all agent identities
$agents = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/agentIdentities' |
    Select-Object -ExpandProperty value

# Check sponsors for each agent
foreach ($agent in $agents) {
    $sponsors = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/agentIdentities/$($agent.id)/sponsors" |
        Select-Object -ExpandProperty value

    [PSCustomObject]@{
        AgentName    = $agent.displayName
        AgentId      = $agent.id
        SponsorCount = $sponsors.Count
        Sponsors     = ($sponsors | Select-Object -ExpandProperty displayName) -join ', '
    }
}
```

<!--- Results --->
%TestResult%
