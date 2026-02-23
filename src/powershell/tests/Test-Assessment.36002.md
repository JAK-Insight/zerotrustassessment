The Owner role in Azure grants unrestricted access to all resources in a subscription, including the ability to assign roles to other users, delete resources, modify security settings, and access all data. It is the most privileged standing role in Azure RBAC. When individual user accounts are assigned as permanent Owners of Azure subscriptions, the risk surface extends to every credential compromise, phishing attack, or insider threat targeting those accounts. A single compromised Owner account can enumerate, exfiltrate, and destroy all resources in the subscription.

Zero Trust principles require that permanent standing privileged access be eliminated in favor of just-in-time access. For Azure subscription ownership, this means Owner assignments should not be made directly to individual user accounts. Instead, Owner access should be granted through Microsoft Entra ID Privileged Identity Management (PIM) as eligible role assignments that require activation, approval, and justification before access is granted. Where a service identity or automation account needs Owner access, managed identities and service principals scoped to specific resources are preferable to broad subscription-level assignments.

When Owner access must be assigned permanently (e.g., for break-glass emergency accounts), it should be assigned to a group rather than to individual user accounts, the group should have no more than 2-3 members, and all activation events should be monitored via Microsoft Sentinel or a SIEM. This test checks for individual user accounts with permanent Owner assignments directly at the subscription scope.

**Remediation action**

1. Sign in to the [Azure portal](https://portal.azure.com) as a Privileged Role Administrator
2. For each user listed below, navigate to **Subscriptions** > select the subscription > **Access control (IAM)**
3. Review the Owner role assignments and identify any that are assigned directly to individual users
4. Convert direct user Owner assignments to [PIM eligible assignments](https://learn.microsoft.com/en-us/azure/role-based-access-control/pim-resource-roles-assign-roles) or reassign to a group
5. Consider enabling [PIM alerts](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-resource-roles-configure-alerts) for permanent privileged assignments

**Query via PowerShell**

```powershell
Connect-AzAccount

# Find users with permanent Owner on subscriptions
$ownerRoleId = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
Get-AzSubscription | ForEach-Object {
    $sub = $_
    Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -RoleDefinitionId $ownerRoleId |
        Where-Object { $_.ObjectType -eq 'User' } |
        Select-Object DisplayName, SignInName, @{N='Subscription';E={$sub.Name}}
}
```

<!--- Results --->
%TestResult%
