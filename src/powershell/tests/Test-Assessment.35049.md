Access reviews help organizations maintain least-privilege access by periodically validating who still needs access to sensitive resources. Without recurring access reviews, users may retain access long after job changes, project completion, or role transitions, increasing the risk of unintended data exposure.

This check evaluates whether Microsoft Entra ID Access Reviews are configured for sensitive resources such as groups, applications, and other entitlements that commonly grant access to data. Recurring access reviews are preferred because they continuously validate access over time rather than relying on one-time attestations.

---

## Remediation action

1. In the Microsoft Entra admin center, go to **Identity governance** → **Access reviews**
2. Create access reviews for high-risk resources, such as:
   - Groups that grant access to SharePoint, Teams, or OneDrive content
   - Applications that provide access to sensitive data stores
   - Privileged roles or other high-impact entitlements
3. Configure each access review to be **recurring** (weekly, monthly, or quarterly)
4. Assign appropriate reviewers (group owners, managers, or security personnel)
5. Configure automated actions for non-responders (for example, remove access or require justification)

---

## Graph validation (conceptual)

```text
GET /identityGovernance/accessReviews/definitions
GET /identityGovernance/accessReviews/definitions/{id}/instances
```

<!--- Results --->
%TestResult%
