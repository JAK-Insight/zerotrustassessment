Access reviews help organizations maintain least-privilege access by periodically validating who still needs access to sensitive resources. Without recurring access reviews, users may retain access long after job changes, project completion, or role transitions, increasing the risk of data exposure.

This check evaluates whether Microsoft Entra ID Access Reviews are configured for sensitive resources such as groups, applications, and other entitlements that commonly grant access to data. Recurring access reviews are preferred because they continuously validate access over time.

**Remediation action**
1. In the Microsoft Entra admin center, go to **Identity governance** > **Access reviews**
2. Create an access review for high-risk resources:
   - Groups that grant access to SharePoint/Teams/OneDrive content
   - Applications that provide access to data stores
   - Privileged roles or high-impact entitlements
3. Configure the review to be **recurring** (weekly/monthly/quarterly)
4. Assign reviewers (group owners, managers, or security)
5. Configure automated actions for non-responders (remove access, require justification, etc.)

**Graph validation (conceptual)**
```text
GET /identityGovernance/accessReviews/definitions
GET /identityGovernance/accessReviews/definitions/{id}/instances
```
<!--- Results --->
%TestResult%
