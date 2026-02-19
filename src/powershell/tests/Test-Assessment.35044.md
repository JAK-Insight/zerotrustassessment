DLP policies in enforcement mode actively prevent data loss by blocking or restricting actions when sensitive information is detected. Policies that run only in simulation/test mode provide visibility and reporting, but do not prevent data loss.

This check evaluates whether the tenant has at least one DLP policy actively enforcing (enabled) rather than only simulation/test policies. If no DLP policies are enforcing, sensitive information may be detected but not protected.

**Remediation action**
1. Sign in to the [Microsoft Purview portal2. Navigate to [DLPPolicies
3. Identify policies in simulation mode and review match reports in Activity Explorer
4. Promote at least one appropriate policy to enforcement:
   - Change from **Run in simulation** to **Turn it on right away**
5. Validate that the enforcing policy includes the relevant locations (Exchange, SharePoint, OneDrive, Teams, Devices)

**Query via PowerShell**
```powershell
Connect-IPPSSession

Get-DlpCompliancePolicy |
  Select-Object Name, Mode,
    @{N='Locations';E={
      $loc=@()
      if ($_.ExchangeLocation) { $loc += 'Exchange' }
      if ($_.SharePointLocation) { $loc += 'SharePoint' }
      if ($_.OneDriveLocation) { $loc += 'OneDrive' }
      if ($_.TeamsLocation) { $loc += 'Teams' }
      if ($_.EndpointDlpLocation) { $loc += 'Endpoints' }
      if ($loc.Count -gt 0) { $loc -join ', ' } else { 'None' }
    }} |
  Sort-Object Mode, Name |
  Format-Table -AutoSize
```
<!--- Results --->
%TestResult%
