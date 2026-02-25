<#
.SYNOPSIS
 A tenant-level DLP policy is configured in Power Platform
#>
function Test-Assessment-37002 {
    [ZtTest(
        Category = 'Identity governance',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Free'),
        Pillar = 'PowerPlatform',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 37002,
        Title = 'A tenant-level DLP policy is configured in Power Platform',
        UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 37002
    $title    = 'A tenant-level DLP policy is configured in Power Platform'
    $activity = 'Checking Power Platform DLP policies'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    try {
        $azToken = Get-AzAccessToken -AsSecureString -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    catch {
        Write-PSFMessage $_.Exception.Message -Tag Test -Level Warning
    }

    if (!$azToken) {
        Add-ZtTestResultDetail -SkippedBecause NotConnectedAzure
        return
    }

    Write-ZtProgress -Activity $activity -Status 'Getting DLP policies'

    $passed       = $false
    $customStatus = $null
    $errorMsg     = $null
    $policies     = @()

    try {
        $response = Invoke-ZtPowerPlatformRequest -Path '/scopes/admin/apiPolicies' -ApiVersion '2016-11-01' -ErrorAction Stop
        $policies = @($response.value)
    }
    catch {
        $errorMsg     = $_.Exception.Message
        $customStatus = 'Investigate'
    }

    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add('Unable to retrieve Power Platform DLP policies.')
        $lines.Add('')
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add('')
        $lines.Add('Ensure the assessment account has the **Power Platform Administrator** or **Global Administrator** role.')
    }
    elseif ($policies.Count -eq 0) {
        $lines.Add('No DLP policies are configured. At least one tenant-level DLP policy is recommended to govern connector usage.')
        $lines.Add('')
        $lines.Add('Create a DLP policy in [Power Platform Admin Center > Policies > Data policies](https://admin.powerplatform.microsoft.com/dlp).')
    }
    else {
        # A tenant-level policy applies to AllEnvironments or has no environment filter
        $tenantWidePolicies = @($policies | Where-Object {
            $envType = $null
            if ($_.PSObject.Properties['properties'] -and $_.properties.PSObject.Properties['environmentType']) {
                $envType = $_.properties.environmentType
            }
            ([string]::IsNullOrEmpty($envType)) -or ($envType -eq 'AllEnvironments')
        })

        $passed = ($tenantWidePolicies.Count -gt 0)

        if ($passed) {
            $lines.Add(("**{0}** tenant-level DLP polic{1} configured ({2} total)." -f $tenantWidePolicies.Count, (if ($tenantWidePolicies.Count -eq 1) { 'y is' } else { 'ies are' }), $policies.Count))
        }
        else {
            $lines.Add(("**{0}** DLP polic{1} configured, but none apply at the tenant level." -f $policies.Count, (if ($policies.Count -eq 1) { 'y is' } else { 'ies are' })))
            $lines.Add('')
            $lines.Add('Create an **All environments** DLP policy to establish a tenant-wide baseline for connector governance.')
        }

        $lines.Add('')
        $lines.Add('| Policy Name | Scope |')
        $lines.Add('|:---|:---|')
        foreach ($policy in ($policies | Sort-Object { $_.displayName })) {
            $name = if ($policy.PSObject.Properties['displayName']) { $policy.displayName } else { '(unnamed)' }
            $envType = $null
            if ($policy.PSObject.Properties['properties'] -and $policy.properties.PSObject.Properties['environmentType']) {
                $envType = $policy.properties.environmentType
            }
            $scope = if ([string]::IsNullOrEmpty($envType)) { 'All environments' } else { $envType }
            $lines.Add(("| {0} | {1} |" -f $name, $scope))
        }
    }

    $mdInfo = ($lines -join "`n")

    if (-not (Test-Path $mdPath)) {
        $customStatus = 'Investigate'
        Write-PSFMessage ("Missing markdown file: {0}" -f $mdPath) -Level Warning
    }

    $params = @{
        TestId = "$testId"
        Title  = $title
        Status = $passed
        Result = $mdInfo
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }

    Add-ZtTestResultDetail @params
}
