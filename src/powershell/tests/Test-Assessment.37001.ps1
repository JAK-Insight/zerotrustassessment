<#
.SYNOPSIS
 Tenant isolation is enabled in Power Platform
#>
function Test-Assessment-37001 {
    [ZtTest(
        Category = 'Identity governance',
        ImplementationCost = 'Low',
        MinimumLicense = ('Free'),
        Pillar = 'PowerPlatform',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 37001,
        Title = 'Tenant isolation is enabled in Power Platform',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 37001
    $title    = 'Tenant isolation is enabled in Power Platform'
    $activity = 'Checking Power Platform tenant isolation'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    # Check Azure connection (PP auth piggybacks on Azure token)
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

    Write-ZtProgress -Activity $activity -Status 'Getting tenant settings'

    $passed         = $false
    $customStatus   = $null
    $errorMsg       = $null
    $apiHttpStatus  = $null
    $tenantSettings = $null

    # Try multiple known paths for tenant settings
    $tsPaths = @(
        @{ Path = '/scopes/admin/tenantSettings'; Version = '2023-06-01' },
        @{ Path = '/scopes/admin/tenantSettings'; Version = '2020-10-01' },
        @{ Path = '/tenantSettings';              Version = '2023-06-01' }
    )
    foreach ($attempt in $tsPaths) {
        try {
            $tenantSettings = Invoke-ZtPowerPlatformRequest -Path $attempt.Path -ApiVersion $attempt.Version -ErrorAction Stop
            break
        }
        catch {
            $resp = $_.Exception.Response
            if ($resp) { $apiHttpStatus = [int]$resp.StatusCode }
            $errorMsg = $_.Exception.Message
        }
    }
    if ($tenantSettings) { $errorMsg = $null; $apiHttpStatus = $null }
    $customStatus = if ($tenantSettings) { $null } else { 'Investigate' }

    $lines = New-Object System.Collections.Generic.List[string]

    if ($apiHttpStatus -in 403, 404) {
        $lines.Add(('The Power Platform tenant settings API returned HTTP {0}.' -f $apiHttpStatus))
        $lines.Add('')
        $lines.Add('This endpoint may require the **Power Platform Administrator** role. An account with only the Global Administrator role may not have access to tenant-level Power Platform policy settings.')
        $lines.Add('')
        $lines.Add('Please verify tenant isolation manually:')
        $lines.Add('1. Sign in to the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com/policies/tenant-isolation)')
        $lines.Add('2. Navigate to **Policies > Tenant isolation**')
        $lines.Add('3. Confirm that tenant isolation is **Enabled** with the desired inbound/outbound restriction')
    }
    elseif ($errorMsg) {
        $lines.Add('Unable to retrieve Power Platform tenant settings.')
        $lines.Add('')
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add('')
        $lines.Add('Ensure the assessment account has the **Power Platform Administrator** or **Global Administrator** role.')
    }
    else {
        $isolationMode  = $null
        $isolationFound = $false

        if ($tenantSettings.PSObject.Properties['properties']) {
            $props = $tenantSettings.properties
            # Try tenantIsolationSettings.allowedIntegrationTargets
            if ($props.PSObject.Properties['tenantIsolationSettings']) {
                $iso = $props.tenantIsolationSettings
                if ($iso.PSObject.Properties['allowedIntegrationTargets']) {
                    $isolationMode  = $iso.allowedIntegrationTargets
                    $isolationFound = $true
                    $passed = ($isolationMode -ne 'None')
                }
                elseif ($iso.PSObject.Properties['isDisabled']) {
                    $isolationMode  = if (-not $iso.isDisabled) { 'Enabled' } else { 'None' }
                    $isolationFound = $true
                    $passed = (-not $iso.isDisabled)
                }
            }
            # Try powerPlatform.governance.enableTenantIsolation
            elseif ($props.PSObject.Properties['powerPlatform'] -and $props.powerPlatform.PSObject.Properties['governance']) {
                $gov = $props.powerPlatform.governance
                if ($gov.PSObject.Properties['enableTenantIsolation']) {
                    $isolationMode  = if ($gov.enableTenantIsolation) { 'Enabled' } else { 'None' }
                    $isolationFound = $true
                    $passed = $gov.enableTenantIsolation
                }
            }
        }

        if (-not $isolationFound) {
            $customStatus = 'Investigate'
            $lines.Add('The tenant isolation setting could not be read from the Power Platform Admin API response.')
            $lines.Add('')
            $lines.Add('Please verify the tenant isolation status in the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com/policies/tenant-isolation).')
        }
        else {
            if ($passed) {
                $lines.Add(("Tenant isolation is enabled (mode: **{0}**). Cross-tenant connector connections are restricted." -f $isolationMode))
            }
            else {
                $lines.Add('Tenant isolation is **not enabled**. External tenants can make inbound/outbound Power Platform connections to your tenant.')
                $lines.Add('')
                $lines.Add('Enable tenant isolation in [Power Platform Admin Center > Policies > Tenant isolation](https://admin.powerplatform.microsoft.com/policies/tenant-isolation).')
            }
            $lines.Add('')
            $lines.Add('| Setting | Value |')
            $lines.Add('|:---|:---|')
            $lines.Add(("| Isolation mode | {0} |" -f $isolationMode))
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
