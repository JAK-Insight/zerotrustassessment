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
    $customStatus   = 'Investigate'
    $errorMsg       = $null
    $tenantSettings = $null

    # The tenant isolation on/off status is not exposed by the public BAP REST API.
    # POST /listTenantSettings returns general governance settings but does NOT
    # include the isolation toggle.  We call it to verify connectivity and surface
    # related governance settings alongside manual verification steps.
    try {
        $tenantSettings = Invoke-ZtPowerPlatformRequest -Path '/listTenantSettings' -Method POST -ApiVersion '2023-06-01' -ErrorAction Stop
    }
    catch {
        $errorMsg = $_.Exception.Message
    }

    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add('Unable to retrieve Power Platform tenant settings.')
        $lines.Add('')
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add('')
        $lines.Add('Ensure the assessment account has the **Power Platform Administrator** or **Global Administrator** role.')
    }
    else {
        # The listTenantSettings response does not include the tenant isolation
        # toggle — that setting is only accessible through the Power Platform
        # Admin Center UI or the Microsoft.PowerApps.Administration.PowerShell module.
        $lines.Add('The tenant isolation status cannot be determined automatically. The Power Platform Admin API does not expose the isolation toggle through its public REST endpoints.')
        $lines.Add('')
        $lines.Add('**Please verify tenant isolation manually:**')
        $lines.Add('')
        $lines.Add('1. Sign in to the [Power Platform Admin Center](https://admin.powerplatform.microsoft.com)')
        $lines.Add('2. Navigate to **Security** > **Identity and access** > **Tenant isolation**')
        $lines.Add('3. Confirm that **Restrict cross-tenant connections** is **Enabled** with the desired inbound/outbound rules')
        $lines.Add('')

        # Surface related governance settings that ARE available in the API
        $gov = $null
        if ($tenantSettings.PSObject.Properties['powerPlatform'] -and
            $tenantSettings.powerPlatform.PSObject.Properties['governance']) {
            $gov = $tenantSettings.powerPlatform.governance
        }

        $lines.Add('The following related governance settings were read from the tenant:')
        $lines.Add('')
        $lines.Add('| Setting | Value |')
        $lines.Add('|:---|:---|')

        # Environment creation
        $envCreateDisabled = $tenantSettings.disableEnvironmentCreationByNonAdminUsers
        $lines.Add(("| Non-admin environment creation disabled | {0} |" -f $(if ($envCreateDisabled) { 'Yes' } else { 'No' })))

        # Trial environment creation
        $trialDisabled = $tenantSettings.disableTrialEnvironmentCreationByNonAdminUsers
        $lines.Add(("| Non-admin trial environment creation disabled | {0} |" -f $(if ($trialDisabled) { 'Yes' } else { 'No' })))

        if ($gov) {
            # Developer environment creation
            if ($gov.PSObject.Properties['disableDeveloperEnvironmentCreationByNonAdminUsers']) {
                $devDisabled = $gov.disableDeveloperEnvironmentCreationByNonAdminUsers
                $lines.Add(("| Non-admin developer environment creation disabled | {0} |" -f $(if ($devDisabled) { 'Yes' } else { 'No' })))
            }
            # Default environment routing
            if ($gov.PSObject.Properties['enableDefaultEnvironmentRouting']) {
                $lines.Add(("| Default environment routing enabled | {0} |" -f $(if ($gov.enableDefaultEnvironmentRouting) { 'Yes' } else { 'No' })))
            }
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
