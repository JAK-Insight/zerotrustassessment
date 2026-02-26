<#
.SYNOPSIS
 Managed Environments have an Azure Virtual Network policy configured
#>
function Test-Assessment-37008 {
    [ZtTest(
        Category = 'Privileged access',
        ImplementationCost = 'High',
        MinimumLicense = ('Free'),
        Pillar = 'PowerPlatform',
        RiskLevel = 'Medium',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 37008,
        Title = 'Managed Environments have an Azure Virtual Network policy configured',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 37008
    $title    = 'Managed Environments have an Azure Virtual Network policy configured'
    $activity = 'Checking Managed Environment VNet policy'
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

    Write-ZtProgress -Activity $activity -Status 'Getting environments'

    $passed       = $false
    $customStatus = $null
    $errorMsg     = $null
    $environments = @()

    try {
        $response     = Invoke-ZtPowerPlatformRequest -Path '/scopes/admin/environments' -ApiVersion '2023-06-01' -ErrorAction Stop
        $environments = @($response.value)
    }
    catch {
        $errorMsg     = $_.Exception.Message
        $customStatus = 'Investigate'
    }

    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add('Unable to retrieve Power Platform environments.')
        $lines.Add('')
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add('')
        $lines.Add('Ensure the assessment account has the **Power Platform Administrator** or **Global Administrator** role.')
    }
    else {
        $managedEnvs = @($environments | Where-Object {
            $level = $null
            if ($_.PSObject.Properties['properties'] -and $_.properties.PSObject.Properties['governanceConfiguration']) {
                $level = $_.properties.governanceConfiguration.protectionLevel
            }
            $level -eq 'Standard'
        })

        if ($managedEnvs.Count -eq 0) {
            $customStatus = 'Investigate'
            $lines.Add('No Managed Environments were found. Managed Environments require a Power Platform Premium or Managed Environment license.')
            $lines.Add('')
            $lines.Add('Enable Managed Environments in [Power Platform Admin Center > Environments](https://admin.powerplatform.microsoft.com/environments).')
        }
        else {
            $noVnet       = [System.Collections.Generic.List[string]]::new()
            $fieldMissing = $false

            foreach ($env in $managedEnvs) {
                $name    = if ($env.properties.PSObject.Properties['displayName']) { $env.properties.displayName } else { $env.name }
                $govCfg  = $env.properties.governanceConfiguration
                $hasVnet = $false

                if ($govCfg.PSObject.Properties['settings']) {
                    $settings = $govCfg.settings
                    if ($settings.PSObject.Properties['networkSettings']) {
                        $net = $settings.networkSettings
                        $hasVnet = ($net.PSObject.Properties['subnetId'] -and -not [string]::IsNullOrEmpty($net.subnetId))
                    }
                    elseif ($settings.PSObject.Properties['extendedSettings']) {
                        $ext = $settings.extendedSettings
                        if ($ext.PSObject.Properties['networkSettings']) {
                            $net = $ext.networkSettings
                            $hasVnet = ($net.PSObject.Properties['subnetId'] -and -not [string]::IsNullOrEmpty($net.subnetId))
                        }
                        elseif ($ext.PSObject.Properties['virtualNetworkSubnetId']) {
                            $hasVnet = (-not [string]::IsNullOrEmpty($ext.virtualNetworkSubnetId))
                        }
                        # Absent field in extendedSettings = not configured; $hasVnet remains $false
                    }
                    else {
                        $fieldMissing = $true
                    }
                }
                else {
                    $fieldMissing = $true
                }

                if (-not $hasVnet) {
                    $noVnet.Add($name)
                }
            }

            if ($fieldMissing) {
                $customStatus = 'Investigate'
                $lines.Add(("{0} Managed Environment(s) found. The Azure VNet policy field could not be confirmed from the API response." -f $managedEnvs.Count))
                $lines.Add('')
                $lines.Add('Please verify Azure VNet policy in [Power Platform Admin Center > Environments > (select Managed Env) > Edit Managed Environments](https://admin.powerplatform.microsoft.com/environments).')
            }
            else {
                $passed = ($noVnet.Count -eq 0)

                if ($passed) {
                    $lines.Add(("All **{0}** Managed Environment(s) have an Azure Virtual Network policy configured. Power Platform traffic is routed through your private VNet." -f $managedEnvs.Count))
                }
                else {
                    $lines.Add(("**{0}** of {1} Managed Environment(s) do not have an Azure Virtual Network policy configured. Without VNet integration, Power Platform connectors use shared Microsoft infrastructure." -f $noVnet.Count, $managedEnvs.Count))
                    $lines.Add('')
                    $lines.Add('Configure an Azure VNet policy in [Power Platform Admin Center > Environments > (select env) > Edit Managed Environments](https://admin.powerplatform.microsoft.com/environments).')
                }

                $lines.Add('')
                $lines.Add('| Environment | VNet Policy |')
                $lines.Add('|:---|:---|')
                foreach ($env in ($managedEnvs | Sort-Object { $_.properties.displayName })) {
                    $name   = if ($env.properties.PSObject.Properties['displayName']) { $env.properties.displayName } else { $env.name }
                    $status = if ($noVnet -contains $name) { 'Not configured' } else { 'Configured' }
                    $lines.Add(("| {0} | {1} |" -f $name, $status))
                }
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
