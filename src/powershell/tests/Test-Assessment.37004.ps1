<#
.SYNOPSIS
 Managed Environments have canvas app sharing limits configured
#>
function Test-Assessment-37004 {
    [ZtTest(
        Category = 'Privileged access',
        ImplementationCost = 'Low',
        MinimumLicense = ('Free'),
        Pillar = 'PowerPlatform',
        RiskLevel = 'Medium',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 37004,
        Title = 'Managed Environments have canvas app sharing limits configured',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 37004
    $title    = 'Managed Environments have canvas app sharing limits configured'
    $activity = 'Checking Managed Environment sharing limits'
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
        # Managed Environments have protectionLevel = 'Standard' in governanceConfiguration
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
            $lines.Add('Enable Managed Environments in [Power Platform Admin Center > Environments](https://admin.powerplatform.microsoft.com/environments) to access advanced governance controls.')
        }
        else {
            # Check if sharing limits are configured
            $noLimit = [System.Collections.Generic.List[string]]::new()
            $fieldMissing = $false

            foreach ($env in $managedEnvs) {
                $name    = if ($env.properties.PSObject.Properties['displayName']) { $env.properties.displayName } else { $env.name }
                $govCfg  = $env.properties.governanceConfiguration
                $hasLimit = $false

                if ($govCfg.PSObject.Properties['settings']) {
                    $settings = $govCfg.settings
                    # Check for sharing limit fields (field names may vary by API version)
                    if ($settings.PSObject.Properties['limitSharingMode']) {
                        $hasLimit = ($settings.limitSharingMode -ne 'NoLimit' -and -not [string]::IsNullOrEmpty($settings.limitSharingMode))
                    }
                    elseif ($settings.PSObject.Properties['extendedSettings']) {
                        $ext = $settings.extendedSettings
                        if ($ext.PSObject.Properties['limitSharingMode']) {
                            $hasLimit = ($ext.limitSharingMode -ne 'NoLimit' -and -not [string]::IsNullOrEmpty($ext.limitSharingMode))
                        }
                        elseif ($ext.PSObject.Properties['sharingSettings']) {
                            $hasLimit = $true # Any sharing settings object = configured
                        }
                        else {
                            $fieldMissing = $true
                        }
                    }
                    else {
                        $fieldMissing = $true
                    }
                }
                else {
                    $fieldMissing = $true
                }

                if (-not $hasLimit) {
                    $noLimit.Add($name)
                }
            }

            if ($fieldMissing) {
                $customStatus = 'Investigate'
                $lines.Add(("{0} Managed Environment(s) found. The sharing limits field could not be confirmed from the API response." -f $managedEnvs.Count))
                $lines.Add('')
                $lines.Add('Please verify canvas app sharing limits in [Power Platform Admin Center > Environments > (select Managed Env) > Edit Managed Environments](https://admin.powerplatform.microsoft.com/environments).')
            }
            else {
                $passed = ($noLimit.Count -eq 0)

                if ($passed) {
                    $lines.Add(("All **{0}** Managed Environment(s) have canvas app sharing limits configured." -f $managedEnvs.Count))
                }
                else {
                    $lines.Add(("**{0}** of {1} Managed Environment(s) do not have canvas app sharing limits configured. Without sharing limits, users can share apps with the entire organization." -f $noLimit.Count, $managedEnvs.Count))
                    $lines.Add('')
                    $lines.Add('Configure sharing limits in [Power Platform Admin Center > Environments > (select env) > Edit Managed Environments](https://admin.powerplatform.microsoft.com/environments).')
                }

                $lines.Add('')
                $lines.Add('| Environment | Sharing Limit |')
                $lines.Add('|:---|:---|')
                foreach ($env in ($managedEnvs | Sort-Object { $_.properties.displayName })) {
                    $name   = if ($env.properties.PSObject.Properties['displayName']) { $env.properties.displayName } else { $env.name }
                    $status = if ($noLimit -contains $name) { 'Not configured' } else { 'Configured' }
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
