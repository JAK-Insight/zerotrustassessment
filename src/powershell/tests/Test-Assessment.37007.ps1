<#
.SYNOPSIS
 Environments restrict guest user access
#>
function Test-Assessment-37007 {
    [ZtTest(
        Category = 'Access control',
        ImplementationCost = 'Low',
        MinimumLicense = ('Free'),
        Pillar = 'PowerPlatform',
        RiskLevel = 'Medium',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 37007,
        Title = 'Environments restrict guest user access',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 37007
    $title    = 'Environments restrict guest user access'
    $activity = 'Checking Power Platform guest access settings'
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
        # Check Managed Environments - the guest maker governance setting applies to Managed Environments
        $targetEnvs = @($environments | Where-Object {
            $level = $null
            if ($_.PSObject.Properties['properties'] -and $_.properties.PSObject.Properties['governanceConfiguration']) {
                $level = $_.properties.governanceConfiguration.protectionLevel
            }
            $level -eq 'Standard'
        })

        if ($targetEnvs.Count -eq 0) {
            $customStatus = 'Investigate'
            $lines.Add('No Managed Environments were found. The guest maker restriction setting is available for Managed Environments.')
            $lines.Add('')
            $lines.Add('Enable Managed Environments in [Power Platform Admin Center > Environments](https://admin.powerplatform.microsoft.com/environments) to access advanced governance controls including guest access restrictions.')
        }
        else {
            $noRestriction = [System.Collections.Generic.List[string]]::new()
            $fieldMissing  = $false

            foreach ($env in $targetEnvs) {
                $name         = if ($env.properties.PSObject.Properties['displayName']) { $env.properties.displayName } else { $env.name }
                $hasRestriction = $false

                if ($env.PSObject.Properties['properties']) {
                    $p = $env.properties
                    # Check various field names for guest access restriction
                    if ($p.PSObject.Properties['guestMakerSettings']) {
                        $gms = $p.guestMakerSettings
                        if ($gms.PSObject.Properties['isGuesstsAllowed']) {
                            $hasRestriction = ($gms.isGuesstsAllowed -eq $false)
                        }
                        elseif ($gms.PSObject.Properties['isGuestMakerEnabled']) {
                            $hasRestriction = ($gms.isGuestMakerEnabled -eq $false)
                        }
                        else {
                            $fieldMissing = $true
                        }
                    }
                    elseif ($p.PSObject.Properties['governanceConfiguration']) {
                        $govCfg = $p.governanceConfiguration
                        if ($govCfg.PSObject.Properties['settings']) {
                            $ext = $govCfg.settings
                            if ($ext.PSObject.Properties['extendedSettings']) { $ext = $ext.extendedSettings }
                            if ($ext.PSObject.Properties['disableGuestMakerFeature']) {
                                # String "true"/"false" in extendedSettings
                                $hasRestriction = ($ext.disableGuestMakerFeature -eq 'true' -or $ext.disableGuestMakerFeature -eq $true)
                            }
                            elseif ($ext.PSObject.Properties['guestMakerSettings']) {
                                $gms = $ext.guestMakerSettings
                                if ($gms.PSObject.Properties['isGuestMakerEnabled']) {
                                    $hasRestriction = ($gms.isGuestMakerEnabled -eq $false)
                                }
                                # Absent sub-field = not configured
                            }
                            # Absent field in extendedSettings = not restricted; $hasRestriction remains $false
                        }
                        else {
                            $fieldMissing = $true
                        }
                    }
                    else {
                        $fieldMissing = $true
                    }
                }

                if (-not $hasRestriction) {
                    $noRestriction.Add($name)
                }
            }

            if ($fieldMissing) {
                $customStatus = 'Investigate'
                $lines.Add(("{0} Managed Environment(s) found. The guest access restriction field could not be confirmed from the API response." -f $targetEnvs.Count))
                $lines.Add('')
                $lines.Add('Please verify guest access settings in [Power Platform Admin Center > Environments > (select env) > Settings > Features](https://admin.powerplatform.microsoft.com/environments).')
            }
            else {
                $passed = ($noRestriction.Count -eq 0)

                if ($passed) {
                    $lines.Add(("All **{0}** Managed Environment(s) restrict guest user access." -f $targetEnvs.Count))
                }
                else {
                    $lines.Add(("**{0}** of {1} Managed Environment(s) allow guest user access. Guest users may create apps and flows, increasing the risk of data exfiltration." -f $noRestriction.Count, $targetEnvs.Count))
                    $lines.Add('')
                    $lines.Add('Disable guest maker access in [Power Platform Admin Center > Environments > (select env) > Settings > Features](https://admin.powerplatform.microsoft.com/environments).')
                }

                $lines.Add('')
                $lines.Add('| Environment | Guest Access |')
                $lines.Add('|:---|:---|')
                foreach ($env in ($targetEnvs | Sort-Object { $_.properties.displayName })) {
                    $name   = if ($env.properties.PSObject.Properties['displayName']) { $env.properties.displayName } else { $env.name }
                    $status = if ($noRestriction -contains $name) { 'Not restricted' } else { 'Restricted' }
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
