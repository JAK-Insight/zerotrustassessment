<#
.SYNOPSIS
 Managed Environments have IP cookie binding enabled
#>
function Test-Assessment-37006 {
    [ZtTest(
        Category = 'Privileged access',
        ImplementationCost = 'Low',
        MinimumLicense = ('Free'),
        Pillar = 'PowerPlatform',
        RiskLevel = 'Medium',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 37006,
        Title = 'Managed Environments have IP cookie binding enabled',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 37006
    $title    = 'Managed Environments have IP cookie binding enabled'
    $activity = 'Checking Managed Environment IP cookie binding'
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
            $noCookieBinding = [System.Collections.Generic.List[string]]::new()
            $fieldMissing    = $false

            foreach ($env in $managedEnvs) {
                $name      = if ($env.properties.PSObject.Properties['displayName']) { $env.properties.displayName } else { $env.name }
                $govCfg    = $env.properties.governanceConfiguration
                $hasBinding = $false

                if ($govCfg.PSObject.Properties['settings']) {
                    $settings = $govCfg.settings
                    if ($settings.PSObject.Properties['ipFirewallSettings']) {
                        $fw = $settings.ipFirewallSettings
                        if ($fw.PSObject.Properties['enableIpBasedCookieBinding']) {
                            $hasBinding = ($fw.enableIpBasedCookieBinding -eq $true)
                        }
                        else {
                            $fieldMissing = $true
                        }
                    }
                    elseif ($settings.PSObject.Properties['extendedSettings']) {
                        $ext = $settings.extendedSettings
                        if ($ext.PSObject.Properties['enableIpBasedCookieBinding']) {
                            $hasBinding = ($ext.enableIpBasedCookieBinding -eq $true)
                        }
                        elseif ($ext.PSObject.Properties['ipFirewallSettings'] -and `
                                $ext.ipFirewallSettings.PSObject.Properties['enableIpBasedCookieBinding']) {
                            $hasBinding = ($ext.ipFirewallSettings.enableIpBasedCookieBinding -eq $true)
                        }
                        # Absent field in extendedSettings = not configured; $hasBinding remains $false
                    }
                    else {
                        $fieldMissing = $true
                    }
                }
                else {
                    $fieldMissing = $true
                }

                if (-not $hasBinding) {
                    $noCookieBinding.Add($name)
                }
            }

            if ($fieldMissing) {
                $customStatus = 'Investigate'
                $lines.Add(("{0} Managed Environment(s) found. The IP cookie binding field could not be confirmed from the API response." -f $managedEnvs.Count))
                $lines.Add('')
                $lines.Add('Please verify IP cookie binding settings in [Power Platform Admin Center > Environments > (select Managed Env) > Edit Managed Environments](https://admin.powerplatform.microsoft.com/environments).')
            }
            else {
                $passed = ($noCookieBinding.Count -eq 0)

                if ($passed) {
                    $lines.Add(("All **{0}** Managed Environment(s) have IP cookie binding enabled. Session cookies are bound to the user IP address." -f $managedEnvs.Count))
                }
                else {
                    $lines.Add(("**{0}** of {1} Managed Environment(s) do not have IP cookie binding enabled. Enable IP cookie binding to prevent session token replay attacks." -f $noCookieBinding.Count, $managedEnvs.Count))
                    $lines.Add('')
                    $lines.Add('Enable IP cookie binding in [Power Platform Admin Center > Environments > (select env) > Edit Managed Environments](https://admin.powerplatform.microsoft.com/environments).')
                }

                $lines.Add('')
                $lines.Add('| Environment | IP Cookie Binding |')
                $lines.Add('|:---|:---|')
                foreach ($env in ($managedEnvs | Sort-Object { $_.properties.displayName })) {
                    $name   = if ($env.properties.PSObject.Properties['displayName']) { $env.properties.displayName } else { $env.name }
                    $status = if ($noCookieBinding -contains $name) { 'Not enabled' } else { 'Enabled' }
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
