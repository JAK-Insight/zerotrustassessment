<#
.SYNOPSIS
 Production and sandbox environments have security groups assigned
#>
function Test-Assessment-37003 {
    [ZtTest(
        Category = 'Access control',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Free'),
        Pillar = 'PowerPlatform',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 37003,
        Title = 'Production and sandbox environments have security groups assigned',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 37003
    $title    = 'Production and sandbox environments have security groups assigned'
    $activity = 'Checking Power Platform environment security groups'
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
    elseif ($environments.Count -eq 0) {
        $lines.Add('No environments found.')
        $customStatus = 'Investigate'
    }
    else {
        # Focus on Production and Sandbox environments; Default environment cannot have security groups
        $targetEnvs = @($environments | Where-Object {
            $sku = $null
            if ($_.PSObject.Properties['properties'] -and $_.properties.PSObject.Properties['environmentSku']) {
                $sku = $_.properties.environmentSku
            }
            $sku -in @('Production', 'Sandbox')
        })

        $defaultEnvs = @($environments | Where-Object {
            $sku = $null
            if ($_.PSObject.Properties['properties'] -and $_.properties.PSObject.Properties['environmentSku']) {
                $sku = $_.properties.environmentSku
            }
            $sku -eq 'Default'
        })

        if ($targetEnvs.Count -eq 0) {
            $customStatus = 'Investigate'
            if ($defaultEnvs.Count -gt 0) {
                $lines.Add(('No dedicated Production or Sandbox environments were found. Only the default environment ({0}) was detected.' -f ($defaultEnvs | ForEach-Object { $_.properties.displayName }) -join ', '))
                $lines.Add('')
                $lines.Add('The **default environment** accepts all licensed Power Platform users in the tenant and cannot have a security group assigned by design. To restrict access to Power Platform, create dedicated Production or Sandbox environments and assign security groups to them.')
                $lines.Add('')
                $lines.Add('Create dedicated environments in [Power Platform Admin Center > Environments > New](https://admin.powerplatform.microsoft.com/environments).')
            }
            else {
                $lines.Add('No Production or Sandbox environments found.')
            }
        }
        else {
            $noGroup = @($targetEnvs | Where-Object {
                $sgId = $null
                if ($_.PSObject.Properties['properties']) {
                    $p = $_.properties
                    # connectedGroups is the primary location for assigned security groups
                    if ($p.PSObject.Properties['connectedGroups'] -and @($p.connectedGroups).Count -gt 0) {
                        $sgId = (@($p.connectedGroups)[0]).groupId
                    }
                    elseif ($p.PSObject.Properties['addGroupTeamConfiguration']) {
                        $sgId = $p.addGroupTeamConfiguration.groupTeamMetadata.securityGroupId
                    }
                    elseif ($p.PSObject.Properties['securityGroupId']) {
                        $sgId = $p.securityGroupId
                    }
                    elseif ($p.PSObject.Properties['linkedEnvironmentMetadata'] -and `
                            $p.linkedEnvironmentMetadata.PSObject.Properties['securityGroupId']) {
                        $sgId = $p.linkedEnvironmentMetadata.securityGroupId
                    }
                }
                [string]::IsNullOrEmpty($sgId)
            })

            $passed = ($noGroup.Count -eq 0)

            if ($passed) {
                $lines.Add(("All **{0}** Production/Sandbox environment(s) have a security group assigned. Environment access is restricted to group members." -f $targetEnvs.Count))
            }
            else {
                $lines.Add(("**{0}** of {1} Production/Sandbox environment(s) do not have a security group assigned. Without a security group, any licensed user in the tenant can access the environment." -f $noGroup.Count, $targetEnvs.Count))
                $lines.Add('')
                $lines.Add('Assign a security group to each environment in [Power Platform Admin Center > Environments](https://admin.powerplatform.microsoft.com/environments).')
            }

            $lines.Add('')
            $lines.Add('| Environment | Type | Security Group |')
            $lines.Add('|:---|:---|:---|')
            foreach ($env in ($targetEnvs | Sort-Object { $_.properties.displayName })) {
                $name = if ($env.properties.PSObject.Properties['displayName']) { $env.properties.displayName } else { $env.name }
                $sku  = if ($env.properties.PSObject.Properties['environmentSku']) { $env.properties.environmentSku } else { 'Unknown' }
                $sgId = $null
                if ($env.PSObject.Properties['properties']) {
                    $p = $env.properties
                    if ($p.PSObject.Properties['connectedGroups'] -and @($p.connectedGroups).Count -gt 0) {
                        $sgId = (@($p.connectedGroups)[0]).groupId
                    }
                    elseif ($p.PSObject.Properties['addGroupTeamConfiguration']) {
                        $sgId = $p.addGroupTeamConfiguration.groupTeamMetadata.securityGroupId
                    }
                    elseif ($p.PSObject.Properties['securityGroupId']) {
                        $sgId = $p.securityGroupId
                    }
                    elseif ($p.PSObject.Properties['linkedEnvironmentMetadata'] -and `
                            $p.linkedEnvironmentMetadata.PSObject.Properties['securityGroupId']) {
                        $sgId = $p.linkedEnvironmentMetadata.securityGroupId
                    }
                }
                $groupStatus = if ([string]::IsNullOrEmpty($sgId)) { 'Not assigned' } else { 'Assigned' }
                $lines.Add(("| {0} | {1} | {2} |" -f $name, $sku, $groupStatus))
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
