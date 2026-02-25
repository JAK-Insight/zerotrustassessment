<#
.SYNOPSIS
 AI agent identities registered in Microsoft Entra have sponsors assigned
#>
function Test-Assessment-21993 {
    [ZtTest(
        Category = 'Identity governance',
        ImplementationCost = 'Low',
        MinimumLicense = ('Free'),
        Pillar = 'Identity',
        RiskLevel = 'Medium',
        SfiPillar = 'Protect identities and secrets',
        TenantType = ('Workforce'),
        TestId = 21993,
        Title = 'AI agent identities have sponsors assigned',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose

    $testId   = 21993
    $title    = 'AI agent identities have sponsors assigned'
    $activity = 'Checking Microsoft Entra AI agent identity sponsorship'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    Write-ZtProgress -Activity $activity -Status 'Getting agent identities'

    $passed         = $false
    $customStatus   = $null
    $errorMsg       = $null
    $agentIdentities = @()

    try {
        $agentIdentities = @(Invoke-ZtGraphRequest -RelativeUri 'agentIdentities' -ApiVersion beta -ErrorAction Stop)
    }
    catch {
        $errorMsg     = $_.Exception.Message
        $customStatus = 'Investigate'
    }

    $lines = New-Object System.Collections.Generic.List[string]

    if ($errorMsg) {
        $lines.Add('Unable to retrieve AI agent identities from Microsoft Entra.')
        $lines.Add('')
        $lines.Add(("**Details:** {0}" -f $errorMsg))
        $lines.Add('')
        $lines.Add('Ensure the assessment account has the **AgentIdentity.Read.All** permission (currently in preview).')
        $lines.Add('')
        $lines.Add('If your organization does not yet use Microsoft Entra Agent ID, no action is required.')
    }
    elseif ($agentIdentities.Count -eq 0) {
        $customStatus = 'Investigate'
        $lines.Add('No AI agent identities were found in Microsoft Entra.')
        $lines.Add('')
        $lines.Add('If your organization uses AI agents (such as Microsoft Copilot Studio agents or custom-built agents), register them in [Microsoft Entra Agent ID](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AgentIdMenuBlade) and assign sponsors to establish human accountability for each agent.')
        $lines.Add('')
        $lines.Add('If your organization does not use AI agents, this check does not apply.')
    }
    else {
        # For each agent identity, check sponsors
        $agentsWithoutSponsor = [System.Collections.Generic.List[pscustomobject]]::new()
        $agentsWithSponsor    = [System.Collections.Generic.List[pscustomobject]]::new()

        Write-ZtProgress -Activity $activity -Status 'Checking sponsors for each agent identity'

        foreach ($agent in $agentIdentities) {
            $agentName = if ($agent.PSObject.Properties['displayName']) { $agent.displayName } else { $agent.id }
            $sponsors  = @()

            try {
                $sponsors = @(Invoke-ZtGraphRequest -RelativeUri "agentIdentities/$($agent.id)/sponsors" -ApiVersion beta -ErrorAction Stop)
            }
            catch {
                Write-PSFMessage ("Failed to get sponsors for agent {0}: {1}" -f $agentName, $_.Exception.Message) -Level Warning
            }

            $agentObj = [pscustomobject]@{
                Id           = $agent.id
                Name         = $agentName
                SponsorCount = $sponsors.Count
                Sponsors     = $sponsors | ForEach-Object {
                    if ($_.PSObject.Properties['displayName']) { $_.displayName } else { $_.id }
                }
            }

            if ($sponsors.Count -eq 0) {
                $agentsWithoutSponsor.Add($agentObj)
            }
            else {
                $agentsWithSponsor.Add($agentObj)
            }
        }

        $passed = ($agentsWithoutSponsor.Count -eq 0)

        if ($passed) {
            $lines.Add(("All **{0}** AI agent identit{1} have at least one sponsor assigned. Each agent has a designated human accountable for its access and lifecycle." -f `
                $agentIdentities.Count, (if ($agentIdentities.Count -eq 1) { 'y' } else { 'ies' })))
        }
        else {
            $lines.Add(("**{0}** of {1} AI agent identit{2} do not have a sponsor assigned. Unsponsored agent identities lack human accountability for their access, permissions, and lifecycle." -f `
                $agentsWithoutSponsor.Count, $agentIdentities.Count, (if ($agentIdentities.Count -eq 1) { 'y' } else { 'ies' })))
            $lines.Add('')
            $lines.Add('Assign sponsors to all agent identities in [Microsoft Entra Agent ID](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AgentIdMenuBlade).')
        }

        $lines.Add('')
        $lines.Add('| Agent Identity | Sponsors |')
        $lines.Add('|:---|:---|')

        foreach ($agent in ($agentIdentities | Sort-Object { $_.displayName })) {
            $agentName = if ($agent.PSObject.Properties['displayName']) { $agent.displayName } else { $agent.id }
            $match     = $agentsWithSponsor | Where-Object { $_.Id -eq $agent.id }
            if (-not $match) {
                $match = $agentsWithoutSponsor | Where-Object { $_.Id -eq $agent.id }
            }

            if ($match -and $match.SponsorCount -gt 0) {
                $sponsorList = $match.Sponsors -join ', '
                $lines.Add(("| {0} | {1} |" -f $agentName, $sponsorList))
            }
            else {
                $lines.Add(("| {0} | Not assigned |" -f $agentName))
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
