<#
.SYNOPSIS
 External sharing for SharePoint is restricted
#>
function Test-Assessment-35047 {
    [ZtTest(
        Category = 'Access Control',
        ImplementationCost = 'Low',
        MinimumLicense = ('Microsoft 365 E3'),
        Pillar = 'Data',
        RiskLevel = 'High',
        SfiPillar = 'Protect tenants and production systems',
        TenantType = ('Workforce'),
        TestId = 35047,
        Title = 'External sharing for SharePoint is restricted',
        UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $testId   = 35047
    $title    = 'External sharing for SharePoint is restricted'
    $activity = 'Checking SharePoint external sharing configuration'
    $mdPath   = Join-Path -Path $PSScriptRoot -ChildPath ("Test-Assessment.{0}.md" -f $testId)

    Write-ZtProgress -Activity $activity -Status 'Getting SPO tenant settings'

    $passed = $false
    $customStatus = $null
    $spoTenant = $null
    $errorMsg = $null

    # --- Stronger pre-checks ---
    if (-not (Get-Command Get-SPOTenant -ErrorAction SilentlyContinue)) {
        $customStatus = 'Investigate'
        $errorMsg = "Get-SPOTenant cmdlet not found. Install/import the SharePoint Online Management Shell and connect using Connect-SPOService -Url https://<tenant>-admin.sharepoint.com."
        Write-PSFMessage $errorMsg -Level Warning
    }
    else {
        try {
            $spoTenant = Get-SPOTenant -ErrorAction Stop
        }
        catch {
            $customStatus = 'Investigate'
            # Include exception message so the report shows why (not connected vs access denied)
            $errorMsg = $_.Exception.Message
            Write-PSFMessage ("Error querying SPO tenant settings: {0}" -f $_) -Level Error
        }
    }

    # --- Assessment Logic (same intent as your existing script) ---
    $leadText = ''
    if ($errorMsg) {
        $leadText = "⚠️ Unable to determine SharePoint external sharing configuration.`n`n**Details:** $errorMsg`n"
    }
    else {
        # SharingCapability values described in your script. [1](https://insightonline-my.sharepoint.com/personal/joshua_kaye_insight_com/Documents/Microsoft%20Copilot%20Chat%20Files/Test-Assessment.35047.ps1.txt)
        $sharingLevel = $spoTenant.SharingCapability

        switch ($sharingLevel) {
            'Disabled' {
                $passed = $true
                $leadText = "✅ SharePoint external sharing is disabled. Only people within the organization can access content.`n"
            }
            'ExistingExternalUserSharingOnly' {
                $passed = $true
                $leadText = "✅ SharePoint external sharing is restricted to existing guests only. New external users cannot be invited.`n"
            }
            'ExternalUserSharingOnly' {
                $passed = $true
                $leadText = "✅ SharePoint external sharing requires authentication. New and existing guests must sign in to access shared content.`n"
            }
            'ExternalUserAndGuestSharing' {
                $passed = $false
                $leadText = "❌ SharePoint external sharing is set to the most permissive level (Anyone). Anonymous links can be used without sign-in, increasing data leakage risk.`n"
            }
            default {
                $passed = $false
                $customStatus = 'Investigate'
                $leadText = "⚠️ SharePoint external sharing level could not be determined: $sharingLevel`n"
            }
        }
    }

    # --- Evidence Markdown ---
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($leadText)
    $lines.Add("")

    if ($spoTenant) {
        $lines.Add("### SharePoint Sharing Configuration")
        $lines.Add("")
        $lines.Add("Setting | Value")
        $lines.Add(":---|:---")

        $sharingDisplay = switch ($spoTenant.SharingCapability) {
            'ExternalUserAndGuestSharing' { '❌ Anyone (anonymous links allowed)' }
            'ExternalUserSharingOnly' { '✅ New and existing guests (authenticated)' }
            'ExistingExternalUserSharingOnly' { '✅ Existing guests only' }
            'Disabled' { '✅ Only people in your organization' }
            default { $spoTenant.SharingCapability }
        }

        $lines.Add(("Sharing capability | {0}" -f $sharingDisplay))

        if ($spoTenant.RequireAnonymousLinksExpireInDays -and $spoTenant.RequireAnonymousLinksExpireInDays -gt 0) {
            $lines.Add(("Anonymous link expiration | {0} days" -f $spoTenant.RequireAnonymousLinksExpireInDays))
        }
        else {
            $lines.Add("Anonymous link expiration | Not configured")
        }

        $defaultLinkType = switch ($spoTenant.DefaultSharingLinkType) {
            'None' { 'Specific people' }
            'Direct' { 'Specific people' }
            'Internal' { 'People in your organization' }
            'AnonymousAccess' { '⚠️ Anyone with the link' }
            default { $spoTenant.DefaultSharingLinkType }
        }
        $lines.Add(("Default sharing link type | {0}" -f $defaultLinkType))

        $defaultPermission = switch ($spoTenant.DefaultLinkPermission) {
            'View' { 'View only' }
            'Edit' { '⚠️ Edit' }
            default { $spoTenant.DefaultLinkPermission }
        }
        $lines.Add(("Default link permission | {0}" -f $defaultPermission))
    }

    $mdInfo = ($lines -join "`n")

    # Ensure the markdown description file exists (does not affect pass/fail)
    if (-not (Test-Path $mdPath)) {
        $customStatus = 'Investigate'
        Write-PSFMessage ("Missing markdown file: {0}" -f $mdPath) -Level Warning
    }

    # --- Output ---
    $params = @{
        TestId = "$testId"
        Title  = $title
        Status = $passed
        Result = $mdInfo   # evidence block only; TestDescription carries the narrative
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }

    Add-ZtTestResultDetail @params
}
