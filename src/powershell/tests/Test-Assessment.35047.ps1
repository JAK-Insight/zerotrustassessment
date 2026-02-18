# src\powershell\tests\Test-Assessment.35047.ps1

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

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking SharePoint external sharing configuration'
    Write-ZtProgress -Activity $activity -Status 'Getting SPO tenant settings'

    $errorMsg = $null
    $spoTenant = $null

    try {
        $spoTenant = Get-SPOTenant -ErrorAction Stop
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage "Error querying SPO tenant settings: $_" -Level Error
    }
    #endregion Data Collection

    #region Assessment Logic
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine SharePoint external sharing configuration due to permissions issues or query failure.`n`n"
        $customStatus = 'Investigate'
    }
    else {
        # SharingCapability values:
        # ExternalUserAndGuestSharing (Anyone) - Most permissive
        # ExternalUserSharingOnly (New and existing guests)
        # ExistingExternalUserSharingOnly (Existing guests only)
        # Disabled (Only people in your organization)

        $sharingLevel = $spoTenant.SharingCapability

        switch ($sharingLevel) {
            'Disabled' {
                $passed = $true
                $testResultMarkdown = "✅ SharePoint external sharing is disabled. Only people within the organization can access content.`n`n%TestResult%"
            }
            'ExistingExternalUserSharingOnly' {
                $passed = $true
                $testResultMarkdown = "✅ SharePoint external sharing is restricted to existing guests only. New external users cannot be invited.`n`n%TestResult%"
            }
            'ExternalUserSharingOnly' {
                $passed = $true
                $testResultMarkdown = "✅ SharePoint external sharing requires authentication. New and existing guests must sign in to access shared content.`n`n%TestResult%"
            }
            'ExternalUserAndGuestSharing' {
                $passed = $false
                $testResultMarkdown = "❌ SharePoint external sharing is set to the most permissive level (Anyone). Documents can be shared via anonymous links that require no sign-in, creating significant data leakage risk.`n`n%TestResult%"
            }
            default {
                $passed = $false
                $testResultMarkdown = "⚠️ SharePoint external sharing level could not be determined: $sharingLevel`n`n%TestResult%"
                $customStatus = 'Investigate'
            }
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    if ($spoTenant) {
        $mdInfo += "`n`n### [SharePoint Sharing Configuration](https://admin.microsoft.com/sharepoint?page=sharing)`n"
        $mdInfo += "| Setting | Value |`n"
        $mdInfo += "| :--- | :--- |`n"

        $sharingDisplay = switch ($spoTenant.SharingCapability) {
            'ExternalUserAndGuestSharing' { '❌ Anyone (anonymous links allowed)' }
            'ExternalUserSharingOnly' { '✅ New and existing guests (authenticated)' }
            'ExistingExternalUserSharingOnly' { '✅ Existing guests only' }
            'Disabled' { '✅ Only people in your organization' }
            default { $spoTenant.SharingCapability }
        }

        $mdInfo += "| Sharing capability | $sharingDisplay |`n"

        if ($spoTenant.RequireAnonymousLinksExpireInDays -and $spoTenant.RequireAnonymousLinksExpireInDays -gt 0) {
            $mdInfo += "| Anonymous link expiration | $($spoTenant.RequireAnonymousLinksExpireInDays) days |`n"
        }
        else {
            $mdInfo += "| Anonymous link expiration | Not configured |`n"
        }

        $defaultLinkType = switch ($spoTenant.DefaultSharingLinkType) {
            'None' { 'Specific people' }
            'Direct' { 'Specific people' }
            'Internal' { 'People in your organization' }
            'AnonymousAccess' { '⚠️ Anyone with the link' }
            default { $spoTenant.DefaultSharingLinkType }
        }
        $mdInfo += "| Default sharing link type | $defaultLinkType |`n"

        $defaultPermission = switch ($spoTenant.DefaultLinkPermission) {
            'View' { 'View only' }
            'Edit' { '⚠️ Edit' }
            default { $spoTenant.DefaultLinkPermission }
        }
        $mdInfo += "| Default link permission | $defaultPermission |"
    }

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35047'
        Title  = 'External sharing for SharePoint is restricted'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
