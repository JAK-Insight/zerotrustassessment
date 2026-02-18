# src\powershell\tests\Test-Assessment.35049.ps1

<#
.SYNOPSIS
    Data access reviews are configured for sensitive resources
#>

function Test-Assessment-35049 {
    [ZtTest(
        Category = 'Access Control',
        ImplementationCost = 'Medium',
        MinimumLicense = ('Microsoft Entra ID P2'),
        Pillar = 'Data',
        RiskLevel = 'Medium',
        SfiPillar = 'Protect identities and secrets',
        TenantType = ('Workforce'),
        TestId = 35049,
        Title = 'Data access reviews are configured for sensitive resources',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param(
        $Database
    )

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking access review configuration'
    Write-ZtProgress -Activity $activity -Status 'Getting access review definitions'

    $errorMsg = $null
    $accessReviews = @()

    try {
        $accessReviews = Invoke-ZtGraphRequest -Uri '/v1.0/identityGovernance/accessReviews/definitions' -ErrorAction Stop
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage "Error querying access reviews: $_" -Level Error
    }
    #endregion Data Collection

    #region Assessment Logic
    $activeReviews = @()
    $passed = $false
    $customStatus = $null

    if ($errorMsg) {
        $testResultMarkdown = "⚠️ Unable to determine access review configuration due to permissions issues or query failure.`n`n"
        $customStatus = 'Investigate'
    }
    else {
        $reviewList = if ($accessReviews.value) { $accessReviews.value } else { @($accessReviews) }

        # Filter for active access reviews targeting groups (which may contain sensitive data)
        $activeReviews = @($reviewList | Where-Object { $_.status -eq 'InProgress' -or $_.status -eq 'NotStarted' -or $_.status -eq 'Starting' })

        if ($activeReviews.Count -gt 0) {
            $passed = $true
            $testResultMarkdown = "✅ $($activeReviews.Count) access review(s) are configured and active, helping ensure least-privilege access to resources.`n`n%TestResult%"
        }
        elseif ($reviewList.Count -gt 0) {
            $passed = $false
            $testResultMarkdown = "❌ $($reviewList.Count) access review definition(s) exist but none are currently active. Access reviews should be recurring to continuously validate entitlements.`n`n%TestResult%"
        }
        else {
            $passed = $false
            $testResultMarkdown = "❌ No access reviews are configured. Users may retain access to sensitive data long after it is no longer needed, violating least-privilege principles.`n`n%TestResult%"
        }
    }
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    $mdInfo += "`n`n### Summary`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :--- | :--- |`n"
    $mdInfo += "| Total access review definitions | $($reviewList.Count) |`n"
    $mdInfo += "| Active access reviews | $($activeReviews.Count) |"

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    $params = @{
        TestId = '35049'
        Title  = 'Data access reviews are configured for sensitive resources'
        Status = $passed
        Result = $testResultMarkdown
    }
    if ($null -ne $customStatus) { $params.CustomStatus = $customStatus }
    Add-ZtTestResultDetail @params
}
