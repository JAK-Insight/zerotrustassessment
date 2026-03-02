<#
.SYNOPSIS
 Helper function to call the Power Platform Admin (BAP) API.
#>
function Invoke-ZtPowerPlatformRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = '2023-06-01',

        [Parameter(Mandatory = $false)]
        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET'
    )

    $baseUrl = 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform'
    $uri     = '{0}{1}?api-version={2}' -f $baseUrl, $Path, $ApiVersion

    $tokenObj   = Get-AzAccessToken -ResourceUrl 'https://service.powerapps.com/' -AsSecureString -ErrorAction Stop
    $plainToken = [System.Net.NetworkCredential]::new('', $tokenObj.Token).Password
    $headers    = @{
        Authorization = "Bearer $plainToken"
        Accept        = 'application/json'
    }

    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method $Method -ErrorAction Stop
    return $response
}