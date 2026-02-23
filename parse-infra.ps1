$ids = @(36001, 36002, 36003, 36004, 36005, 36006, 36007, 36008, 36009)
$allOk = $true
foreach ($id in $ids) {
    $path = "c:\Epic\MS-ztassessment\zerotrustassessment\src\powershell\tests\Test-Assessment.$id.ps1"
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        Write-Host ("ERRORS in {0}:" -f $id) -ForegroundColor Red
        $errors | ForEach-Object { Write-Host "  Line $($_.Extent.StartLineNumber): $($_.Message)" }
        $allOk = $false
    } else {
        Write-Host "OK: $id" -ForegroundColor Green
    }
}
if ($allOk) { Write-Host "All files parsed with 0 errors." -ForegroundColor Green }
