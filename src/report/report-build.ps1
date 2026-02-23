# Run this in the ./src/report directory to build the report, append the end marker and copy the report template to the powershell assets directory

Write-Host "Adding EndJson marker to report-data.ts"
$content = Get-Content ./src/config/report-data.ts

# Find the EndOfJson line by pattern (robust against file length changes)
$endJsonIndex = -1
for ($i = 0; $i -lt $content.Count; $i++) {
    if ($content[$i] -match '"EndOfJson"') {
        $endJsonIndex = $i
    }
}

if ($endJsonIndex -eq -1) {
    Write-Error "Could not find EndOfJson line in report-data.ts"
    exit 1
}

$last = $content[$endJsonIndex]
if (!$last.EndsWith("|EndJson|`"")) {
    $content[$endJsonIndex] = $last.Substring(0, $last.Length - 1) + "|EndJson|`""
}

$content | Set-Content ./src/config/report-data.ts

Write-Host "Building report"
npm run build

Write-Host "Updating report template"
Copy-Item ./dist/index.html ../powershell/assets/ReportTemplate.html -Force
