# DEV-NOTES — Zero Trust Assessment Tool (Data Pillar Extension)

> **Owner:** Joshua Kaye (Security Consultant Sr, Insight)
> 
> **Repo:** `C:\Epic\MS-ztassessment\zerotrustassessment`  
> **Fork:** https://github.com/JAK-Insight/zerotrustassessment  
> **Branch:** `feature/data-pillar`

---

## 1) Project Goal

Extend Microsoft’s Zero Trust Assessment tool to include additional pillars—**Data (first)**, then **Applications, Infrastructure, Network**—by adding tests and enabling those pillars in the report UI.

---

## 2) Repo Architecture (high-level)

- **Docs site (React/Docusaurus):** `src/react/docs/workshop-guidance/`
- **Assessment engine (PowerShell module):** `src/powershell/`
- **Report web app (Vite/React):** `src/report/`
- **Tests (PowerShell):** `src/powershell/tests/Test-Assessment.{TestId}.ps1`
  - Each test uses `[ZtTest()]` attribute metadata (Pillar, Category, TestId, Title, etc.)
  - Many tests query Graph-export data in DuckDB; Data pillar also uses Purview/EXO/SPO cmdlets.

---

## 3) Completed Work Summary

### 3.1 Data Pillar: new tests added (35040–35052)

Added 13 new Data pillar tests:

- **35040:** DLP policies for Exchange Online
- **35041:** DLP policies for SharePoint/OneDrive
- **35042:** DLP policies for Microsoft Teams
- **35043:** Endpoint DLP enabled
- **35044:** DLP policies in enforcement mode
- **35045:** DLP alerts configured and routed
- **35046:** TLS enforcement for Exchange Online
- **35047:** SharePoint external sharing restricted
- **35048:** Retention policies configured
- **35049:** Data access reviews configured (Graph identity governance)
- **35050:** Audit log retention extended
- **35051:** Insider Risk Management policies
- **35052:** Purview alert policies for data events

### 3.2 Data Pillar: enabled in report UI

- PowerShell results logic updated so Data totals are not gated behind Preview-only logic.
- Report UI updated to always show the Data tab and include Data in overview charts.

### 3.3 Data Pillar: added to “stable pillars”

Changed stable pillars list to include `Data` (so it appears as stable in orchestration logic).

---

## 4) Standardization Pattern for New Tests

### 4.1 Goal

For each new test (35040–35052), standardize to:

1. A **matching markdown file** in the **same folder** as the test:
   - `src/powershell/tests/Test-Assessment.<ID>.md`
2. The MD holds narrative/remediation and includes the injection token:

```md
<!--- Results --->
%TestResult%
```

3. The PowerShell test script:
   - Collects data
   - Builds **evidence markdown** (tables + summary; keep icons ✅ ⚠️ ❌ 🧪)
   - Loads the `.md` template with `Get-Content -Raw`
   - Replaces `%TestResult%` with computed evidence
   - Uses `Add-ZtTestResultDetail` to output

### 4.2 Implementation Tips

- Prefer **line-array markdown generation** (avoid fragile multiline string escaping).
- Avoid backslash line continuations and here-strings unless you’re careful with terminators.
- Add **cmdlet existence checks** (e.g., `Get-Command Get-SPOTenant`) and improve `Investigate` messages.
- Save scripts as **UTF-8** to keep emoji/icons stable.

---

## 5) “Best UX” Enhancement — Opt-in Auto-Connect

### 5.1 Problem

Some tests require service-specific sessions (EXO, Security & Compliance/IPPS, SharePointOnline). If a user only follows the default “Connect then Invoke” flow, Data tests like **35047** may return `Investigate` due to missing SharePoint Online connection.

### 5.2 Decision

Add an **opt-in** switch to `Invoke-ZtAssessment`:

- `Invoke-ZtAssessment ... -Connect`

When `-Connect` is set, `Invoke-ZtAssessment` calls `Connect-ZtAssessment` with a service set based on pillar/tests (e.g., Data connects Graph/Azure + SecurityCompliance + SharePointOnline).

### 5.3 Status

- `Invoke-ZtAssessment` was edited to add `-Connect` (opt-in).
- Module reload confirmed the new parameter appears.

---

## 6) Known Issue (Active): Test 35040 Parse Failure

### Symptom

Module import or test parsing fails with PowerShell parse errors.

### Root Cause

In `Test-Assessment.35040.ps1`, a markdown header line was truncated mid-URL, causing an unterminated string and cascading parse errors.

### Correct URL

Use:

```text
https://purview.microsoft.com/datalossprevention/policies
```

### Fix Pattern

Ensure the line is complete and not merged with the next statement:

```powershell
$lines.Add("### [DLP Policies covering Exchange Online](https://purview.microsoft.com/datalossprevention/policies)")
$lines.Add("")
```

Then validate syntax with the parser check (below).

---

## 7) Useful Commands (Copy/Paste)

### 7.1 Reload local module (dev workflow)

```powershell
cd C:\Epic\MS-ztassessment\zerotrustassessment
Remove-Module ZeroTrustAssessment -Force -ErrorAction SilentlyContinue
Import-Module .\src\powershell\ZeroTrustAssessment.psd1 -Force
```

### 7.2 Confirm `-Connect` exists

```powershell
(Get-Command Invoke-ZtAssessment).Parameters.Keys | Sort-Object
```

### 7.3 Parse-check a single test file

```powershell
$path = "C:\Epic\MS-ztassessment\zerotrustassessment\src\powershell\tests\Test-Assessment.35040.ps1"
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
$errors | Format-List
```

### 7.4 Parse-check all test files (find syntax breakers)

```powershell
$root = "C:\Epic\MS-ztassessment\zerotrustassessment\src\powershell\tests"
$files = Get-ChildItem $root -Filter "Test-Assessment.*.ps1" -File

$allErrors = foreach ($f in $files) {
  $tokens = $null
  $errors = $null
  [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors) | Out-Null
  foreach ($e in $errors) {
    [pscustomobject]@{
      File   = $f.Name
      Line   = $e.Extent.StartLineNumber
      Column = $e.Extent.StartColumnNumber
      Message= $e.Message
      Text   = $e.Extent.Text
    }
  }
}

$allErrors | Sort-Object File, Line, Column | Format-Table -AutoSize
```

### 7.5 Run Data pillar end-to-end (after fixes)

```powershell
Invoke-ZtAssessment -Preview -Pillar Data -Connect -ShowLog -Verbose
```

---

## 8) Next Steps Checklist

1. **Fix 35040 syntax** (ensure URL line is complete; no merged `$lines.Add(...)` lines).
2. Re-run **Parse-check all test files** (must return 0 errors).
3. Reload module.
4. Run a **fast validation** (optional): `Invoke-ZtAssessment -Preview -Pillar Data -Tests 35040 -Connect -ShowLog -Verbose`
5. Full validation run: `Invoke-ZtAssessment -Preview -Pillar Data -Connect -ShowLog -Verbose`
6. After validation, consider improving “just works” connections for remaining `Investigate` scenarios:
   - Ensure SharePointOnline connect success for 35047 (admin URL inference vs explicit parameter)
   - Address Graph permissions for 35049 (Identity Governance access reviews)

---

## 9) Session Resume Prompt (for new chat)

If you need to restart a Copilot/Chat session, paste this summary:

```text
I’m Joshua Kaye (Security Consultant Sr, Insight) extending Microsoft Zero Trust Assessment.
Fork: https://github.com/JAK-Insight/zerotrustassessment | Branch: feature/data-pillar | Local: C:\Epic\MS-ztassessment\zerotrustassessment
Added 13 Data tests 35040–35052 and enabled Data pillar in report UI and stable pillars.
Standardizing all tests to use matching MD templates in src\powershell\tests with %TestResult% injection.
Added opt-in -Connect to Invoke-ZtAssessment to auto-call Connect-ZtAssessment with required services (Data uses SecurityCompliance + SharePointOnline).
Current blocker: Test-Assessment.35040.ps1 parse error due to truncated URL; correct is https://purview.microsoft.com/datalossprevention/policies. Fix 35040, parse-check all tests, reload module, then run: Invoke-ZtAssessment -Preview -Pillar Data -Connect -ShowLog -Verbose.
```
