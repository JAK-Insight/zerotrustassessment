# DEV-NOTES — Zero Trust Assessment Tool (Data Pillar Extension)

> **Owner:** Joshua Kaye (Security Consultant Sr, Insight)
>
> **Repo:** `C:\Epic\MS-ztassessment\zerotrustassessment`
> **Fork:** https://github.com/JAK-Insight/zerotrustassessment
> **Branch:** `copilot/na` *(previously `feature/data-pillar`)*

---

## 1) Project Goal

Extend Microsoft's Zero Trust Assessment tool to include additional pillars—**Data (first)**, then **Applications, Infrastructure, Network**—by adding tests and enabling those pillars in the report UI.

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

### 3.1 Data Pillar: 13 new tests added (35041–35052 + 35060) ✅

| ID | Test |
|----|------|
| 35060 | DLP policies for Exchange Online *(renumbered from 35040 — see §3.8)* |
| 35041 | DLP policies for SharePoint/OneDrive |
| 35042 | DLP policies for Microsoft Teams |
| 35043 | Endpoint DLP enabled |
| 35044 | DLP policies in enforcement mode |
| 35045 | DLP alerts configured and routed |
| 35046 | TLS enforcement for Exchange Online |
| 35047 | SharePoint external sharing restricted |
| 35048 | Retention policies configured |
| 35049 | Data access reviews configured (Graph identity governance) |
| 35050 | Audit log retention extended |
| 35051 | Insider Risk Management policies |
| 35052 | Purview alert policies for data events |

Each test has a matching `.md` template in the same folder (`Test-Assessment.<ID>.md`) with the `%TestResult%` injection token.

### 3.2 Evidence-only result pattern applied to all tests ✅

All 13 tests emit evidence-only markdown into `TestResult`. `TestDescription` remains the authoritative source for static narrative and remediation guidance. This avoids duplication in report output and aligns with how the report renders description vs. results. (Committed: `be5a058f`)

### 3.3 Test 35040 parse error fixed (now 35060) ✅

The truncated URL in the DLP Exchange test (originally 35040, now renumbered to 35060) that caused cascading parse failures was corrected:

```powershell
$lines.Add("### [DLP Policies covering Exchange Online](https://purview.microsoft.com/datalossprevention/policies)")
```

(Committed: `b0316e19`)

### 3.4 Data pillar enabled in report UI ✅

- PowerShell results logic updated so Data totals are not gated behind Preview-only logic.
- Report UI updated to always show the Data tab and include Data in overview charts.

### 3.5 Data added to stable pillars ✅

`Data` added to the stable pillars list so it appears as stable in orchestration logic.

### 3.6 Opt-in `-Connect` auto-connect added to `Invoke-ZtAssessment` ✅

```powershell
Invoke-ZtAssessment ... -Connect
```

When `-Connect` is set, `Invoke-ZtAssessment` auto-calls `Connect-ZtAssessment` with services derived from the selected pillar/tests. For the Data pillar, this includes:
- `ExchangeOnline`
- `SecurityCompliance` (IPPS)
- `SharePointOnline`

Optional parameters added for reliability: `-UserPrincipalName`, `-SharePointAdminUrl`.

IPPS and EXO connectivity improved for multi-service scenarios. (Committed: `ecb1609d`)

### 3.7 Insight branding added to report UI ✅

Insight logo added to the report header alongside the Microsoft ZT logo.

- **Report logo asset:** `src/report/src/assets/insight-logo.png`
- **Docs site logo asset:** `src/react/static/img/logo.png` *(untracked — see Next Steps)*
- **Header component:** `src/report/src/components/layouts/Header.tsx`
- **Logo component:** `src/report/src/components/logo.tsx`

(Committed: `32e802cf`, `a2e03446`)

### 3.8 Upstream merge into `copilot/na` ✅

Merged `microsoft/zerotrustassessment:main` into the fork's `copilot/na` branch. Resolved 8 conflicted files across 15 conflict regions. Renumbered our DLP Exchange test from 35040 → 35060 to avoid collision with upstream's new Communication Compliance for AI test at 35040. ReportTemplate.html was rebuilt from source rather than manually merging minified JS. See §7 for full details. (Committed: `c01159d`)

---

## 4) Standardization Pattern for New Tests

### 4.1 Goal

For each test (35041–35052 + 35060), standardize to:

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
- Avoid backslash line continuations and here-strings unless you're careful with terminators.
- Add **cmdlet existence checks** (e.g., `Get-Command Get-SPOTenant`) and meaningful `Investigate` messages.
- Save scripts as **UTF-8** to keep emoji/icons stable.
- `TestDescription` = static narrative and remediation guidance (from `.md` template).
- `TestResult` = dynamic evidence only — do not re-emit the full description.

---

## 5) Known Issues / Remaining Investigate Scenarios

### 5.1 Test 35047 — SharePoint External Sharing

**Symptom:** May return `Investigate` when SharePoint Online session isn't fully established.

**Cause:** `Connect-ZtAssessment` needs to infer the SPO admin URL correctly (or receive it explicitly via `-SharePointAdminUrl`).

**Workaround:** Pass `-SharePointAdminUrl https://<tenant>-admin.sharepoint.com` when invoking.

### 5.2 Test 35049 — Data Access Reviews

**Symptom:** May return `Investigate` due to missing Graph Identity Governance permissions.

**Cause:** Access reviews require elevated Graph scopes (`AccessReview.Read.All` or `AccessReview.ReadWrite.All`) that may not be granted in all tenants.

**Note:** The PowerShell logic (typed Graph SDK with REST fallback, recurring review detection, instance sampling) is correct and validated.

---

## 6) Useful Commands (Copy/Paste)

### 6.1 Reload local module (dev workflow)

```powershell
cd C:\Epic\MS-ztassessment\zerotrustassessment
Remove-Module ZeroTrustAssessment -Force -ErrorAction SilentlyContinue
Import-Module .\src\powershell\ZeroTrustAssessment.psd1 -Force
```

### 6.2 Confirm `-Connect` parameter exists

```powershell
(Get-Command Invoke-ZtAssessment).Parameters.Keys | Sort-Object
```

### 6.3 Parse-check a single test file

```powershell
$path = "C:\Epic\MS-ztassessment\zerotrustassessment\src\powershell\tests\Test-Assessment.35040.ps1"
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
$errors | Format-List
```

### 6.4 Parse-check all test files (find syntax breakers)

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

### 6.5 Run Data pillar end-to-end

```powershell
# Full run
Invoke-ZtAssessment -Preview -Pillar Data -Connect -ShowLog -Verbose

# Single-test fast validation
Invoke-ZtAssessment -Preview -Pillar Data -Tests 35060 -Connect -ShowLog -Verbose
```

---

## 7) Upstream Merge — `microsoft/zerotrustassessment:main` into `copilot/na` ✅

> **Merge commit:** `c01159d` — 2026-04-02
> **Scope:** 634 files changed, 20,012 insertions, 11,398 deletions

### 7.1 Why

The upstream repo (`microsoft/zerotrustassessment`) had diverged significantly since the fork was created. A merge was required to pull in upstream improvements (timeout helpers, retry logic, language-mode checks, new Identity/Devices tests, report UI changes, build pipeline updates) before opening a PR.

### 7.2 Conflict Resolutions (8 files, 15 conflict regions)

| File | Resolution |
|------|------------|
| `Get-ZtAssessmentResults.ps1` | Kept our full 6-pillar set (Identity, Devices, Network, Data, Infrastructure, PowerPlatform); adopted upstream's tab indentation and `.Where{}` syntax. |
| `Invoke-ZtTests.ps1` | Same pillar-list merge; adopted upstream's `.Where{}` filtering. |
| `Get-ZtGraphScope.ps1` | Retained our 3 extra scopes (`AgentIdentity.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory`); adopted upstream's no-comma array formatting. |
| `Connect-ZtAssessment.ps1` | Took upstream's `elseif` for auto-adding Graph service; kept our resilient UPN fallback (`Get-MgContext` + warning) over upstream's hard `throw`; took upstream's SharePoint catch block. |
| `Invoke-ZtAssessment.ps1` | Combined non-overlapping params from both sides (`-Connect`, `-UserPrincipalName`, `-SharePointAdminUrl` + `-Timeout`, `-TestTimeout`); added upstream's `Test-ZtLanguageMode` guard. |
| `Test-Assessment.35040.ps1` | **Test-ID collision** — both sides created 35040 independently. Kept upstream's (Communication Compliance for AI); renumbered ours to **35060** (DLP policies for Exchange Online). New files: `Test-Assessment.35060.ps1`, `Test-Assessment.35060.md`. |
| `Test-Assessment.35040.md` | Took upstream's version (Communication Compliance template). |
| `ReportTemplate.html` | Regenerated from `src/report/` source build (`npm ci && npm run build`) instead of merging minified JS. |

### 7.3 Key Upstream Additions Now In Our Branch

- **Timeout helpers** — `Initialize-ZtTimeoutHelper.ps1`, `-Timeout` and `-TestTimeout` params on `Invoke-ZtAssessment`
- **Retry logic** — `Invoke-ZtRetry.ps1`, `Test-ZtRetryableError.ps1`, `Get-ZtHttpStatusCode.ps1`
- **Language-mode check** — `Test-ZtLanguageMode.ps1`, `Write-ZtLanguageModeError.ps1`
- **License checks** — `Test-ZtLicense.ps1`
- **DevProxy testing harness** — `devproxy/` directory for offline Graph mock testing
- **New upstream tests** — Communication Compliance for AI (35040), plus many new Identity/Devices tests
- **Build & CI updates** — production publish workflow, updated dependency resolution, 1ES build template changes
- **Report UI** — updated components for Infrastructure, Network, and other pillars

---

## 8) Next Steps Checklist

- [ ] **Commit `src/react/static/img/logo.png`** — docs site logo is untracked and will be lost.
- [ ] **Run parse-check** across all test files (35041–35052 + 35060) — must return 0 errors.
- [ ] **Reload module and run end-to-end validation:**
  ```powershell
  Invoke-ZtAssessment -Preview -Pillar Data -Connect -ShowLog -Verbose
  ```
- [ ] **Investigate 35047 SPO connection** — test with explicit `-SharePointAdminUrl` to confirm pass/fail accuracy.
- [ ] **Investigate 35049 Graph permissions** — document minimum required scopes; consider graceful degradation message.
- [ ] **Open PR** `copilot/na` → `main` when validation passes.

---

## 9) Session Resume Prompt (for new chat)

```text
I'm Joshua Kaye (Security Consultant Sr, Insight) extending Microsoft Zero Trust Assessment.
Fork: https://github.com/JAK-Insight/zerotrustassessment | Branch: copilot/na | Local: C:\Epic\MS-ztassessment\zerotrustassessment

COMPLETED:
- 13 Data pillar tests added (35041–35052 + 35060), all with matching .md templates using %TestResult% injection
- All tests standardized to evidence-only result pattern (TestResult = evidence only; TestDescription = static narrative)
- Test 35040 URL parse error fixed (commit b0316e19), then renumbered to 35060 to avoid upstream collision
- Data pillar enabled in report UI and added to stable pillars
- Opt-in -Connect switch added to Invoke-ZtAssessment; auto-connects EXO, IPPS (SecurityCompliance), and SharePointOnline for Data pillar
- Insight logo branding added to report header (Header.tsx, logo.tsx) — commits 32e802cf and a2e03446
- Upstream merge completed (commit c01159d) — 8 conflicted files / 15 regions resolved, ReportTemplate.html rebuilt from source

PENDING:
- src/react/static/img/logo.png is untracked and needs to be committed
- Run parse-check on all test files, then: Invoke-ZtAssessment -Preview -Pillar Data -Connect -ShowLog -Verbose
- Remaining Investigate scenarios: 35047 (SPO admin URL), 35049 (Graph Identity Governance scopes)
- Open PR to main when validation passes
```
