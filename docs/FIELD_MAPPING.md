# Field mapping: Qualys → Jira

The connector **discovers** each custom field's `customfield_XXXXX` id by **name**
via `/rest/api/3/field` at runtime (`JiraClient.discover_fields()`); ids are never
hardcoded. Issue type: **Host Vulnerability**. Summary: **`QID - Vuln Title`**.

Source legend:
- **HLD/HOST** — Host List Detection, `HOST` element
- **HLD/DETECTION** — Host List Detection, `DETECTION` element
- **KB** — KnowledgeBase `VULN` element
- **derived** — computed by qjsync

If a source value is absent, the field is **omitted** (never sent as null, never
crashes). Datetime fields are written as **text**, preserving the raw Qualys
string (no DatePicker parsing).

| Jira custom field | Type | Source | Qualys element / note |
|---|---|---|---|
| Host ID | number | HLD/HOST | `ID` |
| Asset ID | number | HLD/HOST | `ASSET_ID` |
| IP | text | HLD/HOST | `IP` |
| IPV6 | text | HLD/HOST | `IPV6` |
| Tracking Method | text | HLD/HOST | `TRACKING_METHOD` |
| OS | text | HLD/HOST | `OS` |
| Last Scan Datetime | text | HLD/HOST | `LAST_SCAN_DATETIME` |
| Last VM Scanned Date | text | HLD/HOST | `LAST_VM_SCANNED_DATE` |
| Asset Tag | labels | HLD/HOST | `TAGS/TAG/NAME` (list → labels; spaces sanitised) |
| QID | number | HLD/DETECTION | `QID` |
| QDS | number | HLD/DETECTION | `QDS` (Qualys Detection Score 0–100) |
| Port | number | HLD/DETECTION | `PORT` |
| Severity | number | HLD/DETECTION | `SEVERITY` |
| Vuln Type | text | HLD/DETECTION | `TYPE` (Confirmed/Potential/Information) |
| Patchable | text | KB | `PATCHABLE` (0/1 → "Yes"/"No") |
| PCI Flag | text | KB | `PCI_FLAG` (0/1 → "Yes"/"No") |
| Vuln Category | text | KB | `CATEGORY` |
| Published Datetime | text | KB | `PUBLISHED_DATETIME` |
| CVSS Base | number | KB | `CVSS/BASE` |
| CVSS Temporal | number | KB | `CVSS/TEMPORAL` |
| Detection Status | text | HLD/DETECTION | `STATUS` (New/Active/Re-Opened/Fixed) |
| CVSS V3 Base | number | KB | `CVSS_V3/BASE` |
| CVSS V3 Temporal | number | KB | `CVSS_V3/TEMPORAL` |
| Last Service Modification Datetime | text | KB | `LAST_SERVICE_MODIFICATION_DATETIME` |
| CVEs | multi-line | KB | `CVE_LIST/CVE/ID` (joined, one per line) |
| Diagnosis | multi-line | KB | `DIAGNOSIS` (THREAT) |
| Consequence | multi-line | KB | `CONSEQUENCE` (IMPACT) |
| Solution | multi-line | KB | `SOLUTION` |
| Primary Key | text | derived | `HOST_ID:QID:PORT` — **only the connector writes this** |
| TruRisk Score | number | — | **Not available in HLD 2.0** (no field; `show_trurisk` 400s). Left empty; future via Qualys 4.0 API |
| Asset Criticality Score | number | derived | from tags via `qualys.asset_criticality_tag_pattern` (e.g. `ACS-4`→4; MAX of matches) |
| Last VM Scanned Duration | number | HLD/HOST | `LAST_VM_SCANNED_DURATION` (seconds) |
| Network ID | number | HLD/HOST | `NETWORK_ID` |
| DNS | text | HLD/HOST | `DNS` |
| QG Host ID | text | HLD/HOST | `QG_HOSTID` |
| Netbios | text | HLD/HOST | `NETBIOS` |
| Unique Value ID | number | HLD/DETECTION | `UNIQUE_VULN_ID` |
| SSL | number | HLD/DETECTION | `SSL` (0/1) |
| Results | multi-line | HLD/DETECTION | `RESULTS` |
| First Found Datetime | text | HLD/DETECTION | `FIRST_FOUND_DATETIME` |
| Last Found Datetime | text | HLD/DETECTION | `LAST_FOUND_DATETIME` |
| Times Found | number | HLD/DETECTION | `TIMES_FOUND` |
| Last Test Datetime | text | HLD/DETECTION | `LAST_TEST_DATETIME` |
| Last Update Datetime | text | HLD/DETECTION | `LAST_UPDATE_DATETIME` |
| Last Fixed Datetime | text | HLD/DETECTION | `LAST_FIXED_DATETIME` |
| Is Ignored | number | HLD/DETECTION | `IS_IGNORED` (0/1) |
| Is Disabled | number | HLD/DETECTION | `IS_DISABLED` (0/1) |
| Last Processed Datetime | text | HLD/DETECTION | `LAST_PROCESSED_DATETIME` |
| Protocol | text | HLD/DETECTION | `PROTOCOL` |

## Change classes — MATERIAL vs TELEMETRY (write-amplification control)

Only **MATERIAL** changes trigger a Jira write. **TELEMETRY** changes every ~4h
agent round and must never, on its own, cause a write — it rides along on a write
that a material change already triggered, and otherwise updates only the Postgres
snapshot. Authoritative lists: `qjsync.models.canonical.MATERIAL_SIGNAL_KEYS` /
`TELEMETRY_FIELD_KEYS`. The `material_hash()` is computed over MATERIAL only.

**MATERIAL** (a change here → update the issue):
QDS · TruRisk Score · Severity · CVSS Base · CVSS Temporal · CVSS V3 Base ·
CVSS V3 Temporal · Detection Status (lifecycle: Active/New/Re-Opened/Fixed) ·
Patchable · PCI Flag · Asset Criticality Score.

**TELEMETRY** (excluded from the hash; ride-along only):
Last Scan Datetime · Last VM Scanned Date · Last VM Scanned Duration ·
First Found Datetime · Last Found Datetime · Last Update Datetime ·
Last Processed Datetime · Last Test Datetime · Last Fixed Datetime · Times Found ·
Last Service Modification Datetime.

**CONTEXT / identity** (everything else: Host ID, IP, OS, DNS, Tracking Method,
QID, Port, Vuln Category, CVEs, Diagnosis/Consequence/Solution, Results, Primary
Key, …): stable; written at create and refreshed opportunistically whenever a
material change already forces a PUT. They are not in `material_hash`, so a change
to one of them alone does not, by itself, trigger a write.

> A short Jira **comment** is added only when QDS/TruRisk move materially or the
> priority band changes (rare); never for telemetry.

## Description (ADF, API v3)

Built by `jira/adf.py::build_description(merged)`:

1. Lead paragraph — `Host details: IP <ip> DNS name : <dns> Vulnerability details: <title>`
2. **Environment** (heading 3) — bullet list: OS, IP / IPv6, DNS, NetBIOS, Tracking Method
3. **CVEs** (heading 3) — KB CVE list (or "None")
4. **Diagnosis** (heading 3) — KB `DIAGNOSIS`
5. **Consequence** (heading 3) — KB `CONSEQUENCE`
6. **Solution** (heading 3) — KB `SOLUTION`

Each section degrades gracefully when its KB source is missing.

## Standard Jira fields

- `summary` = `QID - <KB title>`
- `priority.name` = the `EvaluationResult.priority` chosen by the rules engine
- `project.key`, `issuetype.name` = routing from the matched rule or `JiraConfig`
- `labels` = `managed_label` ("qjsync") + rule labels (+ `stale_label` on purge)
  + **derived patch-routing label** (orthogonal to priority, set in the mapper when
  `jira.derive_patch_routing`): `patch_label` ("auto-patch") if KB `patchable` is
  true, else `mitigation_label` ("needs-mitigation") if false; nothing if unknown.
  This keeps `patchable` as a *routing* signal — never a creation gate, so
  non-patchable criticals (EOL/0-day/config) still become issues.
