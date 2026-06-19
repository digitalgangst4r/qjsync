# Jira project setup

qjsync writes each Qualys detection into a Jira issue. This is everything the target
project must have, and how to create it.

## 1. What the connector needs

| Requirement | Detail |
|---|---|
| A Jira Cloud **project** | Any key — see [§2](#2-the-project-is-not-hardcoded). |
| An **issue type** | Default `Bug`; configurable. Its create/edit screen must expose the fields below. |
| The **custom fields** | Resolved **by name** ([§4](#4-how-the-mapping-works)). Create the ones you want surfaced. |
| **Priority** + **Labels** on the screen | qjsync sets `priority` (the band) and `labels` (managed + modifier + routing labels). |
| A **Done transition** + resolutions | For lifecycle close/reopen — see [§7](#7-lifecycle-prerequisites). |

Nothing else is required: a missing custom field is **skipped with a warning**, never a
crash, so you can adopt fields incrementally.

## 2. The project is **not** hardcoded

The project key and issue type are configuration, not code:

```yaml
# rules.yml
jira:
  project: "PRODSEC"        # literal …
  issue_type: "Bug"
```

…or pulled from the environment so one ruleset serves many environments (the loader
expands `${VAR}` / `${VAR:-default}` in any value before validation):

```yaml
jira:
  project: "${JIRA_PROJECT_KEY:-QVULN}"   # export JIRA_PROJECT_KEY=PRODSEC
  issue_type: "${JIRA_ISSUE_TYPE:-Bug}"
```

```bash
export JIRA_PROJECT_KEY=PRODSEC
qjsync validate-config -c rules.yml   # -> project resolves to PRODSEC
```

A `${VAR}` with no default whose variable is unset fails fast with a clear error —
never a silently empty project key.

## 3. Fast path: the bootstrap script

[`scripts/bootstrap_jira_fields.py`](../scripts/bootstrap_jira_fields.py) creates the
project (optional), **all** custom fields, their global contexts (so they're JQL-searchable),
and associates them to the project's screens — idempotently (existing fields are matched by
name and reused).

```bash
export JIRA_BASE_URL="https://your-site.atlassian.net"
export JIRA_EMAIL="you@example.com"
export JIRA_API_TOKEN="…"                 # an id.atlassian.com API token
export JIRA_PROJECT_KEY="PRODSEC"         # optional; default QVULN
# Optional: restrict which screens to attach to (default: ALL — careful in prod):
export JIRA_TARGET_SCREENS="PRODSEC: Scrum Default Issue Screen"

python3 scripts/bootstrap_jira_fields.py --dry-run   # show what it would do
python3 scripts/bootstrap_jira_fields.py             # create for real
```

Flags: `--dry-run`, `--no-project` (fields only), `--skip-screens` (create fields but don't
attach), `--project-key`, `--project-name`.

> The script needs **admin** scope (create field / project / screen). The runtime connector
> does **not** — it only reads field ids and creates/updates issues.

## 4. How the mapping works

On startup the connector calls `discover_fields()` → `{field name: field id}` and writes each
value by **name**. Consequences:

- **Names must match exactly** (case- and space-sensitive). `QDS`, `PCI Flag`, `Primary Key`.
- **Type is for rendering, not matching** — but use the recommended type so values render and
  sort correctly (a Number field sorts numerically, a Paragraph field renders multi-line).
- A field name the project doesn't have is **logged and skipped**; the issue is still created.

## 5. Custom field reference

49 fields, grouped by purpose. **Type**: `Number` · `Short text` (single line) ·
`Paragraph` (multi-line) · `Labels`. All are populated by the connector except the two noted
in [§5.7](#57-defined-but-not-populated).

### 5.1 Connector control (critical)

| Field | Type | Purpose |
|---|---|---|
| **Primary Key** | Short text | The idempotency key `HOST_ID:QID:PORT` (`PORT`→`none` sentinel when port-less). qjsync finds the existing issue by this value, so **it must never be edited by hand** (read-only by convention — Jira has no native read-only flag). Configurable via `jira.primary_key_field`. |

### 5.2 Host / asset identity

| Field | Type | Purpose |
|---|---|---|
| Host ID | Number | Qualys host id. |
| Asset ID | Number | Qualys asset id. |
| IP | Short text | IPv4. |
| IPV6 | Short text | IPv6. |
| DNS | Short text | DNS name. |
| Netbios | Short text | NetBIOS name. |
| QG Host ID | Short text | Qualys-assigned host id (agentless tracking / cloud agent). |
| Network ID | Number | Qualys network id. |
| OS | Short text | Detected operating system. |
| Tracking Method | Short text | `IP` / `DNS` / `NETBIOS` / `AGENT` — drives tracking-aware purge. |
| Asset Tag | Labels | The asset's Qualys tags (exposure, ACS, business unit). |
| Asset Criticality Score | Number | ACS (1–5). Not an HLD field — derived from a tag via `qualys.asset_criticality_tag_pattern`. |

### 5.3 Detection core

| Field | Type | Purpose |
|---|---|---|
| QID | Number | Qualys vulnerability id. |
| **QDS** | Number | Qualys Detection Score — the **base** of prioritisation ([LIFECYCLE.md](LIFECYCLE.md)). |
| Severity | Number | Qualys severity 1–5. |
| Port | Number | Detection port (may be absent for host-level QIDs). |
| Protocol | Short text | `tcp` / `udp`. |
| Vuln Type | Short text | Detection type: `Confirmed` / `Potential` / `Information`. |
| Detection Status | Short text | `New` / `Active` / `Re-Opened` / `Fixed`. |
| SSL | Number | `1` if detected over SSL, else `0`. |
| Unique Value ID | Number | Qualys `UNIQUE_VULN_ID` — distinguishes a detection across ports/services. |
| Results | Paragraph | Qualys scan evidence/output. |

### 5.4 Triage / scoring signals

| Field | Type | Purpose |
|---|---|---|
| Patchable | Short text | `Yes`/`No` — drives the `auto-patch` / `needs-mitigation` label (routing, never a gate). |
| PCI Flag | Short text | `Yes`/`No` — PCI in scope (feeds the `pci-scope` routing example). |
| Vuln Category | Short text | KB category (e.g. `Local`, `Windows`, `OEL`) — used by reachability down-weights. |

### 5.5 KnowledgeBase enrichment

| Field | Type | Purpose |
|---|---|---|
| CVEs | Paragraph | CVE list from the KB. |
| Diagnosis | Paragraph | KB diagnosis text. |
| Consequence | Paragraph | KB consequence text. |
| Solution | Paragraph | KB remediation text. |
| CVSS Base | Number | CVSS v2 base. |
| CVSS Temporal | Number | CVSS v2 temporal. |
| CVSS V3 Base | Number | CVSS v3 base (often absent in the KB). |
| CVSS V3 Temporal | Number | CVSS v3 temporal. |
| Published Datetime | Short text | KB publication date. |

### 5.6 Lifecycle timestamps & counters

| Field | Type | Purpose |
|---|---|---|
| First Found Datetime | Short text | First detection. |
| Last Found Datetime | Short text | Most recent detection. |
| Times Found | Number | Detection count. |
| Last Test Datetime | Short text | Last test. |
| Last Update Datetime | Short text | Last update. |
| Last Fixed Datetime | Short text | Last fixed. |
| Last Processed Datetime | Short text | Last processed. |
| Last Scan Datetime | Short text | Asset's last scan. |
| Last VM Scanned Date | Short text | Last VM scan. |
| Last VM Scanned Duration | Number | Duration (s) of the most recent unauthenticated VM scan. |
| Is Ignored | Number | `1`/`0` — ignored detection. |
| Is Disabled | Number | `1`/`0` — disabled detection. |

### 5.7 Defined but **not** populated

The bootstrap script creates these for completeness, but the connector leaves them empty:

| Field | Type | Why empty |
|---|---|---|
| TruRisk Score | Number | **No TruRisk/ASSET_RISK_SCORE field exists in HLD 2.0** (`show_trurisk` is rejected). QDS is the score qjsync uses. |
| Last Service Modification Datetime | Short text | Not surfaced by the current mapping; reserved. |

## 6. Standard Jira fields

Set on every issue alongside the custom fields (full detail in
[FIELD_MAPPING.md](FIELD_MAPPING.md)):

- **`summary`** = `QID - <KB title>`
- **`description`** = rich ADF (diagnosis / consequence / solution / evidence), oversized
  sections truncated to Jira's 32 767-char/field limit.
- **`priority`** = the computed band (`Low`…`Highest`).
- **`labels`** = `qjsync` (managed) + firing modifiers' labels + routing labels (+ `qjsync-stale` on purge).
- **`components`** = set only when a `routing` rule assigns one.

## 7. Lifecycle prerequisites

For the connector to close/reopen issues as detections come and go (see
[LIFECYCLE.md](LIFECYCLE.md)), the workflow must expose:

| `JiraConfig` key | Default | Meaning |
|---|---|---|
| `done_transition` | `Done` | Transition used to close a fixed/purged detection. |
| `reopen_transition` | `Reopen` | Transition used when a detection returns. |
| `resolution_fixed` | `Fixed` | Resolution set when Qualys reports the detection fixed. |
| `resolution_stale` | `Stale - asset/detection purged` | Resolution set when an asset/detection is purged. |
| `sticky_resolutions` | — | Resolutions qjsync will **not** reopen (e.g. `Won't Do`, `Risk Accepted`). |

All are configurable in `rules.yml` — match them to your project's workflow names.
