# qjsync — Architecture

qjsync syncs **Qualys VMDR** detections into **Jira Cloud** issues, gated by a
configurable prioritisation engine, enriched from the Qualys KnowledgeBase, with
correct handling of the detection lifecycle and of **purge ≠ remediation**.

This document is the contract. The canonical model, config schema, and DB schema
are defined in code (authoritative); this describes responsibilities, key
algorithms, and the interfaces each module exposes.

## Operating model (drives the design)

- ~90% of the estate runs the **Qualys Cloud Agent**, re-assessing every **~4h**.
- ~10% are **network-scanned** by an appliance on a slower, appliance-paced cadence.
- The connector runs **incremental every ~4h** (aligned to the agent) via
  cron/systemd timer, and a **full reconciliation weekly** (or at the slowest
  network-scan cadence).
- Telemetry fields (Last Scan Datetime, Last VM Scanned Date, …) change every
  agent round, i.e. every ~4h — so they must not, on their own, cause Jira writes.

Two structural consequences, baked into the contract:

1. **Sync modes.** Only a `full` run may infer purge; an `incremental` run never
   does (otherwise everything outside the 4h delta would look "missing" → mass
   false-purge). See *Sync modes* below.
2. **Material vs telemetry.** Only a change in a *material* field triggers a Jira
   write; telemetry rides along. See *Change detection* below.

## Layered design

```
        Qualys VMDR (HLD + KB)                         Jira Cloud REST v3
                 │                                            ▲
                 ▼                                            │
        sources/qualys (VmSource) ── canonical ──►  rules.engine ──► jira.mapper/client
                 │  MergedVulnerability                  │  EvaluationResult     │
                 └──────────────► sync.orchestrator ◄────┘                       │
                                        │  (modes, snapshot diff, lifecycle)     │
                                        ▼                                        ▼
                                  state (PostgreSQL)  ◄───────────────  state (mapping)
```

Everything downstream of a source speaks only the **canonical model**
(`qjsync.models.canonical`). Sources translate raw API payloads into it. This is
what makes WAS/Container future modules drop-in: implement `SourceModule` once
more, nothing else changes.

## Directory layout

```
src/qjsync/
  models/      canonical.py (domain + MATERIAL/TELEMETRY + material_hash), identity.py   [DONE — contract]
  config/      schema.py (rules.yml), settings.py (secrets)   [DONE]; loader.py
  sources/     base.py (SourceModule ABC) [DONE]; qualys/ (client, detection, knowledgebase, parse, source)
  rules/       engine.py (evaluate -> EvaluationResult), operators.py (operator registry)
  jira/        auth.py (AuthProvider), client.py, adf.py, mapper.py
  state/       models.py [DONE — DB contract], db.py (engine/session), repositories.py
  sync/        orchestrator.py, purge.py, summary.py
  logging.py   structured logging setup
  cli.py       typer app: sync (--mode), dry-run, init-db, validate-config, kb-refresh
migrations/    alembic env + versions
tests/         pytest suite with fixtures (no live APIs)
docs/          this file, FIELD_MAPPING.md, LIFECYCLE.md
examples/      rules.yml (realistic, commented)
docker/        Dockerfile, docker-compose.yml (app + postgres)
scripts/       bootstrap_jira_fields.py (provisions the custom fields by name)
```

## Sync modes (incremental vs full)

`SyncMode = Literal["incremental", "full"]` (DB enum `sync_runs.mode`).

- **incremental** (default; every ~4h): the orchestrator computes a
  connector-managed `vm_scan_since` from the **last successful sync** (of any
  mode) minus `QualysConfig.incremental_overlap_minutes`, and passes it to
  `source.iter_merged(since=...)`. It creates / updates / closes-by-Fixed /
  reopens, and **SKIPS the purge pass entirely**.
- **full** (weekly reconciliation): injects **no** managed window — it scans the
  user's whole query scope — and **runs the purge pass**. It is the only mode
  that can mark a detection stale.

**`vm_scan_since` precedence.** A static `qualys.query.vm_scan_since` in the YAML
is a floor for full-scope queries. In incremental mode the managed window **wins**
(overrides the static value). In full mode no managed window is injected and the
static value (if any) is used verbatim.

## Change detection (material vs telemetry)

`material_hash()` (on `MergedVulnerability`) hashes **only** the MATERIAL fields.
The orchestrator compares it to `DetectionState.material_hash`:

- **MATERIAL** (`canonical.MATERIAL_SIGNAL_KEYS`) — a change here means real risk/
  lifecycle movement → **write the Jira issue**:
  `status` (Active/New/Re-Opened/Fixed), `qds`, `trurisk`, `severity`,
  `cvss_base`, `cvss_temporal`, `cvss_v3_base`, `cvss_v3_temporal`, `patchable`,
  `pci_flag`, `asset_criticality`.
- **TELEMETRY** (`canonical.TELEMETRY_FIELD_KEYS`) — changes every ~4h; on its own
  it updates **only the Postgres snapshot**, never Jira:
  `last_scan_datetime`, `last_vm_scanned_date`, `last_vm_scanned_duration`,
  `first_found_datetime`, `last_found_datetime`, `last_update_datetime`,
  `last_processed_datetime`, `last_test_datetime`, `last_fixed_datetime`,
  `times_found`, `last_service_modification_datetime`.

When a material change triggers a write, the single idempotent PUT carries
material **and** telemetry together (telemetry rides along). A short Jira
**comment** is optional and **rare** — only when QDS/TruRisk move materially or the
priority band changes (e.g. "QDS 65→88, priority raised to High"); never on
telemetry.

## Qualys API grounding (verified against a live VMDR subscription)

Confirmed against a live VMDR subscription (your POD, e.g. `qualysapi.<pod>.apps.qualys.com`):

- **Auth:** HTTP Basic + mandatory header `X-Requested-With`. POST form params.
- **API path:** `/api/2.0/fo/asset/host/vm/detection/` (2.0 shows an EOS warning,
  ~375 days to EOL → 4.0 is a future migration; 2.0 is used now).
- **HLD HOST fields:** `ID, IP, TRACKING_METHOD, NETWORK_ID, OS, OS_CPE, DNS,
  DNS_DATA, QG_HOSTID, LAST_SCAN_DATETIME, LAST_VM_SCANNED_DATE,
  LAST_VM_AUTH_SCANNED_DATE, TAGS`. **No TruRisk/ASSET_RISK_SCORE/ACS field exists**
  and `show_trurisk` returns HTTP 400 ("Unrecognized parameter").
- **HLD DETECTION fields:** `UNIQUE_VULN_ID, QID, TYPE, SEVERITY, SSL, RESULTS,
  STATUS, FIRST/LAST_FOUND_DATETIME, QDS, QDS_FACTORS, TIMES_FOUND, LAST_TEST/
  UPDATE/FIXED/PROCESSED_DATETIME, IS_IGNORED, IS_DISABLED` (PORT/PROTOCOL absent
  for host-level QIDs → port-less, sentinel applies).
- **RTIs:** in `DETECTION/QDS_FACTORS/QDS_FACTOR[name=RTI]` as a comma list, e.g.
  `Denial_of_Service,Remote_Code_Execution,Exploit_Public`. Also in KB
  `THREAT_INTELLIGENCE`. `has_exploit` unions both. The canonical model further
  classifies RTIs into threat-category booleans (`actively_attacked`, `ransomware`,
  `wormable`, `zero_day`, `easy_exploit`) so modifiers can weight them distinctly.
- **EPSS:** when present as a `QDS_FACTOR[name=EPSS]`, parsed to a float and exposed
  as the `epss` signal (0–1 exploitation probability).
- **ACS:** not an API field; this tenant encodes it as tags (`ACS-4`). Derived
  via `qualys.asset_criticality_tag_pattern` (a host may carry several → MAX wins).
- **Exposure tag:** the exact applied string is **`Internet Facing Assets`** (also
  present: `AMS - LatAM - CMDB - DMZ`, `EASM`, `Shodan`).
- **Tag enumeration:** `POST /qps/rest/2.0/search/am/tag` (XML body, `Content-Type:
  text/xml`) lists all tag names — used to confirm the exposure string.
- **KB:** `/api/2.0/fo/knowledge_base/vuln/` `action=list&details=All`; CVSS_V3 may
  be absent; CVE_LIST may be empty.

## Module interfaces (what to implement)

**`config/loader.py`** — `load_config(path) -> QjsyncConfig`; `ConfigError`.

**`sources/qualys/client.py`** — `QualysClient(api_url, username, password, *, requests_per_second, max_concurrency)`:
Basic auth + mandatory `X-Requested-With` header; token-bucket rps + concurrency
cap; retry/backoff on 5xx and Qualys concurrency-limit; `get/post(endpoint, params) -> bytes`.

**`sources/qualys/detection.py`** — `iter_detections(client, query: QualysQueryConfig, *, since: str | None = None, acs_pattern: str | None = None) -> Iterator[tuple[Asset, Detection]]`:
build params from the whitelist (the managed `since` overrides `query.vm_scan_since`
when provided); follow the HLD `<WARNING><URL>` truncation pointer. Parse
`DETECTION/QDS_FACTORS` → `Detection.rtis` (the `RTI` factor, comma-split) and
`Detection.qds_factors`. Persist `tracking_method` and `last_vm_scanned_date` onto
the Asset. If `acs_pattern` is set, derive `Asset.asset_criticality_score` =
MAX of `re.search(acs_pattern, tag).group(1)` over the asset's tags (None if no
match). **There is no TruRisk/ACS field in HLD 2.0 and `show_trurisk` is rejected.**

**`sources/qualys/knowledgebase.py`** — `fetch_kb(client, qids=None) -> Iterator[KbVuln]`
(paginated, `details=All`; parse `DIAGNOSIS`/`CONSEQUENCE`/`SOLUTION`, `CVSS`
BASE/TEMPORAL, optional `CVSS_V3` (often absent), `CVE_LIST/CVE/ID`, `CATEGORY`,
`PATCHABLE`/`PCI_FLAG` (0/1→bool), and `THREAT_INTELLIGENCE/THREAT_INTEL` text →
`KbVuln.rtis`). Note `KB.VULN_TYPE` ("Vulnerability"/"Potential") differs from the
detection's `TYPE` ("Confirmed"/"Potential"/"Information").

**`sources/qualys/source.py`** — `VmSource(SourceModule)`:
- `iter_merged(self, *, since=None)`: stream `iter_detections(..., since=since)`,
  enrich from KB cache (refresh on miss/stale), yield `MergedVulnerability`. Raise
  on incomplete fetch (purge safety).
- `refresh_knowledgebase() -> int`.

**`rules/operators.py`** / **`rules/engine.py`** — operator registry (None-safe;
list `contains` matches an exact element **or a substring within any element**, so
`asset_tags contains "Falcon"` finds the tag `"SW: CS Falcon Sensor Installed"`);
`RulesEngine(config).evaluate(merged) -> EvaluationResult` via the **band-shift**
model: `final = base_band(QDS) + Σ(±N modifier shifts)`, clamped to [skip, Highest].
Modifiers key off any `signal_context()` signal — threat-intel (`actively_attacked`,
`ransomware`, `wormable`, `zero_day`, `easy_exploit`, `has_exploit`), `epss`, exposure
(`asset_tags`), `asset_criticality`, `age_days`, `category`, … — and stack.
Gates: a `caps_at_high` modifier (exposure) never reaches Highest alone (Lever C);
Highest requires the QDS base ≥ High when `highest_requires_high_base` (Lever B). A
modifier flagged `bypasses_highest_gate` (confirmed in-the-wild exploitation / KEV)
**waives both** so "patch now" reaches Highest from any base. Only bands ≥
`materialize_min_band` create (action=CREATE); lower bands (Low) are classified
(priority set) with action=SKIP. `skip_when` short-circuits to skip. After scoring,
an orthogonal first-match `routing` pass may override the destination
(`project`/`issue_type`/`component`) and add labels **without touching priority**;
final labels = `JiraConfig` managed label + firing modifiers' labels + route labels.

**`jira/auth.py`** / **`client.py`** / **`adf.py`** / **`mapper.py`** — auth provider
(basic now, OAuth-ready); REST client with `discover_fields()` (name→id),
`find_issue_by_primary_key`, `create_issue`, `update_issue`, `get_issue`,
`list_transitions`, `transition_issue(name, resolution=None)`, 429 backoff; ADF
builder; `IssueMapper.build_fields(merged, evaluation, primary_key)` per
FIELD_MAPPING.md (omit None sources; dates as text).

**`state/db.py`** — `make_engine`, `make_session_factory`, `session_scope`, `create_all`/`drop_all`.

**`state/repositories.py`** (bound to a Session):
- `SyncRunRepo`: `start(mode: SyncMode) -> SyncRun`; `finish(run, status, **counts)`;
  `last_successful_full() -> SyncRun | None` (**filters `mode == FULL`**, for purge
  gating); `last_successful_any() -> SyncRun | None` (**any mode**, for the
  incremental window start).
- `DetectionStateRepo`: `get(pk)`; `upsert_seen(merged, pk, run_id, *, issue_key=None,
  qualys_status=None, material_hash=None, tracking_method=None,
  last_vm_scanned_date=None, signals=None)` (insert/update; set `first_seen_run` on
  insert, `last_seen_run=run_id`, reset `consecutive_misses=0`); `mark_missed(run_id)
  -> list[DetectionState]` (open rows with `last_seen_run < run_id`: increment
  `consecutive_misses`, return them); `iter_open()`; `record_closed(pk, reason,
  resolution, *, purged=False)`; `set_sticky(pk, resolution)`.
- `KbRepo`: `get(qid)`; `upsert_many(list[KbVuln]) -> int`; `age_hours(qid)`; `to_kbvuln(entry)`.
- `JobQueue`: `enqueue`, `claim_batch(n)` (`FOR UPDATE SKIP LOCKED` only on
  postgresql), `complete`, `fail`.

**`sync/purge.py`** — `classify_missing(state: DetectionState, cfg: PurgeConfig) -> Literal["stale", "keep"]`,
**tracking-method aware** (see below); plus `is_purge_eligible(run) -> bool`
(`run.mode == FULL and run.status == SUCCESS`).

**`sync/orchestrator.py`** — `SyncOrchestrator(source, engine, jira, session_factory, config)`
with `run(dry_run: bool = False, *, mode: SyncMode = "incremental") -> RunSummary`.

**`cli.py`** — typer `app`: `sync [--mode incremental|full] [--dry-run]`,
`dry-run` (= sync --dry-run, honouring --mode), `init-db`, `validate-config -c`,
`kb-refresh -c`.

## The sync algorithm (orchestrator.run)

**Step 1 — start.**
- `run = SyncRunRepo.start(mode)`.
- If `mode == incremental`: `since = (last_successful_any().started_at -
  incremental_overlap_minutes)` formatted as Qualys datetime (None if no prior
  run → first incremental behaves as a bounded full of the query scope). If
  `mode == full`: `since = None`.
- Iterate `source.iter_merged(since=since)`.

**Step 2 — per `MergedVulnerability`:**
- compute `primary_key` (PrimaryKeyConfig) and `material_hash`.
- `evaluation = engine.evaluate(merged)`; look up `DetectionState`.
- **Qualys STATUS=Fixed** → if an open issue exists, transition to Done with
  `resolution_fixed`, `closed_reason=fixed`. (Remediation.)
- **STATUS Active/New/Re-Opened**:
  - no issue & `evaluation.should_create` → create issue, write back Primary Key,
    record mapping (`material_hash`, `tracking_method`, `last_vm_scanned_date`).
  - no issue & skip → record state only.
  - issue exists & open →
    - if `material_hash` changed vs snapshot → **one idempotent PUT** updating
      material + telemetry together; optional rare comment on QDS/TruRisk/priority
      band change.
    - if only telemetry changed → **update the Postgres snapshot only**, no Jira
      write.
  - issue closed-by-fixed and now Re-Opened/Active → reopen (unless `sticky`).
  - issue closed-by-stale and detection returned → per `purge.reevaluate_on_return`
    (default: treat as a fresh evaluation).
  - **drift**: issue open but detection now below threshold (`skip`) → apply
    `DriftConfig.below_threshold` (default keep_open).
- mark `last_seen_run = run.id`; persist snapshot; count.

**Step 3 — purge pass (FULL mode only).** Guard: `is_purge_eligible(run)`
(`mode == full` and success). For each open `DetectionState` not seen this run
(`mark_missed`), call `classify_missing`. If `stale`: add `stale_label`, set
`resolution_stale`, `closed_reason=stale`, `purged_at=now`. Never closed as
`fixed`; never auto-reopened (see `reevaluate_on_return`). **Incremental runs skip
this step entirely.**

**Step 4 — non-surprise** everywhere: before closing/reopening/updating, read
current Jira state; never overwrite a `sticky_resolutions` resolution; set `sticky`.

**Step 5 — finish:** `SyncRunRepo.finish(SUCCESS, **counts)`; emit `RunSummary`.

`--dry-run`: all reads, no Jira writes; reports would-create / would-update /
would-close-fixed / would-mark-stale / would-reopen / skipped (per the chosen mode).

## Purge classification (tracking-method aware)

`classify_missing(state, cfg)` protects the network-scanned 10% from false purge:

- **Agent-tracked** (`tracking_method` contains "AGENT"): a sustained absence is a
  strong purge/decommission signal → stale once `consecutive_misses >=
  cfg.agent_grace_syncs`.
- **Network-scanned** (any non-agent tracking method): absence from a full run is
  expected if the appliance simply hasn't scanned it yet. Only a stale candidate
  once `last_vm_scanned_date` is **older than `cfg.network_scan_grace_days`** — i.e.
  the asset is overdue beyond its own (slower) cycle, not merely missing from a run.
- A successful FULL sync is still required (`require_full_sync`); the grace period
  alone only *delays* a false purge — the tracking-method gate is what *prevents*
  it for network assets.

## Cross-cutting rules

- **Idempotency & reentrancy.** Per-detection transactions + the `jobs` queue;
  an interrupted `sync` resumes cleanly.
- **Rate limiting.** Qualys: token bucket + concurrency cap, back off on
  concurrency-limit; Jira: honour HTTP 429 `Retry-After`.
- **Pagination.** HLD truncation pointer; KB pagination. Never assume one page.
- **Logging.** Structured (JSON by default). Per-run summary line with mode + all counts.
- **No live APIs in tests.** Mock with `responses`/fixtures; DB tests on SQLite.

## Key documented decisions

- Sync modes (incremental/full) with managed `vm_scan_since`; purge only on full.
- Material vs telemetry change detection (`material_hash`) to stop write-amplification.
- Tracking-method-aware purge (agent grace-syncs vs network scan-age days).
- Band-shift prioritisation (QDS base + stacking ±N multi-dimensional modifiers —
  threat-intel, EPSS, exposure, asset criticality, SLA age, reachability — clamped)
  with a structured condition AST (no `eval`); Highest hygiene (Levers B + C) with a
  `bypasses_highest_gate` escape hatch for confirmed in-the-wild exploitation; Low
  classified-but-not-materialised (`materialize_min_band`); orthogonal context
  `routing` (destination + labels) that never alters priority.
- `requests`/`typer`/pydantic2/SQLAlchemy2/psycopg3; dates kept as text.
- Primary key `HOST_ID:QID:PORT` with `none` sentinel; `UNIQUE_VULN_ID` optional.
