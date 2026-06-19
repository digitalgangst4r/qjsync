# qjsync — Detection lifecycle & purge

Qualys is the **source of truth**. State flows Qualys → Jira only; qjsync never
writes to Qualys. It does *read* Jira state to avoid overriding human action.

## Sync modes recap

| Mode | Window | Creates/Updates/Closes-Fixed/Reopens | Purge pass | Cadence |
|---|---|---|---|---|
| `incremental` | managed `vm_scan_since` (last success − overlap) | yes | **no** | every ~4h (agent) |
| `full` | whole query scope | yes | **yes** | weekly / slowest network cadence |

Only a **successful `full`** run may mark anything stale. Incremental runs deliberately
skip purge so the 4h delta never looks like mass disappearance.

## State machine (Qualys status → Jira action)

| Qualys `STATUS` | Existing issue? | qjsync action |
|---|---|---|
| New / Active | none, rule = create | **create** issue (write Primary Key, snapshot `material_hash`, tracking, last scan) |
| New / Active | none, rule = skip | record state only; no issue |
| Active | open | if `material_hash` changed → **one PUT** (material + telemetry); else snapshot-only, **no Jira write** |
| Re-Opened | open | update as Active |
| Re-Opened / Active | closed by **fixed** | **reopen** (unless resolution is sticky) |
| New / Active | closed by **stale** (purge) | per `purge.reevaluate_on_return` (default: treat as fresh evaluation) |
| **Fixed** | open | **transition to Done**, `resolution = resolution_fixed`, `closed_reason = fixed` (remediation) |
| *(missing from a full run)* | open | purge candidate → `classify_missing` (below) |

## Prioritisation & materialisation (band-shift model)

Priority is `final = base_band(QDS) + Σ(±N modifiers)`, clamped `[skip, Highest]`
(see `docs/ARCHITECTURE.md`). Two hygiene gates protect the top band:

- **Lever B** — Highest requires the QDS *base* to already be High (qds ≥ `high`);
  no modifier manufactures a Highest from a Medium/skip base.
- **Lever C** — a `caps_at_high` modifier (internet-facing) can lift at most to
  High; exposure alone never reaches Highest. Only a non-capped contributor
  (active exploit) or a base already in the Highest band gets there.

**Materialisation (Lever D-narrow).** Only bands **≥ `materialize_min_band`**
(default **Medium**) become Jira issues. Lower bands (**Low**) are **classified but
not materialised**:

- A Low detection **is** evaluated and its state **is** recorded in Postgres
  (`detection_state`, `jira_issue_key = NULL`) so the connector can detect a later
  promotion and not reprocess it as brand-new. It stays visible in Qualys (the
  source of truth); it just does not create a low-priority ticket the team won't
  action before the rest.
- **Promotion (Low → Medium+).** When a previously-Low detection rises a band
  (QDS climbs, gains an exploit, exposure changes), it now materialises — handled
  as a **fresh create** (no prior issue existed), with the open comment.
- **Demotion (Medium+ → Low).** A detection that *had* a ticket and now classifies
  Low is **drift**: `DriftConfig.below_threshold` applies (default `keep_open`).
  We do **not** close a ticket because its band fell — only Qualys `STATUS=Fixed`
  or a confirmed purge closes it.

> "Low is classified but not materialised; it becomes a ticket only when promoted."

**Drift.** An open issue whose detection later evaluates below the materialise
threshold (e.g. → Low) is handled by `DriftConfig.below_threshold` — default
`keep_open` (we do not flap issues open/closed on score fluctuation).

**Non-surprise.** Before any close/reopen/update, qjsync reads the current Jira
issue. A resolution in `jira.sticky_resolutions` (e.g. *Won't Do*, *Risk Accepted*)
is never overwritten; the row is flagged `sticky` and left alone.

## Fixed vs Purge — the core distinction

- **Fixed** — Qualys explicitly reports `STATUS=Fixed`. The vulnerability was
  genuinely remediated. → close with `resolution_fixed`, `closed_reason=fixed`.
- **Purged / Stale** — the detection **disappears** from the Host List Detection
  result *without* ever being reported Fixed (asset decommissioned, removed, or
  aged out by Qualys retention). This is **not** remediation. →
  - label `stale_label` (`qjsync-stale`), `resolution_stale`
    ("Stale - asset/detection purged"), `closed_reason=stale`, `purged_at=now`;
  - **not** auto-reopened if it returns (governed by `reevaluate_on_return`);
  - recorded in `detection_state` with the purge timestamp.

Closing a purge as "Fixed" would be a dangerous lie (it implies remediation that
never happened) — hence the separate reason and resolution.

## Detecting purge — snapshot diff + grace + tracking method

Purge is inferred by **snapshot diff**: every full sync stamps `last_seen_run` on
each detection it sees. After the run, open detections **not** seen this run have
their `consecutive_misses` incremented (`mark_missed`). A miss becomes *stale* only
when **all** of these hold:

1. **Mode + success gate** — the current run is `mode == full` and succeeded
   (`require_full_sync`). A partial/failed/incremental run never marks stale.
2. **Tracking-method gate** (`classify_missing`):
   - **Agent-tracked** (`tracking_method` contains "AGENT", ~4h cadence): sustained
     absence is a strong purge/decommission signal → stale once
     `consecutive_misses >= purge.agent_grace_syncs` (default **2**).
   - **Network-scanned** (any non-agent method, appliance cadence): absence from a
     run is *expected* if the appliance simply hasn't scanned the asset yet. So it
     is only a stale candidate once `last_vm_scanned_date` is **older than
     `purge.network_scan_grace_days`** (default **30** days) — i.e. the asset is
     overdue beyond its own slower cycle, not merely missing from one run.

The grace period alone only *delays* a false purge; the tracking-method gate is
what *prevents* it for the ~10% network-scanned estate. Both defaults are
deliberately conservative — prefer a lingering issue over a wrongly "resolved" one.

### Why this matters operationally

With ~90% agent-tracked assets reassessed every 4h, a genuinely decommissioned
agent host is confidently purgeable after a couple of weekly fulls. A network
asset that just wasn't in this week's appliance scan window must **not** be purged
on absence alone — only when it has demonstrably not been scanned for longer than
its expected cycle.

## Idempotency

Every Jira write is idempotent (find-by-Primary-Key before create; PUT carries the
full field set). An interrupted sync resumes cleanly: per-detection transactions
plus the `jobs` queue mean re-running reconciles rather than duplicates.
