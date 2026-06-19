<h1 align="center">qjsync</h1>

<p align="center">
  <b>Turn hundreds of thousands of Qualys findings into a Jira queue your team can actually work.</b>
</p>

<p align="center">
  <a href="https://github.com/digitalgangst4r/qjsync/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/digitalgangst4r/qjsync/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-blue.svg">
  <img alt="Qualys" src="https://img.shields.io/badge/source-Qualys%20VMDR-1f6feb.svg">
  <img alt="Jira" src="https://img.shields.io/badge/target-Jira%20Cloud-0052cc.svg">
  <img alt="State" src="https://img.shields.io/badge/state-PostgreSQL-336791.svg">
</p>

---

The official Qualys ↔ Jira integration is a black box: it pushes findings you didn't choose,
prioritises them by rules you can't see, and closes tickets that were never actually fixed.
For a security team that has to **defend its ticket queue** to engineering and to auditors,
*"the vendor decided"* is not an answer.

**qjsync is the opposite.** It is a transparent, self-hosted connector where **you** decide
what becomes a ticket and at what priority — in a `rules.yml` you own and review like code.
It never dumps your whole inventory into Jira; it sends only the **prioritised, actionable**
subset, and keeps the lifecycle honest.

> Dumping hundreds of thousands of vulnerabilities into Jira is the wrong move: Jira is a *work tracker*, not a
> vulnerability database. Qualys stays the source of truth — qjsync forwards only the work.

## Why qjsync

| | qjsync | Typical vendor connector |
|---|---|---|
| **Prioritisation** | Your `rules.yml`: a QDS base band + stacking context modifiers, reviewed in PRs | Opaque, vendor-chosen |
| **Exposure aware** | Internet-facing **lowers the bar** to ticket (reachable = real risk) | Usually severity-only |
| **"Critical" means critical** | Highest is gated to genuinely-high QDS and/or active exploit | Inflated by raw CVSS |
| **Volume control** | Low band is *classified* but not ticketed until promoted | Everything becomes an issue |
| **Lifecycle** | Explicit Fixed / Re-Opened / Drift state machine | Often "delete and recreate" |
| **Purge ≠ remediation** | A vanished detection closes as **Stale**, never **Fixed** | Frequently closed as resolved (a lie) |
| **Write discipline** | Only *material* changes write; 4h telemetry never re-tickets | Re-writes on every scan round |
| **Auditability** | Each priority carries its maths; structured logs; idempotent writes | Limited |
| **Where your data lives** | PostgreSQL you host | Vendor cloud |

## What it delivers

- 🎯 **Prioritisation you control.** A declarative `rules.yml` decides *what* becomes a ticket and *at what priority* — versionable, diff-able, auditable.
- 🧮 **QDS-based band-shift model.** Priority starts from Qualys's own QDS, then context (exposure, active exploit, local-only reach) nudges it — explainable on every ticket.
- 🌐 **Exposure as a multiplier.** Internet-facing assets cross the bar sooner, because reachability turns theoretical risk into real risk.
- 🧹 **Signal, not noise.** The Low band is classified but never ticketed unless it gets worse — your queue stays workable.
- 🔁 **An honest lifecycle.** Fixed, Re-Opened, Drift, and **Purge ≠ Fixed** — a disappeared detection is closed as *Stale*, never mislabelled as remediated.
- ⏱️ **Built for 24/7.** Incremental syncs every ~4h (agent cadence) + a full reconciliation that runs purge.
- 🔌 **Pluggable sources.** VMDR today; the canonical model keeps WAS/Container drop-in.

## Architecture

Everything downstream of a source speaks one **canonical model** — sources translate raw API
payloads into it, which is what keeps future source modules drop-in.

```
        Qualys VMDR (HLD + KB)                          Jira Cloud REST v3
                 │                                              ▲
                 ▼                                              │
        sources/qualys (VmSource) ─ canonical ─►  rules.engine ─► jira.mapper/client
                 │  MergedVulnerability                 │  EvaluationResult        │
                 └───────────────► sync.orchestrator ◄──┘                          │
                                         │  (modes · snapshot diff · lifecycle)     │
                                         ▼                                          ▼
                                   state (PostgreSQL)  ◄──────────────────  state (mapping)
```

## How prioritisation works

Priority is **derived from QDS, then nudged by context** — a band-shift model:

```
final_band = base_band(QDS) + Σ(±N context modifiers)      (clamped skip … Highest)
```

**Base band** (Qualys's QDS is the trusted starting point):

| QDS | Band |
|---|---|
| ≥ 90 | Highest |
| ≥ 70 | High |
| ≥ 60 | Medium |
| below | skip |

**Modifiers** express *your* risk appetite across several dimensions and **stack**:

| Dimension | Signal → modifier | shift |
|---|---|---|
| **Threat intel** | actively-attacked / KEV-grade | **+2** *(bypasses the Highest gate)* |
| | ransomware | **+2** |
| | wormable · EPSS ≥ 0.5 · generic exploit available | **+1** each |
| **Exposure** | internet-facing · DMZ · external attack surface | **+1** each *(caps at High)* |
| **Asset** | high-criticality asset / low-criticality asset | **+1 / −1** |
| **SLA** | open beyond the remediation window | **+1** |
| **Reachability** | local-only category / compensating control (EDR/proxy) | **−1** each |

Three guard-rails keep **Highest** meaningful: exposure alone caps at High, and Highest requires
a QDS base already ≥ 70 — so a QDS 26 with a public exploit lands **Low/Medium, not critical**.
The one deliberate exception is **confirmed in-the-wild exploitation** (actively-attacked / KEV),
which *bypasses* both gates to reach Highest from any base — "patch now" should never be capped.
Only bands **≥ Medium** become Jira issues; **Low** is classified but not ticketed until promoted.

**Context routing** (orthogonal to priority) sends findings to a different project, component, or
label by context — e.g. PCI-in-scope detections get a `pci-scope` label, a business unit routes to
its own Jira project — without ever changing the computed band.

Full detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · [`docs/JIRA_SETUP.md`](docs/JIRA_SETUP.md) · [`docs/FIELD_MAPPING.md`](docs/FIELD_MAPPING.md) · [`docs/LIFECYCLE.md`](docs/LIFECYCLE.md) · a commented [`examples/rules.yml`](examples/rules.yml).

## Quickstart

Requires **Python 3.11+** and **PostgreSQL**.

```bash
# 1. Install
git clone https://github.com/digitalgangst4r/qjsync.git && cd qjsync
python -m venv .venv && . .venv/bin/activate
pip install -e .                      # add ".[dev]" for tests/lint

# 2. Secrets (gitignored) — NEVER in rules.yml
cp .env.example .env                  # fill in Qualys + Jira creds + DB URL

# 3. Jira project + custom fields (see docs/JIRA_SETUP.md)
python scripts/bootstrap_jira_fields.py --dry-run   # then drop --dry-run to create

# 4. Rules
cp examples/rules.yml rules.yml       # set your project key (or $JIRA_PROJECT_KEY) + tags + bands

# 5. Bring up state + run
docker compose -f docker/docker-compose.yml up -d postgres
qjsync init-db
qjsync validate-config -c rules.yml
qjsync dry-run        -c rules.yml     # read-only: reports would-create/update/close/…
qjsync sync --mode full -c rules.yml   # first reconciliation
```

> Always start with `dry-run` — it does every read and reports exactly what a real run would
> do, without touching Jira.

## CLI

| Command | Description |
|---|---|
| `qjsync validate-config -c rules.yml` | Parse + validate the ruleset; fail fast. |
| `qjsync init-db` | Create the PostgreSQL state schema. |
| `qjsync kb-refresh -c rules.yml` | Refresh the local KnowledgeBase cache. |
| `qjsync sync -c rules.yml [--mode incremental\|full] [--dry-run]` | Run a sync. `--mode` defaults to `incremental`; `full` adds the purge pass. |
| `qjsync dry-run -c rules.yml [--mode …]` | Alias for `sync --dry-run` (writes nothing). |

**Steady state (cron / systemd timer / k8s CronJob):**

```bash
qjsync sync --mode incremental -c rules.yml   # every ~4h, aligned to the agent cadence
qjsync sync --mode full        -c rules.yml   # daily/weekly reconciliation (enables purge)
```

## Lifecycle: it tells the truth

- **Fixed** → Qualys reported `STATUS=Fixed`: closed with a *Fixed* resolution.
- **Re-Opened** → reappears active: reopened (unless a human set a sticky resolution).
- **Drift** → priority drops below threshold: kept open (no flapping on score noise).
- **Purge ≠ Fixed** → a detection that *vanishes* without ever being Fixed (decommissioned,
  aged out) is closed as **Stale** — never as resolved. Purge is inferred only on a successful
  **full** sync, with a grace period, and is **tracking-method aware** so slow network-scanned
  assets aren't false-purged.

## Configuration & secrets

Two strictly separated concerns:

- **`rules.yml`** — versionable, non-secret: the Qualys query, the prioritisation, lifecycle behaviour.
- **Environment / `.env`** — secrets only: Qualys + Jira credentials and the database URL. Never in `rules.yml`.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, the exact sync algorithm, the verified Qualys API grounding.
- [`docs/FIELD_MAPPING.md`](docs/FIELD_MAPPING.md) — every Qualys → Jira field + the material-vs-telemetry write model.
- [`docs/LIFECYCLE.md`](docs/LIFECYCLE.md) — the state machine, fixed-vs-purge, and the band-shift hygiene.

## Contributing & Security

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md).

## License

[Apache-2.0](LICENSE).
