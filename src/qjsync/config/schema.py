"""Pydantic schema for the versionable ``rules.yml``.

Design decisions (documented, not reopened):

* **Structured conditions, not a string DSL.** A modifier's ``when`` (and the
  ``skip_when`` pre-filter) is a typed AST (``all`` / ``any`` / ``not`` / leaf
  ``{signal, op, value}``) rather than an ``eval``'d expression. For a security
  tool this avoids arbitrary code execution, validates cleanly at startup, and is
  trivially testable. New signals are just new keys in ``signal_context()``; new
  operators are a single registry entry — neither requires touching this schema.

* **Band-shift prioritisation (not first-match-wins).** Priority is derived from
  QDS (the trusted base — Qualys already folds RTIs/exposure into it) and then
  shifted by stacking ±N context modifiers (exposure, exploit, local), clamped to
  [skip, Highest]. Exposure, exploit and Local are the *same* mechanism, so the
  result is predictable and explainable ("QDS 70, +1 exposed, +1 exploit ->
  Highest"). See :class:`PrioritizationConfig`.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Operators the engine understands. Mirrored by the engine's registry; kept here
# so the schema can reject unknown operators at load time.
Operator = Literal[
    "==", "!=", ">", ">=", "<", "<=",
    "in", "not_in", "contains", "not_contains",
    "exists", "not_exists", "matches",
]


class Condition(BaseModel):
    """A boolean expression over signals.

    Exactly one *form* must be set per node:

    * leaf:        ``{signal: qds, op: ">=", value: 90}``
    * conjunction: ``{all: [<condition>, ...]}``
    * disjunction: ``{any: [<condition>, ...]}``
    * negation:    ``{not: <condition>}``
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    # leaf
    signal: str | None = None
    op: Operator | None = None
    value: Any = None

    # composites
    all_: list[Condition] | None = Field(default=None, alias="all")
    any_: list[Condition] | None = Field(default=None, alias="any")
    not_: Condition | None = Field(default=None, alias="not")

    @model_validator(mode="after")
    def _exactly_one_form(self) -> Condition:
        is_leaf = self.signal is not None
        forms = [is_leaf, self.all_ is not None, self.any_ is not None, self.not_ is not None]
        if sum(bool(f) for f in forms) != 1:
            raise ValueError(
                "each condition must be exactly one of: a leaf {signal, op, value}, "
                "or {all: [...]}, {any: [...]}, {not: {...}}"
            )
        if is_leaf and self.op is None:
            raise ValueError(f"leaf condition on signal '{self.signal}' needs an 'op'")
        # 'exists'/'not_exists' take no value; everything else requires one.
        if is_leaf and self.op not in ("exists", "not_exists") and self.value is None:
            raise ValueError(f"operator '{self.op}' on signal '{self.signal}' requires a 'value'")
        return self


# ---------------------------------------------------------------------------
# Prioritisation: a UNIFIED band-shift model (supersedes the old first-match
# rule list).  final_band = base_band(QDS) + Σ(±N context modifiers), clamped to
# [skip, Highest].  QDS is the trusted base — Qualys already folds RTIs/exposure
# into it — so modifiers only express how *our* risk appetite differs from its
# generic default: exposure, active exploit, and local-only reachability each
# nudge the band by one level. Exposure, exploit and Local are the SAME mechanism.
# ---------------------------------------------------------------------------
class QdsBands(BaseModel):
    """QDS thresholds for the base band (before modifiers). Below ``medium`` -> skip."""

    model_config = ConfigDict(extra="forbid")

    highest: int = 90  # qds >= highest -> Highest
    high: int = 70     # qds >= high    -> High
    medium: int = 50   # qds >= medium  -> Medium ; below medium -> skip

    @model_validator(mode="after")
    def _ordered(self) -> QdsBands:
        if not (self.highest >= self.high >= self.medium):
            raise ValueError("qds_bands must satisfy highest >= high >= medium")
        return self


class Modifier(BaseModel):
    """A context modifier: when ``when`` holds, the QDS-derived band shifts by
    ``shift`` levels. Shifts STACK (algebraic sum); the result is clamped to
    [skip, Highest]. ``label`` (if set) is added to the issue when it fires."""

    model_config = ConfigDict(extra="forbid")

    name: str
    when: Condition
    shift: int  # e.g. +1 (internet-facing / active exploit) or -1 (local category)
    label: str | None = None
    # Lever C: a modifier that "caps at High" can never, on its own, push a
    # detection to Highest — its positive lift tops out at High. Used so exposure
    # alone (internet-facing) is High at most; only a non-capped contributor
    # (active exploit) or a base already in the Highest band reaches Highest.
    caps_at_high: bool = False
    # Escape hatch from the Highest hygiene gates (Levers B + C): a firing modifier
    # with this set lets the result reach Highest even from a sub-High QDS base.
    # Reserved for the strongest real-world signals (confirmed in-the-wild /
    # KEV-grade exploitation), where "patch now" outranks the QDS base.
    bypasses_highest_gate: bool = False

    @model_validator(mode="after")
    def _nonzero(self) -> Modifier:
        if self.shift == 0:
            raise ValueError(f"modifier '{self.name}' has shift 0 (no effect)")
        return self


class RoutingRule(BaseModel):
    """Orthogonal routing: the FIRST matching rule sets the Jira destination
    (project / component / extra labels) for a detection, independent of priority.
    Lets different business units / scopes (e.g. PCI) land in different projects."""

    model_config = ConfigDict(extra="forbid")

    name: str
    when: Condition
    project: str | None = None
    component: str | None = None
    issue_type: str | None = None
    labels: list[str] = Field(default_factory=list)


class PrioritizationConfig(BaseModel):
    """The band-shift prioritisation model: a QDS base band + stacking modifiers."""

    model_config = ConfigDict(extra="forbid")

    qds_bands: QdsBands = Field(default_factory=QdsBands)
    modifiers: list[Modifier] = Field(default_factory=list)
    skip_when: Condition | None = None  # noise pre-filter -> always skip
    # Lever B: Highest requires the QDS *base* to already be in the High band
    # (qds >= qds_bands.high). No modifier can manufacture a Highest from a
    # Medium/skip base. Set False to let modifiers reach Highest from any base.
    highest_requires_high_base: bool = True
    # Lever D-narrow: only bands at or above this are MATERIALISED as Jira issues.
    # Lower bands are still classified/recorded in state (for promotion detection)
    # but create no ticket until promoted. Default Medium (Low is classified, not
    # ticketed).
    materialize_min_band: Literal["Low", "Medium", "High", "Highest"] = "Medium"
    # Orthogonal context routing (first match wins) — overrides the destination
    # project/component/issue_type and adds labels, without affecting priority.
    routing: list[RoutingRule] = Field(default_factory=list)


class QualysQueryConfig(BaseModel):
    """Whitelisted Host List Detection parameters the operator may set.

    These are passed straight through to ``/api/2.0/fo/asset/host/vm/detection/``.
    Secrets (username/password/platform URL) live in the environment, never here.

    **vm_scan_since precedence.** ``vm_scan_since`` here is a *static* floor for
    the full-scope query. In ``incremental`` mode the connector computes and
    injects its own managed ``vm_scan_since`` (from the last successful sync minus
    ``QualysConfig.incremental_overlap_minutes``); that **managed value wins** and
    overrides this static one. In ``full`` mode the connector injects no window
    and this static value (if set) is used verbatim. See ARCHITECTURE.md §sync.
    """

    model_config = ConfigDict(extra="forbid")

    severities: str | None = None  # e.g. "3-5"
    status: str | None = None  # e.g. "Active,Re-Opened,New,Fixed"
    show_igs: int | None = None  # include information-gathered
    # REQUIRED for the exposure layer: includes asset TAGS in the response so the
    # `asset_tags` signal (e.g. "Internet Facing Assets") is populated. Without it
    # the exposure rules silently never match (contains on an empty list is False).
    show_tags: int = 1
    # NOTE: HLD 2.0 has NO TruRisk/ACS field and rejects `show_trurisk` (HTTP 400).
    # QDS comes from show_qds; RTIs come from QDS_FACTORS (show_qds_factors).
    show_qds: int = 1
    show_qds_factors: int = 1
    show_reopened_info: int = 1
    qids: str | None = None
    ids: str | None = None
    id_min: int | None = None
    vm_scan_since: str | None = None  # static floor; overridden by managed window in incremental
    vm_processed_since: str | None = None
    detection_updated_since: str | None = None
    use_tags: int | None = None
    tag_set_by: str | None = None
    tag_set_include: str | None = None
    tag_set_exclude: str | None = None
    truncation_limit: int = 1000
    extra: dict[str, str] = Field(default_factory=dict)  # escape hatch, still whitelisted by caller


class QualysConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module: Literal["vm"] = "vm"  # WAS/Container are future source modules
    query: QualysQueryConfig = Field(default_factory=QualysQueryConfig)
    kb_refresh_max_age_hours: int = 24
    requests_per_second: float = 2.0
    max_concurrency: int = 2  # Qualys caps concurrent API calls per subscription
    # Overlap subtracted from the last successful sync's start when computing the
    # managed ``vm_scan_since`` for an incremental run, so edge detections near the
    # boundary are not missed. Tune relative to the 4h agent cadence.
    incremental_overlap_minutes: int = 30
    # HLD 2.0 exposes no Asset Criticality Score field. Some orgs encode ACS as
    # asset tags (e.g. "ACS-4"). If set, this regex's group(1) is parsed from
    # each asset tag and the MAX match becomes `asset_criticality` (None if no
    # match). Leave null to disable. Example: r"(?i)ACS[-_ ]?(\d)".
    asset_criticality_tag_pattern: str | None = None


class JiraConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # `project` is required only when the active sink is `jira` (validated on QjsyncConfig).
    project: str = ""
    issue_type: str = "Host Vulnerability"
    primary_key_field: str = "Primary Key"
    # Transitions / resolutions for the lifecycle. Names are resolved to ids at runtime.
    done_transition: str = "Done"
    reopen_transition: str = "Reopen"
    resolution_fixed: str = "Fixed"
    resolution_stale: str = "Stale - asset/detection purged"
    stale_label: str = "qjsync-stale"
    managed_label: str = "qjsync"
    # Derived patch routing (orthogonal to priority): the mapper auto-adds exactly
    # one of these labels from KB ``patchable`` so the patch lane and the
    # mitigation/triage lane are separated WITHOUT multiplying the priority rules.
    # patchable is used for routing, never as a creation gate.
    derive_patch_routing: bool = True
    patch_label: str = "auto-patch"  # patchable == True
    mitigation_label: str = "needs-mitigation"  # patchable == False (EOL/0-day/config)
    # Resolutions a human may set that the connector must never overwrite.
    sticky_resolutions: list[str] = Field(
        default_factory=lambda: ["Won't Do", "Won't Fix", "Risk Accepted"]
    )
    requests_per_second: float = 8.0


class DriftConfig(BaseModel):
    """What to do when an existing issue's detection later drops below threshold."""

    model_config = ConfigDict(extra="forbid")

    below_threshold: Literal["keep_open", "close", "downgrade"] = "keep_open"


class PurgeConfig(BaseModel):
    """Heuristic separating *purge* (not remediation) from *fixed*, with separate
    thresholds per tracking method so network-scanned (non-agent) assets are not
    false-purged just for not being scanned within a window.

    Purge can only ever be inferred from a **successful FULL-mode** sync
    (``require_full_sync``); incremental runs never mark anything stale.
    """

    model_config = ConfigDict(extra="forbid")

    # Agent-tracked assets (Cloud Agent, ~4h cadence): a sustained absence across
    # this many consecutive successful full syncs is a strong purge/decommission
    # signal.
    agent_grace_syncs: int = 2
    # Network-scanned assets (no agent, appliance cadence): only a stale candidate
    # once ``last_vm_scanned_date`` is older than this many days — i.e. the asset
    # is overdue beyond its own (slower) scan cycle, not merely absent from a run.
    # Conservative by default to avoid false purge of the ~10% non-agent estate.
    network_scan_grace_days: int = 30
    require_full_sync: bool = True  # never infer purge from a partial/failed/incremental sync
    reevaluate_on_return: bool = True  # a purged detection that returns is treated as new


class PrimaryKeyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    port_sentinel: str = "none"
    include_unique_vuln_id: bool = False


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: str = "INFO"
    format: Literal["json", "console"] = "json"


class QjsyncConfig(BaseModel):
    """Root of ``rules.yml``."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    # Where the sync lifecycle writes issue state:
    #   jira  -> Jira Cloud over HTTP (requires jira.project + JIRA_* secrets)
    #   local -> the dash.issues work-layer in the same Postgres (no HTTP, no rate limit)
    #   none  -> no-op sink (dashboard-only via a plain read of detection_state)
    sink: Literal["jira", "local", "none"] = "jira"
    qualys: QualysConfig = Field(default_factory=QualysConfig)
    jira: JiraConfig = Field(default_factory=JiraConfig)
    prioritization: PrioritizationConfig = Field(default_factory=PrioritizationConfig)
    drift: DriftConfig = Field(default_factory=DriftConfig)
    purge: PurgeConfig = Field(default_factory=PurgeConfig)
    primary_key: PrimaryKeyConfig = Field(default_factory=PrimaryKeyConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @model_validator(mode="after")
    def _require_jira_project_for_jira_sink(self) -> QjsyncConfig:
        """``jira.project`` is mandatory only when the active sink is ``jira``."""
        if self.sink == "jira" and not self.jira.project:
            raise ValueError("jira.project is required when sink is 'jira'")
        return self
