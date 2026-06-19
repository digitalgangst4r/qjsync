"""Canonical domain objects.

The merge order is: a :class:`Detection` (host+QID+port) is enriched with its
host :class:`Asset` and the :class:`KbVuln` (KnowledgeBase entry for the QID)
into a :class:`MergedVulnerability`. That merged object exposes a flat
``signal_context()`` mapping that the rules engine evaluates, and is the single
input the Jira mapper consumes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from qjsync.models.identity import compute_primary_key

# Real-Time Threat Indicators that signal an *available/active* exploit (vs mere
# impact indicators like High_Data_Loss). RTIs are sourced from the detection's
# QDS_FACTORS (factor name=RTI) and/or the KB THREAT_INTELLIGENCE block. Used to
# derive ``has_exploit``. Tune per environment.
EXPLOIT_RTI_MARKERS = (
    "Exploit_Public",
    "Exploit_Kit",
    "Active_Attacks",
    "Malware",
    "Wormable",
    "Zero_Day",
    "Easy_Exploit",
    "Predicted_High_Risk",
)

# RTIs ranked most -> least critical, used to surface the single most critical RTI
# of a vulnerability as a Jira label. Names not listed rank below every listed one.
RTI_CRITICALITY: tuple[str, ...] = (
    "Active_Attacks",
    "Actively_Attacked",
    "Ransomware",
    "Wormable",
    "Exploit_Public",
    "Public_Exploit",
    "Exploit_Kit",
    "Easy_Exploit",
    "Malware",
    "Zero_Day",
    "Unauthenticated_Exploitation",
    "Remote_Code_Execution",
    "Predicted_High_Risk",
    "Privilege_Escalation",
    "High_Lateral_Movement",
    "Denial_of_Service",
    "High_Data_Loss",
    "No_Patch",
)


def most_critical_rti(rtis: list[str]) -> str | None:
    """Return the single most critical RTI present (by :data:`RTI_CRITICALITY`),
    falling back to the first RTI when none are ranked; ``None`` if there are none."""
    if not rtis:
        return None
    rank = {name.lower(): i for i, name in enumerate(RTI_CRITICALITY)}
    return min(
        (r.strip() for r in rtis if r.strip()),
        key=lambda r: rank.get(r.lower(), len(RTI_CRITICALITY)),
        default=None,
    )


# Qualys datetime format used across HLD/KB, e.g. "2024-10-15T13:45:02Z".
_QUALYS_DT_FMT = "%Y-%m-%dT%H:%M:%SZ"

# --- Write-amplification control: MATERIAL vs TELEMETRY -----------------------
# A detection re-evaluated by the Cloud Agent every ~4h returns fresh scan
# timestamps every round. If those fed the change-detection hash, every active
# detection would be re-written to Jira every 4h (polluted history, rate limits).
# So only MATERIAL fields feed ``material_hash()``; TELEMETRY rides along on a
# write that a material change already triggered, and on its own changes only the
# Postgres snapshot — never Jira.

# Keys into ``MergedVulnerability.signal_context()`` whose change is MATERIAL and
# SHOULD trigger a Jira write.
MATERIAL_SIGNAL_KEYS: tuple[str, ...] = (
    "status",  # lifecycle: Active / New / Re-Opened / Fixed
    "qds",
    "trurisk",
    "severity",
    "cvss_base",
    "cvss_temporal",
    "cvss_v3_base",
    "cvss_v3_temporal",
    "patchable",
    "pci_flag",
    "asset_criticality",
)

# Fields that change ~every 4h and must NOT, on their own, trigger a Jira write.
TELEMETRY_FIELD_KEYS: tuple[str, ...] = (
    "last_scan_datetime",
    "last_vm_scanned_date",
    "last_vm_scanned_duration",
    "first_found_datetime",
    "last_found_datetime",
    "last_update_datetime",
    "last_processed_datetime",
    "last_test_datetime",
    "last_fixed_datetime",
    "times_found",
    "last_service_modification_datetime",
)


class DetectionStatus(str, Enum):
    """Lifecycle status reported by Qualys for a detection (HLD ``STATUS``)."""

    NEW = "New"
    ACTIVE = "Active"
    REOPENED = "Re-Opened"
    FIXED = "Fixed"


class JiraPriority(str, Enum):
    """Jira priority names a rule may assign."""

    HIGHEST = "Highest"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    LOWEST = "Lowest"


class RuleAction(str, Enum):
    """What a matching rule decides to do with a detection."""

    CREATE = "create"
    SKIP = "skip"


class Asset(BaseModel):
    """Host-level attributes (Host List Detection ``HOST`` block)."""

    model_config = ConfigDict(extra="ignore")

    host_id: int
    asset_id: int | None = None
    ip: str | None = None
    ipv6: str | None = None
    tracking_method: str | None = None
    os: str | None = None
    dns: str | None = None
    netbios: str | None = None
    qg_hostid: str | None = None
    network_id: int | None = None
    last_scan_datetime: str | None = None
    last_vm_scanned_date: str | None = None
    last_vm_scanned_duration: int | None = None
    last_processed_datetime: str | None = None
    asset_tags: list[str] = Field(default_factory=list)
    # TruRisk / asset criticality (present when requested via show_qds/show_trurisk).
    trurisk_score: float | None = None
    asset_criticality_score: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class Detection(BaseModel):
    """A single vulnerability detection on a host (``DETECTION`` element)."""

    model_config = ConfigDict(extra="ignore")

    qid: int
    port: int | None = None
    protocol: str | None = None
    ssl: int | None = None  # 0/1
    severity: int | None = None
    status: DetectionStatus | None = None
    vuln_type: str | None = None  # TYPE: Confirmed / Potential / Information
    results: str | None = None
    qds: int | None = None  # Qualys Detection Score (0-100)
    unique_vuln_id: int | None = None
    is_ignored: int | None = None  # 0/1
    is_disabled: int | None = None  # 0/1
    first_found_datetime: str | None = None
    last_found_datetime: str | None = None
    times_found: int | None = None
    last_test_datetime: str | None = None
    last_update_datetime: str | None = None
    last_fixed_datetime: str | None = None
    last_processed_datetime: str | None = None
    # Real-Time Threat Indicators parsed from QDS_FACTORS (factor name=RTI),
    # e.g. ["Denial_of_Service", "Remote_Code_Execution", "Exploit_Public"].
    rtis: list[str] = Field(default_factory=list)
    qds_factors: dict[str, str] = Field(default_factory=dict)  # raw QDS_FACTORS by name
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def detection_status(self) -> str | None:
        """Raw status text for the read-only ``Detection Status`` Jira field."""
        return self.status.value if self.status is not None else None


class KbVuln(BaseModel):
    """KnowledgeBase entry for a QID (enrichment source)."""

    model_config = ConfigDict(extra="ignore")

    qid: int
    title: str | None = None
    category: str | None = None  # VULN_CATEGORY
    severity_level: int | None = None
    vuln_type: str | None = None
    published_datetime: str | None = None
    last_service_modification_datetime: str | None = None
    patchable: bool | None = None
    pci_flag: bool | None = None
    cvss_base: float | None = None
    cvss_temporal: float | None = None
    cvss_v3_base: float | None = None
    cvss_v3_temporal: float | None = None
    diagnosis: str | None = None  # THREAT
    consequence: str | None = None  # IMPACT
    solution: str | None = None
    cve_list: list[str] = Field(default_factory=list)
    rtis: list[str] = Field(default_factory=list)  # Real-Time Threat Indicators
    raw: dict[str, Any] = Field(default_factory=dict)


class EvaluationResult(BaseModel):
    """Outcome of running the rules engine over one merged vulnerability."""

    model_config = ConfigDict(extra="ignore")

    action: RuleAction
    matched_rule: str | None = None  # rule name, or None for the implicit default
    priority: JiraPriority | None = None
    project: str | None = None
    issue_type: str | None = None
    labels: list[str] = Field(default_factory=list)
    component: str | None = None

    @property
    def should_create(self) -> bool:
        return self.action is RuleAction.CREATE


def _parse_qualys_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, _QUALYS_DT_FMT).replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


class MergedVulnerability(BaseModel):
    """Detection + Asset + KB, the canonical unit of work.

    ``signal_context()`` flattens everything a rule might reference into a single
    dict; new signals are added here without touching the engine.
    """

    model_config = ConfigDict(extra="ignore")

    asset: Asset
    detection: Detection
    kb: KbVuln | None = None

    # ----- identity -----
    def primary_key(
        self,
        *,
        port_sentinel: str = "none",
        include_unique_vuln_id: bool = False,
    ) -> str:
        return compute_primary_key(
            self.asset.host_id,
            self.detection.qid,
            self.detection.port,
            port_sentinel=port_sentinel,
            unique_vuln_id=self.detection.unique_vuln_id,
            include_unique_vuln_id=include_unique_vuln_id,
        )

    # ----- derived signals -----
    @property
    def all_rtis(self) -> list[str]:
        """RTIs from the detection (QDS_FACTORS) unioned with the KB (THREAT_INTELLIGENCE)."""
        rtis = list(self.detection.rtis)
        if self.kb:
            rtis += self.kb.rtis
        return rtis

    @property
    def has_cve(self) -> bool:
        return bool(self.kb and self.kb.cve_list)

    @property
    def has_exploit(self) -> bool:
        joined = " ".join(self.all_rtis)
        return any(marker.lower() in joined.lower() for marker in EXPLOIT_RTI_MARKERS)

    @property
    def top_rti(self) -> str | None:
        """The single most critical RTI of this vulnerability (for a Jira label)."""
        return most_critical_rti(self.all_rtis)

    @property
    def age_days(self) -> int | None:
        """Days since the detection was first found, or None if unknown."""
        first = _parse_qualys_dt(self.detection.first_found_datetime)
        if first is None:
            return None
        return max(0, (datetime.now(UTC) - first).days)

    @property
    def title(self) -> str:
        """Jira summary: ``QID - Vuln Title`` (Qualys-instance convention)."""
        kb_title = (self.kb.title if self.kb else None) or "Unknown vulnerability"
        return f"{self.detection.qid} - {kb_title}"

    def signal_context(self) -> dict[str, Any]:
        """Flat mapping consumed by the rules engine. Keys are stable signal names."""
        kb = self.kb
        return {
            # risk scores
            "qds": self.detection.qds,
            "trurisk": self.asset.trurisk_score,
            "asset_criticality": self.asset.asset_criticality_score,
            "severity": self.detection.severity,
            "cvss_base": kb.cvss_base if kb else None,
            "cvss_temporal": kb.cvss_temporal if kb else None,
            "cvss_v3_base": kb.cvss_v3_base if kb else None,
            "cvss_v3_temporal": kb.cvss_v3_temporal if kb else None,
            # threat intel
            "rtis": self.all_rtis,
            "has_exploit": self.has_exploit,
            "has_cve": self.has_cve,
            "cve_list": kb.cve_list if kb else [],
            # classification
            "category": kb.category if kb else None,
            "vuln_type": self.detection.vuln_type,
            "patchable": kb.patchable if kb else None,
            "pci_flag": kb.pci_flag if kb else None,
            # detection facts
            "status": self.detection.status.value if self.detection.status else None,
            "port": self.detection.port,
            "protocol": self.detection.protocol,
            "ssl": self.detection.ssl,
            "times_found": self.detection.times_found,
            "is_ignored": self.detection.is_ignored,
            "is_disabled": self.detection.is_disabled,
            "age_days": self.age_days,
            # asset facts
            "os": self.asset.os,
            "tracking_method": self.asset.tracking_method,
            "asset_tags": self.asset.asset_tags,
            "network_id": self.asset.network_id,
        }

    # ----- change detection (write-amplification control) -----
    def material_signature(self) -> dict[str, Any]:
        """The MATERIAL subset of ``signal_context()`` — the only fields whose
        change should cause a Jira write."""
        ctx = self.signal_context()
        return {k: ctx.get(k) for k in MATERIAL_SIGNAL_KEYS}

    def material_hash(self) -> str:
        """Stable hash over MATERIAL fields only.

        An active detection re-seen every 4h with only new scan timestamps yields
        an unchanged hash -> no Jira write. Compare against
        ``DetectionState.material_hash`` to decide whether to update the issue.
        """
        blob = json.dumps(self.material_signature(), sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()
