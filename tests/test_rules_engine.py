"""Tests for the prioritisation engine and its operator registry.

Two layers:

* :mod:`qjsync.rules.operators` — every operator, with the None-safety contract
  exercised explicitly (a missing/None signal never raises and fails the leaf).
* :mod:`qjsync.rules.engine` — the UNIFIED BAND-SHIFT model: a base band from QDS
  plus stacking ±N context modifiers, clamped to [skip, Highest]; the ``skip_when``
  noise pre-filter; modifier labels; and the human-readable explanation.

The end-to-end cases load the shipped ``examples/rules.yml`` via the real loader
and reproduce the exact tickets that motivated the model, proving no low-QDS
detection reaches Highest.
"""

from __future__ import annotations

from pathlib import Path

from qjsync.config.loader import load_config
from qjsync.config.schema import (
    Condition,
    JiraConfig,
    Modifier,
    PrioritizationConfig,
    QdsBands,
    QjsyncConfig,
    RoutingRule,
)
from qjsync.models.canonical import (
    Asset,
    Detection,
    DetectionStatus,
    JiraPriority,
    KbVuln,
    MergedVulnerability,
    RuleAction,
)
from qjsync.rules.engine import RulesEngine
from qjsync.rules.operators import OPERATORS

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLE_RULES = _REPO_ROOT / "examples" / "rules.yml"


# --------------------------------------------------------------------------- #
# operators (unchanged contract)
# --------------------------------------------------------------------------- #
def test_equality_operators() -> None:
    assert OPERATORS["=="](5, 5) is True
    assert OPERATORS["=="](5, 6) is False
    assert OPERATORS["=="](None, None) is True
    assert OPERATORS["!="](5, 6) is True
    assert OPERATORS["=="](None, 5) is False
    assert OPERATORS["!="](None, 5) is True


def test_numeric_operators_none_safe() -> None:
    for op in (">", ">=", "<", "<="):
        assert OPERATORS[op](None, 80) is False
        assert OPERATORS[op](80, None) is False
    assert OPERATORS[">"]("high", 80) is False
    assert OPERATORS[">="](80, 80) is True


def test_in_contains_none_safe() -> None:
    assert OPERATORS["in"]("Active", ["Active", "Re-Opened"]) is True
    assert OPERATORS["in"](None, ["Active"]) is False
    tags = ["Internet Facing Assets", "EASM"]
    assert OPERATORS["contains"](tags, "Internet Facing Assets") is True
    assert OPERATORS["contains"](None, "x") is False
    assert OPERATORS["not_contains"](["EASM"], "Internet Facing Assets") is True
    # list `contains` matches a substring within an element too, so a keyword finds a
    # longer Qualys auto-tag (e.g. "Falcon" inside "SW: CS Falcon Sensor Installed").
    assert OPERATORS["contains"](["SW: CS Falcon Sensor Installed"], "Falcon") is True
    assert OPERATORS["contains"](["AMS - LatAM - CMDB - DMZ"], "DMZ") is True
    assert OPERATORS["contains"](["Internet Facing Assets"], "Zscaler") is False


def test_exists_and_matches() -> None:
    assert OPERATORS["exists"](0, None) is True
    assert OPERATORS["exists"](None, None) is False
    assert OPERATORS["matches"]("Windows Server", "Windows") is True
    assert OPERATORS["matches"](None, "Windows") is False


# --------------------------------------------------------------------------- #
# band-shift engine — helpers
# --------------------------------------------------------------------------- #
def _merged(
    *,
    qds: int | None = None,
    category: str | None = None,
    rtis: list[str] | None = None,
    asset_tags: list[str] | None = None,
    severity: int | None = 5,
    vuln_type: str | None = None,
    is_ignored: int | None = None,
    status: DetectionStatus = DetectionStatus.ACTIVE,
    epss: float | None = None,
    asset_criticality: int | None = None,
    pci_flag: bool = False,
) -> MergedVulnerability:
    return MergedVulnerability(
        asset=Asset(
            host_id=1, asset_tags=asset_tags or [],
            asset_criticality_score=asset_criticality,
        ),
        detection=Detection(
            qid=1, qds=qds, severity=severity, status=status,
            rtis=rtis or [], vuln_type=vuln_type, is_ignored=is_ignored,
            qds_factors={"EPSS": str(epss)} if epss is not None else {},
        ),
        kb=KbVuln(qid=1, category=category, pci_flag=pci_flag),
    )


def _mod(
    name: str, signal: str, op: str, value: object, shift: int,
    label: str | None = None, caps_at_high: bool = False,
    bypasses_highest_gate: bool = False,
) -> Modifier:
    return Modifier(
        name=name,
        when=Condition(signal=signal, op=op, value=value),
        shift=shift,
        label=label,
        caps_at_high=caps_at_high,
        bypasses_highest_gate=bypasses_highest_gate,
    )


def _engine(
    modifiers: list[Modifier] | None = None,
    *,
    qds_bands: QdsBands | None = None,
    skip_when: Condition | None = None,
    routing: list[RoutingRule] | None = None,
) -> RulesEngine:
    p = PrioritizationConfig(
        qds_bands=qds_bands or QdsBands(),
        modifiers=modifiers or [],
        skip_when=skip_when,
        routing=routing or [],
    )
    return RulesEngine(QjsyncConfig(jira=JiraConfig(project="QVULN"), prioritization=p))


_IFA = ["Internet Facing Assets"]  # an internet-facing asset_tags list
_EXPOSED = _mod(
    "internet-facing", "asset_tags", "contains", "Internet Facing Assets", 1, "internet-facing"
)
_EXPOSED_CAP = _mod(
    "internet-facing", "asset_tags", "contains", "Internet Facing Assets", 1,
    "internet-facing", caps_at_high=True,
)
_EXPLOIT = _mod("active-exploit", "has_exploit", "==", True, 1)
_LOCAL = _mod("local-category", "category", "==", "Local", -1)


# --------------------------------------------------------------------------- #
# base bands (pure QDS, no modifiers)
# --------------------------------------------------------------------------- #
def test_base_bands_from_qds() -> None:
    eng = _engine()
    assert eng.evaluate(_merged(qds=92)).priority is JiraPriority.HIGHEST
    assert eng.evaluate(_merged(qds=75)).priority is JiraPriority.HIGH
    assert eng.evaluate(_merged(qds=55)).priority is JiraPriority.MEDIUM
    assert eng.evaluate(_merged(qds=40)).action is RuleAction.SKIP
    assert eng.evaluate(_merged(qds=None)).action is RuleAction.SKIP


def test_skip_when_prefilter() -> None:
    eng = _engine(skip_when=Condition(signal="vuln_type", op="==", value="Information"))
    # Even a high QDS is skipped when the noise pre-filter matches.
    assert eng.evaluate(_merged(qds=95, vuln_type="Information")).action is RuleAction.SKIP
    assert eng.evaluate(_merged(qds=95, vuln_type="Confirmed")).action is RuleAction.CREATE


# --------------------------------------------------------------------------- #
# modifiers shift the band
# --------------------------------------------------------------------------- #
def test_single_modifier_up() -> None:
    eng = _engine([_EXPOSED])
    assert eng.evaluate(_merged(qds=55, asset_tags=_IFA)).priority is JiraPriority.HIGH
    assert eng.evaluate(_merged(qds=55)).priority is JiraPriority.MEDIUM  # not exposed -> base


def test_single_modifier_down_local() -> None:
    eng = _engine([_LOCAL])
    assert eng.evaluate(_merged(qds=55, category="Local")).priority is JiraPriority.LOW
    assert eng.evaluate(_merged(qds=55, category="Windows")).priority is JiraPriority.MEDIUM


def test_modifiers_stack() -> None:
    eng = _engine([_EXPOSED, _EXPLOIT])
    # qds 35 -> base skip(0); +1 exposed +1 exploit -> level 2 = Medium (NOT Highest).
    r = eng.evaluate(_merged(qds=35, asset_tags=_IFA, rtis=["Easy_Exploit"]))
    assert r.priority is JiraPriority.MEDIUM


def test_clamp_ceiling_and_floor() -> None:
    eng = _engine([_EXPOSED, _LOCAL])
    # Ceiling: high QDS + exposure cannot exceed Highest.
    assert eng.evaluate(_merged(qds=95, asset_tags=_IFA)).priority is JiraPriority.HIGHEST
    # Floor: a sub-threshold QDS with a -1 stays at skip.
    assert eng.evaluate(_merged(qds=40, category="Local")).action is RuleAction.SKIP


def test_modifier_label_and_managed_label() -> None:
    eng = _engine([_EXPOSED])
    r = eng.evaluate(_merged(qds=55, asset_tags=_IFA))
    assert "qjsync" in r.labels  # managed label always present
    assert "internet-facing" in r.labels  # firing modifier's label


def test_lever_c_exposure_caps_at_high() -> None:
    eng = _engine([_EXPOSED_CAP, _EXPLOIT])  # B gate on by default
    # base High (qds>=70) + exposure only: capped at High (exposure alone never Highest).
    assert eng.evaluate(_merged(qds=75, asset_tags=_IFA)).priority is JiraPriority.HIGH
    # base High + active exploit (not capped) reaches Highest.
    exploited = _merged(qds=75, asset_tags=_IFA, rtis=["Exploit_Public"])
    assert eng.evaluate(exploited).priority is JiraPriority.HIGHEST


def test_lever_b_highest_requires_high_base() -> None:
    eng = _engine([_EXPOSED, _EXPLOIT])  # uncapped exposure, but B gate on
    # base Medium (qds 55) + exposure + exploit would be level 4, but B forbids a
    # Medium base from reaching Highest -> capped at High.
    mid = _merged(qds=55, asset_tags=_IFA, rtis=["Exploit_Public"])
    assert eng.evaluate(mid).priority is JiraPriority.HIGH


def test_materialize_low_is_classified_not_created() -> None:
    eng = _engine([_LOCAL])
    r = eng.evaluate(_merged(qds=55, category="Local"))  # base Medium -1 -> Low
    assert r.priority is JiraPriority.LOW
    assert r.action is RuleAction.SKIP  # Low is classified, materialised only at >= Medium


def test_explanation_is_auditable() -> None:
    eng = _engine([_EXPOSED, _EXPLOIT])
    r = eng.evaluate(_merged(qds=70, asset_tags=_IFA, rtis=["Exploit_Public"]))
    assert "base=" in r.matched_rule and "internet-facing+1" in r.matched_rule
    assert r.priority is JiraPriority.HIGHEST  # base High(3) +1 +1 -> clamp Highest


# --------------------------------------------------------------------------- #
# new dimensions: threat-intel weights, KEV bypass, EPSS, asset criticality, routing
# --------------------------------------------------------------------------- #
def test_bypass_gate_reaches_highest_from_low_base() -> None:
    # A modifier flagged `bypasses_highest_gate` (confirmed in-the-wild exploitation)
    # waives Levers B+C: a sub-High QDS base may legitimately reach Highest.
    kev = _mod("actively-attacked", "actively_attacked", "==", True, 2,
               "actively-attacked", bypasses_highest_gate=True)
    r = _engine([kev]).evaluate(_merged(qds=62, rtis=["Active_Attacks"]))  # Medium(2)+2 -> 4
    assert r.priority is JiraPriority.HIGHEST
    # The same +2 WITHOUT the bypass flag is gated back to High (Lever B).
    gated = _engine([_mod("ransomware", "ransomware", "==", True, 2, "ransomware")])
    assert gated.evaluate(_merged(qds=62, rtis=["Ransomware"])).priority is JiraPriority.HIGH


def test_weighted_modifier_stacks_by_shift() -> None:
    # A +2 weight moves two bands, not one: High base + ransomware -> Highest.
    eng = _engine([_mod("ransomware", "ransomware", "==", True, 2)])
    assert eng.evaluate(_merged(qds=75, rtis=["Ransomware"])).priority is JiraPriority.HIGHEST


def test_epss_signal_drives_a_modifier() -> None:
    eng = _engine([_mod("epss-high", "epss", ">=", 0.5, 1)])
    assert eng.evaluate(_merged(qds=62, epss=0.7)).priority is JiraPriority.HIGH
    assert eng.evaluate(_merged(qds=62, epss=0.2)).priority is JiraPriority.MEDIUM  # below thr


def test_asset_criticality_modifiers() -> None:
    eng = _engine([
        _mod("high-crit", "asset_criticality", ">=", 4, 1),
        _mod("low-crit", "asset_criticality", "<=", 1, -1),
    ])
    assert eng.evaluate(_merged(qds=62, asset_criticality=5)).priority is JiraPriority.HIGH
    assert eng.evaluate(_merged(qds=62, asset_criticality=1)).priority is JiraPriority.LOW


def test_routing_overrides_destination_without_touching_priority() -> None:
    routing = [RoutingRule(
        name="pci", when=Condition(signal="pci_flag", op="==", value=True),
        project="PCI", component="Compliance", labels=["pci-scope"],
    )]
    eng = _engine(routing=routing)
    r = eng.evaluate(_merged(qds=75, pci_flag=True))
    assert r.project == "PCI" and r.component == "Compliance"
    assert "pci-scope" in r.labels and "qjsync" in r.labels
    assert r.priority is JiraPriority.HIGH  # routing never changes the band
    base = eng.evaluate(_merged(qds=75))  # no match -> default destination
    assert base.project == "QVULN" and base.component is None


def test_signal_context_exposes_threat_intel_and_epss() -> None:
    # The canonical signal_context surfaces each threat-category RTI and parsed EPSS so
    # the modifiers can key off them; absent signals are False/None and never raise.
    m = _merged(qds=80, rtis=["Active_Attacks", "Ransomware", "Wormable"], epss=0.83)
    ctx = m.signal_context()
    assert ctx["actively_attacked"] is True
    assert ctx["ransomware"] is True
    assert ctx["wormable"] is True
    assert ctx["has_exploit"] is True  # Active_Attacks is also a generic exploit marker
    assert ctx["epss"] == 0.83
    clean = _merged(qds=80).signal_context()
    assert clean["actively_attacked"] is False
    assert clean["zero_day"] is False
    assert clean["epss"] is None


# --------------------------------------------------------------------------- #
# end-to-end against the shipped examples/rules.yml — the motivating tickets
# --------------------------------------------------------------------------- #
def _example_engine() -> RulesEngine:
    return RulesEngine(load_config(_EXAMPLE_RULES))


def _inet(qds: int, category: str, rti: str) -> MergedVulnerability:
    return _merged(qds=qds, category=category, rtis=[rti], asset_tags=_IFA)


def test_generic_exploit_on_low_qds_never_highest() -> None:
    eng = _example_engine()
    # Generic "exploit available" / "easy exploit" must NOT manufacture a Highest from a
    # low QDS base — it may escalate, but Levers B+C hold it below Highest (the QDS-26 case).
    assert eng.evaluate(_inet(26, "Local", "Exploit_Public")).priority is JiraPriority.LOW
    assert eng.evaluate(_inet(35, "Windows", "Easy_Exploit")).priority is not JiraPriority.HIGHEST


def test_kev_grade_reaches_highest_from_low_base() -> None:
    eng = _example_engine()
    # Confirmed in-the-wild exploitation (actively-attacked, bypasses_highest_gate)
    # legitimately reaches Highest even from a sub-High QDS base — unlike generic exploit.
    assert eng.evaluate(_inet(42, "Windows", "Active_Attacks")).priority is JiraPriority.HIGHEST
    assert eng.evaluate(_inet(62, "Windows", "Active_Attacks")).priority is JiraPriority.HIGHEST


def test_compensating_control_downweights_via_substring_tag() -> None:
    eng = _example_engine()
    # A High-band detection on an EDR-covered host drops a band — exercising both the
    # down-weight modifier and the list-substring `contains` against a long Qualys tag.
    falcon = _merged(qds=88, category="Windows", asset_tags=["SW: CS Falcon Sensor Installed"])
    assert eng.evaluate(falcon).priority is JiraPriority.MEDIUM


def test_high_qds_still_reaches_top() -> None:
    eng = _example_engine()
    assert eng.evaluate(_merged(qds=92, category="Windows")).priority is JiraPriority.HIGHEST
    # internet-facing + exploit lifts a High-band QDS to Highest (deliberate).
    assert eng.evaluate(_inet(72, "Windows", "Exploit_Public")).priority is JiraPriority.HIGHEST
    assert eng.evaluate(_merged(qds=30, category="Windows")).action is RuleAction.SKIP
