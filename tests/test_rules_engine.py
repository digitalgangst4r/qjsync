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
) -> MergedVulnerability:
    return MergedVulnerability(
        asset=Asset(host_id=1, asset_tags=asset_tags or []),
        detection=Detection(
            qid=1, qds=qds, severity=severity, status=status,
            rtis=rtis or [], vuln_type=vuln_type, is_ignored=is_ignored,
        ),
        kb=KbVuln(qid=1, category=category),
    )


def _mod(
    name: str, signal: str, op: str, value: object, shift: int,
    label: str | None = None, caps_at_high: bool = False,
) -> Modifier:
    return Modifier(
        name=name,
        when=Condition(signal=signal, op=op, value=value),
        shift=shift,
        label=label,
        caps_at_high=caps_at_high,
    )


def _engine(
    modifiers: list[Modifier] | None = None,
    *,
    qds_bands: QdsBands | None = None,
    skip_when: Condition | None = None,
) -> RulesEngine:
    p = PrioritizationConfig(
        qds_bands=qds_bands or QdsBands(),
        modifiers=modifiers or [],
        skip_when=skip_when,
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
# end-to-end against the shipped examples/rules.yml — the motivating tickets
# --------------------------------------------------------------------------- #
def _example_engine() -> RulesEngine:
    return RulesEngine(load_config(_EXAMPLE_RULES))


def _inet(qds: int, category: str, rti: str) -> MergedVulnerability:
    return _merged(qds=qds, category=category, rtis=[rti], asset_tags=_IFA)


def test_no_low_qds_reaches_highest() -> None:
    eng = _example_engine()
    # The exact tickets that motivated the change — none may be Highest.
    assert eng.evaluate(_inet(35, "Windows", "Easy_Exploit")).priority is JiraPriority.MEDIUM
    assert eng.evaluate(_inet(26, "Local", "Exploit_Public")).priority is JiraPriority.LOW
    assert eng.evaluate(_inet(42, "Windows", "Active_Attacks")).priority is JiraPriority.MEDIUM


def test_high_qds_still_reaches_top() -> None:
    eng = _example_engine()
    assert eng.evaluate(_merged(qds=92, category="Windows")).priority is JiraPriority.HIGHEST
    # internet-facing + exploit lifts a High-band QDS to Highest (deliberate).
    assert eng.evaluate(_inet(72, "Windows", "Exploit_Public")).priority is JiraPriority.HIGHEST
    assert eng.evaluate(_merged(qds=30, category="Windows")).action is RuleAction.SKIP
