"""The prioritisation engine — a unified band-shift model.

Priority is derived from QDS and then nudged by stacking context modifiers:

    final_level = clamp[skip..Highest]( base_band(QDS) + Σ shift(matched modifiers) )

QDS is the trusted base (Qualys already folds RTIs/exposure into it). Modifiers
(internet-facing, active exploit, local category, …) express how *our* risk
appetite differs from Qualys's generic default — each shifts the band by ±N, and
they STACK. Exposure, exploit and Local are the same mechanism, so the outcome is
explainable: "QDS 70, +1 internet-facing, +1 exploit -> Highest".

Levels: 0 skip · 1 Low · 2 Medium · 3 High · 4 Highest. The QDS base maps
highest/high/medium thresholds to 4/3/2 and anything below ``medium`` to skip (0);
level 1 (Low) is only ever reached by a downward/ upward shift. ``skip_when`` is a
noise pre-filter that short-circuits to skip.

Conditions (modifier ``when`` and ``skip_when``) are the same structured, None-safe
AST as before: a leaf is ``OPERATORS[op](ctx.get(signal), value)`` and composites
recurse over ``all`` / ``any`` / ``not``.
"""

from __future__ import annotations

from typing import Any

from qjsync.config.schema import Condition, QjsyncConfig
from qjsync.models.canonical import (
    EvaluationResult,
    JiraPriority,
    MergedVulnerability,
    RuleAction,
)
from qjsync.rules.operators import OPERATORS

_SKIP_LEVEL = 0
_HIGH_LEVEL = 3
_MAX_LEVEL = 4  # Highest
_LEVEL_TO_PRIORITY: dict[int, JiraPriority] = {
    1: JiraPriority.LOW,
    2: JiraPriority.MEDIUM,
    3: JiraPriority.HIGH,
    4: JiraPriority.HIGHEST,
}
_BAND_TO_LEVEL: dict[str, int] = {"Low": 1, "Medium": 2, "High": 3, "Highest": 4}


def _clamp(level: int) -> int:
    """Clamp a band level to the valid range [skip, Highest]."""
    return max(_SKIP_LEVEL, min(_MAX_LEVEL, level))


class RulesEngine:
    """Evaluate the band-shift prioritisation model against a merged vulnerability.

    Construct once per config (stateless w.r.t. the detections it scores) and call
    :meth:`evaluate` per :class:`MergedVulnerability`.
    """

    def __init__(self, config: QjsyncConfig) -> None:
        self.config = config
        self.p = config.prioritization

    def evaluate(self, merged: MergedVulnerability) -> EvaluationResult:
        """Return the band-shift decision (create + priority, or skip).

        ``matched_rule`` carries a human-readable explanation of the maths so a
        ticket's priority is auditable ("qds=35 base=0 internet-facing+1
        active-exploit+1 -> level 2"). Labels = managed label + each firing
        modifier's ``label`` (the Jira mapper adds the top RTI / patch-routing /
        PCI labels on top).
        """
        ctx = merged.signal_context()
        jira = self.config.jira

        # 0) Noise pre-filter -> always skip.
        if self.p.skip_when is not None and self._eval(self.p.skip_when, ctx):
            return EvaluationResult(action=RuleAction.SKIP, matched_rule="skip_when")

        # 1) Base band from QDS (the trusted score).
        base = self._base_level(ctx.get("qds"))

        # 2) Stacking context modifiers (and the subset that is NOT caps_at_high,
        #    used to decide whether Highest is reachable without exposure alone).
        shift = 0
        shift_uncapped = 0
        bypass_gate = False
        fired: list[str] = []
        mod_labels: list[str] = []
        for mod in self.p.modifiers:
            if self._eval(mod.when, ctx):
                shift += mod.shift
                if not mod.caps_at_high:
                    shift_uncapped += mod.shift
                if mod.bypasses_highest_gate:
                    bypass_gate = True
                fired.append(f"{mod.name}{mod.shift:+d}")
                if mod.label:
                    mod_labels.append(mod.label)

        level = _clamp(base + shift)

        # 3) Highest hygiene (Levers B + C). A result of Highest is only allowed if
        #    the QDS base is already High (B) AND it is reachable without relying on
        #    a caps_at_high (exposure) modifier (C). A firing modifier with
        #    `bypasses_highest_gate` (e.g. confirmed in-the-wild exploitation) waives
        #    both. Otherwise cap at High.
        capped = False
        if level == _MAX_LEVEL and not bypass_gate:
            b_ok = base >= _HIGH_LEVEL or not self.p.highest_requires_high_base
            c_ok = _clamp(base + shift_uncapped) == _MAX_LEVEL
            if not (b_ok and c_ok):
                level = _HIGH_LEVEL
                capped = True

        explain = f"qds={ctx.get('qds')} base={base}" + "".join(f" {f}" for f in fired)
        if capped:
            explain += " [Highest-capped]"
        explain += f" -> level {level}"

        if level == _SKIP_LEVEL:
            return EvaluationResult(action=RuleAction.SKIP, matched_rule=explain)

        # 4) Orthogonal context routing (first match wins): override the Jira
        #    destination and add labels, without touching priority.
        project, issue_type, component = jira.project, jira.issue_type, None
        route_labels: list[str] = []
        for route in self.p.routing:
            if self._eval(route.when, ctx):
                project = route.project or project
                issue_type = route.issue_type or issue_type
                component = route.component
                route_labels = list(route.labels)
                break

        # 5) Materialisation gate (Lever D-narrow): bands below materialize_min_band
        #    are CLASSIFIED (priority set) but not created as Jira issues — action is
        #    SKIP so the orchestrator records state without ticketing until promoted.
        materialize_level = _BAND_TO_LEVEL[self.p.materialize_min_band]
        action = RuleAction.CREATE if level >= materialize_level else RuleAction.SKIP
        return EvaluationResult(
            action=action,
            matched_rule=explain,
            priority=_LEVEL_TO_PRIORITY[level],
            project=project,
            issue_type=issue_type,
            component=component,
            labels=[jira.managed_label, *mod_labels, *route_labels],
        )

    def _base_level(self, qds: Any) -> int:
        """Map QDS to a base level (4/3/2), or skip (0) below the medium threshold.

        A missing QDS yields skip — modifiers may still lift it if context warrants.
        """
        if qds is None:
            return _SKIP_LEVEL
        bands = self.p.qds_bands
        if qds >= bands.highest:
            return 4
        if qds >= bands.high:
            return 3
        if qds >= bands.medium:
            return 2
        return _SKIP_LEVEL

    def _eval(self, cond: Condition, ctx: dict[str, Any]) -> bool:
        """Recursively evaluate a condition AST node against the signal context."""
        if cond.all_ is not None:
            return all(self._eval(child, ctx) for child in cond.all_)
        if cond.any_ is not None:
            return any(self._eval(child, ctx) for child in cond.any_)
        if cond.not_ is not None:
            return not self._eval(cond.not_, ctx)
        signal = cond.signal
        op = cond.op
        if signal is None or op is None:  # pragma: no cover - schema-guaranteed
            return False
        return OPERATORS[op](ctx.get(signal), cond.value)


__all__ = ["RulesEngine"]
