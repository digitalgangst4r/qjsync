"""Map a canonical vulnerability to a Jira create/update ``fields`` payload.

:class:`IssueMapper` is the single place that knows the Qualys -> Jira field
translation table from ``docs/FIELD_MAPPING.md``. It is constructed with the
``name -> customfield_id`` mapping discovered at runtime
(:meth:`~qjsync.jira.client.JiraClient.discover_fields`) so ids are never
hard-coded, and with the parsed config (for the standard-field routing and the
derived patch-routing label).

Rules baked in here (all from the contract):

* **Omit, never null.** A field whose source value is ``None`` is left out of the
  payload entirely — Jira is never sent an explicit null.
* **Discover by name.** Each custom field is looked up by its human name; if that
  name is absent from the discovered ids, the field is skipped with a warning
  rather than crashing the whole sync.
* **Type coercion.** Numbers stay numbers; the ``Patchable`` / ``PCI Flag`` text
  fields become ``"Yes"`` / ``"No"``; ``Asset Tag`` becomes a labels list; date
  fields are written as the raw Qualys text (no DatePicker parsing).
* **Derived.** ``Primary Key`` is written from the connector-computed key;
  ``Asset Criticality Score`` from the asset's derived ACS; ``TruRisk Score`` has
  no HLD 2.0 source and is omitted.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from qjsync.jira.adf import build_description, text_to_adf, truncate_field_text

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    from qjsync.config.schema import QjsyncConfig
    from qjsync.models.canonical import EvaluationResult, MergedVulnerability

logger = logging.getLogger("qjsync.jira.mapper")


def _yes_no(value: bool | None) -> str | None:
    """Coerce a tri-state boolean to the ``Yes`` / ``No`` text Jira expects."""
    if value is None:
        return None
    return "Yes" if value else "No"


def _sanitise_label(raw: str) -> str:
    """Jira labels may not contain spaces; collapse them to underscores."""
    return "_".join(raw.split())


class IssueMapper:
    """Build the Jira ``fields`` dict for one merged vulnerability.

    Parameters
    ----------
    field_ids:
        ``human field name -> customfield_XXXXX`` as returned by
        :meth:`JiraClient.discover_fields`.
    config:
        The parsed :class:`~qjsync.config.schema.QjsyncConfig` (its ``jira``
        block supplies routing defaults and the patch-routing labels).
    """

    def __init__(self, field_ids: dict[str, str], config: QjsyncConfig) -> None:
        self.field_ids = field_ids
        self.config = config

    # ------------------------------------------------------------------ public
    def build_fields(
        self,
        merged: MergedVulnerability,
        evaluation: EvaluationResult,
        primary_key: str,
    ) -> dict[str, Any]:
        """Return the Jira create/update ``fields`` payload for ``merged``."""
        jira = self.config.jira
        asset = merged.asset
        detection = merged.detection
        kb = merged.kb

        fields: dict[str, Any] = {
            "summary": merged.title,
            "project": {"key": evaluation.project or jira.project},
            "issuetype": {"name": evaluation.issue_type or jira.issue_type},
            "description": build_description(merged),
            "labels": self._labels(merged, evaluation),
        }
        if evaluation.priority is not None:
            fields["priority"] = {"name": evaluation.priority.value}
        if evaluation.component:
            fields["components"] = [{"name": evaluation.component}]

        # --- custom fields (discovered by name) -------------------------------
        # HOST
        self._put(fields, "Host ID", asset.host_id)
        self._put(fields, "Asset ID", asset.asset_id)
        self._put(fields, "IP", asset.ip)
        self._put(fields, "IPV6", asset.ipv6)
        self._put(fields, "Tracking Method", asset.tracking_method)
        self._put(fields, "OS", asset.os)
        self._put(fields, "DNS", asset.dns)
        self._put(fields, "Netbios", asset.netbios)
        self._put(fields, "QG Host ID", asset.qg_hostid)
        self._put(fields, "Network ID", asset.network_id)
        self._put(fields, "Last Scan Datetime", asset.last_scan_datetime)
        self._put(fields, "Last VM Scanned Date", asset.last_vm_scanned_date)
        self._put(fields, "Last VM Scanned Duration", asset.last_vm_scanned_duration)
        self._put_labels(fields, "Asset Tag", asset.asset_tags)

        # DETECTION
        self._put(fields, "QID", detection.qid)
        self._put(fields, "QDS", detection.qds)
        self._put(fields, "Port", detection.port)
        self._put(fields, "Protocol", detection.protocol)
        self._put(fields, "Severity", detection.severity)
        self._put(fields, "Vuln Type", detection.vuln_type)
        self._put(fields, "Detection Status", detection.detection_status)
        self._put(fields, "Unique Value ID", detection.unique_vuln_id)
        self._put(fields, "SSL", detection.ssl)
        self._put_adf(fields, "Results", detection.results)
        self._put(fields, "First Found Datetime", detection.first_found_datetime)
        self._put(fields, "Last Found Datetime", detection.last_found_datetime)
        self._put(fields, "Times Found", detection.times_found)
        self._put(fields, "Last Test Datetime", detection.last_test_datetime)
        self._put(fields, "Last Update Datetime", detection.last_update_datetime)
        self._put(fields, "Last Fixed Datetime", detection.last_fixed_datetime)
        self._put(fields, "Last Processed Datetime", detection.last_processed_datetime)
        self._put(fields, "Is Ignored", detection.is_ignored)
        self._put(fields, "Is Disabled", detection.is_disabled)

        # KB
        if kb is not None:
            self._put(fields, "Patchable", _yes_no(kb.patchable))
            self._put(fields, "PCI Flag", _yes_no(kb.pci_flag))
            self._put(fields, "Vuln Category", kb.category)
            self._put(fields, "Published Datetime", kb.published_datetime)
            self._put(fields, "CVSS Base", kb.cvss_base)
            self._put(fields, "CVSS Temporal", kb.cvss_temporal)
            self._put(fields, "CVSS V3 Base", kb.cvss_v3_base)
            self._put(fields, "CVSS V3 Temporal", kb.cvss_v3_temporal)
            self._put(
                fields,
                "Last Service Modification Datetime",
                kb.last_service_modification_datetime,
            )
            self._put_adf(fields, "CVEs", "\n".join(kb.cve_list) if kb.cve_list else None)
            self._put_adf(fields, "Diagnosis", kb.diagnosis)
            self._put_adf(fields, "Consequence", kb.consequence)
            self._put_adf(fields, "Solution", kb.solution)

        # derived
        self._put(fields, "Asset Criticality Score", asset.asset_criticality_score)
        # TruRisk Score has no HLD 2.0 source -> always omitted.
        self._put(fields, jira.primary_key_field, primary_key)

        return fields

    # ----------------------------------------------------------------- internal
    def _labels(
        self, merged: MergedVulnerability, evaluation: EvaluationResult
    ) -> list[str]:
        """Rule labels plus the optional derived patch-routing label.

        ``patchable`` is a *routing* signal: when configured, exactly one of
        ``patch_label`` (patchable) / ``mitigation_label`` (not patchable) is
        appended; an unknown ``patchable`` adds nothing.
        """
        labels = list(evaluation.labels)
        jira = self.config.jira
        if jira.derive_patch_routing and merged.kb is not None:
            patchable = merged.kb.patchable
            if patchable is True and jira.patch_label not in labels:
                labels.append(jira.patch_label)
            elif patchable is False and jira.mitigation_label not in labels:
                labels.append(jira.mitigation_label)
        # Surface the single most critical RTI of the vuln as a label.
        top_rti = merged.top_rti
        if top_rti:
            label = _sanitise_label(top_rti)
            if label not in labels:
                labels.append(label)
        # PCI is a visibility/triage label (it is not a priority band modifier).
        if merged.kb is not None and merged.kb.pci_flag and "pci" not in labels:
            labels.append("pci")
        return labels

    def _put(self, fields: dict[str, Any], name: str, value: Any) -> None:
        """Set custom field ``name`` to ``value`` unless the value is absent.

        Resolves ``name`` to its discovered ``customfield_id``; a name missing
        from the discovered set is skipped with a warning so one un-provisioned
        field never fails the whole mapping.
        """
        if value is None:
            return
        field_id = self.field_ids.get(name)
        if field_id is None:
            logger.warning("Jira field %r not found in discovered fields; skipping", name)
            return
        fields[field_id] = value

    def _put_labels(self, fields: dict[str, Any], name: str, values: list[str]) -> None:
        """Set a labels-typed custom field, sanitising spaces; skip if empty."""
        if not values:
            return
        self._put(fields, name, [_sanitise_label(v) for v in values])

    def _put_adf(self, fields: dict[str, Any], name: str, value: Any) -> None:
        """Set a multi-line (textarea) custom field. In Jira API v3 these require
        an Atlassian Document Format value, not a plain string."""
        if value is None or value == "":
            return
        field_id = self.field_ids.get(name)
        if field_id is None:
            logger.warning("Jira field %r not found in discovered fields; skipping", name)
            return
        # Truncate below Jira's 32767-char field limit — Qualys `Results` (raw scan
        # output) and verbose KB text routinely exceed it (HTTP 400
        # CONTENT_LIMIT_EXCEEDED, which is fatal, not retryable).
        text = truncate_field_text(str(value))
        content = text_to_adf(text) or [
            {"type": "paragraph", "content": [{"type": "text", "text": text}]}
        ]
        fields[field_id] = {"type": "doc", "version": 1, "content": content}


__all__ = ["IssueMapper"]
