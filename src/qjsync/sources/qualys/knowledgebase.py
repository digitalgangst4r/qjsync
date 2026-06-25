"""KnowledgeBase reader.

:func:`fetch_kb` streams :class:`KbVuln` enrichment rows out of
``/api/4.0/fo/knowledge_base/vuln/`` with ``action=list&details=All`` (the 2.0 path is at
End-of-Service on current PODs; 4.0 is the drop-in successor). When a set
of QIDs is given it requests just those (``ids=<comma list>``); otherwise it pulls
the whole KnowledgeBase. Either way it follows the same ``<WARNING><URL>``
truncation pointer the HLD endpoint uses (``id_min``), so a full refresh never
silently stops short.

Per-field notes (see ``docs/FIELD_MAPPING.md``):

* ``CVSS_V3`` is frequently *absent* (older/unscored QIDs) -> its fields stay
  ``None``.
* ``CVE_LIST`` may be empty.
* ``PATCHABLE``/``PCI_FLAG`` are ``0``/``1`` -> ``bool``.
* ``THREAT_INTELLIGENCE/THREAT_INTEL`` texts become ``KbVuln.rtis`` (unioned with
  the detection's RTIs downstream to derive ``has_exploit``).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from urllib.parse import parse_qs, urlsplit
from xml.etree.ElementTree import Element, fromstring

from qjsync.models.canonical import KbVuln
from qjsync.sources.qualys import parse
from qjsync.sources.qualys.client import QualysClient

# Qualys 4.0 KnowledgeBase path. The legacy 2.0 path (.../api/2.0/fo/knowledge_base/vuln/) is at
# End-of-Service on current PODs (returns an EOS warning, and rejects heavy full pulls); the 4.0
# path is a drop-in replacement — identical request params and identical XML response schema
# (KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN), so the parser below is unchanged.
_KB_ENDPOINT = "/api/4.0/fo/knowledge_base/vuln/"
_TRUNCATION_CODE = "1980"


def fetch_kb(client: QualysClient, qids: Iterable[int] | None = None) -> Iterator[KbVuln]:
    """Yield a :class:`KbVuln` per QID, following pagination.

    When ``qids`` is given only those entries are requested; otherwise the whole
    KnowledgeBase is pulled (used by the explicit cache warm-up).
    """
    params: dict[str, object] = {"action": "list", "details": "All"}
    if qids is not None:
        ids = sorted({int(q) for q in qids})
        if not ids:
            return
        params["ids"] = ",".join(str(q) for q in ids)

    while True:
        body = client.post(_KB_ENDPOINT, params)
        root = fromstring(body)
        for vuln in root.findall(".//RESPONSE/VULN_LIST/VULN"):
            yield _parse_vuln(vuln)

        next_id_min = _next_id_min(root)
        if next_id_min is None:
            return
        params = dict(params)
        params["id_min"] = next_id_min


def _next_id_min(root: Element) -> str | None:
    warning = root.find(".//RESPONSE/WARNING")
    if warning is None:
        return None
    code = parse.text(warning, "CODE")
    url = parse.text(warning, "URL")
    if url is None:
        return None
    if code is not None and code != _TRUNCATION_CODE:
        return None
    qs = parse_qs(urlsplit(url).query)
    values = qs.get("id_min")
    if not values:
        return None
    return values[0]


def _parse_vuln(vuln: Element) -> KbVuln:
    qid = parse.intval(vuln, "QID")
    if qid is None:
        raise ValueError("KB VULN element missing required QID")

    cvss = vuln.find("CVSS")
    cvss_v3 = vuln.find("CVSS_V3")
    return KbVuln(
        qid=qid,
        title=parse.text(vuln, "TITLE"),
        category=parse.text(vuln, "CATEGORY"),
        severity_level=parse.intval(vuln, "SEVERITY_LEVEL"),
        vuln_type=parse.text(vuln, "VULN_TYPE"),
        published_datetime=parse.text(vuln, "PUBLISHED_DATETIME"),
        last_service_modification_datetime=parse.text(vuln, "LAST_SERVICE_MODIFICATION_DATETIME"),
        patchable=parse.boolval(vuln, "PATCHABLE"),
        pci_flag=parse.boolval(vuln, "PCI_FLAG"),
        cvss_base=parse.floatval(cvss, "BASE"),
        cvss_temporal=parse.floatval(cvss, "TEMPORAL"),
        cvss_v3_base=parse.floatval(cvss_v3, "BASE"),
        cvss_v3_temporal=parse.floatval(cvss_v3, "TEMPORAL"),
        diagnosis=parse.text(vuln, "DIAGNOSIS"),
        consequence=parse.text(vuln, "CONSEQUENCE"),
        solution=parse.text(vuln, "SOLUTION"),
        cve_list=parse.texts(vuln, "CVE_LIST/CVE/ID"),
        rtis=parse.texts(vuln, "THREAT_INTELLIGENCE/THREAT_INTEL"),
    )
