"""Host List Detection (HLD) reader.

:func:`iter_detections` streams ``(Asset, Detection)`` pairs out of
``/api/2.0/fo/asset/host/vm/detection/``. It owns three Qualys-specific concerns:

* **Whitelisted params.** Only the fields :class:`QualysQueryConfig` exposes are
  sent (plus the fixed ``action=list`` and the ``show_*`` toggles the exposure /
  QDS layers depend on). The connector-managed ``since`` overrides the static
  ``query.vm_scan_since`` floor when provided. ``show_trurisk`` is *never* sent —
  HLD 2.0 has no TruRisk/ACS field and rejects it (HTTP 400).
* **Truncation pointer.** A large result set is paginated: Qualys ends a page with
  ``<WARNING><CODE>1980</CODE><URL>...id_min=N...</URL></WARNING>``. We follow the
  ``id_min`` from that URL into the next page until a page arrives with no warning,
  i.e. the fetch is *known complete*. (The source layer relies on this for purge
  safety.)
* **QDS_FACTORS -> RTIs.** Each ``<QDS_FACTOR name="X">v</QDS_FACTOR>`` lands in
  ``Detection.qds_factors[X]``; the ``RTI`` factor is comma-split into
  ``Detection.rtis``.

Asset Criticality Score is not an API field on this tenant; when ``acs_pattern``
is supplied it is derived as the MAX integer captured from the asset's tags.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import parse_qs, urlsplit
from xml.etree.ElementTree import Element, fromstring

from qjsync.config.schema import QualysQueryConfig
from qjsync.models.canonical import Asset, Detection, DetectionStatus
from qjsync.sources.qualys import parse
from qjsync.sources.qualys.client import QualysClient

_HLD_ENDPOINT = "/api/2.0/fo/asset/host/vm/detection/"
# Qualys truncation warning code: more records remain; follow <URL> id_min pointer.
_TRUNCATION_CODE = "1980"


def iter_detections(
    client: QualysClient,
    query: QualysQueryConfig,
    *,
    since: str | None = None,
    acs_pattern: str | None = None,
) -> Iterator[tuple[Asset, Detection]]:
    """Yield every in-scope ``(Asset, Detection)`` pair, following pagination.

    ``since`` (the connector-managed ``vm_scan_since``) overrides
    ``query.vm_scan_since`` when not ``None``. ``acs_pattern`` derives
    :attr:`Asset.asset_criticality_score` from the asset's tags (MAX match).
    """
    params = _build_params(query, since=since)
    compiled_acs = re.compile(acs_pattern) if acs_pattern else None

    while True:
        body = client.post(_HLD_ENDPOINT, params)
        root = fromstring(body)
        yield from _parse_page(root, acs=compiled_acs)

        next_id_min = _next_id_min(root)
        if next_id_min is None:
            return
        # Follow the truncation pointer: same query, advanced id_min.
        params = dict(params)
        params["id_min"] = next_id_min


# --------------------------------------------------------------------------- #
# Params
# --------------------------------------------------------------------------- #
def _build_params(query: QualysQueryConfig, *, since: str | None) -> dict[str, object]:
    """Build the POST form params from the whitelisted query config.

    Only whitelisted fields are sent. ``show_trurisk`` is intentionally absent.
    ``query.extra`` is merged last (operator escape hatch). The managed ``since``
    wins over the static ``query.vm_scan_since``.
    """
    params: dict[str, object] = {
        "action": "list",
        "show_tags": query.show_tags,
        "show_qds": query.show_qds,
        "show_qds_factors": query.show_qds_factors,
        "show_reopened_info": query.show_reopened_info,
        "truncation_limit": query.truncation_limit,
    }

    # Optional whitelisted scope/filter fields: included only when set.
    optional: dict[str, object | None] = {
        "severities": query.severities,
        "status": query.status,
        "show_igs": query.show_igs,
        "qids": query.qids,
        "ids": query.ids,
        "id_min": query.id_min,
        "vm_processed_since": query.vm_processed_since,
        "detection_updated_since": query.detection_updated_since,
        "use_tags": query.use_tags,
        "tag_set_by": query.tag_set_by,
        "tag_set_include": query.tag_set_include,
        "tag_set_exclude": query.tag_set_exclude,
    }
    for key, value in optional.items():
        if value is not None:
            params[key] = value

    # vm_scan_since: managed window (since) overrides the static floor.
    scan_since = since if since is not None else query.vm_scan_since
    if scan_since is not None:
        params["vm_scan_since"] = scan_since

    # Escape hatch, merged last. Still whitelisted by the caller's schema.
    for key, value in query.extra.items():
        params[key] = value

    return params


# --------------------------------------------------------------------------- #
# Pagination
# --------------------------------------------------------------------------- #
def _next_id_min(root: Element) -> str | None:
    """Return the ``id_min`` to fetch next, or ``None`` if the page is the last.

    A truncated page carries ``<WARNING><CODE>1980</CODE><URL>...id_min=N...</URL>``.
    We extract ``id_min`` from the URL query string so we don't depend on the host
    in the pointer (it is the same platform we're already pointed at).
    """
    warning = root.find(".//RESPONSE/WARNING")
    if warning is None:
        return None
    code = parse.text(warning, "CODE")
    url = parse.text(warning, "URL")
    if url is None:
        return None
    # Only follow the truncation pointer; ignore unrelated informational warnings.
    if code is not None and code != _TRUNCATION_CODE:
        return None
    qs = parse_qs(urlsplit(url).query)
    values = qs.get("id_min")
    if not values:
        return None
    return values[0]


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _parse_page(root: Element, *, acs: re.Pattern[str] | None) -> Iterator[tuple[Asset, Detection]]:
    for host in root.findall(".//RESPONSE/HOST_LIST/HOST"):
        asset = _parse_host(host, acs=acs)
        for det_el in host.findall("DETECTION_LIST/DETECTION"):
            yield (asset, _parse_detection(det_el))


def _parse_host(host: Element, *, acs: re.Pattern[str] | None) -> Asset:
    host_id = parse.intval(host, "ID")
    if host_id is None:
        raise ValueError("HLD HOST element missing required ID")

    tags = parse.texts(host, "TAGS/TAG/NAME")
    return Asset(
        host_id=host_id,
        asset_id=parse.intval(host, "ASSET_ID"),
        ip=parse.text(host, "IP"),
        ipv6=parse.text(host, "IPV6"),
        tracking_method=parse.text(host, "TRACKING_METHOD"),
        os=parse.text(host, "OS"),
        dns=parse.text(host, "DNS"),
        netbios=parse.text(host, "NETBIOS"),
        qg_hostid=parse.text(host, "QG_HOSTID"),
        network_id=parse.intval(host, "NETWORK_ID"),
        last_scan_datetime=parse.text(host, "LAST_SCAN_DATETIME"),
        last_vm_scanned_date=parse.text(host, "LAST_VM_SCANNED_DATE"),
        last_vm_scanned_duration=parse.intval(host, "LAST_VM_SCANNED_DURATION"),
        asset_tags=tags,
        asset_criticality_score=_derive_acs(tags, acs),
    )


def _derive_acs(tags: list[str], acs: re.Pattern[str] | None) -> int | None:
    """MAX of ``acs.search(tag).group(1)`` over the asset's tags (None if no match)."""
    if acs is None:
        return None
    scores: list[int] = []
    for tag in tags:
        match = acs.search(tag)
        if match is None:
            continue
        try:
            scores.append(int(match.group(1)))
        except (ValueError, IndexError):
            continue
    return max(scores) if scores else None


def _parse_detection(det: Element) -> Detection:
    qid = parse.intval(det, "QID")
    if qid is None:
        raise ValueError("HLD DETECTION element missing required QID")

    qds_factors, rtis = _parse_qds_factors(det)
    return Detection(
        qid=qid,
        port=parse.intval(det, "PORT"),
        protocol=parse.text(det, "PROTOCOL"),
        ssl=parse.intval(det, "SSL"),
        severity=parse.intval(det, "SEVERITY"),
        status=_parse_status(parse.text(det, "STATUS")),
        vuln_type=parse.text(det, "TYPE"),
        results=parse.text(det, "RESULTS"),
        qds=parse.intval(det, "QDS"),
        unique_vuln_id=parse.intval(det, "UNIQUE_VULN_ID"),
        is_ignored=parse.intval(det, "IS_IGNORED"),
        is_disabled=parse.intval(det, "IS_DISABLED"),
        first_found_datetime=parse.text(det, "FIRST_FOUND_DATETIME"),
        last_found_datetime=parse.text(det, "LAST_FOUND_DATETIME"),
        times_found=parse.intval(det, "TIMES_FOUND"),
        last_test_datetime=parse.text(det, "LAST_TEST_DATETIME"),
        last_update_datetime=parse.text(det, "LAST_UPDATE_DATETIME"),
        last_fixed_datetime=parse.text(det, "LAST_FIXED_DATETIME"),
        last_processed_datetime=parse.text(det, "LAST_PROCESSED_DATETIME"),
        rtis=rtis,
        qds_factors=qds_factors,
    )


def _parse_status(raw: str | None) -> DetectionStatus | None:
    if raw is None:
        return None
    try:
        return DetectionStatus(raw)
    except ValueError:
        return None


def _parse_qds_factors(det: Element) -> tuple[dict[str, str], list[str]]:
    """Collect ``QDS_FACTORS`` into a name->value dict; split the RTI factor.

    Each ``<QDS_FACTOR name="X">v</QDS_FACTOR>`` becomes ``factors[X] = v``. The
    factor named ``RTI`` carries a comma-separated indicator list which is split
    (and trimmed) into the returned RTI list.
    """
    factors: dict[str, str] = {}
    rtis: list[str] = []
    for factor in det.findall("QDS_FACTORS/QDS_FACTOR"):
        name = factor.get("name")
        value = (factor.text or "").strip()
        if not name:
            continue
        factors[name] = value
        if name == "RTI" and value:
            rtis = [part.strip() for part in value.split(",") if part.strip()]
    return factors, rtis
