"""Tests for :class:`~qjsync.sources.qualys.client.QualysClient` using ``responses``.

Covered: the mandatory ``X-Requested-With`` header is always sent; the HLD
truncation pointer (``<WARNING><URL>...id_min=N...</URL>``) is followed across two
pages and both are parsed; a Qualys concurrency-limit rejection is retried.
"""

from __future__ import annotations

from pathlib import Path

import responses

from qjsync.config.schema import QualysQueryConfig
from qjsync.sources.qualys.client import QualysClient
from qjsync.sources.qualys.detection import iter_detections

_API = "https://qualysapi.qg3.apps.qualys.com"
_HLD_URL = f"{_API}/api/2.0/fo/asset/host/vm/detection/"


def _client() -> QualysClient:
    # No real sleeping in retry tests: zero backoff.
    return QualysClient(
        _API,
        "user",
        "pass",
        requests_per_second=0,  # disable rate limiting in tests
        max_concurrency=2,
        backoff_base=0,
        backoff_max=0,
    )


_PAGE_2_FROM_FIXTURE = Path(__file__).parent / "fixtures" / "hld_sample.xml"


def _page_with_warning(host_id: int, *, next_id_min: int) -> str:
    """A single-host HLD page ending with a truncation WARNING pointer."""
    return f"""<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <DATETIME>2026-06-19T03:00:00Z</DATETIME>
    <HOST_LIST>
      <HOST>
        <ID>{host_id}</ID>
        <IP>10.0.0.{host_id}</IP>
        <TRACKING_METHOD>AGENT</TRACKING_METHOD>
        <DETECTION_LIST>
          <DETECTION>
            <UNIQUE_VULN_ID>{host_id}1</UNIQUE_VULN_ID>
            <QID>105413</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>5</SEVERITY>
            <STATUS>Active</STATUS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
    <WARNING>
      <CODE>1980</CODE>
      <TEXT>more records</TEXT>
      <URL>{_HLD_URL}?action=list&amp;id_min={next_id_min}</URL>
    </WARNING>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>"""


def _final_page(host_id: int) -> str:
    """A single-host HLD page with NO warning (last page)."""
    return f"""<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <DATETIME>2026-06-19T03:00:00Z</DATETIME>
    <HOST_LIST>
      <HOST>
        <ID>{host_id}</ID>
        <IP>10.0.0.{host_id}</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <DETECTION_LIST>
          <DETECTION>
            <UNIQUE_VULN_ID>{host_id}2</UNIQUE_VULN_ID>
            <QID>91234</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>3</SEVERITY>
            <STATUS>Active</STATUS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>"""


_CONCURRENCY_ERROR_BODY = """<?xml version="1.0" encoding="UTF-8" ?>
<SIMPLE_RETURN>
  <RESPONSE>
    <DATETIME>2026-06-19T03:00:00Z</DATETIME>
    <CODE>1965</CODE>
    <TEXT>You have reached the maximum number of concurrent running programs.</TEXT>
  </RESPONSE>
</SIMPLE_RETURN>"""


@responses.activate
def test_mandatory_x_requested_with_header_is_sent() -> None:
    responses.add(
        responses.POST,
        _HLD_URL,
        body=_final_page(1),
        status=200,
        content_type="application/xml",
    )
    client = _client()
    client.post("/api/2.0/fo/asset/host/vm/detection/", {"action": "list"})

    assert len(responses.calls) == 1
    sent = responses.calls[0].request
    assert sent.headers.get("X-Requested-With") == "qjsync"
    # Basic auth was applied too.
    assert sent.headers.get("Authorization", "").startswith("Basic ")


@responses.activate
def test_truncation_pointer_is_followed_and_both_pages_parsed() -> None:
    # Page 1: ends with a WARNING pointing at id_min=200; page 2: final, no warning.
    responses.add(
        responses.POST,
        _HLD_URL,
        body=_page_with_warning(100, next_id_min=200),
        status=200,
        content_type="application/xml",
    )
    responses.add(
        responses.POST,
        _HLD_URL,
        body=_final_page(200),
        status=200,
        content_type="application/xml",
    )

    client = _client()
    pairs = list(iter_detections(client, QualysQueryConfig()))

    # One detection from each page -> both pages parsed.
    host_ids = sorted({asset.host_id for asset, _det in pairs})
    assert host_ids == [100, 200]
    assert len(responses.calls) == 2

    # The second request carried the id_min lifted from the WARNING URL.
    second = responses.calls[1].request
    assert "id_min=200" in (second.body or "")


@responses.activate
def test_retries_on_concurrency_limit_then_succeeds() -> None:
    # First call: HTTP 409 concurrency-limit (retryable); second: success.
    responses.add(
        responses.POST,
        _HLD_URL,
        body=_CONCURRENCY_ERROR_BODY,
        status=409,
        content_type="application/xml",
    )
    responses.add(
        responses.POST,
        _HLD_URL,
        body=_final_page(1),
        status=200,
        content_type="application/xml",
    )

    client = _client()
    body = client.post("/api/2.0/fo/asset/host/vm/detection/", {"action": "list"})

    assert b"HOST_LIST_VM_DETECTION_OUTPUT" in body
    assert len(responses.calls) == 2  # retried once


@responses.activate
def test_retries_on_5xx_then_succeeds() -> None:
    responses.add(responses.POST, _HLD_URL, body="boom", status=503)
    responses.add(
        responses.POST,
        _HLD_URL,
        body=_final_page(1),
        status=200,
        content_type="application/xml",
    )

    client = _client()
    body = client.post("/api/2.0/fo/asset/host/vm/detection/", {"action": "list"})
    assert b"HOST_LIST_VM_DETECTION_OUTPUT" in body
    assert len(responses.calls) == 2


@responses.activate
def test_4xx_is_not_retried_and_raises() -> None:
    from qjsync.sources.qualys.client import QualysApiError

    responses.add(
        responses.POST,
        _HLD_URL,
        body="<SIMPLE_RETURN><RESPONSE><TEXT>Unrecognized parameter</TEXT>"
        "</RESPONSE></SIMPLE_RETURN>",
        status=400,
    )
    client = _client()
    try:
        client.post("/api/2.0/fo/asset/host/vm/detection/", {"action": "list"})
    except QualysApiError as exc:
        assert exc.status == 400
    else:  # pragma: no cover
        raise AssertionError("expected QualysApiError on HTTP 400")
    assert len(responses.calls) == 1  # not retried


@responses.activate
def test_none_params_are_dropped() -> None:
    responses.add(
        responses.POST,
        _HLD_URL,
        body=_final_page(1),
        status=200,
        content_type="application/xml",
    )
    client = _client()
    client.post(
        "/api/2.0/fo/asset/host/vm/detection/",
        {"action": "list", "id_min": None, "truncation_limit": 1000},
    )
    body = responses.calls[0].request.body or ""
    assert "action=list" in body
    assert "truncation_limit=1000" in body
    assert "id_min" not in body  # None param omitted
