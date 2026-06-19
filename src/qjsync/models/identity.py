"""Primary-key derivation for a detection.

A detection's stable identity follows the Qualys convention ``HOSTID:QID:PORT``.
This is the deduplication key (one detection -> at most one Jira issue), the key
of the ``detection_state`` table, and is written back to the issue's
**Primary Key** custom field.

Edge cases (documented decisions):

* **Port-less detections.** Many QIDs are not bound to a port (host-level or
  remote checks). Qualys omits ``PORT`` for these. We normalise the missing
  port to a configurable sentinel (default ``"none"``) so the key is total and
  stable across syncs — a detection that is port-less today must not produce a
  different key tomorrow.

* **Collisions / non-uniqueness.** In VMDR, ``(HOST_ID, QID, PORT)`` uniquely
  identifies an active detection. The truly unique identifier Qualys exposes is
  ``UNIQUE_VULN_ID``; if an environment ever distinguishes two live detections
  that share host+qid+port (e.g. the same QID seen via different protocols on
  the same port number), set ``include_unique_vuln_id=True`` to append it. We
  default to *off* because ``UNIQUE_VULN_ID`` is not human-meaningful and bloats
  the key; turning it on is a one-line config change with no migration needed
  for new keys.
"""

from __future__ import annotations

DEFAULT_PORT_SENTINEL = "none"


def compute_primary_key(
    host_id: int | str,
    qid: int | str,
    port: int | str | None,
    *,
    port_sentinel: str = DEFAULT_PORT_SENTINEL,
    unique_vuln_id: int | str | None = None,
    include_unique_vuln_id: bool = False,
) -> str:
    """Return the stable primary key for a detection.

    >>> compute_primary_key(123, 38739, 443)
    '123:38739:443'
    >>> compute_primary_key(123, 38739, None)
    '123:38739:none'
    >>> compute_primary_key(1, 2, None, unique_vuln_id=9, include_unique_vuln_id=True)
    '1:2:none:9'
    """
    has_port = port is not None and str(port).strip() != ""
    port_part = str(port).strip() if has_port else port_sentinel
    key = f"{host_id}:{qid}:{port_part}"
    if include_unique_vuln_id:
        has_uvid = unique_vuln_id is not None and str(unique_vuln_id).strip() != ""
        uvid = str(unique_vuln_id).strip() if has_uvid else "none"
        key = f"{key}:{uvid}"
    return key
