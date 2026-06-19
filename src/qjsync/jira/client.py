"""The Jira Cloud REST v3 client.

A small wrapper around :mod:`requests` covering exactly the operations the sync
lifecycle needs (see ``docs/ARCHITECTURE.md`` §Module interfaces):

* :meth:`discover_fields` — resolve custom-field ids by name (cached) so the
  mapper never hard-codes ``customfield_XXXXX``.
* :meth:`find_issue_by_primary_key` — locate the existing issue for a detection
  via its connector-written Primary Key (idempotent create).
* :meth:`get_issue` / :meth:`create_issue` / :meth:`update_issue` — the CRUD the
  reconciler performs.
* :meth:`list_transitions` / :meth:`transition_issue` — lifecycle moves
  (Done/Reopen), resolving a transition *name* to its id and optionally setting a
  resolution in the same transition.
* :meth:`add_comment` — the rare QDS/priority-band-change note.

Authentication is delegated to an :class:`~qjsync.jira.auth.AuthProvider`
(Basic now, OAuth2-ready). Rate is self-limited with a token bucket, and HTTP
429 ``Retry-After`` is honoured with backoff so the connector is a good citizen.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import requests

# Default page size; the lifecycle only ever needs the first match.
_DEFAULT_MAX_RESULTS = 5
# Caps on the 429 / 5xx retry loop.
_MAX_RETRIES = 5
_BACKOFF_BASE = 1.0
_BACKOFF_MAX = 60.0
_DEFAULT_TIMEOUT = 60.0


class JiraApiError(RuntimeError):
    """A non-retryable Jira API failure (bad request, auth, exhausted retries)."""

    def __init__(
        self, message: str, *, status: int | None = None, body: bytes | None = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class _TokenBucket:
    """Thread-safe token bucket limiting average requests/second (``<=0`` off)."""

    def __init__(self, rate: float) -> None:
        self._rate = rate
        self._capacity = max(rate, 1.0)
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self._rate <= 0:
            return
        with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                time.sleep(deficit / self._rate)


class JiraClient:
    """REST v3 client for Jira Cloud.

    Parameters
    ----------
    base_url:
        Site root, e.g. ``https://acme.atlassian.net`` (no trailing ``/``).
    auth:
        An :class:`~qjsync.jira.auth.AuthProvider` that configures the session.
    requests_per_second:
        Average request-rate cap (token bucket); ``<= 0`` disables it.
    primary_key_field:
        Human name of the connector-owned Primary Key custom field; used by
        :meth:`find_issue_by_primary_key` to build its JQL.
    project:
        Optional default project key to scope the Primary Key search to.
    """

    def __init__(
        self,
        base_url: str,
        auth: Any,
        *,
        requests_per_second: float = 8.0,
        primary_key_field: str = "Primary Key",
        project: str | None = None,
        max_retries: int = _MAX_RETRIES,
        backoff_base: float = _BACKOFF_BASE,
        backoff_max: float = _BACKOFF_MAX,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.primary_key_field = primary_key_field
        self.project = project
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.timeout = timeout

        self._bucket = _TokenBucket(requests_per_second)
        self._session = requests.Session()
        self._session.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )
        auth.apply(self._session)

        # name -> customfield_id cache, populated by discover_fields().
        self._field_cache: dict[str, str] | None = None

    # ------------------------------------------------------------------ public
    def discover_fields(self) -> dict[str, str]:
        """Return ``{field name: field id}`` from ``GET /rest/api/3/field``.

        Cached on the instance so repeated mapper lookups hit the API once.
        """
        if self._field_cache is not None:
            return self._field_cache
        resp = self._request("GET", "/rest/api/3/field")
        payload = resp.json()
        mapping: dict[str, str] = {}
        for field in payload:
            name = field.get("name")
            field_id = field.get("id")
            if name and field_id:
                mapping[name] = field_id
        self._field_cache = mapping
        return mapping

    def find_issue_by_primary_key(
        self,
        primary_key: str,
        *,
        project: str | None = None,
        pk_field_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Return the issue carrying ``primary_key``, or ``None``.

        ``pk_field_id`` defaults to the discovered id for the configured Primary
        Key field name; ``project`` defaults to the client's project (if any).
        Searches via JQL ``project = X AND "<pk_field_id>" ~ "<pk>"`` (the
        project clause is dropped when no project is known).
        """
        if pk_field_id is None:
            pk_field_id = self.discover_fields().get(self.primary_key_field)
        if pk_field_id is None:
            raise JiraApiError(
                f"Primary Key field {self.primary_key_field!r} not found in Jira"
            )
        scope = project if project is not None else self.project
        clauses = []
        if scope:
            clauses.append(f'project = "{scope}"')
        clauses.append(f'"{pk_field_id}" ~ "{primary_key}"')
        jql = " AND ".join(clauses)

        resp = self._request(
            "POST",
            "/rest/api/3/search/jql",
            json={"jql": jql, "maxResults": _DEFAULT_MAX_RESULTS, "fields": ["*all"]},
        )
        issues = resp.json().get("issues") or []
        if not issues:
            return None
        return issues[0]

    def get_issue(
        self, issue_key: str, fields: list[str] | None = None
    ) -> dict[str, Any]:
        """Fetch one issue (``GET /rest/api/3/issue/{key}``)."""
        params = {"fields": ",".join(fields)} if fields else None
        resp = self._request("GET", f"/rest/api/3/issue/{issue_key}", params=params)
        return resp.json()

    def create_issue(self, fields: dict[str, Any]) -> dict[str, Any]:
        """Create an issue and return the created resource (``{"key": ...}``)."""
        resp = self._request("POST", "/rest/api/3/issue", json={"fields": fields})
        return resp.json()

    def update_issue(self, issue_key: str, fields: dict[str, Any]) -> None:
        """Idempotent edit (``PUT /rest/api/3/issue/{key}``)."""
        self._request(
            "PUT", f"/rest/api/3/issue/{issue_key}", json={"fields": fields}
        )

    def list_transitions(self, issue_key: str) -> list[dict[str, Any]]:
        """Return the transitions available from the issue's current status."""
        resp = self._request("GET", f"/rest/api/3/issue/{issue_key}/transitions")
        transitions: list[dict[str, Any]] = resp.json().get("transitions") or []
        return transitions

    def transition_issue(
        self, issue_key: str, name: str, *, resolution: str | None = None
    ) -> None:
        """Move an issue by transition *name*, optionally setting a resolution.

        The name is resolved to its id against the live transition list; a
        resolution, when given, is set in the same transition's ``fields``.
        """
        transition_id = self._resolve_transition_id(issue_key, name)
        body: dict[str, Any] = {"transition": {"id": transition_id}}
        if resolution is not None:
            body["fields"] = {"resolution": {"name": resolution}}
        self._request(
            "POST", f"/rest/api/3/issue/{issue_key}/transitions", json=body
        )

    def add_comment(self, issue_key: str, body_adf: dict[str, Any]) -> None:
        """Add a comment whose body is an ADF document."""
        self._request(
            "POST",
            f"/rest/api/3/issue/{issue_key}/comment",
            json={"body": body_adf},
        )

    def close(self) -> None:
        """Close the underlying :class:`requests.Session`."""
        self._session.close()

    # ----------------------------------------------------------------- internal
    def _resolve_transition_id(self, issue_key: str, name: str) -> str:
        for transition in self.list_transitions(issue_key):
            if str(transition.get("name", "")).lower() == name.lower():
                return str(transition["id"])
        raise JiraApiError(
            f"No transition named {name!r} available on issue {issue_key}"
        )

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
    ) -> requests.Response:
        """Issue a rate-limited request, honouring 429 ``Retry-After`` + 5xx backoff."""
        url = self._url(path)
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._bucket.acquire()
            try:
                resp = self._session.request(
                    method, url, params=params, json=json, timeout=self.timeout
                )
            except requests.RequestException as exc:  # network blip -> retry
                last_exc = exc
                self._sleep_backoff(attempt)
                continue

            if resp.status_code == 429:
                last_exc = JiraApiError(
                    f"Jira {method} {path} -> HTTP 429 (rate limited)",
                    status=429,
                    body=resp.content,
                )
                self._sleep_retry_after(resp, attempt)
                continue

            if resp.status_code >= 500:
                last_exc = JiraApiError(
                    f"Jira {method} {path} -> HTTP {resp.status_code}",
                    status=resp.status_code,
                    body=resp.content,
                )
                self._sleep_backoff(attempt)
                continue

            if resp.status_code >= 400:
                raise JiraApiError(
                    f"Jira {method} {path} -> HTTP {resp.status_code}: "
                    f"{resp.text[:500]}",
                    status=resp.status_code,
                    body=resp.content,
                )

            return resp

        if isinstance(last_exc, JiraApiError):
            raise last_exc
        raise JiraApiError(
            f"Jira {method} {path} failed after {self.max_retries} retries"
        ) from last_exc

    def _sleep_backoff(self, attempt: int) -> None:
        delay = min(self.backoff_max, self.backoff_base * (2**attempt))
        if delay > 0:
            time.sleep(delay)

    def _sleep_retry_after(self, resp: requests.Response, attempt: int) -> None:
        """Sleep for the server's ``Retry-After`` (seconds), else exponential backoff."""
        retry_after = resp.headers.get("Retry-After")
        if retry_after is not None:
            try:
                delay = min(self.backoff_max, float(retry_after))
            except (TypeError, ValueError):
                delay = min(self.backoff_max, self.backoff_base * (2**attempt))
        else:
            delay = min(self.backoff_max, self.backoff_base * (2**attempt))
        if delay > 0:
            time.sleep(delay)


__all__ = ["JiraApiError", "JiraClient"]
