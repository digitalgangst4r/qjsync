"""Tests for :class:`~qjsync.jira.client.JiraClient` using ``responses``.

No live API: every Jira endpoint is mocked. Covered: field discovery parses
name->id and caches; Primary Key search builds JQL and returns the first issue;
create_issue posts ``{"fields": ...}``; transition_issue resolves the id by name
and includes a resolution; a 429 with Retry-After is retried then succeeds.
"""

from __future__ import annotations

import responses

from qjsync.jira.auth import BasicAuthProvider
from qjsync.jira.client import JiraClient

_BASE = "https://acme.atlassian.net"


def _client() -> JiraClient:
    return JiraClient(
        _BASE,
        BasicAuthProvider("bot@acme.test", "token"),
        requests_per_second=0,  # disable rate limiting in tests
        backoff_base=0,
        backoff_max=0,
    )


@responses.activate
def test_discover_fields_parses_and_caches() -> None:
    responses.add(
        responses.GET,
        f"{_BASE}/rest/api/3/field",
        json=[
            {"id": "summary", "name": "Summary"},
            {"id": "customfield_10010", "name": "Primary Key"},
            {"id": "customfield_10011", "name": "QDS"},
            {"id": None, "name": "Broken"},  # skipped (no id)
        ],
        status=200,
    )

    client = _client()
    fields = client.discover_fields()
    assert fields["Primary Key"] == "customfield_10010"
    assert fields["QDS"] == "customfield_10011"
    assert "Broken" not in fields

    # Cached: a second call hits no further HTTP request.
    again = client.discover_fields()
    assert again is fields
    assert len(responses.calls) == 1


@responses.activate
def test_find_issue_by_primary_key_builds_jql() -> None:
    responses.add(
        responses.GET,
        f"{_BASE}/rest/api/3/field",
        json=[{"id": "customfield_10010", "name": "Primary Key"}],
        status=200,
    )
    responses.add(
        responses.POST,
        f"{_BASE}/rest/api/3/search/jql",
        json={"issues": [{"key": "SEC-1", "fields": {}}]},
        status=200,
    )

    client = JiraClient(
        _BASE,
        BasicAuthProvider("bot@acme.test", "token"),
        requests_per_second=0,
        project="SEC",
    )
    issue = client.find_issue_by_primary_key("42:105413:443")
    assert issue is not None
    assert issue["key"] == "SEC-1"

    search = responses.calls[-1].request
    assert search.body is not None
    body = search.body.decode() if isinstance(search.body, bytes) else search.body
    assert 'project = \\"SEC\\"' in body
    assert 'customfield_10010' in body
    assert '42:105413:443' in body


@responses.activate
def test_find_issue_by_primary_key_no_match() -> None:
    responses.add(
        responses.GET,
        f"{_BASE}/rest/api/3/field",
        json=[{"id": "customfield_10010", "name": "Primary Key"}],
        status=200,
    )
    responses.add(
        responses.POST,
        f"{_BASE}/rest/api/3/search/jql",
        json={"issues": []},
        status=200,
    )
    client = _client()
    assert client.find_issue_by_primary_key("nope") is None


@responses.activate
def test_create_issue_posts_fields() -> None:
    responses.add(
        responses.POST,
        f"{_BASE}/rest/api/3/issue",
        json={"key": "SEC-7", "id": "10007"},
        status=201,
    )
    client = _client()
    created = client.create_issue({"summary": "boom", "project": {"key": "SEC"}})
    assert created["key"] == "SEC-7"

    sent = responses.calls[0].request
    body = sent.body.decode() if isinstance(sent.body, bytes) else sent.body
    assert '"fields"' in body
    assert '"summary": "boom"' in body


@responses.activate
def test_update_issue_puts() -> None:
    responses.add(
        responses.PUT,
        f"{_BASE}/rest/api/3/issue/SEC-7",
        status=204,
    )
    client = _client()
    client.update_issue("SEC-7", {"summary": "updated"})
    assert len(responses.calls) == 1
    assert responses.calls[0].request.method == "PUT"


@responses.activate
def test_transition_issue_resolves_id_by_name() -> None:
    responses.add(
        responses.GET,
        f"{_BASE}/rest/api/3/issue/SEC-7/transitions",
        json={
            "transitions": [
                {"id": "11", "name": "Start Progress"},
                {"id": "31", "name": "Done"},
            ]
        },
        status=200,
    )
    responses.add(
        responses.POST,
        f"{_BASE}/rest/api/3/issue/SEC-7/transitions",
        status=204,
    )

    client = _client()
    client.transition_issue("SEC-7", "Done", resolution="Fixed")

    post = responses.calls[-1].request
    body = post.body.decode() if isinstance(post.body, bytes) else post.body
    assert '"id": "31"' in body  # resolved Done -> 31
    assert '"resolution"' in body
    assert '"Fixed"' in body


@responses.activate
def test_429_then_success_retry() -> None:
    responses.add(
        responses.GET,
        f"{_BASE}/rest/api/3/issue/SEC-7",
        status=429,
        headers={"Retry-After": "0"},
    )
    responses.add(
        responses.GET,
        f"{_BASE}/rest/api/3/issue/SEC-7",
        json={"key": "SEC-7", "fields": {"summary": "ok"}},
        status=200,
    )

    client = _client()
    issue = client.get_issue("SEC-7")
    assert issue["key"] == "SEC-7"
    assert len(responses.calls) == 2  # retried once after the 429


