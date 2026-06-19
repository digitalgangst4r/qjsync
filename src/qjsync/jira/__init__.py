"""Jira Cloud integration: auth, REST client, ADF builder, and field mapper.

This package is everything downstream of the rules engine: it turns an evaluated
:class:`~qjsync.models.canonical.MergedVulnerability` into a Jira issue payload
(:mod:`qjsync.jira.mapper` + :mod:`qjsync.jira.adf`) and performs the REST calls
(:mod:`qjsync.jira.client`). Authentication is pluggable
(:mod:`qjsync.jira.auth`) so Basic auth today can become OAuth2 tomorrow without
touching the client.
"""

from __future__ import annotations

from qjsync.jira.adf import build_description, text_to_adf
from qjsync.jira.auth import AuthProvider, BasicAuthProvider
from qjsync.jira.client import JiraApiError, JiraClient
from qjsync.jira.mapper import IssueMapper

__all__ = [
    "AuthProvider",
    "BasicAuthProvider",
    "IssueMapper",
    "JiraApiError",
    "JiraClient",
    "build_description",
    "text_to_adf",
]
