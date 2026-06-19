"""Pluggable authentication for the Jira REST client.

The client never hard-codes *how* it authenticates: it is handed an
:class:`AuthProvider` whose :meth:`~AuthProvider.apply` mutates the
:class:`requests.Session` (sets credentials, headers, …). Today the only
provider is :class:`BasicAuthProvider` (email + API token, the standard Jira
Cloud scheme). An OAuth2 provider — refreshing a bearer token and setting the
``Authorization: Bearer`` header on the session — is a future drop-in that
implements the same :class:`AuthProvider` protocol; no change to
:class:`~qjsync.jira.client.JiraClient` is required.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import requests
from requests.auth import HTTPBasicAuth


@runtime_checkable
class AuthProvider(Protocol):
    """Something that can authenticate a :class:`requests.Session`.

    Implementations apply their scheme (Basic credentials now; a Bearer token
    from an OAuth2 flow in future) onto the session the client uses for every
    call. Keeping this a :class:`~typing.Protocol` means the client depends only
    on the behaviour, not on any concrete auth class.
    """

    def apply(self, session: requests.Session) -> None:
        """Configure ``session`` so subsequent requests are authenticated."""
        ...


class BasicAuthProvider:
    """HTTP Basic auth with a Jira Cloud email + API token.

    This is the standard Jira Cloud REST scheme: the account email as the
    username and a personal API token as the password. A future
    ``OAuth2Provider`` would implement the same :class:`AuthProvider` protocol
    (setting ``Authorization: Bearer <token>`` and handling refresh) and be
    swapped in without any client change.
    """

    def __init__(self, email: str, token: str) -> None:
        self.email = email
        self._token = token

    def apply(self, session: requests.Session) -> None:
        """Attach :class:`requests.auth.HTTPBasicAuth` to ``session``."""
        session.auth = HTTPBasicAuth(self.email, self._token)


__all__ = ["AuthProvider", "BasicAuthProvider"]
