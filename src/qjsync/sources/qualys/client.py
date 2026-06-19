"""The Qualys HTTP client.

A thin, deliberately small wrapper around :mod:`requests` that encodes the three
non-negotiable facts about talking to the Qualys API (verified against a live VMDR subscription,
see ``docs/ARCHITECTURE.md``):

* **Auth.** HTTP Basic + the *mandatory* ``X-Requested-With`` header. Qualys
  rejects requests that omit the header even with valid credentials.
* **Rate limiting.** A subscription is metered two ways at once: a requests/second
  rate and a cap on *concurrent* calls. We enforce both locally — a token bucket
  for the rate and a :class:`threading.Semaphore` for concurrency — so the
  connector is a good citizen before the server ever has to push back.
* **Back-pressure.** When the server *does* push back (5xx, or a Qualys
  concurrency-limit response), we retry with exponential backoff rather than
  failing the whole sync.

Everything above the client speaks ``get(endpoint, params) -> bytes`` /
``post(endpoint, params) -> bytes``; the readers parse the returned XML bytes.
Qualys takes its parameters as POST form fields, so :meth:`post` is the common
path and :meth:`get` exists for the few read-only endpoints.
"""

from __future__ import annotations

import threading
import time

import requests

# Qualys returns this auth error code in the XML body (HTTP 409) when the
# per-subscription concurrent-request cap is exceeded. It is retryable.
_CONCURRENCY_LIMIT_CODE = "1965"
# Substrings Qualys uses in the concurrency-limit message, matched case-insensitively
# as a belt-and-braces fallback when the numeric code is not present.
_CONCURRENCY_LIMIT_MARKERS = (
    "concurrent",
    "rate limit",
    "exceeded the limit",
)
# The mandatory header value Qualys keys behaviour off; any non-empty value works,
# but a recognisable one aids their support/log correlation.
_X_REQUESTED_WITH = "qjsync"


class QualysApiError(RuntimeError):
    """A non-retryable Qualys API failure (bad request, auth, exhausted retries)."""

    def __init__(
        self, message: str, *, status: int | None = None, body: bytes | None = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class _TokenBucket:
    """A simple thread-safe token bucket limiting average requests/second.

    Capacity equals the per-second rate, so short bursts up to one second's worth
    are allowed; sustained throughput is capped at ``rate`` tokens/second. A rate
    of ``<= 0`` disables limiting.
    """

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
                # Not enough credit yet: sleep just long enough for one token.
                deficit = 1.0 - self._tokens
                time.sleep(deficit / self._rate)


class QualysClient:
    """HTTP client for the Qualys API (Basic auth, rate/concurrency limited).

    Parameters
    ----------
    api_url:
        Platform API root, e.g. ``https://qualysapi.qg2.apps.qualys.com`` (no
        trailing ``/api``). The ``endpoint`` passed to :meth:`get` / :meth:`post`
        is appended to this.
    username, password:
        Subscription credentials used for HTTP Basic auth.
    requests_per_second:
        Average request rate cap (token bucket). ``<= 0`` disables it.
    max_concurrency:
        Maximum number of in-flight requests; Qualys caps concurrent calls per
        subscription, so we never exceed this locally.
    """

    def __init__(
        self,
        api_url: str,
        username: str,
        password: str,
        *,
        requests_per_second: float = 2.0,
        max_concurrency: int = 2,
        max_retries: int = 12,
        backoff_base: float = 1.0,
        backoff_max: float = 60.0,
        timeout: float = 300.0,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.timeout = timeout

        self._bucket = _TokenBucket(requests_per_second)
        self._semaphore = threading.Semaphore(max(1, max_concurrency))

        self._session = requests.Session()
        self._session.auth = (username, password)
        # X-Requested-With is MANDATORY for every Qualys API call.
        self._session.headers.update({"X-Requested-With": _X_REQUESTED_WITH})

    # ------------------------------------------------------------------ public
    def get(self, endpoint: str, params: dict[str, object]) -> bytes:
        """Issue a rate/concurrency-limited GET; return the raw response body."""
        return self._request("GET", endpoint, params)

    def post(self, endpoint: str, params: dict[str, object]) -> bytes:
        """Issue a rate/concurrency-limited POST (form params); return raw body."""
        return self._request("POST", endpoint, params)

    def close(self) -> None:
        """Close the underlying :class:`requests.Session`."""
        self._session.close()

    # ----------------------------------------------------------------- internal
    def _url(self, endpoint: str) -> str:
        return f"{self.api_url}/{endpoint.lstrip('/')}"

    def _request(self, method: str, endpoint: str, params: dict[str, object]) -> bytes:
        url = self._url(endpoint)
        # Qualys form fields must be strings; drop None so optional params are absent.
        form = {k: str(v) for k, v in params.items() if v is not None}

        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._bucket.acquire()
            with self._semaphore:
                try:
                    if method == "GET":
                        resp = self._session.get(url, params=form, timeout=self.timeout)
                    else:
                        resp = self._session.post(url, data=form, timeout=self.timeout)
                except requests.RequestException as exc:  # network blip -> retry
                    last_exc = exc
                    self._sleep_backoff(attempt)
                    continue

            if resp.status_code >= 500:
                last_exc = QualysApiError(
                    f"Qualys {method} {endpoint} -> HTTP {resp.status_code}",
                    status=resp.status_code,
                    body=resp.content,
                )
                self._sleep_backoff(attempt)
                continue

            if self._is_concurrency_limit(resp):
                last_exc = QualysApiError(
                    f"Qualys {method} {endpoint} -> concurrency limit",
                    status=resp.status_code,
                    body=resp.content,
                )
                # A concurrency-limit clears only when another in-flight call on the
                # subscription finishes, so a 1s exponential floor is useless here.
                # Wait a substantial, growing interval (15s, 30s, 45s ... capped) so
                # a single request can patiently outlast a busy window.
                time.sleep(min(self.backoff_max, 15.0 * (attempt + 1)))
                continue

            if resp.status_code >= 400:
                # Non-retryable client error (bad params, auth, unrecognised param).
                raise QualysApiError(
                    f"Qualys {method} {endpoint} -> HTTP {resp.status_code}: "
                    f"{resp.text[:500]}",
                    status=resp.status_code,
                    body=resp.content,
                )

            return resp.content

        # Retries exhausted.
        if isinstance(last_exc, QualysApiError):
            raise last_exc
        raise QualysApiError(
            f"Qualys {method} {endpoint} failed after {self.max_retries} retries"
        ) from last_exc

    def _sleep_backoff(self, attempt: int) -> None:
        delay = min(self.backoff_max, self.backoff_base * (2**attempt))
        time.sleep(delay)

    @staticmethod
    def _is_concurrency_limit(resp: requests.Response) -> bool:
        """True when the response is a Qualys concurrency/rate-limit rejection.

        Qualys signals this with HTTP 409 and a ``<CODE>1965</CODE>`` (or similar
        wording) in the small XML error body. We sniff the body text so we do not
        need a full XML parse for the retry decision.
        """
        if resp.status_code not in (409, 429):
            return False
        body = resp.text.lower()
        if f"<code>{_CONCURRENCY_LIMIT_CODE}</code>" in body:
            return True
        return any(marker in body for marker in _CONCURRENCY_LIMIT_MARKERS)
