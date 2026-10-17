"""Safe TAXII 2.1 collection adapter.

The adapter is deliberately transport-only: callers decide how parsed records
are persisted. Network failures are explicit and never become empty feeds.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from services.threat_intel.parsers.stix21 import ParsedFeedRecord, Stix21FeedParser


class TaxiiAdapterError(RuntimeError):
    """Base error for TAXII provider failures."""


class TaxiiTimeoutError(TaxiiAdapterError):
    """The provider exceeded the configured transport timeout."""


class TaxiiRateLimitError(TaxiiAdapterError):
    """The local request budget or provider rate limit was exceeded."""


@dataclass(frozen=True)
class TaxiiAdapterConfig:
    collection_url: str
    timeout_seconds: float = 10.0
    requests_per_minute: int = 60
    bearer_token: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.collection_url.startswith(("https://", "http://")):
            raise ValueError("TAXII collection URL must use HTTP or HTTPS")
        if not 1.0 <= self.timeout_seconds <= 60.0:
            raise ValueError("TAXII timeout must be between 1 and 60 seconds")
        if not 1 <= self.requests_per_minute <= 600:
            raise ValueError("TAXII request budget must be between 1 and 600 per minute")


class TaxiiAdapter:
    """Fetch and safely parse a bounded STIX 2.1 TAXII collection."""

    ACCEPT = "application/taxii+json;version=2.1"

    def __init__(
        self,
        config: TaxiiAdapterConfig,
        client: Optional[httpx.Client] = None,
        clock: Optional[Any] = None,
    ):
        self.config = config
        self._client = client
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._requests: List[float] = []

    def _allow_request(self) -> None:
        now = self._clock()
        with self._lock:
            self._requests = [stamp for stamp in self._requests if now - stamp < 60.0]
            if len(self._requests) >= self.config.requests_per_minute:
                raise TaxiiRateLimitError("TAXII local request budget exceeded")
            self._requests.append(now)

    def fetch_records(self) -> List[ParsedFeedRecord]:
        """Fetch one collection page; pagination is intentionally caller-controlled."""
        self._allow_request()
        headers = {"Accept": self.ACCEPT}
        if self.config.bearer_token:
            headers["Authorization"] = f"Bearer {self.config.bearer_token}"
        client = self._client or httpx.Client(timeout=self.config.timeout_seconds)
        close_client = self._client is None
        try:
            try:
                response = client.get(self.config.collection_url, headers=headers)
                response.raise_for_status()
            except httpx.TimeoutException as exc:
                raise TaxiiTimeoutError("TAXII provider request timed out") from exc
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429:
                    raise TaxiiRateLimitError("TAXII provider rate limit returned 429") from exc
                raise TaxiiAdapterError(
                    f"TAXII provider returned HTTP {exc.response.status_code}"
                ) from exc
            except httpx.HTTPError as exc:
                raise TaxiiAdapterError("TAXII provider transport failed") from exc

            try:
                payload: Dict[str, Any] = response.json()
            except ValueError as exc:
                raise TaxiiAdapterError("TAXII provider returned invalid JSON") from exc
            if payload.get("type") == "bundle":
                return Stix21FeedParser.parse_bundle(payload)
            objects = payload.get("objects")
            if not isinstance(objects, list):
                raise TaxiiAdapterError("TAXII response did not contain an objects list")
            return Stix21FeedParser.parse_bundle({"type": "bundle", "objects": objects})
        finally:
            if close_client:
                client.close()


__all__ = [
    "TaxiiAdapter",
    "TaxiiAdapterConfig",
    "TaxiiAdapterError",
    "TaxiiRateLimitError",
    "TaxiiTimeoutError",
]
