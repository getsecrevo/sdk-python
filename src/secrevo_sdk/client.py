from __future__ import annotations

import logging
import os
import random
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, Callable, Literal

import httpx

from . import integrations
from .exceptions import (
    AgentRevokedError,
    RateLimitedError,
    SecretNotFoundError,
    SecrevoAPIError,
    SecrevoOfflineError,
    SecrevoPreviousValueNotFoundError,
)
from .models import SecretAccess, SecretRecord, SecretValue

if TYPE_CHECKING:
    from .cache import FileCache

_cache_logger = logging.getLogger("secrevo_sdk.cache")

ENV_BASE_URL = "SECREVO_API_BASE_URL"
ENV_WORKSPACE_ID = "SECREVO_WORKSPACE_ID"
ENV_TOKEN = "SECREVO_API_TOKEN"

DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BACKOFF_BASE = 0.5
DEFAULT_RETRY_BACKOFF_MAX = 30.0
RETRYABLE_STATUS = frozenset({429, 502, 503, 504})

_ACCESS_MODE_ALIASES = {
    "": "standard",
    "default": "standard",
    "get": "standard",
    "standard": "standard",
    "context": "with_context",
    "with_context": "with_context",
    "with-context": "with_context",
    "agent": "for_agent",
    "for_agent": "for_agent",
    "for-agent": "for_agent",
}


def normalize_access_mode(value: str | None) -> str:
    if value is None:
        return "standard"
    normalized = value.strip().lower().replace("-", "_")
    if normalized in _ACCESS_MODE_ALIASES:
        return _ACCESS_MODE_ALIASES[normalized]
    raise ValueError(f"unsupported secret access mode: {value!r}")


class SecrevoClient:
    """HTTP client for the Secrevo API.

    The minimum signal you need to pass is ``base_url``, ``workspace_id``
    and ``token``. Everything else has sensible defaults. The client
    maintains an internal cache of the secret name → id mapping so
    name-based lookups don't pay a list round-trip every call.

    Example::

        from secrevo_sdk import SecrevoClient

        with SecrevoClient(
            base_url="https://api.secrevo.com",
            workspace_id="workspace-…",
            token="agt_…",
        ) as secrevo:
            openai = secrevo.openai_for("OPENAI_API_KEY")
            result = openai.responses.create(
                model="gpt-5",
                input="What is the capital of France?",
            )
            print(result.output_text)
    """

    def __init__(
        self,
        *,
        base_url: str,
        workspace_id: str,
        token: str,
        timeout: float | httpx.Timeout = 10.0,
        transport: httpx.BaseTransport | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff_base: float = DEFAULT_RETRY_BACKOFF_BASE,
        retry_backoff_max: float = DEFAULT_RETRY_BACKOFF_MAX,
        sleep: Callable[[float], None] = time.sleep,
        cache: "FileCache | Literal['auto'] | None" = None,
    ) -> None:
        clean_token = _require_text(token, "token")
        self._workspace_id = _require_text(workspace_id, "workspace_id")
        self._client = httpx.Client(
            base_url=_require_text(base_url, "base_url"),
            headers={
                "Authorization": f"Bearer {clean_token}",
                "Accept": "application/json",
            },
            timeout=timeout,
            transport=transport,
        )
        self._secret_index: dict[str, SecretRecord] | None = None
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        self._max_retries = max_retries
        self._retry_backoff_base = retry_backoff_base
        self._retry_backoff_max = retry_backoff_max
        self._sleep = sleep
        self._cache = self._resolve_cache(cache, clean_token)
        self._offline = False

    @staticmethod
    def _resolve_cache(
        cache: "FileCache | Literal['auto'] | None",
        token: str,
    ) -> "FileCache | None":
        if cache is None:
            return None
        if cache == "auto":
            from .cache import FileCache, derive_cache_key

            return FileCache(encryption_key=derive_cache_key(token))
        return cache

    @classmethod
    def from_env(
        cls,
        *,
        timeout: float | httpx.Timeout = 10.0,
        transport: httpx.BaseTransport | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff_base: float = DEFAULT_RETRY_BACKOFF_BASE,
        retry_backoff_max: float = DEFAULT_RETRY_BACKOFF_MAX,
    ) -> "SecrevoClient":
        """Construct a client from the standard Secrevo environment variables.

        Reads ``SECREVO_API_BASE_URL``, ``SECREVO_WORKSPACE_ID`` and
        ``SECREVO_API_TOKEN``. Missing or empty values raise
        :class:`ValueError` with the exact variable name so the caller can
        fix the misconfiguration without guessing.

        This is the idiomatic entry point when the application is already
        configured through env vars (e.g. running under ``secrevo run`` or
        a CI environment). For explicit construction use the regular
        constructor.
        """
        return cls(
            base_url=_require_env(ENV_BASE_URL),
            workspace_id=_require_env(ENV_WORKSPACE_ID),
            token=_require_env(ENV_TOKEN),
            timeout=timeout,
            transport=transport,
            max_retries=max_retries,
            retry_backoff_base=retry_backoff_base,
            retry_backoff_max=retry_backoff_max,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SecrevoClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def workspace_id(self) -> str:
        return self._workspace_id

    # --- Listing & metadata --------------------------------------------------

    def list_secrets(self, *, refresh: bool = False) -> list[SecretRecord]:
        """Return every secret visible to this token.

        The result is cached on the instance; pass ``refresh=True`` to
        force a re-fetch (e.g. after an admin granted you a new secret
        in another tab).
        """
        if not refresh and self._secret_index is not None:
            return list(self._secret_index.values())
        payload = self._request_json(
            "GET", f"/v1/workspaces/{self._workspace_id}/secrets"
        )
        secrets = payload.get("secrets")
        if not isinstance(secrets, list):
            raise SecrevoAPIError("invalid secrets payload: expected a secrets list")
        records = [SecretRecord.from_payload(item) for item in secrets]
        self._secret_index = {record.name: record for record in records}
        return records

    def get(self, secret_name: str) -> SecretRecord:
        secret = self._resolve_secret_by_name(secret_name)
        detail = self._request_json(
            "GET",
            f"/v1/workspaces/{self._workspace_id}/secrets/{secret.secret_id}",
        )
        return SecretRecord.from_payload(detail)

    def get_with_context(self, secret_name: str) -> SecretAccess:
        secret = self.get(secret_name)
        return SecretAccess(
            secret=secret,
            access_mode=normalize_access_mode("context"),
            context=_context_payload(self._workspace_id, secret, "with_context"),
        )

    def get_for_agent(self, secret_name: str) -> SecretAccess:
        secret = self.get(secret_name)
        return SecretAccess(
            secret=secret,
            access_mode=normalize_access_mode("agent"),
            context=_context_payload(self._workspace_id, secret, "for_agent"),
        )

    # --- Reveal --------------------------------------------------------------

    def reveal_value(
        self,
        secret_name: str,
        *,
        version: Literal["current", "previous"] = "current",
    ) -> SecretValue:
        """Reveal the plaintext value of a secret.

        The returned object holds both the metadata and the value. The
        value is sensitive — do not log it or persist it; pass it
        directly to the consumer (e.g. an API client) and let it go out
        of scope.

        On the wire this hits ``GET /v1/workspaces/{ws}/secrets/{id}/value``,
        which the API records as a ``secret.value.read`` audit event so
        the workspace owner sees who accessed what.

        ``version`` selects which materialization to read:

        * ``"current"`` (default) — the live value. Cache-integrated:
          on transient API failure or in ``set_offline(True)`` mode,
          the SDK falls back to the most recent cached value within
          the cache's ``max_age`` window and flags the returned
          :class:`SecretValue` with ``degraded=True``.
        * ``"previous"`` — the previous value during the rotation
          grace window opened by api#46. Hits the ``?version=previous``
          variant of the endpoint. The disk cache is deliberately
          BYPASSED for previous-value reads (both read and write):
          the cache contract is "the operator's view of the current
          value, used to survive transient API outages", and caching
          previous-value reads would invite consuming stale rolled-back
          values long after the grace window expired. Previous-value
          reads are one-off operator actions during rotation, not the
          hot path. On a successful previous-value response the
          ``X-Secrevo-Grace-Expires-At`` header is parsed and surfaced
          as :attr:`SecretValue.grace_expires_at`. If no grace window
          is active, the API returns ``404 not_found_previous`` which
          the SDK raises as
          :class:`SecrevoPreviousValueNotFoundError`.
        """
        normalized_name = _require_text(secret_name, "secret_name")
        if version not in ("current", "previous"):
            raise ValueError(
                f"version must be 'current' or 'previous', got {version!r}"
            )
        cache_key = self._cache_key_for(normalized_name)

        # Previous-value reads NEVER touch the disk cache (read or write).
        # See docstring above for rationale. We still honor offline mode
        # by failing loudly: a previous-value read in offline mode is
        # almost certainly a misuse and silently returning the cached
        # CURRENT value would be a footgun.
        if version == "previous":
            if self._offline:
                raise SecrevoOfflineError(
                    "previous-value reads require network access; "
                    "the disk cache only stores current values"
                )
            secret = self._resolve_secret_by_name(normalized_name)
            path = (
                f"/v1/workspaces/{self._workspace_id}"
                f"/secrets/{secret.secret_id}/value"
            )
            try:
                payload, headers = self._request_json_with_headers(
                    "GET", path, params={"version": "previous"}
                )
            except SecrevoAPIError as exc:
                if exc.status_code == 404 and _is_not_found_previous(exc):
                    raise SecrevoPreviousValueNotFoundError(
                        normalized_name
                    ) from exc
                raise
            grace_expires_at = _parse_grace_header(
                headers.get("X-Secrevo-Grace-Expires-At")
                or headers.get("x-secrevo-grace-expires-at")
            )
            return SecretValue.from_payload(
                secret, payload, grace_expires_at=grace_expires_at
            )

        # version == "current": existing path, unchanged behavior.
        if self._offline:
            cached = self._cache.get(cache_key) if self._cache else None
            if cached is None:
                raise SecrevoOfflineError(
                    f"client is offline and {normalized_name!r} is not in the cache"
                )
            return self._cached_secret_value(normalized_name, cached, degraded=True)

        try:
            secret = self._resolve_secret_by_name(normalized_name)
            payload = self._request_json(
                "GET",
                f"/v1/workspaces/{self._workspace_id}/secrets/{secret.secret_id}/value",
            )
        except SecrevoAPIError:
            cached = self._cache.get(cache_key) if self._cache else None
            if cached is None:
                raise
            _cache_logger.warning(
                "fallback_to_cache_after_api_failure key=%s", normalized_name
            )
            return self._cached_secret_value(normalized_name, cached, degraded=True)

        value = SecretValue.from_payload(secret, payload)
        if self._cache is not None:
            self._cache.set(
                cache_key,
                value=value.value,
                kind="secret_value",
                metadata={
                    "workspace_id": secret.workspace_id,
                    "secret_id": secret.secret_id,
                    "name": secret.name,
                    "status": secret.status,
                    "updated_at": secret.updated_at,
                },
            )
        return value

    def set_offline(self, offline: bool) -> None:
        """Toggle offline mode.

        When ``True``, :meth:`reveal_value` skips the API and reads
        exclusively from the disk cache. A cache miss raises
        :class:`SecrevoOfflineError`. Useful for tests, disaster
        drills, and scheduled "what would survive a network outage"
        audits in long-running services.
        """
        self._offline = bool(offline)

    @property
    def offline(self) -> bool:
        return self._offline

    @property
    def cache(self) -> "FileCache | None":
        return self._cache

    def _cache_key_for(self, secret_name: str) -> str:
        return f"{self._workspace_id}:{secret_name}"

    def _cached_secret_value(
        self, secret_name: str, cached: Any, *, degraded: bool
    ) -> SecretValue:
        metadata = cached.metadata or {}
        record = SecretRecord(
            workspace_id=str(metadata.get("workspace_id") or self._workspace_id),
            secret_id=str(metadata.get("secret_id") or ""),
            name=str(metadata.get("name") or secret_name),
            description="",
            regeneration_instructions="",
            status=str(metadata.get("status") or "active"),
            updated_at=str(metadata.get("updated_at") or ""),
        )
        return SecretValue(secret=record, value=cached.value, degraded=degraded)

    # --- Integrations --------------------------------------------------------

    def openai_for(self, secret_name: str, **kwargs: Any) -> Any:
        """Return an ``openai.OpenAI`` client keyed on ``secret_name``."""
        return integrations.openai_for(self, secret_name, **kwargs)

    def anthropic_for(self, secret_name: str, **kwargs: Any) -> Any:
        """Return an ``anthropic.Anthropic`` client keyed on ``secret_name``."""
        return integrations.anthropic_for(self, secret_name, **kwargs)

    def stripe_for(self, secret_name: str) -> Any:
        """Return the ``stripe`` module with ``api_key`` set to the secret."""
        return integrations.stripe_for(self, secret_name)

    def aws_session_for(
        self,
        *,
        access_key_secret: str,
        secret_key_secret: str,
        session_token_secret: str | None = None,
        region_name: str | None = None,
        profile_name: str | None = None,
    ) -> Any:
        """Return a ``boto3.Session`` whose credentials come from Secrevo."""
        return integrations.aws_session_for(
            self,
            access_key_secret=access_key_secret,
            secret_key_secret=secret_key_secret,
            session_token_secret=session_token_secret,
            region_name=region_name,
            profile_name=profile_name,
        )

    def github_for(self, secret_name: str, **kwargs: Any) -> Any:
        """Return a ``github.Github`` client authed with the secret."""
        return integrations.github_for(self, secret_name, **kwargs)

    # --- Internals -----------------------------------------------------------

    def _resolve_secret_by_name(self, secret_name: str) -> SecretRecord:
        normalized_name = _require_text(secret_name, "secret_name")
        for secret in self.list_secrets():
            if secret.name == normalized_name:
                return secret
        # Refresh once in case the cache predates a recent grant.
        for secret in self.list_secrets(refresh=True):
            if secret.name == normalized_name:
                return secret
        available = sorted(secret.name for secret in self.list_secrets())
        raise SecretNotFoundError(
            normalized_name,
            workspace_id=self._workspace_id,
            available=available,
        )

    def _request_json(self, method: str, path: str) -> dict[str, Any]:
        payload, _ = self._request_json_with_headers(method, path)
        return payload

    def _request_json_with_headers(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        attempt = 0
        last_transport_error: Exception | None = None
        while True:
            try:
                response = self._client.request(method, path, params=params)
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_transport_error = exc
                if attempt >= self._max_retries:
                    raise SecrevoAPIError(
                        f"{method} {path} failed after {attempt + 1} attempt(s): "
                        f"{type(exc).__name__}: {exc}"
                    ) from exc
                self._sleep(self._compute_backoff(attempt, retry_after=None))
                attempt += 1
                continue

            if response.is_success:
                payload = response.json()
                if not isinstance(payload, dict):
                    raise SecrevoAPIError(
                        f"invalid response payload for {method} {path}: expected object"
                    )
                return payload, dict(response.headers)

            if response.status_code in (401, 403):
                error_body = (response.text or "").lower()
                if "agent" in error_body and (
                    "revoked" in error_body or "paused" in error_body
                ):
                    raise AgentRevokedError(
                        "the agent token used by the SDK has been paused or revoked. "
                        "Ask the workspace owner to mint a new token."
                    )

            if response.status_code in RETRYABLE_STATUS and attempt < self._max_retries:
                retry_after_hint = (
                    _parse_retry_after(response.headers.get("retry-after"))
                    if response.status_code == 429
                    else None
                )
                self._sleep(self._compute_backoff(attempt, retry_after=retry_after_hint))
                attempt += 1
                continue

            if response.status_code == 429:
                retry_after = _parse_retry_after(response.headers.get("retry-after"))
                raise RateLimitedError(
                    f"rate limited by the Secrevo API on {method} {path}; "
                    f"retry after ~{retry_after:.0f}s",
                    status_code=429,
                    retry_after_seconds=retry_after,
                )

            raise SecrevoAPIError(
                self._format_error(response, method, path),
                status_code=response.status_code,
                response_body=response.text,
            )

    def _compute_backoff(self, attempt: int, *, retry_after: float | None) -> float:
        """Return seconds to wait before retry attempt N (0-indexed).

        If the server provided a ``Retry-After`` value, honor it (clamped to
        ``retry_backoff_max``). Otherwise use exponential backoff with full
        jitter: ``random([0, base * 2^attempt])`` capped at ``backoff_max``.
        """
        if retry_after is not None:
            return min(retry_after, self._retry_backoff_max)
        ceiling = min(self._retry_backoff_base * (2 ** attempt), self._retry_backoff_max)
        return random.uniform(0, ceiling)

    @staticmethod
    def _format_error(response: httpx.Response, method: str, path: str) -> str:
        message = response.text.strip() or response.reason_phrase
        return f"{method} {path} failed with {response.status_code}: {message}"


def _context_payload(
    workspace_id: str, secret: SecretRecord, access_mode: str
) -> dict[str, Any]:
    return {
        "workspace_id": workspace_id,
        "secret_id": secret.secret_id,
        "secret_name": secret.name,
        "access_mode": access_mode,
        "consumer": "python-sdk",
    }


def _require_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _require_env(name: str) -> str:
    raw = os.environ.get(name, "")
    if not raw.strip():
        raise ValueError(
            f"{name} is required but not set. Run `secrevo login` or export "
            f"the variable manually."
        )
    return raw.strip()


def _is_not_found_previous(exc: SecrevoAPIError) -> bool:
    """Return ``True`` if the API error body identifies the ``not_found_previous``
    error code shipped by api#46 for missing-grace previous-value reads.

    We inspect the raw response body so a regular 404 (e.g. the secret
    doesn't exist at all) doesn't get mis-mapped to
    :class:`SecrevoPreviousValueNotFoundError`.
    """
    body = (exc.response_body or "").lower()
    return "not_found_previous" in body


def _parse_grace_header(raw: str | None) -> datetime | None:
    """Parse ``X-Secrevo-Grace-Expires-At`` into a timezone-aware UTC datetime.

    The API emits ISO-8601 (e.g. ``2026-06-02T12:34:56Z``). Returns
    ``None`` if the header is missing or unparseable — we never let a
    malformed header crash a reveal call, since the value itself is
    still usable.
    """
    if not raw:
        return None
    raw = raw.strip()
    if not raw:
        return None
    try:
        # ``fromisoformat`` accepts the trailing ``Z`` on Python 3.11+.
        # For 3.10 we fall back to manual ``+00:00`` substitution.
        candidate = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if dt.tzinfo is None:
        from datetime import timezone

        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_retry_after(raw: str | None) -> float:
    """Parse a Retry-After header per RFC 7231 — either delta-seconds or
    an HTTP-date. Falls back to 1.0 second if the value is missing or
    unparseable.
    """
    if not raw:
        return 1.0
    raw = raw.strip()
    if raw.isdigit():
        return float(raw)
    try:
        # HTTP-date case (rare)
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(raw)
        delta = dt.timestamp() - time.time()
        return max(delta, 1.0)
    except Exception:
        return 1.0
