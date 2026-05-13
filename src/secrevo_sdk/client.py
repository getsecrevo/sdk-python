from __future__ import annotations

import os
import random
import time
from typing import Any, Callable

import httpx

from . import integrations
from .exceptions import (
    AgentRevokedError,
    RateLimitedError,
    SecretNotFoundError,
    SecrevoAPIError,
)
from .models import SecretAccess, SecretRecord, SecretValue

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
    ) -> None:
        self._workspace_id = _require_text(workspace_id, "workspace_id")
        self._client = httpx.Client(
            base_url=_require_text(base_url, "base_url"),
            headers={
                "Authorization": f"Bearer {_require_text(token, 'token')}",
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

    def reveal_value(self, secret_name: str) -> SecretValue:
        """Reveal the plaintext value of a secret.

        The returned object holds both the metadata and the value. The
        value is sensitive — do not log it or persist it; pass it
        directly to the consumer (e.g. an API client) and let it go out
        of scope.

        On the wire this hits ``GET /v1/workspaces/{ws}/secrets/{id}/value``,
        which the API records as a ``secret.value.read`` audit event so
        the workspace owner sees who accessed what.
        """
        secret = self._resolve_secret_by_name(secret_name)
        payload = self._request_json(
            "GET",
            f"/v1/workspaces/{self._workspace_id}/secrets/{secret.secret_id}/value",
        )
        return SecretValue.from_payload(secret, payload)

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
        attempt = 0
        last_transport_error: Exception | None = None
        while True:
            try:
                response = self._client.request(method, path)
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
                return payload

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
