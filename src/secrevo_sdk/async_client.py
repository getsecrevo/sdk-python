"""Async mirror of :class:`SecrevoClient`.

The async client speaks the same protocol over an ``httpx.AsyncClient``
and exposes the same surface — listing, fetching, revealing,
constructing third-party clients — but every blocking call returns a
coroutine instead. Use it from any async runtime (asyncio, anyio,
trio via the asyncio bridge); the only difference is that
``async with`` replaces ``with`` and reveal calls require ``await``.

Example::

    from secrevo_sdk import AsyncSecrevoClient

    async with AsyncSecrevoClient.from_env() as secrevo:
        openai = await secrevo.openai_for("OPENAI_API_KEY")
        result = await openai.responses.create(
            model="gpt-5",
            input="What is the capital of France?",
        )

The integration helpers return third-party async clients when one
exists (``openai.AsyncOpenAI``, ``anthropic.AsyncAnthropic``) and the
sync client otherwise (``stripe``, ``boto3``, ``PyGithub``); the
caller is responsible for not blocking the event loop on the sync
ones.
"""

from __future__ import annotations

import asyncio
import importlib
import random
from typing import Any, Awaitable, Callable, Literal
from urllib.parse import quote

import httpx

from .client import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_BACKOFF_BASE,
    DEFAULT_RETRY_BACKOFF_MAX,
    ENV_BASE_URL,
    ENV_TOKEN,
    ENV_WORKSPACE_ID,
    RETRYABLE_STATUS,
    _is_not_found_previous,
    _parse_grace_header,
    _parse_retry_after,
    _require_env,
    _require_text,
    normalize_access_mode,
)
from .exceptions import (
    AgentRevokedError,
    IntegrationNotInstalledError,
    RateLimitedError,
    SecretNotFoundError,
    SecrevoAPIError,
    SecrevoPreviousValueNotFoundError,
    api_error_from_body,
)
from . import _proxy
from .models import (
    Cred,
    CredScope,
    ProxyResponse,
    ProxySession,
    ProxyTarget,
    SecretAccess,
    SecretRecord,
    SecretValue,
)


class AsyncSecrevoClient:
    """Async equivalent of :class:`SecrevoClient`.

    The constructor, ``from_env`` classmethod and retry policy mirror
    the sync client. Methods that perform HTTP I/O are ``async def``;
    purely local helpers (``workspace_id``) are synchronous.
    """

    def __init__(
        self,
        *,
        base_url: str,
        workspace_id: str,
        token: str,
        timeout: float | httpx.Timeout = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff_base: float = DEFAULT_RETRY_BACKOFF_BASE,
        retry_backoff_max: float = DEFAULT_RETRY_BACKOFF_MAX,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._workspace_id = _require_text(workspace_id, "workspace_id")
        self._client = httpx.AsyncClient(
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
        transport: httpx.AsyncBaseTransport | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff_base: float = DEFAULT_RETRY_BACKOFF_BASE,
        retry_backoff_max: float = DEFAULT_RETRY_BACKOFF_MAX,
    ) -> "AsyncSecrevoClient":
        """Construct an async client from the standard env variables.

        See :meth:`SecrevoClient.from_env` for the contract — both
        clients honor the same variables.
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

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncSecrevoClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    @property
    def workspace_id(self) -> str:
        return self._workspace_id

    # --- Listing & metadata --------------------------------------------------

    async def list_secrets(self, *, refresh: bool = False) -> list[SecretRecord]:
        if not refresh and self._secret_index is not None:
            return list(self._secret_index.values())
        payload = await self._request_json(
            "GET", f"/v1/workspaces/{self._workspace_id}/secrets"
        )
        secrets = payload.get("secrets")
        if not isinstance(secrets, list):
            raise SecrevoAPIError("invalid secrets payload: expected a secrets list")
        records = [SecretRecord.from_payload(item) for item in secrets]
        self._secret_index = {record.name: record for record in records}
        return records

    async def get(self, secret_name: str) -> SecretRecord:
        secret = await self._resolve_secret_by_name(secret_name)
        detail = await self._request_json(
            "GET",
            f"/v1/workspaces/{self._workspace_id}/secrets/{secret.secret_id}",
        )
        return SecretRecord.from_payload(detail)

    async def get_with_context(self, secret_name: str) -> SecretAccess:
        secret = await self.get(secret_name)
        return SecretAccess(
            secret=secret,
            access_mode=normalize_access_mode("context"),
            context=_context_payload(self._workspace_id, secret, "with_context"),
        )

    async def get_for_agent(self, secret_name: str) -> SecretAccess:
        secret = await self.get(secret_name)
        return SecretAccess(
            secret=secret,
            access_mode=normalize_access_mode("agent"),
            context=_context_payload(self._workspace_id, secret, "for_agent"),
        )

    # --- Reveal --------------------------------------------------------------

    async def reveal_value(
        self,
        secret_name: str,
        *,
        version: Literal["current", "previous"] = "current",
    ) -> SecretValue:
        """Async equivalent of :meth:`SecrevoClient.reveal_value`.

        Supports the same ``version`` parameter for reading
        rotation-grace previous values. The async client is not
        cache-integrated (the disk cache lives on the sync client
        only), so previous-value reads here follow the same wire
        protocol as current reads — they just append ``?version=previous``
        and parse the ``X-Secrevo-Grace-Expires-At`` header.
        """
        if version not in ("current", "previous"):
            raise ValueError(
                f"version must be 'current' or 'previous', got {version!r}"
            )
        # Resolve + reveal in one call against the by-name value endpoint so a
        # per-secret grant suffices (listing requires secret.read@workspace,
        # overbroad for the team-sharing model). Mirrors the sync client + CLI.
        normalized_name = _require_text(secret_name, "secret_name")
        path = self._value_by_name_path(normalized_name)
        if version == "previous":
            try:
                payload, headers = await self._request_json_with_headers(
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
            secret = self._record_from_value_payload(normalized_name, payload)
            return SecretValue.from_payload(
                secret, payload, grace_expires_at=grace_expires_at
            )

        payload = await self._request_json("GET", path)
        secret = self._record_from_value_payload(normalized_name, payload)
        return SecretValue.from_payload(secret, payload)

    # --- Integrations --------------------------------------------------------

    async def openai_for(self, secret_name: str, **kwargs: Any) -> Any:
        """Return an ``openai.AsyncOpenAI`` client keyed on ``secret_name``."""
        openai_pkg = _import_or_raise("OpenAI", "openai")
        api_key = (await self.reveal_value(secret_name)).value
        return openai_pkg.AsyncOpenAI(api_key=api_key, **kwargs)

    async def anthropic_for(self, secret_name: str, **kwargs: Any) -> Any:
        """Return an ``anthropic.AsyncAnthropic`` client keyed on ``secret_name``."""
        anthropic_pkg = _import_or_raise("Anthropic", "anthropic")
        api_key = (await self.reveal_value(secret_name)).value
        return anthropic_pkg.AsyncAnthropic(api_key=api_key, **kwargs)

    async def stripe_for(self, secret_name: str) -> Any:
        """Return the ``stripe`` module with ``api_key`` set. Stripe has no
        first-class async SDK; callers needing async use ``stripe`` in a
        thread (e.g. ``asyncio.to_thread``) to avoid blocking the loop.
        """
        stripe_pkg = _import_or_raise("Stripe", "stripe")
        stripe_pkg.api_key = (await self.reveal_value(secret_name)).value
        return stripe_pkg

    async def aws_session_for(
        self,
        *,
        access_key_secret: str,
        secret_key_secret: str,
        session_token_secret: str | None = None,
        region_name: str | None = None,
        profile_name: str | None = None,
    ) -> Any:
        """Return a ``boto3.Session`` whose credentials came from Secrevo.

        boto3 is sync; for async AWS usage swap to ``aioboto3`` and
        construct your own session with the credentials. The reveal
        itself stays async — the bottleneck would be boto3, not the
        reveal.
        """
        boto3_pkg = _import_or_raise("AWS", "boto3")
        access_key = (await self.reveal_value(access_key_secret)).value
        secret_key = (await self.reveal_value(secret_key_secret)).value
        session_token = (
            (await self.reveal_value(session_token_secret)).value
            if session_token_secret
            else None
        )
        return boto3_pkg.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region_name,
            profile_name=profile_name,
        )

    async def github_for(self, secret_name: str, **kwargs: Any) -> Any:
        """Return a ``github.Github`` (PyGithub) client. PyGithub is sync;
        for async GitHub use ``gidgethub`` separately.
        """
        github_pkg = _import_or_raise("GitHub", "PyGithub", module_name="github")
        token = (await self.reveal_value(secret_name)).value
        auth = github_pkg.Auth.Token(token)
        return github_pkg.Github(auth=auth, **kwargs)

    # --- Mediated proxy (value never reaches this process) -------------------

    async def call(
        self,
        secret_name: str,
        *,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> ProxyResponse:
        """Async :meth:`SecrevoClient.call` — mediated outbound call; the value
        never reaches this process."""
        payload, _ = await self._request_json_with_headers(
            "POST",
            _proxy.proxy_consume_path(self._workspace_id, _require_text(secret_name, "secret_name")),
            json_body=_proxy.build_request_body(method=method, url=url, headers=headers, body=body),
        )
        return ProxyResponse.from_payload(payload)

    async def openai_call(self, secret_name: str, path: str, *, method: str = "GET", headers: dict[str, str] | None = None, body: str | None = None) -> ProxyResponse:
        return await self._typed_call("openai", secret_name, path, method=method, headers=headers, body=body)

    async def anthropic_call(self, secret_name: str, path: str, *, method: str = "GET", headers: dict[str, str] | None = None, body: str | None = None) -> ProxyResponse:
        return await self._typed_call("anthropic", secret_name, path, method=method, headers=headers, body=body)

    async def stripe_call(self, secret_name: str, path: str, *, method: str = "GET", headers: dict[str, str] | None = None, body: str | None = None) -> ProxyResponse:
        return await self._typed_call("stripe", secret_name, path, method=method, headers=headers, body=body)

    async def github_call(self, secret_name: str, path: str, *, method: str = "GET", headers: dict[str, str] | None = None, body: str | None = None) -> ProxyResponse:
        return await self._typed_call("github", secret_name, path, method=method, headers=headers, body=body)

    async def _typed_call(self, provider: str, secret_name: str, path: str, *, method: str, headers: dict[str, str] | None, body: str | None) -> ProxyResponse:
        url, merged = _proxy.resolve_typed(provider, path, headers)
        return await self.call(secret_name, url=url, method=method, headers=merged, body=body)

    async def open_proxy_session(self, secret_name: str) -> ProxySession:
        """Async :meth:`SecrevoClient.open_proxy_session`."""
        payload, _ = await self._request_json_with_headers(
            "POST",
            _proxy.proxy_session_open_path(self._workspace_id, _require_text(secret_name, "secret_name")),
            json_body={},
        )
        return ProxySession.from_payload(payload)

    async def session_call(
        self,
        session_id: str,
        *,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> ProxyResponse:
        """Async :meth:`SecrevoClient.session_call`."""
        payload, _ = await self._request_json_with_headers(
            "POST",
            _proxy.proxy_session_request_path(self._workspace_id, _require_text(session_id, "session_id")),
            json_body=_proxy.build_request_body(method=method, url=url, headers=headers, body=body),
        )
        return ProxyResponse.from_payload(payload)

    async def close_proxy_session(self, session_id: str) -> None:
        """Async :meth:`SecrevoClient.close_proxy_session`."""
        await self._request_no_content(
            "DELETE", _proxy.proxy_session_path(self._workspace_id, _require_text(session_id, "session_id"))
        )

    async def list_proxy_targets(self, secret_name: str) -> list[ProxyTarget]:
        """Async :meth:`SecrevoClient.list_proxy_targets`."""
        secret = await self._resolve_secret_by_name(secret_name)
        payload = await self._request_json("GET", _proxy.proxy_targets_path(self._workspace_id, secret.secret_id))
        return [ProxyTarget.from_payload(t) for t in (payload.get("targets") or [])]

    async def put_proxy_target(self, secret_name: str, target: ProxyTarget) -> ProxyTarget:
        """Async :meth:`SecrevoClient.put_proxy_target`."""
        secret = await self._resolve_secret_by_name(secret_name)
        payload, _ = await self._request_json_with_headers(
            "PUT",
            _proxy.proxy_targets_path(self._workspace_id, secret.secret_id),
            json_body=target.to_payload(),
        )
        return ProxyTarget.from_payload(payload)

    async def remove_proxy_target(self, secret_name: str, host: str) -> None:
        """Async :meth:`SecrevoClient.remove_proxy_target`."""
        secret = await self._resolve_secret_by_name(secret_name)
        await self._request_no_content(
            "DELETE",
            _proxy.proxy_targets_path(self._workspace_id, secret.secret_id),
            params={"host": _require_text(host, "host")},
        )

    async def mint_creds(self, secret_name: str, *, ttl_seconds: int = 0) -> Cred:
        """Async :meth:`SecrevoClient.mint_creds`."""
        payload, _ = await self._request_json_with_headers(
            "POST",
            _proxy.creds_path(self._workspace_id, _require_text(secret_name, "secret_name")),
            json_body={"ttl_seconds": int(ttl_seconds)},
        )
        return Cred.from_payload(payload)

    async def get_cred_scope(self, secret_name: str) -> CredScope:
        """Async :meth:`SecrevoClient.get_cred_scope`."""
        secret = await self._resolve_secret_by_name(secret_name)
        payload = await self._request_json("GET", _proxy.cred_scope_path(self._workspace_id, secret.secret_id))
        return CredScope.from_payload(payload)

    async def put_cred_scope(self, secret_name: str, scope: CredScope) -> CredScope:
        """Async :meth:`SecrevoClient.put_cred_scope`."""
        secret = await self._resolve_secret_by_name(secret_name)
        payload, _ = await self._request_json_with_headers(
            "PUT",
            _proxy.cred_scope_path(self._workspace_id, secret.secret_id),
            json_body=scope.to_payload(),
        )
        return CredScope.from_payload(payload)

    async def remove_cred_scope(self, secret_name: str) -> None:
        """Async :meth:`SecrevoClient.remove_cred_scope`."""
        secret = await self._resolve_secret_by_name(secret_name)
        await self._request_no_content(
            "DELETE", _proxy.cred_scope_path(self._workspace_id, secret.secret_id)
        )

    async def set_agent_read(self, secret_name: str, allowed: bool) -> None:
        """Async :meth:`SecrevoClient.set_agent_read`."""
        secret = await self._resolve_secret_by_name(secret_name)
        await self._request_json_with_headers(
            "PUT",
            _proxy.agent_read_path(self._workspace_id, secret.secret_id),
            json_body={"allowed": bool(allowed)},
        )

    # --- Internals -----------------------------------------------------------

    def _value_by_name_path(self, name: str) -> str:
        return (
            f"/v1/workspaces/{self._workspace_id}"
            f"/secrets/by-name/{quote(name, safe='')}/value"
        )

    def _record_from_value_payload(self, name: str, payload: Any) -> SecretRecord:
        # The by-name value endpoint returns {workspace_id, secret_id, value}
        # only — build a minimal record so SecretValue still carries the id.
        return SecretRecord(
            workspace_id=str(payload.get("workspace_id") or self._workspace_id),
            secret_id=str(payload.get("secret_id") or ""),
            name=name,
            description="",
            regeneration_instructions="",
            status="active",
            updated_at="",
        )

    async def _resolve_secret_by_name(self, secret_name: str) -> SecretRecord:
        normalized_name = _require_text(secret_name, "secret_name")
        for secret in await self.list_secrets():
            if secret.name == normalized_name:
                return secret
        for secret in await self.list_secrets(refresh=True):
            if secret.name == normalized_name:
                return secret
        available = sorted(
            secret.name for secret in await self.list_secrets()
        )
        raise SecretNotFoundError(
            normalized_name,
            workspace_id=self._workspace_id,
            available=available,
        )

    async def _request_json(self, method: str, path: str) -> dict[str, Any]:
        payload, _ = await self._request_json_with_headers(method, path)
        return payload

    async def _request_no_content(
        self, method: str, path: str, *, params: dict[str, str] | None = None
    ) -> None:
        """Issue a request whose success returns no JSON body (e.g. DELETE 204)."""
        response = await self._client.request(method, path, params=params)
        if response.is_success:
            return
        if response.status_code in (401, 403):
            error_body = (response.text or "").lower()
            if "agent" in error_body and ("revoked" in error_body or "paused" in error_body):
                raise AgentRevokedError(
                    "the agent token used by the SDK has been paused or revoked. "
                    "Ask the workspace owner to mint a new token."
                )
        raise api_error_from_body(
            status_code=response.status_code,
            response_body=response.text,
            fallback_message=self._format_error(response, method, path),
        )

    async def _request_json_with_headers(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        attempt = 0
        while True:
            try:
                response = await self._client.request(
                    method, path, params=params, json=json_body
                )
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                if attempt >= self._max_retries:
                    raise SecrevoAPIError(
                        f"{method} {path} failed after {attempt + 1} attempt(s): "
                        f"{type(exc).__name__}: {exc}"
                    ) from exc
                await self._sleep(self._compute_backoff(attempt, retry_after=None))
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
                await self._sleep(
                    self._compute_backoff(attempt, retry_after=retry_after_hint)
                )
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

            raise api_error_from_body(
                status_code=response.status_code,
                response_body=response.text,
                fallback_message=self._format_error(response, method, path),
            )

    def _compute_backoff(self, attempt: int, *, retry_after: float | None) -> float:
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
        "consumer": "python-sdk-async",
    }


def _import_or_raise(integration: str, package: str, module_name: str | None = None):
    target = module_name or package
    try:
        return importlib.import_module(target)
    except ImportError as exc:
        raise IntegrationNotInstalledError(
            integration=integration, package=package
        ) from exc
