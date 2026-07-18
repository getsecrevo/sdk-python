from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class SecretRecord:
    workspace_id: str
    secret_id: str
    name: str
    description: str
    regeneration_instructions: str
    status: str
    updated_at: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SecretRecord":
        return cls(
            workspace_id=_require_text(payload, "workspace_id"),
            secret_id=_require_text(payload, "secret_id"),
            name=_require_text(payload, "name"),
            description=_optional_text(payload, "description"),
            regeneration_instructions=_optional_text(
                payload, "regeneration_instructions"
            ),
            status=_require_text(payload, "status"),
            updated_at=_require_text(payload, "updated_at"),
        )


@dataclass(frozen=True, slots=True)
class SecretValue:
    """The plaintext value of a secret, paired with its metadata.

    Returned by :meth:`SecrevoClient.reveal_value`. Treat ``value`` as
    sensitive: it is the raw credential. Avoid printing it, logging it,
    or storing it on disk.

    ``degraded`` is ``True`` when the value came from the local disk
    cache because the API was unreachable. Consumers that need
    freshness guarantees (e.g. rotating credentials) should branch on
    this flag.

    ``grace_expires_at`` is set only when the value was read with
    ``version="previous"``. It carries the timezone-aware UTC datetime
    at which the previous-value grace window expires, parsed from the
    ``X-Secrevo-Grace-Expires-At`` response header. For current-value
    reads (the default) this is always ``None``.
    """

    secret: SecretRecord
    value: str
    degraded: bool = False
    grace_expires_at: datetime | None = None

    @classmethod
    def from_payload(
        cls,
        secret: SecretRecord,
        payload: Mapping[str, Any],
        *,
        grace_expires_at: datetime | None = None,
    ) -> "SecretValue":
        return cls(
            secret=secret,
            value=_require_text(payload, "value"),
            grace_expires_at=grace_expires_at,
        )


@dataclass(frozen=True, slots=True)
class SecretAccess:
    secret: SecretRecord
    access_mode: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProxyResponse:
    """The (projected or redacted) upstream response from a mediated call.

    Returned by :meth:`SecrevoClient.call` and :meth:`SecrevoClient.session_call`.
    The secret value is **never** part of this object — the server injects it
    server-side and returns only ``body`` (a declared projection, or a redacted
    body for human-only targets). ``projected`` is ``True`` when ``body`` is a
    server-side projection rather than a redacted raw body.
    """

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    truncated: bool = False
    projected: bool = False

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ProxyResponse":
        headers = payload.get("headers") or {}
        return cls(
            status=int(payload.get("status") or 0),
            headers={str(k): str(v) for k, v in dict(headers).items()},
            body=str(payload.get("body") or ""),
            truncated=bool(payload.get("truncated")),
            projected=bool(payload.get("projected")),
        )


@dataclass(frozen=True, slots=True)
class ProxySession:
    """A short-lived, identity-bound handle for a multi-step mediated flow.

    Returned by :meth:`SecrevoClient.open_proxy_session`. Pass ``session_id`` to
    :meth:`SecrevoClient.session_call` for each step. The session is bound to
    your identity, expires at ``expires_at``, and dies on grant revocation — the
    value never reaches this process at any step.
    """

    session_id: str
    expires_at: str = ""

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ProxySession":
        return cls(
            session_id=_require_text(payload, "session_id"),
            expires_at=_optional_text(payload, "expires_at"),
        )


@dataclass(frozen=True, slots=True)
class ProxyTarget:
    """One allowlisted operation for a secret's mediated proxy (host + method +
    path [+ query/body/response contract]). Managed by a human principal only."""

    host: str
    methods: list[str] = field(default_factory=list)
    path_prefixes: list[str] = field(default_factory=list)
    allowed_query: list[str] = field(default_factory=list)
    query_constraints: dict[str, str] = field(default_factory=dict)
    body_template: str = ""
    response_mode: str = "projection"
    response_fields: list[str] = field(default_factory=list)
    max_response_bytes: int = 0

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ProxyTarget":
        return cls(
            host=_require_text(payload, "host"),
            methods=[str(m) for m in (payload.get("methods") or [])],
            path_prefixes=[str(p) for p in (payload.get("path_prefixes") or [])],
            allowed_query=[str(q) for q in (payload.get("allowed_query") or [])],
            query_constraints={
                str(k): str(v) for k, v in dict(payload.get("query_constraints") or {}).items()
            },
            body_template=_optional_text(payload, "body_template"),
            response_mode=_optional_text(payload, "response_mode") or "projection",
            response_fields=[str(f) for f in (payload.get("response_fields") or [])],
            max_response_bytes=int(payload.get("max_response_bytes") or 0),
        )

    def to_payload(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "host": self.host,
            "methods": list(self.methods),
            "path_prefixes": list(self.path_prefixes),
            "response_mode": self.response_mode,
            "response_fields": list(self.response_fields),
        }
        if self.allowed_query:
            body["allowed_query"] = list(self.allowed_query)
        if self.query_constraints:
            body["query_constraints"] = dict(self.query_constraints)
        if self.body_template:
            body["body_template"] = self.body_template
        if self.max_response_bytes:
            body["max_response_bytes"] = self.max_response_bytes
        return body


@dataclass(frozen=True, slots=True)
class Cred:
    """A short-lived, scoped ephemeral credential minted for a secret (F3).

    Unlike a mediated call, this credential DOES come back to your process — the
    deliberate, TTL-bounded exception for loads that must see bytes (AWS SigV4,
    DB clients). It is scoped and expires at ``expiration``; do not persist it.
    ``repr`` redacts the live material so an accidental log/traceback never leaks
    it — read the fields explicitly when you need them.
    """

    provider: str
    access_key_id: str = ""
    secret_access_key: str = ""
    session_token: str = ""
    expiration: str = ""
    ttl_seconds: int = 0

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "Cred":
        return cls(
            provider=_optional_text(payload, "provider"),
            access_key_id=_optional_text(payload, "access_key_id"),
            secret_access_key=_optional_text(payload, "secret_access_key"),
            session_token=_optional_text(payload, "session_token"),
            expiration=_optional_text(payload, "expiration"),
            ttl_seconds=int(payload.get("ttl_seconds") or 0),
        )

    def __repr__(self) -> str:  # never leak live material in logs/tracebacks
        return f"Cred(provider={self.provider!r}, ttl_seconds={self.ttl_seconds}, <redacted>)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class CredScope:
    """Per-secret declaration of what ephemeral credential it mints and its bounds
    (F3, human-only to edit). ``provider`` is ``aws_sts`` (``config`` carries
    ``role_arn`` [+ optional ``session_policy``]) or ``db`` (``config`` carries
    ``openbao_db_role``). ``role_arn`` is re-clamped by the mediator against an
    IaC allowlist at mint time — declaring one here does not by itself grant it.
    """

    provider: str
    config: dict[str, str] = field(default_factory=dict)
    max_ttl_seconds: int = 0

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "CredScope":
        return cls(
            provider=_require_text(payload, "provider"),
            config={str(k): str(v) for k, v in dict(payload.get("config") or {}).items()},
            max_ttl_seconds=int(payload.get("max_ttl_seconds") or 0),
        )

    def to_payload(self) -> dict[str, Any]:
        body: dict[str, Any] = {"provider": self.provider, "config": dict(self.config)}
        if self.max_ttl_seconds:
            body["max_ttl_seconds"] = self.max_ttl_seconds
        return body


def _require_text(payload: Mapping[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"payload field '{field_name}' must be a non-empty string")
    return value


def _optional_text(payload: Mapping[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"payload field '{field_name}' must be a string when present")
    return value
