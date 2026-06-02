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
