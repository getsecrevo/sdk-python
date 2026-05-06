from __future__ import annotations

from dataclasses import dataclass, field
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
            description=_require_text(payload, "description"),
            regeneration_instructions=_require_text(
                payload, "regeneration_instructions"
            ),
            status=_require_text(payload, "status"),
            updated_at=_require_text(payload, "updated_at"),
        )


@dataclass(frozen=True, slots=True)
class SecretAccess:
    secret: SecretRecord
    access_mode: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class OpenAISecretStub:
    secret: SecretRecord
    access_mode: str = "for_agent"
    provider: str = "openai"

    def as_client_kwargs(self) -> dict[str, Any]:
        raise NotImplementedError(
            "Secrevo does not yet expose secret value material in the current API "
            "contract, so the OpenAI wrapper is a stub."
        )


def _require_text(payload: Mapping[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"payload field '{field_name}' must be a non-empty string")
    return value

