from __future__ import annotations

from typing import Any, Mapping

import httpx

from .exceptions import SecrevoAPIError, SecretNotFoundError
from .models import OpenAISecretStub, SecretAccess, SecretRecord

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
    def __init__(
        self,
        *,
        base_url: str,
        workspace_id: str,
        token: str,
        timeout: float | httpx.Timeout = 10.0,
        transport: httpx.BaseTransport | None = None,
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

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SecrevoClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def workspace_id(self) -> str:
        return self._workspace_id

    def list_secrets(self) -> list[SecretRecord]:
        payload = self._request_json(
            "GET", f"/v1/workspaces/{self._workspace_id}/secrets"
        )
        secrets = payload.get("secrets")
        if not isinstance(secrets, list):
            raise SecrevoAPIError("invalid secrets payload: expected a secrets list")
        return [SecretRecord.from_payload(item) for item in secrets]

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

    def openai_for(self, secret_name: str) -> OpenAISecretStub:
        return OpenAISecretStub(secret=self.get(secret_name))

    def _resolve_secret_by_name(self, secret_name: str) -> SecretRecord:
        normalized_name = _require_text(secret_name, "secret_name")
        for secret in self.list_secrets():
            if secret.name == normalized_name:
                return secret
        raise SecretNotFoundError(
            f"secret {normalized_name!r} was not found in workspace {self._workspace_id!r}"
        )

    def _request_json(self, method: str, path: str) -> dict[str, Any]:
        response = self._client.request(method, path)
        if response.is_success:
            payload = response.json()
            if not isinstance(payload, dict):
                raise SecrevoAPIError(
                    f"invalid response payload for {method} {path}: expected object"
                )
            return payload
        raise SecrevoAPIError(self._format_error(response, method, path))

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
