"""Framework-agnostic helpers for the mediated proxy surface.

These are pure functions shared by the sync and async clients so the path
building, request-body normalization, and typed-provider table live in one
place. None of them touch the network or the secret value.
"""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import quote

# The placeholder the caller puts where the value goes (headers/body only, never
# the URL). The server injects the value there and returns only the response.
PLACEHOLDER = "{{secret}}"

# Typed providers hardcode host + auth header so the caller supplies only a path
# — the host is the allowlist boundary and the value goes only into the fixed
# auth header. Mirrors the CLI/mcp-server typed proxies.
TYPED_PROVIDERS: dict[str, dict[str, Any]] = {
    "openai": {"host": "api.openai.com", "headers": {"Authorization": "Bearer {{secret}}"}},
    "anthropic": {
        "host": "api.anthropic.com",
        "headers": {"x-api-key": "{{secret}}", "anthropic-version": "2023-06-01"},
    },
    "stripe": {"host": "api.stripe.com", "headers": {"Authorization": "Bearer {{secret}}"}},
    "github": {
        "host": "api.github.com",
        "headers": {"Authorization": "Bearer {{secret}}", "Accept": "application/vnd.github+json"},
    },
}


def proxy_consume_path(workspace_id: str, name: str) -> str:
    return f"/v1/workspaces/{workspace_id}/secrets/by-name/{quote(name, safe='')}/proxy"


def proxy_session_open_path(workspace_id: str, name: str) -> str:
    return f"/v1/workspaces/{workspace_id}/secrets/by-name/{quote(name, safe='')}/proxy-session"


def proxy_session_request_path(workspace_id: str, session_id: str) -> str:
    return f"/v1/workspaces/{workspace_id}/proxy-sessions/{quote(session_id, safe='')}/requests"


def proxy_session_path(workspace_id: str, session_id: str) -> str:
    return f"/v1/workspaces/{workspace_id}/proxy-sessions/{quote(session_id, safe='')}"


def proxy_targets_path(workspace_id: str, secret_id: str) -> str:
    return f"/v1/workspaces/{workspace_id}/secrets/{quote(secret_id, safe='')}/proxy-targets"


def creds_path(workspace_id: str, name: str) -> str:
    return f"/v1/workspaces/{workspace_id}/secrets/by-name/{quote(name, safe='')}/creds"


def cred_scope_path(workspace_id: str, secret_id: str) -> str:
    return f"/v1/workspaces/{workspace_id}/secrets/{quote(secret_id, safe='')}/cred-scope"


def agent_read_path(workspace_id: str, secret_id: str) -> str:
    return f"/v1/workspaces/{workspace_id}/secrets/{quote(secret_id, safe='')}/agent-read"


def build_request_body(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str] | None,
    body: str | None,
) -> dict[str, Any]:
    """Build the JSON body for a mediated request, omitting empty fields.

    Rejects the placeholder in the URL client-side (the server also rejects it):
    the value must only ever go into a header or the request body.
    """
    if not url:
        raise ValueError("url is required")
    if PLACEHOLDER in url:
        raise ValueError(
            f"the {PLACEHOLDER} placeholder must not appear in the URL — "
            "put it in a header or the request body"
        )
    out: dict[str, Any] = {"method": (method or "GET").upper(), "url": url}
    if headers:
        out["headers"] = {str(k): str(v) for k, v in dict(headers).items()}
    if body:
        out["body"] = body
    return out


def resolve_typed(
    provider: str,
    path: str,
    extra_headers: Mapping[str, str] | None,
) -> tuple[str, dict[str, str]]:
    """Return (url, headers) for a typed provider call. The caller supplies only
    a path; the host and auth header come from the provider table."""
    p = TYPED_PROVIDERS.get(provider)
    if p is None:
        known = "|".join(sorted(TYPED_PROVIDERS))
        raise ValueError(f"unknown provider {provider!r} ({known})")
    if not path.startswith("/"):
        raise ValueError("path must start with '/', e.g. /v1/models")
    merged: dict[str, str] = dict(p["headers"])
    if extra_headers:
        for k, v in dict(extra_headers).items():
            merged[str(k)] = str(v)
    return "https://" + p["host"] + path, merged
