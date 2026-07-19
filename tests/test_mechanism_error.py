from __future__ import annotations

import httpx
import pytest

from secrevo_sdk.client import SecrevoClient
from secrevo_sdk.exceptions import (
    SecrevoAPIError,
    SecrevoMechanismError,
    api_error_from_body,
)
from secrevo_sdk.models import SecretRecord


def test_api_error_from_body_builds_mechanism_error() -> None:
    """A wall envelope with a remediation becomes a typed SecrevoMechanismError."""
    body = (
        '{"error":"ephemeral_not_supported",'
        '"message":"This secret has no ephemeral-credential scope.",'
        '"remediation":"A human runs `secrevo secret cred-scope add`; or use `secrevo call`.",'
        '"retryable":false}'
    )
    err = api_error_from_body(
        status_code=409, response_body=body, fallback_message="fallback"
    )
    assert isinstance(err, SecrevoMechanismError)
    assert err.code == "ephemeral_not_supported"
    assert err.retryable is False
    assert "cred-scope add" in err.remediation
    # The message surfaces both the code and the remediation as the next step.
    assert "ephemeral_not_supported" in str(err)
    assert "cred-scope add" in str(err)


def test_api_error_from_body_plain_coded_error_stays_api_error() -> None:
    """A coded error WITHOUT a remediation (forbidden, not_found_previous) stays a
    plain SecrevoAPIError so existing handling (isForbidden / grace) is untouched."""
    err = api_error_from_body(
        status_code=403,
        response_body='{"error":"forbidden","message":"missing capability"}',
        fallback_message="POST /x failed with 403: ...",
    )
    assert isinstance(err, SecrevoAPIError)
    assert not isinstance(err, SecrevoMechanismError)
    # not_found_previous detection relies on response_body — must be preserved.
    prev = api_error_from_body(
        status_code=404,
        response_body='{"error":"not_found_previous","message":"expired"}',
        fallback_message="fallback",
    )
    assert isinstance(prev, SecrevoAPIError)
    assert "not_found_previous" in (prev.response_body or "")


def test_api_error_from_body_non_envelope_falls_back() -> None:
    err = api_error_from_body(
        status_code=500, response_body="upstream exploded", fallback_message="the fallback"
    )
    assert isinstance(err, SecrevoAPIError)
    assert not isinstance(err, SecrevoMechanismError)
    assert str(err) == "the fallback"


def test_mint_creds_wall_raises_mechanism_error() -> None:
    """End-to-end: a client method that hits the /creds wall raises the typed
    error with the remediation, and honours retryable=False."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/creds"):
            return httpx.Response(
                409,
                json={
                    "error": "creds_not_enabled",
                    "message": "Ephemeral credentials are not enabled on this deployment.",
                    "remediation": "Use mediated consumption instead: `secrevo call --secret <NAME> --url ...`.",
                    "retryable": False,
                },
            )
        return httpx.Response(404, json={"error": "not_found"})

    client = SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="agt_x",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(SecrevoMechanismError) as ei:
        client.mint_creds("SOME_AWS_KEY")
    err = ei.value
    assert err.code == "creds_not_enabled"
    assert err.retryable is False
    assert "secrevo call" in err.remediation


def test_secret_record_surfaces_usability_flags() -> None:
    """SecretRecord.from_payload carries the agent-usability introspection from a
    single GET, and defaults them to None/empty when absent (list results)."""
    with_flags = SecretRecord.from_payload(
        {
            "workspace_id": "ws-1",
            "secret_id": "sec-1",
            "name": "K",
            "description": "",
            "regeneration_instructions": "",
            "status": "active",
            "updated_at": "2026-07-19T00:00:00Z",
            "agent_raw_read_allowed": False,
            "has_proxy_target": True,
            "has_cred_scope": False,
            "usable_by_agent_via": ["mediated_http"],
        }
    )
    assert with_flags.has_proxy_target is True
    assert with_flags.has_cred_scope is False
    assert with_flags.usable_by_agent_via == ["mediated_http"]

    from_list = SecretRecord.from_payload(
        {
            "workspace_id": "ws-1",
            "secret_id": "sec-1",
            "name": "K",
            "description": "",
            "regeneration_instructions": "",
            "status": "active",
            "updated_at": "2026-07-19T00:00:00Z",
        }
    )
    assert from_list.has_proxy_target is None
    assert from_list.usable_by_agent_via == []
