"""Lazy wrappers that hand a Secrevo-managed credential to a third-party
SDK without ever exposing the raw value to caller code.

The wrappers import the third-party library at call time so apps that
only need one provider don't have to install the rest. Each helper
returns the canonical client object the third-party docs talk about,
already configured with the credential pulled from Secrevo.

Usage:

    with SecrevoClient(...) as secrevo:
        openai_client = secrevo.openai_for("OPENAI_API_KEY")
        # use it like the openai SDK normally would
        result = openai_client.responses.create(model="gpt-5", input="hi")
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from .exceptions import IntegrationNotInstalledError

if TYPE_CHECKING:  # pragma: no cover
    from .client import SecrevoClient


def _import_or_raise(integration: str, package: str, module_name: str | None = None):
    target = module_name or package
    try:
        return importlib.import_module(target)
    except ImportError as exc:
        raise IntegrationNotInstalledError(
            integration=integration, package=package
        ) from exc


def openai_for(client: "SecrevoClient", secret_name: str, **kwargs: Any) -> Any:
    """Return an ``openai.OpenAI`` client whose API key is ``secret_name``.

    Any additional keyword arguments are forwarded to the OpenAI
    constructor (``base_url``, ``timeout``, ``max_retries``, etc.).
    """
    openai_pkg = _import_or_raise("OpenAI", "openai")
    api_key = client.reveal_value(secret_name).value
    return openai_pkg.OpenAI(api_key=api_key, **kwargs)


def anthropic_for(client: "SecrevoClient", secret_name: str, **kwargs: Any) -> Any:
    """Return an ``anthropic.Anthropic`` client whose API key is
    ``secret_name``.
    """
    anthropic_pkg = _import_or_raise("Anthropic", "anthropic")
    api_key = client.reveal_value(secret_name).value
    return anthropic_pkg.Anthropic(api_key=api_key, **kwargs)


def stripe_for(client: "SecrevoClient", secret_name: str) -> Any:
    """Return the ``stripe`` module configured with ``secret_name`` as the
    API key.

    Stripe's Python SDK is module-level by design, so this helper sets
    ``stripe.api_key`` on the imported module and returns it. Subsequent
    calls overwrite the api key on the same module instance — call this
    once at startup if you only have one Stripe account.
    """
    stripe_pkg = _import_or_raise("Stripe", "stripe")
    stripe_pkg.api_key = client.reveal_value(secret_name).value
    return stripe_pkg


def aws_session_for(
    client: "SecrevoClient",
    *,
    access_key_secret: str,
    secret_key_secret: str,
    session_token_secret: str | None = None,
    region_name: str | None = None,
    profile_name: str | None = None,
) -> Any:
    """Return a ``boto3.Session`` whose credentials come from Secrevo.

    Pass the names of the secrets that hold the access key / secret
    key (and optionally the session token). The session can then be
    used like any other boto3 session — call ``.client("s3")`` etc.

    If you keep AWS credentials packed in Secrevo as ``AWS_ACCESS_KEY_ID``
    and ``AWS_SECRET_ACCESS_KEY``, the canonical call is:

        session = secrevo.aws_session_for(
            access_key_secret="AWS_ACCESS_KEY_ID",
            secret_key_secret="AWS_SECRET_ACCESS_KEY",
        )
    """
    boto3_pkg = _import_or_raise("AWS", "boto3")
    access_key = client.reveal_value(access_key_secret).value
    secret_key = client.reveal_value(secret_key_secret).value
    session_token = (
        client.reveal_value(session_token_secret).value
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


def github_for(client: "SecrevoClient", secret_name: str, **kwargs: Any) -> Any:
    """Return a ``github.Github`` client authenticated with ``secret_name``
    as a personal access token.

    Additional keyword arguments are forwarded to PyGithub's
    ``Github(...)`` constructor.
    """
    github_pkg = _import_or_raise("GitHub", "PyGithub", module_name="github")
    token = client.reveal_value(secret_name).value
    auth = github_pkg.Auth.Token(token)
    return github_pkg.Github(auth=auth, **kwargs)
