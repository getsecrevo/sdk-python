class SecrevoError(Exception):
    """Base error for the Secrevo SDK."""


class SecretNotFoundError(SecrevoError):
    """Raised when a secret name cannot be resolved.

    Includes the list of secret names that *are* available so the caller
    can spot typos without round-tripping back to the dashboard.
    """

    def __init__(self, secret_name: str, *, workspace_id: str, available: list[str]):
        self.secret_name = secret_name
        self.workspace_id = workspace_id
        self.available = available
        if available:
            preview = ", ".join(available[:10])
            if len(available) > 10:
                preview += f", … (+{len(available) - 10} more)"
            message = (
                f"secret {secret_name!r} was not found in workspace {workspace_id!r}. "
                f"Available secrets: [{preview}]"
            )
        else:
            message = (
                f"secret {secret_name!r} was not found in workspace {workspace_id!r}. "
                "The workspace has no secrets visible to this token."
            )
        super().__init__(message)


class AgentRevokedError(SecrevoError):
    """Raised when the agent token used by the client has been revoked.

    The remediation is for the workspace owner to mint a new token; the
    SDK cannot recover on its own.
    """


class SecrevoAPIError(SecrevoError):
    """Raised when the Secrevo API returns a non-success response.

    ``response_body`` carries the raw text body of the failing response
    (when one was received). Useful for inspecting structured error
    codes like ``not_found_previous`` without re-parsing the message.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retry_after_seconds: float | None = None,
        response_body: str | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds
        self.response_body = response_body


class SecrevoMechanismError(SecrevoAPIError):
    """Raised when the caller hits a *mechanism wall* — a deny point reached
    while trying to USE a secret without seeing its plaintext (mediated
    consumption not configured, no ephemeral-credential scope, ephemeral creds
    disabled on the deployment, the agent raw-read cut, …).

    Unlike a bare :class:`SecrevoAPIError`, it carries the api's actionable
    envelope so a stuck agent (or its author) is never left at a dead-end:

    - ``code``        — the stable machine code (e.g. ``mediated_not_configured``)
    - ``remediation`` — the concrete next step AND the alternative
    - ``retryable``   — ``False`` for a policy/config cut (do not retry)

    The exception message leads with the code + message and appends the
    remediation on its own line so it reads as the next action to take.
    """

    def __init__(
        self,
        *,
        code: str,
        message: str,
        remediation: str,
        retryable: bool = False,
        status_code: int | None = None,
        response_body: str | None = None,
    ):
        self.code = code
        self.remediation = remediation
        self.retryable = retryable
        text = message or code or "the request was denied"
        if code and code not in text:
            text = f"{code}: {text}"
        if remediation:
            text = f"{text}\n  → {remediation}"
        super().__init__(
            text, status_code=status_code, response_body=response_body
        )


def api_error_from_body(
    *,
    status_code: int,
    response_body: str | None,
    fallback_message: str,
) -> SecrevoAPIError:
    """Build the right exception from a non-success response body.

    When the body is the actionable envelope ``{error, message, remediation,
    retryable}`` AND carries a remediation, return a rich
    :class:`SecrevoMechanismError`; otherwise return a plain
    :class:`SecrevoAPIError` with ``fallback_message`` (back-compat: the message
    still embeds the status + raw body so existing substring checks keep working).
    """
    import json

    body = response_body or ""
    try:
        envelope = json.loads(body)
    except (ValueError, TypeError):
        envelope = None
    if isinstance(envelope, dict):
        code = envelope.get("error") or ""
        remediation = envelope.get("remediation") or ""
        # Only a mechanism wall carries a remediation — that is the signal to
        # raise the rich typed error. A plain coded error (forbidden, not_found,
        # not_found_previous) stays a SecrevoAPIError so existing handling is
        # untouched.
        if code and remediation:
            return SecrevoMechanismError(
                code=code,
                message=envelope.get("message") or "",
                remediation=remediation,
                retryable=bool(envelope.get("retryable", False)),
                status_code=status_code,
                response_body=body,
            )
    return SecrevoAPIError(
        fallback_message, status_code=status_code, response_body=body
    )


class RateLimitedError(SecrevoAPIError):
    """Raised when the Secrevo API rate limits the caller (HTTP 429)."""


class SecrevoPreviousValueNotFoundError(SecrevoAPIError):
    """Raised when a previous-value read finds no active grace window.

    Distinct from a plain 404 on the current-value endpoint: this means
    the secret exists, but either rotation happened without grace, or
    the grace window has already expired.

    Raised when ``reveal_value(name, version="previous")`` receives an
    HTTP 404 with the ``not_found_previous`` error code from the API.
    """

    def __init__(self, secret_name: str, *, status_code: int | None = 404):
        self.secret_name = secret_name
        message = (
            f"No previous value available for {secret_name}. "
            "Either rotation was done without grace, or grace window expired."
        )
        super().__init__(message, status_code=status_code)


class SecrevoOfflineError(SecrevoError):
    """Raised when the client is in offline mode and the cache has no entry.

    The client only enters offline mode when the caller explicitly opts in
    via :meth:`SecrevoClient.set_offline`. If you reach this exception, the
    SDK has been told not to hit the API and the requested secret was not
    present in the local cache (or was past ``max_age``).
    """


class IntegrationNotInstalledError(SecrevoError):
    """Raised when an integration helper is used without the third-party
    library installed.

    The SDK lazy-imports each integration so apps that only need OpenAI
    don't have to install the AWS SDK. The error message names the
    package the caller should install.
    """

    def __init__(self, *, integration: str, package: str):
        self.integration = integration
        self.package = package
        super().__init__(
            f"the {integration} integration requires the {package!r} package. "
            f"Install it with `pip install {package}` and try again."
        )
