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
    """Raised when the Secrevo API returns a non-success response."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retry_after_seconds: float | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds


class RateLimitedError(SecrevoAPIError):
    """Raised when the Secrevo API rate limits the caller (HTTP 429)."""


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
