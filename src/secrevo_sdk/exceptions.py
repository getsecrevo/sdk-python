class SecrevoError(Exception):
    """Base error for the Secrevo SDK."""


class SecretNotFoundError(SecrevoError):
    """Raised when a secret name cannot be resolved."""


class SecrevoAPIError(SecrevoError):
    """Raised when the Secrevo API returns a non-success response."""

