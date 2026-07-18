from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from .async_client import AsyncSecrevoClient
from .client import (
    ENV_BASE_URL,
    ENV_TOKEN,
    ENV_WORKSPACE_ID,
    SecrevoClient,
    normalize_access_mode,
)
from .exceptions import (
    AgentRevokedError,
    IntegrationNotInstalledError,
    RateLimitedError,
    SecretNotFoundError,
    SecrevoAPIError,
    SecrevoError,
    SecrevoOfflineError,
    SecrevoPreviousValueNotFoundError,
)
from .models import (
    Cred,
    CredScope,
    ProxyResponse,
    ProxySession,
    ProxyTarget,
    SecretAccess,
    SecretRecord,
    SecretValue,
)

try:
    __version__ = _pkg_version("secrevo-sdk")
except PackageNotFoundError:
    # Editable install before metadata is registered (rare) or a source
    # tree imported without being installed. Pin a sentinel so callers
    # that read __version__ for telemetry still get a string.
    __version__ = "0.0.0+local"

__all__ = [
    "AgentRevokedError",
    "AsyncSecrevoClient",
    "Cred",
    "CredScope",
    "ENV_BASE_URL",
    "ENV_TOKEN",
    "ENV_WORKSPACE_ID",
    "IntegrationNotInstalledError",
    "ProxyResponse",
    "ProxySession",
    "ProxyTarget",
    "RateLimitedError",
    "SecretAccess",
    "SecretNotFoundError",
    "SecretRecord",
    "SecretValue",
    "SecrevoAPIError",
    "SecrevoClient",
    "SecrevoError",
    "SecrevoOfflineError",
    "SecrevoPreviousValueNotFoundError",
    "__version__",
    "normalize_access_mode",
]
