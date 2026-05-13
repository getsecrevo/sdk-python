"""__version__ is read from installed metadata at import time so callers
can include it in user-agent strings, telemetry, and bug reports without
having to parse pyproject.toml themselves.
"""

import re

import secrevo_sdk


def test_version_is_a_string():
    assert isinstance(secrevo_sdk.__version__, str)
    assert secrevo_sdk.__version__


def test_version_matches_pep440():
    # PEP 440: digit-major-minor-patch with optional pre/dev/local segments.
    # We accept either a real version (when installed normally) or the
    # 0.0.0+local sentinel emitted when metadata is missing.
    assert re.match(r"^\d+\.\d+\.\d+(?:[\w+.-]*)?$", secrevo_sdk.__version__), (
        secrevo_sdk.__version__
    )


def test_version_is_exported():
    assert "__version__" in secrevo_sdk.__all__
