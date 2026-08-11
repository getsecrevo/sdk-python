# secrevo-sdk

The official Python SDK for [Secrevo](https://secrevo.com). Pull secrets from
your Secrevo workspace and hand them to OpenAI, Anthropic, Stripe, AWS, or
GitHub without ever materializing them in your code.

## Install

    pip install secrevo-sdk

If you want a specific integration installed alongside the SDK, install one of
the extras:

    pip install "secrevo-sdk[openai]"
    pip install "secrevo-sdk[anthropic]"
    pip install "secrevo-sdk[stripe]"
    pip install "secrevo-sdk[aws]"
    pip install "secrevo-sdk[github]"
    pip install "secrevo-sdk[all]"

The integrations are imported lazily, so the base install only depends on
`httpx`.

## 30-second example

    from secrevo_sdk import SecrevoClient

    # Reads SECREVO_API_BASE_URL, SECREVO_WORKSPACE_ID, SECREVO_API_TOKEN.
    # Run `secrevo login` once, then any process in the shell can do this.
    with SecrevoClient.from_env() as secrevo:
        openai = secrevo.openai_for("OPENAI_API_KEY")
        result = openai.responses.create(
            model="gpt-5",
            input="What is the capital of France?",
        )
        print(result.output_text)

If you prefer explicit construction (e.g. binding to a specific workspace
inside a multi-tenant app):

    with SecrevoClient(
        base_url="https://api.secrevo.com",
        workspace_id="workspace-...",
        token="agt_...",
    ) as secrevo:
        ...

## Async

For FastAPI, batch LLM calls, or anything else that lives in an event
loop, the SDK ships an `AsyncSecrevoClient` with the same surface but
async methods. Integration helpers return the third-party async client
where one exists (`openai.AsyncOpenAI`, `anthropic.AsyncAnthropic`):

    from secrevo_sdk import AsyncSecrevoClient

    async with AsyncSecrevoClient.from_env() as secrevo:
        openai = await secrevo.openai_for("OPENAI_API_KEY")
        result = await openai.responses.create(
            model="gpt-5",
            input="What is the capital of France?",
        )
        print(result.output_text)

The OpenAI client is the canonical `openai.OpenAI` object. The same pattern
works for Anthropic (`anthropic_for`), Stripe (`stripe_for`), AWS
(`aws_session_for`) and GitHub (`github_for`). Every reveal goes through
the API and lands as a `secret.value.read` audit event in the workspace.

## Reveal a value directly

    revealed = secrevo.reveal_value("OPENAI_API_KEY")
    print(revealed.value)         # plaintext secret — handle with care
    print(revealed.secret.name)   # metadata is preserved alongside

`reveal_value` is the lowest-level API: every integration helper is built on
top of it. Treat the returned `value` as sensitive — pass it directly to
the consumer and let it go out of scope.

## Multi-field secrets (one credential, several parts)

Plenty of real credentials are tuples: a SUNAT login is `ruc` + `usuario` +
`clave`; a database is `host` + `port` + `user` + `password`. Storing them as
one secret keeps **every** part on the protected side of the permission
boundary, instead of the halves that "aren't the password" ending up in the
description — which anyone who can list secrets can read.

Reading:

    record = secrevo.get("SUNAT_SOL")
    print(record.fields)          # ['clave', 'ruc', 'usuario'] — NAMES only

    revealed = secrevo.reveal_value("SUNAT_SOL")
    revealed.field_value("clave") # the value of one field
    revealed.value                # empty for a multi-field secret

One reveal returns the whole bundle. That is deliberate: the reveal token is
single-use, so fetching fields one at a time would burn it on the first half of
a login.

Writing — **send every field, every time**:

    secrevo.set_fields("SUNAT_SOL", {
        "ruc": "20600000001",
        "usuario": "OPERADOR",
        "clave": "…",
    })

There is no partial update. The vault replaces the whole map on write and the
API cannot merge, because it cannot read the current value. **A call that omits
a field deletes it.** Read `record.fields` first if you need to know what a
secret is currently composed of.

Field names are lowercase snake_case (`^[a-z][a-z0-9_]{0,63}$`), at most 32 per
secret, values non-empty. The SDK checks all of that before the round trip and
names the offending field. Values are never trimmed — a password may legitimately
begin or end with a space.

`set_value(name, value)` writes a single-value secret. It is refused with
`multi_field_secret` against a secret that stores fields, rather than silently
collapsing the bundle. Converting a scalar secret that already feeds a proxy
target or a cred-scope is refused too, unless the bundle carries what that
mechanism reads: the consumer would otherwise break at consume time, on another
host, long after the write.

Group only what shares a trust boundary. Grants are per secret, so every field a
bundle gains widens what one grant hands out.

## Errors you actually want to handle

The SDK distinguishes the failure modes that matter:

| Exception                       | When                                                   |
| ------------------------------- | ------------------------------------------------------ |
| `SecretNotFoundError`           | Name doesn't resolve. The list of names that *do* live in this workspace is attached so you can spot typos. |
| `AgentRevokedError`             | The agent token was paused or revoked. Mint a new one. |
| `RateLimitedError`              | Hit a 429. `retry_after_seconds` is parsed from the response. |
| `IntegrationNotInstalledError`  | You called `openai_for(...)` but `openai` isn't installed. The error names the exact `pip install` line. |
| `SecrevoAPIError`               | Catch-all for everything else; carries the `status_code`. |

All of them inherit from `SecrevoError`, so `except SecrevoError:` is a valid
top-level guard.

## Integration helpers

| Helper                       | Returns                              | Optional extra        |
| ---------------------------- | ------------------------------------ | --------------------- |
| `secrevo.openai_for(name)`   | `openai.OpenAI(api_key=...)`         | `secrevo-sdk[openai]` |
| `secrevo.anthropic_for(name)`| `anthropic.Anthropic(api_key=...)`   | `secrevo-sdk[anthropic]` |
| `secrevo.stripe_for(name)`   | `stripe` module with `api_key` set   | `secrevo-sdk[stripe]` |
| `secrevo.aws_session_for(...)` | `boto3.Session(...)`               | `secrevo-sdk[aws]`    |
| `secrevo.github_for(name)`   | `github.Github(auth=Auth.Token(...))` | `secrevo-sdk[github]` |

`aws_session_for` takes the names of two (or three) secrets:

    session = secrevo.aws_session_for(
        access_key_secret="AWS_ACCESS_KEY_ID",
        secret_key_secret="AWS_SECRET_ACCESS_KEY",
        region_name="us-east-1",
    )
    s3 = session.client("s3")

## Offline resilience

Long-running services on intermittent networks (kiosks, mini-PCs on client
LANs) can opt into an encrypted local cache. When the API is unreachable,
the SDK falls back to the last cached value and flags the result with
`degraded=True` instead of crashing the worker.

    pip install "secrevo-sdk[cache]"

Default cache — 24h TTL, platform user cache dir, key derived from the
agent token via HKDF-SHA256:

    with SecrevoClient.from_env(cache="auto") as secrevo:
        revealed = secrevo.reveal_value("OPENAI_API_KEY")
        if revealed.degraded:
            log.warning("serving cached OPENAI_API_KEY — API unreachable")

Explicit configuration:

    from datetime import timedelta
    from secrevo_sdk import SecrevoClient
    from secrevo_sdk.cache import FileCache, derive_cache_key

    cache = FileCache(
        directory="/var/lib/myapp/secrevo-cache",
        encryption_key=derive_cache_key("agt_..."),
        max_age=timedelta(hours=6),
    )
    client = SecrevoClient(base_url="...", workspace_id="...", token="agt_...", cache=cache)
    client.set_offline(True)  # skip the API entirely; cache misses raise SecrevoOfflineError

On disk every entry is AES-256-GCM with a per-write random nonce; filenames
are SHA-256 of the cache key, so the directory listing never leaks secret
names. Rotating the agent token automatically invalidates the cache (the
HKDF-derived key changes, decrypt fails, the entry is unlinked).

## Local development

    python -m venv .venv
    source .venv/bin/activate     # Windows: .venv\Scripts\activate
    pip install -e ".[test]"
    pytest

The tests use `httpx.MockTransport`, so no network or real Secrevo account is
required.

## Cross-references

- Product website: <https://secrevo.com>
- Docs / quickstart: <https://secrevo.com/docs>
- Status page: <https://secrevo.com/status>
- Privacy / Terms / DPA: <https://secrevo.com/privacy>, <https://secrevo.com/terms>, <https://secrevo.com/dpa>
- CLI: <https://github.com/getsecrevo/cli>
