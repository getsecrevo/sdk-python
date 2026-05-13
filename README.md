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

## Local development

    python -m venv .venv
    source .venv/bin/activate     # Windows: .venv\Scripts\activate
    pip install -e ".[test]"
    pytest

The tests use `httpx.MockTransport`, so no network or real Secrevo account is
required.

## Cross-references

- Product website: <https://secrevo.com>
- Status page: <https://secrevo.com/status>
- Privacy / Terms / DPA: <https://secrevo.com/privacy>, <https://secrevo.com/terms>, <https://secrevo.com/dpa>
- API repo: <https://github.com/getsecrevo/api>
- Infrastructure: <https://github.com/getsecrevo/infrastructure>
