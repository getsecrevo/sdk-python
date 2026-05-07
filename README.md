# getsecrevo/sdk-python

`sdk-python` is the Python SDK for the **secrevo** product. It is a Cat D
consumption-surface repository.

## Purpose

This repository provides the Python client library for Secrevo. It gives
Python code a small, explicit, and testable way to talk to the Secrevo API,
resolve secrets by name, normalize secret access modes, and prepare
agent-facing secret access flows without hand-writing HTTP logic in every
consumer.

The SDK is intentionally narrow. It follows the current API contract and keeps
authentication explicit instead of hiding it behind global state.

## Stack

- Python 3.12+
- httpx for HTTP transport and request construction
- pytest for tests
- setuptools for packaging

## Architecture role

This repo sits on the client side of Secrevo. It does not host secrets and it
does not talk to OpenBao directly. Instead, it consumes the Secrevo API over
HTTP and turns the documented secret and agent flows into a Pythonic library.

The package currently focuses on:

- resolving secret metadata by name
- returning a normalized secret view for direct use, contextual use, or
  agent use
- preparing a lightweight OpenAI wrapper stub for the secret flow that will
  matter in phase 03

## Primary consumers

- Python automation jobs that need to resolve Secrevo secrets
- agent-side integration code that will call Secrevo from Python
- CLI helpers and notebooks that want a thin client instead of raw HTTP calls
- future product services that need a reusable Secrevo client

## API / contract

This SDK consumes the Secrevo API contract documented in:

- [API contract](../api/docs/contract.md)
- [OpenAPI](../api/docs/openapi.yaml)

The current client implementation uses:

- `GET /v1/workspaces/{workspaceId}/secrets`
- `GET /v1/workspaces/{workspaceId}/secrets/{secretId}`

The package is aligned with the broader Secrevo surface documented in the API
contract, including workspace bootstrap, members, agents, grants, access
requests, and audit trail endpoints.

## Local development

```bash
python -m venv .venv
.venv\\Scripts\\activate
pip install -e ".[test]"
pytest
```

If you want to run against Python 3.12 explicitly, use a 3.12 interpreter or a
container image that provides it.

## Tests

The test suite uses pytest and mocked HTTP transports. It covers:

- secret access mode normalization
- request construction and auth header handling
- secret lookup by name through the Secrevo API contract
- contextual and agent-facing secret views
- the OpenAI wrapper stub behavior

Run the tests with:

```bash
pytest
```

## Deployment

This repository does not run as a service. It is packaged as a versioned Python
library and consumed by Python applications, agent tooling, and automation
jobs.

Planned delivery is a wheel/sdist published from CI once phase 03 is wired into
the product pipeline. Until then, the repo is meant to be installed from
source.

## Cross-references

- Governance: <https://github.com/getGanemo/docs-company/blob/main/governance/product-structure.md>
- Product project_management: <https://github.com/getsecrevo/project_management>
- API contract: [api/docs/contract.md](../api/docs/contract.md)
- API OpenAPI: [api/docs/openapi.yaml](../api/docs/openapi.yaml)
- Infrastructure: <https://github.com/getsecrevo/infrastructure>
