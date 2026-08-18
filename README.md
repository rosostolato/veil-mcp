# Veil

[![CI](https://github.com/rosostolato/veil-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rosostolato/veil-mcp/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

**An AI agent can orchestrate the placement of a credential without ever receiving the
credential value, while a trusted human-controlled interface independently authorizes
where that credential is allowed to go.**

That sentence is the entire promise. Veil is an MCP server plus a secure input broker:
the agent says *"put a Stripe production key in Google Secret Manager"*, the human sees
exactly which project and secret will be written and types the value into Veil's own
window, and the value goes straight to the destination. The model never holds it.

Implemented from [`SPEC.md`](SPEC.md).

---

## What Veil solves

It removes an entire class of failures caused by the agent **knowing** the secret.
With Veil in the loop, a credential does not pass through:

- LLM prompts or conversation history
- MCP tool arguments or tool results
- agent memory or generated code
- shell command arguments or process argv
- logs, debug traces or telemetry
- URLs
- model-visible command output

## What Veil does **not** solve

Veil does not make an AI agent trustworthy, and it is not "safe AI". It does not
guarantee that the agent picked the right destination, that it understood you, that it
is free of prompt injection, that the destination is itself secure, that your machine is
uncompromised, or that a credential cannot be misused later by software that legitimately
receives it.

There are two separate problems here:

| Question | Veil's answer |
| --- | --- |
| Should the agent know the secret? | No. |
| Should the agent decide alone where the secret goes? | Not without human authorization. |

Veil answers those two. It does not claim to answer the rest.

---

## Trust model

```text
Trusted with the credential value:

  The human at the keyboard
  Veil's secure input UI          (loopback only, in your control)
  Veil's secure input broker      (this process)
  The selected destination adapter
  The destination provider        (e.g. Google Secret Manager)

NOT trusted with the credential value:

  The LLM
  The agent / MCP client
  The conversation
  The prompt and any repository content it read
  Generated code
  Logs, telemetry, crash reports
```

This diagram does not claim the trusted components are invulnerable. It says where the
credential is *allowed* to exist. Veil is security-sensitive software: if Veil itself is
malicious or compromised, the boundary is gone. Its source, dependencies and releases
deserve the scrutiny you would give any credential-handling tool.

---

## The two flows

**The secret flow** — the human's path, which the model cannot observe:

```text
Human ─▶ Veil secure UI (127.0.0.1) ─▶ Broker ─▶ Adapter ─▶ Destination
```

**The agent flow** — everything the model sees:

```text
LLM ─▶ MCP client ─▶ Veil MCP server ─▶ non-sensitive result metadata
```

The MCP tool schema has no property capable of carrying a credential. That is structural,
not a prompt instruction: there is no `value`, `secret_value`, `password`, `token`,
`content` or `raw_secret` field to abuse, closed schemas reject unknown properties, and
arguments are screened for credential-shaped values before they are parsed.

### What the agent calls

```json
{
  "destination": "gcp-secret-manager",
  "name": "STRIPE_SECRET_KEY",
  "target": { "project": "my-production-project", "secret": "STRIPE_SECRET_KEY" },
  "write_mode": "new-version",
  "environment": "production",
  "description": "Stripe production API key"
}
```

Veil replies with a `request_id`, a risk classification and the normalized destination —
and opens its own authorization window on your machine. The agent polls `secret.status`.

**The agent does not get the authorization link.** That link is a capability: anything
holding it can complete the human's half of the flow, and an agent with a shell or an HTTP
tool is precisely the threat model. Veil hands it to your browser and prints it to its own
console instead. Set `VEIL_DISCLOSE_AUTHORIZATION_URL=true` if your setup needs the agent
to relay the link (for example, a remote or headless session) — and understand that this
lets a compromised agent authorize its own request.

| Tool | Purpose |
| --- | --- |
| `secret.store` | Create a credential request. Returns non-sensitive metadata and a request id. |
| `secret.status` | Poll a request. Never returns credential material. |
| `secret.cancel` | Cancel a pending request; any entered value is destroyed. |
| `secret.revise` | Invalidate an authorization and start a new one. Nothing is edited in place. |
| `secret.destinations` | List destinations and the target fields each expects. |

### What the human sees

Stage A shows the credential name, destination provider, project/account, resource,
operation and risk **before** the value is entered. High-risk operations (production
overwrite, plaintext storage, application databases, replacing a credential) require a
second confirmation in Stage B, after entry and before the write. The value is never
displayed back.

The page the human reads and the operation the executor performs are the *same immutable
object* — there is no separate "display destination". Any change to destination, project,
secret name, operation, write mode or adapter invalidates the authorization and requires a
new one.

---

## Supported adapters

| Adapter | Class | Notes |
| --- | --- | --- |
| `gcp-secret-manager` | `secret-store` | Preferred. Needs `veil-mcp[gcp]`. `create`, `new-version`, `replace` (disables previous versions). |
| `env-file` | `local-plaintext` | Path-restricted, symlink-refusing, atomic `0600` write. Git-tracked files blocked by default. |
| `firestore` | `remote-application-storage` | Needs `veil-mcp[firestore]`. Always warns; always requires Stage B. |

`arbitrary-network` destinations (generic HTTP POST, webhooks) are **not implemented**, and
the adapter registry refuses to register one.

---

## Security assumptions and limitations

Stated plainly, because a security tool that oversells itself is worse than none:

- **The broker process sees the secret.** That is the point: something must, or storage is
  impossible. The guarantee is that only the minimal trusted transport and destination
  components do.
- **CPython cannot reliably erase memory.** `SecretBuffer` wipes the mutable buffer it owns,
  but percent-decoding, `str`/`bytes` conversions and provider SDKs create immutable copies
  the interpreter may keep until GC. Veil minimizes and does not fabricate this guarantee.
- **The UI is loopback HTTP.** Any process running as your user on your machine can reach
  it, and any such process could also imitate it. Each Veil process prints a random
  identity phrase that its pages display (anti-spoofing aid, not a cryptographic control).
  Withholding the link from the agent raises the bar; it does not stop a process that can
  read Veil's console output, list the browser's argv, or scan loopback ports.
- **Veil does not audit the destination.** If you authorize a credential into a Firestore
  document, Veil writes it there and tells you it is a bad idea; it does not stop you.
- **Timeouts are provider-level.** Veil cannot cancel a blocking SDK call from
  outside it, so each adapter passes an explicit timeout to the provider. A destination
  SDK that ignores its own timeout can still hold a request — and its secret — open.
- **Preflight is best-effort.** A provider that is unreachable at preflight is reported as
  unavailable rather than guessed at.
- **Crash semantics.** A crash between the provider write and the response can leave a
  credential written with no local record of success. Veil reports the request as failed;
  the destination is the source of truth.

---

## Local development

```bash
uv venv
uv pip install -e ".[dev]"

# run the server the way an MCP client would
uv run veil serve

# with optional providers
uv pip install -e ".[dev,gcp,firestore]"
```

Configuration is read from Veil's own environment — never from tool arguments:

| Variable | Default | Meaning |
| --- | --- | --- |
| `VEIL_REQUEST_TTL_SECONDS` | `300` | Request expiry. |
| `VEIL_ADAPTER_TIMEOUT_SECONDS` | `30` | Upper bound on one destination write. |
| `VEIL_STAGE_B_FOR_MEDIUM` | `true` | Require confirmation for medium-risk operations. |
| `VEIL_UI_HOST` / `VEIL_UI_PORT` | `127.0.0.1` / ephemeral | Secure UI bind address. |
| `VEIL_OPEN_BROWSER` | `true` | Open the authorization window automatically. |
| `VEIL_DISCLOSE_AUTHORIZATION_URL` | `false` | Return the authorization link to the agent. |
| `VEIL_ENV_ALLOWED_ROOTS` | current directory | Roots the `.env` adapter may write inside. |
| `VEIL_ALLOW_GIT_TRACKED_ENV` | `false` | Permit writing into a git-tracked env file. |
| `VEIL_ENABLED_ADAPTERS` | all | Comma-separated allowlist. |

### MCP client configuration

```json
{
  "mcpServers": {
    "veil": { "command": "uv", "args": ["run", "veil", "serve"] }
  }
}
```

## Tests

```bash
uv run pytest                  # everything
uv run pytest tests/security   # the adversarial suite only
uv run ruff check .
uv run mypy
```

The security suite is a product requirement, not a nicety. It contains canary-leakage
detection across every observable channel, malicious-agent tests, prompt-injection
fixtures, TOCTOU and replay tests, 100-way concurrency stress, race conditions, crash
paths, provider-failure simulation, UI checks and fuzzing. A release is blocked if any
canary leaks, any authorization bypass succeeds, any post-approval mutation succeeds, any
completed request is replayable, any secret crosses a request boundary, any raw provider
error reaches MCP, or any high-risk operation skips confirmation.

See [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) for the invariant-to-test map.


## Project status

Version 0.1.0, built to [`SPEC.md`](SPEC.md), which stays in the repository as the
authoritative description of the intended behaviour. Every substantial module and test
cites the section it implements, so a reviewer can check the code against the requirement
rather than against a summary of it.

The MVP is complete and the full suite — including the adversarial one — passes. What
remains before anyone should rely on it in anger: independent review, human-factor testing
of the confirmation UI (SPEC.md §35), and signed release artefacts (§43).

## Contributing

Security is the product here, so the bar for changes is specific rather than bureaucratic:

- A change that touches credential handling, authorization or the MCP surface needs a test
  that *attempts to break* the invariant it affects, not only one that shows it working.
- Never weaken a security test to make a suite pass. If a test reveals an architectural
  flaw, the architecture is what changes.
- New runtime dependencies in the core are opposed by default. The broker is the trusted
  computing base for credential material; provider SDKs belong behind an optional extra.
- Run `ruff check .`, `ruff format --check .`, `mypy` and `pytest` before opening a pull
  request.

Found a vulnerability? Please report it privately through GitHub's security advisories
rather than opening a public issue.

## License

[Apache License 2.0](LICENSE) © 2026 Eduardo Rosostolato.
