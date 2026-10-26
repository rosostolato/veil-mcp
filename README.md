# Veil

**Let your AI agent set up API keys without ever seeing them.**

[![CI](https://github.com/rosostolato/veil-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rosostolato/veil-mcp/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node 20+](https://img.shields.io/badge/node-20%2B-blue.svg)](https://nodejs.org/)

You ask Claude, Cursor or any MCP client to *"put the Stripe key in Secret Manager"*. The
agent works out **where** it goes. You paste the value into Veil's own window. The key goes
straight to the destination and never enters the chat, the prompt or the logs.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/paste-dark.png">
    <img src="docs/images/paste-light.png" width="420" alt="Veil's window: a red PRODUCTION band, 'Paste STRIPE_SECRET_KEY', the destination Google Secret Manager › acme-prod › stripe-secret-key, a masked field and a Continue button">
  </picture>
</p>

1. **The agent asks.** It calls `secret_store` with the destination. The tool has no field
   that could carry a value.
2. **You paste.** Veil opens a local window that shows where the key goes and checks its
   format.
3. **Veil writes it.** The agent only learns `STORED` and a reference. It never sees the key.

```bash
claude mcp add veil -e VEIL_ENV_ALLOWED_ROOTS="$PWD" -- npx -y veil-mcp serve
```

Then ask your agent: *"store my Stripe test key in .env"*.

---

## Install

Veil is a stdio MCP server, so you do not run it yourself — your MCP client starts it, the
same way it starts any other npm-published server. Requires Node 20+.

### Claude Code

```bash
cd ~/some/project
claude mcp add veil -e VEIL_ENV_ALLOWED_ROOTS="$PWD" -- npx -y veil-mcp serve
```

Add `-s project` to record it in the repository's `.mcp.json` instead of your own config.

### Any other client (Claude Desktop, Cursor, Windsurf, VS Code, Zed…)

Drop this into the client's MCP configuration — the `mcpServers` block is the same shape
everywhere:

```json
{
  "mcpServers": {
    "veil": {
      "command": "npx",
      "args": ["-y", "veil-mcp", "serve"],
      "env": {
        "VEIL_ENV_ALLOWED_ROOTS": "/absolute/path/to/your/project"
      }
    }
  }
}
```

Prefer a pinned install to an ephemeral one:

```bash
npm install -g veil-mcp
# then use `veil-mcp serve` as the command, with no npx
```

**Set `VEIL_ENV_ALLOWED_ROOTS`.** The `.env` adapter refuses to write outside those
directories, and it defaults only to the server's working directory. Everything else is
optional — see [Configuration](#configuration).

Google Secret Manager and Firestore need application default credentials
(`gcloud auth application-default login`) and the optional `google-auth-library` package,
which npm installs by default. Veil reports `ADAPTER_UNAVAILABLE` when either is missing.

### First run

Ask your agent for something like *"store my Stripe test key in .env"*. Veil opens its
window on your machine; the agent does not receive that link. The band at the top tells you
the environment at a glance, and the field tells you whether the key looks right before you
send it.

<table>
  <tr>
    <td width="33%" valign="top">
      <picture>
        <source media="(prefers-color-scheme: dark)" srcset="docs/images/warning-dark.png">
        <img src="docs/images/warning-light.png" alt="A test key pasted for a production destination: 'Looks like a test key, but this goes to production.'">
      </picture>
      <p><strong>Catches the wrong key.</strong> A <code>test</code> key headed for
      production gets flagged in the window. The check runs locally and never shows the
      value.</p>
    </td>
    <td width="33%" valign="top">
      <picture>
        <source media="(prefers-color-scheme: dark)" srcset="docs/images/confirm-dark.png">
        <img src="docs/images/confirm-light.png" alt="Second step: 'Save to production?' with a field where acme-prod has been typed">
      </picture>
      <p><strong>Confirms risky writes.</strong> For production or overwrites, nothing is
      written until you type the project name.</p>
    </td>
    <td width="33%" valign="top">
      <picture>
        <source media="(prefers-color-scheme: dark)" srcset="docs/images/saved-dark.png">
        <img src="docs/images/saved-light.png" alt="'Saved' with the destination and the reference projects/acme-prod/secrets/stripe-secret-key/versions/4">
      </picture>
      <p><strong>Tells the agent only "stored".</strong> Veil wipes the value and hands back
      a reference such as the new version.</p>
    </td>
  </tr>
</table>

<kbd>Enter</kbd> continues and <kbd>Esc</kbd> cancels. The link works once: if anything
opened it before your browser did, Veil shows an alarm and a Cancel button instead of the
request. Veil's stderr carries structured audit JSON; nothing else is expected of you in the
terminal.

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

Veil's runtime dependency list is one package (`zod`, for input validation) plus an
optional `google-auth-library` used only when a cloud destination is selected. The MCP
protocol is implemented in-tree rather than through the official SDK, which would add ~90
packages — including HTTP servers and an OAuth stack — to a process that holds plaintext
credentials.

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
and opens its own authorization window on your machine. The agent polls `secret_status`.

**The agent does not get the authorization link.** That link is a capability: anything
holding it can complete the human's half of the flow, and an agent with a shell or an HTTP
tool is precisely the threat model. Veil hands it straight to your browser. Set
`VEIL_DISCLOSE_AUTHORIZATION_URL=true` if your setup needs the agent to relay the link (for
example, a remote or headless session) — and understand that this lets a compromised agent
authorize its own request.

**The link works once.** Opening it trades it for an `HttpOnly; SameSite=Lax` session cookie
scoped to that request and redirects to an address with no token in it; every later page and
form needs the cookie. A second opening of the same link gets an alarm page ("This link was
already opened") with a Cancel button, never the request. So a copy left in browser history,
a process list or a log is dead once you open it, and one used by someone else first is
visible to you.

**Logs never hold the identity phrase, and hold the link only as a last resort.** MCP hosts
save server stderr to files any process running as you can read (Claude Desktop under
`~/Library/Logs/Claude/`, Claude Code under its cache directory), so the audit record carries
a short fingerprint of the link instead. The full link is logged only when no browser could
be opened (`VEIL_OPEN_BROWSER=false`, too many windows, or the opener failed), because the
operator then has no other way in.

| Tool | Purpose |
| --- | --- |
| `secret_store` | Create a credential request. Returns non-sensitive metadata and a request id. |
| `secret_status` | Poll a request. Never returns credential material. |
| `secret_cancel` | Cancel a pending request; any entered value is destroyed. |
| `secret_revise` | Invalidate an authorization and start a new one. Nothing is edited in place. |
| `secret_destinations` | List destinations and the target fields each expects. |

### What the human sees

Stage A shows the credential name, the destination path and the environment and risk
**before** the value is entered; operation, warnings and the agent's description sit under
"Details". High-risk operations (production overwrite, plaintext storage, application
databases, replacing a credential) require a second confirmation in Stage B, after entry and
before the write: the human types the project name (for a local file, `path:KEY`, such as
`.env:API_TOKEN`), and the server checks it. This is an attention check, not
authentication: the expected text is on the page, and it is whatever the agent chose. What
keeps a second party out of Stage B is the session cookie. The value is never displayed back.

POSTs are refused unless they come from Veil's own page (`Origin` and `Sec-Fetch-Site`), and
every response sets `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy` to
`same-origin`. The credential field asks browser and third-party password managers not to
save it.

The page runs one inline script under a per-response CSP nonce. It describes the value's
shape (length, a `live`/`test` marker against the destination's environment, stray
whitespace), counts down the expiry and maps <kbd>Esc</kbd> to Cancel. The CSP gives it no
network access, and Cancel is a separate form, so cancelling never sends the value. Without
JavaScript the page still works, minus those three aids.

The page the human reads and the operation the executor performs are the *same immutable
object* — there is no separate "display destination". Any change to destination, project,
secret name, operation, write mode or adapter invalidates the authorization and requires a
new one.

---

## Supported adapters

| Adapter | Class | Notes |
| --- | --- | --- |
| `gcp-secret-manager` | `secret-store` | Preferred. `create`, `new-version`, `replace` (disables previous versions). |
| `env-file` | `local-plaintext` | Only `.env` / `.env.<suffix>` names, inside allowed roots. Symlink-refusing, atomic `0600` write. Git-tracked files blocked, and a new file must be git-ignored. |
| `firestore` | `remote-application-storage` | Always warns; always requires Stage B. |

`arbitrary-network` destinations (generic HTTP POST, webhooks) are **not implemented**, and
the adapter registry refuses to register one.

---

## Security assumptions and limitations

Stated plainly, because a security tool that oversells itself is worse than none:

- **The broker process sees the secret.** That is the point: something must, or storage is
  impossible. The guarantee is that only the minimal trusted transport and destination
  components do.
- **Memory erasure is best-effort.** `SecretBuffer` wipes the exact `Buffer` it owns, and
  the HTTP body is percent-decoded into buffers Veil wipes too. But any conversion to a
  JavaScript string — which writing a `.env` line requires — creates an immutable copy that
  V8 may keep until garbage collection, and that copy cannot be wiped. Veil minimizes those
  conversions rather than pretending they do not happen.
- **The UI is loopback HTTP.** Any process running as your user on your machine can reach
  it, and any such process could also imitate it. Veil refuses to bind anywhere but
  loopback. Request pages show a per-process identity phrase, but it is no longer logged,
  so today there is no second channel to compare it against: treat it as decoration, not
  as anti-spoofing. Withholding the link and making it single-use raise the bar; they do
  not stop a process that wins the race to the link, reads the browser's memory, or binds
  its own lookalike port.
- **An agent with an unrestricted shell is out of reach.** Running as you, it can read
  files Veil writes (including a `.env` destination), browser state and MCP logs. No page
  design fixes that. Run the agent sandboxed — for example Claude Code's sandboxed Bash,
  with loopback and the MCP log directories outside what it may reach.
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
git clone https://github.com/rosostolato/veil-mcp && cd veil-mcp
npm install
npm run check      # typecheck + lint + format + tests
npm run build
```

To point a client at your checkout, use `node /path/to/veil-mcp/dist/index.js` as the
command instead of `npx`.

## Configuration

Configuration is read from Veil's own environment — never from tool arguments, so an agent
cannot relax a policy:

| Variable | Default | Meaning |
| --- | --- | --- |
| `VEIL_REQUEST_TTL_SECONDS` | `300` | Request expiry. |
| `VEIL_ADAPTER_TIMEOUT_SECONDS` | `30` | Upper bound on one destination write. |
| `VEIL_STAGE_B_FOR_MEDIUM` | `true` | Require confirmation for medium-risk operations. |
| `VEIL_UI_HOST` / `VEIL_UI_PORT` | `127.0.0.1` / ephemeral | Secure UI bind address. Loopback only; anything else refuses to start. |
| `VEIL_OPEN_BROWSER` | `true` | Open the authorization window automatically. |
| `VEIL_DISCLOSE_AUTHORIZATION_URL` | `false` | Return the authorization link to the agent. |
| `VEIL_ENV_ALLOWED_ROOTS` | current directory | Roots the `.env` adapter may write inside. |
| `VEIL_ALLOW_GIT_TRACKED_ENV` | `false` | Permit writing into a git-tracked, or new and un-ignored, env file. |
| `VEIL_ENV_ALLOW_ANY_FILENAME` | `false` | Permit file names other than `.env` / `.env.<suffix>`. |
| `VEIL_ENABLED_ADAPTERS` | all | Comma-separated allowlist. |

## Tests

```bash
npm test                # everything
npm run test:security   # the adversarial suite only
npm run check           # what CI runs
```

The security suite is a product requirement, not a nicety. It contains canary-leakage
detection across every observable channel, malicious-agent tests, prompt-injection
fixtures, TOCTOU and replay tests, 100-way concurrency stress, race conditions, crash
paths (including a real `SIGKILL` mid-write), provider-failure simulation, UI checks and
fuzzing. A release is blocked if any canary leaks, any authorization bypass succeeds, any
post-approval mutation succeeds, any completed request is replayable, any secret crosses a
request boundary, any raw provider error reaches MCP, or any high-risk operation skips
confirmation.

See [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) for the invariant-to-test map.

## Project status

Version 0.1.0, built to [`SPEC.md`](SPEC.md), which stays in the repository as the
authoritative description of the intended behaviour. The implementation is TypeScript on
Node; it was ported from an equivalent Python implementation, which remains in the git
history. Every substantial module and test
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
- Run `npm run check` before opening a pull request.

Found a vulnerability? Please report it privately through GitHub's security advisories
rather than opening a public issue.

## License

[Apache License 2.0](LICENSE) © 2026 Eduardo Rosostolato.
