# Veil — Implementation Plan

Derived directly from `SPEC.md`. Each slice lists the spec sections it implements, the
files it touches, and the invariant it protects. Slices are vertical: every one of them
ends with runnable tests.

## Runtime decisions

| Decision | Rationale | Spec |
| --- | --- | --- |
| Python 3.11+, `src/` layout, package `veil` | Spec's adapter interface is written in Python; `pytest tests/security` is the named test entrypoint | §15, §37 |
| **Zero runtime dependencies** for the core (stdlib JSON-RPC, stdlib `http.server` UI) | The broker is the trusted computing base; every dependency inside it is a supply-chain path to the credential | §42, §43 |
| Provider SDKs are *optional extras* (`veil-mcp[gcp]`, `[firestore]`) and are imported lazily inside their adapter | Keeps the TCB small for users who only need `.env`; SDKs preferred over shell wrappers | §42, SEC-008/009 |
| Adapter methods are `async` (as specified); the broker is synchronous and thread-safe, bridging with `asyncio.run` in the executor thread | Matches §15 verbatim while keeping the state machine's locking obvious rather than clever | §15 |
| MCP transport implemented in-tree | Makes SEC-002 ("capture complete MCP communication") a first-class, testable seam, and keeps an untrusted framework out of the secret's process | §24 |

## Slices

1. **Core domain types** — §5, §11, §12, §15
   `model.py`, `secret_buffer.py`, `errors.py`, `ids.py`, `redaction.py`.
   `NormalizedTarget` / `AuthorizationSnapshot` are frozen dataclasses with a canonical
   digest; `SecretBuffer` refuses `repr`, `str`, pickling, copying and JSON.
   *Invariant:* a secret cannot be stringified or serialized by accident.

2. **Structured logging + outbound guard** — §19, §18.8, §20
   `logging_.py`, `redaction.py`.
   Audit records are built from an explicit allowlist of safe field names. A tripwire
   checks every outbound string (log line, MCP frame, HTTP body) against every *live*
   secret and its encodings before it leaves the process.
   *Invariant:* Secret ∉ logs, Secret ∉ MCP traffic — enforced, not merely intended.

3. **Request state machine** — §14, §18.5, §18.6, §18.7, §29, §30
   `broker.py`.
   States exactly as specified; terminal states are permanently non-reusable; per-request
   unpredictable tokens; monotonic expiry; single-flight execution guard.
   *Invariant:* replay, TOCTOU and cross-request confusion fail closed.

4. **Immutable authorization snapshot** — §11, §12
   `model.py`, `broker.py`.
   The snapshot digest is recorded at authorization time and re-verified immediately
   before the adapter write. The UI renders *the same object* the executor consumes.
   *Invariant:* display destination ≡ execution destination.

5. **Policy / risk evaluation** — §10, §26.2
   `policy.py`.
   Risk only ever escalates. The agent-supplied `environment` is advisory; the
   server-derived environment wins when it is more severe.
   *Invariant:* agents cannot downgrade a risk classification.

6. **Adapter interface + registry** — §15, §16, §17
   `adapters/base.py`, `adapters/registry.py`.
   `arbitrary-network` is not implemented and cannot be registered.

7. **Secure input broker + UI** — §7, §8, §9, §34, §18.4
   `ui/`.
   Loopback-only HTTP, masked field, POST/redirect/GET, `no-store`, strict CSP,
   per-server identity phrase, untrusted metadata rendered through a control-character
   and bidi-safe escaper.

8. **MCP tool contract** — §6, §13, §18.3
   `mcp_server/`.
   `secret.store`, `secret.status`, `secret.cancel`, `secret.revise`,
   `secret.destinations`. Strict schemas (`additionalProperties: false`), a
   secret-shaped-field rejector, and a credential-shaped-value rejector.

9. **Adapters** — §16, §17, §33
   `.env` (local-plaintext), Google Secret Manager (secret-store),
   Firestore (remote-application-storage).

10. **Error sanitization** — §20, §32
    Every adapter failure passes through `sanitize_error`; failures of sanitization
    itself degrade to `INTERNAL_ERROR` with no detail.

11. **Security suite** — §21–§39
    `tests/security/{leakage,authorization,malicious_agent,prompt_injection,concurrency,replay,crash,provider_errors,ui,fuzz}`
    plus the canary harness.

12. **Docs + packaging** — §41, §42, §44
    README trust boundary, claims and non-claims, CI workflow running the security suite.
