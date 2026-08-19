# Veil — Implementation Plan

> **Status:** delivered. Originally executed in Python; the implementation was later ported
> to TypeScript so the server installs the way MCP clients expect (`npx -y veil-mcp`). The
> slices and invariants below still describe the shipped design — only the runtime table
> changed.

Derived directly from `SPEC.md`. Each slice lists the spec sections it implements, the
files it touches, and the invariant it protects. Slices are vertical: every one of them
ends with runnable tests.

## Runtime decisions

| Decision | Rationale | Spec |
| --- | --- | --- |
| TypeScript on Node 20+, ESM, published to npm as `veil-mcp` | `npx -y <server>` is how MCP clients install a server; the spec's Python interface maps one-to-one onto the TypeScript classes | §15, §37 |
| **One runtime dependency** (`zod`), plus optional `google-auth-library` | The broker is the trusted computing base; every dependency inside it is a supply-chain path to the credential. The official MCP SDK would add ~90 packages including Express, Hono and an OAuth stack | §42, §43 |
| Google destinations use the REST APIs plus lazily-imported ADC, not the full client libraries | Keeps the TCB small for users who only need `.env`; still no shell wrappers, and the credential travels in a request body | §42, SEC-008/009 |
| Adapter methods are `async` (as specified); the broker needs no locks because Node is single-threaded, and every check-then-act on request state runs without an intervening `await` | Matches §15 while removing a whole class of race conditions | §15 |
| MCP transport implemented in-tree | Makes SEC-002 ("capture complete MCP communication") a first-class, testable seam, and keeps an untrusted framework out of the secret's process | §24 |

## Slices

1. **Core domain types** — §5, §11, §12, §15
   `model.ts`, `secretBuffer.ts`, `errors.ts`, `ids.ts`, `redaction.ts`.
   `NormalizedTarget` / `AuthorizationSnapshot` are deep-frozen objects with a canonical
   digest; `SecretBuffer` refuses stringification and JSON, and wipes its own bytes.
   *Invariant:* a secret cannot be stringified or serialized by accident.

2. **Structured logging + outbound guard** — §19, §18.8, §20
   `logging.ts`, `redaction.ts`.
   Audit records are built from an explicit allowlist of safe field names. A tripwire
   checks every outbound string (log line, MCP frame, HTTP body) against every *live*
   secret and its encodings before it leaves the process.
   *Invariant:* Secret ∉ logs, Secret ∉ MCP traffic — enforced, not merely intended.

3. **Request state machine** — §14, §18.5, §18.6, §18.7, §29, §30
   `broker.ts`.
   States exactly as specified; terminal states are permanently non-reusable; per-request
   unpredictable tokens; monotonic expiry; single-flight execution guard.
   *Invariant:* replay, TOCTOU and cross-request confusion fail closed.

4. **Immutable authorization snapshot** — §11, §12
   `model.ts`, `broker.ts`.
   The snapshot digest is recorded at authorization time and re-verified immediately
   before the adapter write. The UI renders *the same object* the executor consumes.
   *Invariant:* display destination ≡ execution destination.

5. **Policy / risk evaluation** — §10, §26.2
   `policy.ts`.
   Risk only ever escalates. The agent-supplied `environment` is advisory; the
   server-derived environment wins when it is more severe.
   *Invariant:* agents cannot downgrade a risk classification.

6. **Adapter interface + registry** — §15, §16, §17
   `adapters/base.ts`, `adapters/registry.ts`.
   `arbitrary-network` is not implemented and cannot be registered.

7. **Secure input broker + UI** — §7, §8, §9, §34, §18.4
   `ui/`.
   Loopback-only HTTP, masked field, POST/redirect/GET, `no-store`, strict CSP,
   per-server identity phrase, untrusted metadata rendered through a control-character
   and bidi-safe escaper.

8. **MCP tool contract** — §6, §13, §18.3
   `mcp/`.
   `secret_store`, `secret_status`, `secret_cancel`, `secret_revise`,
   `secret_destinations`. Strict zod-backed schemas (`additionalProperties: false`), a
   secret-shaped-field rejector, and a credential-shaped-value rejector.

9. **Adapters** — §16, §17, §33
   `.env` (local-plaintext), Google Secret Manager (secret-store),
   Firestore (remote-application-storage).

10. **Error sanitization** — §20, §32
    Every adapter failure passes through `sanitizeError`; failures of sanitization
    itself degrade to `INTERNAL_ERROR` with no detail.

11. **Security suite** — §21–§39
    `test/security/{leakage,authorization,malicious-agent,prompt-injection,concurrency,replay,crash,provider-errors,ui,fuzz}`
    plus the canary harness.

12. **Docs + packaging** — §41, §42, §44
    README trust boundary, claims and non-claims, CI workflow running the security suite,
    and a packaging job that installs the tarball and starts the binary the way a user
    would — the one failure mode unit tests cannot see.
