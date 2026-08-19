# Veil security model and spec traceability

This document maps each invariant in `SPEC.md` to the code that enforces it and the test
that tries to break it. If you are reviewing Veil, this is the shortest path through it.

## The two guarantees

1. **Confidentiality.** The credential exists only inside the trusted boundary: the user's
   browser on loopback, the broker process, the selected adapter, and the destination.
2. **Authorization.** The exact operation a human approved — and no other — is what
   executes.

Everything below serves one of those two.

## Where the credential lives

```text
browser (POST body, loopback)
  └─▶ readBody / formValue          Buffers, wiped after use
        └─▶ SecretBuffer            owned by exactly one SecretRequest
              └─▶ adapter.store()   HTTPS request body / atomic file write
                    └─▶ destination
```

It is never placed in: a tool argument, a tool result, a log record, a URL, an argv, a
shell string, a global, a cache, or anything serialized.

## Defence in depth for leakage

| Layer | Code | What it catches |
| --- | --- | --- |
| No secret-shaped schema fields | `src/mcp/tools.ts` | An agent trying to *send* a credential |
| Argument screen (names + value shapes) | `ToolRouter.#screenArguments` | Covert transport in unmodelled fields |
| Field allowlist for logs | `logging.ALLOWED_AUDIT_FIELDS` | A careless call site logging the wrong thing |
| Credential-shape screen for log values | `redaction.looksLikeCredential` | Recognisable credential text in an allowed field |
| Live-secret tripwire | `SecretBroker.containsLiveSecret` | *Any* live secret in a log line, MCP frame or HTML page, in any encoding |
| Result and error scrubbing | `SecretBroker.#scrubResult`, `#sanitize` | An adapter echoing the credential back |
| stdout reservation | `src/index.ts` (`reserveStdout`) | A stray `console.log` or `process.stdout.write` contaminating the protocol stream |

## Traceability

### Confidentiality (SPEC.md §5, §6, §19–§24)

| Requirement | Implementation | Test |
| --- | --- | --- |
| SEC-001 no secret-value parameter | `ToolRouter.listTools`, closed schemas | `leakage` › *SEC-001: no tool schema permits credential content* |
| SEC-002 no secret in MCP traffic | `MCPServer.#write` tripwire | `leakage` › *SEC-002…SEC-008*, `mcpProtocol` › *blocks an outbound frame carrying a live secret* |
| SEC-003 no secret in model-visible results | `storeResultToPublic`, `#scrubResult` | `provider-errors` › *sanitizes an adapter that returns the secret in its result* |
| SEC-004/005 no secret in stdout/stderr | fd reservation, structured logging | `mcpProtocol` › *SEC-004: reserves stdout for the protocol alone* |
| SEC-006 no secret in logs, any level | `logging.AuditLogger` | `leakage` › *SEC-006* (both cases) |
| SEC-007 no secret in URLs | POST body only; PRG redirect | `ui` › *keeps the credential out of the URL and redirects after POST* |
| SEC-008/009 no secret in argv or shell | `envFile` git helper (paths only, no shell) and REST calls | `envAdapter` › *keeps the credential out of every spawned argv* |
| SEC-010 no temporary copies | `envFile.atomicWrite` (0600, deterministic unlink) | `leakage` › *SEC-010*, `envAdapter` › *interrupted write* |
| §23 derived-canary search | `redaction.derivations` (shared by product and harness) | `leakage` › *derivations cover the required encodings* |

### Authorization (SPEC.md §7–§12, §25)

| Requirement | Implementation | Test |
| --- | --- | --- |
| AUTH-001 display ≡ execution | one deep-frozen `AuthorizationSnapshot`; UI renders it, executor consumes it | `authorization` › *AUTH-001* (asserts object *identity*) |
| AUTH-002 destination mutation | `deepFreeze` + digest re-check + `revise` | `authorization` › *AUTH-002* (both cases) |
| AUTH-003 operation mutation | same | `authorization` › *AUTH-003* |
| AUTH-004 secret-name mutation | same | `authorization` › *AUTH-004* |
| AUTH-005 adapter mutation | executor re-resolves the adapter by identity | `authorization` › *AUTH-005* |
| AUTH-006 high-risk double confirmation | `policy.evaluateRisk`, `#execute` precondition | `authorization` › *AUTH-006* |
| AUTH-007/008 cancellation | `SecretBroker.cancel` → zeroize | `authorization` › *AUTH-007*, *AUTH-008* |
| §10 agents cannot downgrade risk | monotonic escalation only | `authorization` › *§10 an agent cannot downgrade risk* |
| §4.2 authorization is out of band | link goes to the browser, not to MCP | `test/security/authorization/out-of-band.test.ts` |

### State machine, replay, concurrency (SPEC.md §14, §18.5–§18.7, §28–§31)

| Requirement | Implementation | Test |
| --- | --- | --- |
| Exact state graph | `model.ALLOWED_TRANSITIONS` | `coreTypes` › *matches the specified state graph* |
| Terminal ⇒ non-reusable | `#finish`, `#requireState` | `test/security/replay/replay.test.ts` (completed, cancelled, expired) |
| Unpredictable single-use ids | `ids.newRequestId`, `newToken` | `replay` › *request ids are unpredictable and unique* |
| Single-flight execution | `#claimExecution` | `races` › *a double submit writes exactly once* |
| No cross-request secrets | secret owned by its request; no global table | `test/security/concurrency/concurrency.test.ts` (100 canaries) |
| Deterministic races | no locks (single-threaded event loop); every check-then-act runs without an intervening `await` | `test/security/concurrency/races.test.ts` |
| Crash safety | `installCrashHandler`, `shutdown` | `test/security/crash/crash.test.ts` (4 kill points, one a real `SIGKILL`) |

### Errors, adapters, UI (SPEC.md §16, §20, §32–§34, §36)

| Requirement | Implementation | Test |
| --- | --- | --- |
| No raw provider errors | `adapter.sanitizeError` + broker fallback | `test/security/provider-errors/provider-errors.test.ts` |
| Sanitizer failure suppresses | `#sanitize` catches everything | `provider-errors` › *throws inside its sanitizer* |
| Status-code mapping only | `GcpSecretManagerAdapter.sanitizeError` | `provider-errors` › *maps provider status N* |
| `arbitrary-network` disabled | `AdapterRegistry.register` refuses it | `malicious-agent` › *§16 cannot even be registered* |
| `.env` symlink/traversal/git rules | `src/adapters/envFile.ts` | `test/envAdapter.test.ts` |
| UI headers, masking, PRG, expiry | `ui/render.securityHeaders`, `ui/server` | `test/security/ui/ui.test.ts` |
| Hostile metadata rendering | `redaction.safeDisplay` + HTML escaping | `test/security/fuzz/fuzz.test.ts` |

## Release-blocking rules (SPEC.md §38)

CI runs `npm run test:security` on every push and pull request. There is no warning-only
mode: a canary leak, an authorization bypass, a post-approval mutation, a replay, a
cross-request secret, a raw provider error or a skipped high-risk confirmation fails the
build.

## Implementation notes worth knowing

- **Why not the official MCP SDK?** It pulls ~90 packages, including Express, Hono, Jose
  and an OAuth stack, none of which a stdio server uses. The protocol is implemented in
  `src/mcp/server.ts` instead, and `test/mcpProtocol.test.ts` pins the wire behaviour.
- **Why not elicitation?** The spec-native way to collect input mid-tool returns the value
  through the MCP protocol and into the model's context — precisely the disclosure Veil
  exists to prevent. The out-of-band browser window is the point, not a workaround.
- **Tool names use underscores** (`secret_store`, not `secret.store` as SPEC.md §13 writes
  it) because several MCP clients constrain tool names to `[a-zA-Z0-9_-]`. The contract is
  otherwise the one the spec describes.

## Known limitations

See the README's "Security assumptions and limitations". The short version: the broker
process sees the credential, V8 cannot guarantee memory erasure, the loopback UI is
reachable by any process running as you, and Veil does not judge whether the destination
you approved was a good idea.
