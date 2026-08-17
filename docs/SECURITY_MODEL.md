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
  └─▶ Handler._read_body / _form_value      bytearray, wiped after use
        └─▶ SecretBuffer                    owned by exactly one SecretRequest
              └─▶ adapter.store(...)        provider SDK / atomic file write
                    └─▶ destination
```

It is never placed in: a tool argument, a tool result, a log record, a URL, an argv, a
shell string, a global, a cache, or anything serialized.

## Defence in depth for leakage

| Layer | Code | What it catches |
| --- | --- | --- |
| No secret-shaped schema fields | `mcp_server/tools.py` | An agent trying to *send* a credential |
| Argument screen (names + value shapes) | `ToolRouter._screen_arguments` | Covert transport in unmodelled fields |
| Field allowlist for logs | `logging_.ALLOWED_AUDIT_FIELDS` | A careless call site logging the wrong thing |
| Credential-shape screen for log values | `redaction.looks_like_credential` | Recognisable credential text in an allowed field |
| Live-secret tripwire | `SecretBroker.contains_live_secret` | *Any* live secret in a log line, MCP frame or HTML page, in any encoding |
| Result and error scrubbing | `SecretBroker._scrub_result`, `_sanitize` | An adapter echoing the credential back |
| stdout reservation | `veil.__main__._serve` | A stray `print` contaminating the protocol stream |

## Traceability

### Confidentiality (SPEC.md §5, §6, §19–§24)

| Requirement | Implementation | Test |
| --- | --- | --- |
| SEC-001 no secret-value parameter | `tools.ToolRouter.list_tools`, closed schemas | `leakage/…::test_secret_never_enters_mcp_arguments` |
| SEC-002 no secret in MCP traffic | `MCPServer._write` tripwire | `leakage/…::test_secret_never_appears_in_any_observable_channel`, `test_mcp_protocol.py::test_outbound_frames_carrying_a_live_secret_are_blocked` |
| SEC-003 no secret in model-visible results | `StoreResult.as_public_dict`, `_scrub_result` | `provider_errors/…::test_provider_error_is_sanitized[LeakyResultAdapter]` |
| SEC-004/005 no secret in stdout/stderr | fd reservation, structured logging | `leakage/…`, `test_mcp_protocol.py::test_server_process_keeps_stdout_for_protocol_only` |
| SEC-006 no secret in logs, any level | `logging_.AuditLogger` | `leakage/…::test_secret_is_absent_from_logs_at_every_level`, `…::test_live_secret_in_a_log_record_is_suppressed_by_the_tripwire` |
| SEC-007 no secret in URLs | POST body only; PRG redirect | `ui/…::test_url_never_contains_credential_material_and_post_redirects` |
| SEC-008/009 no secret in argv or shell | `env_file._git_output` (paths only, `shell=False`), provider SDKs | `test_env_adapter.py::test_no_credential_ever_reaches_a_subprocess_argv`, `conftest.argv_recorder` |
| SEC-010 no temporary copies | `env_file._atomic_write` (0600, deterministic unlink) | `leakage/…::test_secret_reaches_only_the_approved_env_file`, `test_env_adapter.py::test_interrupted_write_leaves_the_original_intact` |
| §23 derived-canary search | `redaction.derivations` (shared by product and harness) | `leakage/…::test_canary_derivations_cover_required_encodings` |

### Authorization (SPEC.md §7–§12, §25)

| Requirement | Implementation | Test |
| --- | --- | --- |
| AUTH-001 display ≡ execution | one `AuthorizationSnapshot`; UI renders it, executor consumes it | `authorization/…::test_displayed_destination_is_the_executed_destination` (asserts object *identity*) |
| AUTH-002 destination mutation | frozen dataclasses + digest re-check + `revise` | `…::test_destination_mutation_invalidates_authorization`, `…::test_snapshot_is_frozen_and_tampering_aborts_execution` |
| AUTH-003 operation mutation | same | `…::test_operation_mutation_requires_new_confirmation` |
| AUTH-004 secret-name mutation | same | `…::test_secret_name_mutation_after_authorization_fails` |
| AUTH-005 adapter mutation | executor re-resolves the adapter by identity | `…::test_adapter_mutation_after_authorization_fails` |
| AUTH-006 high-risk double confirmation | `policy.evaluate_risk`, `_execute` precondition | `…::test_high_risk_operation_cannot_skip_stage_b` |
| AUTH-007/008 cancellation | `SecretBroker.cancel` → zeroize | `…::test_cancellation_at_stage_a_accepts_no_secret`, `…::test_cancellation_at_stage_b_discards_the_secret` |
| §10 agents cannot downgrade risk | monotonic escalation only | `…::test_agent_cannot_downgrade_risk_by_claiming_development` |
| §4.2 authorization is out of band | link goes to the browser, not to MCP | `authorization/test_out_of_band_authorization.py` |

### State machine, replay, concurrency (SPEC.md §14, §18.5–§18.7, §28–§31)

| Requirement | Implementation | Test |
| --- | --- | --- |
| Exact state graph | `model.ALLOWED_TRANSITIONS` | `test_core_types.py::test_state_machine_matches_the_specified_graph` |
| Terminal ⇒ non-reusable | `_finish`, `_require_state` | `replay/test_replay.py` (completed, cancelled, expired) |
| Unpredictable single-use ids | `ids.new_request_id`, `new_token` | `replay/…::test_request_ids_are_unpredictable` |
| Single-flight execution | `_claim_execution_locked` | `concurrency/test_races.py::test_double_submit_writes_exactly_once` |
| No cross-request secrets | secret owned by its request; no global table | `concurrency/test_concurrency.py` (100 canaries) |
| Deterministic races | one `RLock`, expiry checked on entry | `concurrency/test_races.py` |
| Crash safety | `install_crash_handler`, `shutdown` | `crash/test_crash_paths.py` (4 kill points, one via `SIGKILL`) |

### Errors, adapters, UI (SPEC.md §16, §20, §32–§34, §36)

| Requirement | Implementation | Test |
| --- | --- | --- |
| No raw provider errors | `adapter.sanitize_error` + broker fallback | `provider_errors/test_provider_errors.py` |
| Sanitizer failure suppresses | `_sanitize` catches everything | `…[RaisingSanitizerAdapter]` |
| Status-code mapping only | `GcpSecretManagerAdapter.sanitize_error` | `…::test_provider_status_codes_map_to_public_errors` |
| `arbitrary-network` disabled | `AdapterRegistry.register` refuses it | `malicious_agent/…::test_arbitrary_network_destination_cannot_be_registered` |
| `.env` symlink/traversal/git rules | `env_file` | `test_env_adapter.py` |
| UI headers, masking, PRG, expiry | `ui/render.security_headers`, `ui/server` | `ui/test_ui_security.py` |
| Hostile metadata rendering | `redaction.safe_display` + HTML escaping | `fuzz/test_fuzz_metadata.py` |

## Release-blocking rules (SPEC.md §38)

CI runs `pytest tests/security` on every push and pull request. There is no warning-only
mode: a canary leak, an authorization bypass, a post-approval mutation, a replay, a
cross-request secret, a raw provider error or a skipped high-risk confirmation fails the
build.

## Known limitations

See the README's "Security assumptions and limitations". The short version: the broker
process sees the credential, CPython cannot guarantee memory erasure, the loopback UI is
reachable by any process running as you, and Veil does not judge whether the destination
you approved was a good idea.
