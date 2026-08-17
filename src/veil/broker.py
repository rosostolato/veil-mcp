"""The secure input broker: state machine, custody and execution.

Implements SPEC.md §11 (immutable authorization snapshot), §12 (destination
integrity), §14 (state machine), §18.5–§18.7 (TOCTOU, replay, cross-request
confusion), §20 (error sanitization) and §29–§30 (races and replay).

Threading model
---------------
One re-entrant lock guards all request state. Adapter I/O happens *outside* the
lock, in the thread that legitimately claimed the ``EXECUTING`` transition, so a
slow provider cannot stall cancellation of other requests. Adapters are async
(SPEC.md §15); the executor bridges with ``asyncio.run`` in its own thread.

Secret custody
--------------
A ``SecretBuffer`` lives in exactly one ``SecretRequest`` and is reachable only
through it. There is no global secret table, no cache and no copy: a secret
submitted for request A is structurally incapable of reaching request B.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from veil.adapters.base import AdapterError, SecretDestinationAdapter
from veil.adapters.registry import AdapterRegistry
from veil.config import VeilConfig
from veil.errors import INTERNAL_ERROR, ErrorCode, PublicError, VeilError, veil_error
from veil.ids import new_request_id, new_token, token_equals
from veil.logging_ import AuditLogger, get_logger
from veil.model import (
    ALLOWED_TRANSITIONS,
    AuthorizationSnapshot,
    Environment,
    NormalizedTarget,
    RequestState,
    RiskAssessment,
    RiskLevel,
    StoreResult,
    WriteMode,
)
from veil.policy import evaluate_risk
from veil.redaction import safe_display
from veil.secret_buffer import MAX_SECRET_BYTES, SecretBuffer

MAX_NAME_LENGTH = 128
MAX_DESCRIPTION_LENGTH = 512
MAX_TARGET_FIELDS = 12
MAX_TARGET_VALUE_LENGTH = 1024
TERMINAL_HISTORY_LIMIT = 512


@dataclass(frozen=True, slots=True)
class StoreRequestParams:
    """Validated, non-secret parameters of a ``secret.store`` call (SPEC.md §13)."""

    destination: str
    name: str
    target: tuple[tuple[str, Any], ...]
    write_mode: WriteMode
    environment: Environment
    description: str | None = None

    @property
    def target_mapping(self) -> dict[str, Any]:
        return dict(self.target)


class SecretRequest:
    """Server-side state for one credential request.

    ``snapshot`` is frozen at creation time; ``authorized_digest`` is the digest
    the human was shown. Execution recomputes the digest and refuses to proceed
    on any divergence.
    """

    __slots__ = (
        "adapter",
        "authorized_digest",
        "confirm_token",
        "confirmation",
        "created_at",
        "error",
        "execution_claimed",
        "expires_at",
        "params",
        "request_id",
        "result",
        "secret",
        "snapshot",
        "state",
        "submit_token",
        "superseded_by",
        "terminal_event",
    )

    def __init__(
        self,
        *,
        request_id: str,
        params: StoreRequestParams,
        adapter: SecretDestinationAdapter,
        snapshot: AuthorizationSnapshot,
        created_at: float,
        expires_at: float,
    ) -> None:
        self.request_id = request_id
        self.params = params
        self.adapter = adapter
        self.snapshot = snapshot
        self.authorized_digest = snapshot.digest
        self.created_at = created_at
        self.expires_at = expires_at
        self.state = RequestState.CREATED
        self.submit_token = new_token()
        self.confirm_token = new_token()
        self.secret: SecretBuffer | None = None
        self.result: StoreResult | None = None
        self.error: PublicError | None = None
        self.confirmation: str = "none"
        self.superseded_by: str | None = None
        self.execution_claimed = False
        self.terminal_event = threading.Event()

    # -- introspection -----------------------------------------------------

    @property
    def requires_stage_b(self) -> bool:
        return self.snapshot.risk.requires_stage_b

    def public_status(self, *, authorization_url: str | None = None) -> dict[str, Any]:
        data: dict[str, Any] = {
            "request_id": self.request_id,
            "state": str(self.state),
            "operation": str(self.snapshot.operation),
            "credential": safe_display(self.snapshot.logical_name),
            "destination": self.snapshot.target.as_public_dict(),
            "risk": self.snapshot.risk.as_public_dict(),
            "requires_confirmation": self.requires_stage_b,
            "authorization_digest": self.authorized_digest,
            "terminal": self.state.is_terminal,
        }
        if authorization_url and not self.state.is_terminal:
            data["authorization_url"] = authorization_url
        if self.superseded_by:
            data["superseded_by"] = self.superseded_by
        if self.result is not None:
            data["result"] = self.result.as_public_dict()
        if self.error is not None:
            data["error"] = self.error.to_dict()
        return data

    def __repr__(self) -> str:  # never leak custody details
        return f"<SecretRequest {self.request_id} {self.state}>"


class SecretBroker:
    def __init__(
        self,
        config: VeilConfig,
        registry: AdapterRegistry,
        *,
        logger: AuditLogger | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self.registry = registry
        self.log = logger or get_logger()
        self._clock = clock
        self._lock = threading.RLock()
        self._active: dict[str, SecretRequest] = {}
        self._history: OrderedDict[str, SecretRequest] = OrderedDict()
        self._ui_base_url: str | None = None
        self._notifier: Callable[[str, str], None] | None = None
        self.log.set_tripwire(self.contains_live_secret)

    # -- UI wiring ---------------------------------------------------------

    def set_ui_base_url(self, base_url: str | None) -> None:
        with self._lock:
            self._ui_base_url = base_url.rstrip("/") if base_url else None

    def set_authorization_notifier(self, notifier: Callable[[str, str], None] | None) -> None:
        """Register who presents a new request to the human (the UI).

        The notifier receives ``(request_id, url)``. It is how the authorization
        window reaches the *person* without the URL passing through the agent.
        """

        with self._lock:
            self._notifier = notifier

    def authorization_url(self, request: SecretRequest) -> str | None:
        base = self._ui_base_url
        if not base or request.state.is_terminal:
            return None
        return f"{base}/r/{request.request_id}/{request.submit_token}"

    def disclosable_authorization_url(self, request: SecretRequest) -> str | None:
        """The URL as the *agent* may see it — normally not at all.

        The link is a capability: anything holding it can complete Stage A. An
        agent with a shell or an HTTP tool could therefore authorize its own
        request, so by default Veil hands the link to the human's browser and
        gives the agent only a request id (SPEC.md §4.2, §7).
        """

        if not self.config.disclose_authorization_url:
            return None
        return self.authorization_url(request)

    # -- creation ----------------------------------------------------------

    def create_request(self, params: StoreRequestParams) -> SecretRequest:
        adapter = self.registry.get(params.destination)
        if params.write_mode not in adapter.supported_write_modes():
            raise veil_error(
                ErrorCode.INVALID_ARGUMENTS,
                "The destination does not support the requested write mode.",
            )

        target = self._adapter_call(
            adapter.normalize_target(
                params.target_mapping,
                name=params.name,
                environment_hint=params.environment,
            ),
            fallback_code=ErrorCode.INVALID_TARGET,
            fallback_message="The destination target could not be interpreted.",
        )
        if target.adapter_id != adapter.id:
            raise veil_error(
                ErrorCode.INVALID_TARGET,
                "The destination adapter produced an inconsistent target.",
            )

        validation = self._adapter_call(
            adapter.validate_target(target),
            fallback_code=ErrorCode.INVALID_TARGET,
            fallback_message="The destination target could not be validated.",
        )
        if not validation.ok:
            raise veil_error(
                validation.code or ErrorCode.INVALID_TARGET,
                validation.message or "The destination target is not valid.",
            )

        preflight = self._adapter_call(
            adapter.preflight(target),
            fallback_code=ErrorCode.PREFLIGHT_FAILED,
            fallback_message="The destination could not be prepared.",
        )
        if not preflight.ok:
            raise veil_error(
                preflight.code or ErrorCode.PREFLIGHT_FAILED,
                preflight.message or "The destination could not be prepared.",
            )

        adapter_risk = self._adapter_call(
            adapter.calculate_risk(target, params.write_mode, exists=preflight.exists),
            fallback_code=ErrorCode.PREFLIGHT_FAILED,
            fallback_message="The destination could not be classified.",
        )
        risk = evaluate_risk(
            self.config,
            adapter_assessment=adapter_risk,
            adapter_floor=adapter.risk_class,
            target=target,
            operation=params.write_mode,
            claimed_environment=params.environment,
            exists=preflight.exists,
        )

        now = self._clock()
        request_id = new_request_id()
        snapshot = AuthorizationSnapshot(
            request_id=request_id,
            logical_name=params.name,
            target=target,
            operation=params.write_mode,
            risk=risk,
            created_at=now,
            expires_at=now + self.config.request_ttl_seconds,
            description=params.description,
            exists_at_preflight=preflight.exists,
        )
        request = SecretRequest(
            request_id=request_id,
            params=params,
            adapter=adapter,
            snapshot=snapshot,
            created_at=now,
            expires_at=snapshot.expires_at,
        )

        with self._lock:
            self._sweep_expired_locked()
            if len(self._active) >= self.config.max_active_requests:
                raise veil_error(
                    ErrorCode.TOO_MANY_REQUESTS,
                    "Too many credential requests are already pending.",
                )
            self._active[request_id] = request
            self._transition(request, RequestState.PREFLIGHT)
            self._transition(request, RequestState.AWAITING_SECRET_AUTHORIZATION)

        self.log.event(
            "request_created",
            request_id=request_id,
            adapter=adapter.id,
            destination=str(target.destination_class),
            logical_name=safe_display(params.name, max_length=80),
            environment=str(target.environment),
            operation=str(params.write_mode),
            risk=str(risk.level),
            stage=("A+B" if risk.requires_stage_b else "A"),
            authorization_digest=snapshot.digest,
        )
        self._notify(request)
        return request

    def _notify(self, request: SecretRequest) -> None:
        with self._lock:
            notifier = self._notifier
            url = self.authorization_url(request)
        if notifier is None or url is None:
            return
        try:
            notifier(request.request_id, url)
        except Exception:
            self.log.error("authorization_notify_failed", request_id=request.request_id)

    # -- lookup ------------------------------------------------------------

    def get(self, request_id: object) -> SecretRequest:
        if not isinstance(request_id, str):
            raise veil_error(ErrorCode.REQUEST_NOT_FOUND, "Unknown credential request.")
        with self._lock:
            request = self._active.get(request_id) or self._history.get(request_id)
            if request is None:
                raise veil_error(ErrorCode.REQUEST_NOT_FOUND, "Unknown credential request.")
            self._check_expiry_locked(request)
            return request

    def public_status(self, request_id: object) -> dict[str, Any]:
        request = self.get(request_id)
        with self._lock:
            status = request.public_status(
                authorization_url=self.disclosable_authorization_url(request)
            )
        if "authorization_url" not in status and not request.state.is_terminal:
            status["authorization"] = (
                "Veil has opened its own window on the user's machine. Ask the user to "
                "complete it there; the link is deliberately not shared with you."
            )
        return status

    def active_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._active)

    # -- stage A -----------------------------------------------------------

    def submit_secret(self, request_id: object, token: str, raw: bytes | bytearray) -> None:
        """Accept credential bytes for exactly one request (SPEC.md §18.7)."""

        buffer: SecretBuffer | None = None
        try:
            if not raw:
                raise veil_error(ErrorCode.EMPTY_SECRET, "No credential value was provided.")
            if len(raw) > MAX_SECRET_BYTES:
                raise veil_error(ErrorCode.SECRET_TOO_LARGE, "The credential value is too large.")
            buffer = SecretBuffer(raw)

            with self._lock:
                request = self.get(request_id)
                self._require_state(request, RequestState.AWAITING_SECRET_AUTHORIZATION)
                self._require_token(request, request.submit_token, token, stage="A")
                request.secret = buffer
                buffer = None  # ownership transferred to the request
                self._transition(request, RequestState.SECRET_RECEIVED)
                request.confirmation = "implicit"
                self.log.event(
                    "secret_received",
                    request_id=request.request_id,
                    stage="A",
                    risk=str(request.snapshot.risk.level),
                )
                if request.requires_stage_b:
                    self._transition(request, RequestState.AWAITING_EXECUTION_CONFIRMATION)
                    self.log.event(
                        "stage_b_required",
                        request_id=request.request_id,
                        risk=str(request.snapshot.risk.level),
                    )
                    return
                claimed = self._claim_execution_locked(request)
            if claimed:
                self._execute(request)
        finally:
            if buffer is not None:
                buffer.zeroize()
            if isinstance(raw, bytearray):
                raw[:] = b"\x00" * len(raw)

    # -- stage B -----------------------------------------------------------

    def confirm_execution(self, request_id: object, token: str) -> None:
        with self._lock:
            request = self.get(request_id)
            self._require_state(request, RequestState.AWAITING_EXECUTION_CONFIRMATION)
            self._require_token(request, request.confirm_token, token, stage="B")
            request.confirmation = "explicit"
            self.log.event(
                "execution_confirmed",
                request_id=request.request_id,
                stage="B",
                confirmation="explicit",
            )
            claimed = self._claim_execution_locked(request)
        if claimed:
            self._execute(request)

    # -- cancellation / revision ------------------------------------------

    def cancel(self, request_id: object, *, token: str | None = None, reason: str = "user") -> None:
        with self._lock:
            request = self.get(request_id)
            if request.state.is_terminal:
                raise veil_error(
                    ErrorCode.REQUEST_NOT_ACTIVE,
                    "This credential request is no longer active.",
                )
            if token is not None:
                valid = token_equals(request.submit_token, token) or token_equals(
                    request.confirm_token, token
                )
                if not valid:
                    self.log.security("token_mismatch", request_id=request.request_id, stage="C")
                    raise veil_error(ErrorCode.UNAUTHORIZED, "Invalid authorization token.")
            if request.state is RequestState.EXECUTING:
                raise veil_error(
                    ErrorCode.INVALID_STATE,
                    "The operation is already executing and cannot be cancelled.",
                )
            self._finish(request, RequestState.CANCELLED, reason=reason)

    def revise(self, request_id: object, params: StoreRequestParams) -> SecretRequest:
        """Any change to an authorized operation invalidates it (SPEC.md §11).

        The old request is cancelled and its secret destroyed; a brand-new
        request with a fresh authorization flow is returned. There is no path
        that mutates an existing snapshot.
        """

        with self._lock:
            existing = self.get(request_id)
            self.log.security(
                "authorization_invalidated",
                request_id=existing.request_id,
                reason="revision_requested",
                state=str(existing.state),
            )
            if not existing.state.is_terminal:
                if existing.state is RequestState.EXECUTING:
                    raise veil_error(
                        ErrorCode.INVALID_STATE,
                        "The operation is already executing and cannot be revised.",
                    )
                self._finish(existing, RequestState.CANCELLED, reason="superseded")

        # Built outside the lock: normalization and preflight touch providers.
        new_request = self.create_request(params)
        with self._lock:
            existing.superseded_by = new_request.request_id
        return new_request

    # -- maintenance -------------------------------------------------------

    def sweep_expired(self) -> int:
        with self._lock:
            return self._sweep_expired_locked()

    def shutdown(self) -> None:
        """Destroy every live secret (used on exit and on crash)."""

        with self._lock:
            for request in list(self._active.values()):
                if not request.state.is_terminal:
                    self._finish(request, RequestState.CANCELLED, reason="shutdown")
                self._destroy_secret(request)

    def contains_live_secret(self, text: str) -> bool:
        """Tripwire used by the logger, the MCP transport and the UI."""

        if not text:
            return False
        with self._lock:
            requests = list(self._active.values())
        for request in requests:
            secret = request.secret
            if secret is not None and not secret.destroyed and secret.contains_in(text):
                return True
        return False

    def wait_for_terminal(self, request_id: object, timeout: float) -> dict[str, Any]:
        request = self.get(request_id)
        request.terminal_event.wait(timeout)
        return self.public_status(request.request_id)

    # -- internals ---------------------------------------------------------

    def _adapter_call(
        self,
        coro: Any,
        *,
        fallback_code: str,
        fallback_message: str,
    ) -> Any:
        """Run a pre-secret adapter step, translating failures safely.

        An adapter may describe its own refusal through :class:`AdapterError`;
        anything else it raises is replaced with a generic public error, because
        an unplanned exception's text is not ours to trust (SPEC.md §20).
        """

        try:
            return _run(coro)
        except AdapterError as exc:
            raise VeilError(exc.public) from None
        except VeilError:
            raise
        except Exception:
            self.log.error("adapter_step_failed", code=fallback_code)
            raise veil_error(fallback_code, fallback_message) from None

    def _require_state(self, request: SecretRequest, expected: RequestState) -> None:
        if request.state is expected:
            return
        if request.state.is_terminal:
            self.log.security(
                "reuse_attempt",
                request_id=request.request_id,
                state=str(request.state),
            )
            code = {
                RequestState.EXPIRED: ErrorCode.REQUEST_EXPIRED,
                RequestState.CANCELLED: ErrorCode.REQUEST_CANCELLED,
            }.get(request.state, ErrorCode.REQUEST_NOT_ACTIVE)
            raise veil_error(code, "This credential request is no longer active.")
        raise veil_error(
            ErrorCode.INVALID_STATE,
            "The credential request is not at the expected stage.",
        )

    def _require_token(
        self, request: SecretRequest, expected: str, provided: str, *, stage: str
    ) -> None:
        if not isinstance(provided, str) or not token_equals(expected, provided):
            self.log.security("token_mismatch", request_id=request.request_id, stage=stage)
            raise veil_error(ErrorCode.UNAUTHORIZED, "Invalid authorization token.")

    def _claim_execution_locked(self, request: SecretRequest) -> bool:
        """Single-flight guard against double submit and replay (SPEC.md §29)."""

        if request.execution_claimed:
            return False
        request.execution_claimed = True
        self._transition(request, RequestState.EXECUTING)
        return True

    def _transition(self, request: SecretRequest, to_state: RequestState) -> None:
        allowed = ALLOWED_TRANSITIONS[request.state]
        if to_state not in allowed:
            raise veil_error(
                ErrorCode.INVALID_STATE,
                "The credential request is not at the expected stage.",
            )
        request.state = to_state

    def _check_expiry_locked(self, request: SecretRequest) -> None:
        if request.state.is_terminal or request.state is RequestState.EXECUTING:
            return
        if self._clock() >= request.expires_at:
            self._finish(request, RequestState.EXPIRED, reason="ttl")

    def _sweep_expired_locked(self) -> int:
        count = 0
        for request in list(self._active.values()):
            before = request.state
            self._check_expiry_locked(request)
            if request.state is not before:
                count += 1
        return count

    def _finish(
        self,
        request: SecretRequest,
        state: RequestState,
        *,
        reason: str = "",
        result: StoreResult | None = None,
        error: PublicError | None = None,
    ) -> None:
        request.state = state
        request.result = result
        request.error = error
        self._destroy_secret(request)
        self._active.pop(request.request_id, None)
        self._history[request.request_id] = request
        while len(self._history) > TERMINAL_HISTORY_LIMIT:
            self._history.popitem(last=False)
        request.terminal_event.set()
        self.log.event(
            "request_finished",
            request_id=request.request_id,
            state=str(state),
            reason=reason or "",
            result=("success" if state is RequestState.STORED else "failure"),
            confirmation=request.confirmation,
            adapter=request.snapshot.target.adapter_id,
            operation=str(request.snapshot.operation),
            logical_name=safe_display(request.snapshot.logical_name, max_length=80),
            environment=str(request.snapshot.target.environment),
            risk=str(request.snapshot.risk.level),
            error_code=(error.code if error else ""),
        )

    def _destroy_secret(self, request: SecretRequest) -> None:
        secret = request.secret
        request.secret = None
        if secret is not None:
            secret.zeroize()

    def _execute(self, request: SecretRequest) -> None:
        """Perform exactly the authorized operation (SPEC.md §4.3, §11, §12)."""

        started = time.monotonic()
        snapshot = request.snapshot
        adapter = request.adapter
        secret = request.secret

        try:
            if snapshot.digest != request.authorized_digest:
                raise veil_error(
                    ErrorCode.SNAPSHOT_MISMATCH,
                    "The authorized operation changed and can no longer be executed.",
                )
            if adapter.id != snapshot.target.adapter_id or adapter is not self.registry.get(
                snapshot.target.adapter_id
            ):
                raise veil_error(
                    ErrorCode.SNAPSHOT_MISMATCH,
                    "The authorized destination adapter changed and cannot be executed.",
                )
            if secret is None or secret.destroyed:
                raise veil_error(ErrorCode.INVALID_STATE, "No credential value is available.")
            if snapshot.risk.requires_stage_b and request.confirmation != "explicit":
                raise veil_error(
                    ErrorCode.CONFIRMATION_REQUIRED,
                    "This operation requires explicit confirmation before execution.",
                )
        except VeilError as exc:
            with self._lock:
                self._finish(request, RequestState.FAILED, reason="precondition", error=exc.public)
            self.log.security(
                "execution_blocked",
                request_id=request.request_id,
                code=exc.public.code,
            )
            return

        self.log.event(
            "execution_started",
            request_id=request.request_id,
            adapter=adapter.id,
            operation=str(snapshot.operation),
            authorization_digest=request.authorized_digest,
        )

        result: StoreResult | None = None
        error: PublicError | None = None
        try:
            result = _run(
                adapter.store(secret, snapshot.target, snapshot.operation),
                timeout=self.config.adapter_timeout_seconds,
            )
            if not isinstance(result, StoreResult):
                raise AdapterError(
                    PublicError(
                        ErrorCode.INTERNAL_ERROR,
                        "The destination adapter returned an unusable result.",
                    )
                )
            error = self._scrub_result(request, result)
            if error is not None:
                result = None
        except VeilError as exc:
            error = exc.public
        except BaseException as exc:
            error = self._sanitize(request, adapter, exc)

        duration_ms = int((time.monotonic() - started) * 1000)
        with self._lock:
            if error is None and result is not None:
                self._finish(
                    request,
                    RequestState.STORED,
                    reason="stored",
                    result=result,
                )
            else:
                self._finish(
                    request,
                    RequestState.FAILED,
                    reason="adapter",
                    error=error or INTERNAL_ERROR,
                )
        self.log.event(
            "execution_finished",
            request_id=request.request_id,
            adapter=adapter.id,
            duration_ms=duration_ms,
            result=("success" if error is None else "failure"),
            error_code=(error.code if error else ""),
        )

    def _sanitize(
        self,
        request: SecretRequest,
        adapter: SecretDestinationAdapter,
        exc: BaseException,
    ) -> PublicError:
        """Translate a provider exception without ever echoing it (SPEC.md §20)."""

        try:
            if not isinstance(exc, Exception):
                return INTERNAL_ERROR
            if isinstance(exc, TimeoutError):
                return PublicError(
                    ErrorCode.DESTINATION_TIMEOUT,
                    "The destination did not respond in time.",
                )
            public = _run(adapter.sanitize_error(exc))
            if not isinstance(public, PublicError):
                return INTERNAL_ERROR
        except BaseException:
            self.log.security("sanitization_failed", request_id=request.request_id)
            return INTERNAL_ERROR

        rendered = public.code + " " + public.message + " " + repr(public.detail)
        secret = request.secret
        if secret is not None and not secret.destroyed and secret.contains_in(rendered):
            self.log.security(
                "sanitized_error_contained_secret",
                request_id=request.request_id,
                code="TRIPWIRE",
            )
            return INTERNAL_ERROR
        if self.contains_live_secret(rendered):
            self.log.security("tripwire_blocked_error", request_id=request.request_id)
            return INTERNAL_ERROR
        return PublicError(
            code=safe_display(public.code, max_length=64),
            message=safe_display(public.message, max_length=300),
            detail=tuple(
                (safe_display(k, max_length=40), safe_display(v, max_length=200))
                for k, v in public.detail
            ),
        )

    def _scrub_result(self, request: SecretRequest, result: StoreResult) -> PublicError | None:
        """Refuse to publish a result that carries credential material."""

        rendered = repr(result.as_public_dict())
        secret = request.secret
        if (secret is not None and not secret.destroyed and secret.contains_in(rendered)) or (
            self.contains_live_secret(rendered)
        ):
            self.log.security(
                "adapter_result_contained_secret",
                request_id=request.request_id,
                adapter=request.snapshot.target.adapter_id,
            )
            return PublicError(
                ErrorCode.INTERNAL_ERROR,
                "The destination reported a result that could not be safely returned.",
            )
        return None


def _run(coro: Any, *, timeout: float | None = None) -> Any:
    """Run an adapter coroutine from the broker's synchronous world."""

    if not asyncio.iscoroutine(coro):
        return coro
    if timeout is None:
        return asyncio.run(coro)

    async def _bounded() -> Any:
        return await asyncio.wait_for(coro, timeout)

    return asyncio.run(_bounded())


# -- parameter validation -------------------------------------------------


def parse_store_params(
    payload: Mapping[str, Any],
    registry: AdapterRegistry,
) -> StoreRequestParams:
    """Validate ``secret.store`` arguments (SPEC.md §6, §13, §18.3).

    Structural rejection of secret-shaped input happens here and in the MCP
    schema layer: unknown fields are refused rather than ignored, so a malicious
    agent cannot smuggle credential material through an unmodelled property.
    """

    if not isinstance(payload, Mapping):
        raise veil_error(ErrorCode.INVALID_ARGUMENTS, "Arguments must be an object.")

    allowed = {"destination", "name", "target", "write_mode", "description", "environment"}
    unknown = sorted(k for k in payload if k not in allowed)
    if unknown:
        raise veil_error(
            ErrorCode.FORBIDDEN_FIELD,
            "The request contained fields that are not part of the tool contract.",
            fields=", ".join(safe_display(u, max_length=40) for u in unknown[:5]),
        )

    destination = payload.get("destination")
    if not isinstance(destination, str) or destination not in registry:
        raise veil_error(
            ErrorCode.UNKNOWN_DESTINATION, "The requested destination is not available."
        )

    name = payload.get("name")
    if not isinstance(name, str) or not name.strip():
        raise veil_error(ErrorCode.INVALID_ARGUMENTS, "A logical credential name is required.")
    if len(name) > MAX_NAME_LENGTH:
        raise veil_error(ErrorCode.INVALID_ARGUMENTS, "The credential name is too long.")

    raw_target = payload.get("target")
    if not isinstance(raw_target, Mapping):
        raise veil_error(ErrorCode.INVALID_TARGET, "A destination target object is required.")
    if len(raw_target) > MAX_TARGET_FIELDS:
        raise veil_error(ErrorCode.INVALID_TARGET, "The destination target has too many fields.")

    target: dict[str, Any] = {}
    for key, value in raw_target.items():
        if not isinstance(key, str):
            raise veil_error(ErrorCode.INVALID_TARGET, "Target keys must be strings.")
        if not isinstance(value, str | int | bool):
            raise veil_error(
                ErrorCode.INVALID_TARGET,
                "Target values must be simple scalars.",
            )
        text = str(value)
        if len(text) > MAX_TARGET_VALUE_LENGTH:
            raise veil_error(ErrorCode.INVALID_TARGET, "A target value is too long.")
        target[key] = value

    write_mode_raw = payload.get("write_mode", WriteMode.CREATE)
    try:
        write_mode = WriteMode(write_mode_raw)
    except ValueError:
        raise veil_error(ErrorCode.INVALID_ARGUMENTS, "Unsupported write mode.") from None

    environment_raw = payload.get("environment", Environment.UNKNOWN)
    try:
        environment = Environment(environment_raw)
    except ValueError:
        raise veil_error(ErrorCode.INVALID_ARGUMENTS, "Unsupported environment.") from None

    description = payload.get("description")
    if description is not None:
        if not isinstance(description, str):
            raise veil_error(ErrorCode.INVALID_ARGUMENTS, "Description must be a string.")
        if len(description) > MAX_DESCRIPTION_LENGTH:
            raise veil_error(ErrorCode.INVALID_ARGUMENTS, "Description is too long.")

    return StoreRequestParams(
        destination=destination,
        name=name.strip(),
        target=tuple(sorted(target.items())),
        write_mode=write_mode,
        environment=environment,
        description=description,
    )


__all__ = [
    "NormalizedTarget",
    "RiskAssessment",
    "RiskLevel",
    "SecretBroker",
    "SecretRequest",
    "StoreRequestParams",
    "parse_store_params",
]
