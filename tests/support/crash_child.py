"""Child process for crash tests (SPEC.md §31).

Runs a real credential flow, then dies at a chosen point. The parent inspects
stdout, stderr and the filesystem for canary material. Nothing here is a mock:
the crash handler, the audit logger and the broker are the production ones.

Usage: ``crash_child.py <stage> <tmpdir>`` with the canary on stdin.
"""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path
from typing import Any

from tests.support.fakes import RecordingAdapter
from veil.adapters.registry import AdapterRegistry
from veil.broker import SecretBroker, parse_store_params
from veil.config import VeilConfig
from veil.logging_ import AuditLogger, install_crash_handler
from veil.model import NormalizedTarget, StoreResult, WriteMode
from veil.secret_buffer import SecretBuffer

STAGES = ("secret_entry", "secret_received", "during_destination_call", "after_destination_success")


class CrashingAdapter(RecordingAdapter):
    id = "fake-store"

    def __init__(self, config: VeilConfig, stage: str) -> None:
        super().__init__(config)
        self.stage = stage

    async def store(
        self,
        secret: SecretBuffer,
        target: NormalizedTarget,
        operation: WriteMode,
    ) -> StoreResult:
        if self.stage == "during_destination_call":
            sys.stdout.flush()
            sys.stderr.flush()
            os.kill(os.getpid(), signal.SIGKILL)
        result = await super().store(secret, target, operation)
        if self.stage == "after_destination_success":
            raise RuntimeError("crash after the destination write succeeded")
        return result


def main() -> int:
    stage = sys.argv[1]
    workdir = Path(sys.argv[2])
    secret = sys.stdin.buffer.readline().strip()

    config = VeilConfig(
        env_allowed_roots=(workdir.resolve(),),
        request_ttl_seconds=60.0,
        open_browser=False,
    )
    adapter = CrashingAdapter(config, stage)
    registry = AdapterRegistry([adapter])
    logger = AuditLogger(stream=sys.stderr)
    broker = SecretBroker(config, registry, logger=logger)
    install_crash_handler(broker.shutdown, logger)

    args: dict[str, Any] = {
        "destination": "fake-store",
        "name": "CRASH_KEY",
        "target": {"project": "acme-production", "secret": "CRASH_KEY"},
        "write_mode": "replace",
        "environment": "production",
    }
    request = broker.create_request(parse_store_params(args, registry))

    if stage == "secret_entry":
        raise RuntimeError("crash while the user was entering the value")

    broker.submit_secret(request.request_id, request.submit_token, secret)
    if stage == "secret_received":
        raise RuntimeError("crash after the secret was received")

    broker.confirm_execution(request.request_id, request.confirm_token)
    raise RuntimeError("crash before the response was returned")


if __name__ == "__main__":
    raise SystemExit(main())
