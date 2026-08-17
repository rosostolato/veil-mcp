"""Veil entry point: ``veil serve`` runs the MCP server and the secure UI.

Two process-level protections are set up here:

* stdout is reserved exclusively for the MCP protocol. The real stdout is duped
  for the transport and file descriptor 1 is pointed at stderr, so a stray
  ``print`` anywhere in the process — or in a dependency — cannot corrupt or
  contaminate protocol traffic (SEC-004).
* a crash handler wipes every live secret before the interpreter unwinds, and
  never serializes an in-flight request (SPEC.md §18.9).
"""

from __future__ import annotations

import argparse
import atexit
import os
import sys
import threading
import time

from veil import __version__
from veil.adapters.registry import default_registry
from veil.broker import SecretBroker
from veil.config import VeilConfig
from veil.logging_ import AuditLogger, install_crash_handler
from veil.mcp_server.server import MCPServer
from veil.ui.server import SecureInputUI

SWEEP_INTERVAL_SECONDS = 5.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veil", description="Veil secure input MCP server")
    parser.add_argument("--version", action="version", version=f"veil {__version__}")
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="run the MCP server on stdio with the secure UI")
    serve.add_argument("--ui-host", default=None)
    serve.add_argument("--ui-port", type=int, default=None)
    args = parser.parse_args(argv)

    if args.command in (None, "serve"):
        return _serve(
            ui_host=getattr(args, "ui_host", None),
            ui_port=getattr(args, "ui_port", None),
        )
    parser.print_help(file=sys.stderr)
    return 2


def _serve(*, ui_host: str | None, ui_port: int | None) -> int:
    config = VeilConfig.from_env()
    if ui_host is not None:
        config = config.with_(ui_host=ui_host)
    if ui_port is not None:
        config = config.with_(ui_port=ui_port)

    logger = AuditLogger(stream=sys.stderr)
    registry = default_registry(config)
    broker = SecretBroker(config, registry, logger=logger)
    ui = SecureInputUI(broker, config, logger=logger)
    server = MCPServer(broker, registry, logger=logger)

    install_crash_handler(broker.shutdown, logger)
    atexit.register(broker.shutdown)

    ui.start()
    _start_sweeper(broker)

    protocol_out = os.fdopen(os.dup(sys.stdout.fileno()), "wb", buffering=0)
    protocol_in = sys.stdin.buffer
    os.dup2(sys.stderr.fileno(), 1)
    sys.stdout = sys.stderr

    logger.event(
        "server_started",
        component="mcp",
        detail={
            "version": __version__,
            "adapters": list(registry.ids()),
            "ui": ui.base_url or "",
            "identity": ui.identity,
        },
    )
    try:
        server.serve(protocol_in, protocol_out)
    except KeyboardInterrupt:
        pass
    finally:
        broker.shutdown()
        ui.stop()
        logger.event("server_stopped", component="mcp")
    return 0


def _start_sweeper(broker: SecretBroker) -> threading.Thread:
    def loop() -> None:
        while True:
            time.sleep(SWEEP_INTERVAL_SECONDS)
            try:
                broker.sweep_expired()
            except Exception:
                broker.log.error("sweeper_failed", component="broker")

    thread = threading.Thread(target=loop, name="veil-sweeper", daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    raise SystemExit(main())
