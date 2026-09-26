"""Loopback policy broker for the DSH pre/post-execution hooks."""

from __future__ import annotations

import argparse
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os

from crucible.plugins_api import Action, PluginRegistry
from crucible.plugins.d1_egress_allowlist import EgressAllowlistPlugin
from crucible.plugins.d3_classifier import SemanticClassifierPlugin
from crucible.plugins.d3_shell_gate import ShellGatePlugin
from crucible.plugins.d6_output_filter import OutputFilterPlugin
from crucible.scenarios import CANARY
from crucible.env import load_env_local

MAX_REQUEST = 128 * 1024


def make_server(host: str, port: int, token: str) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("policy broker must bind to loopback")
    if len(token) < 16:
        raise ValueError("CRUCIBLE_BROKER_TOKEN must be at least 16 characters")
    scanner = OutputFilterPlugin((CANARY,))
    registry = PluginRegistry()
    registry.mount(scanner)
    registry.mount(EgressAllowlistPlugin({"pypi.org", "files.pythonhosted.org", "registry.npmjs.org"}))
    registry.mount(SemanticClassifierPlugin(scanner, enabled=True))
    registry.mount(ShellGatePlugin())

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            # Request bodies and authorization headers are never logged.
            pass

        def _reply(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            supplied = self.headers.get("Authorization", "")
            if not compare_digest(supplied, f"Bearer {token}"):
                self._reply(401, {"decision": "deny", "reason": "unauthorized broker request"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_REQUEST:
                    raise ValueError("request size invalid")
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError("request must be an object")
                if self.path == "/pre-exec":
                    action = Action(data["kind"], data["payload"], data.get("context", {}))
                    verdict = registry.evaluate(action).final
                    self._reply(200, {"decision": verdict.decision, "reason": verdict.reason,
                                      "dimension": verdict.dimension, "plugin_id": verdict.plugin_id})
                elif self.path == "/post-exec":
                    clean, count = scanner.redact(str(data["text"]))
                    self._reply(200, {"text": clean, "redactions": count, "blocked": count > 0})
                else:
                    self._reply(404, {"error": "unknown route"})
            except (ValueError, TypeError, KeyError, json.JSONDecodeError):
                self._reply(400, {"decision": "deny", "reason": "invalid broker request"})

    return ThreadingHTTPServer((host, port), Handler)


def main() -> int:
    from pathlib import Path
    load_env_local(Path(__file__).resolve().parent.parent)
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    token = os.getenv("CRUCIBLE_BROKER_TOKEN", "")
    server = make_server(args.host, args.port, token)
    print(f"Policy broker listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
