"""Execute one approved action inside a disposable container.

The host owns model access and policy decisions. This module receives no cloud key.
Its JSON output is still untrusted and must pass the host D6 filter before storage.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import urllib.request
from urllib.error import HTTPError

from crucible.network_policy import SAFE_FETCH_URLS
from crucible.safe_commands import parse_safe_command

MAX_OUTPUT = 32_768
MAX_ACTION = 64 * 1024
WORK = Path("/work")


class PolicyDenied(ValueError):
    def __init__(self, dimension: str, reason: str) -> None:
        self.dimension = dimension
        super().__init__(reason)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise HTTPError(request.full_url, code, "redirect blocked", headers, fp)


def _inside(path: str, root: Path) -> Path:
    target = Path(path)
    if not target.is_absolute():
        target = root / target
    resolved = target.resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise ValueError("path outside permitted work directory")
    return resolved


def execute(action: dict) -> dict:
    kind = action.get("kind")
    payload = action.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    if kind == "shell":
        command = payload.get("cmd")
        try:
            argv = parse_safe_command(command)
        except ValueError:
            raise PolicyDenied("D3", "command outside diagnostic grammar") from None
        result = subprocess.run(
            argv, cwd="/work", capture_output=True,
            text=True, errors="replace", timeout=15, check=False, env={
                "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/work", "TMPDIR": "/work"
            },
        )
        return {"exit_code": result.returncode, "stdout": result.stdout[:MAX_OUTPUT],
                "stderr": result.stderr[:MAX_OUTPUT]}
    if kind == "file_read":
        path = _inside(str(payload.get("path", "")), WORK)
        return {"exit_code": 0, "stdout": path.read_text(errors="replace")[:MAX_OUTPUT], "stderr": ""}
    if kind == "file_write":
        path = _inside(str(payload.get("path", "")), WORK / "output")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(payload.get("content", "")))
        return {"exit_code": 0, "stdout": str(path), "stderr": ""}
    if kind == "http_get":
        url = str(payload.get("url", ""))
        if not url.startswith("https://"):
            raise ValueError("http_get requires HTTPS")
        if url not in SAFE_FETCH_URLS:
            raise PolicyDenied("D1", "network URL is outside exact fetch policy")
        request = urllib.request.Request(url, method="GET", headers={"User-Agent": "crucible-worker/0.1"})
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=10) as response:
                body = response.read(MAX_OUTPUT + 1)
                return {"exit_code": 0, "stdout": body[:MAX_OUTPUT].decode("utf-8", "replace"),
                        "stderr": "", "http_status": response.status,
                        "network_request_attempted": True, "network_response_received": True,
                        "truncated": len(body) > MAX_OUTPUT}
        except HTTPError as exc:
            exc.close()
            return {"exit_code": 1, "stdout": "", "stderr": f"HTTP status {exc.code}",
                    "http_status": exc.code, "network_request_attempted": True,
                    "network_response_received": True}
        except Exception as exc:
            return {"exit_code": 1, "stdout": "", "stderr": f"network error: {type(exc).__name__}",
                    "network_request_attempted": True, "network_response_received": False}
    if kind == "net_connect":
        # Connect probes are expressed as HTTPS GETs so TLS/port restrictions still apply.
        return execute({"kind": "http_get", "payload": {"url": payload.get("url", "")}})
    raise ValueError(f"unsupported action kind: {kind}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action-file", default="/work/scenario/action.json")
    args = parser.parse_args()
    try:
        if args.action_file == "-":
            raw = sys.stdin.buffer.read(MAX_ACTION + 1)
            if len(raw) > MAX_ACTION:
                raise ValueError("action input too large")
            action = json.loads(raw)
        else:
            action = json.loads(Path(args.action_file).read_text())
        if not isinstance(action, dict):
            raise ValueError("action must be a JSON object")
        result = execute(action)
    except subprocess.TimeoutExpired:
        result = {"exit_code": 124, "stdout": "", "stderr": "action timed out"}
    except PolicyDenied as exc:
        result = {"exit_code": 77, "stdout": "", "stderr": str(exc),
                  "policy_denial": exc.dimension}
    except Exception as exc:
        # The host must redact this result before logging or forwarding it.
        result = {"exit_code": 1, "stdout": "", "stderr": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
