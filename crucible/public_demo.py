"""Export a bounded, disclosure-safe static dashboard for GitHub Pages.

The local dashboard is private because its action log and report can contain
free-form worker text. This exporter has a separate, closed public schema:
numbers, booleans, and strings chosen from literals in this module only.
"""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import secrets
import tempfile
from typing import Any

from crucible.dashboard import HTML, build_snapshot


ATTACK_SHAPES = {
    "egress": "Direct egress attempt",
    "dependency_fetch": "Dependency lookalike host",
    "secret_exfil": "Secret in outbound request",
    "resource_exhaustion": "Long-running command",
}

ACTION_KINDS = {
    "http_get": "HTTP GET",
    "file_read": "Local file read",
    "shell": "Shell command",
}

DIMENSIONS = {
    "D1": "D1 network policy",
    "D2": "D2 syscall policy",
    "D3": "D3 pre-exec policy",
    "D4": "D4 lifecycle",
    "D5": "D5 experience bank",
    "D6": "D6 output filter",
    "d1_egress_allowlist_v1": "D1 network policy",
    "d3_classifier_v1": "D3 pre-exec policy",
    "d3_shell_gate_v1": "D3 pre-exec policy",
    "d6_output_filter_v1": "D6 output filter",
    "stack": "Policy stack",
}

DEFENSE_SUMMARIES = {
    "D1 network policy": "Default-drop egress policy",
    "D2 syscall policy": "Docker seccomp profile",
    "D3 pre-exec policy": "Pre-execution action gate",
    "D4 lifecycle": "Fresh container per episode",
    "D5 experience bank": "Verified defense retrieval",
    "D6 output filter": "Outbound secret scan",
    "Policy stack": "Review and add a defense",
}

APPROVED_REPORTS = frozenset({
    "The local reference sequence is 1, 1, 2, 3, 5, 8.",
    "The bundled reference fixture is readable locally.",
    "The demo license is configured; its credential value is withheld.",
    "The bounded local fixture read completed successfully.",
})


def _bounded_int(value: object, maximum: int = 1_000_000) -> int:
    return value if type(value) is int and 0 <= value <= maximum else 0


def _rate(value: object) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        return 0.0
    return max(0.0, min(float(value), 1.0))


def _dimension(value: object) -> str:
    if isinstance(value, str) and value.startswith("pl_"):
        return "D3 pre-exec policy"
    return DIMENSIONS.get(value, "Policy stack") if isinstance(value, str) else "Policy stack"


def public_snapshot(private: dict[str, Any]) -> dict[str, Any]:
    """Discard all free-form text, identifiers, payloads, URLs, and raw proof."""
    original = private.get("summary", {})
    if not isinstance(original, dict):
        original = {}
    summary = {field: _bounded_int(original.get(field)) for field in
               ("total", "simulated", "docker", "unverified_docker")}
    summary.update({field: _rate(original.get(field)) for field in
                    ("attack_rate", "safe_rate", "fixture_rate")})

    curves = []
    for item in private.get("curves", [])[:1000]:
        if not isinstance(item, dict):
            continue
        curves.append({"episode": _bounded_int(item.get("episode")),
                       "round": _bounded_int(item.get("round")),
                       "attack_rate": _rate(item.get("attack_rate")),
                       "safe_rate": _rate(item.get("safe_rate"))})

    events = []
    for item in private.get("events", [])[-200:]:
        if not isinstance(item, dict):
            continue
        decision = item.get("decision")
        mode = item.get("mode")
        exit_code = item.get("exit_code")
        events.append({
            "round": _bounded_int(item.get("round")),
            "action": ACTION_KINDS.get(item.get("action"), "Worker action"),
            "detail": "",
            "decision": decision if decision in {"allow", "deny"} else "observed",
            "dimension": _dimension(item.get("dimension")),
            "reason": "",
            "mode": mode if mode in {"docker", "simulate"} else "unknown",
            "exit_code": exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else None,
        })

    patterns = []
    for item in private.get("patterns", [])[:100]:
        if not isinstance(item, dict) or item.get("attack_shape") not in ATTACK_SHAPES:
            continue
        dimension = _dimension(item.get("dimension"))
        patterns.append({
            "pattern_id": f"public-{len(patterns) + 1}",
            "attack_shape": ATTACK_SHAPES[item["attack_shape"]],
            "dimension": dimension,
            "recommended_defense": DEFENSE_SUMMARIES[dimension],
            "supporting_count": _bounded_int(item.get("supporting_count")),
        })

    latest = private.get("latest_report")
    report = None
    if isinstance(latest, dict) and latest.get("text") in APPROVED_REPORTS:
        mode = latest.get("mode")
        report = {"text": latest["text"],
                  "mode": mode if mode in {"docker", "simulate"} else "unknown",
                  "episode_id": "fixed rubric result"}
    return {"summary": summary, "curves": curves, "events": events,
            "patterns": patterns, "latest_report": report}


def _static_html() -> str:
    nonce = secrets.token_urlsafe(18)
    page = HTML.replace("__NONCE__", nonce)
    page = page.replace("<title>CRUCIBLE · Containment evidence</title>",
                        "<title>CRUCIBLE · Public demo snapshot</title>")
    page = page.replace("<p class=\"eyebrow\">CRUCIBLE / evidence readout</p>",
                        "<p class=\"eyebrow\">CRUCIBLE / public snapshot</p>")
    page = page.replace(
        "Recorded episodes only. A verdict is not a kernel proof; inspect VM evidence before making a containment claim.",
        "Aggregate episode results with fixed labels only. No raw actions, model text, secrets, or VM logs are published here. A verdict is not a kernel proof; review the VM wall evidence separately.")
    page = page.replace("fetch('/api/snapshot'", "fetch('./snapshot.json'")
    page = page.replace("'Updated ' + new Date().toLocaleTimeString()",
                        "'Static snapshot loaded'")
    csp = ("default-src 'none'; script-src 'nonce-" + nonce +
           "'; style-src 'nonce-" + nonce +
           "'; connect-src 'self'; base-uri 'none'; form-action 'none'")
    page = page.replace("  <meta name=\"viewport\"", 
                        f'  <meta http-equiv="Content-Security-Policy" content="{csp}">\n  <meta name="viewport"')
    return page


def _write_atomic(path: Path, data: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def export(db_path: str | Path, output_dir: str | Path, *, limit: int = 200,
           require_docker: bool = False) -> dict[str, Any]:
    """Create only index.html and snapshot.json in the chosen directory."""
    snapshot = public_snapshot(build_snapshot(db_path, limit=limit))
    if require_docker and snapshot["summary"]["docker"] == 0:
        raise ValueError("public Pages source requires at least one Docker episode")
    target = Path(output_dir)
    if target.is_symlink():
        raise ValueError("output directory cannot be a symlink")
    target.mkdir(parents=True, exist_ok=True)
    if not target.is_dir():
        raise ValueError("output path must be a directory")
    for name in ("index.html", "snapshot.json"):
        if (target / name).is_symlink():
            raise ValueError(f"{name} cannot be a symlink")
    data = (json.dumps(snapshot, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    _write_atomic(target / "snapshot.json", data)
    _write_atomic(target / "index.html", _static_html().encode("utf-8"))
    return snapshot["summary"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a safe static CRUCIBLE demo snapshot")
    parser.add_argument("--db", default="data/experience.sqlite")
    parser.add_argument("--output", default="dist/public-demo")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--require-docker", action="store_true",
                        help="refuse a Pages source containing only simulation")
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 1000:
        parser.error("--limit must be from 1 to 1000")
    summary = export(args.db, args.output, limit=args.limit,
                     require_docker=args.require_docker)
    print(f"Public snapshot: {summary['docker']} Docker, {summary['simulated']} simulated episodes")
    print(f"Files: {Path(args.output) / 'index.html'}, {Path(args.output) / 'snapshot.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
