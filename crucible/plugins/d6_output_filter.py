"""D6 redacts secrets and blocks exfiltration across the supervisor seam."""

from __future__ import annotations

from crucible.plugins_api import Action, Verdict
from crucible.secret_scan import SecretScanner


class OutputFilterPlugin(SecretScanner):
    id = "d6_output_filter_v1"
    dimension = "D6"
    triggers = ("secret_exfil", "output", "egress", "shared_channel")

    def pre_exec(self, action: Action) -> Verdict:
        if action.kind not in {"http_get", "net_connect", "file_write", "output", "shell"}:
            return Verdict("allow", "no outward payload", self.dimension, plugin_id=self.id)
        # Shell text is checked too; stdout/stderr are redacted separately before logging.
        text = "\n".join(str(value) for value in action.payload.values())
        _, matches = self.redact(text)
        if matches:
            return Verdict("deny", f"outward payload contains {matches} secret marker(s)", self.dimension, plugin_id=self.id)
        return Verdict("allow", "no secret marker found", self.dimension, plugin_id=self.id)
