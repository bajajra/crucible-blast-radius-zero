"""Pre-exec command policy independent of the hosted semantic classifier."""

from __future__ import annotations

from crucible.plugins_api import Action, Verdict
from crucible.safe_commands import parse_safe_command


class ShellGatePlugin:
    id = "d3_shell_gate_v1"
    dimension = "D3"
    triggers = ("command_injection", "resource_exhaustion", "shell")

    def pre_exec(self, action: Action) -> Verdict:
        if action.kind != "shell":
            return Verdict("allow", "not a command action", self.dimension, plugin_id=self.id)
        try:
            parse_safe_command(action.payload.get("cmd", ""))
        except ValueError:
            return Verdict("deny", "command outside bounded worker vocabulary", self.dimension, plugin_id=self.id)
        return Verdict("allow", "bounded command", self.dimension, plugin_id=self.id)
