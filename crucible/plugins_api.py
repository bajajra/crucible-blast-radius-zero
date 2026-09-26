"""Validated, substrate-independent pre-execution plugin interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

Decision = Literal["allow", "deny"]
ActionKind = Literal["shell", "http_get", "file_read", "file_write", "net_connect", "output"]


@dataclass(frozen=True)
class Action:
    kind: ActionKind
    payload: dict[str, Any]
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in {"shell", "http_get", "file_read", "file_write", "net_connect", "output"}:
            raise ValueError(f"unsupported action kind: {self.kind}")
        if not isinstance(self.payload, dict) or not isinstance(self.context, dict):
            raise ValueError("payload and context must be objects")


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str
    dimension: str
    confidence: float = 1.0
    plugin_id: str = ""

    def __post_init__(self) -> None:
        if self.decision not in {"allow", "deny"} or not 0 <= self.confidence <= 1:
            raise ValueError("invalid plugin verdict")


class Plugin(Protocol):
    id: str
    dimension: str
    triggers: tuple[str, ...]

    def pre_exec(self, action: Action) -> Verdict: ...


@dataclass(frozen=True)
class Evaluation:
    final: Verdict
    checks: tuple[Verdict, ...]


class PluginRegistry:
    """Run mounted plugins in order; a denial or plugin failure stops execution."""

    def __init__(self) -> None:
        self._plugins: list[Plugin] = []

    def mount(self, plugin: Plugin) -> None:
        if any(item.id == plugin.id for item in self._plugins):
            raise ValueError(f"plugin already mounted: {plugin.id}")
        if not plugin.id or not plugin.dimension:
            raise ValueError("plugin id and dimension are required")
        self._plugins.append(plugin)

    @property
    def mounted(self) -> tuple[str, ...]:
        return tuple(item.id for item in self._plugins)

    def find_for(self, attack_shape: str) -> tuple[Plugin, ...]:
        return tuple(item for item in self._plugins if attack_shape in item.triggers)

    def evaluate(self, action: Action) -> Evaluation:
        checks: list[Verdict] = []
        for plugin in self._plugins:
            try:
                verdict = plugin.pre_exec(action)
                if not isinstance(verdict, Verdict):
                    raise TypeError("plugin returned a non-verdict")
            except Exception as exc:
                # Do not expose exception content: it may contain action data or keys.
                verdict = Verdict("deny", f"{plugin.id} unavailable ({type(exc).__name__})", plugin.dimension, 1, plugin.id)
            checks.append(verdict)
            if verdict.decision == "deny":
                return Evaluation(verdict, tuple(checks))
        return Evaluation(Verdict("allow", "all mounted checks passed", "stack"), tuple(checks))
