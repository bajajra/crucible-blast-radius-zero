"""Load local development credentials without shell evaluation or logging."""

from __future__ import annotations

import os
from pathlib import Path
import re

_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


def load_env_local(root: str | Path) -> bool:
    override = os.getenv("CRUCIBLE_ENV_FILE")
    path = Path(override) if override else Path(root) / ".env.local"
    if not path.exists():
        if override:
            raise FileNotFoundError("CRUCIBLE_ENV_FILE does not exist")
        return False
    if path.is_symlink():
        raise ValueError("credential file cannot be a symlink")
    if path.stat().st_mode & 0o077:
        raise PermissionError("credential file must be private: chmod 600")
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"credential file line {number} must be KEY=value")
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not _NAME.fullmatch(name):
            raise ValueError(f"credential file line {number} has an invalid key name")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if "\n" in value or "\r" in value:
            raise ValueError(f"credential file line {number} has an invalid value")
        os.environ.setdefault(name, value)
    return True
