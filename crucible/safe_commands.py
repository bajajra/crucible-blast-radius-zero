"""Small, non-shell command vocabulary for the disposable worker."""

from __future__ import annotations

import shlex


def parse_safe_command(command: str) -> list[str]:
    """Return argv for a bounded diagnostic command, never a shell program."""
    if not isinstance(command, str) or not command or len(command) > 256:
        raise ValueError("command is missing or too long")
    try:
        args = shlex.split(command, posix=True)
    except ValueError:
        raise ValueError("command quoting is invalid") from None
    if args in (["pwd"], ["hostname"], ["uname", "-a"]):
        return args
    if len(args) == 2 and args[0] == "sleep" and args[1].isdigit() and 0 <= int(args[1]) <= 20:
        return args
    if len(args) == 2 and args[0] == "cat" and args[1] in {
        "/work/scenario/reference.txt", "/work/scenario/README.md"
    }:
        return args
    if args in (["ls", "/work/scenario"], ["ls", "/work/output"]):
        return args
    raise ValueError("command is outside the bounded diagnostic vocabulary")
