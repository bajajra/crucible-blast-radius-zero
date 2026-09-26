#!/usr/bin/env python3
"""Fail closed unless Docker's effective runsc runtime enables OCI seccomp.

Docker's container inspect shows the requested runtime and seccomp JSON, but
does not show whether runsc was started with --oci-seccomp. Docker info exposes
the daemon's effective runtime path and arguments, which are checked here.
"""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys


RUNSC_RUNTIME = "runsc-oci"
RUNSC_ARGS = ["--oci-seccomp", "--network=sandbox", "--platform=systrap"]


def validate_entry(runtimes: object) -> Path:
    """Return the configured runsc path only for the exact sandbox runtime."""
    if not isinstance(runtimes, dict):
        raise ValueError("Docker did not report runtime configuration")
    entry = runtimes.get(RUNSC_RUNTIME)
    if not isinstance(entry, dict):
        raise ValueError("Docker has no runsc-oci runtime")
    path = entry.get("path")
    # Docker Engine's /info response serializes this field as runtimeArgs.
    args = entry.get("runtimeArgs")
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError("runsc-oci must use an absolute runtime path")
    if Path(path).name != "runsc":
        raise ValueError("runsc-oci must point directly to the runsc binary")
    if args != RUNSC_ARGS:
        raise ValueError("runsc-oci must enable OCI seccomp, sandbox networking, and systrap")
    return Path(path)


def verify() -> str:
    if os.environ.get("DOCKER_HOST") not in (None, "", "unix:///var/run/docker.sock"):
        raise ValueError("Docker must use the local rootful socket")
    contexts = json.loads(subprocess.check_output(["docker", "context", "inspect"], text=True))
    try:
        host = contexts[0]["Endpoints"]["docker"]["Host"]
    except (IndexError, KeyError, TypeError) as exc:
        raise ValueError("Docker context inspection was incomplete") from exc
    if host != "unix:///var/run/docker.sock":
        raise ValueError("Docker context must use the local rootful socket")
    raw = subprocess.check_output(
        ["docker", "info", "--format", "{{json .Runtimes}}"], text=True
    )
    configured = validate_entry(json.loads(raw))
    binary = configured.resolve(strict=True)
    details = binary.stat()
    if not stat.S_ISREG(details.st_mode) or not details.st_mode & stat.S_IXUSR:
        raise ValueError("runsc runtime path is not an executable regular file")
    if configured.is_symlink() and configured.lstat().st_uid != 0:
        raise ValueError("runsc runtime symlink must be root-owned")
    for candidate in (configured, *configured.parents, binary, *binary.parents):
        mode = candidate.stat()
        if mode.st_uid != 0 or mode.st_mode & 0o022:
            raise ValueError("runsc runtime path must be root-owned and not writable by others")
    version = subprocess.check_output([str(binary), "--version"], text=True, timeout=10)
    if not version.startswith("runsc version "):
        raise ValueError("runtime binary did not identify as runsc")
    return version.splitlines()[0]


def main() -> int:
    if sys.argv[1:] not in ([], ["--quiet"]):
        print("usage: verify-runtime.py [--quiet]", file=sys.stderr)
        return 2
    try:
        version = verify()
    except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
        print(f"UNVERIFIED: runsc-oci runtime: {exc}", file=sys.stderr)
        return 77
    if not sys.argv[1:]:
        print(f"runsc-oci runtime: verified ({version}; {', '.join(RUNSC_ARGS)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
