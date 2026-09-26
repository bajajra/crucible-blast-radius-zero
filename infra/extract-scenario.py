#!/usr/bin/env python3
"""Extract the bounded scenario stream inside /work tmpfs without link traversal."""

import os
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath

DESTINATION = Path("/work/scenario")
MAX_FILES = 512
MAX_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 1024
MAX_DEPTH = 16


def extract(stream) -> None:
    DESTINATION.mkdir(mode=0o700, parents=True, exist_ok=False)
    files = 0
    total = 0
    entries = 0
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
                raise ValueError("unsafe scenario path")
            entries += 1
            if entries > MAX_ENTRIES or len(path.parts) > MAX_DEPTH:
                raise ValueError("scenario exceeds entry or depth limit")
            target = DESTINATION.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            elif member.isfile():
                files += 1
                total += member.size
                if files > MAX_FILES or total > MAX_BYTES:
                    raise ValueError("scenario exceeds file or byte limit")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("scenario file has no content")
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as output:
                    shutil.copyfileobj(source, output)
            else:
                raise ValueError("scenario contains a link or special file")


if __name__ == "__main__":
    try:
        extract(sys.stdin.buffer)
    except (OSError, ValueError, tarfile.TarError) as exc:
        raise SystemExit(f"scenario extraction refused: {exc}") from exc
