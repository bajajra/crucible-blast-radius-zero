#!/usr/bin/env python3
"""Stream a bounded, regular-file-only scenario as a tar archive to stdout."""

import os
import stat
import sys
import tarfile
from pathlib import Path

MAX_FILES = 512
MAX_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 1024
MAX_DEPTH = 16


def stage(source: Path, output) -> None:
    count = 0
    total = 0
    entries_seen = 0
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(source, flags)
    try:
        with tarfile.open(fileobj=output, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            def walk(directory_fd: int, prefix: str) -> None:
                nonlocal count, total, entries_seen
                with os.scandir(directory_fd) as entries:
                    names = sorted(entry.name for entry in entries)
                for name in names:
                    if any(ord(char) < 32 or ord(char) == 127 for char in name):
                        raise ValueError("control character in scenario path")
                    relative = f"{prefix}/{name}" if prefix else name
                    entries_seen += 1
                    if entries_seen > MAX_ENTRIES or relative.count("/") >= MAX_DEPTH:
                        raise ValueError("scenario exceeds entry or depth limit")
                    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode):
                        child_fd = os.open(name, flags, dir_fd=directory_fd)
                        try:
                            if os.fstat(child_fd).st_ino != metadata.st_ino:
                                raise ValueError("scenario changed during staging")
                            info = tarfile.TarInfo(relative + "/")
                            info.type = tarfile.DIRTYPE
                            info.mode = 0o700
                            info.uid = info.gid = 10001
                            archive.addfile(info)
                            walk(child_fd, relative)
                        finally:
                            os.close(child_fd)
                    elif stat.S_ISREG(metadata.st_mode):
                        if metadata.st_nlink != 1:
                            raise ValueError("hard-linked scenario file rejected")
                        count += 1
                        total += metadata.st_size
                        if count > MAX_FILES or total > MAX_BYTES:
                            raise ValueError("scenario exceeds file or byte limit")
                        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                        try:
                            opened = os.fstat(fd)
                            if (not stat.S_ISREG(opened.st_mode) or
                                    opened.st_ino != metadata.st_ino or
                                    opened.st_size != metadata.st_size):
                                raise ValueError("scenario changed during staging")
                            info = tarfile.TarInfo(relative)
                            info.size = opened.st_size
                            info.mode = 0o600
                            info.uid = info.gid = 10001
                            with os.fdopen(fd, "rb", closefd=False) as stream:
                                archive.addfile(info, stream)
                        finally:
                            os.close(fd)
                    else:
                        raise ValueError("scenario contains a link or special file")
            walk(root_fd, "")
    finally:
        os.close(root_fd)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: stage-scenario.py <scenario_dir>")
    try:
        stage(Path(sys.argv[1]), sys.stdout.buffer)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"scenario staging refused: {exc}") from exc
