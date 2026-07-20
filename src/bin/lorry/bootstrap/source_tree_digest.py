#!/usr/bin/env python3
"""Compute the plan's lorry-source-tree-v1 digest for an exported source tree."""

import hashlib
import os
import stat
import struct
import sys
from pathlib import Path


def portable_path(path: Path, root: Path) -> bytes:
    relative = path.relative_to(root).as_posix()
    encoded = relative.encode("utf-8")
    if (
        not encoded
        or encoded.startswith(b"/")
        or b"\\" in encoded
        or b"\0" in encoded
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
        or any(component in ("", ".", "..") for component in relative.split("/"))
    ):
        raise ValueError(f"non-portable source path: {relative!r}")
    return encoded


def hash_file(path: Path) -> tuple[int, bytes]:
    before = path.stat(follow_symlinks=False)
    digest = hashlib.sha256()
    length = 0
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
            length += len(block)
    after = path.stat(follow_symlinks=False)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ValueError(f"source file changed while hashing: {path}")
    if length != before.st_size:
        raise ValueError(f"source file length changed while hashing: {path}")
    return length, digest.digest()


def source_tree_digest(root: Path) -> tuple[int, int, int, int, str]:
    if not root.is_dir():
        raise ValueError(f"source root is not a directory: {root}")

    entries: list[tuple[bytes, int, int, int, bytes]] = []
    file_count = 0
    directory_count = 0
    total_bytes = 0

    for directory, names, files in os.walk(root, followlinks=False):
        names[:] = [name for name in names if name != ".git"]
        files = [name for name in files if name != ".git"]
        current = Path(directory)

        for name in names:
            path = current / name
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(f"unsupported source entry: {path}")

        if current != root:
            entries.append((portable_path(current, root), 1, 0, 0, bytes(32)))
            directory_count += 1

        for name in files:
            path = current / name
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"unsupported source entry: {path}")
            length, content_digest = hash_file(path)
            executable = int(bool(metadata.st_mode & 0o111))
            entries.append(
                (
                    portable_path(path, root),
                    2,
                    executable,
                    length,
                    content_digest,
                )
            )
            file_count += 1
            total_bytes += length

    entries.sort(key=lambda entry: entry[0])
    digest = hashlib.sha256()
    digest.update(b"lorry-source-tree-v1\0")
    digest.update(struct.pack(">Q", len(entries)))
    for path, kind, executable, length, content_digest in entries:
        digest.update(struct.pack(">BBI", kind, executable, len(path)))
        digest.update(path)
        digest.update(struct.pack(">Q", length))
        digest.update(content_digest)

    return len(entries), file_count, directory_count, total_bytes, digest.hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} EXPORTED_SOURCE_TREE", file=sys.stderr)
        return 2
    try:
        entries, files, directories, total_bytes, digest = source_tree_digest(
            Path(sys.argv[1])
        )
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"entries={entries}")
    print(f"files={files}")
    print(f"directories={directories}")
    print(f"bytes={total_bytes}")
    print(f"source-tree-sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
