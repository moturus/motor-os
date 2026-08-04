#!/usr/bin/env python3
"""Validate and hash a source tree using the lorry-source-tree-v1 format."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


FORMAT_TAG = b"lorry-source-tree-v1\0"
ZERO_SHA256 = bytes(32)
EXCLUDED_DIRECTORY_NAMES = frozenset({".git", "target"})


@dataclass(frozen=True)
class SourceTreeLimits:
    max_entries: int = 40_000
    max_path_bytes: int = 4_096
    max_file_bytes: int = 134_217_728
    max_tree_bytes: int = 134_217_728


@dataclass(frozen=True)
class SourceEntry:
    path: str
    kind: int
    executable: bool
    length: int
    sha256: str

    def path_bytes(self) -> bytes:
        return self.path.encode("utf-8")

    def digest_bytes(self) -> bytes:
        return bytes.fromhex(self.sha256)

    def manifest_value(self) -> dict[str, object]:
        return {
            "executable": self.executable,
            "kind": "directory" if self.kind == 1 else "file",
            "length": self.length,
            "path": self.path,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class SourceTree:
    entries: tuple[SourceEntry, ...]
    file_count: int
    directory_count: int
    total_bytes: int
    sha256: str

    def manifest_bytes(self) -> bytes:
        value = {
            "entries": [entry.manifest_value() for entry in self.entries],
            "format-version": 1,
            "source-tree-sha256": self.sha256,
        }
        return (
            json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("utf-8")


def portable_path(path: Path, root: Path, limits: SourceTreeLimits) -> str:
    relative = path.relative_to(root).as_posix()
    encoded = relative.encode("utf-8")
    if (
        not encoded
        or len(encoded) > limits.max_path_bytes
        or encoded.startswith(b"/")
        or b"\\" in encoded
        or b"\0" in encoded
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
        or any(component in ("", ".", "..") for component in relative.split("/"))
    ):
        raise ValueError(f"non-portable source path: {relative!r}")
    return relative


def hash_file(path: Path, limits: SourceTreeLimits) -> tuple[int, bytes]:
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"unsupported source entry: {path}")
    if before.st_size > limits.max_file_bytes:
        raise ValueError(f"source file exceeds byte limit: {path}")

    digest = hashlib.sha256()
    length = 0
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
            length += len(block)
            if length > limits.max_file_bytes:
                raise ValueError(f"source file exceeds byte limit: {path}")

    after = path.stat(follow_symlinks=False)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ValueError(f"source file changed while hashing: {path}")
    if length != before.st_size:
        raise ValueError(f"source file length changed while hashing: {path}")
    return length, digest.digest()


def digest_entries(entries: Iterable[SourceEntry]) -> str:
    ordered = tuple(entries)
    digest = hashlib.sha256()
    digest.update(FORMAT_TAG)
    digest.update(struct.pack(">Q", len(ordered)))
    for entry in ordered:
        path = entry.path_bytes()
        digest.update(
            struct.pack(">BBI", entry.kind, int(entry.executable), len(path))
        )
        digest.update(path)
        digest.update(struct.pack(">Q", entry.length))
        digest.update(entry.digest_bytes())
    return digest.hexdigest()


def source_tree(
    root: Path,
    limits: SourceTreeLimits = SourceTreeLimits(),
    excluded_directory_names: frozenset[str] = EXCLUDED_DIRECTORY_NAMES,
) -> SourceTree:
    root_metadata = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError(f"source root is not a directory: {root}")

    entries: list[SourceEntry] = []
    file_count = 0
    directory_count = 0
    total_bytes = 0

    for directory, names, files in os.walk(root, followlinks=False):
        names[:] = [name for name in names if name not in excluded_directory_names]
        files = [
            name
            for name in files
            if not (name == ".git" and ".git" in excluded_directory_names)
        ]
        current = Path(directory)

        for name in names:
            path = current / name
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(f"unsupported source entry: {path}")
            portable_path(path, root, limits)

        if current != root:
            entries.append(
                SourceEntry(
                    portable_path(current, root, limits),
                    1,
                    False,
                    0,
                    ZERO_SHA256.hex(),
                )
            )
            directory_count += 1

        for name in files:
            path = current / name
            relative = portable_path(path, root, limits)
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"unsupported source entry: {path}")
            length, content_digest = hash_file(path, limits)
            total_bytes += length
            if total_bytes > limits.max_tree_bytes:
                raise ValueError("source tree exceeds byte limit")
            entries.append(
                SourceEntry(
                    relative,
                    2,
                    bool(metadata.st_mode & 0o111),
                    length,
                    content_digest.hex(),
                )
            )
            file_count += 1

        if len(entries) > limits.max_entries:
            raise ValueError("source tree exceeds entry-count limit")

    entries.sort(key=SourceEntry.path_bytes)
    result = tuple(entries)
    return SourceTree(
        result,
        file_count,
        directory_count,
        total_bytes,
        digest_entries(result),
    )


def source_tree_digest(root: Path) -> tuple[int, int, int, int, str]:
    """Compatibility interface used by the Phase 0 verification command."""
    result = source_tree(root)
    return (
        len(result.entries),
        result.file_count,
        result.directory_count,
        result.total_bytes,
        result.sha256,
    )


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} EXPORTED_SOURCE_TREE", file=sys.stderr)
        return 2
    try:
        result = source_tree(Path(sys.argv[1]))
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"entries={len(result.entries)}")
    print(f"files={result.file_count}")
    print(f"directories={result.directory_count}")
    print(f"bytes={result.total_bytes}")
    print(f"source-tree-sha256={result.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
