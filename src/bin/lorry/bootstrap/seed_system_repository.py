#!/usr/bin/env python3
"""Build a verified Lorry format-1 system repository on a Linux host."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable

from source_tree_digest import SourceTreeLimits, source_tree


CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
VERSION = re.compile(r"^[A-Za-z0-9.+-]+$")
GIT_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
RING_GIT_URL = "https://github.com/moturus/ring.git"
REPOSITORY_TOML = b'format-version = 1\nobject-hash = "sha256"\n'
ALLOWED_PAX_KEYS = frozenset({"path", "size"})
ZERO_BLOCK_BYTES = 1024
AT_FDCWD = -100
RENAME_NOREPLACE = 1


@dataclass(frozen=True)
class Limits:
    max_package_bytes: int
    max_extracted_package_bytes: int
    max_package_files: int
    max_path_bytes: int

    def source_limits(self) -> SourceTreeLimits:
        return SourceTreeLimits(
            max_entries=self.max_package_files * 2,
            max_path_bytes=self.max_path_bytes,
            max_file_bytes=self.max_extracted_package_bytes,
            max_tree_bytes=self.max_extracted_package_bytes,
        )


@dataclass(frozen=True)
class RegistryPackage:
    name: str
    version: str
    checksum: str
    license: str
    lock_graphs: tuple[str, ...]
    retained_archive: bool
    retained_source: bool
    allow_build_script: bool = False

    @property
    def archive_name(self) -> str:
        return f"{self.name}-{self.version}.crate"

    @property
    def archive_url(self) -> str:
        return (
            f"https://static.crates.io/crates/{self.name}/"
            f"{self.name}-{self.version}.crate"
        )

    @property
    def archive_root(self) -> str:
        return f"{self.name}-{self.version}"


@dataclass(frozen=True)
class SeededGitPackage:
    name: str
    version: str
    license: str
    upstream_checksum: str
    git_url: str
    requested_revision: str
    resolved_commit: str
    git_tree: str
    source_tree_sha256: str
    extracted_bytes: int
    file_count: int
    directory_count: int
    lock_graphs: tuple[str, ...]
    retained_source: bool


@dataclass(frozen=True)
class SeedManifest:
    limits: Limits
    registry: tuple[RegistryPackage, ...]
    seeded_git: tuple[SeededGitPackage, ...]


def require_keys(
    value: dict[str, object],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    context: str,
) -> None:
    keys = frozenset(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise ValueError(f"{context}: missing keys: {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"{context}: unknown keys: {', '.join(sorted(unknown))}")


def require_string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context}: expected a non-empty string")
    return value


def require_positive_integer(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{context}: expected a positive integer")
    return value


def require_boolean(value: object, context: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{context}: expected a boolean")
    return value


def require_hex(value: object, pattern: re.Pattern[str], context: str) -> str:
    text = require_string(value, context)
    if not pattern.fullmatch(text):
        raise ValueError(f"{context}: expected lowercase hexadecimal")
    return text


def require_strings(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{context}: expected a non-empty string array")
    result = tuple(require_string(item, context) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"{context}: duplicate value")
    return result


def load_seed_manifest(path: Path) -> SeedManifest:
    with path.open("rb") as source:
        value = tomllib.load(source)

    require_keys(
        value,
        required=frozenset(
            {
                "manifest-version",
                "repository-format-version",
                "object-hash",
                "production-registry-object-count",
                "limits",
                "lock-graph",
                "crates-io",
            }
        ),
        optional=frozenset({"seeded-git"}),
        context=str(path),
    )
    if value["manifest-version"] != 1:
        raise ValueError(f"{path}: unsupported manifest-version")
    if value["repository-format-version"] != 1:
        raise ValueError(f"{path}: unsupported repository-format-version")
    if value["object-hash"] != "sha256":
        raise ValueError(f"{path}: unsupported object-hash")

    raw_limits = value["limits"]
    if not isinstance(raw_limits, dict):
        raise ValueError(f"{path}: limits must be a table")
    require_keys(
        raw_limits,
        required=frozenset(
            {
                "max-package-bytes",
                "max-extracted-package-bytes",
                "max-package-files",
                "max-path-bytes",
            }
        ),
        context=f"{path}: limits",
    )
    limits = Limits(
        require_positive_integer(
            raw_limits["max-package-bytes"], "limits.max-package-bytes"
        ),
        require_positive_integer(
            raw_limits["max-extracted-package-bytes"],
            "limits.max-extracted-package-bytes",
        ),
        require_positive_integer(
            raw_limits["max-package-files"], "limits.max-package-files"
        ),
        require_positive_integer(
            raw_limits["max-path-bytes"], "limits.max-path-bytes"
        ),
    )

    raw_graphs = value["lock-graph"]
    if not isinstance(raw_graphs, list) or not raw_graphs:
        raise ValueError(f"{path}: lock-graph must be a non-empty array of tables")
    graph_ids = set()
    for index, graph in enumerate(raw_graphs):
        if not isinstance(graph, dict):
            raise ValueError(f"{path}: lock-graph {index} must be a table")
        require_keys(
            graph,
            required=frozenset({"id", "path"}),
            context=f"{path}: lock-graph {index}",
        )
        graph_id = require_string(graph["id"], f"lock-graph {index}.id")
        require_string(graph["path"], f"lock-graph {index}.path")
        if graph_id in graph_ids:
            raise ValueError(f"{path}: duplicate lock graph {graph_id!r}")
        graph_ids.add(graph_id)

    raw_registry = value["crates-io"]
    if not isinstance(raw_registry, list):
        raise ValueError(f"{path}: crates-io must be an array of tables")
    registry = []
    identities = set()
    checksums = set()
    for index, package in enumerate(raw_registry):
        context = f"{path}: crates-io {index}"
        if not isinstance(package, dict):
            raise ValueError(f"{context}: expected a table")
        require_keys(
            package,
            required=frozenset(
                {
                    "name",
                    "version",
                    "checksum",
                    "license",
                    "lock-graphs",
                    "retained-archive",
                    "retained-source",
                }
            ),
            optional=frozenset({"allow-build-script"}),
            context=context,
        )
        name = require_string(package["name"], f"{context}.name")
        version = require_string(package["version"], f"{context}.version")
        if not PACKAGE_NAME.fullmatch(name):
            raise ValueError(f"{context}.name: invalid package name")
        if not VERSION.fullmatch(version):
            raise ValueError(f"{context}.version: invalid package version")
        checksum = require_hex(package["checksum"], HEX_64, f"{context}.checksum")
        lock_graphs = require_strings(package["lock-graphs"], f"{context}.lock-graphs")
        if not set(lock_graphs) <= graph_ids:
            raise ValueError(f"{context}: references an unknown lock graph")
        identity = (name, version)
        if identity in identities:
            raise ValueError(f"{context}: duplicate package identity")
        if checksum in checksums:
            raise ValueError(f"{context}: duplicate package checksum")
        identities.add(identity)
        checksums.add(checksum)
        registry.append(
            RegistryPackage(
                name,
                version,
                checksum,
                require_string(package["license"], f"{context}.license"),
                lock_graphs,
                require_boolean(
                    package["retained-archive"], f"{context}.retained-archive"
                ),
                require_boolean(
                    package["retained-source"], f"{context}.retained-source"
                ),
                require_boolean(
                    package.get("allow-build-script", False),
                    f"{context}.allow-build-script",
                ),
            )
        )

    expected_count = require_positive_integer(
        value["production-registry-object-count"],
        "production-registry-object-count",
    )
    if len(registry) != expected_count:
        raise ValueError(
            f"{path}: expected {expected_count} registry objects, found {len(registry)}"
        )

    raw_seeded_git = value.get("seeded-git", [])
    if not isinstance(raw_seeded_git, list):
        raise ValueError(f"{path}: seeded-git must be an array of tables")
    seeded_git = []
    for index, package in enumerate(raw_seeded_git):
        context = f"{path}: seeded-git {index}"
        if not isinstance(package, dict):
            raise ValueError(f"{context}: expected a table")
        require_keys(
            package,
            required=frozenset(
                {
                    "name",
                    "version",
                    "license",
                    "upstream-crates-io-checksum",
                    "git-url",
                    "requested-revision",
                    "resolved-commit",
                    "git-tree",
                    "source-tree-sha256",
                    "extracted-bytes",
                    "file-count",
                    "directory-count",
                    "lock-graphs",
                    "retained-source",
                }
            ),
            context=context,
        )
        name = require_string(package["name"], f"{context}.name")
        version = require_string(package["version"], f"{context}.version")
        if not PACKAGE_NAME.fullmatch(name) or not VERSION.fullmatch(version):
            raise ValueError(f"{context}: invalid package identity")
        git_url = require_string(package["git-url"], f"{context}.git-url")
        if git_url != RING_GIT_URL:
            raise ValueError(f"{context}: unsupported seeded-Git URL")
        requested_revision = require_string(
            package["requested-revision"], f"{context}.requested-revision"
        )
        if (
            not GIT_REVISION.fullmatch(requested_revision)
            or ".." in requested_revision
            or requested_revision.endswith(("/", "."))
        ):
            raise ValueError(f"{context}: unsafe requested revision")
        lock_graphs = require_strings(package["lock-graphs"], f"{context}.lock-graphs")
        if not set(lock_graphs) <= graph_ids:
            raise ValueError(f"{context}: references an unknown lock graph")
        seeded_git.append(
            SeededGitPackage(
                name,
                version,
                require_string(package["license"], f"{context}.license"),
                require_hex(
                    package["upstream-crates-io-checksum"],
                    HEX_64,
                    f"{context}.upstream-crates-io-checksum",
                ),
                git_url,
                requested_revision,
                require_hex(
                    package["resolved-commit"], HEX_40, f"{context}.resolved-commit"
                ),
                require_hex(package["git-tree"], HEX_40, f"{context}.git-tree"),
                require_hex(
                    package["source-tree-sha256"],
                    HEX_64,
                    f"{context}.source-tree-sha256",
                ),
                require_positive_integer(
                    package["extracted-bytes"], f"{context}.extracted-bytes"
                ),
                require_positive_integer(
                    package["file-count"], f"{context}.file-count"
                ),
                require_positive_integer(
                    package["directory-count"], f"{context}.directory-count"
                ),
                lock_graphs,
                require_boolean(
                    package["retained-source"], f"{context}.retained-source"
                ),
            )
        )

    return SeedManifest(limits, tuple(registry), tuple(seeded_git))


def crates_index_path(name: str) -> str:
    lowered = name.lower()
    if len(lowered) == 1:
        return f"1/{lowered}"
    if len(lowered) == 2:
        return f"2/{lowered}"
    if len(lowered) == 3:
        return f"3/{lowered[0]}/{lowered}"
    return f"{lowered[:2]}/{lowered[2:4]}/{lowered}"


def json_object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def validate_index_record(package: RegistryPackage, line: bytes) -> None:
    try:
        value = json.loads(
            line,
            object_pairs_hook=json_object_no_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{package.name}: malformed sparse-index record: {error}")
    if not isinstance(value, dict):
        raise ValueError(f"{package.name}: sparse-index record is not an object")
    if value.get("name") != package.name:
        raise ValueError(f"{package.name}: sparse-index name mismatch")
    if value.get("vers") != package.version:
        raise ValueError(f"{package.name}: sparse-index version mismatch")
    if value.get("cksum") != package.checksum:
        raise ValueError(f"{package.name}: sparse-index checksum mismatch")


class HttpsRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_repeats = 5
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if (
            old.scheme != "https"
            or new.scheme != "https"
            or new.username is not None
            or new.password is not None
        ):
            raise ValueError("bootstrap download rejected an unsafe redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def ssl_context(ca_bundle: Path | None) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)


def fetch_bytes(
    url: str,
    *,
    expected_host: str,
    limit: int,
    ca_bundle: Path | None,
) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(f"unsafe bootstrap URL: {url}")
    opener = urllib.request.build_opener(
        HttpsRedirectHandler(),
        urllib.request.HTTPSHandler(context=ssl_context(ca_bundle)),
    )
    request = urllib.request.Request(url, headers={"User-Agent": "motor-lorry-seeder/1"})
    with opener.open(request, timeout=30) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != expected_host:
            raise ValueError(f"bootstrap download escaped {expected_host}")
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) > limit:
            raise ValueError(f"bootstrap download exceeds {limit} bytes")
        output = bytearray()
        while block := response.read(min(1024 * 1024, limit + 1 - len(output))):
            output.extend(block)
            if len(output) > limit:
                raise ValueError(f"bootstrap download exceeds {limit} bytes")
        return bytes(output)


def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
    finally:
        os.close(descriptor)


def rename_no_replace(source: Path, destination: Path) -> None:
    """Atomically rename a directory without replacing any destination."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(
            errno.ENOSYS,
            "the Stage 2 host seeder requires renameat2(RENAME_NOREPLACE)",
        )
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error in (errno.EEXIST, errno.ENOTEMPTY):
            raise FileExistsError(error, os.strerror(error), destination)
        raise OSError(error, os.strerror(error), destination)


def atomic_cache_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with temporary.open("wb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != data:
                raise ValueError(f"corrupt bootstrap cache entry: {path}")
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def read_bounded_file(path: Path, limit: int, context: str) -> bytes:
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{context}: cache entry is not a regular file")
    if before.st_size > limit:
        raise ValueError(f"{context}: cache entry exceeds {limit} bytes")
    output = bytearray()
    with path.open("rb") as source:
        while block := source.read(min(1024 * 1024, limit + 1 - len(output))):
            output.extend(block)
            if len(output) > limit:
                raise ValueError(f"{context}: cache entry exceeds {limit} bytes")
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
        raise ValueError(f"{context}: cache entry changed while reading")
    return bytes(output)


def cached_or_fetch_archive(
    package: RegistryPackage,
    limits: Limits,
    cache: Path | None,
    offline: bool,
    ca_bundle: Path | None,
) -> bytes:
    cache_path = cache / "archives" / package.archive_name if cache else None
    if cache_path and cache_path.exists():
        data = read_bounded_file(
            cache_path, limits.max_package_bytes, package.archive_name
        )
    else:
        if offline:
            raise ValueError(f"offline cache is missing {package.archive_name}")
        data = fetch_bytes(
            package.archive_url,
            expected_host="static.crates.io",
            limit=limits.max_package_bytes,
            ca_bundle=ca_bundle,
        )
        if cache_path:
            atomic_cache_write(cache_path, data)
    if len(data) > limits.max_package_bytes:
        raise ValueError(f"{package.archive_name}: compressed-byte limit exceeded")
    actual = hashlib.sha256(data).hexdigest()
    if actual != package.checksum:
        raise ValueError(
            f"{package.archive_name}: checksum mismatch: expected "
            f"{package.checksum}, got {actual}"
        )
    return data


def cached_or_fetch_index_record(
    package: RegistryPackage,
    cache: Path | None,
    offline: bool,
    ca_bundle: Path | None,
) -> bytes:
    filename = f"{package.name}-{package.version}.json"
    cache_path = cache / "index-records" / filename if cache else None
    if cache_path and cache_path.exists():
        line = read_bounded_file(cache_path, 16_777_216, filename)
    else:
        if offline:
            raise ValueError(f"offline cache is missing index record {filename}")
        path = crates_index_path(package.name)
        body = fetch_bytes(
            f"https://index.crates.io/{path}",
            expected_host="index.crates.io",
            limit=16_777_216,
            ca_bundle=ca_bundle,
        )
        matches = []
        for candidate in body.splitlines():
            try:
                value = json.loads(candidate)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (
                isinstance(value, dict)
                and value.get("name") == package.name
                and value.get("vers") == package.version
            ):
                matches.append(candidate + b"\n")
        if len(matches) != 1:
            raise ValueError(
                f"{package.name}: sparse index has {len(matches)} records "
                f"for version {package.version}"
            )
        line = matches[0]
        if cache_path:
            atomic_cache_write(cache_path, line)
    if not line.endswith(b"\n") or b"\n" in line[:-1]:
        raise ValueError(f"{package.name}: cached index record is not one line")
    validate_index_record(package, line)
    return line


def validate_archive_path(name: str, package: RegistryPackage, limits: Limits) -> str:
    if name.endswith("/"):
        name = name[:-1]
    try:
        encoded = name.encode("utf-8")
    except UnicodeError as error:
        raise ValueError(f"{package.archive_name}: non-UTF-8 archive path") from error
    if (
        not encoded
        or len(encoded) > limits.max_path_bytes + len(package.archive_root) + 1
        or encoded.startswith(b"/")
        or b"\\" in encoded
        or b"\0" in encoded
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
    ):
        raise ValueError(f"{package.archive_name}: unsafe archive path {name!r}")
    components = name.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise ValueError(f"{package.archive_name}: unsafe archive path {name!r}")
    if components[0] != package.archive_root:
        raise ValueError(
            f"{package.archive_name}: entry is outside {package.archive_root}/"
        )
    if len(components) == 1:
        return ""
    relative = "/".join(components[1:])
    if len(relative.encode("utf-8")) > limits.max_path_bytes:
        raise ValueError(f"{package.archive_name}: extracted path exceeds limit")
    return relative


def ensure_real_directories(root: Path, relative_parent: str) -> None:
    current = root
    if not relative_parent:
        return
    for component in relative_parent.split("/"):
        current = current / component
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            metadata = current.stat(follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(f"archive parent is not a directory: {current}")


def decompress_single_gzip(
    archive: Path,
    destination: Path,
    limits: Limits,
) -> None:
    maximum = (
        limits.max_extracted_package_bytes
        + limits.max_package_files * 4096
        + 1024 * 1024
    )
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    written = 0
    with archive.open("rb") as source, destination.open("xb") as output:
        while block := source.read(1024 * 1024):
            inflated = decompressor.decompress(block)
            if decompressor.unused_data:
                raise ValueError("gzip archive has trailing data or multiple members")
            written += len(inflated)
            if written > maximum:
                raise ValueError("expanded tar stream exceeds limit")
            output.write(inflated)
        inflated = decompressor.flush()
        written += len(inflated)
        if written > maximum:
            raise ValueError("expanded tar stream exceeds limit")
        output.write(inflated)
        output.flush()
        os.fsync(output.fileno())
    if not decompressor.eof or decompressor.unused_data:
        raise ValueError("truncated or non-canonical gzip archive")


def extract_registry_archive(
    archive: Path,
    destination: Path,
    package: RegistryPackage,
    limits: Limits,
) -> None:
    destination.mkdir(mode=0o700)
    raw_tar = archive.with_suffix(".tar")
    decompress_single_gzip(archive, raw_tar, limits)
    seen = {}
    root_seen = False
    file_count = 0
    total_bytes = 0
    final_offset = 0
    try:
        with tarfile.open(raw_tar, mode="r|") as source:
            if source.pax_headers:
                raise ValueError(f"{package.archive_name}: global PAX headers rejected")
            for member in source:
                if set(member.pax_headers) - ALLOWED_PAX_KEYS:
                    raise ValueError(
                        f"{package.archive_name}: unsupported PAX keys "
                        f"{sorted(set(member.pax_headers) - ALLOWED_PAX_KEYS)}"
                    )
                relative = validate_archive_path(member.name, package, limits)
                if not relative:
                    if not member.isdir():
                        raise ValueError(
                            f"{package.archive_name}: archive root is not a directory"
                        )
                    if root_seen:
                        raise ValueError(
                            f"{package.archive_name}: duplicate archive root"
                        )
                    root_seen = True
                    continue
                if relative in seen:
                    raise ValueError(
                        f"{package.archive_name}: duplicate archive entry {relative!r}"
                    )
                seen[relative] = "directory" if member.isdir() else "file"
                parent = relative.rpartition("/")[0]
                ensure_real_directories(destination, parent)
                output_path = destination.joinpath(*relative.split("/"))

                if member.isdir():
                    try:
                        output_path.mkdir(mode=0o700)
                    except FileExistsError:
                        metadata = output_path.stat(follow_symlinks=False)
                        if not stat.S_ISDIR(metadata.st_mode):
                            raise ValueError(
                                f"{package.archive_name}: conflicting entry {relative!r}"
                            )
                    continue
                if not member.isreg():
                    raise ValueError(
                        f"{package.archive_name}: unsupported archive entry "
                        f"{relative!r}"
                    )
                if member.size > limits.max_extracted_package_bytes:
                    raise ValueError(
                        f"{package.archive_name}: file exceeds extracted-byte limit"
                    )
                total_bytes += member.size
                file_count += 1
                if total_bytes > limits.max_extracted_package_bytes:
                    raise ValueError(
                        f"{package.archive_name}: extracted-byte limit exceeded"
                    )
                if file_count > limits.max_package_files:
                    raise ValueError(
                        f"{package.archive_name}: file-count limit exceeded"
                    )
                extracted = source.extractfile(member)
                if extracted is None:
                    raise ValueError(
                        f"{package.archive_name}: cannot read {relative!r}"
                    )
                mode = 0o700 if member.mode & 0o111 else 0o600
                descriptor = os.open(
                    output_path,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    mode,
                )
                copied = 0
                try:
                    with os.fdopen(descriptor, "wb", closefd=False) as output:
                        while block := extracted.read(1024 * 1024):
                            copied += len(block)
                            if copied > member.size:
                                raise ValueError(
                                    f"{package.archive_name}: entry size mismatch"
                                )
                            output.write(block)
                        output.flush()
                        os.fsync(output.fileno())
                finally:
                    os.close(descriptor)
                if copied != member.size:
                    raise ValueError(
                        f"{package.archive_name}: truncated entry {relative!r}"
                    )
            final_offset = source.offset

        with raw_tar.open("rb") as source:
            source.seek(final_offset)
            trailing = source.read()
        if len(trailing) < ZERO_BLOCK_BYTES or any(trailing):
            raise ValueError(
                f"{package.archive_name}: malformed or nonzero tar trailer"
            )
    finally:
        raw_tar.unlink(missing_ok=True)


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def registry_package_toml(
    package: RegistryPackage,
    archive_bytes: int,
    tree,
) -> bytes:
    return (
        "format-version = 1\n"
        f"name = {toml_string(package.name)}\n"
        f"version = {toml_string(package.version)}\n"
        f"source = {toml_string(CRATES_IO_SOURCE)}\n"
        f"checksum = {toml_string(package.checksum)}\n"
        f"license = {toml_string(package.license)}\n"
        f"archive-bytes = {archive_bytes}\n"
        f"extracted-bytes = {tree.total_bytes}\n"
        f"file-count = {tree.file_count}\n"
        f"directory-count = {tree.directory_count}\n"
        f"source-tree-sha256 = {toml_string(tree.sha256)}\n"
        f"retained-archive = {str(package.retained_archive).lower()}\n"
        f"retained-source = {str(package.retained_source).lower()}\n"
    ).encode("utf-8")


def registry_object_path(repository: Path, checksum: str) -> Path:
    return repository / "objects/crates-io/sha256" / checksum[:2] / checksum


def build_registry_object(
    repository: Path,
    package: RegistryPackage,
    archive_data: bytes,
    index_record: bytes,
    limits: Limits,
) -> Path:
    object_path = registry_object_path(repository, package.checksum)
    object_path.mkdir(parents=True, mode=0o700)
    archive = object_path / "package.crate"
    write_exclusive(archive, archive_data)
    source = object_path / "source"
    extract_registry_archive(archive, source, package, limits)
    tree = source_tree(
        source,
        limits.source_limits(),
        excluded_directory_names=frozenset(),
    )
    write_exclusive(object_path / "source-manifest.json", tree.manifest_bytes())
    write_exclusive(object_path / "index-record.json", index_record)
    write_exclusive(
        object_path / "package.toml",
        registry_package_toml(package, len(archive_data), tree),
    )
    fsync_tree(object_path)
    verify_registry_object(object_path, package, limits)
    return object_path


def verify_registry_object(
    object_path: Path,
    package: RegistryPackage,
    limits: Limits,
) -> None:
    actual_entries = {entry.name for entry in object_path.iterdir()}
    expected_entries = {
        "package.toml",
        "index-record.json",
        "package.crate",
        "source",
        "source-manifest.json",
    }
    if actual_entries != expected_entries:
        raise ValueError(
            f"{object_path}: object entries mismatch: "
            f"expected {sorted(expected_entries)}, got {sorted(actual_entries)}"
        )
    metadata_path = object_path / "package.toml"
    with metadata_path.open("rb") as source:
        metadata = tomllib.load(source)
    required = frozenset(
        {
            "format-version",
            "name",
            "version",
            "source",
            "checksum",
            "license",
            "archive-bytes",
            "extracted-bytes",
            "file-count",
            "directory-count",
            "source-tree-sha256",
            "retained-archive",
            "retained-source",
        }
    )
    require_keys(metadata, required=required, context=str(metadata_path))
    expected = {
        "format-version": 1,
        "name": package.name,
        "version": package.version,
        "source": CRATES_IO_SOURCE,
        "checksum": package.checksum,
        "license": package.license,
        "retained-archive": package.retained_archive,
        "retained-source": package.retained_source,
    }
    for key, value in expected.items():
        if metadata[key] != value:
            raise ValueError(f"{metadata_path}: {key} mismatch")

    archive = object_path / "package.crate"
    if not archive.is_file():
        raise ValueError(f"{object_path}: retained archive is missing")
    archive_digest = hashlib.sha256()
    archive_bytes = 0
    with archive.open("rb") as source:
        while block := source.read(1024 * 1024):
            archive_digest.update(block)
            archive_bytes += len(block)
            if archive_bytes > limits.max_package_bytes:
                raise ValueError(f"{object_path}: archive exceeds byte limit")
    if archive_digest.hexdigest() != package.checksum:
        raise ValueError(f"{object_path}: retained archive checksum mismatch")
    if metadata["archive-bytes"] != archive_bytes:
        raise ValueError(f"{object_path}: archive byte count mismatch")

    index_record = (object_path / "index-record.json").read_bytes()
    validate_index_record(package, index_record)
    tree = source_tree(
        object_path / "source",
        limits.source_limits(),
        excluded_directory_names=frozenset(),
    )
    if metadata["extracted-bytes"] != tree.total_bytes:
        raise ValueError(f"{object_path}: extracted byte count mismatch")
    if metadata["file-count"] != tree.file_count:
        raise ValueError(f"{object_path}: file count mismatch")
    if metadata["directory-count"] != tree.directory_count:
        raise ValueError(f"{object_path}: directory count mismatch")
    if metadata["source-tree-sha256"] != tree.sha256:
        raise ValueError(f"{object_path}: source-tree digest mismatch")
    manifest = (object_path / "source-manifest.json").read_bytes()
    if manifest != tree.manifest_bytes():
        raise ValueError(f"{object_path}: source manifest mismatch")


def git_program() -> str:
    program = shutil.which("git")
    if program is None or not Path(program).is_absolute():
        raise ValueError("host git executable was not found")
    return program


def run_git(
    arguments: list[str],
    *,
    cwd: Path,
    timeout: int = 120,
) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    try:
        result = subprocess.run(
            [git_program(), *arguments],
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"git command timed out: {' '.join(arguments)}") from error
    if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise ValueError("git command output exceeded bootstrap limit")
    if result.returncode != 0:
        diagnostic = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(
            f"git command failed ({' '.join(arguments)}): {diagnostic}"
        )
    return result.stdout


def git_cache_path(cache: Path, package: SeededGitPackage) -> Path:
    return cache / "seeded-git" / f"{package.resolved_commit}.git"


def verify_git_cache(path: Path, package: SeededGitPackage) -> None:
    if not path.is_dir():
        raise ValueError(f"Git cache entry is not a repository: {path}")
    commit = (
        run_git(
            ["rev-parse", "--verify", f"refs/lorry-seed/{package.name}^{{commit}}"],
            cwd=path,
        )
        .decode("ascii")
        .strip()
    )
    if commit != package.resolved_commit:
        raise ValueError(f"Git cache commit mismatch: {path}")
    tree = (
        run_git(
            ["rev-parse", "--verify", f"{commit}^{{tree}}"],
            cwd=path,
        )
        .decode("ascii")
        .strip()
    )
    if tree != package.git_tree:
        raise ValueError(f"Git cache tree mismatch: {path}")


def acquire_git_repository(
    package: SeededGitPackage,
    work: Path,
    *,
    cache: Path | None,
    offline: bool,
    allow_local_git: bool = False,
) -> Path:
    repository = work / "git"
    repository.mkdir(mode=0o700)
    run_git(["init", "--quiet"], cwd=repository)
    protocol = "always" if allow_local_git else "never"
    fetch_prefix = ["-c", f"protocol.file.allow={protocol}"]

    cached_repository = git_cache_path(cache, package) if cache else None
    if offline:
        if cached_repository is None or not cached_repository.exists():
            raise ValueError(
                f"offline cache is missing Git object for {package.resolved_commit}"
            )
        verify_git_cache(cached_repository, package)
        run_git(
            [
                "-c",
                "protocol.file.allow=always",
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth=1",
                str(cached_repository),
                f"refs/lorry-seed/{package.name}",
            ],
            cwd=repository,
        )
    else:
        if not allow_local_git and package.git_url != RING_GIT_URL:
            raise ValueError(f"unsupported seeded-Git URL: {package.git_url}")
        run_git(["remote", "add", "origin", package.git_url], cwd=repository)
        revision = f"refs/heads/{package.requested_revision}"
        run_git(
            [
                *fetch_prefix,
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth=1",
                "origin",
                revision,
            ],
            cwd=repository,
            timeout=300,
        )

    commit = (
        run_git(["rev-parse", "--verify", "FETCH_HEAD^{commit}"], cwd=repository)
        .decode("ascii")
        .strip()
    )
    if commit != package.resolved_commit:
        raise ValueError(
            f"{package.name}: resolved Git commit mismatch: expected "
            f"{package.resolved_commit}, got {commit}"
        )
    tree = (
        run_git(
            ["rev-parse", "--verify", f"{package.resolved_commit}^{{tree}}"],
            cwd=repository,
        )
        .decode("ascii")
        .strip()
    )
    if tree != package.git_tree:
        raise ValueError(
            f"{package.name}: Git tree mismatch: expected {package.git_tree}, got {tree}"
        )

    if not offline and cached_repository is not None:
        reference = f"refs/lorry-seed/{package.name}"
        run_git(
            ["update-ref", reference, package.resolved_commit],
            cwd=repository,
        )
        temporary_cache = work / "download.git"
        run_git(
            ["init", "--quiet", "--bare", str(temporary_cache)],
            cwd=work,
        )
        run_git(
            [
                "-c",
                "protocol.file.allow=always",
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth=1",
                str(repository),
                reference,
            ],
            cwd=temporary_cache,
        )
        run_git(
            ["update-ref", reference, "FETCH_HEAD"],
            cwd=temporary_cache,
        )
        fsync_tree(temporary_cache)
        cached_repository.parent.mkdir(parents=True, exist_ok=True)
        if cached_repository.exists():
            verify_git_cache(cached_repository, package)
        else:
            try:
                rename_no_replace(temporary_cache, cached_repository)
            except FileExistsError:
                verify_git_cache(cached_repository, package)
            fsync_directory(cached_repository.parent)
        verify_git_cache(cached_repository, package)

    return repository


def portable_git_path(
    name: str,
    package: SeededGitPackage,
    limits: Limits,
) -> str:
    if name.endswith("/"):
        name = name[:-1]
    try:
        encoded = name.encode("utf-8")
    except UnicodeError as error:
        raise ValueError(f"{package.name}: non-UTF-8 Git path") from error
    if (
        not encoded
        or len(encoded) > limits.max_path_bytes
        or encoded.startswith(b"/")
        or b"\\" in encoded
        or b"\0" in encoded
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
        or any(component in ("", ".", "..") for component in name.split("/"))
    ):
        raise ValueError(f"{package.name}: unsafe Git path {name!r}")
    return name


def extract_git_archive(
    archive: Path,
    destination: Path,
    package: SeededGitPackage,
    limits: Limits,
) -> None:
    destination.mkdir(mode=0o700)
    seen = {}
    file_count = 0
    total_bytes = 0
    final_offset = 0
    with tarfile.open(archive, mode="r|") as source:
        for member in source:
            pax_headers = dict(member.pax_headers)
            comment = pax_headers.pop("comment", None)
            if comment is not None and comment != package.resolved_commit:
                raise ValueError(
                    f"{package.name}: Git archive commit comment mismatch"
                )
            if set(pax_headers) - ALLOWED_PAX_KEYS:
                raise ValueError(
                    f"{package.name}: unsupported Git archive PAX keys "
                    f"{sorted(set(pax_headers) - ALLOWED_PAX_KEYS)}"
                )
            relative = portable_git_path(member.name, package, limits)
            if relative in seen:
                raise ValueError(
                    f"{package.name}: duplicate Git archive entry {relative!r}"
                )
            seen[relative] = "directory" if member.isdir() else "file"

            if not (member.isdir() or member.isreg()):
                raise ValueError(
                    f"{package.name}: unsupported Git entry {relative!r}"
                )
            if any(
                component in (".git", "target")
                for component in relative.split("/")
            ):
                continue

            parent = relative.rpartition("/")[0]
            ensure_real_directories(destination, parent)
            output_path = destination.joinpath(*relative.split("/"))
            if member.isdir():
                try:
                    output_path.mkdir(mode=0o700)
                except FileExistsError:
                    metadata = output_path.stat(follow_symlinks=False)
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise ValueError(
                            f"{package.name}: conflicting Git entry {relative!r}"
                        )
                continue

            if member.size > limits.max_extracted_package_bytes:
                raise ValueError(f"{package.name}: Git file exceeds byte limit")
            total_bytes += member.size
            file_count += 1
            if total_bytes > limits.max_extracted_package_bytes:
                raise ValueError(f"{package.name}: Git tree exceeds byte limit")
            if file_count > limits.max_package_files:
                raise ValueError(f"{package.name}: Git tree exceeds file-count limit")
            extracted = source.extractfile(member)
            if extracted is None:
                raise ValueError(f"{package.name}: cannot read {relative!r}")
            mode = 0o700 if member.mode & 0o111 else 0o600
            descriptor = os.open(
                output_path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                mode,
            )
            copied = 0
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as output:
                    while block := extracted.read(1024 * 1024):
                        copied += len(block)
                        if copied > member.size:
                            raise ValueError(
                                f"{package.name}: Git entry size mismatch"
                            )
                        output.write(block)
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                os.close(descriptor)
            if copied != member.size:
                raise ValueError(f"{package.name}: truncated Git entry {relative!r}")
        final_offset = source.offset

    with archive.open("rb") as source:
        source.seek(final_offset)
        trailing = source.read()
    if len(trailing) < ZERO_BLOCK_BYTES or any(trailing):
        raise ValueError(f"{package.name}: malformed or nonzero Git tar trailer")


def cargo_git_source(package: SeededGitPackage) -> str:
    revision = urllib.parse.quote(package.requested_revision, safe="/")
    return (
        f"git+{package.git_url}?branch={revision}"
        f"#{package.resolved_commit}"
    )


def seeded_git_package_toml(package: SeededGitPackage, tree) -> bytes:
    return (
        "format-version = 1\n"
        f"name = {toml_string(package.name)}\n"
        f"version = {toml_string(package.version)}\n"
        f"cargo-source = {toml_string(cargo_git_source(package))}\n"
        f"git-url = {toml_string(package.git_url)}\n"
        f"requested-revision = {toml_string(package.requested_revision)}\n"
        f"resolved-commit = {toml_string(package.resolved_commit)}\n"
        f"git-tree = {toml_string(package.git_tree)}\n"
        f"upstream-crates-io-checksum = "
        f"{toml_string(package.upstream_checksum)}\n"
        f"source-tree-sha256 = {toml_string(tree.sha256)}\n"
        f"license = {toml_string(package.license)}\n"
        f"extracted-bytes = {tree.total_bytes}\n"
        f"file-count = {tree.file_count}\n"
        f"directory-count = {tree.directory_count}\n"
        f"retained-source = {str(package.retained_source).lower()}\n"
    ).encode("utf-8")


def seeded_git_object_path(repository: Path, source_tree_sha256: str) -> Path:
    return (
        repository
        / "objects/seeded-git/sha256"
        / source_tree_sha256[:2]
        / source_tree_sha256
    )


def build_seeded_git_object(
    repository: Path,
    package: SeededGitPackage,
    acquisition_root: Path,
    limits: Limits,
    *,
    cache: Path | None,
    offline: bool,
    allow_local_git: bool = False,
) -> Path:
    git_repository = acquire_git_repository(
        package,
        acquisition_root,
        cache=cache,
        offline=offline,
        allow_local_git=allow_local_git,
    )
    archive = acquisition_root / "source.tar"
    run_git(
        [
            "archive",
            "--format=tar",
            f"--output={archive}",
            package.resolved_commit,
        ],
        cwd=git_repository,
    )

    object_path = seeded_git_object_path(repository, package.source_tree_sha256)
    object_path.mkdir(parents=True, mode=0o700)
    source = object_path / "source"
    extract_git_archive(archive, source, package, limits)
    tree = source_tree(
        source,
        limits.source_limits(),
        excluded_directory_names=frozenset(),
    )
    if tree.sha256 != package.source_tree_sha256:
        raise ValueError(
            f"{package.name}: source-tree digest mismatch: expected "
            f"{package.source_tree_sha256}, got {tree.sha256}"
        )
    if tree.total_bytes != package.extracted_bytes:
        raise ValueError(f"{package.name}: extracted byte count mismatch")
    if tree.file_count != package.file_count:
        raise ValueError(f"{package.name}: file count mismatch")
    if tree.directory_count != package.directory_count:
        raise ValueError(f"{package.name}: directory count mismatch")

    write_exclusive(object_path / "source-manifest.json", tree.manifest_bytes())
    write_exclusive(
        object_path / "package.toml",
        seeded_git_package_toml(package, tree),
    )
    fsync_tree(object_path)
    verify_seeded_git_object(object_path, package, limits)
    return object_path


def verify_seeded_git_object(
    object_path: Path,
    package: SeededGitPackage,
    limits: Limits,
) -> None:
    actual_entries = {entry.name for entry in object_path.iterdir()}
    expected_entries = {"package.toml", "source", "source-manifest.json"}
    if actual_entries != expected_entries:
        raise ValueError(
            f"{object_path}: object entries mismatch: "
            f"expected {sorted(expected_entries)}, got {sorted(actual_entries)}"
        )
    metadata_path = object_path / "package.toml"
    with metadata_path.open("rb") as source:
        metadata = tomllib.load(source)
    required = frozenset(
        {
            "format-version",
            "name",
            "version",
            "cargo-source",
            "git-url",
            "requested-revision",
            "resolved-commit",
            "git-tree",
            "upstream-crates-io-checksum",
            "source-tree-sha256",
            "license",
            "extracted-bytes",
            "file-count",
            "directory-count",
            "retained-source",
        }
    )
    require_keys(metadata, required=required, context=str(metadata_path))
    expected = {
        "format-version": 1,
        "name": package.name,
        "version": package.version,
        "cargo-source": cargo_git_source(package),
        "git-url": package.git_url,
        "requested-revision": package.requested_revision,
        "resolved-commit": package.resolved_commit,
        "git-tree": package.git_tree,
        "upstream-crates-io-checksum": package.upstream_checksum,
        "source-tree-sha256": package.source_tree_sha256,
        "license": package.license,
        "extracted-bytes": package.extracted_bytes,
        "file-count": package.file_count,
        "directory-count": package.directory_count,
        "retained-source": package.retained_source,
    }
    for key, value in expected.items():
        if metadata[key] != value:
            raise ValueError(f"{metadata_path}: {key} mismatch")
    tree = source_tree(
        object_path / "source",
        limits.source_limits(),
        excluded_directory_names=frozenset(),
    )
    if tree.sha256 != package.source_tree_sha256:
        raise ValueError(f"{object_path}: source-tree digest mismatch")
    if tree.total_bytes != package.extracted_bytes:
        raise ValueError(f"{object_path}: extracted byte count mismatch")
    if tree.file_count != package.file_count:
        raise ValueError(f"{object_path}: file count mismatch")
    if tree.directory_count != package.directory_count:
        raise ValueError(f"{object_path}: directory count mismatch")
    if (object_path / "source-manifest.json").read_bytes() != tree.manifest_bytes():
        raise ValueError(f"{object_path}: source manifest mismatch")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_tree(root: Path) -> None:
    directories = []
    for directory, names, files in os.walk(root, followlinks=False):
        current = Path(directory)
        directories.append(current)
        for name in names:
            path = current / name
            if not stat.S_ISDIR(path.stat(follow_symlinks=False).st_mode):
                raise ValueError(f"cannot fsync special repository entry: {path}")
        for name in files:
            path = current / name
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"cannot fsync special repository entry: {path}")
            with path.open("rb") as source:
                os.fsync(source.fileno())
    for directory in reversed(directories):
        fsync_directory(directory)


def verify_repository_header(repository: Path) -> None:
    path = repository / "repository.toml"
    if path.read_bytes() != REPOSITORY_TOML:
        raise ValueError(f"{repository}: unsupported or corrupt repository.toml")


def install_registry_objects(
    staged_repository: Path,
    destination: Path,
    packages: Iterable[RegistryPackage],
    limits: Limits,
) -> None:
    if destination.exists():
        verify_repository_header(destination)
    else:
        destination.mkdir(mode=0o755)
        write_exclusive(destination / "repository.toml", REPOSITORY_TOML, 0o644)
        fsync_directory(destination)
        fsync_directory(destination.parent)

    for package in packages:
        staged = registry_object_path(staged_repository, package.checksum)
        final = registry_object_path(destination, package.checksum)
        final.parent.mkdir(parents=True, exist_ok=True)
        if final.exists():
            verify_registry_object(final, package, limits)
            continue
        try:
            rename_no_replace(staged, final)
        except FileExistsError:
            verify_registry_object(final, package, limits)
        fsync_directory(final.parent)
        verify_registry_object(final, package, limits)


def install_seeded_git_objects(
    staged_repository: Path,
    destination: Path,
    packages: Iterable[SeededGitPackage],
    limits: Limits,
) -> None:
    if destination.exists():
        verify_repository_header(destination)
    else:
        destination.mkdir(mode=0o755)
        write_exclusive(destination / "repository.toml", REPOSITORY_TOML, 0o644)
        fsync_directory(destination)
        fsync_directory(destination.parent)

    for package in packages:
        staged = seeded_git_object_path(
            staged_repository, package.source_tree_sha256
        )
        final = seeded_git_object_path(destination, package.source_tree_sha256)
        final.parent.mkdir(parents=True, exist_ok=True)
        if final.exists():
            verify_seeded_git_object(final, package, limits)
            continue
        try:
            rename_no_replace(staged, final)
        except FileExistsError:
            verify_seeded_git_object(final, package, limits)
        fsync_directory(final.parent)
        verify_seeded_git_object(final, package, limits)


def validate_seed_locations(
    destination: Path,
    cache: Path | None,
    ca_bundle: Path | None,
    offline: bool,
) -> None:
    if not destination.is_absolute():
        raise ValueError("destination repository must be absolute")
    if cache is not None and not cache.is_absolute():
        raise ValueError("cache directory must be absolute")
    if ca_bundle is not None and not ca_bundle.is_absolute():
        raise ValueError("CA bundle must be absolute")
    if offline and cache is None:
        raise ValueError("--offline requires --cache")
    destination.parent.mkdir(parents=True, exist_ok=True)


def seed_registry_repository(
    manifest: SeedManifest,
    destination: Path,
    *,
    cache: Path | None,
    offline: bool,
    ca_bundle: Path | None,
) -> None:
    validate_seed_locations(destination, cache, ca_bundle, offline)

    staging_root = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.lorry-seed-",
            dir=destination.parent,
        )
    )
    os.chmod(staging_root, 0o700)
    staged_repository = staging_root / "repository"
    staged_repository.mkdir(mode=0o700)
    write_exclusive(staged_repository / "repository.toml", REPOSITORY_TOML)
    try:
        for package in manifest.registry:
            archive = cached_or_fetch_archive(
                package, manifest.limits, cache, offline, ca_bundle
            )
            index_record = cached_or_fetch_index_record(
                package, cache, offline, ca_bundle
            )
            build_registry_object(
                staged_repository,
                package,
                archive,
                index_record,
                manifest.limits,
            )
        fsync_tree(staged_repository)
        install_registry_objects(
            staged_repository,
            destination,
            manifest.registry,
            manifest.limits,
        )
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


def seed_system_repository(
    manifest: SeedManifest,
    destination: Path,
    *,
    mode: str,
    cache: Path | None,
    offline: bool,
    ca_bundle: Path | None,
    allow_local_git: bool = False,
) -> None:
    if mode not in ("full", "minimal"):
        raise ValueError(f"unsupported seed mode: {mode}")
    validate_seed_locations(destination, cache, ca_bundle, offline)
    registry = manifest.registry if mode == "full" else ()

    staging_root = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.lorry-seed-",
            dir=destination.parent,
        )
    )
    os.chmod(staging_root, 0o700)
    staged_repository = staging_root / "repository"
    staged_repository.mkdir(mode=0o700)
    write_exclusive(staged_repository / "repository.toml", REPOSITORY_TOML)
    try:
        for package in registry:
            archive = cached_or_fetch_archive(
                package, manifest.limits, cache, offline, ca_bundle
            )
            index_record = cached_or_fetch_index_record(
                package, cache, offline, ca_bundle
            )
            build_registry_object(
                staged_repository,
                package,
                archive,
                index_record,
                manifest.limits,
            )
        for index, package in enumerate(manifest.seeded_git):
            acquisition_root = staging_root / f"git-{index}"
            acquisition_root.mkdir(mode=0o700)
            build_seeded_git_object(
                staged_repository,
                package,
                acquisition_root,
                manifest.limits,
                cache=cache,
                offline=offline,
                allow_local_git=allow_local_git,
            )

        fsync_tree(staged_repository)
        install_registry_objects(
            staged_repository,
            destination,
            registry,
            manifest.limits,
        )
        install_seeded_git_objects(
            staged_repository,
            destination,
            manifest.seeded_git,
            manifest.limits,
        )
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a verified Lorry system dependency repository"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--mode", choices=("full", "minimal"), required=True)
    parser.add_argument("--ca-bundle", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--offline", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        manifest = load_seed_manifest(args.manifest)
        seed_system_repository(
            manifest,
            args.destination,
            mode=args.mode,
            cache=args.cache,
            offline=args.offline,
            ca_bundle=args.ca_bundle,
        )
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"seed-system-repository: error: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
