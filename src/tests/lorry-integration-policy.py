#!/usr/bin/env python3
"""Render integration policy from lockfiles and verified Lorry objects."""

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path, PurePosixPath


CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUM_RE = re.compile(r"[0-9a-f]{64}")
NAME_RE = re.compile(r"[A-Za-z0-9_-]+")
VERSION_RE = re.compile(r"[A-Za-z0-9.+-]+")


class PolicyError(Exception):
    pass


def load_toml(path: Path, description: str) -> dict:
    try:
        with path.open("rb") as source:
            value = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise PolicyError(f"cannot load {description} '{path}': {error}") from error
    if not isinstance(value, dict):
        raise PolicyError(f"{description} '{path}' is not a TOML table")
    return value


def load_json(path: Path, description: str) -> dict:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyError(f"cannot load {description} '{path}': {error}") from error
    if not isinstance(value, dict):
        raise PolicyError(f"{description} '{path}' is not a JSON object")
    return value


def locked_registry_packages(lock: Path) -> list[tuple[str, str, str]]:
    packages: set[tuple[str, str, str]] = set()
    document = load_toml(lock, "lockfile")
    entries = document.get("package")
    if not isinstance(entries, list):
        raise PolicyError(f"lockfile '{lock}' has no package array")
    for package in entries:
        if not isinstance(package, dict):
            raise PolicyError(f"lockfile '{lock}' has a malformed package")
        source = package.get("source")
        if source is None:
            continue
        if not isinstance(source, str):
            raise PolicyError(f"lockfile '{lock}' has an invalid package source")
        if not source.startswith("registry+"):
            continue
        if source != CRATES_IO_SOURCE:
            raise PolicyError(
                f"lockfile '{lock}' uses unsupported registry source '{source}'"
            )
        name = package.get("name")
        version = package.get("version")
        checksum = package.get("checksum")
        if not isinstance(name, str) or NAME_RE.fullmatch(name) is None:
            raise PolicyError(f"lockfile '{lock}' has an invalid package name")
        if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
            raise PolicyError(f"lockfile '{lock}' has an invalid package version")
        if not isinstance(checksum, str) or CHECKSUM_RE.fullmatch(checksum) is None:
            raise PolicyError(
                f"lockfile '{lock}' has an invalid checksum for {name} {version}"
            )
        identity = (name, version, checksum)
        if identity in packages:
            raise PolicyError(f"lockfile '{lock}' repeats {name} {version}")
        packages.add(identity)
    return sorted(packages)


def compact_admission(
    lock: Path, state: Path
) -> tuple[set[tuple[str, str, str]], dict[tuple[str, str, str], list[str]]]:
    locked = set(locked_registry_packages(lock))
    document = load_toml(state, "Lorry dependency state")
    if document.get("format-version") != 2 or document.get(
        "review-format-version"
    ) != 1:
        raise PolicyError(f"dependency state '{state}' has unsupported format")
    review = document.get("review-sha256")
    if not isinstance(review, str) or CHECKSUM_RE.fullmatch(review) is None:
        raise PolicyError(f"dependency state '{state}' has an invalid review commitment")
    contexts = document.get("context")
    if not isinstance(contexts, list) or not contexts:
        raise PolicyError(f"dependency state '{state}' has no reviewed context")
    for entry in contexts:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("host"), str)
            or not isinstance(entry.get("target"), str)
        ):
            raise PolicyError(f"dependency state '{state}' has a malformed context")
    capabilities: dict[tuple[str, str, str], list[str]] = {}
    entries = document.get("capability", [])
    if not isinstance(entries, list):
        raise PolicyError(f"dependency state '{state}' has malformed capabilities")
    for entry in entries:
        if not isinstance(entry, dict):
            raise PolicyError(f"dependency state '{state}' has a malformed capability")
        name = entry.get("package")
        version = entry.get("version")
        checksum = entry.get("checksum")
        if not isinstance(name, str) or NAME_RE.fullmatch(name) is None:
            raise PolicyError(f"dependency state '{state}' has an invalid package name")
        if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
            raise PolicyError(f"dependency state '{state}' has an invalid package version")
        if not isinstance(checksum, str) or CHECKSUM_RE.fullmatch(checksum) is None:
            raise PolicyError(f"dependency state '{state}' has an invalid package checksum")
        if entry.get("build-script") is not True:
            raise PolicyError(
                f"dependency state '{state}' has a capability without a build-script grant"
            )
        tools = entry.get("native-tools")
        if not isinstance(tools, list) or not all(
            isinstance(tool, str) for tool in tools
        ):
            raise PolicyError(f"dependency state '{state}' has invalid native tools")
        identity = (name, version, checksum)
        if identity not in locked:
            raise PolicyError(
                f"dependency state '{state}' grants a capability absent from '{lock}'"
            )
        if identity in capabilities:
            raise PolicyError(f"dependency state '{state}' repeats a capability")
        capabilities[identity] = sorted(tools)
    return locked, capabilities


def verified_file(source: Path, entries: dict[str, dict], relative: PurePosixPath) -> Path:
    candidate = source
    for component in relative.parts:
        candidate /= component
        if candidate.is_symlink():
            raise PolicyError(f"verified repository path '{relative}' is a symlink")
    entry = entries.get(relative.as_posix())
    if not isinstance(entry, dict) or entry.get("kind") != "file":
        raise PolicyError(f"source manifest has no file entry for '{relative}'")
    try:
        contents = candidate.read_bytes()
    except OSError as error:
        raise PolicyError(f"cannot load verified source file '{candidate}': {error}") from error
    if entry.get("length") != len(contents) or entry.get("sha256") != hashlib.sha256(
        contents
    ).hexdigest():
        raise PolicyError(f"verified source file '{relative}' does not match its manifest")
    return candidate


def package_has_build_script(
    repository: Path, name: str, version: str, checksum: str
) -> tuple[bool, str, str]:
    object_path = (
        repository
        / "objects"
        / "crates-io"
        / "sha256"
        / checksum[:2]
        / checksum
    )
    metadata = load_toml(object_path / "package.toml", "repository metadata")
    expected = {
        "format-version": 1,
        "name": name,
        "version": version,
        "source": CRATES_IO_SOURCE,
        "checksum": checksum,
        "retained-source": True,
    }
    for field, value in expected.items():
        if metadata.get(field) != value:
            raise PolicyError(
                f"repository evidence for {name} {version} has invalid {field}"
            )

    source_tree_sha256 = metadata.get("source-tree-sha256")
    license_name = metadata.get("license")
    if not isinstance(source_tree_sha256, str) or CHECKSUM_RE.fullmatch(
        source_tree_sha256
    ) is None:
        raise PolicyError(
            f"repository evidence for {name} {version} has invalid source-tree-sha256"
        )
    if not isinstance(license_name, str) or not license_name:
        raise PolicyError(f"repository evidence for {name} {version} has invalid license")
    source = object_path / "source"
    if source.is_symlink() or not source.is_dir():
        raise PolicyError(f"repository evidence for {name} {version} has no source tree")
    source_manifest = load_json(object_path / "source-manifest.json", "source manifest")
    if (
        source_manifest.get("format-version") != 1
        or source_manifest.get("source-tree-sha256") != source_tree_sha256
        or not isinstance(source_manifest.get("entries"), list)
    ):
        raise PolicyError(f"repository evidence for {name} {version} has invalid source manifest")
    entries: dict[str, dict] = {}
    for entry in source_manifest["entries"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise PolicyError(f"source manifest for {name} {version} has an invalid entry")
        if entry["path"] in entries:
            raise PolicyError(
                f"source manifest for {name} {version} repeats '{entry['path']}'"
            )
        entries[entry["path"]] = entry

    manifest_path = verified_file(source, entries, PurePosixPath("Cargo.toml"))
    manifest = load_toml(manifest_path, "verified package manifest")
    package = manifest.get("package")
    if not isinstance(package, dict):
        raise PolicyError(f"verified manifest for {name} {version} has no package table")
    if package.get("name") != name or package.get("version") != version:
        raise PolicyError(f"verified manifest does not identify {name} {version}")
    build = package.get("build")
    if build is False:
        return False, license_name, source_tree_sha256
    if build is None:
        if "build.rs" not in entries:
            return False, license_name, source_tree_sha256
        verified_file(source, entries, PurePosixPath("build.rs"))
        return True, license_name, source_tree_sha256
    if not isinstance(build, str) or not build:
        raise PolicyError(f"verified manifest for {name} {version} has invalid build")
    script = PurePosixPath(build)
    if script.is_absolute() or ".." in script.parts:
        raise PolicyError(f"verified manifest for {name} {version} has unsafe build")
    verified_file(source, entries, script)
    return True, license_name, source_tree_sha256


def rule_id(name: str, version: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", f"allow-{name}-{version}")


def render(mode: str, repository: Path, projects: list[list[Path]]) -> str:
    output: list[str] = []
    used_rule_ids: set[str] = set()
    locked_union: set[tuple[str, str, str]] = set()
    grants: dict[tuple[str, str, str], list[str]] = {}
    for lock, state in projects:
        locked, capabilities = compact_admission(lock, state)
        locked_union |= locked
        for identity, tools in capabilities.items():
            merged = sorted(set(grants.get(identity, [])) | set(tools))
            grants[identity] = merged
    for name, version, checksum in sorted(locked_union):
        identity = (name, version, checksum)
        granted = identity in grants
        object_present = (
            repository
            / "objects"
            / "crates-io"
            / "sha256"
            / checksum[:2]
            / checksum
            / "package.toml"
        ).is_file()
        if granted or object_present:
            # Locked packages not selected for the tested targets may have no
            # retained object; a build-script grant always requires verified
            # matching evidence.
            has_build_script = package_has_build_script(
                repository, name, version, checksum
            )[0]
            if granted and not has_build_script:
                raise PolicyError(
                    f"capability for {name} {version} has no build-script evidence"
                )
        if mode == "build-scripts" and not granted:
            continue
        identifier = rule_id(name, version)
        if identifier in used_rule_ids:
            raise PolicyError(f"policy rule identifier collision at '{identifier}'")
        used_rule_ids.add(identifier)
        output.extend(
            [
                "",
                f"[policy.rules.{identifier}]",
                'action = "allow"',
                f'name = "{name}"',
                f'version = "={version}"',
                'source = "crates.io"',
                f'checksum = "{checksum}"',
            ]
        )
        if granted:
            output.append("allow-build-script = true")
            tools = grants[identity]
            if tools:
                rendered = ", ".join(f'"{tool}"' for tool in tools)
                output.append(f"native-tools = [{rendered}]")
    return "\n".join(output) + ("\n" if output else "")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("all", "build-scripts"))
    parser.add_argument("repository", type=Path)
    parser.add_argument(
        "--project",
        action="append",
        nargs=2,
        required=True,
        type=Path,
        metavar=("LOCK", "STATE"),
    )
    arguments = parser.parse_args()
    try:
        sys.stdout.write(render(arguments.mode, arguments.repository, arguments.project))
    except PolicyError as error:
        print(f"lorry-integration-policy: {error}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
