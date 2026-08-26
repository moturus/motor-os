#!/usr/bin/env python3
"""Check that dev-only lockfiles match their local path dependencies."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROJECTS = (
    ROOT / "src/bin/curl",
    ROOT / "src/bin/lorry",
)
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def load_toml(path: Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def dependency_specs(manifest: dict):
    for table_name in DEPENDENCY_TABLES:
        yield from manifest.get(table_name, {}).values()
    for target in manifest.get("target", {}).values():
        for table_name in DEPENDENCY_TABLES:
            yield from target.get(table_name, {}).values()
    for registry in manifest.get("patch", {}).values():
        yield from registry.values()


def local_packages(manifest_path: Path) -> set[tuple[str, str]]:
    packages = set()
    pending = [manifest_path]
    visited = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        manifest = load_toml(current)
        for spec in dependency_specs(manifest):
            if not isinstance(spec, dict) or "path" not in spec:
                continue
            relative_path = Path(spec["path"])
            dependency = (current.parent / relative_path / "Cargo.toml").resolve()
            # Lorry materializes reviewed patch sources below .lorry/vendor.
            if not dependency.is_file():
                if relative_path.parts[:2] == (".lorry", "vendor"):
                    continue
                raise ValueError(f"{current}: missing path dependency {relative_path}")
            package = load_toml(dependency).get("package", {})
            name = package.get("name")
            version = package.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                raise ValueError(f"{dependency}: path package needs a name and version")
            packages.add((name, version))
            pending.append(dependency)
    return packages


def check_project(project: Path) -> list[str]:
    lock_path = project / "Cargo.lock"
    locked = {
        (package.get("name"), package.get("version"))
        for package in load_toml(lock_path).get("package", [])
        if "source" not in package
    }
    errors = []
    for name, version in sorted(local_packages(project / "Cargo.toml")):
        if (name, version) not in locked:
            versions = sorted(
                locked_version
                for locked_name, locked_version in locked
                if locked_name == name
            )
            found = ", ".join(versions) if versions else "not present"
            errors.append(
                f"{lock_path.relative_to(ROOT)}: local {name} is {version}, "
                f"lockfile has {found}"
            )
    return errors


def main() -> int:
    errors = [error for project in PROJECTS for error in check_project(project)]
    if errors:
        print("dev path dependency lock check failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        print("refresh each reported Cargo.lock before building images", file=sys.stderr)
        return 1
    print("dev path dependency lock check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
