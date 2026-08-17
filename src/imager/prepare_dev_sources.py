#!/usr/bin/env python3
"""Prepare source trees that need image-specific offline materialization."""

from __future__ import annotations

import argparse
import shutil
import tomllib
from pathlib import Path


EXCLUDED_DIRECTORIES = {".git", "__pycache__", "target"}
CROSSTERM_GIT_URL = "https://github.com/moturus/crossterm.git"
CROSSTERM_BRANCH = "motor-os-support"
CROSSTERM_VERSION = "0.29.0"
CROSSTERM_PATCH_ID = "crossterm-0_29_0"


def replace_once(source: str, old: str, new: str, description: str) -> str:
    if source.count(old) != 1:
        raise ValueError(f"expected exactly one {description}")
    return source.replace(old, new)


def materialize_red(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(*EXCLUDED_DIRECTORIES),
    )

    manifest_path = destination / "Cargo.toml"
    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest = tomllib.loads(manifest_text)
    expected_patch = {
        "git": CROSSTERM_GIT_URL,
        "branch": CROSSTERM_BRANCH,
    }
    if manifest.get("patch", {}).get("crates-io", {}).get("crossterm") != expected_patch:
        raise ValueError("Red's crossterm Git patch changed")
    old_patch = (
        f'crossterm = {{ git = "{CROSSTERM_GIT_URL}", '
        f'branch = "{CROSSTERM_BRANCH}" }}'
    )
    new_patch = (
        "# dev.img resolves this reviewed fork through Lorry's system seed.\n"
        f'crossterm = {{ path = ".lorry/vendor/{CROSSTERM_PATCH_ID}/source" }}'
    )
    manifest_text = replace_once(
        manifest_text, old_patch, new_patch, "Red crossterm patch declaration"
    )
    tomllib.loads(manifest_text)
    manifest_path.write_text(manifest_text, encoding="utf-8")

    lock_path = destination / "Cargo.lock"
    lock_text = lock_path.read_text(encoding="utf-8")
    lock = tomllib.loads(lock_text)
    packages = [
        package
        for package in lock.get("package", [])
        if package.get("name") == "crossterm"
        and package.get("version") == CROSSTERM_VERSION
    ]
    if len(packages) != 1:
        raise ValueError("Red's lockfile must contain one crossterm 0.29.0 package")
    git_source = packages[0].get("source", "")
    expected_prefix = (
        f"git+{CROSSTERM_GIT_URL}?branch={CROSSTERM_BRANCH}#"
    )
    commit = git_source.removeprefix(expected_prefix)
    if (
        not git_source.startswith(expected_prefix)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
        or "checksum" in packages[0]
    ):
        raise ValueError("Red's locked crossterm Git identity changed")
    lock_text = replace_once(
        lock_text,
        f'source = "{git_source}"\n',
        "",
        "Red locked crossterm Git source",
    )
    materialized_lock = tomllib.loads(lock_text)
    materialized = [
        package
        for package in materialized_lock["package"]
        if package.get("name") == "crossterm"
        and package.get("version") == CROSSTERM_VERSION
    ][0]
    if "source" in materialized or "checksum" in materialized:
        raise ValueError("failed to materialize Red's crossterm lock entry")
    lock_path.write_text(lock_text, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("repository_root", type=Path)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()

    repository_root = args.repository_root.resolve(strict=True)
    output_root = args.output_root.resolve()
    try:
        output_root.relative_to(repository_root / "build")
    except ValueError as error:
        raise ValueError("developer source output must be below build/") from error
    output_root.mkdir(parents=True, exist_ok=True)
    materialize_red(repository_root / "src/bin/red", output_root / "red")


if __name__ == "__main__":
    main()
