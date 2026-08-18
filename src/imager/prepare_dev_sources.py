#!/usr/bin/env python3
"""Prepare source trees that need image-specific offline materialization."""

from __future__ import annotations

import argparse
import shutil
import tomllib
from pathlib import Path


EXCLUDED_DIRECTORIES = {".git", ".lorry", "__pycache__", "target"}
CROSSTERM_GIT_URL = "https://github.com/moturus/crossterm.git"
CROSSTERM_BRANCH = "motor-os-support"
CROSSTERM_VERSION = "0.29.0"
CROSSTERM_PATCH_ID = "crossterm-0_29_0"
PATCH_IDS = {
    "cc": "cc-1_4_0",
    "ring": "ring-0_17_14",
}


def replace_once(source: str, old: str, new: str, description: str) -> str:
    if source.count(old) != 1:
        raise ValueError(f"expected exactly one {description}")
    return source.replace(old, new)


def copy_source_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(*EXCLUDED_DIRECTORIES),
    )


def seeded_git_sources(repository_root: Path) -> dict[str, Path]:
    manifest_path = repository_root / "src/bin/lorry/bootstrap/stage2-seed.toml"
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    repository = repository_root / "img_files/generated/rustc/devtools/lorry/vendor"
    result = {}
    for package in manifest["seeded-git"]:
        digest = package["source-tree-sha256"]
        source = repository / "objects/seeded-git/sha256" / digest[:2] / digest / "source"
        if not source.is_dir():
            raise ValueError(f"seeded source is absent for {package['name']}: {source}")
        result[package["name"]] = source
    return result


def install_patch_source(destination: Path, name: str, source: Path) -> None:
    package = destination / ".lorry/vendor" / PATCH_IDS[name] / "source"
    package.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, package, ignore=shutil.ignore_patterns(*EXCLUDED_DIRECTORIES))


def materialize_crossterm(destination: Path, seeded_source: Path) -> None:

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
    patch_destination = destination / ".lorry/vendor" / CROSSTERM_PATCH_ID / "source"
    patch_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        seeded_source,
        patch_destination,
        ignore=shutil.ignore_patterns(*EXCLUDED_DIRECTORIES),
    )


def rewrite_runtime_paths(destination: Path) -> None:
    manifest_path = destination / "Cargo.toml"
    text = manifest_path.read_text(encoding="utf-8")
    text = text.replace('../../sys/lib/moto-rt', '../moto-rt')
    text = text.replace('../../sys/lib/moto-sys', '../moto-sys')
    tomllib.loads(text)
    manifest_path.write_text(text, encoding="utf-8")


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
    seeds = seeded_git_sources(repository_root)
    for name in ("red", "curl", "lorry", "gears"):
        copy_source_tree(repository_root / "src/bin" / name, output_root / name)
    for name in ("curl", "lorry", "gears"):
        rewrite_runtime_paths(output_root / name)
    for name in ("red", "gears"):
        materialize_crossterm(output_root / name, seeds["crossterm"])
    for name in ("cc", "ring"):
        install_patch_source(output_root / "curl", name, seeds[name])
    copy_source_tree(repository_root / "src/sys/lib/moto-rt", output_root / "moto-rt")
    copy_source_tree(repository_root / "src/sys/lib/moto-sys", output_root / "moto-sys")


if __name__ == "__main__":
    main()
