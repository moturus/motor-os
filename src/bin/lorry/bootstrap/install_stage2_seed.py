#!/usr/bin/env python3
"""Install the reviewed Stage 2 seed for the Linux host and Motor image."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
import tomllib
from pathlib import Path

from seed_system_repository import (
    SeedManifest,
    SeededGitPackage,
    fsync_directory,
    fsync_tree,
    install_registry_objects,
    install_seeded_git_objects,
    rename_no_replace,
    registry_object_path,
    seed_system_repository,
    seeded_git_object_path,
    toml_string,
    verify_registry_object,
    verify_repository_header,
    verify_seeded_git_object,
    write_exclusive,
)


BOOTSTRAP = Path(__file__).resolve().parent
REPOSITORY_ROOT = BOOTSTRAP.parents[3]
DEFAULT_MANIFEST = BOOTSTRAP / "stage2-seed.toml"
DEFAULT_BUILD_REPOSITORY = REPOSITORY_ROOT / "build/lorry/stage2/system-seed"
DEFAULT_CACHE = REPOSITORY_ROOT / "build/lorry/stage2/download-cache"
DEFAULT_IMAGE_REPOSITORY = (
    REPOSITORY_ROOT
    / "img_files/generated/rustc/sys/tools/rust/lorry/vendor"
)
DEFAULT_MOTOR_CONFIG = (
    REPOSITORY_ROOT
    / "img_files/generated/rustc/sys/tools/rust/cfg/lorry.toml"
)
MOTOR_SYSTEM_REPOSITORY = Path("/sys/tools/rust/lorry/vendor")


def selected_registry(manifest: SeedManifest, mode: str):
    return manifest.registry if mode == "full" else ()


def verify_seed_repository(
    repository: Path,
    manifest: SeedManifest,
    mode: str,
) -> None:
    verify_repository_header(repository)
    for package in selected_registry(manifest, mode):
        verify_registry_object(
            registry_object_path(repository, package.checksum),
            package,
            manifest.limits,
        )
    for package in manifest.seeded_git:
        verify_seeded_git_object(
            seeded_git_object_path(repository, package.source_tree_sha256),
            package,
            manifest.limits,
        )


def repository_fingerprint(
    repository: Path,
    manifest: SeedManifest,
    mode: str,
) -> str:
    verify_seed_repository(repository, manifest, mode)
    digest = hashlib.sha256()
    digest.update(b"lorry-seed-repository-v1\0")

    objects = []
    for package in selected_registry(manifest, mode):
        objects.append(
            (
                b"crates-io",
                package.checksum.encode("ascii"),
                registry_object_path(repository, package.checksum),
            )
        )
    for package in manifest.seeded_git:
        objects.append(
            (
                b"seeded-git",
                package.source_tree_sha256.encode("ascii"),
                seeded_git_object_path(repository, package.source_tree_sha256),
            )
        )
    objects.sort(key=lambda item: (item[0], item[1]))

    digest.update(len(objects).to_bytes(8, "big"))
    for kind, identity, object_path in objects:
        digest.update(len(kind).to_bytes(4, "big"))
        digest.update(kind)
        digest.update(len(identity).to_bytes(4, "big"))
        digest.update(identity)
        for name in (
            "package.toml",
            "index-record.json",
            "source-manifest.json",
            "package.crate",
        ):
            path = object_path / name
            if not path.exists():
                continue
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"repository evidence is not a file: {path}")
            digest.update(len(name).to_bytes(4, "big"))
            digest.update(name.encode("ascii"))
            digest.update(metadata.st_size.to_bytes(8, "big"))
            file_digest = hashlib.sha256()
            with path.open("rb") as source:
                while block := source.read(1024 * 1024):
                    file_digest.update(block)
            digest.update(file_digest.digest())
    return digest.hexdigest()


def copy_selected_objects(
    source: Path,
    staging: Path,
    manifest: SeedManifest,
    mode: str,
) -> None:
    staging.mkdir(mode=0o700)
    write_exclusive(
        staging / "repository.toml",
        (source / "repository.toml").read_bytes(),
    )
    for package in selected_registry(manifest, mode):
        source_object = registry_object_path(source, package.checksum)
        staged_object = registry_object_path(staging, package.checksum)
        staged_object.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_object, staged_object, symlinks=False)
    for package in manifest.seeded_git:
        source_object = seeded_git_object_path(source, package.source_tree_sha256)
        staged_object = seeded_git_object_path(
            staging, package.source_tree_sha256
        )
        staged_object.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_object, staged_object, symlinks=False)
    fsync_tree(staging)


def install_repository_copy(
    source: Path,
    destination: Path,
    manifest: SeedManifest,
    mode: str,
) -> None:
    source_fingerprint = repository_fingerprint(source, manifest, mode)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.lorry-copy-",
            dir=destination.parent,
        )
    )
    os.chmod(staging_root, 0o700)
    staging = staging_root / "repository"
    try:
        copy_selected_objects(source, staging, manifest, mode)
        verify_seed_repository(staging, manifest, mode)
        if destination.exists():
            install_registry_objects(
                staging,
                destination,
                selected_registry(manifest, mode),
                manifest.limits,
            )
            install_seeded_git_objects(
                staging,
                destination,
                manifest.seeded_git,
                manifest.limits,
            )
        else:
            rename_no_replace(staging, destination)
            fsync_directory(destination.parent)
        verify_seed_repository(destination, manifest, mode)
        if repository_fingerprint(destination, manifest, mode) != source_fingerprint:
            raise ValueError(
                f"installed repository differs from generated seed: {destination}"
            )
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


def policy_rule_id(name: str, version: str) -> str:
    safe_name = name.replace("-", "_")
    safe_version = version.replace(".", "_").replace("+", "_").replace("-", "_")
    return f"allow-{safe_name}-{safe_version}"


def render_registry_policy(manifest: SeedManifest) -> str:
    output = []
    for package in sorted(
        manifest.registry, key=lambda item: (item.name, item.version)
    ):
        output.extend(
            [
                "",
                f"[policy.rules.{policy_rule_id(package.name, package.version)}]",
                'action = "allow"',
                f"name = {toml_string(package.name)}",
                f'version = "={package.version}"',
                'source = "crates.io"',
                f'checksum = "{package.checksum}"',
                f"license = {toml_string(package.license)}",
            ]
        )
        if package.allow_build_script:
            output.append("allow-build-script = true")
    return "\n".join(output) + "\n"


def render_ring_policy(package: SeededGitPackage) -> str:
    return f"""
[required-patches.crates-io.ring-0_17_14]
name = {toml_string(package.name)}
version = "={package.version}"
upstream-checksum = "{package.upstream_checksum}"
git-url = {toml_string(package.git_url)}
git-commit = "{package.resolved_commit}"
source-tree-sha256 = "{package.source_tree_sha256}"

[policy.rules.allow-ring-0_17_14]
action = "allow"
name = {toml_string(package.name)}
version = "={package.version}"
source = "system-vendored-path"
source-tree-sha256 = "{package.source_tree_sha256}"
license = {toml_string(package.license)}
allow-build-script = true
native-tools = ["c-compiler", "archiver"]
"""


def render_system_config(
    manifest: SeedManifest,
    *,
    system_repository: Path,
    user_repository: Path | None,
    motor: bool,
) -> bytes:
    template = (BOOTSTRAP / "system-lorry.toml.in").read_text(encoding="utf-8")
    user_line = (
        f"user = {toml_string(str(user_repository))}"
        if user_repository is not None
        else ""
    )
    output = template.replace(
        "@SYSTEM_REPOSITORY@", toml_string(str(system_repository))
    ).replace("@USER_REPOSITORY@", user_line)
    if motor:
        output += """
[native-tools."x86_64-unknown-motor".c-compiler]
program = "/sys/tools/llvm/bin/llvm"
prefix-args = ["clang"]
flags = ["--target=x86_64-unknown-motor"]

[native-tools."x86_64-unknown-motor".archiver]
program = "/sys/tools/llvm/bin/llvm"
prefix-args = ["ar"]
flags = []
"""
    output += render_registry_policy(manifest)
    if len(manifest.seeded_git) != 1:
        raise ValueError("Stage 2 system config requires exactly one seeded-Git rule")
    output += render_ring_policy(manifest.seeded_git[0])
    output += """
[system-constraints]
locked = [
    "repositories.system",
    "policy.default",
    "policy.limits",
    "required-patches.crates-io.ring-0_17_14",
    "policy.rules.allow-ring-0_17_14",
]
"""
    encoded = output.encode("utf-8")
    tomllib.loads(output)
    return encoded


def validate_host_config(path: Path, expected_system_repository: Path) -> None:
    with path.open("rb") as source:
        value = tomllib.load(source)
    try:
        actual = value["repositories"]["system"]
    except (KeyError, TypeError) as error:
        raise ValueError(
            f"{path} must define repositories.system = "
            f"{toml_string(str(expected_system_repository))}"
        ) from error
    if actual != str(expected_system_repository):
        raise ValueError(
            f"{path} names repositories.system = {toml_string(str(actual))}; "
            f"expected {toml_string(str(expected_system_repository))}"
        )


def write_new_host_config(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.lorry-new-", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(contents)
            destination.flush()
            os.fsync(destination.fileno())
        os.link(temporary, path)
    except FileExistsError:
        pass
    finally:
        temporary.unlink(missing_ok=True)
    fsync_directory(path.parent)


def replace_generated_config(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(contents)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def install_configs(
    manifest: SeedManifest,
    *,
    host_config: Path,
    host_repository: Path,
    host_user_repository: Path,
    motor_config: Path,
) -> None:
    host_contents = render_system_config(
        manifest,
        system_repository=host_repository,
        user_repository=host_user_repository,
        motor=False,
    )
    write_new_host_config(host_config, host_contents)
    validate_host_config(host_config, host_repository)
    motor_contents = render_system_config(
        manifest,
        system_repository=MOTOR_SYSTEM_REPOSITORY,
        user_repository=None,
        motor=True,
    )
    replace_generated_config(motor_config, motor_contents)


def cargo_checksum_bytes(source_manifest: Path, package_checksum: str) -> bytes:
    value = json.loads(source_manifest.read_bytes())
    if (
        not isinstance(value, dict)
        or value.get("format-version") != 1
        or not isinstance(value.get("entries"), list)
    ):
        raise ValueError(f"invalid source manifest: {source_manifest}")
    files = {}
    for entry in value["entries"]:
        if not isinstance(entry, dict):
            raise ValueError(f"invalid source manifest entry: {source_manifest}")
        if entry.get("kind") == "file":
            path = entry.get("path")
            digest = entry.get("sha256")
            if not isinstance(path, str) or not isinstance(digest, str):
                raise ValueError(
                    f"invalid source manifest file entry: {source_manifest}"
                )
            if path in files:
                raise ValueError(f"duplicate source manifest path: {path}")
            files[path] = digest
        elif entry.get("kind") != "directory":
            raise ValueError(f"invalid source manifest kind: {source_manifest}")
    output = {"files": files, "package": package_checksum}
    return (
        json.dumps(output, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def materialize_cargo_oracle_view(
    repository: Path,
    destination: Path,
    manifest: SeedManifest,
    mode: str,
) -> None:
    verify_seed_repository(repository, manifest, mode)
    if not destination.is_absolute():
        raise ValueError("Cargo oracle view path must be absolute")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.lorry-cargo-view-",
            dir=destination.parent,
        )
    )
    os.chmod(staging, 0o700)
    try:
        registry_view = staging / "registry"
        registry_view.mkdir(mode=0o700)
        for package in selected_registry(manifest, mode):
            object_path = registry_object_path(repository, package.checksum)
            package_view = registry_view / f"{package.name}-{package.version}"
            shutil.copytree(object_path / "source", package_view, symlinks=False)
            checksum_path = package_view / ".cargo-checksum.json"
            if checksum_path.exists():
                raise ValueError(
                    f"package source already contains {checksum_path.name}: "
                    f"{package.name} {package.version}"
                )
            write_exclusive(
                checksum_path,
                cargo_checksum_bytes(
                    object_path / "source-manifest.json",
                    package.checksum,
                ),
            )

        if len(manifest.seeded_git) != 1:
            raise ValueError("Cargo oracle view requires exactly one seeded-Git object")
        ring = manifest.seeded_git[0]
        ring_object = seeded_git_object_path(
            repository, ring.source_tree_sha256
        )
        ring_view = staging / ".lorry/vendor/ring-0_17_14/source"
        ring_view.parent.mkdir(parents=True)
        shutil.copytree(ring_object / "source", ring_view, symlinks=False)

        cargo_config = staging / ".cargo/config.toml"
        cargo_config.parent.mkdir()
        final_registry_view = destination / "registry"
        write_exclusive(
            cargo_config,
            (
                '[source.crates-io]\n'
                'replace-with = "lorry-stage2-seed"\n\n'
                '[source.lorry-stage2-seed]\n'
                f"directory = {toml_string(str(final_registry_view))}\n"
            ).encode("utf-8"),
        )
        fsync_tree(staging)
        rename_no_replace(staging, destination)
        fsync_directory(destination.parent)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    home = Path.home()
    parser = argparse.ArgumentParser(
        description="Install the reviewed Stage 2 Lorry system seed"
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--build-repository", type=Path, default=DEFAULT_BUILD_REPOSITORY
    )
    parser.add_argument(
        "--host-repository",
        type=Path,
        default=home / ".config/lorry/system/vendor",
    )
    parser.add_argument(
        "--host-user-repository",
        type=Path,
        default=home / ".config/lorry/vendor",
    )
    parser.add_argument(
        "--host-config",
        type=Path,
        default=home / ".config/lorry/lorry.toml",
    )
    parser.add_argument(
        "--image-repository", type=Path, default=DEFAULT_IMAGE_REPOSITORY
    )
    parser.add_argument("--motor-config", type=Path, default=DEFAULT_MOTOR_CONFIG)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--ca-bundle", type=Path)
    parser.add_argument("--mode", choices=("full", "minimal"), default="full")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--cargo-oracle-view", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    from seed_system_repository import load_seed_manifest

    args = parse_args(argv)
    try:
        manifest = load_seed_manifest(args.manifest)
        seed_system_repository(
            manifest,
            args.build_repository,
            mode=args.mode,
            cache=args.cache,
            offline=args.offline,
            ca_bundle=args.ca_bundle,
        )
        install_repository_copy(
            args.build_repository,
            args.host_repository,
            manifest,
            args.mode,
        )
        install_repository_copy(
            args.build_repository,
            args.image_repository,
            manifest,
            args.mode,
        )
        host_fingerprint = repository_fingerprint(
            args.host_repository, manifest, args.mode
        )
        image_fingerprint = repository_fingerprint(
            args.image_repository, manifest, args.mode
        )
        if host_fingerprint != image_fingerprint:
            raise ValueError("host and Motor image seed repositories differ")
        install_configs(
            manifest,
            host_config=args.host_config,
            host_repository=args.host_repository,
            host_user_repository=args.host_user_repository,
            motor_config=args.motor_config,
        )
        if args.cargo_oracle_view is not None:
            materialize_cargo_oracle_view(
                args.build_repository,
                args.cargo_oracle_view,
                manifest,
                args.mode,
            )
        print(f"Stage 2 {args.mode} seed: {host_fingerprint}")
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"install-stage2-seed: error: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
