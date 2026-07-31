#!/usr/bin/env python3
"""Build a disposable Motor image containing only patched source seeds."""

from __future__ import annotations

import argparse
import errno
import os
import shutil
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

from install_stage2_seed import repository_fingerprint
from seed_system_repository import load_seed_manifest


BOOTSTRAP = Path(__file__).resolve().parent
REPOSITORY_ROOT = BOOTSTRAP.parents[3]
MANIFEST = BOOTSTRAP / "stage2-seed.toml"
SEED_INSTALLER = BOOTSTRAP / "install_stage2_seed.py"
DOWNLOAD_CACHE = REPOSITORY_ROOT / "build/lorry/stage2/download-cache"
IMAGER_DIRECTORY = REPOSITORY_ROOT / "src/imager"
VM_SCRIPTS = REPOSITORY_ROOT / "src/vm_scripts"
MINIMAL_SEED_FINGERPRINT = (
    "3152f516ac5a3fbc3bd67bb15c439401c5d819d44304128f7e2a2840708ef968"
)

IMAGE_BINARIES = (
    "boot.bin",
    "crossbench",
    "dns-resolver",
    "httpd",
    "httpd-axum",
    "kernel",
    "kibim",
    "kloader",
    "kloader.bin",
    "mbr.bin",
    "mdbg",
    "mio-test",
    "red",
    "rmux",
    "rnetbench",
    "rush",
    "russhd",
    "strobe",
    "sys-init",
    "sys-io",
    "sys-tty",
    "sysbox",
    "systest",
    "tokio-tests",
)
STATIC_ROOTS = (
    Path("img_files/motor-os"),
    Path("img_files/generated/llvm"),
    Path("img_files/generated/rustc"),
)


def verify_plain_tree(root: Path) -> None:
    if not root.is_dir():
        raise ValueError(f"required image tree is absent: {root}")
    for directory, names, files in os.walk(root, followlinks=False):
        for name in (*names, *files):
            path = Path(directory) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"image input must not be a symbolic link: {path}")
            if not stat.S_ISDIR(metadata.st_mode) and not stat.S_ISREG(
                metadata.st_mode
            ):
                raise ValueError(f"image input must be a file or directory: {path}")


def link_or_copy(source: str, destination: str) -> str:
    try:
        os.link(source, destination)
    except OSError as error:
        if error.errno not in {
            errno.EACCES,
            errno.EMLINK,
            errno.EPERM,
            errno.EXDEV,
            getattr(errno, "ENOTSUP", errno.EPERM),
            getattr(errno, "EOPNOTSUPP", errno.EPERM),
        }:
            raise
        shutil.copy2(source, destination)
    return destination


def copy_plain_tree(source: Path, destination: Path) -> None:
    verify_plain_tree(source)
    shutil.copytree(source, destination, copy_function=link_or_copy)
    verify_plain_tree(destination)


def verify_binary_inputs(root: Path, mode: str) -> None:
    binary_root = root / "build/bin" / mode
    verify_plain_tree(binary_root)
    for name in IMAGE_BINARIES:
        path = binary_root / name
        try:
            metadata = path.stat(follow_symlinks=False)
        except FileNotFoundError as error:
            raise ValueError(f"required image binary is absent: {path}") from error
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"required image binary is absent: {path}")


def assemble_scaffold(source_root: Path, scaffold: Path, mode: str) -> Path:
    if not scaffold.is_absolute():
        raise ValueError(f"scaffold path must be absolute: {scaffold}")
    if scaffold.exists():
        raise ValueError(f"scaffold path already exists: {scaffold}")

    verify_binary_inputs(source_root, mode)
    for relative in STATIC_ROOTS:
        verify_plain_tree(source_root / relative)

    scaffold.mkdir(parents=True, mode=0o700)
    copy_plain_tree(
        source_root / "build/bin" / mode,
        scaffold / "build/bin" / mode,
    )
    for relative in STATIC_ROOTS:
        copy_plain_tree(source_root / relative, scaffold / relative)

    image_repository = (
        scaffold
        / "img_files/generated/rustc/sys/tools/rust/lorry/vendor"
    )
    if not image_repository.is_dir():
        raise ValueError(
            f"copied Rust image lacks the full Stage 2 seed: {image_repository}"
        )
    shutil.rmtree(image_repository)
    return image_repository


def seed_installer_command(
    scaffold: Path,
    image_repository: Path,
    host_c_compiler: Path | None,
    host_archiver: Path | None,
) -> list[str]:
    work = scaffold / "build/lorry/minimal-seed"
    command = [
        sys.executable,
        str(SEED_INSTALLER),
        "--manifest",
        str(MANIFEST),
        "--build-repository",
        str(work / "generated/vendor"),
        "--host-repository",
        str(work / "host/system/vendor"),
        "--host-user-repository",
        str(work / "host/user/vendor"),
        "--host-config",
        str(work / "host/cfg/lorry.toml"),
        "--image-repository",
        str(image_repository),
        "--motor-config",
        str(
            scaffold
            / "img_files/generated/rustc/sys/tools/rust/cfg/lorry.toml"
        ),
        "--cache",
        str(DOWNLOAD_CACHE),
        "--mode",
        "minimal",
        "--offline",
    ]
    if host_c_compiler is not None:
        command.extend(("--host-c-compiler", str(host_c_compiler)))
    if host_archiver is not None:
        command.extend(("--host-archiver", str(host_archiver)))
    return command


def verify_minimal_repository(repository: Path) -> None:
    registry_root = repository / "objects/crates-io"
    if registry_root.exists():
        raise ValueError(
            f"minimal image seed contains a crates.io namespace: {registry_root}"
        )
    manifest = load_seed_manifest(MANIFEST)
    actual = repository_fingerprint(repository, manifest, "minimal")
    if actual != MINIMAL_SEED_FINGERPRINT:
        raise ValueError(
            f"minimal image seed fingerprint is {actual}; "
            f"expected {MINIMAL_SEED_FINGERPRINT}"
        )


def verify_scaffold(scaffold: Path, mode: str) -> None:
    verify_binary_inputs(scaffold, mode)
    for relative in STATIC_ROOTS:
        verify_plain_tree(scaffold / relative)
    motor_config = (
        scaffold
        / "img_files/generated/rustc/sys/tools/rust/cfg/lorry.toml"
    )
    with motor_config.open("rb") as source:
        config = tomllib.load(source)
    if (
        config.get("repositories", {}).get("system")
        != "/sys/tools/rust/lorry/vendor"
    ):
        raise ValueError(f"minimal image has an invalid Motor config: {motor_config}")


def stage_vm_scripts(scaffold: Path, mode: str) -> Path:
    destination = scaffold / "vm_images" / mode
    for source in sorted(VM_SCRIPTS.iterdir()):
        metadata = source.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"VM script input is not a regular file: {source}")
        shutil.copy2(source, destination / source.name)
    (destination / "test.key").chmod(0o400)
    return destination


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a disposable patched-source-only Motor image"
    )
    parser.add_argument("--mode", choices=("debug", "release"), required=True)
    parser.add_argument("--scaffold", type=Path, required=True)
    parser.add_argument("--imager", type=Path)
    parser.add_argument("--host-c-compiler", type=Path)
    parser.add_argument("--host-archiver", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    imager = args.imager
    if imager is None:
        imager = IMAGER_DIRECTORY / "target" / args.mode / "imager"
    try:
        imager = imager.resolve(strict=True)
        if not imager.is_file() or imager.stat().st_mode & 0o111 == 0:
            raise ValueError(f"imager is not a regular executable: {imager}")
        scaffold = args.scaffold.resolve(strict=False)
        image_repository = assemble_scaffold(
            REPOSITORY_ROOT, scaffold, args.mode
        )
        subprocess.run(
            seed_installer_command(
                scaffold,
                image_repository,
                args.host_c_compiler,
                args.host_archiver,
            ),
            check=True,
        )
        verify_minimal_repository(image_repository)
        output = scaffold / "vm_images" / args.mode
        output.mkdir(parents=True)
        verify_scaffold(scaffold, args.mode)
        subprocess.run(
            [str(imager), str(scaffold), args.mode, "motor-os.yaml"],
            cwd=IMAGER_DIRECTORY,
            check=True,
        )
        stage_vm_scripts(scaffold, args.mode)
        image = output / "motor-os.img"
        if not image.is_file():
            raise ValueError(f"imager did not produce the expected image: {image}")
        print(f"Minimal-seed Motor image: {image}")
    except (
        OSError,
        ValueError,
        subprocess.CalledProcessError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"build-minimal-seed-image: error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
