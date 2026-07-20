#!/usr/bin/env python3

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


BOOTSTRAP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BOOTSTRAP))

from seed_system_repository import (  # noqa: E402
    Limits,
    RegistryPackage,
    SeedManifest,
    SeededGitPackage,
    extract_registry_archive,
    load_seed_manifest,
    rename_no_replace,
    registry_object_path,
    seed_registry_repository,
    seed_system_repository,
    seeded_git_object_path,
)
from source_tree_digest import source_tree  # noqa: E402


TEST_LIMITS = """\
[limits]
max-package-bytes = 1048576
max-extracted-package-bytes = 1048576
max-package-files = 100
max-path-bytes = 256
"""


def add_directory(archive: tarfile.TarFile, name: str) -> None:
    entry = tarfile.TarInfo(name)
    entry.type = tarfile.DIRTYPE
    entry.mode = 0o755
    archive.addfile(entry)


def add_file(
    archive: tarfile.TarFile, name: str, contents: bytes, mode: int = 0o644
) -> None:
    entry = tarfile.TarInfo(name)
    entry.size = len(contents)
    entry.mode = mode
    archive.addfile(entry, io.BytesIO(contents))


def write_crate(
    path: Path,
    name: str = "demo",
    version: str = "1.2.3",
    malicious=None,
) -> bytes:
    root = f"{name}-{version}"
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        add_directory(archive, root)
        add_directory(archive, f"{root}/src")
        add_file(
            archive,
            f"{root}/Cargo.toml",
            b'[package]\nname = "demo"\nversion = "1.2.3"\n',
        )
        add_file(
            archive,
            f"{root}/src/main.rs",
            b'fn main() { println!("seeded"); }\n',
            0o755,
        )
        add_directory(archive, f"{root}/target")
        add_file(archive, f"{root}/target/kept", b"registry source\n")
        if malicious is not None:
            malicious(archive, root)
    return path.read_bytes()


def index_record(package: RegistryPackage) -> bytes:
    return (
        json.dumps(
            {
                "name": package.name,
                "vers": package.version,
                "deps": [],
                "cksum": package.checksum,
                "features": {},
                "yanked": False,
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def write_manifest(path: Path, package: RegistryPackage) -> None:
    path.write_text(
        f"""\
manifest-version = 1
repository-format-version = 1
object-hash = "sha256"
production-registry-object-count = 1

{TEST_LIMITS}

[[lock-graph]]
id = "test"
path = "Cargo.lock"

[[crates-io]]
name = "{package.name}"
version = "{package.version}"
checksum = "{package.checksum}"
license = "{package.license}"
lock-graphs = ["test"]
retained-archive = true
retained-source = true
""",
        encoding="utf-8",
    )


def prepare_fixture(root: Path) -> tuple[Path, Path, RegistryPackage]:
    archive_path = root / "demo.crate"
    archive = write_crate(archive_path)
    package = RegistryPackage(
        "demo",
        "1.2.3",
        hashlib.sha256(archive).hexdigest(),
        "MIT OR Apache-2.0",
        ("test",),
        True,
        True,
    )
    manifest_path = root / "seed.toml"
    write_manifest(manifest_path, package)
    cache = root / "cache"
    archive_cache = cache / "archives" / package.archive_name
    archive_cache.parent.mkdir(parents=True)
    archive_cache.write_bytes(archive)
    record_cache = cache / "index-records" / f"{package.name}-{package.version}.json"
    record_cache.parent.mkdir(parents=True)
    record_cache.write_bytes(index_record(package))
    return manifest_path, cache, package


def git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def prepare_git_fixture(
    root: Path,
    *,
    with_symlink: bool = False,
) -> SeededGitPackage:
    repository = root / "upstream"
    repository.mkdir()
    git(repository, "init", "--quiet", "--initial-branch=reviewed")
    git(repository, "config", "user.name", "Lorry Test")
    git(repository, "config", "user.email", "lorry@example.invalid")
    (repository / "src").mkdir()
    (repository / "Cargo.toml").write_text(
        '[package]\nname = "git-demo"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    (repository / "src/lib.rs").write_text(
        "pub fn seeded() -> bool { true }\n",
        encoding="utf-8",
    )
    executable = repository / "configure"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    if with_symlink:
        (repository / "link").symlink_to("Cargo.toml")
    git(repository, "add", ".")
    git(repository, "commit", "--quiet", "-m", "reviewed tree")
    commit = git(repository, "rev-parse", "HEAD")
    tree_id = git(repository, "rev-parse", "HEAD^{tree}")
    if with_symlink:
        tree_sha256 = "0" * 64
        tree_bytes = 1
        file_count = 1
        directory_count = 1
    else:
        tree = source_tree(repository)
        tree_sha256 = tree.sha256
        tree_bytes = tree.total_bytes
        file_count = tree.file_count
        directory_count = tree.directory_count
    return SeededGitPackage(
        "git-demo",
        "1.0.0",
        "MIT",
        "1" * 64,
        str(repository),
        "reviewed",
        commit,
        tree_id,
        tree_sha256,
        tree_bytes,
        file_count,
        directory_count,
        ("test",),
        True,
    )


class SeedSystemRepositoryTests(unittest.TestCase):
    def test_directory_install_never_replaces_an_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            destination.mkdir()
            (source / "source-marker").write_text("source", encoding="utf-8")
            (destination / "destination-marker").write_text(
                "destination", encoding="utf-8"
            )

            with self.assertRaises(FileExistsError):
                rename_no_replace(source, destination)

            self.assertTrue((source / "source-marker").is_file())
            self.assertTrue((destination / "destination-marker").is_file())

    def test_offline_seed_is_complete_reproducible_and_reverified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, cache, package = prepare_fixture(root)
            manifest = load_seed_manifest(manifest_path)
            repository = root / "repository"

            seed_registry_repository(
                manifest,
                repository,
                cache=cache,
                offline=True,
                ca_bundle=None,
            )

            object_path = registry_object_path(repository, package.checksum)
            self.assertEqual(
                (repository / "repository.toml").read_text(encoding="utf-8"),
                'format-version = 1\nobject-hash = "sha256"\n',
            )
            self.assertEqual(
                (object_path / "package.crate").read_bytes(),
                (cache / "archives" / package.archive_name).read_bytes(),
            )
            self.assertTrue((object_path / "source/Cargo.toml").is_file())
            self.assertTrue((object_path / "source/target/kept").is_file())
            self.assertTrue(
                (object_path / "source/src/main.rs").stat().st_mode & 0o111
            )

            first_manifest = (object_path / "source-manifest.json").read_bytes()
            seed_registry_repository(
                manifest,
                repository,
                cache=cache,
                offline=True,
                ca_bundle=None,
            )
            self.assertEqual(
                (object_path / "source-manifest.json").read_bytes(),
                first_manifest,
            )

            (object_path / "source/src/main.rs").write_text(
                "corrupt\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "count mismatch|manifest mismatch"):
                seed_registry_repository(
                    manifest,
                    repository,
                    cache=cache,
                    offline=True,
                    ca_bundle=None,
                )
            self.assertEqual(
                (object_path / "source/src/main.rs").read_text(encoding="utf-8"),
                "corrupt\n",
            )

    def test_failed_seed_exposes_no_partial_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, cache, package = prepare_fixture(root)
            archive = cache / "archives" / package.archive_name
            archive.write_bytes(archive.read_bytes() + b"corrupt")
            repository = root / "repository"

            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                seed_registry_repository(
                    load_seed_manifest(manifest_path),
                    repository,
                    cache=cache,
                    offline=True,
                    ca_bundle=None,
                )

            self.assertFalse(repository.exists())
            self.assertEqual(list(root.glob(".repository.lorry-seed-*")), [])

    def test_archive_rejects_traversal_links_and_duplicate_entries(self) -> None:
        cases = {}

        def traversal(archive, root):
            add_file(archive, f"{root}/../escape", b"escape")

        cases["unsafe archive path"] = traversal

        def link(archive, root):
            entry = tarfile.TarInfo(f"{root}/link")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "Cargo.toml"
            archive.addfile(entry)

        cases["unsupported archive entry"] = link

        def duplicate(archive, root):
            add_file(archive, f"{root}/Cargo.toml", b"duplicate")

        cases["duplicate archive entry"] = duplicate

        for expected, malicious in cases.items():
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    archive = root / "malicious.crate"
                    data = write_crate(archive, malicious=malicious)
                    package = RegistryPackage(
                        "demo",
                        "1.2.3",
                        hashlib.sha256(data).hexdigest(),
                        "MIT",
                        ("test",),
                        True,
                        True,
                    )
                    with self.assertRaisesRegex(ValueError, expected):
                        extract_registry_archive(
                            archive,
                            root / "source",
                            package,
                            Limits(1048576, 1048576, 100, 256),
                        )
                    self.assertFalse((root / "escape").exists())

    def test_seeded_git_is_verified_cached_and_reproduced_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = prepare_git_fixture(root)
            manifest = SeedManifest(
                Limits(1048576, 1048576, 100, 256),
                (),
                (package,),
            )
            cache = root / "cache"
            first = root / "first"
            second = root / "second"

            seed_system_repository(
                manifest,
                first,
                mode="minimal",
                cache=cache,
                offline=False,
                ca_bundle=None,
                allow_local_git=True,
            )
            seed_system_repository(
                manifest,
                second,
                mode="minimal",
                cache=cache,
                offline=True,
                ca_bundle=None,
                allow_local_git=True,
            )

            first_object = seeded_git_object_path(first, package.source_tree_sha256)
            second_object = seeded_git_object_path(second, package.source_tree_sha256)
            self.assertEqual(
                (first_object / "package.toml").read_bytes(),
                (second_object / "package.toml").read_bytes(),
            )
            self.assertEqual(
                (first_object / "source-manifest.json").read_bytes(),
                (second_object / "source-manifest.json").read_bytes(),
            )
            self.assertFalse((first_object / "source/.git").exists())
            self.assertTrue((first_object / "source/configure").stat().st_mode & 0o111)

            (first_object / "source/src/lib.rs").write_text(
                "corrupt\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "count mismatch|digest mismatch"):
                seed_system_repository(
                    manifest,
                    first,
                    mode="minimal",
                    cache=cache,
                    offline=True,
                    ca_bundle=None,
                    allow_local_git=True,
                )

    def test_seeded_git_rejects_commit_tree_digest_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = prepare_git_fixture(root)
            limits = Limits(1048576, 1048576, 100, 256)

            wrong_commit = replace(valid, resolved_commit="0" * 40)
            with self.assertRaisesRegex(ValueError, "resolved Git commit mismatch"):
                seed_system_repository(
                    SeedManifest(limits, (), (wrong_commit,)),
                    root / "wrong-commit",
                    mode="minimal",
                    cache=None,
                    offline=False,
                    ca_bundle=None,
                    allow_local_git=True,
                )

            wrong_tree = replace(valid, git_tree="0" * 40)
            with self.assertRaisesRegex(ValueError, "Git tree mismatch"):
                seed_system_repository(
                    SeedManifest(limits, (), (wrong_tree,)),
                    root / "wrong-tree",
                    mode="minimal",
                    cache=None,
                    offline=False,
                    ca_bundle=None,
                    allow_local_git=True,
                )

            wrong_digest = replace(valid, source_tree_sha256="0" * 64)
            with self.assertRaisesRegex(ValueError, "source-tree digest mismatch"):
                seed_system_repository(
                    SeedManifest(limits, (), (wrong_digest,)),
                    root / "wrong-digest",
                    mode="minimal",
                    cache=None,
                    offline=False,
                    ca_bundle=None,
                    allow_local_git=True,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            linked = prepare_git_fixture(root, with_symlink=True)
            with self.assertRaisesRegex(ValueError, "unsupported Git entry"):
                seed_system_repository(
                    SeedManifest(
                        Limits(1048576, 1048576, 100, 256),
                        (),
                        (linked,),
                    ),
                    root / "linked",
                    mode="minimal",
                    cache=None,
                    offline=False,
                    ca_bundle=None,
                    allow_local_git=True,
                )


if __name__ == "__main__":
    unittest.main()
