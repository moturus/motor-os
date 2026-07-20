#!/usr/bin/env python3

import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


BOOTSTRAP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BOOTSTRAP))

from seed_system_repository import (  # noqa: E402
    Limits,
    RegistryPackage,
    extract_registry_archive,
    load_seed_manifest,
    registry_object_path,
    seed_registry_repository,
)


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


class SeedSystemRepositoryTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
