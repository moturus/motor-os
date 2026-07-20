#!/usr/bin/env python3

import re
import tomllib
import unittest
from pathlib import Path


BOOTSTRAP = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[0-9a-f]{64}$")

CORE_PACKAGES = {
    "adler2",
    "anstyle",
    "block-buffer",
    "cfg-if",
    "clap",
    "clap_builder",
    "clap_lex",
    "cpufeatures",
    "crc32fast",
    "crypto-common",
    "digest",
    "equivalent",
    "flate2",
    "generic-array",
    "hashbrown",
    "indexmap",
    "itoa",
    "memchr",
    "miniz_oxide",
    "semver",
    "serde",
    "serde_core",
    "serde_json",
    "sha2",
    "simd-adler32",
    "strsim",
    "toml_datetime",
    "toml_edit",
    "typenum",
    "version_check",
    "winnow",
    "zmij",
}

FETCH_PACKAGES = {
    "cc",
    "cfg-if",
    "find-msvc-tools",
    "getrandom",
    "libc",
    "once_cell",
    "rustls",
    "rustls-pemfile",
    "rustls-pki-types",
    "rustls-webpki",
    "shlex",
    "subtle",
    "untrusted",
    "zeroize",
}

BUILD_SCRIPT_PACKAGES = {
    "crc32fast",
    "generic-array",
    "libc",
    "rustls",
    "semver",
    "serde",
    "serde_core",
    "serde_json",
    "zmij",
}


def load_toml(name: str) -> dict[str, object]:
    with (BOOTSTRAP / name).open("rb") as source:
        return tomllib.load(source)


class SeedManifestTests(unittest.TestCase):
    def test_production_seed_is_the_reviewed_45_object_union(self) -> None:
        manifest = load_toml("stage2-seed.toml")
        packages = manifest["crates-io"]
        identities = {(package["name"], package["version"]) for package in packages}

        self.assertEqual(manifest["manifest-version"], 1)
        self.assertEqual(manifest["repository-format-version"], 1)
        self.assertEqual(manifest["object-hash"], "sha256")
        self.assertEqual(manifest["production-registry-object-count"], 45)
        self.assertEqual(len(packages), 45)
        self.assertEqual(len(identities), 45)
        self.assertEqual({package["name"] for package in packages}, CORE_PACKAGES | FETCH_PACKAGES)

        core = {
            package["name"]
            for package in packages
            if "stage2-core" in package["lock-graphs"]
        }
        fetch = {
            package["name"]
            for package in packages
            if "lorry-fetch" in package["lock-graphs"]
        }
        self.assertEqual(core, CORE_PACKAGES)
        self.assertEqual(fetch, FETCH_PACKAGES)
        self.assertEqual(core & fetch, {"cfg-if"})
        self.assertEqual(
            {
                package["name"]
                for package in packages
                if package.get("allow-build-script", False)
            },
            BUILD_SCRIPT_PACKAGES,
        )

    def test_every_registry_object_has_closed_integrity_metadata(self) -> None:
        manifest = load_toml("stage2-seed.toml")
        graph_ids = {graph["id"] for graph in manifest["lock-graph"]}
        self.assertEqual(graph_ids, {"stage2-core", "lorry-fetch"})

        checksums = set()
        for package in manifest["crates-io"]:
            with self.subTest(package=f"{package['name']} {package['version']}"):
                self.assertRegex(package["checksum"], SHA256)
                self.assertNotIn(package["checksum"], checksums)
                checksums.add(package["checksum"])
                self.assertTrue(package["license"])
                self.assertTrue(package["retained-archive"])
                self.assertTrue(package["retained-source"])
                self.assertTrue(package["lock-graphs"])
                self.assertLessEqual(set(package["lock-graphs"]), graph_ids)

    def test_ring_identity_matches_the_phase_zero_review(self) -> None:
        manifest = load_toml("stage2-seed.toml")
        phase_zero = load_toml("phase0-ring-seed.toml")
        ring = manifest["seeded-git"]
        reviewed = phase_zero["seeded-git"]

        self.assertEqual(len(ring), 1)
        self.assertEqual(len(reviewed), 1)
        for key in (
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
            "retained-source",
        ):
            self.assertEqual(ring[0][key], reviewed[0][key])


if __name__ == "__main__":
    unittest.main()
