#!/usr/bin/env python3

import re
import tomllib
import unittest
from pathlib import Path


BOOTSTRAP = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[0-9a-f]{64}$")

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


def locked_registry_by_graph(manifest: dict[str, object]) -> dict[str, dict[tuple[str, str], str]]:
    repository_root = BOOTSTRAP.parents[3]
    result = {}
    for graph in manifest["lock-graph"]:
        with (repository_root / graph["path"]).open("rb") as source:
            lock = tomllib.load(source)
        result[graph["id"]] = {
            (package["name"], package["version"]): package["checksum"]
            for package in lock["package"]
            if package.get("source", "").startswith("registry+")
        }
    return result


class SeedManifestTests(unittest.TestCase):
    def test_production_seed_is_the_generated_lock_graph_union(self) -> None:
        manifest = load_toml("stage2-seed.toml")
        packages = manifest["crates-io"]
        identities = {(package["name"], package["version"]) for package in packages}
        oracle_identities = {
            (package["name"], package["version"])
            for package in manifest["cargo-oracle-crates-io"]
        }
        locked = locked_registry_by_graph(manifest)
        locked_identities = set().union(*(set(graph) for graph in locked.values()))

        self.assertEqual(manifest["manifest-version"], 1)
        self.assertEqual(manifest["repository-format-version"], 1)
        self.assertEqual(manifest["object-hash"], "sha256")
        self.assertEqual(manifest["production-registry-object-count"], len(packages))
        self.assertEqual(len(identities), len(packages))
        self.assertEqual(identities | oracle_identities, locked_identities)
        for package in packages:
            identity = (package["name"], package["version"])
            expected_graphs = {
                graph for graph, graph_packages in locked.items() if identity in graph_packages
            }
            self.assertEqual(set(package["lock-graphs"]), expected_graphs)
        self.assertEqual(
            {
                package["name"]
                for package in packages
                if package.get("allow-build-script", False)
            },
            BUILD_SCRIPT_PACKAGES,
        )

    def test_cargo_oracle_closure_is_separate_from_the_production_seed(
        self,
    ) -> None:
        manifest = load_toml("stage2-seed.toml")
        production = {
            (package["name"], package["version"]): package["checksum"]
            for package in manifest["crates-io"]
        }
        oracle = manifest["cargo-oracle-crates-io"]
        oracle_identities = {
            (package["name"], package["version"]): package["checksum"]
            for package in oracle
        }
        expected_registry = {**production, **oracle_identities}
        self.assertEqual(len(oracle_identities), 16)
        self.assertFalse(production.keys() & oracle_identities.keys())
        self.assertEqual(len(oracle_identities), len(oracle))

        locked_registry = {}
        for graph in locked_registry_by_graph(manifest).values():
            for identity, checksum in graph.items():
                self.assertIn(identity, expected_registry)
                if identity in locked_registry:
                    self.assertEqual(locked_registry[identity], checksum)
                locked_registry[identity] = checksum
        self.assertEqual(locked_registry, expected_registry)

    def test_every_registry_object_has_closed_integrity_metadata(self) -> None:
        manifest = load_toml("stage2-seed.toml")
        graph_ids = {graph["id"] for graph in manifest["lock-graph"]}
        self.assertEqual(graph_ids, {"stage2-core", "curl"})

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

        for package in manifest["cargo-oracle-crates-io"]:
            with self.subTest(
                package=f"Cargo oracle {package['name']} {package['version']}"
            ):
                self.assertEqual(
                    set(package),
                    {"name", "version", "checksum", "lock-graphs"},
                )
                self.assertRegex(package["checksum"], SHA256)
                self.assertTrue(package["lock-graphs"])
                self.assertLessEqual(set(package["lock-graphs"]), graph_ids)

    def test_ring_identity_matches_the_phase_zero_review(self) -> None:
        manifest = load_toml("stage2-seed.toml")
        phase_zero = load_toml("phase0-ring-seed.toml")
        seeded_git = {
            package["name"]: package for package in manifest["seeded-git"]
        }
        reviewed = phase_zero["seeded-git"][0]

        self.assertEqual(set(seeded_git), {"cc", "ring"})
        for key in (
            "name",
            "version",
            "license",
            "upstream-crates-io-checksum",
            "git-url",
            "requested-revision",
            "resolved-commit",
            "git-tree",
            "patch-files",
            "source-tree-sha256",
            "extracted-bytes",
            "file-count",
            "directory-count",
            "retained-source",
        ):
            self.assertEqual(seeded_git["ring"][key], reviewed[key])

    def test_cc_identity_is_the_reviewed_motor_patch(self) -> None:
        manifest = load_toml("stage2-seed.toml")
        cc = {
            package["name"]: package for package in manifest["seeded-git"]
        }["cc"]

        self.assertEqual(cc["version"], "1.4.0")
        self.assertEqual(cc["git-url"], "https://github.com/moturus/cc-rs.git")
        self.assertEqual(
            cc["upstream-crates-io-checksum"],
            "5add81bb678e6cb321aff7fa0dc7689ad82b112dbc032cea19f91d6b8e3582b9",
        )
        self.assertEqual(
            cc["resolved-commit"],
            "02932efc0d268db49c150a3ae31a6ad2c422f45b",
        )
        self.assertEqual(cc["patch-files"], ["src/tempfile.rs"])
        self.assertEqual(
            cc["source-tree-sha256"],
            "c4d4a87a32f84d17bfabe7dcaa0bbd75986053a18c97448aa80d394afce214b0",
        )


if __name__ == "__main__":
    unittest.main()
