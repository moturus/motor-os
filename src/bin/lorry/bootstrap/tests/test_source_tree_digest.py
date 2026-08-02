#!/usr/bin/env python3

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


BOOTSTRAP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BOOTSTRAP))

from source_tree_digest import (  # noqa: E402
    SourceEntry,
    SourceTreeLimits,
    digest_entries,
    source_tree,
)


class SourceTreeDigestTests(unittest.TestCase):
    def load_vectors(self) -> dict[str, object]:
        path = Path(__file__).with_name("source-tree-v1-vectors.json")
        return json.loads(path.read_text(encoding="utf-8"))

    def vector_entries(self, vector: dict[str, object]) -> list[SourceEntry]:
        entries = []
        for value in vector["entries"]:
            entries.append(
                SourceEntry(
                    value["path"],
                    1 if value["kind"] == "directory" else 2,
                    value["executable"],
                    value["length"],
                    value["sha256"],
                )
            )
        return entries

    def test_fixed_framing_vectors(self) -> None:
        vectors = self.load_vectors()
        self.assertEqual(vectors["format-version"], 1)
        for vector in vectors["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    digest_entries(self.vector_entries(vector)),
                    vector["source-tree-sha256"],
                )

    def test_scanned_tree_matches_portable_vector_and_manifest(self) -> None:
        vector = self.load_vectors()["vectors"][1]
        values = {entry["path"]: entry for entry in vector["entries"]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            (root / "empty").mkdir()
            tool = root / "bin/tool"
            tool.write_bytes(bytes.fromhex(values["bin/tool"]["content-hex"]))
            tool.chmod(0o700)
            (root / "café.txt").write_bytes(
                bytes.fromhex(values["café.txt"]["content-hex"])
            )

            result = source_tree(root)

            self.assertEqual(result.sha256, vector["source-tree-sha256"])
            self.assertEqual(result.file_count, 2)
            self.assertEqual(result.directory_count, 2)
            self.assertEqual(result.total_bytes, 23)
            manifest = json.loads(result.manifest_bytes())
            self.assertEqual(manifest["format-version"], 1)
            self.assertEqual(manifest["source-tree-sha256"], result.sha256)
            self.assertEqual(
                [entry["path"] for entry in manifest["entries"]],
                ["bin", "bin/tool", "café.txt", "empty"],
            )

    def test_rejects_links_nonportable_paths_and_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "file").write_text("contents", encoding="utf-8")
            (root / "link").symlink_to("file")
            with self.assertRaisesRegex(ValueError, "unsupported source entry"):
                source_tree(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bad\\name").write_text("contents", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-portable source path"):
                source_tree(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "large").write_bytes(b"1234")
            with self.assertRaisesRegex(ValueError, "source file exceeds byte limit"):
                source_tree(root, SourceTreeLimits(max_file_bytes=3))

    def test_excludes_git_and_build_output_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".git").mkdir()
            (root / ".git/config").write_text("ignored", encoding="utf-8")
            (root / "target").mkdir()
            (root / "target/output").write_text("ignored", encoding="utf-8")
            (root / "Cargo.toml").write_text("[package]\n", encoding="utf-8")

            result = source_tree(root)

            self.assertEqual([entry.path for entry in result.entries], ["Cargo.toml"])
            self.assertEqual(
                result.entries[0].sha256,
                hashlib.sha256(b"[package]\n").hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
