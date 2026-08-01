#!/usr/bin/env python3

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


BOOTSTRAP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BOOTSTRAP))

import build_minimal_seed_image as builder  # noqa: E402


class BuildMinimalSeedImageTests(unittest.TestCase):
    def prepare_source(self, root: Path, mode: str = "debug") -> Path:
        binary_root = root / "build/bin" / mode
        binary_root.mkdir(parents=True)
        for name in builder.required_binary_names():
            path = binary_root / name
            path.write_bytes(name.encode("ascii"))
            path.chmod(0o755)
        for relative in builder.STATIC_ROOTS:
            (root / relative).mkdir(parents=True)
            (root / relative / "sentinel").write_bytes(bytes(relative))
        vendor = (
            root
            / "img_files/generated/rustc/sys/tools/rust/lorry/vendor"
        )
        (vendor / "objects/crates-io/stale").mkdir(parents=True)
        (vendor / "objects/crates-io/stale/object").write_bytes(b"stale")
        return vendor

    def test_scaffold_materializes_inputs_and_removes_only_copied_seed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source_vendor = self.prepare_source(source)
            scaffold = root / "work/scaffold"

            image_repository = builder.assemble_scaffold(
                source, scaffold, "debug"
            )

            self.assertFalse(image_repository.exists())
            self.assertTrue(source_vendor.is_dir())
            self.assertTrue(
                (source_vendor / "objects/crates-io/stale/object").is_file()
            )
            builder.verify_binary_inputs(scaffold, "debug")
            for relative in builder.STATIC_ROOTS:
                builder.verify_plain_tree(scaffold / relative)
            self.assertTrue(
                (scaffold / "build/bin/debug/kernel").stat().st_mode & 0o111
            )

    def test_scaffold_rejects_missing_input_and_symbolic_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            self.prepare_source(source)
            (source / "build/bin/debug/kernel").unlink()
            with self.assertRaisesRegex(ValueError, "required image binary"):
                builder.assemble_scaffold(
                    source, root / "missing/scaffold", "debug"
                )

            self.prepare_source(root / "linked")
            linked = root / "linked/img_files/motor-os/link"
            linked.symlink_to("sentinel")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                builder.assemble_scaffold(
                    root / "linked", root / "symlink/scaffold", "debug"
                )

    def test_minimal_repository_requires_pinned_fingerprint_and_no_registry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "vendor"
            repository.mkdir()
            with mock.patch.object(
                builder,
                "repository_fingerprint",
                return_value=builder.MINIMAL_SEED_FINGERPRINT,
            ):
                builder.verify_minimal_repository(repository)

            with mock.patch.object(
                builder, "repository_fingerprint", return_value="0" * 64
            ):
                with self.assertRaisesRegex(ValueError, "fingerprint"):
                    builder.verify_minimal_repository(repository)

            (repository / "objects/crates-io").mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "crates.io namespace"):
                builder.verify_minimal_repository(repository)

    def test_seed_installer_uses_only_disposable_outputs(self) -> None:
        scaffold = Path("/work/scaffold")
        image_repository = scaffold / "image/vendor"
        command = builder.seed_installer_command(
            scaffold,
            image_repository,
            Path("/tools/clang"),
            Path("/tools/ar"),
        )
        joined = "\n".join(command)

        self.assertIn(str(image_repository), command)
        self.assertIn("--offline", command)
        self.assertIn("--mode", command)
        self.assertIn("minimal", command)
        self.assertIn(str(scaffold / "build/lorry/minimal-seed"), joined)
        self.assertNotIn(str(builder.REPOSITORY_ROOT / "img_files"), joined)

    def test_static_template_defines_only_the_minimal_lane(self) -> None:
        self.assertEqual(
            set(builder.template_binary_names()),
            {
                "dns-resolver",
                "rush",
                "russhd",
                "strobe",
                "sys-init",
                "sys-tty",
                "sysbox",
            },
        )

    def test_template_errors_name_the_expected_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.yaml"
            with self.assertRaisesRegex(
                ValueError, "minimal image template is unavailable at expected path"
            ):
                builder.template_binary_names(missing)


if __name__ == "__main__":
    unittest.main()
