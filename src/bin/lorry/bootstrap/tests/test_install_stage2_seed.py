#!/usr/bin/env python3

import json
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path


BOOTSTRAP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BOOTSTRAP))

from install_stage2_seed import (  # noqa: E402
    MOTOR_SYSTEM_REPOSITORY,
    install_configs,
    install_repository_copy,
    materialize_cargo_oracle_view,
    render_system_config,
    repository_fingerprint,
)
from seed_system_repository import (  # noqa: E402
    SeedManifest,
    load_seed_manifest,
    seed_system_repository,
)
from test_seed_system_repository import (  # noqa: E402
    prepare_fixture,
    prepare_git_fixture,
)


class InstallStage2SeedTests(unittest.TestCase):
    def test_repository_is_independently_copied_and_reverified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, cache, registry = prepare_fixture(root)
            limits = load_seed_manifest(manifest_path).limits
            seeded_git = prepare_git_fixture(root)
            manifest = SeedManifest(limits, (registry,), (seeded_git,))
            generated = root / "generated"
            host = root / "host"
            image = root / "image"

            seed_system_repository(
                manifest,
                generated,
                mode="full",
                cache=cache,
                offline=False,
                ca_bundle=None,
                allow_local_git=True,
            )
            install_repository_copy(generated, host, manifest, "full")
            install_repository_copy(generated, image, manifest, "full")

            expected = repository_fingerprint(generated, manifest, "full")
            self.assertEqual(repository_fingerprint(host, manifest, "full"), expected)
            self.assertEqual(repository_fingerprint(image, manifest, "full"), expected)

            install_repository_copy(generated, host, manifest, "full")
            self.assertEqual(repository_fingerprint(host, manifest, "full"), expected)

            oracle = root / "oracle"
            materialize_cargo_oracle_view(
                generated,
                oracle,
                manifest,
                "full",
            )
            checksum = json.loads(
                (oracle / "registry/demo-1.2.3/.cargo-checksum.json").read_bytes()
            )
            self.assertEqual(checksum["package"], registry.checksum)
            self.assertIn("Cargo.toml", checksum["files"])
            self.assertIn("target/kept", checksum["files"])
            self.assertTrue(
                (oracle / ".lorry/vendor/ring-0_17_14/source/Cargo.toml").is_file()
            )
            with (oracle / ".cargo/config.toml").open("rb") as source:
                cargo_config = tomllib.load(source)
            self.assertEqual(
                cargo_config["source"]["lorry-stage2-seed"]["directory"],
                str(oracle / "registry"),
            )
            with self.assertRaises(FileExistsError):
                materialize_cargo_oracle_view(
                    generated,
                    oracle,
                    manifest,
                    "full",
                )

    def test_configs_are_closed_generated_and_non_overwriting(self) -> None:
        manifest = load_seed_manifest(BOOTSTRAP / "stage2-seed.toml")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host_repository = root / "home/.config/lorry/system/vendor"
            user_repository = root / "home/.config/lorry/vendor"
            host_config = root / "home/.config/lorry/lorry.toml"
            motor_config = root / "image/sys/tools/rust/cfg/lorry.toml"

            install_configs(
                manifest,
                host_config=host_config,
                host_repository=host_repository,
                host_user_repository=user_repository,
                motor_config=motor_config,
            )

            with host_config.open("rb") as source:
                host = tomllib.load(source)
            with motor_config.open("rb") as source:
                motor = tomllib.load(source)
            self.assertEqual(
                host["repositories"]["system"], str(host_repository)
            )
            self.assertEqual(host["repositories"]["user"], str(user_repository))
            self.assertEqual(
                motor["repositories"]["system"], str(MOTOR_SYSTEM_REPOSITORY)
            )
            self.assertNotIn("user", motor["repositories"])
            self.assertEqual(len(host["policy"]["rules"]), 46)
            self.assertEqual(
                {
                    rule["name"]
                    for rule in host["policy"]["rules"].values()
                    if rule.get("allow-build-script", False)
                    and rule["source"] == "crates.io"
                },
                {
                    "crc32fast",
                    "generic-array",
                    "libc",
                    "rustls",
                    "semver",
                    "serde",
                    "serde_core",
                    "serde_json",
                    "zmij",
                },
            )
            self.assertEqual(
                motor["native-tools"]["x86_64-unknown-motor"]["archiver"][
                    "prefix-args"
                ],
                ["ar"],
            )

            original_motor = motor_config.read_bytes()
            host_config.write_text(
                '[repositories]\nsystem = "/wrong/repository"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "expected"):
                install_configs(
                    manifest,
                    host_config=host_config,
                    host_repository=host_repository,
                    host_user_repository=user_repository,
                    motor_config=motor_config,
                )
            self.assertEqual(motor_config.read_bytes(), original_motor)
            self.assertEqual(
                host_config.read_text(encoding="utf-8"),
                '[repositories]\nsystem = "/wrong/repository"\n',
            )

    def test_rendered_config_is_valid_toml(self) -> None:
        manifest = load_seed_manifest(BOOTSTRAP / "stage2-seed.toml")
        rendered = render_system_config(
            manifest,
            system_repository=Path("/system/vendor"),
            user_repository=Path("/user/vendor"),
            motor=False,
        )
        value = tomllib.loads(rendered.decode("utf-8"))
        self.assertEqual(value["config-version"], 1)
        self.assertEqual(
            value["required-patches"]["crates-io"]["ring-0_17_14"][
                "source-tree-sha256"
            ],
            manifest.seeded_git[0].source_tree_sha256,
        )


if __name__ == "__main__":
    unittest.main()
