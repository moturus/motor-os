//! Dry validation for manual evaluation definitions. This never starts Gears
//! or contacts a provider; it only proves the checked-in local fixture shape.

use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

const SCENARIO: &str = "evaluations/p0-normalize-label-v1";

fn digest(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn manual_real_model_scenario_is_complete_and_fails_closed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(SCENARIO);
    let manifest_text = std::fs::read_to_string(root.join("manifest.toml")).unwrap();
    let manifest: toml::Value = toml::from_str(&manifest_text).unwrap();
    assert_eq!(manifest["schema_version"].as_integer(), Some(1));
    assert_eq!(manifest["status"].as_str(), Some("not_run"));
    assert_eq!(
        manifest["result"]["human_acknowledged"].as_bool(),
        Some(false)
    );
    assert_eq!(manifest["result"]["result"].as_str(), Some("not_run"));
    let commit = manifest["definition_repository_commit"].as_str().unwrap();
    assert_eq!(commit.len(), 40);
    assert!(commit.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let acknowledgement = manifest["required_acknowledgement"].as_str().unwrap();
    assert!(acknowledgement.contains("human authorizing"));
    assert!(manifest["budget_ceiling"]["usd"].as_float().unwrap() > 0.0);
    assert!(manifest["budget_ceiling"]["tokens"].as_integer().unwrap() > 0);
    for field in [
        "provider_and_version",
        "model_and_version",
        "configuration_without_secrets",
        "budget_usd",
        "budget_tokens",
        "tokens",
        "cost_usd",
        "wall_time_seconds",
        "turns",
    ] {
        assert_eq!(manifest["result"][field].as_str(), Some("UNRECORDED"));
    }

    let readme = std::fs::read_to_string(root.join("README.md")).unwrap();
    assert!(readme.contains("HUMAN-ONLY MANUAL EVALUATION"));
    assert!(readme.contains("must never run Gears or contact a provider"));
    let config = std::fs::read_to_string(root.join("gears.toml.example")).unwrap();
    assert!(config.contains("HUMAN_REQUIRED"));
    assert!(gears::config::Config::parse(&config).is_err());

    for (table, base) in [("fixture_sha256", "fixture"), ("input_sha256", "")] {
        for (relative, expected) in manifest[table].as_table().unwrap() {
            assert_eq!(
                digest(&root.join(base).join(relative)),
                expected.as_str().unwrap()
            );
        }
    }

    let target =
        std::env::temp_dir().join(format!("gears-evaluation-dry-run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&target);
    let output = Command::new(env!("CARGO"))
        .args(["test", "--locked", "--offline", "--target-dir"])
        .arg(&target)
        .arg("--manifest-path")
        .arg(root.join("fixture/Cargo.toml"))
        .output()
        .unwrap();
    std::fs::remove_dir_all(target).unwrap();
    assert!(!output.status.success(), "baseline unexpectedly passed");
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for failure in ["trims_edges", "whitespace_only_is_empty"] {
        assert!(report.contains(failure), "missing {failure}: {report}");
    }
    assert!(report.contains("1 passed; 2 failed"), "{report}");
}
