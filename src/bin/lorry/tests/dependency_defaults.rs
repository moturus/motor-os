mod support;

use serde_json::Value;
use support::Project;

#[test]
fn legacy_defaults_and_workspace_inheritance_follow_the_edition() {
    let project = Project::new();
    project.write("member/src/lib.rs", "pub fn probe() {}\n");
    project.write("dep/src/lib.rs", "pub fn probe() {}\n");
    project.write("dep/Cargo.toml", "[package]\nname=\"dep\"\nversion=\"1.0.0\"\n[features]\ndefault=[\"sentinel\"]\nsentinel=[]\n");
    for edition in ["2015", "2018", "2021", "2024"] {
        for variant in [
            "legacy",
            "both",
            "member-legacy",
            "root-legacy",
            "root-legacy-member-new",
            "member-both",
        ] {
            let inherited = !matches!(variant, "legacy" | "both");
            let root_keys = if variant.starts_with("root-legacy") {
                ", default_features=false"
            } else {
                ", default-features=true"
            };
            let workspace_dependency = if inherited {
                format!("[workspace.dependencies]\ndep={{path=\"dep\"{root_keys}}}\n")
            } else {
                String::new()
            };
            project.write("Cargo.toml", format!("[workspace]\nmembers=[\"member\", \"dep\"]\nresolver=\"2\"\n{workspace_dependency}"));
            let member_keys = match variant {
                "legacy" | "member-legacy" => ", default_features=false",
                "both" | "member-both" => ", default_features=false, default-features=true",
                "root-legacy-member-new" => ", default-features=true",
                _ => "",
            };
            let source = if inherited {
                "workspace=true"
            } else {
                "path=\"../dep\""
            };
            project.write("member/Cargo.toml", format!("[package]\nname=\"probe\"\nversion=\"1.0.0\"\nedition=\"{edition}\"\n[dependencies]\ndep={{{source}{member_keys}}}\n"));
            let output = project.run(&["metadata", "--no-deps", "--format-version=1", "--offline"]);
            if edition == "2024" && !matches!(variant, "member-legacy" | "member-both") {
                assert!(!output.status.success(), "{variant}");
                assert!(
                    String::from_utf8_lossy(&output.stderr)
                        .contains("unsupported as of the 2024 edition"),
                    "{variant}: {output:?}"
                );
            } else {
                assert!(output.status.success(), "{edition}/{variant}: {output:?}");
                let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
                let package = metadata["packages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|package| package["name"] == "probe")
                    .unwrap();
                let expected = !matches!(variant, "legacy" | "root-legacy")
                    && !(edition == "2024" && variant == "member-legacy");
                assert_eq!(
                    package["dependencies"][0]["uses_default_features"], expected,
                    "{edition}/{variant}"
                );
            }
        }
    }
}
