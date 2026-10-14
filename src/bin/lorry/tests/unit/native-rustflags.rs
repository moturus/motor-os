use crate::build_script::{self, EnvironmentOptions};
use crate::compile::{CommandOptions, dependency_rustc_invocation};
use crate::config::CargoCompat;
use crate::manifest::{Manifest, Profile};
use crate::resolver::{CompileKind, PackageKey, PackageSourceKey};
use crate::toolchain::{CfgSet, TargetInfo, Toolchain};
use crate::unit::{
    PlanOptions, ProfileContext, Unit, UnitGraph, UnitKey, UnitKind, UnitMode,
    plan_dependency_units,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[test]
fn native_motor_rustflags_reach_host_commands_environment_and_identity() {
    let root = Path::new("/native-flags-fixture");
    let manifest = Manifest::parse(
        root,
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"1.0.0\"\nbuild = \"build.rs\"\n\
         [lib]\npath = \"src/lib.rs\"\n",
    )
    .unwrap();
    let package = PackageKey {
        name: manifest.name.clone(),
        version: semver::Version::parse("1.0.0").unwrap(),
        source: PackageSourceKey::Path(root.to_owned()),
    };
    let manifests = BTreeMap::from([(package.clone(), manifest)]);
    let order = [
        (CompileKind::Host, UnitKind::Library),
        (CompileKind::Host, UnitKind::BuildScriptCompile),
        (CompileKind::Host, UnitKind::BuildScriptRun),
        (CompileKind::Target, UnitKind::Library),
    ]
    .map(|(compile_kind, kind)| UnitKey {
        package: package.clone(),
        kind,
        mode: UnitMode::Build,
        compile_kind,
        profile: ProfileContext::Normal,
        target: None,
        features: BTreeSet::new(),
    });
    let graph = UnitGraph {
        units: order
            .iter()
            .map(|key| {
                (
                    key.clone(),
                    Unit {
                        key: key.clone(),
                        dependencies: BTreeSet::new(),
                    },
                )
            })
            .collect(),
        order: order.to_vec(),
        selected_packages: BTreeSet::new(),
        primary_macros: BTreeSet::new(),
    };
    let target = "x86_64-unknown-motor";
    let rustc = Toolchain {
        rustc: "/rustc".into(),
        clippy: None,
        verbose_version: "rustc 1.99.0-dev\nhost: x86_64-unknown-motor\n".into(),
        release: "1.99.0-dev".into(),
        host: target.into(),
        compatibility: CargoCompat::V1_99,
        query_cache: None,
    };
    let flags = vec![
        "--cfg=native_flag".into(),
        "-Cdefault-linker-libraries=yes".into(),
    ];
    let profile = Profile::release();
    for physical_target in [None, Some(target)] {
        let options = PlanOptions {
            workspace_root: root,
            release: true,
            panic_abort: false,
            profile: &profile,
            rustc: &rustc,
            logical_target: Some(target),
            physical_target,
            rustflags: &flags,
        };
        let plan = plan_dependency_units(&graph, &manifests, &options).unwrap();
        let unflagged = plan_dependency_units(
            &graph,
            &manifests,
            &PlanOptions {
                rustflags: &[],
                ..options
            },
        )
        .unwrap();
        let commands = CommandOptions {
            cargo: Path::new("/lorry"),
            workspace_root: root,
            selected_packages: &[],
            host_profile: root,
            target_profile: root,
            host_incremental: root,
            target_incremental: root,
            physical_target,
            host_linker: None,
            target_linker: None,
            integration_binaries: None,
            integration_temp_dirs: None,
            verbose: false,
        };
        for key in &order {
            let planned = &plan.units[key];
            let flagged = physical_target.is_none() || key.compile_kind == CompileKind::Target;
            assert_eq!(
                planned.settings.rustflags,
                if flagged { flags.as_slice() } else { &[] }
            );
            assert_eq!(planned.identity != unflagged.units[key].identity, flagged);
            assert_eq!(
                planned.settings.logical_target.as_deref(),
                (key.compile_kind == CompileKind::Target).then_some(target)
            );
            if key.kind != UnitKind::BuildScriptRun {
                let command = dependency_rustc_invocation(&plan, &manifests, key, &commands)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    command
                        .arguments
                        .iter()
                        .any(|arg| arg == "--cfg=native_flag"),
                    flagged
                );
            } else {
                let target_info = TargetInfo {
                    triple: target.into(),
                    cfg: CfgSet::parse("target_os=\"motor\"\n").unwrap(),
                };
                let env = build_script::environment(
                    &manifests[&package],
                    &planned.unit,
                    &planned.settings,
                    &EnvironmentOptions {
                        cargo: Path::new("/lorry"),
                        rustc: &rustc.rustc,
                        host: target,
                        target: &target_info,
                        dynamic_library_paths: &[],
                        out_dir: root,
                        temp_dir: root,
                        release: true,
                        num_jobs: 1,
                        primary_package: false,
                    },
                )
                .unwrap();
                assert_eq!(
                    env["CARGO_ENCODED_RUSTFLAGS"],
                    if flagged {
                        flags.join("\x1f")
                    } else {
                        String::new()
                    }
                    .as_str()
                );
            }
        }
    }
}
