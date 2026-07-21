#![allow(dead_code)]

use crate::hash::StableHasher;
use crate::manifest::{Lto as ManifestLto, ReleaseProfile, Strip as ManifestStrip, Version};
use crate::toolchain::Toolchain;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub metadata: String,
    pub extra_filename: String,
    metadata_value: u64,
    unit_id_value: u64,
}

pub struct IdentityInput<'a> {
    pub package_name: &'a str,
    pub version: &'a Version,
    pub target_name: &'a str,
    pub target_kind: RootTargetKind,
    pub features: &'a [String],
    pub release: bool,
    pub test: bool,
    pub test_profile: bool,
    /// Cargo's logical compile kind. Native Motor uses an explicit logical
    /// target here even when rustc itself is invoked without `--target`.
    pub logical_target: Option<&'a str>,
    pub release_profile: &'a ReleaseProfile,
    pub rustc: &'a Toolchain,
    pub rustflags: &'a [String],
    pub dependencies: &'a [Identity],
}

pub fn cargo_identity(input: &IdentityInput<'_>) -> Identity {
    let profile = stage_one_profile(input);
    cargo_unit_identity(&CargoUnitIdentityInput {
        package_name: input.package_name,
        version: input.version,
        source: CargoSource::Path(""),
        features: input.features,
        profile: &profile,
        mode: if input.test {
            CargoCompileMode::Test
        } else {
            CargoCompileMode::Build
        },
        lto: root_lto(
            input.release,
            input.release_profile.lto,
            input.target_kind,
            input.test,
        ),
        logical_target: input.logical_target,
        target_name: input.target_name,
        target_kind: match input.target_kind {
            RootTargetKind::Library => CargoTargetKind::Lib(vec![CargoCrateType::Lib]),
            RootTargetKind::Binary => CargoTargetKind::Bin,
            RootTargetKind::IntegrationTest => CargoTargetKind::Test,
        },
        rustc: input.rustc,
        rustflags: input.rustflags,
        extra_arguments: &[],
        dependencies: input.dependencies,
        host_configuration_differs: None,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootTargetKind {
    Library,
    Binary,
    IntegrationTest,
}

pub struct CargoUnitIdentityInput<'a> {
    pub package_name: &'a str,
    pub version: &'a Version,
    pub source: CargoSource<'a>,
    /// Cargo stores enabled features as a sorted vector.
    pub features: &'a [String],
    pub profile: &'a CargoProfile<'a>,
    pub mode: CargoCompileMode,
    pub lto: CargoUnitLto<'a>,
    /// `None` is Cargo's host compile kind; `Some` is an explicit target.
    pub logical_target: Option<&'a str>,
    pub target_name: &'a str,
    pub target_kind: CargoTargetKind<'a>,
    pub rustc: &'a Toolchain,
    pub rustflags: &'a [String],
    pub extra_arguments: &'a [String],
    pub dependencies: &'a [Identity],
    /// Cargo hashes this boolean only for a host unit when target
    /// configuration has explicitly stopped applying to the host.
    pub host_configuration_differs: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CargoSource<'a> {
    /// The string is Cargo's workspace-relative path, or its file URL when the
    /// package is outside the workspace.
    Path(&'a str),
    CratesIo,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CargoCompileMode {
    Test,
    Build,
    Check { test: bool },
    Doc,
    Doctest,
    Docscrape,
    RunCustomBuild,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CargoTargetKind<'a> {
    Lib(Vec<CargoCrateType<'a>>),
    Bin,
    Test,
    Bench,
    ExampleLib(Vec<CargoCrateType<'a>>),
    ExampleBin,
    CustomBuild,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CargoCrateType<'a> {
    Bin,
    Lib,
    Rlib,
    Dylib,
    Cdylib,
    Staticlib,
    ProcMacro,
    Other(&'a str),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CargoProfileLto<'a> {
    Off,
    Bool(bool),
    Named(&'a str),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CargoDebugInfo {
    None,
    LineDirectivesOnly,
    LineTablesOnly,
    Limited,
    Full,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CargoPanicStrategy {
    Unwind,
    Abort,
    ImmediateAbort,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CargoStrip<'a> {
    None,
    Named(&'a str),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CargoUnitLto<'a> {
    Run(Option<&'a str>),
    Off,
    OnlyBitcode,
    ObjectAndBitcode,
    OnlyObject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoProfile<'a> {
    pub opt_level: &'a str,
    pub lto: CargoProfileLto<'a>,
    pub codegen_backend: Option<&'a str>,
    pub codegen_units: Option<u32>,
    pub debuginfo: CargoDebugInfo,
    pub split_debuginfo: Option<&'a str>,
    pub debug_assertions: bool,
    pub overflow_checks: bool,
    pub rpath: bool,
    pub incremental: bool,
    pub panic: CargoPanicStrategy,
    pub strip: CargoStrip<'a>,
    pub rustflags: &'a [String],
}

pub fn cargo_unit_identity(input: &CargoUnitIdentityInput<'_>) -> Identity {
    let mut shared = StableHasher::new();
    2u8.hash(&mut shared);

    input.package_name.hash(&mut shared);
    input.version.major.hash(&mut shared);
    input.version.minor.hash(&mut shared);
    input.version.patch.hash(&mut shared);
    input.version.pre.hash(&mut shared);
    input.version.build.hash(&mut shared);
    match input.source {
        CargoSource::Path(path) => {
            std::mem::discriminant(&SourceKind::Path).hash(&mut shared);
            path.hash(&mut shared);
        }
        CargoSource::CratesIo => {
            std::mem::discriminant(&SourceKind::Registry).hash(&mut shared);
            "https://github.com/rust-lang/crates.io-index".hash(&mut shared);
        }
    }

    input.features.hash(&mut shared);
    hash_profile(input.profile, &mut shared);
    input.mode.hash(&mut shared);
    input.lto.hash(&mut shared);

    let kind_fingerprint = match input.logical_target {
        None => 0,
        Some(target) => {
            let mut target_hasher = StableHasher::new();
            target.hash(&mut target_hasher);
            target_hasher.finish()
        }
    };
    kind_fingerprint.hash(&mut shared);
    input.target_name.hash(&mut shared);
    input.target_kind.hash(&mut shared);
    hash_rustc_version(input, &mut shared);
    false.hash(&mut shared);
    if let Some(differs) = input.host_configuration_differs {
        differs.hash(&mut shared);
    }

    let mut metadata = shared.clone();
    let mut dependency_metadata = input
        .dependencies
        .iter()
        .map(|identity| identity.metadata_value)
        .collect::<Vec<_>>();
    dependency_metadata.sort();
    dependency_metadata.hash(&mut metadata);

    let mut unit = shared;
    let mut dependency_units = input
        .dependencies
        .iter()
        .map(|identity| identity.unit_id_value)
        .collect::<Vec<_>>();
    dependency_units.sort();
    dependency_units.hash(&mut unit);
    if !has_remap_path_prefix(input.extra_arguments) {
        input.extra_arguments.hash(&mut unit);
    }
    if !has_remap_path_prefix(input.rustflags) {
        input.rustflags.hash(&mut unit);
    }

    let metadata_value = metadata.finish();
    let unit_id_value = unit.finish();

    Identity {
        metadata: format!("{metadata_value:016x}"),
        extra_filename: format!("-{unit_id_value:016x}"),
        metadata_value,
        unit_id_value,
    }
}

fn stage_one_profile<'a>(input: &'a IdentityInput<'a>) -> CargoProfile<'a> {
    let release = input.release;
    if release {
        CargoProfile {
            opt_level: "3",
            lto: manifest_profile_lto(input.release_profile.lto),
            codegen_backend: None,
            codegen_units: input.release_profile.codegen_units,
            debuginfo: CargoDebugInfo::None,
            split_debuginfo: None,
            debug_assertions: false,
            overflow_checks: false,
            rpath: false,
            incremental: false,
            panic: if input.test_profile || !input.release_profile.panic_abort {
                CargoPanicStrategy::Unwind
            } else {
                CargoPanicStrategy::Abort
            },
            strip: manifest_strip(input.release_profile.strip),
            rustflags: &[],
        }
    } else {
        CargoProfile {
            opt_level: "0",
            lto: CargoProfileLto::Bool(false),
            codegen_backend: None,
            codegen_units: None,
            debuginfo: CargoDebugInfo::Full,
            split_debuginfo: None,
            debug_assertions: true,
            overflow_checks: true,
            rpath: false,
            incremental: true,
            panic: CargoPanicStrategy::Unwind,
            strip: CargoStrip::None,
            rustflags: &[],
        }
    }
}

fn hash_profile(profile: &CargoProfile<'_>, hasher: &mut StableHasher) {
    profile.opt_level.hash(hasher);
    profile.lto.hash(hasher);
    profile.codegen_backend.hash(hasher);
    profile.codegen_units.hash(hasher);
    profile.debuginfo.hash(hasher);
    profile.split_debuginfo.hash(hasher);
    profile.debug_assertions.hash(hasher);
    profile.overflow_checks.hash(hasher);
    profile.rpath.hash(hasher);
    (profile.incremental, profile.panic, profile.strip).hash(hasher);
    profile.rustflags.hash(hasher);
    // Stage 2 does not admit Cargo's unstable trim-paths profile setting.
    Option::<&str>::None.hash(hasher);
}

fn manifest_profile_lto(lto: ManifestLto) -> CargoProfileLto<'static> {
    match lto {
        ManifestLto::Default => CargoProfileLto::Bool(false),
        ManifestLto::True => CargoProfileLto::Bool(true),
        ManifestLto::Fat => CargoProfileLto::Named("fat"),
        ManifestLto::Thin => CargoProfileLto::Named("thin"),
        ManifestLto::Off => CargoProfileLto::Off,
    }
}

fn manifest_strip(strip: ManifestStrip) -> CargoStrip<'static> {
    match strip {
        ManifestStrip::None => CargoStrip::None,
        ManifestStrip::Debuginfo => CargoStrip::Named("debuginfo"),
        ManifestStrip::Symbols => CargoStrip::Named("symbols"),
    }
}

pub fn root_lto(
    release: bool,
    profile_lto: ManifestLto,
    target_kind: RootTargetKind,
    test: bool,
) -> CargoUnitLto<'static> {
    if target_kind == RootTargetKind::Library && !test {
        return if release {
            match profile_lto {
                ManifestLto::True | ManifestLto::Fat | ManifestLto::Thin => {
                    CargoUnitLto::OnlyBitcode
                }
                ManifestLto::Off => CargoUnitLto::Off,
                ManifestLto::Default => CargoUnitLto::OnlyObject,
            }
        } else {
            CargoUnitLto::OnlyObject
        };
    }
    if release {
        match profile_lto {
            ManifestLto::True => CargoUnitLto::Run(None),
            ManifestLto::Fat => CargoUnitLto::Run(Some("fat")),
            ManifestLto::Thin => CargoUnitLto::Run(Some("thin")),
            ManifestLto::Off => CargoUnitLto::Off,
            ManifestLto::Default => CargoUnitLto::OnlyObject,
        }
    } else {
        CargoUnitLto::OnlyObject
    }
}

fn hash_rustc_version(input: &CargoUnitIdentityInput<'_>, hasher: &mut StableHasher) {
    let prerelease = input
        .rustc
        .release
        .split_once('-')
        .map(|(_, prerelease)| prerelease);
    if let Some(prerelease) = prerelease {
        prerelease.split('.').next().hash(hasher);
        if input.logical_target.is_none() {
            input.rustc.host.hash(hasher);
        }
    } else {
        for line in input.rustc.verbose_version.lines() {
            if input.logical_target.is_none() || !line.starts_with("host: ") {
                line.hash(hasher);
            }
        }
    }
}

fn has_remap_path_prefix(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| {
        argument == "--remap-path-prefix" || argument.starts_with("--remap-path-prefix=")
    })
}

#[allow(dead_code)]
#[derive(Hash)]
enum SourceKind {
    Git(String),
    Path,
    Registry,
    SparseRegistry,
    LocalRegistry,
    Directory,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CargoCompat;

    fn version() -> Version {
        parsed_version("0.1.0")
    }

    fn parsed_version(value: &str) -> Version {
        let parsed = semver::Version::parse(value).unwrap();
        Version {
            original: value.to_owned(),
            major: parsed.major,
            minor: parsed.minor,
            patch: parsed.patch,
            pre: parsed.pre.to_string(),
            build: parsed.build.to_string(),
        }
    }

    fn captured_identity(metadata: &str, extra_filename: &str) -> Identity {
        Identity {
            metadata: metadata.to_owned(),
            extra_filename: extra_filename.to_owned(),
            metadata_value: u64::from_str_radix(metadata, 16).unwrap(),
            unit_id_value: u64::from_str_radix(extra_filename.trim_start_matches('-'), 16).unwrap(),
        }
    }

    fn profile() -> ReleaseProfile {
        ReleaseProfile {
            panic_abort: true,
            lto: ManifestLto::Fat,
            strip: ManifestStrip::Symbols,
            codegen_units: Some(1),
        }
    }

    fn native_toolchain() -> Toolchain {
        Toolchain {
            rustc: "/rustc".into(),
            verbose_version: "rustc 1.98.0-nightly (bc2112ed5 2026-06-18)\n\
                              binary: rustc\n\
                              commit-hash: bc2112ed56c99fa649e09ab3ab286afab3d9059a\n\
                              commit-date: 2026-06-18\n\
                              host: x86_64-unknown-linux-gnu\n\
                              release: 1.98.0-nightly\n\
                              LLVM version: 22.1.7\n"
                .to_owned(),
            release: "1.98.0-nightly".to_owned(),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            compatibility: CargoCompat::V1_98,
        }
    }

    fn motor_toolchain() -> Toolchain {
        Toolchain {
            rustc: "/rustc".into(),
            verbose_version: "rustc 1.98.0-dev\n\
                              binary: rustc\n\
                              commit-hash: unknown\n\
                              commit-date: unknown\n\
                              host: x86_64-unknown-linux-gnu\n\
                              release: 1.98.0-dev\n\
                              LLVM version: 23.0.0\n"
                .to_owned(),
            release: "1.98.0-dev".to_owned(),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            compatibility: CargoCompat::V1_98,
        }
    }

    fn release_profile<'a>() -> CargoProfile<'a> {
        CargoProfile {
            opt_level: "3",
            lto: CargoProfileLto::Named("fat"),
            codegen_backend: None,
            codegen_units: Some(1),
            debuginfo: CargoDebugInfo::None,
            split_debuginfo: None,
            debug_assertions: false,
            overflow_checks: false,
            rpath: false,
            incremental: false,
            panic: CargoPanicStrategy::Abort,
            strip: CargoStrip::Named("symbols"),
            rustflags: &[],
        }
    }

    fn build_profile<'a>() -> CargoProfile<'a> {
        CargoProfile {
            opt_level: "0",
            lto: CargoProfileLto::Named("fat"),
            codegen_backend: None,
            codegen_units: None,
            debuginfo: CargoDebugInfo::None,
            split_debuginfo: None,
            debug_assertions: false,
            overflow_checks: false,
            rpath: false,
            incremental: false,
            panic: CargoPanicStrategy::Unwind,
            strip: CargoStrip::Named("symbols"),
            rustflags: &[],
        }
    }

    fn run_build_profile<'a>() -> CargoProfile<'a> {
        CargoProfile {
            opt_level: "3",
            lto: CargoProfileLto::Bool(false),
            codegen_backend: None,
            codegen_units: None,
            debuginfo: CargoDebugInfo::None,
            split_debuginfo: None,
            debug_assertions: false,
            overflow_checks: false,
            rpath: false,
            incremental: false,
            panic: CargoPanicStrategy::Unwind,
            strip: CargoStrip::Named("debuginfo"),
            rustflags: &[],
        }
    }

    fn registry_library(
        name: &str,
        version: &Version,
        crate_name: &str,
        features: &[String],
        profile: &CargoProfile<'_>,
        lto: CargoUnitLto<'_>,
        dependencies: &[Identity],
    ) -> Identity {
        cargo_unit_identity(&CargoUnitIdentityInput {
            package_name: name,
            version,
            source: CargoSource::CratesIo,
            features,
            profile,
            mode: CargoCompileMode::Build,
            lto,
            logical_target: None,
            target_name: crate_name,
            target_kind: CargoTargetKind::Lib(vec![CargoCrateType::Lib]),
            rustc: &native_toolchain(),
            rustflags: &[],
            extra_arguments: &[],
            dependencies,
            host_configuration_differs: None,
        })
    }

    #[test]
    fn matches_all_stage_one_cargo_oracle_identities() {
        let version = version();
        let profile = profile();
        let native = native_toolchain();
        let motor = motor_toolchain();
        for (release, test, toolchain, target, metadata, extra) in [
            (
                false,
                false,
                &native,
                None,
                "21ddaf467d140da2",
                "-682bd9b3639f73b0",
            ),
            (
                false,
                true,
                &native,
                None,
                "61bdcd556a960a48",
                "-49fe10894af1cd5e",
            ),
            (
                true,
                false,
                &native,
                None,
                "383c09b6fac15a9f",
                "-3192ca1bd04bc552",
            ),
            (
                true,
                true,
                &native,
                None,
                "74aac86d015964e0",
                "-07186d9f96045ca2",
            ),
            (
                false,
                false,
                &motor,
                Some("x86_64-unknown-motor"),
                "bfcb236d1978af58",
                "-7c6f12825b966511",
            ),
            (
                false,
                true,
                &motor,
                Some("x86_64-unknown-motor"),
                "b1568c6aa36055f1",
                "-62f30cf1672597e1",
            ),
            (
                true,
                false,
                &motor,
                Some("x86_64-unknown-motor"),
                "dcd19f902df9ef76",
                "-7ece998c9de35604",
            ),
            (
                true,
                true,
                &motor,
                Some("x86_64-unknown-motor"),
                "9d55f51e411f5219",
                "-d6ce5b974d464d9b",
            ),
        ] {
            let identity = cargo_identity(&IdentityInput {
                package_name: "red",
                version: &version,
                target_name: "red",
                target_kind: RootTargetKind::Binary,
                features: &[],
                release,
                test,
                test_profile: test,
                logical_target: target,
                release_profile: &profile,
                rustc: toolchain,
                rustflags: &[],
                dependencies: &[],
            });
            assert_eq!(
                identity.metadata, metadata,
                "release={release} test={test} target={target:?}"
            );
            assert_eq!(
                identity.extra_filename, extra,
                "release={release} test={test} target={target:?}"
            );
        }
    }

    #[test]
    fn matches_the_rush_root_library_and_binary_oracle() {
        let libc = captured_identity("e8cf5400220b6b46", "-4c594f23b34d121c");
        let version = version();
        let profile = profile();
        let toolchain = native_toolchain();
        let library = cargo_identity(&IdentityInput {
            package_name: "moto-rush",
            version: &version,
            target_name: "moto_rush",
            target_kind: RootTargetKind::Library,
            features: &[],
            release: true,
            test: false,
            test_profile: false,
            logical_target: None,
            release_profile: &profile,
            rustc: &toolchain,
            rustflags: &[],
            dependencies: std::slice::from_ref(&libc),
        });
        assert_eq!(library.metadata, "fe7dad0dd7e45261");
        assert_eq!(library.extra_filename, "-f04486fca22dc62e");

        let binary = cargo_identity(&IdentityInput {
            package_name: "moto-rush",
            version: &version,
            target_name: "rush",
            target_kind: RootTargetKind::Binary,
            features: &[],
            release: true,
            test: false,
            test_profile: false,
            logical_target: None,
            release_profile: &profile,
            rustc: &toolchain,
            rustflags: &[],
            dependencies: &[libc, library],
        });
        assert_eq!(binary.metadata, "08ff74a380108d7e");
        assert_eq!(binary.extra_filename, "-96c671f6ca98063a");
    }

    #[test]
    fn matches_the_rush_release_test_target_oracle() {
        let libc = captured_identity("ec62875fe4f4ff0c", "-d93b98bc6485d9ec");
        let version = version();
        let profile = profile();
        let toolchain = native_toolchain();
        let root_library = cargo_identity(&IdentityInput {
            package_name: "moto-rush",
            version: &version,
            target_name: "moto_rush",
            target_kind: RootTargetKind::Library,
            features: &[],
            release: true,
            test: false,
            test_profile: true,
            logical_target: None,
            release_profile: &profile,
            rustc: &toolchain,
            rustflags: &[],
            dependencies: std::slice::from_ref(&libc),
        });
        assert_eq!(root_library.metadata, "55b25b27b3369b74");
        assert_eq!(root_library.extra_filename, "-f88387e790a6d3c6");

        let library_harness = cargo_identity(&IdentityInput {
            package_name: "moto-rush",
            version: &version,
            target_name: "moto_rush",
            target_kind: RootTargetKind::Library,
            features: &[],
            release: true,
            test: true,
            test_profile: true,
            logical_target: None,
            release_profile: &profile,
            rustc: &toolchain,
            rustflags: &[],
            dependencies: std::slice::from_ref(&libc),
        });
        assert_eq!(library_harness.metadata, "cf2dd5a9a7673952");
        assert_eq!(library_harness.extra_filename, "-f23575b7d2dff0ba");

        let harness_dependencies = [libc, root_library];
        let binary_harness = cargo_identity(&IdentityInput {
            package_name: "moto-rush",
            version: &version,
            target_name: "rush",
            target_kind: RootTargetKind::Binary,
            features: &[],
            release: true,
            test: true,
            test_profile: true,
            logical_target: None,
            release_profile: &profile,
            rustc: &toolchain,
            rustflags: &[],
            dependencies: &harness_dependencies,
        });
        assert_eq!(binary_harness.metadata, "bc16843c2d795727");
        assert_eq!(binary_harness.extra_filename, "-576bb2a69b604b3f");

        let program = captured_identity("08ff74a380108d7e", "-96c671f6ca98063a");
        let integration_dependencies = [
            harness_dependencies[0].clone(),
            harness_dependencies[1].clone(),
            program,
        ];
        let integration = cargo_identity(&IdentityInput {
            package_name: "moto-rush",
            version: &version,
            target_name: "phase5",
            target_kind: RootTargetKind::IntegrationTest,
            features: &[],
            release: true,
            test: true,
            test_profile: true,
            logical_target: None,
            release_profile: &profile,
            rustc: &toolchain,
            rustflags: &[],
            dependencies: &integration_dependencies,
        });
        assert_eq!(integration.metadata, "f062644c6d042c2e");
        assert_eq!(integration.extra_filename, "-c1332ac83febc65d");
    }

    #[test]
    fn matches_cargo_1_97_and_1_98_release_dependency_unit_oracle() {
        // Captured from clean Cargo 1.97 and Cargo 1.98 builds using the same
        // rustc 1.98 nightly. Both Cargo families produced these identities.
        let release = release_profile();
        let build = build_profile();
        let cfg_if = registry_library(
            "cfg-if",
            &parsed_version("1.0.4"),
            "cfg_if",
            &[],
            &release,
            CargoUnitLto::OnlyBitcode,
            &[],
        );
        assert_eq!(cfg_if.metadata, "eed0be358b9a99e1");
        assert_eq!(cfg_if.extra_filename, "-94168a7c2b2fed6b");

        let version_check = registry_library(
            "version_check",
            &parsed_version("0.9.5"),
            "version_check",
            &[],
            &build,
            CargoUnitLto::OnlyObject,
            &[],
        );
        assert_eq!(version_check.metadata, "9d0f88734f8d0ba0");
        assert_eq!(version_check.extra_filename, "-a52364eda26712a9");

        let build_script = cargo_unit_identity(&CargoUnitIdentityInput {
            package_name: "generic-array",
            version: &parsed_version("0.14.7"),
            source: CargoSource::CratesIo,
            features: &[],
            profile: &build,
            mode: CargoCompileMode::Build,
            lto: CargoUnitLto::OnlyObject,
            logical_target: None,
            target_name: "build-script-build",
            target_kind: CargoTargetKind::CustomBuild,
            rustc: &native_toolchain(),
            rustflags: &[],
            extra_arguments: &[],
            dependencies: std::slice::from_ref(&version_check),
            host_configuration_differs: None,
        });
        assert_eq!(build_script.metadata, "c0310cdf423fd5fb");
        assert_eq!(build_script.extra_filename, "-54bde9ff4b0e1354");

        let run_script = cargo_unit_identity(&CargoUnitIdentityInput {
            package_name: "generic-array",
            version: &parsed_version("0.14.7"),
            source: CargoSource::CratesIo,
            features: &[],
            profile: &run_build_profile(),
            mode: CargoCompileMode::RunCustomBuild,
            lto: CargoUnitLto::OnlyObject,
            logical_target: None,
            target_name: "build-script-build",
            target_kind: CargoTargetKind::CustomBuild,
            rustc: &native_toolchain(),
            rustflags: &[],
            extra_arguments: &[],
            dependencies: std::slice::from_ref(&build_script),
            host_configuration_differs: None,
        });
        assert_eq!(run_script.extra_filename, "-6dae74b52cdc9822");

        let typenum = registry_library(
            "typenum",
            &parsed_version("1.20.0"),
            "typenum",
            &[],
            &release,
            CargoUnitLto::OnlyBitcode,
            &[],
        );
        assert_eq!(typenum.metadata, "bf17786a989f3163");
        assert_eq!(typenum.extra_filename, "-3bece92618a1f233");

        let generic_array = registry_library(
            "generic-array",
            &parsed_version("0.14.7"),
            "generic_array",
            &[],
            &release,
            CargoUnitLto::OnlyBitcode,
            &[typenum, run_script],
        );
        assert_eq!(generic_array.metadata, "b4888d1c786ef3d6");
        assert_eq!(generic_array.extra_filename, "-ff844e945f4f0d9d");

        let crc32fast = registry_library(
            "crc32fast",
            &parsed_version("1.4.2"),
            "crc32fast",
            &["default".to_owned(), "std".to_owned()],
            &release,
            CargoUnitLto::OnlyBitcode,
            &[cfg_if],
        );
        assert_eq!(crc32fast.metadata, "e8395ad9ac6f5d81");
        assert_eq!(crc32fast.extra_filename, "-318c473e97bb0e1f");

        let local = cargo_unit_identity(&CargoUnitIdentityInput {
            package_name: "local-oracle",
            version: &parsed_version("0.2.0"),
            source: CargoSource::Path("file:///tmp/lorry-unit-oracle/local"),
            features: &[],
            profile: &release,
            mode: CargoCompileMode::Build,
            lto: CargoUnitLto::OnlyBitcode,
            logical_target: None,
            target_name: "local_oracle",
            target_kind: CargoTargetKind::Lib(vec![CargoCrateType::Lib]),
            rustc: &native_toolchain(),
            rustflags: &[],
            extra_arguments: &[],
            dependencies: &[],
            host_configuration_differs: None,
        });
        assert_eq!(local.metadata, "19b865ccb8a55508");
        assert_eq!(local.extra_filename, "-56d3e29f04ed1cbd");
    }
}
