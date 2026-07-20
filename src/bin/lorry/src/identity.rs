#![allow(dead_code)] // Consumed by the build engine in the next implementation slice.

use crate::hash::StableHasher;
use crate::manifest::{Lto as ManifestLto, ReleaseProfile, Strip as ManifestStrip, Version};
use crate::toolchain::Toolchain;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub metadata: String,
    pub extra_filename: String,
}

pub struct IdentityInput<'a> {
    pub package_name: &'a str,
    pub version: &'a Version,
    pub target_name: &'a str,
    pub release: bool,
    pub test: bool,
    /// Cargo's logical compile kind. Native Motor uses an explicit logical
    /// target here even when rustc itself is invoked without `--target`.
    pub logical_target: Option<&'a str>,
    pub release_profile: &'a ReleaseProfile,
    pub rustc: &'a Toolchain,
    pub rustflags: &'a [String],
}

pub fn cargo_identity(input: &IdentityInput<'_>) -> Identity {
    let mut shared = StableHasher::new();
    2u8.hash(&mut shared);

    input.package_name.hash(&mut shared);
    input.version.major.hash(&mut shared);
    input.version.minor.hash(&mut shared);
    input.version.patch.hash(&mut shared);
    input.version.pre.hash(&mut shared);
    input.version.build.hash(&mut shared);
    std::mem::discriminant(&SourceKind::Path).hash(&mut shared);
    "".hash(&mut shared);

    Vec::<&str>::new().hash(&mut shared);
    hash_profile(input, &mut shared);
    if input.test {
        CompileMode::Test.hash(&mut shared);
    } else {
        CompileMode::Build.hash(&mut shared);
    }
    hash_unit_lto(input.release, input.release_profile.lto, &mut shared);

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
    TargetKind::Bin.hash(&mut shared);
    hash_rustc_version(input, &mut shared);
    false.hash(&mut shared);

    let mut metadata = shared.clone();
    Vec::<u64>::new().hash(&mut metadata);

    let mut unit = shared;
    Vec::<u64>::new().hash(&mut unit);
    Vec::<String>::new().hash(&mut unit);
    input.rustflags.hash(&mut unit);

    Identity {
        metadata: format!("{:016x}", metadata.finish()),
        extra_filename: format!("-{:016x}", unit.finish()),
    }
}

fn hash_profile(input: &IdentityInput<'_>, hasher: &mut StableHasher) {
    let release = input.release;
    if release {
        "3".hash(hasher);
        match input.release_profile.lto {
            ManifestLto::Default => ProfileLto::Bool(false).hash(hasher),
            ManifestLto::True => ProfileLto::Bool(true).hash(hasher),
            ManifestLto::Fat => ProfileLto::Named("fat").hash(hasher),
            ManifestLto::Thin => ProfileLto::Named("thin").hash(hasher),
            ManifestLto::Off => ProfileLto::Off.hash(hasher),
        }
        Option::<&str>::None.hash(hasher);
        input.release_profile.codegen_units.hash(hasher);
        DebugInfo::None.hash(hasher);
        Option::<&str>::None.hash(hasher);
        false.hash(hasher);
        false.hash(hasher);
        false.hash(hasher);
        (
            false,
            if input.test || !input.release_profile.panic_abort {
                PanicStrategy::Unwind
            } else {
                PanicStrategy::Abort
            },
            match input.release_profile.strip {
                ManifestStrip::None => StripInner::None,
                ManifestStrip::Debuginfo => StripInner::Named("debuginfo"),
                ManifestStrip::Symbols => StripInner::Named("symbols"),
            },
        )
            .hash(hasher);
    } else {
        "0".hash(hasher);
        ProfileLto::Bool(false).hash(hasher);
        Option::<&str>::None.hash(hasher);
        Option::<u32>::None.hash(hasher);
        DebugInfo::Full.hash(hasher);
        Option::<&str>::None.hash(hasher);
        true.hash(hasher);
        true.hash(hasher);
        false.hash(hasher);
        (true, PanicStrategy::Unwind, StripInner::None).hash(hasher);
    }
    Vec::<&str>::new().hash(hasher);
    Option::<&str>::None.hash(hasher);
}

fn hash_unit_lto(release: bool, profile_lto: ManifestLto, hasher: &mut StableHasher) {
    if release {
        match profile_lto {
            ManifestLto::True => UnitLto::Run(None).hash(hasher),
            ManifestLto::Fat => UnitLto::Run(Some("fat")).hash(hasher),
            ManifestLto::Thin => UnitLto::Run(Some("thin")).hash(hasher),
            ManifestLto::Off => UnitLto::Off.hash(hasher),
            ManifestLto::Default => UnitLto::OnlyObject.hash(hasher),
        }
    } else {
        UnitLto::OnlyObject.hash(hasher);
    }
}

fn hash_rustc_version(input: &IdentityInput<'_>, hasher: &mut StableHasher) {
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

#[allow(dead_code)]
#[derive(Hash)]
enum CompileMode {
    Test,
    Build,
    Check { test: bool },
    Doc,
    Doctest,
    Docscrape,
    RunCustomBuild,
}

#[allow(dead_code)]
#[derive(Hash)]
enum TargetKind {
    Lib(Vec<CrateType>),
    Bin,
    Test,
    Bench,
    ExampleLib(Vec<CrateType>),
    ExampleBin,
    CustomBuild,
}

#[allow(dead_code)]
#[derive(Hash)]
enum CrateType {
    Bin,
    Lib,
    Rlib,
    Dylib,
    Cdylib,
    Staticlib,
    ProcMacro,
}

#[allow(dead_code)]
#[derive(Hash)]
enum ProfileLto<'a> {
    Off,
    Bool(bool),
    Named(&'a str),
}

#[allow(dead_code)]
#[derive(Hash)]
enum DebugInfo {
    None,
    LineDirectivesOnly,
    LineTablesOnly,
    Limited,
    Full,
}

#[allow(dead_code)]
#[derive(Hash)]
enum PanicStrategy {
    Unwind,
    Abort,
    ImmediateAbort,
}

#[allow(dead_code)]
#[derive(Hash)]
enum StripInner<'a> {
    None,
    Named(&'a str),
}

#[allow(dead_code)]
#[derive(Hash)]
enum UnitLto<'a> {
    Run(Option<&'a str>),
    Off,
    OnlyBitcode,
    ObjectAndBitcode,
    OnlyObject,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CargoCompat;

    fn version() -> Version {
        Version {
            original: "0.1.0".to_owned(),
            major: 0,
            minor: 1,
            patch: 0,
            pre: String::new(),
            build: String::new(),
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
                release,
                test,
                logical_target: target,
                release_profile: &profile,
                rustc: toolchain,
                rustflags: &[],
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
}
