#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::build_script::{Directive, Output as BuildScriptOutput};
use crate::diagnostic::{Error, Result};
use crate::identity::{CargoDebugInfo, CargoPanicStrategy, CargoStrip, CargoUnitLto, Identity};
use crate::manifest::{Edition, Manifest};
use crate::resolver::{CompileKind, PackageKey, PackageSourceKey};
use crate::unit::{CompilationPlan, PlannedUnit, UnitEdgeKind, UnitKey, UnitKind};

pub struct CommandOptions<'a> {
    pub cargo: &'a Path,
    pub host_profile: &'a Path,
    pub target_profile: &'a Path,
    pub physical_target: Option<&'a str>,
    pub host_linker: Option<&'a Path>,
    pub target_linker: Option<&'a Path>,
    pub verbose: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustcInvocation {
    pub arguments: Vec<OsString>,
    pub environment: BTreeMap<String, OsString>,
    pub current_dir: PathBuf,
    pub output: RustcOutput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RustcOutput {
    Library {
        rlib: PathBuf,
        rmeta: PathBuf,
        dep_info: PathBuf,
    },
    BuildScript {
        executable: PathBuf,
        unhashed_executable: PathBuf,
        dep_info: PathBuf,
    },
}

pub struct BuildOutput<'a> {
    pub output: &'a BuildScriptOutput,
    pub out_dir: &'a Path,
}

pub fn dependency_rustc_invocation(
    plan: &CompilationPlan,
    manifests: &BTreeMap<PackageKey, Manifest>,
    key: &UnitKey,
    options: &CommandOptions<'_>,
) -> Result<Option<RustcInvocation>> {
    dependency_rustc_invocation_with_build_output(plan, manifests, key, options, None)
}

pub fn dependency_rustc_invocation_with_build_output(
    plan: &CompilationPlan,
    manifests: &BTreeMap<PackageKey, Manifest>,
    key: &UnitKey,
    options: &CommandOptions<'_>,
    build_output: Option<BuildOutput<'_>>,
) -> Result<Option<RustcInvocation>> {
    let planned = plan.units.get(key).ok_or_else(|| {
        Error::failure(format!(
            "dependency compilation plan has no {:?} unit for `{} {}`",
            key.kind, key.package.name, key.package.version
        ))
    })?;
    if key.kind == UnitKind::BuildScriptRun {
        return Ok(None);
    }
    let requires_build_output = key.kind == UnitKind::Library
        && planned
            .unit
            .dependencies
            .iter()
            .any(|dependency| dependency.kind == UnitEdgeKind::BuildScriptOutput);
    if requires_build_output && build_output.is_none() {
        return Err(Error::failure(format!(
            "library unit for `{} {}` requires build-script output before its rustc command can be finalized",
            key.package.name, key.package.version
        )));
    }
    if !requires_build_output && build_output.is_some() {
        return Err(Error::failure(format!(
            "unexpected build-script output for {:?} unit `{} {}`",
            key.kind, key.package.name, key.package.version
        )));
    }
    let manifest = manifests.get(&key.package).ok_or_else(|| {
        Error::failure(format!(
            "dependency rustc command has no manifest for `{} {}`",
            key.package.name, key.package.version
        ))
    })?;
    let profile = profile_dir(key.compile_kind, options);
    let dependencies = profile.join("deps");
    let (crate_name, source, crate_type, emit, output_dir) = match key.kind {
        UnitKind::Library => {
            let library = manifest.library.as_ref().ok_or_else(|| {
                Error::failure(format!(
                    "dependency `{} {}` has no library target",
                    key.package.name, key.package.version
                ))
            })?;
            (
                library.name.as_str(),
                library.path.as_path(),
                "lib",
                "dep-info,metadata,link",
                dependencies.clone(),
            )
        }
        UnitKind::BuildScriptCompile => {
            let source = manifest.build_script.as_deref().ok_or_else(|| {
                Error::failure(format!(
                    "dependency `{} {}` has no build script",
                    key.package.name, key.package.version
                ))
            })?;
            (
                "build_script_build",
                source,
                "bin",
                "dep-info,link",
                options.host_profile.join("build").join(format!(
                    "{}-{}",
                    manifest.name,
                    planned.identity.extra_filename.trim_start_matches('-')
                )),
            )
        }
        UnitKind::BuildScriptRun => unreachable!(),
    };

    let mut arguments = Vec::new();
    push(&mut arguments, "--crate-name");
    push(&mut arguments, crate_name);
    push(
        &mut arguments,
        &format!("--edition={}", edition_name(manifest.edition)),
    );
    arguments.push(source.as_os_str().to_owned());
    push(&mut arguments, "--error-format=json");
    push(
        &mut arguments,
        "--json=diagnostic-rendered-ansi,artifacts,future-incompat",
    );
    push(&mut arguments, "--crate-type");
    push(&mut arguments, crate_type);
    push(&mut arguments, &format!("--emit={emit}"));
    profile_arguments(&mut arguments, planned, manifest);
    identity_arguments(&mut arguments, &planned.identity);
    push(&mut arguments, "--out-dir");
    arguments.push(output_dir.as_os_str().to_owned());
    if key.compile_kind == CompileKind::Target {
        if let Some(target) = options.physical_target {
            push(&mut arguments, "--target");
            push(&mut arguments, target);
        }
    }
    let linker = match key.compile_kind {
        CompileKind::Host => options.host_linker,
        CompileKind::Target => options.target_linker,
    };
    if let Some(linker) = linker {
        codegen(&mut arguments, &format!("linker={}", linker.display()));
    }
    if planned.settings.profile.incremental {
        codegen(
            &mut arguments,
            &format!("incremental={}", profile.join("incremental").display()),
        );
    }
    if let CargoStrip::Named(strip) = planned.settings.profile.strip {
        codegen(&mut arguments, &format!("strip={strip}"));
    }
    dependency_arguments(&mut arguments, plan, manifests, planned, options)?;
    if matches!(key.package.source, PackageSourceKey::CratesIo) {
        push(&mut arguments, "--cap-lints");
        push(
            &mut arguments,
            if options.verbose { "warn" } else { "allow" },
        );
    }
    arguments.extend(planned.settings.rustflags.iter().map(OsString::from));
    let mut environment =
        rustc_environment(options.cargo, options.host_profile, manifest, crate_name)?;
    if let Some(build_output) = build_output {
        apply_build_output(&mut arguments, &mut environment, build_output);
    }
    if options.verbose {
        push(&mut arguments, "--verbose");
    }

    let output = expected_output(key, crate_name, &planned.identity, &output_dir);
    Ok(Some(RustcInvocation {
        arguments,
        environment,
        current_dir: manifest.root.clone(),
        output,
    }))
}

fn apply_build_output(
    arguments: &mut Vec<OsString>,
    environment: &mut BTreeMap<String, OsString>,
    build: BuildOutput<'_>,
) {
    value(environment, "OUT_DIR", build.out_dir);
    for directive in &build.output.directives {
        if let Directive::RustcLinkSearch { kind, path } = directive {
            push(arguments, "-L");
            arguments.push(match kind {
                Some(kind) => format!("{kind}={}", path.display()).into(),
                None => path.as_os_str().to_owned(),
            });
        }
    }
    for directive in &build.output.directives {
        if let Directive::RustcLinkLib(library) = directive {
            push(arguments, "-l");
            push(arguments, library);
        }
    }
    for directive in &build.output.directives {
        if let Directive::RustcCfg(cfg) = directive {
            push(arguments, "--cfg");
            push(arguments, cfg);
        }
    }
    for directive in &build.output.directives {
        if let Directive::RustcCheckCfg(cfg) = directive {
            push(arguments, "--check-cfg");
            push(arguments, cfg);
        }
    }
    for directive in &build.output.directives {
        if let Directive::RustcEnv {
            name,
            value: setting,
        } = directive
        {
            value(environment, name, setting);
        }
    }
}

fn profile_arguments(arguments: &mut Vec<OsString>, planned: &PlannedUnit, manifest: &Manifest) {
    let profile = &planned.settings.profile;
    if profile.opt_level != "0" {
        codegen(arguments, &format!("opt-level={}", profile.opt_level));
    }
    match profile.panic {
        CargoPanicStrategy::Unwind => {}
        CargoPanicStrategy::Abort => codegen(arguments, "panic=abort"),
        CargoPanicStrategy::ImmediateAbort => {
            codegen(arguments, "panic=immediate-abort");
            push(arguments, "-Z");
            push(arguments, "unstable-options");
        }
    }
    match planned.settings.lto {
        CargoUnitLto::Run(None) => codegen(arguments, "lto"),
        CargoUnitLto::Run(Some(mode)) => codegen(arguments, &format!("lto={mode}")),
        CargoUnitLto::Off => {
            codegen(arguments, "lto=off");
            codegen(arguments, "embed-bitcode=no");
        }
        CargoUnitLto::OnlyBitcode => codegen(arguments, "linker-plugin-lto"),
        CargoUnitLto::ObjectAndBitcode => {}
        CargoUnitLto::OnlyObject => codegen(arguments, "embed-bitcode=no"),
    }
    if let Some(units) = profile.codegen_units {
        codegen(arguments, &format!("codegen-units={units}"));
    }
    match profile.debuginfo {
        CargoDebugInfo::None => {}
        CargoDebugInfo::LineDirectivesOnly => codegen(arguments, "debuginfo=line-directives-only"),
        CargoDebugInfo::LineTablesOnly => codegen(arguments, "debuginfo=line-tables-only"),
        CargoDebugInfo::Limited => codegen(arguments, "debuginfo=1"),
        CargoDebugInfo::Full => codegen(arguments, "debuginfo=2"),
    }
    arguments.extend(lint_arguments(manifest));
    if profile.opt_level != "0" {
        if profile.debug_assertions {
            codegen(arguments, "debug-assertions=on");
            if !profile.overflow_checks {
                codegen(arguments, "overflow-checks=off");
            }
        } else if profile.overflow_checks {
            codegen(arguments, "overflow-checks=on");
        }
    } else if !profile.debug_assertions {
        codegen(arguments, "debug-assertions=off");
        if profile.overflow_checks {
            codegen(arguments, "overflow-checks=on");
        }
    } else if !profile.overflow_checks {
        codegen(arguments, "overflow-checks=off");
    }
    for feature in &planned.unit.key.features {
        push(arguments, "--cfg");
        push(arguments, &format!("feature=\"{feature}\""));
    }
    push(arguments, "--check-cfg");
    push(arguments, "cfg(docsrs,test)");
    push(arguments, "--check-cfg");
    push(
        arguments,
        &format!(
            "cfg(feature, values({}))",
            declared_features(manifest)
                .iter()
                .map(|feature| format!("\"{feature}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
}

fn identity_arguments(arguments: &mut Vec<OsString>, identity: &Identity) {
    codegen(arguments, &format!("metadata={}", identity.metadata));
    codegen(
        arguments,
        &format!("extra-filename={}", identity.extra_filename),
    );
}

fn dependency_arguments(
    arguments: &mut Vec<OsString>,
    plan: &CompilationPlan,
    manifests: &BTreeMap<PackageKey, Manifest>,
    planned: &PlannedUnit,
    options: &CommandOptions<'_>,
) -> Result<()> {
    let selected = profile_dir(planned.unit.key.compile_kind, options).join("deps");
    push(arguments, "-L");
    arguments.push(format!("dependency={}", selected.display()).into());
    if planned.unit.key.compile_kind == CompileKind::Target && options.physical_target.is_some() {
        let host = options.host_profile.join("deps");
        if host != selected {
            push(arguments, "-L");
            arguments.push(format!("dependency={}", host.display()).into());
        }
    }

    for dependency in planned
        .unit
        .dependencies
        .iter()
        .filter(|dependency| dependency.kind == UnitEdgeKind::RustDependency)
    {
        let child = plan.units.get(&dependency.unit).ok_or_else(|| {
            Error::failure(format!(
                "dependency rustc command references absent unit `{} {}`",
                dependency.unit.package.name, dependency.unit.package.version
            ))
        })?;
        let child_manifest = manifests.get(&dependency.unit.package).ok_or_else(|| {
            Error::failure(format!(
                "dependency rustc command has no manifest for child `{} {}`",
                dependency.unit.package.name, dependency.unit.package.version
            ))
        })?;
        let child_library = child_manifest.library.as_ref().ok_or_else(|| {
            Error::failure(format!(
                "dependency rustc command child `{} {}` has no library target",
                dependency.unit.package.name, dependency.unit.package.version
            ))
        })?;
        let alias = dependency
            .alias
            .as_deref()
            .unwrap_or(&dependency.unit.package.name)
            .replace('-', "_");
        let extension = if planned.unit.key.kind == UnitKind::Library {
            "rmeta"
        } else {
            "rlib"
        };
        let path = profile_dir(child.unit.key.compile_kind, options)
            .join("deps")
            .join(format!(
                "lib{}{}.{}",
                child_library.name, child.identity.extra_filename, extension
            ));
        push(arguments, "--extern");
        arguments.push(format!("{alias}={}", path.display()).into());
    }
    Ok(())
}

fn expected_output(
    key: &UnitKey,
    crate_name: &str,
    identity: &Identity,
    output_dir: &Path,
) -> RustcOutput {
    let stem = format!("{crate_name}{}", identity.extra_filename);
    match key.kind {
        UnitKind::Library => RustcOutput::Library {
            rlib: output_dir.join(format!("lib{stem}.rlib")),
            rmeta: output_dir.join(format!("lib{stem}.rmeta")),
            dep_info: output_dir.join(format!("{stem}.d")),
        },
        UnitKind::BuildScriptCompile => RustcOutput::BuildScript {
            executable: output_dir.join(&stem),
            unhashed_executable: output_dir.join("build-script-build"),
            dep_info: output_dir.join(format!("{stem}.d")),
        },
        UnitKind::BuildScriptRun => unreachable!(),
    }
}

fn rustc_environment(
    cargo: &Path,
    host_profile: &Path,
    manifest: &Manifest,
    crate_name: &str,
) -> Result<BTreeMap<String, OsString>> {
    let mut values = BTreeMap::new();
    value(&mut values, "CARGO", cargo.as_os_str());
    value(&mut values, "CARGO_CRATE_NAME", crate_name);
    value(&mut values, "CARGO_MANIFEST_DIR", manifest.root.as_os_str());
    value(
        &mut values,
        "CARGO_MANIFEST_PATH",
        manifest.path.as_os_str(),
    );
    let metadata = &manifest.metadata;
    value(&mut values, "CARGO_PKG_AUTHORS", metadata.authors.join(":"));
    value(&mut values, "CARGO_PKG_DESCRIPTION", &metadata.description);
    value(&mut values, "CARGO_PKG_HOMEPAGE", &metadata.homepage);
    value(&mut values, "CARGO_PKG_LICENSE", &metadata.license);
    value(
        &mut values,
        "CARGO_PKG_LICENSE_FILE",
        &metadata.license_file,
    );
    value(&mut values, "CARGO_PKG_NAME", &manifest.name);
    value(&mut values, "CARGO_PKG_README", &metadata.readme);
    value(&mut values, "CARGO_PKG_REPOSITORY", &metadata.repository);
    value(
        &mut values,
        "CARGO_PKG_RUST_VERSION",
        &metadata.rust_version,
    );
    let version = &manifest.version;
    value(&mut values, "CARGO_PKG_VERSION", &version.original);
    value(
        &mut values,
        "CARGO_PKG_VERSION_MAJOR",
        version.major.to_string(),
    );
    value(
        &mut values,
        "CARGO_PKG_VERSION_MINOR",
        version.minor.to_string(),
    );
    value(
        &mut values,
        "CARGO_PKG_VERSION_PATCH",
        version.patch.to_string(),
    );
    value(&mut values, "CARGO_PKG_VERSION_PRE", &version.pre);
    let dynamic = std::env::join_paths([host_profile.join("deps")]).map_err(|error| {
        Error::failure(format!(
            "failed to construct rustc dynamic-library search path: {error}"
        ))
    })?;
    value(&mut values, dynamic_library_path_variable(), dynamic);
    Ok(values)
}

pub(crate) fn lint_arguments(manifest: &Manifest) -> Vec<OsString> {
    let mut lints = manifest
        .rust_lints
        .iter()
        .map(|(name, lint)| {
            let flag = match lint.level.as_str() {
                "forbid" => "--forbid",
                "deny" => "--deny",
                "warn" => "--warn",
                "allow" => "--allow",
                _ => unreachable!("manifest lint level was validated"),
            };
            (lint.priority, name.as_str(), format!("{flag}={name}"))
        })
        .collect::<Vec<_>>();
    lints.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| right.1.cmp(left.1)));
    let mut arguments = lints
        .into_iter()
        .map(|(_, _, argument)| OsString::from(argument))
        .collect::<Vec<_>>();
    if let Some(lint) = manifest.rust_lints.get("unexpected_cfgs") {
        for check in &lint.check_cfg {
            arguments.push("--check-cfg".into());
            arguments.push(check.into());
        }
    }
    arguments
}

pub(crate) fn declared_features(manifest: &Manifest) -> BTreeSet<String> {
    let mut features = manifest.features.keys().cloned().collect::<BTreeSet<_>>();
    let namespaced = manifest
        .features
        .values()
        .flatten()
        .filter_map(|feature| feature.strip_prefix("dep:"))
        .collect::<BTreeSet<_>>();
    for dependency in &manifest.dependencies {
        if dependency.optional && !namespaced.contains(dependency.alias.as_str()) {
            features.insert(dependency.alias.clone());
        }
    }
    features
}

fn profile_dir<'a>(compile_kind: CompileKind, options: &'a CommandOptions<'_>) -> &'a Path {
    match compile_kind {
        CompileKind::Host => options.host_profile,
        CompileKind::Target => options.target_profile,
    }
}

fn edition_name(edition: Edition) -> &'static str {
    match edition {
        Edition::E2015 => "2015",
        Edition::E2018 => "2018",
        Edition::E2021 => "2021",
        Edition::E2024 => "2024",
    }
}

fn dynamic_library_path_variable() -> &'static str {
    if cfg!(target_os = "macos") {
        "DYLD_FALLBACK_LIBRARY_PATH"
    } else if cfg!(windows) {
        "PATH"
    } else {
        "LD_LIBRARY_PATH"
    }
}

fn value(values: &mut BTreeMap<String, OsString>, key: &str, value: impl AsRef<OsStr>) {
    values.insert(key.to_owned(), value.as_ref().to_owned());
}

fn push(arguments: &mut Vec<OsString>, value: &str) {
    arguments.push(value.into());
}

fn codegen(arguments: &mut Vec<OsString>, value: &str) {
    push(arguments, "-C");
    push(arguments, value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CargoCompat;
    use crate::manifest::{Lto, ReleaseProfile, Strip};
    use crate::resolver::{
        FeatureContext, PackageSourceKey, Resolution, ResolvedEdge, ResolvedPackage, ResolvedSource,
    };
    use crate::sparse::DependencyKind;
    use crate::toolchain::Toolchain;
    use crate::unit::{PlanOptions, dependency_units, plan_dependency_units};
    use semver::Version;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("lorry-compile-command-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn package(&self, directory: &str, manifest: &str, build_script: bool) {
            let root = self.0.join(directory);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(root.join("Cargo.toml"), manifest).unwrap();
            fs::write(root.join("src/lib.rs"), "pub fn library() {}\n").unwrap();
            if build_script {
                fs::write(root.join("build.rs"), "fn main() {}\n").unwrap();
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn toolchain() -> Toolchain {
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

    fn key(name: &str, version: &str) -> PackageKey {
        PackageKey {
            name: name.to_owned(),
            version: Version::parse(version).unwrap(),
            source: PackageSourceKey::CratesIo,
        }
    }

    fn package(
        key: PackageKey,
        compile_kind: CompileKind,
        edges: Vec<ResolvedEdge>,
    ) -> ResolvedPackage {
        ResolvedPackage {
            key,
            source: ResolvedSource::CratesIo { checksum: [0; 32] },
            local_manifest: None,
            feature_sets: BTreeMap::new(),
            compile_kinds: [compile_kind].into(),
            target_features: BTreeSet::new(),
            host_features: BTreeSet::new(),
            lock_edges: edges.clone(),
            edges,
        }
    }

    fn string_arguments(invocation: &RustcInvocation) -> Vec<String> {
        invocation
            .arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn renders_cargo_oracle_library_and_build_script_compile_commands() {
        let fixture = Fixture::new();
        fixture.package(
            "version_check",
            "[package]\nname = \"version_check\"\nversion = \"0.9.5\"\nedition = \"2015\"\n",
            false,
        );
        fixture.package(
            "typenum",
            "[package]\nname = \"typenum\"\nversion = \"1.20.0\"\nedition = \"2018\"\n",
            false,
        );
        fixture.package(
            "generic-array",
            "[package]\nname = \"generic-array\"\nversion = \"0.14.7\"\nedition = \"2015\"\n\
             build = \"build.rs\"\n\
             [dependencies]\ntypenum = \"=1.20.0\"\n\
             [build-dependencies]\nversion_check = \"=0.9.5\"\n",
            true,
        );
        let version_check = key("version_check", "0.9.5");
        let typenum = key("typenum", "1.20.0");
        let generic_array = key("generic-array", "0.14.7");
        let resolution = Resolution {
            root_edges: Vec::new(),
            packages: vec![
                package(version_check.clone(), CompileKind::Host, Vec::new()),
                package(typenum.clone(), CompileKind::Target, Vec::new()),
                package(
                    generic_array.clone(),
                    CompileKind::Target,
                    vec![
                        ResolvedEdge {
                            dependency_index: 0,
                            alias: "typenum".to_owned(),
                            kind: DependencyKind::Normal,
                            compile_kind: CompileKind::Target,
                            context: FeatureContext::Target("x86_64-unknown-linux-gnu".to_owned()),
                            package: typenum.clone(),
                        },
                        ResolvedEdge {
                            dependency_index: 1,
                            alias: "version_check".to_owned(),
                            kind: DependencyKind::Build,
                            compile_kind: CompileKind::Host,
                            context: FeatureContext::Host,
                            package: version_check.clone(),
                        },
                    ],
                ),
            ],
        };
        let manifests = [
            version_check.clone(),
            typenum.clone(),
            generic_array.clone(),
        ]
        .into_iter()
        .map(|key| {
            let manifest = Manifest::load_path_dependency(&fixture.0.join(&key.name)).unwrap();
            (key, manifest)
        })
        .collect::<BTreeMap<_, _>>();
        let graph = dependency_units(&resolution, &manifests).unwrap();
        let plan = plan_dependency_units(
            &graph,
            &manifests,
            &PlanOptions {
                workspace_root: &fixture.0,
                release: true,
                test_profile: false,
                release_profile: &ReleaseProfile {
                    panic_abort: true,
                    lto: Lto::Fat,
                    strip: Strip::Symbols,
                    codegen_units: Some(1),
                },
                rustc: &toolchain(),
                logical_target: None,
                rustflags: &[],
            },
        )
        .unwrap();
        let host = Path::new("/target/release");
        let command_options = CommandOptions {
            cargo: Path::new("/cargo"),
            host_profile: host,
            target_profile: host,
            physical_target: None,
            host_linker: None,
            target_linker: None,
            verbose: true,
        };

        let version_key = plan
            .order
            .iter()
            .find(|key| key.package == version_check && key.kind == UnitKind::Library)
            .unwrap();
        let invocation =
            dependency_rustc_invocation(&plan, &manifests, version_key, &command_options)
                .unwrap()
                .unwrap();
        assert_eq!(
            string_arguments(&invocation),
            [
                "--crate-name",
                "version_check",
                "--edition=2015",
                manifests[&version_check]
                    .root
                    .join("src/lib.rs")
                    .to_str()
                    .unwrap(),
                "--error-format=json",
                "--json=diagnostic-rendered-ansi,artifacts,future-incompat",
                "--crate-type",
                "lib",
                "--emit=dep-info,metadata,link",
                "-C",
                "embed-bitcode=no",
                "-C",
                "debug-assertions=off",
                "--check-cfg",
                "cfg(docsrs,test)",
                "--check-cfg",
                "cfg(feature, values())",
                "-C",
                "metadata=9d0f88734f8d0ba0",
                "-C",
                "extra-filename=-a52364eda26712a9",
                "--out-dir",
                "/target/release/deps",
                "-C",
                "strip=symbols",
                "-L",
                "dependency=/target/release/deps",
                "--cap-lints",
                "warn",
                "--verbose",
            ]
        );
        assert_eq!(
            invocation.environment["CARGO_CRATE_NAME"],
            OsString::from("version_check")
        );
        assert_eq!(
            invocation.environment[dynamic_library_path_variable()],
            OsString::from("/target/release/deps")
        );

        let compile_key = plan
            .order
            .iter()
            .find(|key| key.package == generic_array && key.kind == UnitKind::BuildScriptCompile)
            .unwrap();
        let invocation =
            dependency_rustc_invocation(&plan, &manifests, compile_key, &command_options)
                .unwrap()
                .unwrap();
        assert_eq!(
            string_arguments(&invocation),
            [
                "--crate-name",
                "build_script_build",
                "--edition=2015",
                manifests[&generic_array]
                    .root
                    .join("build.rs")
                    .to_str()
                    .unwrap(),
                "--error-format=json",
                "--json=diagnostic-rendered-ansi,artifacts,future-incompat",
                "--crate-type",
                "bin",
                "--emit=dep-info,link",
                "-C",
                "embed-bitcode=no",
                "-C",
                "debug-assertions=off",
                "--check-cfg",
                "cfg(docsrs,test)",
                "--check-cfg",
                "cfg(feature, values())",
                "-C",
                "metadata=c0310cdf423fd5fb",
                "-C",
                "extra-filename=-54bde9ff4b0e1354",
                "--out-dir",
                "/target/release/build/generic-array-54bde9ff4b0e1354",
                "-C",
                "strip=symbols",
                "-L",
                "dependency=/target/release/deps",
                "--extern",
                "version_check=/target/release/deps/libversion_check-a52364eda26712a9.rlib",
                "--cap-lints",
                "warn",
                "--verbose",
            ]
        );
        assert_eq!(
            invocation.output,
            RustcOutput::BuildScript {
                executable: Path::new(
                    "/target/release/build/generic-array-54bde9ff4b0e1354/build_script_build-54bde9ff4b0e1354"
                )
                .to_owned(),
                unhashed_executable: Path::new(
                    "/target/release/build/generic-array-54bde9ff4b0e1354/build-script-build"
                )
                .to_owned(),
                dep_info: Path::new(
                    "/target/release/build/generic-array-54bde9ff4b0e1354/build_script_build-54bde9ff4b0e1354.d"
                )
                .to_owned(),
            }
        );

        let run_key = plan
            .order
            .iter()
            .find(|key| key.package == generic_array && key.kind == UnitKind::BuildScriptRun)
            .unwrap();
        assert!(
            dependency_rustc_invocation(&plan, &manifests, run_key, &command_options,)
                .unwrap()
                .is_none()
        );
        let library_key = plan
            .order
            .iter()
            .find(|key| key.package == generic_array && key.kind == UnitKind::Library)
            .unwrap();
        assert!(
            dependency_rustc_invocation(&plan, &manifests, library_key, &command_options,)
                .unwrap_err()
                .to_string()
                .contains("requires build-script output")
        );
        let script_out = fixture.0.join("script-out");
        fs::create_dir(&script_out).unwrap();
        let output = crate::build_script::Output {
            directives: vec![
                Directive::RustcEnv {
                    name: "GENERATED".to_owned(),
                    value: "yes".to_owned(),
                },
                Directive::RustcLinkLib("static=fixture".to_owned()),
                Directive::RustcCfg("generated_cfg".to_owned()),
                Directive::RustcLinkSearch {
                    kind: Some("native".to_owned()),
                    path: script_out.clone(),
                },
                Directive::RustcCheckCfg("cfg(generated_cfg)".to_owned()),
            ],
            diagnostics: Vec::new(),
            stderr: String::new(),
            out_dir: crate::source_tree::Tree {
                entries: Vec::new(),
                file_count: 0,
                directory_count: 0,
                total_bytes: 0,
                sha256: [0; 32],
            },
        };
        let invocation = dependency_rustc_invocation_with_build_output(
            &plan,
            &manifests,
            library_key,
            &command_options,
            Some(BuildOutput {
                output: &output,
                out_dir: &script_out,
            }),
        )
        .unwrap()
        .unwrap();
        let arguments = string_arguments(&invocation);
        assert!(arguments.ends_with(&[
            "-L".to_owned(),
            format!("native={}", script_out.display()),
            "-l".to_owned(),
            "static=fixture".to_owned(),
            "--cfg".to_owned(),
            "generated_cfg".to_owned(),
            "--check-cfg".to_owned(),
            "cfg(generated_cfg)".to_owned(),
            "--verbose".to_owned(),
        ]));
        assert_eq!(invocation.environment["OUT_DIR"], script_out);
        assert_eq!(invocation.environment["GENERATED"], "yes");

        let cross_flags = vec!["--cfg=cross_oracle".to_owned()];
        let cross_plan = plan_dependency_units(
            &graph,
            &manifests,
            &PlanOptions {
                workspace_root: &fixture.0,
                release: true,
                test_profile: false,
                release_profile: &ReleaseProfile {
                    panic_abort: true,
                    lto: Lto::Fat,
                    strip: Strip::Symbols,
                    codegen_units: Some(1),
                },
                rustc: &toolchain(),
                logical_target: Some("x86_64-unknown-motor"),
                rustflags: &cross_flags,
            },
        )
        .unwrap();
        let cross_options = CommandOptions {
            cargo: Path::new("/cargo"),
            host_profile: Path::new("/target/release"),
            target_profile: Path::new("/target/x86_64-unknown-motor/release"),
            physical_target: Some("x86_64-unknown-motor"),
            host_linker: Some(Path::new("/host-cc")),
            target_linker: Some(Path::new("/target-cc")),
            verbose: true,
        };
        let target_key = cross_plan
            .order
            .iter()
            .find(|key| key.package == typenum && key.kind == UnitKind::Library)
            .unwrap();
        let target = string_arguments(
            &dependency_rustc_invocation(&cross_plan, &manifests, target_key, &cross_options)
                .unwrap()
                .unwrap(),
        );
        assert!(
            target
                .windows(2)
                .any(|args| args == ["--target", "x86_64-unknown-motor"])
        );
        assert!(
            target
                .windows(2)
                .any(|args| args == ["-C", "linker=/target-cc"])
        );
        assert!(
            target.contains(&"dependency=/target/x86_64-unknown-motor/release/deps".to_owned())
        );
        assert!(target.contains(&"dependency=/target/release/deps".to_owned()));
        assert!(target.contains(&"--cfg=cross_oracle".to_owned()));

        let host_key = cross_plan
            .order
            .iter()
            .find(|key| key.package == version_check && key.kind == UnitKind::Library)
            .unwrap();
        let host = string_arguments(
            &dependency_rustc_invocation(&cross_plan, &manifests, host_key, &cross_options)
                .unwrap()
                .unwrap(),
        );
        assert!(!host.contains(&"--target".to_owned()));
        assert!(!host.contains(&"--cfg=cross_oracle".to_owned()));
        assert!(
            host.windows(2)
                .any(|args| args == ["-C", "linker=/host-cc"])
        );
    }
}
