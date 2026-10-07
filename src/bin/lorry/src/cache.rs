use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifact_owner;
use crate::atomic::AtomicDirectory;
use crate::build_script::{Directive, Output as BuildScriptOutput};
use crate::compile::{RustcInvocation, RustcOutput};
use crate::config::CargoCompat;
use crate::diagnostic::{Error, Result};
use crate::hash::{FieldDigest, Sha256, hex, modified_time, sha256_file};
use crate::json::Value;
use crate::manifest::Manifest;
use crate::process;
use crate::resolver::{CompileKind, PackageSourceKey};
use crate::source_tree::{EntryKind, Exclusions, Limits as TreeLimits, Tree};
use crate::toolchain::{TargetInfo, Toolchain};
use crate::tracked_env::{self, Tracked};
use crate::unit::{PlannedUnit, UnitKey, UnitKind};
use crate::validation::ValidationMode;

const FORMAT_VERSION: u64 = 1;
const KEY_TAG: &[u8] = b"lorry-unit-cache-key-v3\0";
const PUBLISHED_RECORD: &str = ".lorry-unit-v1";
const PUBLISHED_STDOUT: &str = ".lorry-rustc-stdout-v1";
const PUBLISHED_STDERR: &str = ".lorry-rustc-stderr-v1";
const PUBLISHED_ENVIRONMENT: &str = ".lorry-tracked-environment-v1";
const PAYLOAD_ENVIRONMENT: &str = "tracked-environment.json";

pub struct Options<'a> {
    pub cargo: &'a Path,
    pub toolchain: &'a Toolchain,
    pub host: &'a TargetInfo,
    pub target: &'a TargetInfo,
    pub host_linker: Option<&'a Path>,
    pub target_linker: Option<&'a Path>,
    pub root_manifest: &'a Manifest,
    pub source_limits: TreeLimits,
    pub validation: ValidationMode,
}

#[derive(Clone, Copy)]
pub struct BuildScriptInput<'a> {
    pub output: &'a BuildScriptOutput,
    pub environment: &'a BTreeMap<String, OsString>,
    pub executable_sha256: [u8; 32],
    pub out_dir: &'a Path,
    pub temp_dir: &'a Path,
}

pub struct DependencyInput<'a> {
    pub key: &'a UnitKey,
    pub alias: Option<&'a str>,
    pub rlib: &'a Path,
    pub rmeta: &'a Path,
    pub cache_key: Option<CacheKey>,
}

pub struct UnitInput<'a> {
    pub key: &'a UnitKey,
    pub selected: bool,
    pub planned: &'a PlannedUnit,
    pub manifest: &'a Manifest,
    pub invocation: &'a RustcInvocation,
    pub host_profile: &'a Path,
    pub target_profile: &'a Path,
    pub dependencies: &'a [DependencyInput<'a>],
    pub build_script: Option<BuildScriptInput<'a>>,
}

#[derive(Clone, Copy)]
pub struct SelectedInputs<'a> {
    pub package_root: &'a Path,
    pub working_dir: &'a Path,
    pub source_remap: Option<&'a crate::unit::SourceRemap>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheKey([u8; 32]);

/// A unit restored from a cache entry.
pub struct Restored {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub tracked: Tracked,
}

pub struct BuildCache {
    units: PathBuf,
    quarantine: PathBuf,
    cargo: PathBuf,
    workspace_root: PathBuf,
    workspace_members: BTreeSet<PathBuf>,
    clippy: Option<crate::toolchain::ClippyDriver>,
    base: [u8; 32],
    source_limits: TreeLimits,
    payload_limits: TreeLimits,
    validation: ValidationMode,
}

pub struct BuildCaches {
    shared: BuildCache,
    local: BuildCache,
    shared_rebuild_reported: AtomicBool,
}

struct VerifiedEntry {
    payload: PathBuf,
    payload_manifest: Vec<u8>,
}

impl BuildCache {
    pub fn new(root: &Path, options: &Options<'_>) -> Result<Self> {
        let units = root.join("v1/units/sha256");
        let quarantine = root.join("v1/quarantine");
        fs::create_dir_all(&units).map_err(|error| {
            Error::failure(format!(
                "failed to create build-cache root `{}`: {error}",
                units.display()
            ))
        })?;

        let payload_limits = TreeLimits {
            max_entries: options.source_limits.max_entries.saturating_add(16),
            max_path_bytes: options.source_limits.max_path_bytes,
            max_file_bytes: options.source_limits.max_file_bytes.saturating_mul(4),
            max_tree_bytes: options.source_limits.max_tree_bytes.saturating_mul(4),
        };
        let mut digest = KeyDigest::new();
        digest.bytes("format", KEY_TAG);
        if options.validation.is_strict() {
            digest.file_contents("lorry-executable", options.cargo)?;
            digest.file("rustc-executable", &options.toolchain.rustc)?;
        } else {
            digest.metadata("lorry-executable", options.cargo)?;
            digest.metadata("rustc-executable", &options.toolchain.rustc)?;
        }
        digest.string("rustc-version", &options.toolchain.verbose_version);
        digest.string(
            "cargo-compatibility",
            match options.toolchain.compatibility {
                CargoCompat::V1_99 => "1.99",
            },
        );
        digest.string("build-script-sandbox-contract", "1");
        target_digest(&mut digest, "host", options.host);
        target_digest(&mut digest, "target", options.target);
        optional_tool_digest(
            &mut digest,
            "host-linker",
            options.host_linker,
            options.validation,
        )?;
        optional_tool_digest(
            &mut digest,
            "target-linker",
            options.target_linker,
            options.validation,
        )?;
        if options.validation.is_strict() {
            digest.file("root-Cargo.toml", &options.root_manifest.path)?;
            digest.file(
                "root-Cargo.lock",
                &options.root_manifest.workspace_root.join("Cargo.lock"),
            )?;
            sysroot_digest(&mut digest, options.toolchain, options.host, options.target)?;
        }

        Ok(Self {
            units,
            quarantine,
            cargo: options.cargo.to_owned(),
            workspace_root: options.root_manifest.workspace_root.clone(),
            workspace_members: options
                .root_manifest
                .workspace_members
                .values()
                .cloned()
                .collect(),
            clippy: options.toolchain.clippy.clone(),
            base: digest.finish(),
            source_limits: options.source_limits,
            payload_limits,
            validation: options.validation,
        })
    }

    pub fn key(&self, input: &UnitInput<'_>) -> Result<CacheKey> {
        if input.key.kind == UnitKind::BuildScriptRun {
            return Err(Error::failure(
                "build-script runs have no compiler identity",
            ));
        }
        let mut digest = KeyDigest::new();
        digest.bytes("base", &self.base);
        if self.workspace_members.contains(&input.manifest.root)
            && let Some(driver) = &self.clippy
        {
            digest.os("clippy-driver-path", driver.path.as_os_str(), &[]);
            digest.bytes("clippy-driver-sha256", &driver.sha256);
            for path in crate::clippy::configuration_candidates(
                &input.manifest.root,
                &input.invocation.current_dir,
                &driver.arguments,
                input.selected,
            ) {
                digest.os("clippy-config-candidate", path.as_os_str(), &[]);
                match fs::metadata(&path) {
                    Ok(metadata) if metadata.is_file() => {
                        let resolved = fs::canonicalize(&path).map_err(|error| {
                            Error::failure(format!(
                                "failed to resolve Clippy configuration `{}`: {error}",
                                path.display()
                            ))
                        })?;
                        digest.os("clippy-config-resolved", resolved.as_os_str(), &[]);
                        digest.file_contents("clippy-config-content", &resolved)?;
                    }
                    Ok(_) => digest.bytes("clippy-config-nonfile", b""),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                        ) =>
                    {
                        digest.bytes("clippy-config-absent", b"");
                    }
                    Err(error) => {
                        return Err(Error::failure(format!(
                            "failed to inspect Clippy configuration `{}`: {error}",
                            path.display()
                        )));
                    }
                }
            }
        }
        digest.string("package-name", &input.key.package.name);
        digest.string("package-version", &input.key.package.version.to_string());
        digest.string(
            "unit-kind",
            match input.key.kind {
                UnitKind::Library => "library",
                UnitKind::Binary => "binary",
                UnitKind::LibraryHarness => "library-harness",
                UnitKind::BinaryHarness => "binary-harness",
                UnitKind::IntegrationHarness => "integration-harness",
                UnitKind::Example => "example",
                UnitKind::Bench => "bench",
                UnitKind::ProcMacro => "proc-macro",
                UnitKind::BuildScriptCompile => "build-script-compile",
                UnitKind::BuildScriptRun => unreachable!(),
            },
        );
        if !matches!(input.key.kind, UnitKind::Library | UnitKind::ProcMacro) {
            digest.string("target", input.key.target.as_deref().unwrap_or(""));
        }
        let workspace_replacement = [(
            self.workspace_root.as_os_str(),
            b"<workspace-root>".as_slice(),
        )];
        match &input.key.package.source {
            PackageSourceKey::CratesIo => digest.string("package-source", "crates.io"),
            PackageSourceKey::Git(source) => {
                digest.string("package-source", "git");
                digest.string("package-source-identity", source);
            }
            PackageSourceKey::Path(path) => {
                digest.string("package-source", "path");
                digest.os(
                    "package-source-path",
                    path.as_os_str(),
                    &workspace_replacement,
                );
            }
        }
        digest.string(
            "compile-kind",
            match input.key.compile_kind {
                CompileKind::Host => "host",
                CompileKind::Target => "target",
            },
        );
        for feature in &input.key.features {
            digest.string("feature", feature);
        }
        digest.string("identity-metadata", &input.planned.identity.metadata);
        digest.string(
            "identity-extra-filename",
            &input.planned.identity.extra_filename,
        );
        if input.manifest.editable {
            digest.string("editable-member-cache", "external-dep-info-v3");
        }

        let mut replacements = vec![
            (self.cargo.as_os_str(), b"<lorry-executable>".as_slice()),
            (
                self.workspace_root.as_os_str(),
                b"<workspace-root>".as_slice(),
            ),
            (input.host_profile.as_os_str(), b"<host-profile>".as_slice()),
            (
                input.target_profile.as_os_str(),
                b"<target-profile>".as_slice(),
            ),
        ];
        if let Some(build) = &input.build_script {
            replacements.push((build.out_dir.as_os_str(), b"<build-out-dir>"));
            replacements.push((build.temp_dir.as_os_str(), b"<build-temp-dir>"));
        }
        replacements.sort_by_key(|(path, _)| std::cmp::Reverse(path.as_encoded_bytes().len()));
        replacements.dedup_by(|left, right| left.0 == right.0);

        digest.os(
            "rustc-current-directory",
            input.invocation.current_dir.as_os_str(),
            &replacements,
        );
        rustc_arguments_digest(&mut digest, &input.invocation.arguments, &replacements)?;
        // Other process variables are rechecked after compilation when rustc
        // reports reading them, as Cargo does.
        let mut environment = input
            .invocation
            .environment
            .iter()
            .map(|(name, value)| (name.as_str(), Some(value.clone())))
            .collect::<BTreeMap<_, _>>();
        for name in tracked_env::COMPILER_VARIABLES {
            environment
                .entry(name)
                .or_insert_with(|| tracked_env::current(name));
        }
        for (name, value) in environment {
            let Some(value) = value else { continue };
            digest.os("rustc-environment-name", OsStr::new(name), &replacements);
            digest.os("rustc-environment-value", &value, &replacements);
        }

        if input.manifest.editable {
            digest.bytes(
                "editable-source",
                &crate::member_source::snapshot(input.manifest, self.validation.is_strict())?
                    .sha256,
            );
        } else if self.validation.is_strict() {
            let source = Tree::scan(
                &input.manifest.root,
                self.source_limits,
                input.planned.source_exclusions,
            )?;
            digest.bytes("package-source-tree", &source.manifest_bytes());
            digest.file("package-manifest", &input.manifest.path)?;
        } else {
            match &input.key.package.source {
                PackageSourceKey::CratesIo => {
                    digest.string("package-source-identity", "immutable-crates.io")
                }
                PackageSourceKey::Git(source) => digest.string("package-source-identity", source),
                PackageSourceKey::Path(_) => metadata_tree_digest(
                    &mut digest,
                    &input.manifest.root,
                    self.source_limits,
                    input.planned.source_exclusions,
                )?,
            }
        }

        for dependency in input.dependencies {
            digest.string("dependency-package", &dependency.key.package.name);
            digest.string(
                "dependency-version",
                &dependency.key.package.version.to_string(),
            );
            digest.string("dependency-alias", dependency.alias.unwrap_or(""));
            if self.validation.is_strict() {
                digest.file_contents("dependency-rlib", dependency.rlib)?;
                digest.file_contents("dependency-rmeta", dependency.rmeta)?;
            } else {
                let key = dependency.cache_key.ok_or_else(|| {
                    Error::failure(format!(
                        "dependency cache identity for `{} {}` is missing",
                        dependency.key.package.name, dependency.key.package.version
                    ))
                })?;
                digest.bytes("dependency-cache-key", &key.0);
            }
        }

        match &input.build_script {
            Some(build) => {
                digest.string("build-script", "present");
                digest.bytes("build-script-executable", &build.executable_sha256);
                for (name, value) in build.environment {
                    digest.string("build-script-environment-name", name);
                    digest.os("build-script-environment-value", value, &replacements);
                }
                directive_digest(&mut digest, &build.output.directives, &replacements);
                digest.bytes(
                    "build-script-OUT_DIR",
                    &build.output.out_dir.manifest_bytes(),
                );
            }
            None => digest.string("build-script", "absent"),
        }
        Ok(CacheKey(digest.finish()))
    }

    /// The identity that dependents compose: the unit key plus the inputs
    /// checked only after compilation (tracked variables and a selected
    /// unit's external dep-info inputs), so a change rebuilds them too.
    pub fn dependency_key(
        &self,
        key: CacheKey,
        output: &RustcOutput,
        selected: Option<SelectedInputs<'_>>,
        tracked: &Tracked,
    ) -> Result<CacheKey> {
        if tracked.is_empty() && selected.is_none() {
            return Ok(key);
        }
        let mut digest = KeyDigest::new();
        digest.bytes("unit-key", &key.0);
        digest.bytes("tracked-environment", &tracked_env::encode(tracked));
        if let Some(inputs) = selected {
            digest.bytes(
                "external-inputs",
                &external_inputs_digest(output.dep_info(), inputs)?,
            );
        }
        Ok(CacheKey(digest.finish()))
    }

    pub fn restore(
        &self,
        key: CacheKey,
        output: &RustcOutput,
        selected: Option<SelectedInputs<'_>>,
    ) -> Result<Option<Restored>> {
        let Some(entry) = self.verified_or_quarantine(key)? else {
            return Ok(None);
        };
        let Some(tracked) = fs::read(entry.payload.join(PAYLOAD_ENVIRONMENT))
            .ok()
            .and_then(|bytes| tracked_env::decode(&bytes))
        else {
            return Ok(None);
        };
        if !tracked_env::matches_current(&tracked) {
            return Ok(None);
        }
        if archive_path(output).is_some()
            && !fs::symlink_metadata(entry.payload.join("library.a"))
                .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        {
            self.quarantine(&self.entry_path(key), key)?;
            return Ok(None);
        }
        if let Some(inputs) = selected {
            let dep_info = entry.payload.join("library.d");
            let recorded = entry.payload.join("external-inputs.sha256");
            let Some(current) = external_inputs_digest(&dep_info, inputs).ok() else {
                return Ok(None);
            };
            if fs::read(recorded).ok().as_deref() != Some(current.as_slice()) {
                return Ok(None);
            }
        }
        let (rlib, rmeta) = library_paths(output)?;
        copy_new_file(&entry.payload.join("library.rlib"), rlib)?;
        if rmeta != rlib {
            copy_new_file(&entry.payload.join("library.rmeta"), rmeta)?;
        }
        if let Some(archive) = archive_path(output) {
            copy_new_file(&entry.payload.join("library.a"), archive)?;
        }
        if selected.is_some() {
            copy_new_file(&entry.payload.join("library.d"), output.dep_info())?;
        }
        let stdout = fs::read(entry.payload.join(PUBLISHED_STDOUT))?;
        let stderr = fs::read(entry.payload.join(PUBLISHED_STDERR))?;
        Ok(Some(Restored {
            stdout,
            stderr,
            tracked,
        }))
    }

    /// Returns the variables a published unit read when it is still fresh.
    pub fn published_fresh(
        &self,
        key: CacheKey,
        output: &RustcOutput,
        selected: Option<SelectedInputs<'_>>,
        package: &crate::resolver::PackageKey,
    ) -> Result<Option<Tracked>> {
        let directory = published_unit_directory(output)?;
        if !artifact_owner::matches(directory, package) {
            return Ok(None);
        }
        let record = directory.join(PUBLISHED_RECORD);
        match fs::symlink_metadata(&record) {
            Ok(metadata) if metadata.file_type().is_file() && metadata.len() == 32 => {}
            _ => return Ok(None),
        }
        let Some(tracked) = fs::read(directory.join(PUBLISHED_ENVIRONMENT))
            .ok()
            .and_then(|bytes| tracked_env::decode(&bytes))
            .filter(tracked_env::matches_current)
        else {
            return Ok(None);
        };
        let Some(current) = published_fingerprint(key, output, selected, self.validation).ok()
        else {
            return Ok(None);
        };
        Ok((fs::read(record).ok().as_deref() == Some(current.as_slice())).then_some(tracked))
    }

    pub fn record_published(
        &self,
        key: CacheKey,
        output: &RustcOutput,
        selected: Option<SelectedInputs<'_>>,
        package: &crate::resolver::PackageKey,
        (stdout, stderr): (&[u8], &[u8]),
        tracked: &Tracked,
    ) -> Result<()> {
        let directory = published_unit_directory(output)?;
        write_synced(&directory.join(PUBLISHED_STDOUT), stdout)?;
        write_synced(&directory.join(PUBLISHED_STDERR), stderr)?;
        write_synced(
            &directory.join(PUBLISHED_ENVIRONMENT),
            &tracked_env::encode(tracked),
        )?;
        let fingerprint = published_fingerprint(key, output, selected, self.validation)?;
        artifact_owner::write(directory, package)?;
        write_synced(&directory.join(PUBLISHED_RECORD), &fingerprint)
    }

    pub fn published_messages(&self, output: &RustcOutput) -> Result<(Vec<u8>, Vec<u8>)> {
        let directory = published_unit_directory(output)?;
        let read = |name| {
            fs::read(directory.join(name)).map_err(|error| {
                Error::failure(format!(
                    "failed to read published compiler messages: {error}"
                ))
            })
        };
        Ok((read(PUBLISHED_STDOUT)?, read(PUBLISHED_STDERR)?))
    }

    pub fn store(
        &self,
        key: CacheKey,
        output: &RustcOutput,
        build_script: Option<&BuildScriptInput<'_>>,
        selected: Option<SelectedInputs<'_>>,
        diagnostics: (&[u8], &[u8]),
        tracked: &Tracked,
    ) -> Result<()> {
        let (rlib, rmeta) = library_paths(output)?;
        let dep_info = selected.map(|_| output.dep_info());
        let destination = self.entry_path(key);
        let external_inputs = selected
            .map(|inputs| external_inputs_digest(dep_info.unwrap(), inputs))
            .transpose()?;
        let environment = tracked_env::encode(tracked);
        let mut replace = false;
        if let Some(existing) = self.verified_or_quarantine(key)? {
            replace = external_inputs.as_ref().is_some_and(|wanted| {
                fs::read(existing.payload.join("external-inputs.sha256"))
                    .ok()
                    .as_deref()
                    != Some(wanted.as_slice())
            }) || fs::read(existing.payload.join(PAYLOAD_ENVIRONMENT)).ok()
                != Some(environment.clone());
            if !replace {
                if !self.validation.is_strict() {
                    return Ok(());
                }
                let wanted = payload_manifest(
                    output,
                    dep_info,
                    external_inputs.as_ref(),
                    build_script,
                    diagnostics,
                    &environment,
                    self.payload_limits,
                )?;
                if existing.payload_manifest == wanted {
                    return Ok(());
                }
                return Err(Error::failure(format!(
                    "concurrent cache writers produced different verified outputs for `{}`",
                    hex(&key.0)
                )));
            }
        }

        let parent = destination
            .parent()
            .ok_or_else(|| Error::failure("build-cache entry has no parent"))?;
        let staging = AtomicDirectory::new(parent, &hex(&key.0))?;
        let payload = staging.path().join("payload");
        fs::create_dir(&payload).map_err(|error| {
            Error::failure(format!(
                "failed to create cache payload `{}`: {error}",
                payload.display()
            ))
        })?;
        copy_synced_file(rlib, &payload.join("library.rlib"))?;
        copy_synced_file(rmeta, &payload.join("library.rmeta"))?;
        if let Some(archive) = archive_path(output) {
            copy_synced_file(archive, &payload.join("library.a"))?;
        }
        write_synced(&payload.join(PUBLISHED_STDOUT), diagnostics.0)?;
        write_synced(&payload.join(PUBLISHED_STDERR), diagnostics.1)?;
        write_synced(&payload.join(PAYLOAD_ENVIRONMENT), &environment)?;
        if let Some(dep_info) = dep_info {
            copy_synced_file(dep_info, &payload.join("library.d"))?;
            write_synced(
                &payload.join("external-inputs.sha256"),
                external_inputs.as_ref().unwrap(),
            )?;
        }
        if let Some(build) = build_script {
            write_synced(
                &payload.join("build-script.json"),
                &build_script_manifest(build),
            )?;
            copy_tree(
                build.out_dir,
                &payload.join("build-output"),
                &build.output.out_dir,
            )?;
        }
        let tree = Tree::scan(&payload, self.payload_limits, Exclusions::None)?;
        let payload_manifest = tree.manifest_bytes();
        write_synced(
            &staging.path().join("payload-manifest.json"),
            &payload_manifest,
        )?;
        let manifest = entry_manifest(key, &tree, &payload_manifest);
        write_synced(&staging.path().join("manifest.json"), &manifest)?;

        if replace {
            staging.commit(&destination)?;
            return Ok(());
        }
        if staging.commit_no_replace(&destination)? {
            return Ok(());
        }
        let existing = self.verify_entry(key)?;
        if !self.validation.is_strict() {
            return Ok(());
        }
        if existing.payload_manifest != payload_manifest {
            return Err(Error::failure(format!(
                "concurrent cache writers produced different verified outputs for `{}`",
                hex(&key.0)
            )));
        }
        Ok(())
    }

    pub fn record_cache_owner(
        &self,
        key: CacheKey,
        package: &crate::resolver::PackageKey,
    ) -> Result<()> {
        artifact_owner::write(&self.entry_path(key), package)
    }

    fn entry_path(&self, key: CacheKey) -> PathBuf {
        let hash = hex(&key.0);
        self.units.join(&hash[..2]).join(hash)
    }

    fn verified_or_quarantine(&self, key: CacheKey) -> Result<Option<VerifiedEntry>> {
        let path = self.entry_path(key);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(Error::failure(format!(
                    "failed to inspect build-cache entry `{}`: {error}",
                    path.display()
                )));
            }
        }
        match self.verify_entry(key) {
            Ok(entry) => Ok(Some(entry)),
            Err(error) => {
                eprintln!(
                    "warning: quarantining corrupt Lorry build-cache entry `{}`: {}",
                    path.display(),
                    error
                );
                self.quarantine(&path, key)?;
                Ok(None)
            }
        }
    }

    fn verify_entry(&self, key: CacheKey) -> Result<VerifiedEntry> {
        let entry = self.entry_path(key);
        let metadata = fs::symlink_metadata(&entry).map_err(|error| {
            Error::failure(format!(
                "failed to inspect cache entry `{}`: {error}",
                entry.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::failure("cache entry is not a regular directory"));
        }
        let mut names = fs::read_dir(&entry)
            .map_err(|error| Error::failure(format!("failed to read cache entry: {error}")))?
            .map(|child| {
                child
                    .map_err(|error| Error::failure(format!("failed to read cache entry: {error}")))
                    .and_then(|child| {
                        child.file_name().into_string().map_err(|_| {
                            Error::failure("cache entry contains a non-UTF-8 filename")
                        })
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        names.sort();
        if names != ["manifest.json", "payload", "payload-manifest.json"]
            && names
                != [
                    ".lorry-owner-v1",
                    "manifest.json",
                    "payload",
                    "payload-manifest.json",
                ]
        {
            return Err(Error::failure(
                "cache entry does not contain the exact format-1 file set",
            ));
        }

        let manifest_path = entry.join("manifest.json");
        let manifest = canonical_document(&manifest_path, "build-cache entry manifest")?;
        let object = manifest
            .as_object()
            .ok_or_else(|| Error::failure("cache entry manifest is not an object"))?;
        if object.len() != 4
            || object.get("format-version").and_then(Value::as_u64) != Some(FORMAT_VERSION)
            || object.get("cache-key-sha256").and_then(Value::as_str) != Some(&hex(&key.0))
        {
            return Err(Error::failure("cache entry manifest identity is invalid"));
        }

        let payload = entry.join("payload");
        let payload_metadata = fs::symlink_metadata(&payload)
            .map_err(|error| Error::failure(format!("failed to inspect cache payload: {error}")))?;
        if payload_metadata.file_type().is_symlink() || !payload_metadata.is_dir() {
            return Err(Error::failure("cache payload is not a regular directory"));
        }
        for required in [
            "library.rlib",
            "library.rmeta",
            PUBLISHED_STDOUT,
            PUBLISHED_STDERR,
        ] {
            let metadata = fs::symlink_metadata(payload.join(required)).map_err(|error| {
                Error::failure(format!("cache payload is missing `{required}`: {error}"))
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::failure(format!(
                    "cache payload `{required}` is not a regular file"
                )));
            }
        }
        if !self.validation.is_strict() {
            return Ok(VerifiedEntry {
                payload,
                payload_manifest: Vec::new(),
            });
        }

        let payload_manifest_path = entry.join("payload-manifest.json");
        let payload_document =
            canonical_document(&payload_manifest_path, "build-cache payload manifest")?;
        let payload_manifest = payload_document.canonical_bytes();
        if object
            .get("payload-manifest-sha256")
            .and_then(Value::as_str)
            != Some(&hex(&sha256_bytes(&payload_manifest)))
        {
            return Err(Error::failure("cache payload manifest digest is invalid"));
        }
        let tree = Tree::scan(&payload, self.payload_limits, Exclusions::None)?;
        if tree.manifest_bytes() != payload_manifest
            || object.get("payload-tree-sha256").and_then(Value::as_str) != Some(&hex(&tree.sha256))
        {
            return Err(Error::failure(
                "cache payload contents do not match its manifest",
            ));
        }
        Ok(VerifiedEntry {
            payload,
            payload_manifest,
        })
    }

    fn quarantine(&self, entry: &Path, key: CacheKey) -> Result<()> {
        fs::create_dir_all(&self.quarantine).map_err(|error| {
            Error::failure(format!(
                "failed to create cache quarantine `{}`: {error}",
                self.quarantine.display()
            ))
        })?;
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let destination =
            self.quarantine
                .join(format!("{}-{}-{time:x}", hex(&key.0), std::process::id()));
        match fs::rename(entry, &destination) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::failure(format!(
                "failed to quarantine corrupt cache entry `{}`: {error}",
                entry.display()
            ))),
        }
    }

    #[cfg(test)]
    fn for_test(root: &Path) -> Self {
        Self::for_test_with_validation(root, ValidationMode::Strict)
    }

    #[cfg(test)]
    fn for_test_with_validation(root: &Path, validation: ValidationMode) -> Self {
        let limits = TreeLimits {
            max_entries: 100,
            max_path_bytes: 1024,
            max_file_bytes: 1024 * 1024,
            max_tree_bytes: 4 * 1024 * 1024,
        };
        Self {
            units: root.join("v1/units/sha256"),
            quarantine: root.join("v1/quarantine"),
            cargo: PathBuf::from("/test/lorry"),
            workspace_root: PathBuf::from("/test/workspace"),
            workspace_members: BTreeSet::new(),
            clippy: None,
            base: [3; 32],
            source_limits: limits,
            payload_limits: limits,
            validation,
        }
    }
}

impl BuildCaches {
    pub fn new(shared_root: &Path, local_root: &Path, options: &Options<'_>) -> Result<Self> {
        Ok(Self {
            shared: BuildCache::new(shared_root, options)?,
            local: BuildCache::new(local_root, options)?,
            shared_rebuild_reported: AtomicBool::new(false),
        })
    }

    pub fn for_unit(&self, planned: &PlannedUnit) -> &BuildCache {
        if globally_cacheable(planned) {
            &self.shared
        } else {
            &self.local
        }
    }

    pub fn report_shared_rebuild(&self, planned: &PlannedUnit) -> bool {
        globally_cacheable(planned) && !self.shared_rebuild_reported.swap(true, Ordering::Relaxed)
    }
}

fn globally_cacheable(planned: &PlannedUnit) -> bool {
    globally_cacheable_source(&planned.unit.key.package.source)
}

fn globally_cacheable_source(source: &PackageSourceKey) -> bool {
    match source {
        PackageSourceKey::CratesIo | PackageSourceKey::Git(_) => true,
        PackageSourceKey::Path(_) => false,
    }
}

fn rustc_arguments_digest(
    digest: &mut KeyDigest,
    arguments: &[OsString],
    replacements: &[(&OsStr, &[u8])],
) -> Result<()> {
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--verbose" {
            continue;
        }
        digest.os("rustc-argument", argument, replacements);
        if argument == "--cap-lints" {
            arguments.next().ok_or_else(|| {
                Error::failure("rustc cache identity found --cap-lints without its value")
            })?;
            digest.string("rustc-argument", "<diagnostic-cap-lints>");
        }
    }
    Ok(())
}

fn target_digest(digest: &mut KeyDigest, role: &str, target: &TargetInfo) {
    digest.string(&format!("{role}-triple"), &target.triple);
    for (name, value) in target.cfg.cargo_environment() {
        digest.string(&format!("{role}-cfg-name"), &name);
        digest.string(&format!("{role}-cfg-value"), &value);
    }
}

fn optional_tool_digest(
    digest: &mut KeyDigest,
    role: &str,
    path: Option<&Path>,
    validation: ValidationMode,
) -> Result<()> {
    match path {
        Some(path) => {
            digest.string(role, "present");
            digest.os(&format!("{role}-path"), path.as_os_str(), &[]);
            if validation.is_strict() {
                digest.file(&format!("{role}-contents"), path)
            } else {
                digest.metadata(&format!("{role}-contents"), path)
            }
        }
        None => {
            digest.string(role, "absent");
            Ok(())
        }
    }
}

fn sysroot_digest(
    digest: &mut KeyDigest,
    toolchain: &Toolchain,
    host: &TargetInfo,
    target: &TargetInfo,
) -> Result<()> {
    let output = process::query_rustc(
        &toolchain.rustc,
        &["--print", "sysroot"],
        "rustc sysroot query",
    )?;
    let text = String::from_utf8(output.stdout)
        .map_err(|_| Error::failure("rustc sysroot output is not Unicode"))?;
    let sysroot = PathBuf::from(text.trim());
    if !sysroot.is_absolute() {
        return Err(Error::failure(format!(
            "rustc returned non-absolute sysroot `{}`",
            sysroot.display()
        )));
    }
    let limits = TreeLimits {
        max_entries: 100_000,
        max_path_bytes: 4_096,
        max_file_bytes: 1024 * 1024 * 1024,
        max_tree_bytes: 2 * 1024 * 1024 * 1024,
    };
    let mut triples = vec![host.triple.as_str(), target.triple.as_str()];
    triples.sort_unstable();
    triples.dedup();
    for triple in triples {
        let libraries = sysroot.join("lib/rustlib").join(triple).join("lib");
        let tree = Tree::scan(&libraries, limits, Exclusions::None).map_err(|error| {
            Error::failure(format!(
                "failed to identify rustc sysroot libraries for `{triple}`: {error}"
            ))
        })?;
        digest.string("sysroot-triple", triple);
        digest.bytes("sysroot-library-tree", &tree.manifest_bytes());
    }
    Ok(())
}

fn metadata_tree_digest(
    digest: &mut KeyDigest,
    root: &Path,
    limits: TreeLimits,
    exclusions: Exclusions,
) -> Result<()> {
    if !fs::symlink_metadata(root)
        .map_err(|error| {
            Error::failure(format!(
                "failed to inspect source root `{}`: {error}",
                root.display()
            ))
        })?
        .is_dir()
    {
        return Err(Error::failure(format!(
            "source root `{}` is not a directory",
            root.display()
        )));
    }
    let mut pending = vec![root.to_owned()];
    let mut entries = Vec::new();
    let mut total_bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for child in fs::read_dir(&directory).map_err(|error| {
            Error::failure(format!(
                "failed to read source directory `{}`: {error}",
                directory.display()
            ))
        })? {
            let path = child
                .map_err(|error| Error::failure(format!("failed to read source entry: {error}")))?
                .path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                Error::failure(format!(
                    "failed to inspect source entry `{}`: {error}",
                    path.display()
                ))
            })?;
            let name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
                Error::failure(format!(
                    "source path is not valid UTF-8: `{}`",
                    path.display()
                ))
            })?;
            let excluded = match exclusions {
                Exclusions::None => false,
                Exclusions::GitAndTarget => {
                    name == ".git" || (name == "target" && metadata.is_dir())
                }
                Exclusions::CargoRegistryMarker => {
                    name == ".cargo-ok" && path.parent() == Some(root) && metadata.is_file()
                }
            };
            if excluded {
                continue;
            }
            if metadata.file_type().is_symlink() {
                return Err(Error::failure(format!(
                    "source entry `{}` is a symbolic link",
                    path.display()
                )));
            }
            let relative = path
                .strip_prefix(root)
                .expect("source walk remains below root");
            let relative = relative.to_str().ok_or_else(|| {
                Error::failure(format!(
                    "source path is not valid UTF-8: `{}`",
                    path.display()
                ))
            })?;
            if relative.len() > limits.max_path_bytes {
                return Err(Error::failure(format!(
                    "source path `{relative}` exceeds the path-length limit"
                )));
            }
            if metadata.is_dir() {
                entries.push((relative.to_owned(), None));
                pending.push(path);
            } else if metadata.is_file() {
                if metadata.len() > limits.max_file_bytes {
                    return Err(Error::failure(format!(
                        "source file `{relative}` exceeds the file-size limit"
                    )));
                }
                total_bytes = total_bytes.saturating_add(metadata.len());
                if total_bytes > limits.max_tree_bytes {
                    return Err(Error::failure(format!(
                        "source tree `{}` exceeds the byte limit",
                        root.display()
                    )));
                }
                let modified = modified_time(&path, &metadata)?;
                entries.push((relative.to_owned(), Some((metadata.len(), modified))));
            } else {
                return Err(Error::failure(format!(
                    "source entry `{}` is not a regular file or directory",
                    path.display()
                )));
            }
            if entries.len() > limits.max_entries {
                return Err(Error::failure(format!(
                    "source tree `{}` exceeds the entry-count limit",
                    root.display()
                )));
            }
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    for (path, file) in entries {
        digest.string("source-path", &path);
        match file {
            None => digest.string("source-kind", "directory"),
            Some((length, modified)) => {
                digest.string("source-kind", "file");
                digest.bytes("source-length", &length.to_le_bytes());
                digest.bytes("source-mtime-secs", &modified.as_secs().to_le_bytes());
                digest.bytes("source-mtime-nanos", &modified.subsec_nanos().to_le_bytes());
            }
        }
    }
    Ok(())
}

fn directive_digest(
    digest: &mut KeyDigest,
    directives: &[Directive],
    replacements: &[(&OsStr, &[u8])],
) {
    for directive in directives {
        match directive {
            Directive::RustcCfg(value) => {
                digest.string("directive", "rustc-cfg");
                digest.os("value", OsStr::new(value), replacements);
            }
            Directive::RustcCheckCfg(value) => {
                digest.string("directive", "rustc-check-cfg");
                digest.os("value", OsStr::new(value), replacements);
            }
            Directive::RustcEnv { name, value } => {
                digest.string("directive", "rustc-env");
                digest.string("name", name);
                digest.os("value", OsStr::new(value), replacements);
            }
            Directive::RustcLinkLib(value) => {
                digest.string("directive", "rustc-link-lib");
                digest.os("value", OsStr::new(value), replacements);
            }
            Directive::RustcLinkArg(value) => {
                digest.string("directive", "rustc-link-arg");
                digest.os("value", OsStr::new(value), replacements);
            }
            Directive::RustcLinkSearch { kind, path } => {
                digest.string("directive", "rustc-link-search");
                digest.string("kind", kind.as_deref().unwrap_or(""));
                digest.os("path", path.as_os_str(), replacements);
            }
            Directive::RerunIfChanged(path) => {
                digest.string("directive", "rerun-if-changed");
                digest.os("path", path.as_os_str(), replacements);
            }
            Directive::RerunIfEnvChanged { name, value } => {
                digest.string("directive", "rerun-if-env-changed");
                digest.string("name", name);
                match value {
                    Some(value) => digest.os("value", value, replacements),
                    None => digest.string("value", "<absent>"),
                }
            }
            Directive::Warning(value) => {
                digest.string("directive", "warning");
                digest.os("value", OsStr::new(value), replacements);
            }
        }
    }
}

fn archive_path(output: &RustcOutput) -> Option<&Path> {
    match output {
        RustcOutput::Library { archive, .. } => archive.as_deref(),
        _ => None,
    }
}

fn library_paths(output: &RustcOutput) -> Result<(&Path, &Path)> {
    match output {
        RustcOutput::Library { rlib, rmeta, .. } => Ok((rlib, rmeta)),
        RustcOutput::StaticLibrary { archive, .. } => Ok((archive, archive)),
        RustcOutput::ProcMacro {
            dynamic_library, ..
        } => Ok((dynamic_library, dynamic_library)),
        RustcOutput::Binary { .. }
        | RustcOutput::Metadata { .. }
        | RustcOutput::BuildScript { .. } => Err(Error::failure(
            "executable artifacts cannot be stored in the dependency unit cache",
        )),
    }
}

fn published_unit_directory(output: &RustcOutput) -> Result<&Path> {
    let primary = match output {
        RustcOutput::Library { rlib, .. } => rlib,
        RustcOutput::StaticLibrary { archive, .. } => archive,
        RustcOutput::Binary { executable, .. } | RustcOutput::BuildScript { executable, .. } => {
            executable
        }
        RustcOutput::Metadata { metadata, .. } => metadata,
        RustcOutput::ProcMacro {
            dynamic_library, ..
        } => dynamic_library,
    };
    primary
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| Error::failure("published library has no unit directory"))
}

fn published_fingerprint(
    key: CacheKey,
    output: &RustcOutput,
    selected: Option<SelectedInputs<'_>>,
    validation: ValidationMode,
) -> Result<[u8; 32]> {
    let files: Vec<&Path> = match output {
        RustcOutput::Library {
            rlib,
            rmeta,
            dep_info,
            archive,
        } => {
            let mut files = vec![rlib.as_path()];
            files.extend(archive.iter().map(PathBuf::as_path));
            if rmeta != rlib {
                files.push(rmeta);
            }
            if selected.is_some() {
                files.push(dep_info);
            }
            files
        }
        RustcOutput::ProcMacro {
            dynamic_library,
            dep_info,
        }
        | RustcOutput::StaticLibrary {
            archive: dynamic_library,
            dep_info,
        } => {
            let mut files = vec![dynamic_library.as_path()];
            if selected.is_some() {
                files.push(dep_info);
            }
            files
        }
        RustcOutput::Binary {
            executable,
            dep_info,
        }
        | RustcOutput::Metadata {
            metadata: executable,
            dep_info,
        } => vec![executable, dep_info],
        RustcOutput::BuildScript {
            executable,
            unhashed_executable,
            dep_info,
        } => vec![executable, unhashed_executable, dep_info],
    };
    let mut digest = KeyDigest::new();
    digest.bytes("schema", b"published-compiler-unit-v1");
    digest.bytes("cache-key", &key.0);
    for path in files {
        let name = path
            .file_name()
            .ok_or_else(|| Error::failure("unit output has no name"))?;
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            Error::failure(format!(
                "failed to inspect unit output `{}`: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(Error::failure(format!(
                "unit output `{}` is not a regular file",
                path.display()
            )));
        }
        digest.os("artifact-name", name, &[]);
        if validation.is_strict() {
            digest.file_contents("artifact-contents", path)?;
        } else {
            let modified = modified_time(path, &metadata)?;
            digest.bytes("artifact-length", &metadata.len().to_le_bytes());
            digest.bytes("artifact-mtime-secs", &modified.as_secs().to_le_bytes());
            digest.bytes(
                "artifact-mtime-nanos",
                &modified.subsec_nanos().to_le_bytes(),
            );
        }
    }
    let directory = published_unit_directory(output)?;
    for name in [PUBLISHED_STDOUT, PUBLISHED_STDERR, PUBLISHED_ENVIRONMENT] {
        let path = directory.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            Error::failure(format!("failed to inspect published unit record: {error}"))
        })?;
        if !metadata.file_type().is_file() {
            return Err(Error::failure(
                "published unit record is not a regular file",
            ));
        }
        digest.file_contents(name, &path)?;
    }
    if let Some(inputs) = selected {
        digest.bytes(
            "external-inputs",
            &external_inputs_digest(output.dep_info(), inputs)?,
        );
    }
    Ok(digest.finish())
}

fn entry_manifest(key: CacheKey, tree: &Tree, payload_manifest: &[u8]) -> Vec<u8> {
    Value::Object(BTreeMap::from([
        ("cache-key-sha256".to_owned(), Value::String(hex(&key.0))),
        (
            "format-version".to_owned(),
            Value::Number(FORMAT_VERSION.into()),
        ),
        (
            "payload-manifest-sha256".to_owned(),
            Value::String(hex(&sha256_bytes(payload_manifest))),
        ),
        (
            "payload-tree-sha256".to_owned(),
            Value::String(hex(&tree.sha256)),
        ),
    ]))
    .canonical_bytes()
}

fn canonical_document(path: &Path, context: &str) -> Result<Value> {
    let document = Value::load(path, context)?;
    let bytes = fs::read(path)
        .map_err(|error| Error::failure(format!("failed to read `{}`: {error}", path.display())))?;
    if bytes != document.canonical_bytes() {
        return Err(Error::failure(format!("{context} is not canonical JSON")));
    }
    Ok(document)
}

fn payload_manifest(
    output: &RustcOutput,
    dep_info: Option<&Path>,
    external_inputs: Option<&[u8; 32]>,
    build_script: Option<&BuildScriptInput<'_>>,
    diagnostics: (&[u8], &[u8]),
    environment: &[u8],
    limits: TreeLimits,
) -> Result<Vec<u8>> {
    let (rlib, rmeta) = library_paths(output)?;
    let parent = std::env::temp_dir().join(format!(
        ".lorry-cache-payload-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    ));
    let staging = AtomicDirectory::new(
        parent
            .parent()
            .ok_or_else(|| Error::failure("temporary directory has no parent"))?,
        parent
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("payload"),
    )?;
    let payload = staging.path().join("payload");
    fs::create_dir(&payload).map_err(|error| {
        Error::failure(format!("failed to create temporary cache payload: {error}"))
    })?;
    copy_synced_file(rlib, &payload.join("library.rlib"))?;
    copy_synced_file(rmeta, &payload.join("library.rmeta"))?;
    if let Some(archive) = archive_path(output) {
        copy_synced_file(archive, &payload.join("library.a"))?;
    }
    write_synced(&payload.join(PUBLISHED_STDOUT), diagnostics.0)?;
    write_synced(&payload.join(PUBLISHED_STDERR), diagnostics.1)?;
    write_synced(&payload.join(PAYLOAD_ENVIRONMENT), environment)?;
    if let Some(dep_info) = dep_info {
        copy_synced_file(dep_info, &payload.join("library.d"))?;
        write_synced(
            &payload.join("external-inputs.sha256"),
            external_inputs.ok_or_else(|| Error::failure("missing external-input fingerprint"))?,
        )?;
    }
    if let Some(build) = build_script {
        write_synced(
            &payload.join("build-script.json"),
            &build_script_manifest(build),
        )?;
        copy_tree(
            build.out_dir,
            &payload.join("build-output"),
            &build.output.out_dir,
        )?;
    }
    Ok(Tree::scan(&payload, limits, Exclusions::None)?.manifest_bytes())
}

fn build_script_manifest(build: &BuildScriptInput<'_>) -> Vec<u8> {
    let mut replacements = vec![
        (build.out_dir.as_os_str(), b"<OUT_DIR>".as_slice()),
        (build.temp_dir.as_os_str(), b"<TEMP_DIR>".as_slice()),
    ];
    if let Some(profile) = build.out_dir.ancestors().nth(3) {
        replacements.push((profile.as_os_str(), b"<HOST_PROFILE>"));
    }
    if let Some(cargo) = build.environment.get("CARGO") {
        replacements.push((cargo.as_os_str(), b"<CARGO>"));
    }
    replacements.sort_by_key(|(path, _)| std::cmp::Reverse(path.as_encoded_bytes().len()));
    let directives = build
        .output
        .directives
        .iter()
        .map(|directive| {
            let (kind, fields) = match directive {
                Directive::RustcCfg(value) => (
                    "rustc-cfg",
                    vec![("value-encoded", encoded(OsStr::new(value), &replacements))],
                ),
                Directive::RustcCheckCfg(value) => (
                    "rustc-check-cfg",
                    vec![("value-encoded", encoded(OsStr::new(value), &replacements))],
                ),
                Directive::RustcEnv { name, value } => (
                    "rustc-env",
                    vec![
                        ("name", Value::String(name.clone())),
                        ("value-encoded", encoded(OsStr::new(value), &replacements)),
                    ],
                ),
                Directive::RustcLinkLib(value) => (
                    "rustc-link-lib",
                    vec![("value-encoded", encoded(OsStr::new(value), &replacements))],
                ),
                Directive::RustcLinkArg(value) => (
                    "rustc-link-arg",
                    vec![("value-encoded", encoded(OsStr::new(value), &replacements))],
                ),
                Directive::RustcLinkSearch { kind, path } => (
                    "rustc-link-search",
                    vec![
                        (
                            "link-kind",
                            kind.as_ref()
                                .map_or(Value::Null, |kind| Value::String(kind.clone())),
                        ),
                        ("path-encoded", encoded(path.as_os_str(), &replacements)),
                    ],
                ),
                Directive::RerunIfChanged(path) => (
                    "rerun-if-changed",
                    vec![("path-encoded", encoded(path.as_os_str(), &replacements))],
                ),
                Directive::RerunIfEnvChanged { name, value } => (
                    "rerun-if-env-changed",
                    vec![
                        ("name", Value::String(name.clone())),
                        (
                            "value-encoded",
                            value.as_ref().map_or(Value::Null, |value| {
                                encoded(value.as_os_str(), &replacements)
                            }),
                        ),
                    ],
                ),
                Directive::Warning(value) => (
                    "warning",
                    vec![("value-encoded", encoded(OsStr::new(value), &replacements))],
                ),
            };
            let mut object = BTreeMap::from([("kind".to_owned(), Value::String(kind.to_owned()))]);
            object.extend(
                fields
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value)),
            );
            Value::Object(object)
        })
        .collect();
    let environment = build
        .environment
        .iter()
        .map(|(name, value)| {
            Value::Object(BTreeMap::from([
                ("name".to_owned(), Value::String(name.clone())),
                (
                    "value-encoded".to_owned(),
                    encoded(value.as_os_str(), &replacements),
                ),
            ]))
        })
        .collect();
    Value::Object(BTreeMap::from([
        ("directives".to_owned(), Value::Array(directives)),
        ("environment".to_owned(), Value::Array(environment)),
        (
            "executable-sha256".to_owned(),
            Value::String(hex(&build.executable_sha256)),
        ),
        (
            "format-version".to_owned(),
            Value::Number(FORMAT_VERSION.into()),
        ),
        (
            "out-dir-tree-sha256".to_owned(),
            Value::String(hex(&build.output.out_dir.sha256)),
        ),
        (
            "sandbox-contract-version".to_owned(),
            Value::Number(1_u64.into()),
        ),
    ]))
    .canonical_bytes()
}

fn encoded(value: &OsStr, replacements: &[(&OsStr, &[u8])]) -> Value {
    Value::String(hex(&normalize(value.as_encoded_bytes(), replacements)))
}

fn copy_tree(source: &Path, destination: &Path, tree: &Tree) -> Result<()> {
    fs::create_dir(destination).map_err(|error| {
        Error::failure(format!(
            "failed to create cached build output `{}`: {error}",
            destination.display()
        ))
    })?;
    for entry in &tree.entries {
        let relative = entry
            .path
            .split('/')
            .fold(PathBuf::new(), |mut path, part| {
                path.push(part);
                path
            });
        let from = source.join(&relative);
        let to = destination.join(&relative);
        match entry.kind {
            EntryKind::Directory => fs::create_dir(&to).map_err(|error| {
                Error::failure(format!(
                    "failed to create cached build-output directory `{}`: {error}",
                    to.display()
                ))
            })?,
            EntryKind::File => copy_synced_file(&from, &to)?,
        }
    }
    Ok(())
}

fn copy_new_file(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        return Err(Error::failure(format!(
            "refusing to replace output while restoring cache entry `{}`",
            destination.display()
        )));
    }
    copy_synced_file(source, destination)
}

fn copy_synced_file(source: &Path, destination: &Path) -> Result<()> {
    fs::copy(source, destination).map_err(|error| {
        Error::failure(format!(
            "failed to copy cache payload `{}` to `{}`: {error}",
            source.display(),
            destination.display()
        ))
    })?;
    File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            Error::failure(format!(
                "failed to persist cache payload `{}`: {error}",
                destination.display()
            ))
        })
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(path).map_err(|error| {
        Error::failure(format!(
            "failed to create cache manifest `{}`: {error}",
            path.display()
        ))
    })?;
    file.write_all(bytes).map_err(|error| {
        Error::failure(format!(
            "failed to write cache manifest `{}`: {error}",
            path.display()
        ))
    })?;
    file.sync_all().map_err(|error| {
        Error::failure(format!(
            "failed to persist cache manifest `{}`: {error}",
            path.display()
        ))
    })
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.finish()
}

fn external_inputs_digest(dep_info: &Path, inputs: SelectedInputs<'_>) -> Result<[u8; 32]> {
    let root = fs::canonicalize(inputs.package_root).map_err(|error| {
        Error::failure(format!(
            "failed to resolve package root `{}`: {error}",
            inputs.package_root.display()
        ))
    })?;
    let parsed = crate::executor::read_dep_info(dep_info, "rustc dep-info input", |source| {
        inputs
            .source_remap
            .and_then(|remap| remap.restore_physical_path(&source))
            .unwrap_or_else(|| inputs.working_dir.join(source))
    })?;
    let mut external = BTreeMap::new();
    for (path, resolved) in parsed.inputs {
        if !resolved.starts_with(&root) {
            external.insert(path, resolved);
        }
    }
    let mut digest = KeyDigest::new();
    digest.bytes("schema", b"external-dep-info-v1");
    for (path, resolved) in external {
        digest.os("source-path", path.as_os_str(), &[]);
        digest.os("resolved-path", resolved.as_os_str(), &[]);
        digest.file_contents("source-contents", &resolved)?;
    }
    Ok(digest.finish())
}

struct KeyDigest(FieldDigest);

impl KeyDigest {
    fn new() -> Self {
        Self(FieldDigest::new())
    }

    fn bytes(&mut self, name: &str, value: &[u8]) {
        self.0.bytes(name, value);
    }

    fn string(&mut self, name: &str, value: &str) {
        self.bytes(name, value.as_bytes());
    }

    fn os(&mut self, name: &str, value: &OsStr, replacements: &[(&OsStr, &[u8])]) {
        let normalized = normalize(value.as_encoded_bytes(), replacements);
        self.bytes(name, &normalized);
    }

    fn file(&mut self, name: &str, path: &Path) -> Result<()> {
        self.os(&format!("{name}-path"), path.as_os_str(), &[]);
        self.file_contents(name, path)
    }

    fn file_contents(&mut self, name: &str, path: &Path) -> Result<()> {
        self.bytes(name, &sha256_file(path)?);
        Ok(())
    }

    fn metadata(&mut self, name: &str, path: &Path) -> Result<()> {
        self.0.metadata(name, path)
    }

    fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

fn normalize(value: &[u8], replacements: &[(&OsStr, &[u8])]) -> Vec<u8> {
    let replacements = replacements
        .iter()
        .map(|(from, to)| (from.as_encoded_bytes(), *to))
        .filter(|(from, _)| !from.is_empty())
        .collect::<Vec<_>>();
    let mut output = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if let Some((from, to)) = replacements
            .iter()
            .find(|(from, _)| value[index..].starts_with(from))
        {
            output.extend_from_slice(to);
            index += from.len();
        } else {
            output.push(value[index]);
            index += 1;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "lorry-cache-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn output(root: &Path, contents: &[u8]) -> RustcOutput {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("library.rlib"), contents).unwrap();
        fs::write(root.join("library.rmeta"), b"metadata").unwrap();
        RustcOutput::Library {
            rlib: root.join("library.rlib"),
            rmeta: root.join("library.rmeta"),
            archive: None,
            dep_info: root.join("library.d"),
        }
    }

    fn generated_build_output(profile: &Path) -> (BuildScriptOutput, BTreeMap<String, OsString>) {
        let out_dir = profile.join("build/package-hash/out");
        fs::create_dir_all(&out_dir).unwrap();
        fs::write(out_dir.join("generated.rs"), b"generated").unwrap();
        let output = BuildScriptOutput {
            directives: vec![Directive::RustcLinkSearch {
                kind: Some("native".to_owned()),
                path: out_dir.clone(),
            }],
            diagnostics: Vec::new(),
            stderr: String::new(),
            out_dir: Tree::scan(
                &out_dir,
                crate::source_tree::DEFAULT_LIMITS,
                Exclusions::None,
            )
            .unwrap(),
        };
        let environment = BTreeMap::from([
            ("CARGO".to_owned(), OsString::from("/devtools/bin/lorry")),
            ("OUT_DIR".to_owned(), out_dir.into_os_string()),
            (
                "LD_LIBRARY_PATH".to_owned(),
                profile.join("deps").into_os_string(),
            ),
        ]);
        (output, environment)
    }

    #[test]
    fn archive_outputs_restore_and_participate_in_unit_freshness() {
        for validation in [ValidationMode::Trusted, ValidationMode::Strict] {
            let fixture = Fixture::new();
            let cache = BuildCache::for_test_with_validation(&fixture.0.join("cache"), validation);
            let key = CacheKey([27; 32]);
            let mut built = output(&fixture.0.join("built/deps"), b"library");
            let archive = fixture.0.join("built/deps/library.a");
            fs::write(&archive, b"archive").unwrap();
            let RustcOutput::Library { archive: extra, .. } = &mut built else {
                unreachable!()
            };
            *extra = Some(archive);
            cache
                .store(key, &built, None, None, (b"", b""), &Tracked::new())
                .unwrap();
            let target = fixture.0.join("restored/deps");
            fs::create_dir_all(&target).unwrap();
            let restored = RustcOutput::Library {
                rlib: target.join("library.rlib"),
                rmeta: target.join("library.rmeta"),
                archive: Some(target.join("library.a")),
                dep_info: target.join("library.d"),
            };
            assert!(cache.restore(key, &restored, None).unwrap().is_some());
            assert_eq!(
                fs::read(archive_path(&restored).unwrap()).unwrap(),
                b"archive"
            );
            let package = crate::resolver::PackageKey {
                name: "library".into(),
                version: "1.0.0".parse().unwrap(),
                source: crate::resolver::PackageSourceKey::Path(fixture.0.join("source")),
            };
            cache
                .record_published(key, &restored, None, &package, (b"", b""), &Tracked::new())
                .unwrap();
            assert!(
                cache
                    .published_fresh(key, &restored, None, &package)
                    .unwrap()
                    .is_some()
            );
            fs::remove_file(archive_path(&restored).unwrap()).unwrap();
            assert!(
                cache
                    .published_fresh(key, &restored, None, &package)
                    .unwrap()
                    .is_none()
            );
            fs::remove_file(cache.entry_path(key).join("payload/library.a")).unwrap();
            assert!(cache.restore(key, &restored, None).unwrap().is_none());
            assert!(!cache.entry_path(key).exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn trusted_archive_restore_rejects_payload_symlinks() {
        let fixture = Fixture::new();
        let cache =
            BuildCache::for_test_with_validation(&fixture.0.join("cache"), ValidationMode::Trusted);
        let key = CacheKey([28; 32]);
        let mut built = output(&fixture.0.join("built"), b"library");
        let archive = fixture.0.join("built/library.a");
        fs::write(&archive, b"archive").unwrap();
        let RustcOutput::Library { archive: extra, .. } = &mut built else {
            unreachable!()
        };
        *extra = Some(archive.clone());
        cache
            .store(key, &built, None, None, (b"", b""), &Tracked::new())
            .unwrap();
        let cached = cache.entry_path(key).join("payload/library.a");
        fs::remove_file(&cached).unwrap();
        std::os::unix::fs::symlink(archive, cached).unwrap();
        assert!(cache.restore(key, &built, None).unwrap().is_none());
        assert!(!cache.entry_path(key).exists());
    }

    #[test]
    fn stores_restores_and_verifies_library_payloads() {
        let fixture = Fixture::new();
        let cache = BuildCache::for_test(&fixture.0.join("cache"));
        let key = CacheKey([9; 32]);
        let built = output(&fixture.0.join("built"), b"library");
        let warning = b"{\"message\":\"unused variable\",\"rendered\":\"warning\\n\"}\n";
        cache
            .store(key, &built, None, None, (b"", warning), &Tracked::new())
            .unwrap();
        let package = crate::resolver::PackageKey {
            name: "library".to_owned(),
            version: "1.0.0".parse().unwrap(),
            source: crate::resolver::PackageSourceKey::Path(fixture.0.join("library")),
        };
        cache.record_cache_owner(key, &package).unwrap();
        assert!(artifact_owner::matches(&cache.entry_path(key), &package));

        let restored_root = fixture.0.join("restored");
        fs::create_dir(&restored_root).unwrap();
        let restored = RustcOutput::Library {
            rlib: restored_root.join("restored.rlib"),
            rmeta: restored_root.join("restored.rmeta"),
            archive: None,
            dep_info: restored_root.join("restored.d"),
        };
        let Restored { stdout, stderr, .. } = cache.restore(key, &restored, None).unwrap().unwrap();
        assert!(stdout.is_empty());
        assert_eq!(stderr, warning);
        let (rlib, rmeta) = library_paths(&restored).unwrap();
        assert_eq!(fs::read(rlib).unwrap(), b"library");
        assert_eq!(fs::read(rmeta).unwrap(), b"metadata");
        assert!(!restored_root.join("restored.d").exists());
    }

    #[test]
    fn restores_only_when_tracked_variables_match_and_replaces_stale_entries() {
        let fixture = Fixture::new();
        let cache = BuildCache::for_test(&fixture.0.join("cache"));
        let key = CacheKey([10; 32]);
        let path = std::env::var("PATH").unwrap();
        let stale = Tracked::from([("PATH".to_owned(), Some("/nowhere".to_owned()))]);
        let current = Tracked::from([("PATH".to_owned(), Some(path))]);
        let restore = |name: &str| {
            let root = fixture.0.join(name);
            fs::create_dir(&root).unwrap();
            let output = output(&root, b"unused");
            fs::remove_file(root.join("library.rlib")).unwrap();
            fs::remove_file(root.join("library.rmeta")).unwrap();
            cache.restore(key, &output, None).unwrap()
        };

        let built = output(&fixture.0.join("old"), b"old");
        cache
            .store(key, &built, None, None, (b"", b""), &stale)
            .unwrap();
        assert!(restore("miss").is_none());

        let built = output(&fixture.0.join("new"), b"new");
        cache
            .store(key, &built, None, None, (b"", b""), &current)
            .unwrap();
        let restored = restore("hit").unwrap();
        assert_eq!(restored.tracked, current);
        assert_eq!(
            fs::read(fixture.0.join("hit/library.rlib")).unwrap(),
            b"new"
        );

        let identity =
            |tracked: &Tracked| cache.dependency_key(key, &built, None, tracked).unwrap();
        assert_eq!(identity(&Tracked::new()), key);
        assert_ne!(identity(&current), key);
        assert_ne!(identity(&current), identity(&stale));
    }

    #[test]
    fn selected_library_cache_restores_rustc_dep_info() {
        let fixture = Fixture::new();
        let cache = BuildCache::for_test(&fixture.0.join("cache"));
        let key = CacheKey([10; 32]);
        let built = output(&fixture.0.join("built"), b"library");
        let source = fixture.0.join("package");
        fs::create_dir_all(source.join("src")).unwrap();
        fs::write(source.join("src/lib.rs"), b"pub fn value() {}\n").unwrap();
        let inputs = SelectedInputs {
            package_root: &source,
            working_dir: &source,
            source_remap: None,
        };
        let dep_info = built.dep_info();
        fs::write(dep_info, b"library.rlib: src/lib.rs\n").unwrap();
        cache
            .store(key, &built, None, Some(inputs), (b"", b""), &Tracked::new())
            .unwrap();

        let restored_root = fixture.0.join("restored");
        fs::create_dir(&restored_root).unwrap();
        let restored = RustcOutput::Library {
            rlib: restored_root.join("library.rlib"),
            rmeta: restored_root.join("library.rmeta"),
            archive: None,
            dep_info: restored_root.join("library.d"),
        };
        assert!(
            cache
                .restore(key, &restored, Some(inputs))
                .unwrap()
                .is_some()
        );
        cache
            .store(key, &built, None, Some(inputs), (b"", b""), &Tracked::new())
            .unwrap();
        assert_eq!(
            fs::read(restored_root.join("library.d")).unwrap(),
            b"library.rlib: src/lib.rs\n"
        );
    }

    #[test]
    fn selected_cache_replaces_entry_when_external_dep_info_input_changes() {
        let fixture = Fixture::new();
        let cache = BuildCache::for_test(&fixture.0.join("cache"));
        let key = CacheKey([11; 32]);
        let source = fixture.0.join("package");
        fs::create_dir(&source).unwrap();
        let external = fixture.0.join("shared.rs");
        fs::write(&external, b"first").unwrap();
        let inputs = SelectedInputs {
            package_root: &source,
            working_dir: &source,
            source_remap: None,
        };
        let built = output(&fixture.0.join("built"), b"old library");
        fs::write(
            built.dep_info(),
            format!("library.rlib: {}\n", external.display()),
        )
        .unwrap();
        cache
            .store(key, &built, None, Some(inputs), (b"", b""), &Tracked::new())
            .unwrap();

        let restored_root = fixture.0.join("restored");
        fs::create_dir(&restored_root).unwrap();
        let restored = RustcOutput::Library {
            rlib: restored_root.join("library.rlib"),
            rmeta: restored_root.join("library.rmeta"),
            archive: None,
            dep_info: restored_root.join("library.d"),
        };
        assert!(
            cache
                .restore(key, &restored, Some(inputs))
                .unwrap()
                .is_some()
        );
        fs::remove_file(restored_root.join("library.rlib")).unwrap();
        fs::remove_file(restored_root.join("library.rmeta")).unwrap();
        fs::remove_file(restored_root.join("library.d")).unwrap();

        fs::write(&external, b"second").unwrap();
        assert!(
            !cache
                .restore(key, &restored, Some(inputs))
                .unwrap()
                .is_some()
        );
        fs::write(library_paths(&built).unwrap().0, b"new library").unwrap();
        cache
            .store(key, &built, None, Some(inputs), (b"", b""), &Tracked::new())
            .unwrap();
        assert!(
            cache
                .restore(key, &restored, Some(inputs))
                .unwrap()
                .is_some()
        );
        assert_eq!(
            fs::read(library_paths(&restored).unwrap().0).unwrap(),
            b"new library"
        );

        fs::remove_file(&external).unwrap();
        assert!(
            !cache
                .restore(key, &restored, Some(inputs))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn published_selected_unit_checks_artifact_and_external_inputs() {
        let fixture = Fixture::new();
        let cache = BuildCache::for_test(&fixture.0.join("cache"));
        let key = CacheKey([12; 32]);
        let source = fixture.0.join("package");
        fs::create_dir(&source).unwrap();
        let external = fixture.0.join("shared.rs");
        fs::write(&external, b"first").unwrap();
        let output = output(&fixture.0.join("unit/deps"), b"library");
        fs::write(
            output.dep_info(),
            format!("library.rlib: {}\n", external.display()),
        )
        .unwrap();
        let inputs = SelectedInputs {
            package_root: &source,
            working_dir: &source,
            source_remap: None,
        };
        let package = crate::resolver::PackageKey {
            name: "app".to_owned(),
            version: "1.0.0".parse().unwrap(),
            source: crate::resolver::PackageSourceKey::Path(source.clone()),
        };

        assert!(
            cache
                .published_fresh(key, &output, Some(inputs), &package)
                .unwrap()
                .is_none()
        );
        cache
            .record_published(
                key,
                &output,
                Some(inputs),
                &package,
                (b"", b""),
                &Tracked::new(),
            )
            .unwrap();
        assert!(
            cache
                .published_fresh(key, &output, Some(inputs), &package)
                .unwrap()
                .is_some()
        );
        let identity = || {
            cache
                .dependency_key(key, &output, Some(inputs), &Tracked::new())
                .unwrap()
        };
        let first = identity();
        fs::write(&external, b"second").unwrap();
        assert!(
            cache
                .published_fresh(key, &output, Some(inputs), &package)
                .unwrap()
                .is_none()
        );
        // Dependents must rebuild when a selected unit's external input changes.
        assert_ne!(identity(), first);
        fs::write(&external, b"first").unwrap();
        assert_eq!(identity(), first);
        fs::write(library_paths(&output).unwrap().0, b"tampered").unwrap();
        assert!(
            cache
                .published_fresh(key, &output, Some(inputs), &package)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn published_check_replays_and_validates_compiler_messages() {
        let fixture = Fixture::new();
        let cache = BuildCache::for_test(&fixture.0.join("cache"));
        let output = output(&fixture.0.join("unit/deps"), b"library");
        let key = CacheKey([14; 32]);
        let package = crate::resolver::PackageKey {
            name: "app".to_owned(),
            version: "1.0.0".parse().unwrap(),
            source: crate::resolver::PackageSourceKey::Path(fixture.0.clone()),
        };
        let warning = b"{\"message\":\"warning marker\"}\n";
        assert!(
            cache
                .published_fresh(key, &output, None, &package)
                .unwrap()
                .is_none()
        );
        cache
            .record_published(
                key,
                &output,
                None,
                &package,
                (warning, b""),
                &Tracked::new(),
            )
            .unwrap();
        assert!(
            cache
                .published_fresh(key, &output, None, &package)
                .unwrap()
                .is_some()
        );
        assert_eq!(cache.published_messages(&output).unwrap().0, warning);
        fs::write(fixture.0.join("unit").join(PUBLISHED_STDOUT), b"changed").unwrap();
        assert!(
            cache
                .published_fresh(key, &output, None, &package)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn external_dep_info_digest_detects_symlink_retarget() {
        let fixture = Fixture::new();
        let source = fixture.0.join("package");
        fs::create_dir(&source).unwrap();
        let first = fixture.0.join("first.rs");
        let second = fixture.0.join("second.rs");
        fs::write(&first, b"same contents").unwrap();
        fs::write(&second, b"same contents").unwrap();
        let link = fixture.0.join("shared.rs");
        std::os::unix::fs::symlink(&first, &link).unwrap();
        let dep_info = fixture.0.join("library.d");
        fs::write(&dep_info, format!("library.rlib: {}\n", link.display())).unwrap();
        let inputs = SelectedInputs {
            package_root: &source,
            working_dir: &source,
            source_remap: None,
        };
        let previous = external_inputs_digest(&dep_info, inputs).unwrap();
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&second, &link).unwrap();
        assert_ne!(previous, external_inputs_digest(&dep_info, inputs).unwrap());
    }

    #[test]
    fn link_arguments_bind_cached_outputs_in_emission_order() {
        let fixture = Fixture::new();
        let profile = fixture.0.join("profile");
        let (mut output, environment) = generated_build_output(&profile);
        output.directives.extend([
            Directive::RustcLinkArg("-Wl,--gc-sections".to_owned()),
            Directive::RustcLinkArg("-Wl,--as-needed".to_owned()),
        ]);
        let out_dir = profile.join("build/package-hash/out");
        let temp_dir = profile.join("build/package-hash/tmp");
        let record = |output: &BuildScriptOutput| {
            build_script_manifest(&BuildScriptInput {
                output,
                environment: &environment,
                executable_sha256: [6; 32],
                out_dir: &out_dir,
                temp_dir: &temp_dir,
            })
        };
        let digest = |output: &BuildScriptOutput| {
            let mut digest = KeyDigest::new();
            directive_digest(&mut digest, &output.directives, &[]);
            digest.finish()
        };
        let original_record = record(&output);
        let original_digest = digest(&output);
        output.directives.swap(1, 2);
        assert_ne!(original_record, record(&output));
        assert_ne!(original_digest, digest(&output));
        output.directives[1] = Directive::RustcLinkArg("-s".to_owned());
        assert_ne!(original_record, record(&output));
        assert_ne!(original_digest, digest(&output));
    }

    #[test]
    fn stores_build_script_results_without_staging_path_identity() {
        let fixture = Fixture::new();
        let cache = BuildCache::for_test(&fixture.0.join("cache"));
        let key = CacheKey([8; 32]);
        let built = output(&fixture.0.join("built"), b"library");
        let first_profile = fixture.0.join(".profile-a");
        let second_profile = fixture.0.join(".profile-b");
        let (first_output, first_environment) = generated_build_output(&first_profile);
        let (second_output, second_environment) = generated_build_output(&second_profile);
        let first_out = first_profile.join("build/package-hash/out");
        let first_temp = first_profile.join("build/package-hash/tmp");
        let second_out = second_profile.join("build/package-hash/out");
        let second_temp = second_profile.join("build/package-hash/tmp");
        let first = BuildScriptInput {
            output: &first_output,
            environment: &first_environment,
            executable_sha256: [6; 32],
            out_dir: &first_out,
            temp_dir: &first_temp,
        };
        let second = BuildScriptInput {
            output: &second_output,
            environment: &second_environment,
            executable_sha256: [6; 32],
            out_dir: &second_out,
            temp_dir: &second_temp,
        };
        assert_eq!(
            build_script_manifest(&first),
            build_script_manifest(&second)
        );

        cache
            .store(key, &built, Some(&first), None, (b"", b""), &Tracked::new())
            .unwrap();
        let payload = cache.entry_path(key).join("payload");
        assert_eq!(
            fs::read(payload.join("build-output/generated.rs")).unwrap(),
            b"generated"
        );
        assert!(payload.join("build-script.json").is_file());
    }

    #[test]
    fn corrupt_entries_are_quarantined_and_rebuilt() {
        let fixture = Fixture::new();
        let cache = BuildCache::for_test(&fixture.0.join("cache"));
        let key = CacheKey([7; 32]);
        let built = output(&fixture.0.join("built"), b"good");
        cache
            .store(key, &built, None, None, (b"", b""), &Tracked::new())
            .unwrap();
        fs::write(cache.entry_path(key).join("payload/library.rlib"), b"bad").unwrap();

        let restore = RustcOutput::Library {
            rlib: fixture.0.join("miss.rlib"),
            rmeta: fixture.0.join("miss.rmeta"),
            archive: None,
            dep_info: fixture.0.join("miss.d"),
        };
        assert!(!cache.restore(key, &restore, None).unwrap().is_some());
        assert_eq!(fs::read_dir(&cache.quarantine).unwrap().count(), 1);
        cache
            .store(key, &built, None, None, (b"", b""), &Tracked::new())
            .unwrap();
        assert!(cache.entry_path(key).is_dir());
    }

    #[test]
    fn ordinary_restore_trusts_an_atomically_published_payload() {
        let fixture = Fixture::new();
        let cache =
            BuildCache::for_test_with_validation(&fixture.0.join("cache"), ValidationMode::Trusted);
        let key = CacheKey([6; 32]);
        let built = output(&fixture.0.join("built"), b"original");
        cache
            .store(key, &built, None, None, (b"", b""), &Tracked::new())
            .unwrap();
        fs::write(
            cache.entry_path(key).join("payload/library.rlib"),
            b"changed",
        )
        .unwrap();

        let restored = RustcOutput::Library {
            rlib: fixture.0.join("restored.rlib"),
            rmeta: fixture.0.join("restored.rmeta"),
            archive: None,
            dep_info: fixture.0.join("restored.d"),
        };
        assert!(cache.restore(key, &restored, None).unwrap().is_some());
        assert_eq!(
            fs::read(library_paths(&restored).unwrap().0).unwrap(),
            b"changed"
        );
        assert!(!cache.quarantine.exists());
    }

    #[test]
    fn ordinary_path_identity_uses_size_and_mtime_not_contents() {
        let fixture = Fixture::new();
        let source = fixture.0.join("source");
        fs::create_dir(&source).unwrap();
        let file = source.join("lib.rs");
        fs::write(&file, b"first").unwrap();
        let modified = fs::metadata(&file).unwrap().modified().unwrap();
        let fingerprint = || {
            let mut digest = KeyDigest::new();
            metadata_tree_digest(
                &mut digest,
                &source,
                crate::source_tree::DEFAULT_LIMITS,
                Exclusions::GitAndTarget,
            )
            .unwrap();
            digest.finish()
        };
        let original = fingerprint();

        fs::write(&file, b"other").unwrap();
        File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert_eq!(fingerprint(), original);

        fs::write(file, b"longer").unwrap();
        assert_ne!(fingerprint(), original);
    }

    #[test]
    fn incomplete_sibling_staging_is_not_a_hit() {
        let fixture = Fixture::new();
        let cache = BuildCache::for_test(&fixture.0.join("cache"));
        let key = CacheKey([5; 32]);
        let parent = cache.entry_path(key).parent().unwrap().to_owned();
        let partial = AtomicDirectory::new(&parent, &hex(&key.0)).unwrap();
        fs::write(partial.path().join("partial"), b"partial").unwrap();
        let restore = RustcOutput::Library {
            rlib: fixture.0.join("miss.rlib"),
            rmeta: fixture.0.join("miss.rmeta"),
            archive: None,
            dep_info: fixture.0.join("miss.d"),
        };
        assert!(!cache.restore(key, &restore, None).unwrap().is_some());
    }

    #[test]
    fn concurrent_identical_writers_accept_the_first_entry() {
        let fixture = Fixture::new();
        let cache = Arc::new(BuildCache::for_test(&fixture.0.join("cache")));
        let key = CacheKey([4; 32]);
        let first = output(&fixture.0.join("first"), b"same");
        let second = output(&fixture.0.join("second"), b"same");
        let barrier = Arc::new(Barrier::new(2));
        let writers = [first, second]
            .into_iter()
            .map(|output| {
                let cache = cache.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    cache
                        .store(key, &output, None, None, (b"", b""), &Tracked::new())
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(
            fs::read_dir(cache.entry_path(key).parent().unwrap())
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn path_normalization_removes_unpredictable_staging_roots() {
        let first = normalize(
            b"dependency=/tmp/.debug.lorry-staging-a/deps",
            &[(OsStr::new("/tmp/.debug.lorry-staging-a"), b"<profile>")],
        );
        let second = normalize(
            b"dependency=/tmp/.debug.lorry-staging-b/deps",
            &[(OsStr::new("/tmp/.debug.lorry-staging-b"), b"<profile>")],
        );
        assert_eq!(first, second);
    }

    #[test]
    fn routes_immutable_units_to_the_per_user_cache() {
        assert!(globally_cacheable_source(&PackageSourceKey::CratesIo));
        assert!(globally_cacheable_source(&PackageSourceKey::Git(
            "git+https://example.invalid/demo#commit".to_owned()
        )));
        assert!(!globally_cacheable_source(&PackageSourceKey::Path(
            PathBuf::from("local")
        )));
    }

    #[test]
    fn shared_arguments_ignore_workspace_and_diagnostic_verbosity() {
        let identity = |arguments: &[&str], workspace: &str| {
            let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
            let mut digest = KeyDigest::new();
            rustc_arguments_digest(
                &mut digest,
                &arguments,
                &[(OsStr::new(workspace), b"<workspace-root>")],
            )
            .unwrap();
            digest.finish()
        };
        let first = identity(
            &["--out-dir", "/work/one/target/deps", "--cap-lints", "allow"],
            "/work/one",
        );
        let second = identity(
            &[
                "--out-dir",
                "/work/two/target/deps",
                "--cap-lints",
                "warn",
                "--verbose",
            ],
            "/work/two",
        );
        assert_eq!(first, second);

        let mut digest = KeyDigest::new();
        assert!(rustc_arguments_digest(&mut digest, &["--cap-lints".into()], &[]).is_err());
    }
}
