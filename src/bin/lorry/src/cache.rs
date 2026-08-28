use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::atomic::AtomicDirectory;
use crate::build_script::{Directive, Output as BuildScriptOutput};
use crate::compile::{RustcInvocation, RustcOutput};
use crate::config::CargoCompat;
use crate::diagnostic::{Error, Result};
use crate::hash::{Sha256, hex, sha256_file};
use crate::json::Value;
use crate::manifest::Manifest;
use crate::process;
use crate::resolver::{CompileKind, PackageSourceKey};
use crate::source_tree::{EntryKind, Exclusions, Limits as TreeLimits, Tree};
use crate::toolchain::{TargetInfo, Toolchain};
use crate::unit::{PlannedUnit, UnitKey, UnitKind};
use crate::validation::ValidationMode;

const FORMAT_VERSION: u64 = 1;
const KEY_TAG: &[u8] = b"lorry-unit-cache-key-v1\0";

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
    pub planned: &'a PlannedUnit,
    pub manifest: &'a Manifest,
    pub invocation: &'a RustcInvocation,
    pub host_profile: &'a Path,
    pub target_profile: &'a Path,
    pub dependencies: &'a [DependencyInput<'a>],
    pub build_script: Option<BuildScriptInput<'a>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheKey([u8; 32]);

pub struct BuildCache {
    units: PathBuf,
    quarantine: PathBuf,
    cargo: PathBuf,
    workspace_root: PathBuf,
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
            base: digest.finish(),
            source_limits: options.source_limits,
            payload_limits,
            validation: options.validation,
        })
    }

    pub fn key(&self, input: &UnitInput<'_>) -> Result<CacheKey> {
        if !matches!(input.key.kind, UnitKind::Library | UnitKind::ProcMacro) {
            return Err(Error::failure(
                "only library and proc-macro units have build-cache keys",
            ));
        }
        let mut digest = KeyDigest::new();
        digest.bytes("base", &self.base);
        digest.string("package-name", &input.key.package.name);
        digest.string("package-version", &input.key.package.version.to_string());
        digest.string(
            "unit-kind",
            if input.key.kind == UnitKind::ProcMacro {
                "proc-macro"
            } else {
                "library"
            },
        );
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
        let mut environment = std::env::vars_os().collect::<BTreeMap<_, _>>();
        for (name, value) in &input.invocation.environment {
            environment.insert(name.into(), value.clone());
        }
        for (name, value) in &environment {
            digest.os("rustc-environment-name", name, &replacements);
            digest.os("rustc-environment-value", value, &replacements);
        }

        if self.validation.is_strict() {
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

    pub fn restore(&self, key: CacheKey, output: &RustcOutput) -> Result<bool> {
        let Some(entry) = self.verified_or_quarantine(key)? else {
            return Ok(false);
        };
        let (rlib, rmeta) = library_paths(output)?;
        copy_new_file(&entry.payload.join("library.rlib"), rlib)?;
        if rmeta != rlib {
            copy_new_file(&entry.payload.join("library.rmeta"), rmeta)?;
        }
        Ok(true)
    }

    pub fn store(
        &self,
        key: CacheKey,
        output: &RustcOutput,
        build_script: Option<&BuildScriptInput<'_>>,
    ) -> Result<()> {
        let (rlib, rmeta) = library_paths(output)?;
        let destination = self.entry_path(key);
        if let Some(existing) = self.verified_or_quarantine(key)? {
            if !self.validation.is_strict() {
                return Ok(());
            }
            let wanted = payload_manifest(rlib, rmeta, build_script, self.payload_limits)?;
            if existing.payload_manifest == wanted {
                return Ok(());
            }
            return Err(Error::failure(format!(
                "concurrent cache writers produced different verified outputs for `{}`",
                hex(&key.0)
            )));
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
        if names != ["manifest.json", "payload", "payload-manifest.json"] {
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
        for required in ["library.rlib", "library.rmeta"] {
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
    globally_cacheable_source(&planned.unit.key.package.source, planned.source_exclusions)
}

fn globally_cacheable_source(source: &PackageSourceKey, exclusions: Exclusions) -> bool {
    match source {
        PackageSourceKey::CratesIo | PackageSourceKey::Git(_) => true,
        PackageSourceKey::Path(_) => exclusions == Exclusions::None,
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
    let output = process::query(
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
                let modified = metadata.modified().map_err(|error| {
                    Error::failure(format!(
                        "failed to read modification time for `{}`: {error}",
                        path.display()
                    ))
                })?;
                let modified = modified.duration_since(UNIX_EPOCH).map_err(|_| {
                    Error::failure(format!(
                        "modification time for `{}` predates the Unix epoch",
                        path.display()
                    ))
                })?;
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

fn library_paths(output: &RustcOutput) -> Result<(&Path, &Path)> {
    match output {
        RustcOutput::Library { rlib, rmeta, .. } => Ok((rlib, rmeta)),
        RustcOutput::ProcMacro {
            dynamic_library, ..
        } => Ok((dynamic_library, dynamic_library)),
        RustcOutput::BuildScript { .. } => Err(Error::failure(
            "build-script executables cannot be stored in the unit cache",
        )),
    }
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
    rlib: &Path,
    rmeta: &Path,
    build_script: Option<&BuildScriptInput<'_>>,
    limits: TreeLimits,
) -> Result<Vec<u8>> {
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

struct KeyDigest(Sha256);

impl KeyDigest {
    fn new() -> Self {
        Self(Sha256::new())
    }

    fn bytes(&mut self, name: &str, value: &[u8]) {
        self.field(name.as_bytes());
        self.field(value);
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
        let metadata = fs::metadata(path).map_err(|error| {
            Error::failure(format!("failed to inspect `{}`: {error}", path.display()))
        })?;
        let modified = metadata.modified().map_err(|error| {
            Error::failure(format!(
                "failed to read modification time for `{}`: {error}",
                path.display()
            ))
        })?;
        let modified = modified.duration_since(UNIX_EPOCH).map_err(|_| {
            Error::failure(format!(
                "modification time for `{}` predates the Unix epoch",
                path.display()
            ))
        })?;
        self.os(&format!("{name}-path"), path.as_os_str(), &[]);
        self.bytes(&format!("{name}-length"), &metadata.len().to_le_bytes());
        self.bytes(
            &format!("{name}-mtime-secs"),
            &modified.as_secs().to_le_bytes(),
        );
        self.bytes(
            &format!("{name}-mtime-nanos"),
            &modified.subsec_nanos().to_le_bytes(),
        );
        Ok(())
    }

    fn field(&mut self, value: &[u8]) {
        self.0.update(&(value.len() as u64).to_le_bytes());
        self.0.update(value);
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
    fn stores_restores_and_verifies_library_payloads() {
        let fixture = Fixture::new();
        let cache = BuildCache::for_test(&fixture.0.join("cache"));
        let key = CacheKey([9; 32]);
        let built = output(&fixture.0.join("built"), b"library");
        cache.store(key, &built, None).unwrap();

        let restored_root = fixture.0.join("restored");
        fs::create_dir(&restored_root).unwrap();
        let restored = RustcOutput::Library {
            rlib: restored_root.join("restored.rlib"),
            rmeta: restored_root.join("restored.rmeta"),
            dep_info: restored_root.join("restored.d"),
        };
        assert!(cache.restore(key, &restored).unwrap());
        let (rlib, rmeta) = library_paths(&restored).unwrap();
        assert_eq!(fs::read(rlib).unwrap(), b"library");
        assert_eq!(fs::read(rmeta).unwrap(), b"metadata");
        assert!(!restored_root.join("restored.d").exists());
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

        cache.store(key, &built, Some(&first)).unwrap();
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
        cache.store(key, &built, None).unwrap();
        fs::write(cache.entry_path(key).join("payload/library.rlib"), b"bad").unwrap();

        let restore = RustcOutput::Library {
            rlib: fixture.0.join("miss.rlib"),
            rmeta: fixture.0.join("miss.rmeta"),
            dep_info: fixture.0.join("miss.d"),
        };
        assert!(!cache.restore(key, &restore).unwrap());
        assert_eq!(fs::read_dir(&cache.quarantine).unwrap().count(), 1);
        cache.store(key, &built, None).unwrap();
        assert!(cache.entry_path(key).is_dir());
    }

    #[test]
    fn ordinary_restore_trusts_an_atomically_published_payload() {
        let fixture = Fixture::new();
        let cache =
            BuildCache::for_test_with_validation(&fixture.0.join("cache"), ValidationMode::Trusted);
        let key = CacheKey([6; 32]);
        let built = output(&fixture.0.join("built"), b"original");
        cache.store(key, &built, None).unwrap();
        fs::write(
            cache.entry_path(key).join("payload/library.rlib"),
            b"changed",
        )
        .unwrap();

        let restored = RustcOutput::Library {
            rlib: fixture.0.join("restored.rlib"),
            rmeta: fixture.0.join("restored.rmeta"),
            dep_info: fixture.0.join("restored.d"),
        };
        assert!(cache.restore(key, &restored).unwrap());
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
            dep_info: fixture.0.join("miss.d"),
        };
        assert!(!cache.restore(key, &restore).unwrap());
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
                    cache.store(key, &output, None).unwrap();
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
        assert!(globally_cacheable_source(
            &PackageSourceKey::CratesIo,
            Exclusions::CargoRegistryMarker
        ));
        assert!(globally_cacheable_source(
            &PackageSourceKey::Path(PathBuf::from("reviewed-patch")),
            Exclusions::None
        ));
        assert!(!globally_cacheable_source(
            &PackageSourceKey::Path(PathBuf::from("local")),
            Exclusions::GitAndTarget
        ));
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
