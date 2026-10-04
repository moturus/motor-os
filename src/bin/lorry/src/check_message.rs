use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{Value, json};

use crate::build_script::{Directive, Output as BuildScriptOutput};
use crate::cli::MessageFormat;
use crate::compile::RustcOutput;
use crate::dependency::PreparedGraph;
use crate::diagnostic::{Error, Result};
use crate::executor::{EventReporter, ExecutedBuildScript};
use crate::identity::CargoDebugInfo;
use crate::manifest::Manifest;
use crate::metadata::package::{self, Identity};
use crate::metadata::wire;
use crate::resolver::PackageKey;
use crate::unit::{PlannedUnit, UnitKey, UnitKind, UnitMode, selected_library_key};

struct Package {
    id: String,
    manifest_path: String,
    targets: Vec<wire::Target>,
}

#[derive(Default)]
struct State {
    artifacts: BTreeSet<UnitKey>,
    build_scripts: BTreeSet<UnitKey>,
}

pub struct Reporter {
    root: Package,
    root_key: PackageKey,
    packages: BTreeMap<PackageKey, Package>,
    staging: PathBuf,
    destination: PathBuf,
    format: MessageFormat,
    color: bool,
    state: Mutex<State>,
}

impl Reporter {
    pub fn new(
        root_manifest: &Manifest,
        prepared: &PreparedGraph,
        roots: &BTreeMap<PackageKey, PathBuf>,
        staging: &Path,
        destination: &Path,
        format: MessageFormat,
        color: bool,
    ) -> Result<Self> {
        let root = Package::from_manifest(root_manifest, Identity::Root, &root_manifest.root)?;
        let mut packages = BTreeMap::new();
        for resolved in &prepared.resolution.packages {
            let manifest = &prepared.packages[&resolved.key].manifest;
            let root = roots.get(&resolved.key).ok_or_else(|| {
                Error::failure(format!(
                    "message source roots omit package `{} {}`",
                    resolved.key.name, resolved.key.version
                ))
            })?;
            packages.insert(
                resolved.key.clone(),
                Package::from_manifest(manifest, Identity::Resolved(resolved), root)?,
            );
        }
        Ok(Self {
            root,
            root_key: selected_library_key(root_manifest)?.package,
            packages,
            staging: staging.to_owned(),
            destination: destination.to_owned(),
            format,
            color,
            state: Mutex::new(State::default()),
        })
    }

    fn package(&self, key: &PackageKey) -> Result<&Package> {
        if key == &self.root_key {
            return Ok(&self.root);
        }
        self.packages.get(key).ok_or_else(|| {
            Error::failure(format!(
                "check messages omit package `{} {}`",
                key.name, key.version
            ))
        })
    }

    fn write_compiler_messages(
        &self,
        package: &Package,
        target: &wire::Target,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<()> {
        for bytes in [stdout, stderr] {
            for line in bytes.split(|byte| *byte == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if line.is_empty() {
                    continue;
                }
                let message: Value = serde_json::from_slice(line).map_err(|error| {
                    Error::failure(format!("rustc emitted a non-JSON check message: {error}"))
                })?;
                let object = message.as_object().ok_or_else(|| {
                    Error::failure("rustc emitted a non-object JSON check message")
                })?;
                if object.contains_key("artifact") || object.contains_key("unused_extern_names") {
                    continue;
                }
                let Some(text) = object.get("message").and_then(Value::as_str) else {
                    continue;
                };
                if text.starts_with("aborting due to")
                    || text.ends_with("warning emitted")
                    || text.ends_with("warnings emitted")
                {
                    continue;
                }
                self.write_value(json!({
                    "reason": "compiler-message",
                    "package_id": package.id,
                    "manifest_path": package.manifest_path,
                    "target": target,
                    "message": message,
                }))?;
            }
        }
        Ok(())
    }

    fn published_path(&self, path: &Path) -> Result<String> {
        let path = match path.strip_prefix(&self.staging) {
            Ok(relative) => self.destination.join(relative),
            Err(_) => path.to_owned(),
        };
        path.into_os_string().into_string().map_err(|path| {
            Error::failure(format!(
                "check artifact path `{}` is not valid UTF-8",
                PathBuf::from(path).display()
            ))
        })
    }

    fn write_value(&self, value: Value) -> Result<()> {
        let _state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        emit(&value, self.format, self.color)
    }
}

impl EventReporter for Reporter {
    fn compiler_messages(&self, key: &UnitKey, stdout: &[u8], stderr: &[u8]) -> Result<()> {
        let package = self.package(&key.package)?;
        let target = package.dependency_target(key.kind, key.target.as_deref())?;
        self.write_compiler_messages(package, target, stdout, stderr)
    }

    fn compiler_artifact(
        &self,
        key: &UnitKey,
        planned: &PlannedUnit,
        output: &RustcOutput,
        fresh: bool,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.artifacts.insert(key.clone()) {
            return Ok(());
        }
        let package = self.package(&key.package)?;
        let target = package.dependency_target(key.kind, key.target.as_deref())?;
        let (filenames, executable) = match output {
            RustcOutput::Library { rlib, rmeta, .. } => (
                vec![self.published_path(rlib)?, self.published_path(rmeta)?],
                None,
            ),
            RustcOutput::ProcMacro {
                dynamic_library, ..
            } => (vec![self.published_path(dynamic_library)?], None),
            RustcOutput::Binary { executable, .. } => (
                vec![self.published_path(executable)?],
                Some(self.published_path(executable)?),
            ),
            RustcOutput::Metadata { metadata, .. } => (vec![self.published_path(metadata)?], None),
            RustcOutput::BuildScript {
                executable,
                unhashed_executable,
                ..
            } => (
                vec![self.published_path(executable)?],
                Some(self.published_path(unhashed_executable)?),
            ),
        };
        emit(
            &json!({
                "reason": "compiler-artifact",
                "package_id": package.id,
                "manifest_path": package.manifest_path,
                "target": target,
                "profile": dependency_profile(planned),
                "features": key.features,
                "filenames": filenames,
                "executable": executable,
                "fresh": fresh,
            }),
            self.format,
            self.color,
        )?;
        Ok(())
    }

    fn build_script_executed(&self, key: &UnitKey, executed: &ExecutedBuildScript) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.build_scripts.insert(key.clone()) {
            return Ok(());
        }
        let package = self.package(&key.package)?;
        let output = &executed.output;
        let linked_libs = directives(output, |directive| match directive {
            Directive::RustcLinkLib(value) => Some(value.clone()),
            _ => None,
        });
        let linked_paths = output
            .directives
            .iter()
            .filter_map(|directive| match directive {
                Directive::RustcLinkSearch { kind, path } => Some((kind, path)),
                _ => None,
            })
            .map(|(kind, path)| {
                self.published_path(path).map(|path| match kind {
                    Some(kind) => format!("{kind}={path}"),
                    None => path,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let cfgs = directives(output, |directive| match directive {
            Directive::RustcCfg(value) => Some(value.clone()),
            _ => None,
        });
        let env = output
            .directives
            .iter()
            .filter_map(|directive| match directive {
                Directive::RustcEnv { name, value } => Some((name.clone(), value.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();
        emit(
            &json!({
                "reason": "build-script-executed",
                "package_id": package.id,
                "linked_libs": linked_libs,
                "linked_paths": linked_paths,
                "cfgs": cfgs,
                "env": env,
                "out_dir": self.published_path(&executed.out_dir)?,
            }),
            self.format,
            self.color,
        )?;
        Ok(())
    }
}

impl Package {
    fn from_manifest(manifest: &Manifest, identity: Identity<'_>, root: &Path) -> Result<Self> {
        Ok(Self {
            id: package::package_id(manifest, identity)?,
            manifest_path: root
                .join("Cargo.toml")
                .to_str()
                .ok_or_else(|| Error::failure("message manifest path is not Unicode"))?
                .to_owned(),
            targets: package::map_targets(manifest, root)?,
        })
    }

    fn dependency_target(&self, kind: UnitKind, name: Option<&str>) -> Result<&wire::Target> {
        self.targets
            .iter()
            .find(|target| {
                name.is_none_or(|name| target.name == name)
                    && match kind {
                        UnitKind::Library | UnitKind::ProcMacro => target
                            .kind
                            .iter()
                            .all(|kind| kind != "bin" && kind != "test" && kind != "custom-build"),
                        UnitKind::Binary | UnitKind::BinaryHarness => {
                            target.kind.iter().any(|kind| kind == "bin")
                        }
                        UnitKind::LibraryHarness => target.kind.iter().any(|kind| kind == "lib"),
                        UnitKind::IntegrationHarness => {
                            target.kind.iter().any(|kind| kind == "test")
                        }
                        UnitKind::BuildScriptCompile | UnitKind::BuildScriptRun => {
                            target.kind.iter().any(|kind| kind == "custom-build")
                        }
                    }
            })
            .ok_or_else(|| Error::failure("check metadata omits a dependency target"))
    }
}

fn dependency_profile(planned: &PlannedUnit) -> Value {
    let profile = &planned.settings.profile;
    let debuginfo = match profile.debuginfo {
        CargoDebugInfo::None => json!(0),
        CargoDebugInfo::LineDirectivesOnly => json!("line-directives-only"),
        CargoDebugInfo::LineTablesOnly => json!("line-tables-only"),
        CargoDebugInfo::Limited => json!(1),
        CargoDebugInfo::Full => json!(2),
    };
    json!({
        "opt_level": profile.opt_level,
        "debuginfo": debuginfo,
        "debug_assertions": profile.debug_assertions,
        "overflow_checks": profile.overflow_checks,
        "test": matches!(planned.unit.key.mode, UnitMode::Test | UnitMode::CheckTest),
    })
}

fn directives(
    output: &BuildScriptOutput,
    map: impl Fn(&Directive) -> Option<String>,
) -> Vec<String> {
    output.directives.iter().filter_map(map).collect()
}

pub fn build_finished(success: bool) -> Result<()> {
    write_line(&json!({"reason": "build-finished", "success": success}))
}

fn emit(value: &Value, format: MessageFormat, color: bool) -> Result<()> {
    if format == MessageFormat::Human {
        if let Some(rendered) = value
            .get("message")
            .and_then(|message| message.get("rendered"))
            .and_then(Value::as_str)
        {
            if color {
                eprint!("{rendered}");
            } else {
                eprint!("{}", crate::process::strip_ansi(rendered));
            }
        }
        return Ok(());
    }
    let mut value = value.clone();
    if format != MessageFormat::JsonDiagnosticRenderedAnsi
        && let Some(rendered) = value
            .get_mut("message")
            .and_then(|message| message.get_mut("rendered"))
        && let Some(text) = rendered.as_str()
    {
        *rendered = Value::String(crate::process::strip_ansi(text));
    }
    write_line(&value)
}

fn write_line(value: &Value) -> Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, value)
        .map_err(|error| Error::failure(format!("failed to serialize check message: {error}")))?;
    stdout
        .write_all(b"\n")
        .and_then(|()| stdout.flush())
        .map_err(|error| Error::failure(format!("failed to write check message: {error}")))
}
