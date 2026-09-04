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
use crate::identity::{CargoDebugInfo, RootTargetKind};
use crate::manifest::Manifest;
use crate::metadata::package::{self, Identity};
use crate::metadata::wire;
use crate::resolver::PackageKey;
use crate::unit::{PlannedUnit, UnitKey, UnitKind};

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
    packages: BTreeMap<PackageKey, Package>,
    staging: PathBuf,
    destination: PathBuf,
    ansi: bool,
    state: Mutex<State>,
}

impl Reporter {
    pub fn new(
        root_manifest: &Manifest,
        prepared: &PreparedGraph,
        metadata: wire::Metadata,
        staging: &Path,
        destination: &Path,
        format: MessageFormat,
    ) -> Result<Self> {
        let mut descriptions = metadata
            .packages
            .into_iter()
            .map(|package| (package.id.clone(), package))
            .collect::<BTreeMap<_, _>>();
        let root_id = package::package_id(root_manifest, Identity::Root)?;
        let root = descriptions
            .remove(&root_id)
            .ok_or_else(|| Error::failure("check metadata omits the selected package"))?;
        let root = Package::from_wire(root);
        let mut packages = BTreeMap::new();
        for resolved in &prepared.resolution.packages {
            let manifest = &prepared.packages[&resolved.key].manifest;
            let id = package::package_id(manifest, Identity::Resolved(resolved))?;
            let description = descriptions.remove(&id).ok_or_else(|| {
                Error::failure(format!(
                    "check metadata omits package `{} {}`",
                    resolved.key.name, resolved.key.version
                ))
            })?;
            packages.insert(resolved.key.clone(), Package::from_wire(description));
        }
        if !descriptions.is_empty() {
            return Err(Error::failure(
                "check metadata contains an unexpected package",
            ));
        }
        Ok(Self {
            root,
            packages,
            staging: staging.to_owned(),
            destination: destination.to_owned(),
            ansi: format == MessageFormat::JsonDiagnosticRenderedAnsi,
            state: Mutex::new(State::default()),
        })
    }

    pub fn root_compiler_messages(
        &self,
        kind: RootTargetKind,
        name: &str,
        output: &std::process::Output,
    ) -> Result<()> {
        let target = self.root.target(kind, name)?;
        self.write_compiler_messages(&self.root, target, output)
    }

    pub fn root_artifact(
        &self,
        kind: RootTargetKind,
        name: &str,
        test: bool,
        features: &[String],
        metadata: &Path,
    ) -> Result<()> {
        let target = self.root.target(kind, name)?;
        self.write_value(json!({
            "reason": "compiler-artifact",
            "package_id": self.root.id,
            "manifest_path": self.root.manifest_path,
            "target": target,
            "profile": root_profile(test),
            "features": features,
            "filenames": [self.published_path(metadata)?],
            "executable": Value::Null,
            "fresh": false,
        }))
    }

    fn package(&self, key: &PackageKey) -> Result<&Package> {
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
        output: &std::process::Output,
    ) -> Result<()> {
        for bytes in [&output.stdout, &output.stderr] {
            for line in bytes.split(|byte| *byte == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if line.is_empty() {
                    continue;
                }
                let mut message: Value = serde_json::from_slice(line).map_err(|error| {
                    Error::failure(format!("rustc emitted a non-JSON check message: {error}"))
                })?;
                let object = message.as_object_mut().ok_or_else(|| {
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
                if !self.ansi
                    && let Some(rendered) = object.get_mut("rendered")
                    && let Some(text) = rendered.as_str()
                {
                    *rendered = Value::String(crate::process::strip_ansi(text));
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
        write_line(&value)
    }
}

impl EventReporter for Reporter {
    fn compiler_messages(&self, key: &UnitKey, output: &std::process::Output) -> Result<()> {
        let package = self.package(&key.package)?;
        let target = package.dependency_target(key.kind)?;
        self.write_compiler_messages(package, target, output)
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
        let target = package.dependency_target(key.kind)?;
        let (filenames, executable) = match output {
            RustcOutput::Library { rlib, rmeta, .. } => (
                vec![self.published_path(rlib)?, self.published_path(rmeta)?],
                None,
            ),
            RustcOutput::ProcMacro {
                dynamic_library, ..
            } => (vec![self.published_path(dynamic_library)?], None),
            RustcOutput::BuildScript {
                executable,
                unhashed_executable,
                ..
            } => (
                vec![self.published_path(executable)?],
                Some(self.published_path(unhashed_executable)?),
            ),
        };
        write_line(&json!({
            "reason": "compiler-artifact",
            "package_id": package.id,
            "manifest_path": package.manifest_path,
            "target": target,
            "profile": dependency_profile(planned),
            "features": key.features,
            "filenames": filenames,
            "executable": executable,
            "fresh": fresh,
        }))?;
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
        write_line(&json!({
            "reason": "build-script-executed",
            "package_id": package.id,
            "linked_libs": linked_libs,
            "linked_paths": linked_paths,
            "cfgs": cfgs,
            "env": env,
            "out_dir": self.published_path(&executed.out_dir)?,
        }))?;
        Ok(())
    }
}

impl Package {
    fn from_wire(package: wire::Package) -> Self {
        Self {
            id: package.id,
            manifest_path: package.manifest_path,
            targets: package.targets,
        }
    }

    fn target(&self, kind: RootTargetKind, name: &str) -> Result<&wire::Target> {
        self.targets
            .iter()
            .find(|target| {
                target.name == name
                    && match kind {
                        RootTargetKind::Library => target
                            .kind
                            .iter()
                            .all(|kind| kind != "bin" && kind != "test" && kind != "custom-build"),
                        RootTargetKind::Binary => target.kind.iter().any(|kind| kind == "bin"),
                        RootTargetKind::IntegrationTest => {
                            target.kind.iter().any(|kind| kind == "test")
                        }
                    }
            })
            .ok_or_else(|| Error::failure(format!("check metadata omits target `{name}`")))
    }

    fn dependency_target(&self, kind: UnitKind) -> Result<&wire::Target> {
        self.targets
            .iter()
            .find(|target| match kind {
                UnitKind::Library | UnitKind::ProcMacro => target
                    .kind
                    .iter()
                    .all(|kind| kind != "bin" && kind != "test" && kind != "custom-build"),
                UnitKind::BuildScriptCompile | UnitKind::BuildScriptRun => {
                    target.kind.iter().any(|kind| kind == "custom-build")
                }
            })
            .ok_or_else(|| Error::failure("check metadata omits a dependency target"))
    }
}

fn root_profile(test: bool) -> Value {
    json!({
        "opt_level": "0",
        "debuginfo": 2,
        "debug_assertions": true,
        "overflow_checks": true,
        "test": test,
    })
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
        "test": false,
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
