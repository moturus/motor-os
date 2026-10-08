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
    root: PathBuf,
}

#[derive(Default)]
struct State {
    artifacts: BTreeSet<UnitKey>,
    build_scripts: BTreeSet<UnitKey>,
    messages: Vec<Value>,
    source_paths: Vec<(PathBuf, PathBuf)>,
}

pub struct Reporter {
    root: Package,
    root_key: PackageKey,
    packages: BTreeMap<PackageKey, Package>,
    source_paths: Vec<(PathBuf, PathBuf)>,
    format: MessageFormat,
    color: bool,
    state: Mutex<State>,
}

impl Reporter {
    pub fn new(
        root_manifest: &Manifest,
        prepared: &PreparedGraph,
        roots: &BTreeMap<PackageKey, PathBuf>,
        format: MessageFormat,
        color: bool,
    ) -> Result<Self> {
        let root = Package::from_manifest(root_manifest, Identity::Root, &root_manifest.root)?;
        let mut packages = BTreeMap::new();
        let mut source_paths = Vec::new();
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
            source_paths.push((manifest.root.clone(), root.clone()));
        }
        source_paths.sort_by_key(|(from, _)| std::cmp::Reverse(from.as_os_str().len()));
        source_paths.dedup();
        Ok(Self {
            root,
            root_key: selected_library_key(root_manifest)?.package,
            packages,
            source_paths,
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
        source_paths: &[(PathBuf, PathBuf)],
    ) -> Result<()> {
        {
            let _state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.format == MessageFormat::Human {
                crate::process::RustcCommand::render_messages(stdout, b"", self.color);
            } else {
                let mut output = io::stdout().lock();
                output
                    .write_all(stdout)
                    .and_then(|()| output.flush())
                    .map_err(|error| {
                        Error::failure(format!("failed to forward rustc stdout: {error}"))
                    })?;
            }
        }
        for line in stderr.split(|byte| *byte == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                continue;
            }
            let message = serde_json::from_slice::<Value>(line).ok();
            if message.as_ref().is_some_and(|message| {
                message.get("artifact").is_some() || message.get("unused_extern_names").is_some()
            }) {
                continue;
            }
            let Some(mut message) =
                message.filter(|message| message.get("message").and_then(Value::as_str).is_some())
            else {
                self.write_value(json!({
                    "reason": "rustc-stderr",
                    "text": format!("{}\n", String::from_utf8_lossy(line)),
                }))?;
                continue;
            };
            let text = message["message"]
                .as_str()
                .expect("diagnostic text was checked");
            if text.starts_with("aborting due to")
                || text.ends_with("warning emitted")
                || text.ends_with("warnings emitted")
            {
                continue;
            }
            restore_diagnostic_paths(&mut message, source_paths);
            self.write_value(json!({
                "reason": "compiler-message",
                "package_id": package.id,
                "manifest_path": package.manifest_path,
                "target": target,
                "message": message,
            }))?;
        }
        Ok(())
    }

    fn published_path(&self, path: &Path) -> Result<String> {
        path.to_owned()
            .into_os_string()
            .into_string()
            .map_err(|path| {
                Error::failure(format!(
                    "check artifact path `{}` is not valid UTF-8",
                    PathBuf::from(path).display()
                ))
            })
    }

    fn write_value(&self, value: Value) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.write_locked(&mut state, value)
    }

    fn write_locked(&self, state: &mut State, value: Value) -> Result<()> {
        emit(&value, self.format, self.color)?;
        state.messages.push(value);
        Ok(())
    }

    pub fn messages(&self) -> Vec<Value> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .messages
            .clone()
    }
}

fn restore_path(path: &str, source_paths: &[(PathBuf, PathBuf)]) -> Option<String> {
    source_paths.iter().find_map(|(from, to)| {
        let relative = Path::new(path).strip_prefix(from).ok()?;
        to.join(relative).into_os_string().into_string().ok()
    })
}

fn restore_diagnostic_paths(message: &mut Value, source_paths: &[(PathBuf, PathBuf)]) {
    match message {
        Value::Array(values) => {
            for value in values {
                restore_diagnostic_paths(value, source_paths);
            }
        }
        Value::Object(fields) => {
            if let Some(filename) = fields.get_mut("file_name")
                && let Some(path) = filename
                    .as_str()
                    .and_then(|path| restore_path(path, source_paths))
            {
                *filename = Value::String(path);
            }
            if let Some(rendered) = fields.get_mut("rendered")
                && let Some(text) = rendered.as_str()
            {
                let mut restored = String::new();
                for line in text.split_inclusive('\n') {
                    let plain = crate::process::strip_ansi(line);
                    let location = plain
                        .trim_start()
                        .strip_prefix("--> ")
                        .or_else(|| plain.trim_start().strip_prefix("::: "));
                    let replacement = location.and_then(|location| {
                        // The final numeric suffix belongs to the diagnostic
                        // location, not the filename (which may contain colons).
                        let (path, column) = location.trim_end().rsplit_once(':')?;
                        column.parse::<usize>().ok()?;
                        let (path, line) = path.rsplit_once(':')?;
                        line.parse::<usize>().ok()?;
                        Some((path.to_owned(), restore_path(path, source_paths)?))
                    });
                    match replacement {
                        Some((from, to)) => restored.push_str(&line.replacen(&from, &to, 1)),
                        None => restored.push_str(line),
                    }
                }
                *rendered = Value::String(restored);
            }
            for value in fields.values_mut() {
                restore_diagnostic_paths(value, source_paths);
            }
        }
        _ => {}
    }
}

impl EventReporter for Reporter {
    fn compiler_messages(
        &self,
        key: &UnitKey,
        planned: &PlannedUnit,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<()> {
        let package = self.package(&key.package)?;
        let target = package.dependency_target(key.kind, key.target.as_deref())?;
        let paths = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(remap) = &planned.source_remap {
                for from in [&remap.logical_root, &remap.presented_root] {
                    let path = (from.clone(), package.root.clone());
                    if !state.source_paths.contains(&path) {
                        state.source_paths.push(path);
                    }
                }
            }
            let mut paths = self.source_paths.clone();
            paths.extend(state.source_paths.iter().cloned());
            paths.sort_by_key(|(from, _)| std::cmp::Reverse(from.as_os_str().len()));
            paths
        };
        self.write_compiler_messages(package, target, stdout, stderr, &paths)
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
            RustcOutput::Library {
                rlib,
                rmeta,
                archive,
                ..
            } => {
                let mut paths = vec![self.published_path(rlib)?, self.published_path(rmeta)?];
                if let Some(archive) = archive {
                    paths.push(self.published_path(archive)?);
                }
                paths.sort();
                paths.dedup();
                (paths, None)
            }
            RustcOutput::ProcMacro {
                dynamic_library, ..
            } => (vec![self.published_path(dynamic_library)?], None),
            RustcOutput::StaticLibrary { archive, .. } => {
                (vec![self.published_path(archive)?], None)
            }
            RustcOutput::Binary { executable, .. } => (
                vec![self.published_path(executable)?],
                Some(self.published_path(executable)?),
            ),
            RustcOutput::Metadata { metadata, .. } => (vec![self.published_path(metadata)?], None),
            RustcOutput::BuildScript { executable, .. } => {
                (vec![self.published_path(executable)?], None)
            }
        };
        self.write_locked(
            &mut state,
            json!({
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
        self.write_locked(
            &mut state,
            json!({
                "reason": "build-script-executed",
                "package_id": package.id,
                "linked_libs": linked_libs,
                "linked_paths": linked_paths,
                "cfgs": cfgs,
                "env": env,
                "out_dir": self.published_path(&executed.out_dir)?,
            }),
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
            root: root.to_owned(),
        })
    }

    fn dependency_target(&self, kind: UnitKind, name: Option<&str>) -> Result<&wire::Target> {
        self.targets
            .iter()
            .find(|target| {
                name.is_none_or(|name| target.name == name)
                    && match kind {
                        UnitKind::Library | UnitKind::ProcMacro | UnitKind::LibraryHarness => {
                            target.kind.iter().any(|kind| {
                                matches!(
                                    kind.as_str(),
                                    "lib"
                                        | "rlib"
                                        | "staticlib"
                                        | "dylib"
                                        | "cdylib"
                                        | "proc-macro"
                                )
                            })
                        }
                        UnitKind::Binary | UnitKind::BinaryHarness => {
                            target.kind.iter().any(|kind| kind == "bin")
                        }
                        UnitKind::IntegrationHarness => {
                            target.kind.iter().any(|kind| kind == "test")
                        }
                        UnitKind::Example => target.kind.iter().any(|kind| kind == "example"),
                        UnitKind::Bench => target.kind.iter().any(|kind| kind == "bench"),
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

/// Replays a completed profile's messages. As for a reused unit, registry and
/// Git dependencies' messages, which only a verbose build records, replay only
/// in verbose builds.
pub fn replay(messages: &[Value], format: MessageFormat, color: bool, verbose: bool) -> Result<()> {
    for message in messages.iter().filter(|message| replays(message, verbose)) {
        let mut message = message.clone();
        if message.get("reason").and_then(Value::as_str) == Some("compiler-artifact") {
            message["fresh"] = Value::Bool(true);
        }
        emit(&message, format, color)?;
    }
    Ok(())
}

fn replays(message: &Value, verbose: bool) -> bool {
    verbose
        || message.get("reason").and_then(Value::as_str) != Some("compiler-message")
        || message
            .get("package_id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.starts_with("path+"))
}

fn emit(value: &Value, format: MessageFormat, color: bool) -> Result<()> {
    if value.get("reason").and_then(Value::as_str) == Some("rustc-stderr") {
        eprint!("{}", value["text"].as_str().unwrap_or_default());
        return Ok(());
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_shows_dependency_messages_only_when_verbose() {
        let message = |id: &str| json!({"reason": "compiler-message", "package_id": id});
        let member = message("path+file:///work/app#0.1.0");
        let registry = message("registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0");
        let artifact = json!({"reason": "compiler-artifact", "package_id": "registry+x#y@1"});
        assert!(replays(&member, false));
        assert!(!replays(&registry, false));
        assert!(replays(&registry, true));
        assert!(replays(&artifact, false));
    }

    #[test]
    fn restores_nested_spans_and_rendered_locations_without_changing_source_text() {
        let paths = vec![
            (
                PathBuf::from("/workspace/logical/pkg"),
                PathBuf::from("/cache/real/pkg"),
            ),
            (
                PathBuf::from("logical/pkg"),
                PathBuf::from("/cache/real/pkg"),
            ),
            (
                PathBuf::from("/temporary/pkg"),
                PathBuf::from("/cache/real/pkg"),
            ),
        ];
        let mut diagnostic = json!({
            "message": "logical/pkg is mentioned by the user",
            "spans": [{
                "file_name": "logical/pkg/src/lib.rs",
                "expansion": {"span": {"file_name": "/workspace/logical/pkg/src/macro.rs"}},
            }],
            "children": [{"spans": [{"file_name": "/temporary/pkg/build.rs"}]}],
            "rendered": "error: logical/pkg\n \u{1b}[1;34m--> \u{1b}[0mlogical/pkg/src/lib.rs:1:2\n1 | let value = \"logical/pkg/src/lib.rs\";\n",
        });
        restore_diagnostic_paths(&mut diagnostic, &paths);
        assert_eq!(
            diagnostic["spans"][0]["file_name"],
            "/cache/real/pkg/src/lib.rs"
        );
        assert_eq!(
            diagnostic["spans"][0]["expansion"]["span"]["file_name"],
            "/cache/real/pkg/src/macro.rs"
        );
        assert_eq!(
            diagnostic["children"][0]["spans"][0]["file_name"],
            "/cache/real/pkg/build.rs"
        );
        assert_eq!(
            diagnostic["message"],
            "logical/pkg is mentioned by the user"
        );
        assert_eq!(
            diagnostic["rendered"],
            "error: logical/pkg\n \u{1b}[1;34m--> \u{1b}[0m/cache/real/pkg/src/lib.rs:1:2\n1 | let value = \"logical/pkg/src/lib.rs\";\n"
        );
        assert!(restore_path("logical/pkg-other/src/lib.rs", &paths).is_none());
        assert!(restore_path("/rustc/stdlib.rs", &paths).is_none());
    }
}
