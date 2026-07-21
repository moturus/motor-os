use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

use semver::{Op, VersionReq};
use toml_edit::{Item, Table};

use crate::diagnostic::{Error, Result};
use crate::toml::Document;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CargoCompat {
    V1_97,
    V1_98,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub cargo_compat: Option<CargoCompat>,
    pub rustc: Option<PathBuf>,
    pub default_target: Option<String>,
    pub build_rustflags: Vec<String>,
    pub incompatible_rust_versions: Option<IncompatibleRustVersions>,
    pub targets: BTreeMap<TargetSelector, TargetOptions>,
    #[allow(dead_code)]
    pub repositories: Repositories,
    #[allow(dead_code)]
    pub vendor: VendorConfig,
    #[allow(dead_code)]
    pub network: NetworkConfig,
    #[allow(dead_code)]
    pub test: TestConfig,
    #[allow(dead_code)]
    pub native_tools: BTreeMap<(String, NativeToolRole), NativeTool>,
    #[allow(dead_code)]
    pub policy: Policy,
    #[allow(dead_code)]
    pub required_patches: BTreeMap<String, RequiredPatch>,
    constraints: Vec<Constraint>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cargo_compat: None,
            rustc: None,
            default_target: None,
            build_rustflags: Vec::new(),
            incompatible_rust_versions: None,
            targets: BTreeMap::new(),
            repositories: Repositories::default(),
            vendor: VendorConfig::default(),
            network: NetworkConfig::default(),
            test: TestConfig::default(),
            native_tools: BTreeMap::new(),
            policy: Policy::default(),
            required_patches: BTreeMap::new(),
            constraints: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TargetSelector {
    Triple(String),
    Cfg(String),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TargetOptions {
    pub linker: Option<PathBuf>,
    pub runner: Option<Vec<String>>,
    pub rustflags: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncompatibleRustVersions {
    Allow,
    Fallback,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Repositories {
    pub system: Option<PathBuf>,
    pub user: Option<PathBuf>,
    pub local: Option<PathBuf>,
    pub keep_artifacts: bool,
    pub keep_sources: bool,
}

impl Default for Repositories {
    fn default() -> Self {
        Self {
            system: None,
            user: None,
            local: None,
            keep_artifacts: true,
            keep_sources: true,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VendorConfig {
    pub targets: Vec<String>,
    pub include_host: bool,
}

impl Default for VendorConfig {
    fn default() -> Self {
        Self {
            targets: vec![
                "x86_64-unknown-linux-musl".to_owned(),
                "x86_64-unknown-motor".to_owned(),
            ],
            include_host: true,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkConfig {
    pub helper: Option<PathBuf>,
    pub ca_bundle: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TestConfig {
    pub extraction_root: Option<PathBuf>,
}

impl TestConfig {
    pub fn extraction_root(&self, target: &str) -> &Path {
        self.extraction_root.as_deref().unwrap_or_else(|| {
            if target.rsplit('-').next() == Some("motor") {
                Path::new("/user/tmp/lorry/test-extraction")
            } else {
                Path::new("/tmp/lorry-tests")
            }
        })
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NativeToolRole {
    CCompiler,
    Archiver,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeTool {
    pub program: Option<PathBuf>,
    pub prefix_args: Vec<String>,
    pub flags: Vec<String>,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyDefault {
    Deny,
    Allow,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub default: PolicyDefault,
    pub path_roots: Vec<PathBuf>,
    pub limits: PolicyLimits,
    pub rules: BTreeMap<String, PolicyRule>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            default: PolicyDefault::Deny,
            path_roots: Vec::new(),
            limits: PolicyLimits::default(),
            rules: BTreeMap::new(),
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyLimits {
    pub max_packages: u64,
    pub max_depth: u64,
    pub max_package_bytes: u64,
    pub max_extracted_package_bytes: u64,
    pub max_package_files: u64,
    pub max_transaction_bytes: u64,
    pub max_extracted_transaction_bytes: u64,
    pub build_script_seconds: u64,
    pub build_script_output_bytes: u64,
}

impl Default for PolicyLimits {
    fn default() -> Self {
        Self {
            max_packages: 64,
            max_depth: 16,
            max_package_bytes: 16 * 1024 * 1024,
            max_extracted_package_bytes: 128 * 1024 * 1024,
            max_package_files: 20_000,
            max_transaction_bytes: 256 * 1024 * 1024,
            max_extracted_transaction_bytes: 1024 * 1024 * 1024,
            build_script_seconds: 300,
            build_script_output_bytes: 8 * 1024 * 1024,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyAction {
    Allow,
    Deny,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    pub action: PolicyAction,
    pub name: Option<String>,
    pub version: Option<VersionReq>,
    pub source: Option<String>,
    pub checksum: Option<String>,
    pub source_tree_sha256: Option<String>,
    pub license: Option<String>,
    pub allow_build_script: bool,
    pub native_tools: BTreeSet<NativeToolRole>,
    pub provenance: PathBuf,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredPatch {
    pub name: String,
    pub version: VersionReq,
    pub upstream_checksum: String,
    pub git_url: String,
    pub git_commit: String,
    pub source_tree_sha256: String,
    pub provenance: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Constraint {
    key: String,
    provenance: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LayerKind {
    LinuxBase,
    MotorSystem,
    MotorUser,
    Local,
}

impl Config {
    pub fn load(package_root: &Path) -> Result<Self> {
        let environment = env::vars_os()
            .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        Self::load_with_environment(package_root, &environment)
    }

    fn load_with_environment(
        package_root: &Path,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self> {
        reject_environment(environment)?;
        let mut config = Config::default();
        load_lorry_layers(package_root, environment, &mut config)?;
        validate_repository_layout(&config.repositories)?;
        load_cargo_layers(package_root, environment, &mut config)?;
        apply_cargo_environment(environment, &mut config)?;
        Ok(config)
    }

    #[cfg(test)]
    pub(crate) fn load_for_test(
        package_root: &Path,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self> {
        Self::load_with_environment(package_root, environment)
    }

    pub fn selected_target(&self, command_target: Option<&str>) -> Result<Option<String>> {
        let target = command_target
            .map(str::to_owned)
            .or_else(|| self.default_target.clone());
        if let Some(target) = target.as_deref() {
            validate_target(target)?;
        }
        Ok(target)
    }

    pub fn target_options(&self, target: &str, matching_cfgs: &[String]) -> Result<TargetOptions> {
        let mut result = TargetOptions::default();
        let mut matching_runners = Vec::new();
        let mut matching_linkers = Vec::new();

        for (selector, options) in &self.targets {
            let matches = match selector {
                TargetSelector::Triple(triple) => triple == target,
                TargetSelector::Cfg(expression) => matching_cfgs.contains(expression),
            };
            if !matches {
                continue;
            }
            result.rustflags.extend(options.rustflags.iter().cloned());
            if let Some(linker) = &options.linker {
                matching_linkers.push((selector, linker));
            }
            if let Some(runner) = &options.runner {
                matching_runners.push((selector, runner));
            }
        }

        if let Some(exact) = self.targets.get(&TargetSelector::Triple(target.to_owned())) {
            if exact.linker.is_some() {
                matching_linkers
                    .retain(|(selector, _)| matches!(selector, TargetSelector::Triple(_)));
            }
            if exact.runner.is_some() {
                matching_runners
                    .retain(|(selector, _)| matches!(selector, TargetSelector::Triple(_)));
            }
        }
        if matching_linkers.len() > 1 {
            return Err(Error::failure(format!(
                "target `{target}` matches more than one configured linker"
            ))
            .with_help("configure one exact target linker or make the cfg selectors disjoint"));
        }
        if matching_runners.len() > 1 {
            return Err(Error::failure(format!(
                "target `{target}` matches more than one configured runner"
            ))
            .with_help("configure one exact target runner or make the cfg selectors disjoint"));
        }
        result.linker = matching_linkers.first().map(|(_, value)| (*value).clone());
        result.runner = matching_runners.first().map(|(_, value)| (*value).clone());
        Ok(result)
    }
}

fn reject_environment(environment: &BTreeMap<String, String>) -> Result<()> {
    for variable in [
        "CARGO_TARGET_DIR",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        if environment.contains_key(variable) {
            let explanation = if variable == "CARGO_TARGET_DIR" {
                "Lorry uses the isolated `target/lorry` artifact root"
            } else {
                "compiler wrappers are outside the Stage-2 identity contract"
            };
            return Err(Error::failure(format!(
                "environment variable `{variable}` is not supported: {explanation}"
            ))
            .with_help(format!("unset `{variable}` before invoking Lorry")));
        }
    }
    Ok(())
}

fn load_lorry_layers(
    package_root: &Path,
    environment: &BTreeMap<String, String>,
    config: &mut Config,
) -> Result<()> {
    let mut layers = Vec::new();
    if cfg!(target_os = "motor") {
        layers.push((
            PathBuf::from("/sys/tools/rust/cfg/lorry.toml"),
            LayerKind::MotorSystem,
        ));
        layers.push((PathBuf::from("/user/cfg/lorry.toml"), LayerKind::MotorUser));
    } else if let Some(home) = environment.get("HOME") {
        layers.push((
            Path::new(home).join(".config/lorry/lorry.toml"),
            LayerKind::LinuxBase,
        ));
    }
    if let Some(local) = nearest_file(package_root, "lorry.toml")
        && !layers.iter().any(|(path, _)| path == &local)
    {
        layers.push((local, LayerKind::Local));
    }
    for (path, kind) in layers {
        if path.is_file() {
            merge_lorry_file(&path, kind, config)?;
        }
    }
    Ok(())
}

fn merge_lorry_file(path: &Path, kind: LayerKind, config: &mut Config) -> Result<()> {
    let document = Document::load(path, "Lorry configuration")?;
    reject_locked_overrides(path, kind, &document, &config.constraints)?;
    validate_lorry_root(path, &document)?;

    let version = document.root().get("config-version").ok_or_else(|| {
        Error::failure(format!(
            "Lorry configuration `{}` is missing `config-version = 1`",
            path.display()
        ))
    })?;
    if version.as_integer() != Some(1) {
        return Err(Error::at(
            path,
            document.line_of_item(version),
            "unsupported Lorry configuration version",
            "set `config-version = 1`",
        ));
    }
    if let Some(item) = document.root().get("cargo-compat-version") {
        config.cargo_compat = Some(match item.as_str() {
            Some("1.97") => CargoCompat::V1_97,
            Some("1.98") => CargoCompat::V1_98,
            Some(value) => {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    format!("unsupported Cargo compatibility family `{value}`"),
                    "choose `1.97` or `1.98`",
                ));
            }
            None => {
                return Err(type_error(
                    path,
                    &document,
                    item,
                    "cargo-compat-version",
                    "a string",
                ));
            }
        });
    }
    merge_toolchain(path, &document, config)?;
    merge_repositories(path, kind, &document, config)?;
    merge_vendor(path, &document, config)?;
    merge_network(path, &document, config)?;
    merge_test(path, &document, config)?;
    merge_native_tools(path, &document, config)?;
    merge_policy(path, &document, config)?;
    merge_required_patches(path, &document, config)?;
    merge_constraints(path, kind, &document, config)?;
    Ok(())
}

fn validate_lorry_root(path: &Path, document: &Document) -> Result<()> {
    const ALLOWED: &[&str] = &[
        "config-version",
        "cargo-compat-version",
        "toolchain",
        "repositories",
        "vendor",
        "network",
        "test",
        "native-tools",
        "policy",
        "required-patches",
        "system-constraints",
    ];
    for (key, item) in document.root().iter() {
        if !ALLOWED.contains(&key) {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported Stage-2 Lorry configuration key `{key}`"),
                "remove the unknown key",
            ));
        }
    }
    Ok(())
}

fn merge_toolchain(path: &Path, document: &Document, config: &mut Config) -> Result<()> {
    let Some(item) = document.root().get("toolchain") else {
        return Ok(());
    };
    let table = require_table(path, document, item, "toolchain")?;
    reject_unknown_keys(path, document, table, "toolchain", &["rustc"])?;
    if let Some(item) = table.get("rustc") {
        config.rustc = Some(absolute_path(path, document, item, "toolchain.rustc")?);
    }
    Ok(())
}

fn merge_repositories(
    path: &Path,
    kind: LayerKind,
    document: &Document,
    config: &mut Config,
) -> Result<()> {
    let Some(item) = document.root().get("repositories") else {
        return Ok(());
    };
    let table = require_table(path, document, item, "repositories")?;
    reject_unknown_keys(
        path,
        document,
        table,
        "repositories",
        &["system", "user", "local", "keep-artifacts", "keep-sources"],
    )?;
    for (key, destination, allowed) in [
        (
            "system",
            &mut config.repositories.system,
            matches!(kind, LayerKind::LinuxBase | LayerKind::MotorSystem),
        ),
        (
            "user",
            &mut config.repositories.user,
            matches!(kind, LayerKind::LinuxBase | LayerKind::MotorUser),
        ),
        (
            "local",
            &mut config.repositories.local,
            kind == LayerKind::Local,
        ),
    ] {
        if let Some(item) = table.get(key) {
            if !allowed {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    format!("`repositories.{key}` is not owned by this configuration layer"),
                    "define system/user/local only in its designated layer",
                ));
            }
            *destination = Some(absolute_path(
                path,
                document,
                item,
                &format!("repositories.{key}"),
            )?);
        }
    }
    if let Some(item) = table.get("keep-artifacts") {
        config.repositories.keep_artifacts =
            require_bool(path, document, item, "repositories.keep-artifacts")?;
    }
    if let Some(item) = table.get("keep-sources") {
        config.repositories.keep_sources =
            require_bool(path, document, item, "repositories.keep-sources")?;
    }
    if !config.repositories.keep_artifacts && !config.repositories.keep_sources {
        return Err(Error::at(
            path,
            document.line_of_table(table),
            "`repositories.keep-artifacts` and `keep-sources` cannot both be false",
            "retain at least one verified dependency representation",
        ));
    }
    Ok(())
}

fn merge_vendor(path: &Path, document: &Document, config: &mut Config) -> Result<()> {
    let Some(item) = document.root().get("vendor") else {
        return Ok(());
    };
    let table = require_table(path, document, item, "vendor")?;
    reject_unknown_keys(
        path,
        document,
        table,
        "vendor",
        &["targets", "include-host"],
    )?;
    if let Some(item) = table.get("targets") {
        let targets = require_string_array(path, document, item, "vendor.targets")?;
        let mut unique = BTreeSet::new();
        for target in &targets {
            validate_target_at(path, document.line_of_item(item), target)?;
            if !unique.insert(target) {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    format!("duplicate vendoring target `{target}`"),
                    "list each target once",
                ));
            }
        }
        config.vendor.targets = targets;
    }
    if let Some(item) = table.get("include-host") {
        config.vendor.include_host = require_bool(path, document, item, "vendor.include-host")?;
    }
    Ok(())
}

fn merge_network(path: &Path, document: &Document, config: &mut Config) -> Result<()> {
    let Some(item) = document.root().get("network") else {
        return Ok(());
    };
    let table = require_table(path, document, item, "network")?;
    reject_unknown_keys(path, document, table, "network", &["helper", "ca-bundle"])?;
    if let Some(item) = table.get("helper") {
        config.network.helper = Some(absolute_path(path, document, item, "network.helper")?);
    }
    if let Some(item) = table.get("ca-bundle") {
        config.network.ca_bundle = Some(absolute_path(path, document, item, "network.ca-bundle")?);
    }
    Ok(())
}

fn merge_test(path: &Path, document: &Document, config: &mut Config) -> Result<()> {
    let Some(item) = document.root().get("test") else {
        return Ok(());
    };
    let table = require_table(path, document, item, "test")?;
    reject_unknown_keys(path, document, table, "test", &["extraction-root"])?;
    if let Some(item) = table.get("extraction-root") {
        config.test.extraction_root =
            Some(absolute_path(path, document, item, "test.extraction-root")?);
    }
    Ok(())
}

fn merge_native_tools(path: &Path, document: &Document, config: &mut Config) -> Result<()> {
    let Some(item) = document.root().get("native-tools") else {
        return Ok(());
    };
    let targets = require_table(path, document, item, "native-tools")?;
    for (target, item) in targets.iter() {
        validate_target_at(path, document.line_of_item(item), target)?;
        let roles = require_table(path, document, item, &format!("native-tools.{target}"))?;
        for (role_name, item) in roles.iter() {
            let role = parse_native_role(path, document.line_of_item(item), role_name)?;
            let table = require_table(
                path,
                document,
                item,
                &format!("native-tools.{target}.{role_name}"),
            )?;
            reject_unknown_keys(
                path,
                document,
                table,
                &format!("native-tools.{target}.{role_name}"),
                &["program", "prefix-args", "flags"],
            )?;
            let tool = config
                .native_tools
                .entry((target.to_owned(), role))
                .or_default();
            if let Some(item) = table.get("program") {
                tool.program = Some(absolute_path(
                    path,
                    document,
                    item,
                    &format!("native-tools.{target}.{role_name}.program"),
                )?);
            }
            if let Some(item) = table.get("prefix-args") {
                tool.prefix_args = native_arguments(
                    path,
                    document,
                    item,
                    &format!("native-tools.{target}.{role_name}.prefix-args"),
                )?;
            }
            if let Some(item) = table.get("flags") {
                tool.flags = native_arguments(
                    path,
                    document,
                    item,
                    &format!("native-tools.{target}.{role_name}.flags"),
                )?;
            }
        }
    }
    Ok(())
}

fn merge_policy(path: &Path, document: &Document, config: &mut Config) -> Result<()> {
    let Some(item) = document.root().get("policy") else {
        return Ok(());
    };
    let policy = require_table(path, document, item, "policy")?;
    reject_unknown_keys(
        path,
        document,
        policy,
        "policy",
        &["default", "path-roots", "limits", "rules"],
    )?;
    if let Some(item) = policy.get("default") {
        config.policy.default = match item.as_str() {
            Some("deny") => PolicyDefault::Deny,
            Some("allow") => PolicyDefault::Allow,
            Some(value) => {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    format!("unsupported policy default `{value}`"),
                    "choose `deny` or `allow`",
                ));
            }
            None => {
                return Err(type_error(
                    path,
                    document,
                    item,
                    "policy.default",
                    "a string",
                ));
            }
        };
    }
    if let Some(item) = policy.get("path-roots") {
        config.policy.path_roots = require_string_array(path, document, item, "policy.path-roots")?
            .into_iter()
            .map(|value| {
                canonical_config_path(
                    path,
                    document.line_of_item(item),
                    "policy.path-roots",
                    &value,
                )
            })
            .collect::<Result<Vec<_>>>()?;
    }
    if let Some(item) = policy.get("limits") {
        merge_policy_limits(
            path,
            document,
            require_table(path, document, item, "policy.limits")?,
            &mut config.policy.limits,
        )?;
    }
    if let Some(item) = policy.get("rules") {
        merge_policy_rules(
            path,
            document,
            require_table(path, document, item, "policy.rules")?,
            &mut config.policy.rules,
        )?;
    }
    Ok(())
}

fn merge_policy_limits(
    path: &Path,
    document: &Document,
    table: &Table,
    limits: &mut PolicyLimits,
) -> Result<()> {
    const KEYS: &[&str] = &[
        "max-packages",
        "max-depth",
        "max-package-bytes",
        "max-extracted-package-bytes",
        "max-package-files",
        "max-transaction-bytes",
        "max-extracted-transaction-bytes",
        "build-script-seconds",
        "build-script-output-bytes",
    ];
    reject_unknown_keys(path, document, table, "policy.limits", KEYS)?;
    for (key, item) in table.iter() {
        let value = positive_integer(path, document, item, &format!("policy.limits.{key}"))?;
        match key {
            "max-packages" => limits.max_packages = value,
            "max-depth" => limits.max_depth = value,
            "max-package-bytes" => limits.max_package_bytes = value,
            "max-extracted-package-bytes" => limits.max_extracted_package_bytes = value,
            "max-package-files" => limits.max_package_files = value,
            "max-transaction-bytes" => limits.max_transaction_bytes = value,
            "max-extracted-transaction-bytes" => {
                limits.max_extracted_transaction_bytes = value;
            }
            "build-script-seconds" => limits.build_script_seconds = value,
            "build-script-output-bytes" => limits.build_script_output_bytes = value,
            _ => unreachable!(),
        }
    }
    Ok(())
}

fn merge_policy_rules(
    path: &Path,
    document: &Document,
    rules: &Table,
    output: &mut BTreeMap<String, PolicyRule>,
) -> Result<()> {
    for (id, item) in rules.iter() {
        validate_rule_id(path, document.line_of_item(item), id)?;
        if output.contains_key(id) {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("policy rule ID `{id}` is already defined by another layer"),
                "use a unique rule ID; rules accumulate and cannot be replaced",
            ));
        }
        let table = require_table(path, document, item, &format!("policy.rules.{id}"))?;
        reject_unknown_keys(
            path,
            document,
            table,
            &format!("policy.rules.{id}"),
            &[
                "action",
                "name",
                "version",
                "source",
                "checksum",
                "source-tree-sha256",
                "license",
                "allow-build-script",
                "native-tools",
            ],
        )?;
        let action_item = table.get("action").ok_or_else(|| {
            Error::at(
                path,
                document.line_of_table(table),
                format!("policy rule `{id}` is missing `action`"),
                "set action to `allow` or `deny`",
            )
        })?;
        let action = match action_item.as_str() {
            Some("allow") => PolicyAction::Allow,
            Some("deny") => PolicyAction::Deny,
            Some(value) => {
                return Err(Error::at(
                    path,
                    document.line_of_item(action_item),
                    format!("unsupported policy action `{value}`"),
                    "choose `allow` or `deny`",
                ));
            }
            None => {
                return Err(type_error(
                    path,
                    document,
                    action_item,
                    &format!("policy.rules.{id}.action"),
                    "a string",
                ));
            }
        };
        let name = optional_string(path, document, table, &format!("policy.rules.{id}"), "name")?;
        if let Some(name) = &name {
            validate_package_name(path, document.line_of_table(table), name)?;
        }
        let version = optional_string(
            path,
            document,
            table,
            &format!("policy.rules.{id}"),
            "version",
        )?
        .map(|value| parse_requirement(path, document.line_of_table(table), &value))
        .transpose()?;
        let source = optional_string(
            path,
            document,
            table,
            &format!("policy.rules.{id}"),
            "source",
        )?;
        if source
            .as_deref()
            .is_some_and(|value| !matches!(value, "crates.io" | "path" | "system-vendored-path"))
        {
            return Err(Error::at(
                path,
                document.line_of_table(table),
                format!("unsupported policy source `{}`", source.as_deref().unwrap()),
                "choose crates.io, path, or system-vendored-path",
            ));
        }
        let checksum = optional_digest(path, document, table, id, "checksum")?;
        let source_tree_sha256 = optional_digest(path, document, table, id, "source-tree-sha256")?;
        let license = optional_string(
            path,
            document,
            table,
            &format!("policy.rules.{id}"),
            "license",
        )?;
        let allow_build_script = optional_bool(
            path,
            document,
            table,
            &format!("policy.rules.{id}"),
            "allow-build-script",
        )?
        .unwrap_or(false);
        let native_tools = match table.get("native-tools") {
            Some(item) => parse_native_roles(path, document, item)?,
            None => BTreeSet::new(),
        };
        if !native_tools.is_empty() && !allow_build_script {
            return Err(Error::at(
                path,
                document.line_of_table(table),
                format!(
                    "policy rule `{id}` grants native tools without `allow-build-script = true`"
                ),
                "explicitly allow the build script before granting native tools",
            ));
        }
        if !native_tools.is_empty()
            && source.as_deref() != Some("crates.io")
            && source_tree_sha256.is_none()
        {
            return Err(Error::at(
                path,
                document.line_of_table(table),
                format!("path policy rule `{id}` grants native tools without a source-tree digest"),
                "pin `source-tree-sha256` before granting native tools",
            ));
        }
        output.insert(
            id.to_owned(),
            PolicyRule {
                action,
                name,
                version,
                source,
                checksum,
                source_tree_sha256,
                license,
                allow_build_script,
                native_tools,
                provenance: path.to_path_buf(),
            },
        );
    }
    Ok(())
}

fn merge_required_patches(path: &Path, document: &Document, config: &mut Config) -> Result<()> {
    let Some(item) = document.root().get("required-patches") else {
        return Ok(());
    };
    let root = require_table(path, document, item, "required-patches")?;
    reject_unknown_keys(path, document, root, "required-patches", &["crates-io"])?;
    let Some(item) = root.get("crates-io") else {
        return Ok(());
    };
    let rules = require_table(path, document, item, "required-patches.crates-io")?;
    for (id, item) in rules.iter() {
        validate_rule_id(path, document.line_of_item(item), id)?;
        if config.required_patches.contains_key(id) {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("required patch ID `{id}` conflicts with another layer"),
                "use one exact requirement for each patch ID",
            ));
        }
        let table = require_table(
            path,
            document,
            item,
            &format!("required-patches.crates-io.{id}"),
        )?;
        reject_unknown_keys(
            path,
            document,
            table,
            &format!("required-patches.crates-io.{id}"),
            &[
                "name",
                "version",
                "upstream-checksum",
                "git-url",
                "git-commit",
                "source-tree-sha256",
            ],
        )?;
        let name = required_string(path, document, table, id, "name")?;
        validate_package_name(path, document.line_of_table(table), &name)?;
        let version_text = required_string(path, document, table, id, "version")?;
        let version = parse_exact_requirement(path, document.line_of_table(table), &version_text)?;
        let upstream_checksum = required_digest(path, document, table, id, "upstream-checksum")?;
        let git_url = required_string(path, document, table, id, "git-url")?;
        validate_https_git_url(path, document.line_of_table(table), &git_url)?;
        let git_commit = required_string(path, document, table, id, "git-commit")?;
        if !is_hex(&git_commit, 40) {
            return Err(Error::at(
                path,
                document.line_of_table(table),
                format!("required patch `{id}` has an invalid Git commit"),
                "pin a full 40-character lowercase Git commit ID",
            ));
        }
        let source_tree_sha256 = required_digest(path, document, table, id, "source-tree-sha256")?;
        config.required_patches.insert(
            id.to_owned(),
            RequiredPatch {
                name,
                version,
                upstream_checksum,
                git_url,
                git_commit,
                source_tree_sha256,
                provenance: path.to_path_buf(),
            },
        );
    }
    Ok(())
}

fn merge_constraints(
    path: &Path,
    kind: LayerKind,
    document: &Document,
    config: &mut Config,
) -> Result<()> {
    let Some(item) = document.root().get("system-constraints") else {
        return Ok(());
    };
    if !matches!(kind, LayerKind::LinuxBase | LayerKind::MotorSystem) {
        return Err(Error::at(
            path,
            document.line_of_item(item),
            "`system-constraints` is allowed only in the trusted system/base layer",
            "remove it from user or repository-local configuration",
        ));
    }
    let table = require_table(path, document, item, "system-constraints")?;
    reject_unknown_keys(path, document, table, "system-constraints", &["locked"])?;
    let locked = table.get("locked").ok_or_else(|| {
        Error::at(
            path,
            document.line_of_table(table),
            "`system-constraints` is missing `locked`",
            "list the key/table prefixes protected from later layers",
        )
    })?;
    for key in require_string_array(path, document, locked, "system-constraints.locked")? {
        validate_constraint_key(path, document.line_of_item(locked), &key)?;
        if config
            .constraints
            .iter()
            .any(|constraint| constraint.key == key)
        {
            return Err(Error::at(
                path,
                document.line_of_item(locked),
                format!("system constraint `{key}` is listed more than once"),
                "list each locked prefix once",
            ));
        }
        config.constraints.push(Constraint {
            key,
            provenance: path.to_path_buf(),
        });
    }
    Ok(())
}

fn reject_locked_overrides(
    path: &Path,
    kind: LayerKind,
    document: &Document,
    constraints: &[Constraint],
) -> Result<()> {
    if matches!(kind, LayerKind::LinuxBase | LayerKind::MotorSystem) {
        return Ok(());
    }
    let mut leaves = Vec::new();
    collect_leaf_paths(document.root(), "", &mut leaves);
    for leaf in leaves {
        if let Some(constraint) = constraints.iter().find(|constraint| {
            leaf == constraint.key
                || leaf.starts_with(&format!("{}.", constraint.key))
                || constraint.key.starts_with(&format!("{leaf}."))
        }) {
            return Err(Error::failure(format!(
                "configuration `{}` attempts to override locked `{}` from `{}`",
                path.display(),
                constraint.key,
                constraint.provenance.display()
            ))
            .with_help("remove the later-layer override"));
        }
    }
    Ok(())
}

fn collect_leaf_paths(table: &Table, prefix: &str, output: &mut Vec<String>) {
    for (key, item) in table.iter() {
        let path = if prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{prefix}.{key}")
        };
        match item {
            Item::Table(table) => collect_leaf_paths(table, &path, output),
            Item::ArrayOfTables(_) | Item::Value(_) | Item::None => output.push(path),
        }
    }
}

fn validate_repository_layout(repositories: &Repositories) -> Result<()> {
    let paths = [
        ("system", repositories.system.as_deref()),
        ("user", repositories.user.as_deref()),
        ("local", repositories.local.as_deref()),
    ];
    for (left_name, left) in paths {
        let Some(left) = left else {
            continue;
        };
        for (right_name, right) in paths {
            let Some(right) = right else {
                continue;
            };
            if left_name >= right_name {
                continue;
            }
            if left == right || left.starts_with(right) || right.starts_with(left) {
                return Err(Error::failure(format!(
                    "repositories.{left_name} `{}` and repositories.{right_name} `{}` overlap",
                    left.display(),
                    right.display()
                ))
                .with_help("configure distinct repositories that do not contain one another"));
            }
        }
    }
    Ok(())
}

fn load_cargo_layers(
    package_root: &Path,
    environment: &BTreeMap<String, String>,
    config: &mut Config,
) -> Result<()> {
    let cargo_home = environment
        .get("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            environment
                .get("HOME")
                .map(|home| Path::new(home).join(".cargo"))
        });
    let mut layers = Vec::new();
    if let Some(home) = cargo_home.as_deref()
        && let Some(path) = cargo_config_in(home)
    {
        layers.push(path);
    }
    let mut ancestors: Vec<_> = package_root.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        let directory = ancestor.join(".cargo");
        if cargo_home
            .as_deref()
            .is_some_and(|home| same_path(home, &directory))
        {
            continue;
        }
        if let Some(path) = cargo_config_in(&directory) {
            layers.push(path);
        }
    }
    for path in layers {
        merge_cargo_file(&path, config)?;
    }
    Ok(())
}

fn cargo_config_in(directory: &Path) -> Option<PathBuf> {
    let legacy = directory.join("config");
    if legacy.is_file() {
        Some(legacy)
    } else {
        let current = directory.join("config.toml");
        current.is_file().then_some(current)
    }
}

fn merge_cargo_file(path: &Path, config: &mut Config) -> Result<()> {
    let document = Document::load(path, "Cargo configuration")?;
    for (key, item) in document.root().iter() {
        if !matches!(key, "build" | "target" | "resolver") {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported Cargo configuration table or key `{key}`"),
                "Lorry reads only build, target, and resolver configuration",
            ));
        }
    }
    let definition_root = path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("/"));
    if let Some(item) = document.root().get("build") {
        let build = require_table(path, &document, item, "build")?;
        reject_unknown_keys(
            path,
            &document,
            build,
            "build",
            &[
                "target",
                "rustflags",
                "target-dir",
                "rustc-wrapper",
                "rustc-workspace-wrapper",
            ],
        )?;
        for (key, item) in build.iter() {
            match key {
                "target" => {
                    let value = require_string(path, &document, item, "build.target")?;
                    validate_target_at(path, document.line_of_item(item), &value)?;
                    config.default_target = Some(value);
                }
                "rustflags" => {
                    config.build_rustflags.extend(argument_words(
                        path,
                        &document,
                        item,
                        "build.rustflags",
                    )?);
                }
                "target-dir" => {
                    return Err(Error::at(
                        path,
                        document.line_of_item(item),
                        "Cargo `build.target-dir` is not supported",
                        "remove it; Lorry always writes below `target/lorry`",
                    ));
                }
                "rustc-wrapper" | "rustc-workspace-wrapper" => {
                    return Err(Error::at(
                        path,
                        document.line_of_item(item),
                        format!("Cargo `build.{key}` is not supported"),
                        "remove the wrapper; compiler wrappers are outside Stage 2",
                    ));
                }
                _ => unreachable!(),
            }
        }
    }
    if let Some(item) = document.root().get("target") {
        let targets = require_table(path, &document, item, "target")?;
        for (selector, item) in targets.iter() {
            let selector = parse_target_selector(path, document.line_of_item(item), selector)?;
            let options = config.targets.entry(selector).or_default();
            let table = require_table(path, &document, item, "target selector")?;
            reject_unknown_keys(
                path,
                &document,
                table,
                "target",
                &["linker", "runner", "rustflags"],
            )?;
            for (key, item) in table.iter() {
                match key {
                    "linker" => {
                        let value = require_string(path, &document, item, "target.linker")?;
                        options.linker = Some(resolve_program_path(definition_root, &value));
                    }
                    "runner" => {
                        let mut value = argument_words(path, &document, item, "target.runner")?;
                        if value.is_empty() {
                            return Err(Error::at(
                                path,
                                document.line_of_item(item),
                                "target runner cannot be empty",
                                "configure an executable and optional arguments",
                            ));
                        }
                        value[0] = resolve_program_path(definition_root, &value[0])
                            .to_string_lossy()
                            .into_owned();
                        options.runner = Some(value);
                    }
                    "rustflags" => options.rustflags.extend(argument_words(
                        path,
                        &document,
                        item,
                        "target.rustflags",
                    )?),
                    _ => unreachable!(),
                }
            }
        }
    }
    if let Some(item) = document.root().get("resolver") {
        let resolver = require_table(path, &document, item, "resolver")?;
        reject_unknown_keys(
            path,
            &document,
            resolver,
            "resolver",
            &["incompatible-rust-versions"],
        )?;
        if let Some(item) = resolver.get("incompatible-rust-versions") {
            config.incompatible_rust_versions = Some(parse_incompatible_rust_versions(
                path,
                &document,
                item,
                "resolver.incompatible-rust-versions",
            )?);
        }
    }
    Ok(())
}

fn apply_cargo_environment(
    environment: &BTreeMap<String, String>,
    config: &mut Config,
) -> Result<()> {
    if let Some(target) = environment.get("CARGO_BUILD_TARGET") {
        validate_target(target)?;
        config.default_target = Some(target.clone());
    }
    if let Some(flags) = environment.get("CARGO_BUILD_RUSTFLAGS") {
        config.build_rustflags = split_words(flags).map_err(|message| {
            Error::failure(format!("invalid `CARGO_BUILD_RUSTFLAGS`: {message}"))
        })?;
    }
    if let Some(value) = environment.get("CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS") {
        config.incompatible_rust_versions = Some(match value.as_str() {
            "allow" => IncompatibleRustVersions::Allow,
            "fallback" => IncompatibleRustVersions::Fallback,
            _ => {
                return Err(Error::failure(format!(
                    "invalid `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS` value `{value}`; expected `allow` or `fallback`"
                )));
            }
        });
    }

    const PREFIX: &str = "CARGO_TARGET_";
    for (key, value) in environment {
        let Some(suffix) = key.strip_prefix(PREFIX) else {
            continue;
        };
        let (encoded, field) = if let Some(target) = suffix.strip_suffix("_LINKER") {
            (target, "linker")
        } else if let Some(target) = suffix.strip_suffix("_RUNNER") {
            (target, "runner")
        } else if let Some(target) = suffix.strip_suffix("_RUSTFLAGS") {
            (target, "rustflags")
        } else {
            continue;
        };
        let target = config
            .default_target
            .iter()
            .chain(config.targets.keys().filter_map(|selector| match selector {
                TargetSelector::Triple(target) => Some(target),
                TargetSelector::Cfg(_) => None,
            }))
            .find(|target| encode_target_environment(target) == encoded)
            .cloned()
            .unwrap_or_else(|| decode_target_environment(encoded));
        validate_target(&target)?;
        let options = config
            .targets
            .entry(TargetSelector::Triple(target))
            .or_default();
        match field {
            "linker" => options.linker = Some(PathBuf::from(value)),
            "runner" => {
                options.runner =
                    Some(split_words(value).map_err(|message| {
                        Error::failure(format!("invalid `{key}`: {message}"))
                    })?);
            }
            "rustflags" => {
                options.rustflags = split_words(value)
                    .map_err(|message| Error::failure(format!("invalid `{key}`: {message}")))?;
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}

fn parse_incompatible_rust_versions(
    path: &Path,
    document: &Document,
    item: &Item,
    name: &str,
) -> Result<IncompatibleRustVersions> {
    match item.as_str() {
        Some("allow") => Ok(IncompatibleRustVersions::Allow),
        Some("fallback") => Ok(IncompatibleRustVersions::Fallback),
        Some(value) => Err(Error::at(
            path,
            document.line_of_item(item),
            format!("unsupported `{name}` value `{value}`"),
            "choose `allow` or `fallback`",
        )),
        None => Err(type_error(path, document, item, name, "a string")),
    }
}

pub fn environment_rustflags() -> Result<Option<Vec<String>>> {
    if let Some(encoded) = env::var_os("CARGO_ENCODED_RUSTFLAGS") {
        let encoded = encoded
            .into_string()
            .map_err(|_| Error::failure("`CARGO_ENCODED_RUSTFLAGS` contains non-Unicode data"))?;
        return Ok(Some(encoded.split('\u{1f}').map(str::to_owned).collect()));
    }
    if let Some(flags) = env::var_os("RUSTFLAGS") {
        let flags = flags
            .into_string()
            .map_err(|_| Error::failure("`RUSTFLAGS` contains non-Unicode data"))?;
        return split_words(&flags)
            .map(Some)
            .map_err(|message| Error::failure(format!("invalid `RUSTFLAGS`: {message}")));
    }
    Ok(None)
}

fn parse_target_selector(path: &Path, line: usize, value: &str) -> Result<TargetSelector> {
    if value.starts_with("cfg(") && value.ends_with(')') {
        if value.len() <= 5 {
            return Err(Error::at(
                path,
                line,
                "empty Cargo target cfg selector",
                "use a non-empty cfg expression",
            ));
        }
        Ok(TargetSelector::Cfg(value.to_owned()))
    } else {
        validate_target_at(path, line, value)?;
        Ok(TargetSelector::Triple(value.to_owned()))
    }
}

fn validate_target(target: &str) -> Result<()> {
    validate_target_at(Path::new("<configuration>"), 1, target)
}

fn validate_target_at(path: &Path, line: usize, target: &str) -> Result<()> {
    let valid = !target.is_empty()
        && !target.ends_with(".json")
        && target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err(Error::at(
            path,
            line,
            format!("unsupported target `{target}`"),
            "use an installed target triple; custom JSON targets are deferred",
        ));
    }
    Ok(())
}

fn resolve_program_path(definition_root: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() || !value.contains('/') {
        path.to_path_buf()
    } else {
        definition_root.join(path)
    }
}

fn require_table<'a>(
    path: &Path,
    document: &Document,
    item: &'a Item,
    name: &str,
) -> Result<&'a Table> {
    item.as_table()
        .ok_or_else(|| type_error(path, document, item, name, "a TOML table"))
}

fn reject_unknown_keys(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    allowed: &[&str],
) -> Result<()> {
    for (key, item) in table.iter() {
        if !allowed.contains(&key) {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported configuration key `{table_name}.{key}`"),
                "remove the unknown key",
            ));
        }
    }
    Ok(())
}

fn required_string(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<String> {
    let item = table.get(key).ok_or_else(|| {
        Error::at(
            path,
            document.line_of_table(table),
            format!("configuration table `{table_name}` is missing `{key}`"),
            "add the required string value",
        )
    })?;
    require_string(path, document, item, &format!("{table_name}.{key}"))
}

fn optional_string(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<Option<String>> {
    table
        .get(key)
        .map(|item| require_string(path, document, item, &format!("{table_name}.{key}")))
        .transpose()
}

fn require_string(path: &Path, document: &Document, item: &Item, name: &str) -> Result<String> {
    item.as_str()
        .map(str::to_owned)
        .ok_or_else(|| type_error(path, document, item, name, "a string"))
}

fn require_bool(path: &Path, document: &Document, item: &Item, name: &str) -> Result<bool> {
    item.as_bool()
        .ok_or_else(|| type_error(path, document, item, name, "a boolean"))
}

fn optional_bool(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<Option<bool>> {
    table
        .get(key)
        .map(|item| require_bool(path, document, item, &format!("{table_name}.{key}")))
        .transpose()
}

fn require_string_array(
    path: &Path,
    document: &Document,
    item: &Item,
    name: &str,
) -> Result<Vec<String>> {
    let array = item
        .as_array()
        .ok_or_else(|| type_error(path, document, item, name, "an array of strings"))?;
    array
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                Error::at(
                    path,
                    document.line_of_value(value),
                    format!("`{name}` must contain only strings"),
                    "remove the non-string array item",
                )
            })
        })
        .collect()
}

fn argument_words(
    path: &Path,
    document: &Document,
    item: &Item,
    name: &str,
) -> Result<Vec<String>> {
    if item.as_array().is_some() {
        require_string_array(path, document, item, name)
    } else if let Some(value) = item.as_str() {
        split_words(value).map_err(|message| {
            Error::at(
                path,
                document.line_of_item(item),
                format!("invalid argument string for `{name}`: {message}"),
                "use an argument array when values contain complex quoting",
            )
        })
    } else {
        Err(type_error(
            path,
            document,
            item,
            name,
            "a string or string array",
        ))
    }
}

fn absolute_path(path: &Path, document: &Document, item: &Item, name: &str) -> Result<PathBuf> {
    let value = require_string(path, document, item, name)?;
    canonical_config_path(path, document.line_of_item(item), name, &value)
}

fn canonical_config_path(path: &Path, line: usize, name: &str, value: &str) -> Result<PathBuf> {
    let candidate = Path::new(value);
    if !candidate.is_absolute()
        || candidate
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(Error::at(
            path,
            line,
            format!("configured `{name}` must be an absolute normalized path"),
            "use an absolute path without `.` or `..` components",
        ));
    }
    let mut existing = candidate;
    let mut tail = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name() else {
            break;
        };
        tail.push(name.to_os_string());
        existing = existing.parent().unwrap_or_else(|| Path::new("/"));
    }
    let mut result = fs::canonicalize(existing).map_err(|error| {
        Error::at(
            path,
            line,
            format!("failed to canonicalize configured `{name}`: {error}"),
            "use a path beneath an accessible existing directory",
        )
    })?;
    for component in tail.into_iter().rev() {
        result.push(component);
    }
    Ok(result)
}

fn positive_integer(path: &Path, document: &Document, item: &Item, name: &str) -> Result<u64> {
    match item.as_integer() {
        Some(value) if value > 0 => Ok(value as u64),
        _ => Err(Error::at(
            path,
            document.line_of_item(item),
            format!("`{name}` must be a positive integer"),
            "use a finite value greater than zero",
        )),
    }
}

fn native_arguments(
    path: &Path,
    document: &Document,
    item: &Item,
    name: &str,
) -> Result<Vec<String>> {
    let arguments = require_string_array(path, document, item, name)?;
    for argument in &arguments {
        if argument.is_empty()
            || argument
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_whitespace())
        {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("`{name}` contains an empty, whitespace-bearing, or NUL argument"),
                "use one non-empty argument per array element",
            ));
        }
    }
    Ok(arguments)
}

fn parse_native_role(path: &Path, line: usize, value: &str) -> Result<NativeToolRole> {
    match value {
        "c-compiler" => Ok(NativeToolRole::CCompiler),
        "archiver" => Ok(NativeToolRole::Archiver),
        _ => Err(Error::at(
            path,
            line,
            format!("unsupported native-tool role `{value}`"),
            "Stage 2 supports only c-compiler and archiver",
        )),
    }
}

fn parse_native_roles(
    path: &Path,
    document: &Document,
    item: &Item,
) -> Result<BTreeSet<NativeToolRole>> {
    let mut output = BTreeSet::new();
    for value in require_string_array(path, document, item, "policy rule native-tools")? {
        let role = parse_native_role(path, document.line_of_item(item), &value)?;
        if !output.insert(role) {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("duplicate native-tool role `{value}`"),
                "list each granted role once",
            ));
        }
    }
    Ok(output)
}

fn optional_digest(
    path: &Path,
    document: &Document,
    table: &Table,
    id: &str,
    key: &str,
) -> Result<Option<String>> {
    optional_string(path, document, table, id, key)?
        .map(|value| {
            if is_hex(&value, 64) {
                Ok(value)
            } else {
                Err(Error::at(
                    path,
                    document.line_of_table(table),
                    format!("`{id}.{key}` must be a lowercase SHA-256 digest"),
                    "use exactly 64 lowercase hexadecimal digits",
                ))
            }
        })
        .transpose()
}

fn required_digest(
    path: &Path,
    document: &Document,
    table: &Table,
    id: &str,
    key: &str,
) -> Result<String> {
    optional_digest(path, document, table, id, key)?.ok_or_else(|| {
        Error::at(
            path,
            document.line_of_table(table),
            format!("required patch `{id}` is missing `{key}`"),
            "pin the reviewed SHA-256 digest",
        )
    })
}

fn parse_requirement(path: &Path, line: usize, value: &str) -> Result<VersionReq> {
    VersionReq::parse(value).map_err(|error| {
        Error::at(
            path,
            line,
            format!("invalid semantic version requirement `{value}`: {error}"),
            "use a Cargo-compatible semantic version requirement",
        )
    })
}

fn parse_exact_requirement(path: &Path, line: usize, value: &str) -> Result<VersionReq> {
    let requirement = parse_requirement(path, line, value)?;
    if requirement.comparators.len() != 1
        || requirement.comparators[0].op != Op::Exact
        || requirement.comparators[0].minor.is_none()
        || requirement.comparators[0].patch.is_none()
    {
        return Err(Error::at(
            path,
            line,
            format!("required patch version `{value}` is not exact"),
            "use `=major.minor.patch`",
        ));
    }
    Ok(requirement)
}

fn validate_rule_id(path: &Path, line: usize, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::at(
            path,
            line,
            format!("invalid policy/patch rule ID `{value}`"),
            "use ASCII letters, digits, `-`, and `_`",
        ));
    }
    Ok(())
}

fn validate_constraint_key(path: &Path, line: usize, value: &str) -> Result<()> {
    if value.is_empty()
        || !value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(Error::at(
            path,
            line,
            format!("invalid locked configuration prefix `{value}`"),
            "use a dotted sequence of configuration key names",
        ));
    }
    Ok(())
}

fn validate_package_name(path: &Path, line: usize, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::at(
            path,
            line,
            format!("invalid package name `{value}`"),
            "use ASCII letters, digits, `-`, and `_`",
        ));
    }
    Ok(())
}

fn validate_https_git_url(path: &Path, line: usize, value: &str) -> Result<()> {
    if !value.starts_with("https://")
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(Error::at(
            path,
            line,
            format!("required patch Git URL `{value}` is not a plain public HTTPS URL"),
            "use an https:// URL without credentials, query, or fragment",
        ));
    }
    Ok(())
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn type_error(path: &Path, document: &Document, item: &Item, name: &str, expected: &str) -> Error {
    Error::at(
        path,
        document.line_of_item(item),
        format!("configuration key `{name}` must be {expected}"),
        "use the supported TOML value type",
    )
}

fn encode_target_environment(target: &str) -> String {
    target.to_ascii_uppercase().replace('-', "_")
}

fn decode_target_environment(encoded: &str) -> String {
    if let Some(rest) = encoded.strip_prefix("X86_64_") {
        format!("x86_64-{}", rest.to_ascii_lowercase().replace('_', "-"))
    } else {
        encoded.to_ascii_lowercase().replace('_', "-")
    }
}

fn nearest_file(start: &Path, name: &str) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

fn same_path(left: &Path, right: &Path) -> bool {
    fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf())
        == fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf())
}

fn split_words(value: &str) -> std::result::Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for character in value.chars() {
        if escaped {
            word.push(character);
            escaped = false;
            started = true;
        } else if character == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
        } else if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
                started = true;
            } else {
                word.push(character);
            }
        } else if character.is_whitespace() && quote.is_none() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            word.push(character);
            started = true;
        }
    }
    if escaped {
        return Err("trailing backslash".to_owned());
    }
    if let Some(quote) = quote {
        return Err(format!("unterminated `{quote}` quote"));
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    #[test]
    fn default_test_extraction_root_follows_the_execution_target() {
        let defaults = TestConfig::default();
        assert_eq!(
            defaults.extraction_root("x86_64-unknown-linux-gnu"),
            Path::new("/tmp/lorry-tests")
        );
        assert_eq!(
            defaults.extraction_root("x86_64-unknown-motor"),
            Path::new("/user/tmp/lorry/test-extraction")
        );

        let configured = TestConfig {
            extraction_root: Some(PathBuf::from("/explicit")),
        };
        assert_eq!(
            configured.extraction_root("x86_64-unknown-motor"),
            Path::new("/explicit")
        );
    }

    impl TempDir {
        fn new() -> Self {
            let path = env::temp_dir().join(format!(
                "lorry-config-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn layers_lorry_and_cargo_configuration() {
        let temp = TempDir::new();
        let home = temp.0.join("home");
        let package = temp.0.join("work/pkg");
        fs::create_dir_all(home.join(".config/lorry")).unwrap();
        fs::create_dir_all(home.join(".cargo")).unwrap();
        fs::create_dir_all(package.join(".cargo")).unwrap();
        fs::write(
            home.join(".config/lorry/lorry.toml"),
            format!(
                "config-version = 1\ncargo-compat-version = \"1.97\"\n\
                 [toolchain]\nrustc = \"/base/rustc\"\n\
                 [repositories]\nsystem = \"{}\"\nuser = \"{}\"\n",
                temp.0.join("system").display(),
                temp.0.join("user").display(),
            ),
        )
        .unwrap();
        fs::write(
            package.join("lorry.toml"),
            format!(
                "config-version = 1\ncargo-compat-version = \"1.98\"\n\
                 [repositories]\nlocal = \"{}\"\n",
                temp.0.join("local").display()
            ),
        )
        .unwrap();
        fs::write(
            home.join(".cargo/config.toml"),
            "[build]\ntarget = \"x86_64-unknown-linux-musl\"\nrustflags = [\n\
             \"--cfg\",\n\"base\",\n]\n\
             [resolver]\nincompatible-rust-versions = \"fallback\"\n",
        )
        .unwrap();
        fs::write(
            package.join(".cargo/config.toml"),
            "[build]\nrustflags = \"--cfg local\"\n\
             [target.x86_64-unknown-linux-musl]\n\
             linker = \"tools/ld\"\nrunner = [\"runner\", \"--flag\"]\n",
        )
        .unwrap();

        let environment =
            BTreeMap::from([("HOME".to_owned(), home.to_string_lossy().into_owned())]);
        let config = Config::load_with_environment(&package, &environment).unwrap();
        assert_eq!(config.cargo_compat, Some(CargoCompat::V1_98));
        assert_eq!(config.rustc, Some(PathBuf::from("/base/rustc")));
        assert_eq!(
            config.default_target.as_deref(),
            Some("x86_64-unknown-linux-musl")
        );
        assert_eq!(config.build_rustflags, ["--cfg", "base", "--cfg", "local"]);
        assert_eq!(
            config.incompatible_rust_versions,
            Some(IncompatibleRustVersions::Fallback)
        );
        assert!(config.repositories.system.is_some());
        assert!(config.repositories.user.is_some());
        assert!(config.repositories.local.is_some());
        let target = config
            .target_options("x86_64-unknown-linux-musl", &[])
            .unwrap();
        assert_eq!(target.linker, Some(package.join("tools/ld")));
        assert_eq!(target.runner.unwrap(), ["runner", "--flag"]);
    }

    #[test]
    fn parses_complete_system_policy_and_required_patch() {
        let temp = TempDir::new();
        let config_path = temp.0.join("lorry.toml");
        let system = temp.0.join("system");
        let user = temp.0.join("user");
        let compiler = temp.0.join("llvm");
        let source = format!(
            r#"
config-version = 1
cargo-compat-version = "1.98"

[repositories]
system = "{}"
user = "{}"
keep-artifacts = true
keep-sources = true

[vendor]
targets = [
  "x86_64-unknown-linux-musl",
  "x86_64-unknown-motor",
]
include-host = true

[native-tools."x86_64-unknown-motor".c-compiler]
program = "{}"
prefix-args = ["clang"]
flags = ["--target=x86_64-unknown-motor"]

[policy]
default = "deny"
path-roots = []

[policy.limits]
max-packages = 64
max-depth = 16
max-package-bytes = 16777216
max-extracted-package-bytes = 134217728
max-package-files = 20000
max-transaction-bytes = 268435456
max-extracted-transaction-bytes = 1073741824
build-script-seconds = 300
build-script-output-bytes = 8388608

[required-patches.crates-io.ring-0_17_14]
name = "ring"
version = "=0.17.14"
upstream-checksum = "a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7"
git-url = "https://github.com/moturus/ring.git"
git-commit = "b1dad2579de791d0c31ad33300187e584ba6c268"
source-tree-sha256 = "776e07288265b7ececb54ef5ed914c3a6093f00b49bd4d12d34764325659b351"

[policy.rules.allow-ring-0_17_14]
action = "allow"
name = "ring"
version = "=0.17.14"
source = "system-vendored-path"
source-tree-sha256 = "776e07288265b7ececb54ef5ed914c3a6093f00b49bd4d12d34764325659b351"
license = "Apache-2.0 AND ISC"
allow-build-script = true
native-tools = ["c-compiler", "archiver"]

[system-constraints]
locked = [
  "repositories.system",
  "required-patches.crates-io.ring-0_17_14",
  "policy.rules.allow-ring-0_17_14",
]
"#,
            system.display(),
            user.display(),
            compiler.display(),
        );
        fs::write(&config_path, source).unwrap();
        let mut config = Config::default();
        merge_lorry_file(&config_path, LayerKind::LinuxBase, &mut config).unwrap();
        assert_eq!(config.vendor.targets.len(), 2);
        assert_eq!(config.policy.rules.len(), 1);
        assert_eq!(config.required_patches.len(), 1);
        assert_eq!(config.constraints.len(), 3);
        assert_eq!(
            config
                .native_tools
                .get(&("x86_64-unknown-motor".to_owned(), NativeToolRole::CCompiler))
                .unwrap()
                .prefix_args,
            ["clang"]
        );
    }

    #[test]
    fn enforces_layer_ownership_constraints_and_repository_separation() {
        let temp = TempDir::new();
        let base = temp.0.join("base.toml");
        let local = temp.0.join("local.toml");
        fs::write(
            &base,
            format!(
                "config-version = 1\n[repositories]\nsystem = \"{}\"\n\
                 [policy]\ndefault = \"deny\"\n\
                 [system-constraints]\nlocked = [\"policy.default\"]\n",
                temp.0.join("repo").display()
            ),
        )
        .unwrap();
        fs::write(
            &local,
            format!(
                "config-version = 1\n[repositories]\nlocal = \"{}\"\n\
                 [policy]\ndefault = \"allow\"\n",
                temp.0.join("repo/child").display()
            ),
        )
        .unwrap();
        let mut config = Config::default();
        merge_lorry_file(&base, LayerKind::LinuxBase, &mut config).unwrap();
        let error = merge_lorry_file(&local, LayerKind::Local, &mut config).unwrap_err();
        assert!(error.to_string().contains("locked"));

        fs::write(
            &local,
            format!(
                "config-version = 1\n[repositories]\nsystem = \"{}\"\n",
                temp.0.join("other").display()
            ),
        )
        .unwrap();
        assert!(merge_lorry_file(&local, LayerKind::Local, &mut config).is_err());

        config.repositories.local = Some(temp.0.join("repo/child"));
        assert!(validate_repository_layout(&config.repositories).is_err());
    }

    #[test]
    fn environment_overrides_target_configuration() {
        let temp = TempDir::new();
        let package = temp.0.join("pkg");
        fs::create_dir_all(&package).unwrap();
        let environment = BTreeMap::from([
            ("HOME".to_owned(), temp.0.join("home").display().to_string()),
            (
                "CARGO_BUILD_TARGET".to_owned(),
                "x86_64-unknown-motor".to_owned(),
            ),
            (
                "CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUNNER".to_owned(),
                "motor-run --quiet".to_owned(),
            ),
            (
                "CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS".to_owned(),
                "allow".to_owned(),
            ),
        ]);
        let config = Config::load_with_environment(&package, &environment).unwrap();
        assert_eq!(
            config.default_target.as_deref(),
            Some("x86_64-unknown-motor")
        );
        assert_eq!(
            config
                .target_options("x86_64-unknown-motor", &[])
                .unwrap()
                .runner
                .unwrap(),
            ["motor-run", "--quiet"]
        );
        assert_eq!(
            config.incompatible_rust_versions,
            Some(IncompatibleRustVersions::Allow)
        );
    }

    #[test]
    fn rejects_output_overrides_wrappers_and_unknown_keys() {
        let temp = TempDir::new();
        let package = temp.0.join("pkg");
        fs::create_dir_all(package.join(".cargo")).unwrap();
        let home = temp.0.join("home").display().to_string();
        for variable in [
            "CARGO_TARGET_DIR",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
        ] {
            let environment = BTreeMap::from([
                ("HOME".to_owned(), home.clone()),
                (variable.to_owned(), "".into()),
            ]);
            assert!(Config::load_with_environment(&package, &environment).is_err());
        }

        fs::write(
            package.join(".cargo/config.toml"),
            "[build]\ntarget-dir = \"elsewhere\"\n",
        )
        .unwrap();
        let environment = BTreeMap::from([("HOME".to_owned(), home)]);
        assert!(Config::load_with_environment(&package, &environment).is_err());
    }

    #[test]
    fn splits_cargo_argument_strings_without_a_shell() {
        assert_eq!(
            split_words(r#"one "two words" 'three words' four\ five"#).unwrap(),
            ["one", "two words", "three words", "four five"]
        );
        assert!(split_words("'unterminated").is_err());
    }

    #[test]
    fn required_patch_versions_are_complete_exact_versions() {
        assert!(parse_exact_requirement(Path::new("lorry.toml"), 1, "=1.2.3").is_ok());
        for requirement in ["=1", "=1.2", "^1.2.3", ">=1.2.3"] {
            assert!(
                parse_exact_requirement(Path::new("lorry.toml"), 1, requirement).is_err(),
                "{requirement}"
            );
        }
    }

    #[test]
    fn source_agnostic_native_tool_grants_require_a_tree_digest() {
        let temp = TempDir::new();
        let path = temp.0.join("lorry.toml");
        fs::write(
            &path,
            "config-version = 1\n\
             [policy.rules.native]\n\
             action = \"allow\"\n\
             allow-build-script = true\n\
             native-tools = [\"c-compiler\"]\n",
        )
        .unwrap();
        let error =
            merge_lorry_file(&path, LayerKind::LinuxBase, &mut Config::default()).unwrap_err();
        assert!(error.to_string().contains("source-tree digest"));

        fs::write(
            &path,
            "config-version = 1\n\
             [policy.rules.native]\n\
             action = \"allow\"\n\
             source = \"crates.io\"\n\
             allow-build-script = true\n\
             native-tools = [\"c-compiler\"]\n",
        )
        .unwrap();
        merge_lorry_file(&path, LayerKind::LinuxBase, &mut Config::default()).unwrap();
    }
}
