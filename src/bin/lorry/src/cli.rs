use clap::builder::{NonEmptyStringValueParser, PossibleValuesParser};
use clap::error::ErrorKind as ClapErrorKind;
use clap::{Arg, ArgAction, ArgMatches, Command as ClapCommand};

use crate::diagnostic::{Error, Result};
use crate::manifest::PackageSelection;
use crate::validation::ValidationMode;

mod features;
pub(crate) use features::FeatureSelection;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Color {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cli {
    pub toolchain: Option<String>,
    pub color: Color,
    pub verbosity: Verbosity,
    /// `--use-cargo-registry` or `--no-use-cargo-registry`, if given.
    pub use_cargo_registry: Option<bool>,
    pub lorry_messages: bool,
    pub max_packages: Option<u64>,
    pub selection: PackageSelection,
    pub features: FeatureSelection,
    pub manifest_path: Option<String>,
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Build(BuildOptions),
    CacheClean,
    Check(CheckOptions),
    Clean(CleanOptions),
    Fetch(FetchOptions),
    LocateProject { workspace: bool, plain: bool },
    Metadata(MetadataOptions),
    New { path: String },
    Review,
    Run(RunOptions),
    RustcQuery(RustcQueryOptions),
    Test(TestOptions),
    Tree(TreeOptions),
    Vendor(VendorOptions),
    Help(Option<String>),
    Version,
}

impl Command {
    /// The options shared by the compiling commands: build, check, clippy, run, and test.
    pub fn build_options(&self) -> Option<&BuildOptions> {
        match self {
            Self::Build(options) => Some(options),
            Self::Check(CheckOptions { build, .. })
            | Self::Run(RunOptions { build, .. })
            | Self::Test(TestOptions { build, .. }) => Some(build),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustcQueryOptions {
    pub target: String,
    pub kind: RustcQueryKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustcQueryKind {
    Cfg,
    TargetSpecJson,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildOptions {
    pub release: bool,
    pub profile: Option<String>,
    pub keep_going: bool,
    pub target: Option<String>,
    pub target_dir: Option<String>,
    pub targets: TargetSelection,
    pub validation: ValidationMode,
    pub message_format: MessageFormat,
    pub jobs: Option<Jobs>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Jobs {
    Default,
    Number(i32),
}

impl Jobs {
    fn parse(value: &str) -> std::result::Result<Self, String> {
        if value == "default" {
            return Ok(Self::Default);
        }
        match value.parse::<i32>() {
            Ok(number) if number != 0 => Ok(Self::Number(number)),
            _ => Err("jobs must be a nonzero integer or `default`".to_owned()),
        }
    }

    pub fn resolve(self, cpus: usize) -> usize {
        match self {
            Self::Default => cpus,
            Self::Number(number) if number < 0 => {
                cpus.saturating_add_signed(number as isize).max(1)
            }
            Self::Number(number) => number as usize,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanOptions {
    pub build: BuildOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataOptions {
    pub no_deps: bool,
    pub filter_platform: Option<String>,
    pub format_version_explicit: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchOptions {
    pub targets: Vec<String>,
    pub offline: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageFormat {
    Human,
    Json,
    JsonDiagnosticRenderedAnsi,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckOptions {
    pub build: BuildOptions,
    pub clippy: Option<Vec<String>>,
    pub compile_time_deps: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TargetSelection {
    pub all_targets: bool,
    pub lib: bool,
    pub bins: bool,
    pub bin: Vec<String>,
    pub tests: bool,
    pub test: Vec<String>,
    pub examples: bool,
    pub example: Vec<String>,
    pub benches: bool,
    pub bench: Vec<String>,
}

impl TargetSelection {
    pub(crate) fn expand_patterns(&mut self, members: &[crate::manifest::Manifest]) -> Result<()> {
        if self.all_targets {
            return Ok(());
        }
        for (kind, names, all) in [
            ("bin", &mut self.bin, self.bins),
            ("test", &mut self.test, self.tests),
            ("example", &mut self.example, self.examples),
            ("bench", &mut self.bench, self.benches),
        ] {
            if all || !names.iter().any(|name| name.contains(['*', '?', '[', ']'])) {
                continue;
            }
            let available = members
                .iter()
                .flat_map(|member| &member.targets)
                .filter(|target| target.kind.as_str() == kind)
                .map(|target| target.name.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let mut expanded = std::collections::BTreeSet::new();
            for name in std::mem::take(names) {
                if !name.contains(['*', '?', '[', ']']) {
                    expanded.insert(name);
                    continue;
                }
                let pattern = crate::glob::Pattern::parse(&name).map_err(Error::failure)?;
                let matching = available
                    .iter()
                    .filter(|target| pattern.matches(target))
                    .collect::<Vec<_>>();
                if matching.is_empty() {
                    return Err(Error::failure(format!(
                        "no {kind} target matches pattern `{name}`"
                    ))
                    .with_help(format!(
                        "available {kind} targets: {}",
                        available.iter().copied().collect::<Vec<_>>().join(", ")
                    )));
                }
                expanded.extend(matching.into_iter().map(|target| (*target).to_owned()));
            }
            *names = expanded.into_iter().collect();
        }
        Ok(())
    }

    pub(crate) fn single_binary(&self) -> Option<&str> {
        if self.bin.len() == 1 && !self.lib && !self.bins && !self.selects_dev_targets() {
            Some(&self.bin[0])
        } else {
            None
        }
    }

    pub(crate) fn has_target_selector(&self) -> bool {
        self.all_targets
            || self.lib
            || self.bins
            || !self.bin.is_empty()
            || self.tests
            || !self.test.is_empty()
            || self.examples
            || !self.example.is_empty()
            || self.benches
            || !self.bench.is_empty()
    }

    pub(crate) fn selects_library(&self) -> bool {
        self.all_targets || self.lib || !self.has_target_selector()
    }

    pub(crate) fn selects_binaries(&self) -> bool {
        self.all_targets || self.bins || !self.bin.is_empty() || !self.has_target_selector()
    }

    pub(crate) fn selects_tests(&self) -> bool {
        self.all_targets || self.tests || !self.test.is_empty()
    }

    pub(crate) fn selects_dev_targets(&self) -> bool {
        self.selects_tests()
            || self.benches
            || self.examples
            || !self.example.is_empty()
            || !self.bench.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeOptions {
    pub target: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunOptions {
    pub build: BuildOptions,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestOptions {
    pub build: BuildOptions,
    pub no_run: bool,
    pub no_fail_fast: bool,
    pub bundle: bool,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VendorOptions {
    pub accept_all: bool,
    pub locked: bool,
    pub offline: bool,
    pub mode: VendorMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VendorMode {
    Sync,
    Upgrade(UpgradeOptions),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeOptions {
    pub package: String,
    pub version: String,
}

impl Cli {
    pub fn is_clippy(&self) -> bool {
        matches!(&self.command, Command::Check(options) if options.clippy.is_some())
    }

    /// Parse errors must honor the option before Clap can return a command.
    pub fn lorry_messages_requested(arguments: &[String]) -> bool {
        arguments
            .iter()
            .take_while(|argument| argument.as_str() != "--")
            .any(|argument| argument == "--lorry-messages")
    }

    pub fn jobs(&self) -> Option<Jobs> {
        self.command
            .build_options()
            .and_then(|options| options.jobs)
    }

    pub fn message_format(&self) -> MessageFormat {
        self.command
            .build_options()
            .map_or(MessageFormat::Human, |options| options.message_format)
    }

    pub fn parse<I>(arguments: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut arguments = arguments.into_iter().collect::<Vec<_>>();
        let toolchain = match arguments.first() {
            Some(value) if value.starts_with('+') => {
                if value.len() == 1 {
                    return Err(Error::usage(
                        "toolchain selector `+` is empty",
                        "use the exact installed Motor toolchain name after `+`",
                    ));
                }
                let value = value[1..].to_owned();
                arguments.remove(0);
                Some(value)
            }
            _ => None,
        };

        if let Some(value) = arguments
            .iter()
            .take_while(|value| value.as_str() != "--")
            .enumerate()
            .find(|(index, value)| {
                value.starts_with('+')
                    && !(*index > 0
                        && matches!(arguments[*index - 1].as_str(), "-j" | "--jobs")
                        && value.parse::<i32>().is_ok())
            })
            .map(|(_, value)| value)
        {
            return Err(Error::usage(
                format!("toolchain selector `{value}` is not first"),
                "place `+toolchain` before global options and the command",
            ));
        }

        let matches = command_line()
            .try_get_matches_from(
                std::iter::once("lorry".to_owned()).chain(arguments.iter().cloned()),
            )
            .map_err(clap_error)?;
        if !matches!(
            matches.subcommand_name(),
            Some("run") | Some("rustc") | Some("test") | Some("clippy")
        ) && arguments.iter().any(|argument| argument == "--")
        {
            return Err(Error::usage(
                "this command does not accept arguments after `--`",
                "use `run`, `test`, or `clippy` for trailing arguments",
            ));
        }
        let color = match matches.get_one::<String>("color").map(String::as_str) {
            None | Some("auto") => Color::Auto,
            Some("always") => Color::Always,
            Some("never") => Color::Never,
            Some(_) => unreachable!("Clap restricts --color values"),
        };
        if matches.get_flag("quiet") && matches.get_flag("verbose") {
            return Err(Error::usage(
                "cannot set both --verbose and --quiet",
                "choose one verbosity",
            ));
        }
        let verbosity = if matches.get_flag("quiet") {
            Verbosity::Quiet
        } else if matches.get_flag("verbose") {
            Verbosity::Verbose
        } else {
            Verbosity::Normal
        };
        let use_cargo_registry = match (
            matches.get_flag("use-cargo-registry"),
            matches.get_flag("no-use-cargo-registry"),
        ) {
            (true, true) => {
                return Err(Error::usage(
                    "`--use-cargo-registry` conflicts with `--no-use-cargo-registry`",
                    "pass only one of them",
                ));
            }
            (true, false) => Some(true),
            (false, true) => Some(false),
            (false, false) => None,
        };
        let selection = matches
            .subcommand()
            .map(|(_, command)| PackageSelection {
                packages: values(command, "selected-package"),
                workspace: flag_set(command, "workspace"),
                exclude: values(command, "exclude"),
            })
            .unwrap_or_default();
        let features = matches
            .subcommand()
            .map(|(_, command)| FeatureSelection::parse(command))
            .transpose()?
            .unwrap_or_default();
        let manifest_path = matches
            .subcommand()
            .and_then(|(_, command)| {
                command
                    .try_get_one::<String>("manifest-path")
                    .ok()
                    .flatten()
            })
            .cloned();
        let command = if matches.get_flag("help") {
            if matches.subcommand().is_some() {
                return Err(Error::usage(
                    "`--help` does not accept trailing arguments",
                    "use `lorry help COMMAND` for command-specific help",
                ));
            }
            Command::Help(None)
        } else if matches.get_flag("version") {
            if matches.subcommand().is_some() {
                return Err(Error::usage(
                    "`--version` does not accept trailing arguments",
                    "remove the trailing arguments",
                ));
            }
            Command::Version
        } else {
            parse_command(&matches)?
        };
        if matches!(command, Command::Run(_))
            && selection
                .packages
                .iter()
                .any(|package| !package.contains("://") && package.contains(['*', '?', '[', ']']))
        {
            return Err(Error::usage(
                "package patterns are not allowed for run",
                "select one package by name, version, or package ID",
            ));
        }
        if let Command::Run(options) = &command
            && options
                .build
                .targets
                .bin
                .iter()
                .chain(&options.build.targets.example)
                .any(|name| name.contains(['*', '?', '[', ']']))
        {
            return Err(Error::usage(
                "target patterns are not allowed for run",
                "select one binary or executable example by name",
            ));
        }
        if let Some(enabled) = use_cargo_registry
            && matches!(
                command,
                Command::New { .. } | Command::CacheClean | Command::Clean(_)
            )
        {
            let option = cargo_registry_option(enabled);
            return Err(Error::usage(
                format!("`{option}` does not apply to this command"),
                format!("remove `{option}`"),
            ));
        }
        if matches!(command, Command::Review)
            && (selection != PackageSelection::default() || features != FeatureSelection::default())
        {
            return Err(Error::usage(
                "`review` does not accept package or feature selection",
                "review writes the committed review of the scope recorded by `lorry vendor`; pass selectors to vendor to change that scope",
            ));
        }
        if use_cargo_registry == Some(true) && matches!(command, Command::Review) {
            return Err(Error::usage(
                "`--use-cargo-registry` cannot be combined with `review`",
                "remove `--use-cargo-registry`; review uses verified Lorry repository evidence",
            ));
        }
        Ok(Self {
            toolchain,
            color,
            verbosity,
            use_cargo_registry,
            lorry_messages: matches.get_flag("lorry-messages"),
            max_packages: matches.get_one::<u64>("max-packages").copied(),
            selection,
            features,
            manifest_path,
            command,
        })
    }
}

fn command_line() -> ClapCommand {
    ClapCommand::new("lorry")
        .disable_help_flag(true)
        .disable_version_flag(true)
        .disable_help_subcommand(true)
        .args_override_self(false)
        .arg(flag("lorry-messages").global(true))
        .arg(
            Arg::new("max-packages")
                .long("max-packages")
                .global(true)
                .value_name("N")
                .value_parser(clap::value_parser!(u64).range(1..)),
        )
        .arg(
            flag("quiet")
                .short('q')
                .global(true)
                .conflicts_with("verbose"),
        )
        .arg(
            flag("verbose")
                .short('v')
                .global(true)
                .conflicts_with("quiet"),
        )
        .arg(
            Arg::new("color")
                .long("color")
                .global(true)
                .value_name("WHEN")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(PossibleValuesParser::new(["auto", "always", "never"])),
        )
        .arg(flag("use-cargo-registry"))
        .arg(flag("no-use-cargo-registry"))
        .arg(flag("help").short('h').exclusive(true))
        .arg(flag("version").short('V').exclusive(true))
        .subcommand(
            compile_command("build")
                .args(workspace_selection_arguments())
                .args(target_selection_arguments())
                .arg(flag("keep-going"))
                .arg(message_format_argument())
                .dont_delimit_trailing_values(true),
        )
        .subcommand(
            ClapCommand::new("cache")
                .disable_help_flag(true)
                .dont_delimit_trailing_values(true)
                .subcommand_required(true)
                .subcommand(
                    ClapCommand::new("clean")
                        .disable_help_flag(true)
                        .dont_delimit_trailing_values(true),
                ),
        )
        .subcommand(check_command("check").arg(flag("compile-time-deps")))
        .subcommand(
            check_command("clippy")
                .arg(flag("no-deps"))
                .arg(child_arguments()),
        )
        .subcommand(clean_command().dont_delimit_trailing_values(true))
        .subcommand(
            ClapCommand::new("fetch")
                .disable_help_flag(true)
                .arg(manifest_path_argument())
                .args(locked_offline_arguments())
                .arg(Arg::new("target").long("target").action(ArgAction::Append)),
        )
        .subcommand(locate_project_command())
        .subcommand(metadata_command())
        .subcommand(
            ClapCommand::new("new")
                .disable_help_flag(true)
                .dont_delimit_trailing_values(true)
                .arg(Arg::new("path").value_name("PATH").required(true)),
        )
        .subcommand(
            ClapCommand::new("review")
                .disable_help_flag(true)
                .dont_delimit_trailing_values(true)
                .arg(package_argument())
                .args(feature_selection_arguments())
                .arg(manifest_path_argument()),
        )
        .subcommand(run_command())
        .subcommand(rustc_query_command())
        .subcommand(test_command())
        .subcommand(tree_command())
        .subcommand(vendor_command())
        .subcommand(
            ClapCommand::new("help")
                .disable_help_flag(true)
                .dont_delimit_trailing_values(true)
                .arg(
                    Arg::new("topic")
                        .num_args(0..=1)
                        .value_parser(PossibleValuesParser::new([
                            "build",
                            "cache",
                            "check",
                            "clippy",
                            "clean",
                            "fetch",
                            "locate-project",
                            "metadata",
                            "new",
                            "review",
                            "run",
                            "test",
                            "tree",
                            "vendor",
                            "help",
                        ])),
                ),
        )
}

fn cargo_registry_option(enabled: bool) -> &'static str {
    if enabled {
        "--use-cargo-registry"
    } else {
        "--no-use-cargo-registry"
    }
}

fn flag(name: &'static str) -> Arg {
    Arg::new(name).long(name).action(ArgAction::SetTrue)
}

fn manifest_path_argument() -> Arg {
    Arg::new("manifest-path")
        .long("manifest-path")
        .value_name("PATH")
        .num_args(1)
        .action(ArgAction::Set)
        .value_parser(NonEmptyStringValueParser::new())
        .global(true)
}

fn metadata_command() -> ClapCommand {
    ClapCommand::new("metadata")
        .disable_help_flag(true)
        .dont_delimit_trailing_values(true)
        .arg(manifest_path_argument())
        .args(feature_selection_arguments())
        .arg(
            Arg::new("format-version")
                .long("format-version")
                .value_parser(PossibleValuesParser::new(["1"])),
        )
        .arg(flag("no-deps"))
        .arg(
            Arg::new("filter-platform")
                .long("filter-platform")
                .value_name("TRIPLE")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(NonEmptyStringValueParser::new()),
        )
        .args(locked_offline_arguments())
}

fn locked_offline_arguments() -> [Arg; 3] {
    // These commands already forbid acquisition and lock-file changes.
    ["locked", "offline", "frozen"].map(flag)
}

/// Not built on `build_command`: argument order breaks ties between Clap's suggestions.
fn check_command(name: &'static str) -> ClapCommand {
    ClapCommand::new(name)
        .disable_help_flag(true)
        .dont_delimit_trailing_values(true)
        .arg(package_argument())
        .args(feature_selection_arguments())
        .arg(manifest_path_argument())
        .args(locked_offline_arguments())
        .arg(jobs_argument())
        .arg(profile_argument())
        .arg(flag("release").short('r'))
        .arg(target_dir_argument())
        .arg(target_argument().value_parser(NonEmptyStringValueParser::new()))
        .args(workspace_selection_arguments())
        .arg(flag("keep-going"))
        .args(target_selection_arguments())
        .arg(message_format_argument())
}

fn profile_argument() -> Arg {
    Arg::new("profile")
        .long("profile")
        .value_name("NAME")
        .conflicts_with("release")
        .value_parser(NonEmptyStringValueParser::new())
}

fn target_argument() -> Arg {
    Arg::new("target")
        .long("target")
        .value_name("TRIPLE")
        .num_args(1)
        .action(ArgAction::Set)
}

fn target_dir_argument() -> Arg {
    Arg::new("target-dir")
        .long("target-dir")
        .value_name("DIRECTORY")
        .num_args(1)
        .action(ArgAction::Set)
        .value_parser(NonEmptyStringValueParser::new())
}

fn target_selection_arguments() -> [Arg; 10] {
    let named = |name: &'static str| {
        Arg::new(name)
            .long(name)
            .value_name("NAME")
            .action(ArgAction::Append)
            .value_parser(NonEmptyStringValueParser::new())
    };
    [
        flag("all-targets"),
        flag("lib"),
        flag("bins"),
        named("bin"),
        named("test"),
        flag("tests"),
        flag("examples"),
        named("example"),
        named("bench"),
        flag("benches"),
    ]
}

fn target_selection(options: &ArgMatches) -> TargetSelection {
    TargetSelection {
        all_targets: flag_set(options, "all-targets"),
        lib: flag_set(options, "lib"),
        bins: flag_set(options, "bins"),
        bin: values(options, "bin"),
        tests: flag_set(options, "tests"),
        test: values(options, "test"),
        examples: flag_set(options, "examples"),
        example: values(options, "example"),
        benches: flag_set(options, "benches"),
        bench: values(options, "bench"),
    }
}

fn message_format_argument() -> Arg {
    Arg::new("message-format")
        .long("message-format")
        .value_name("FORMAT")
        .value_parser(parse_message_format)
}

fn parse_message_format(value: &str) -> std::result::Result<MessageFormat, String> {
    let mut format = MessageFormat::Json;
    for component in value.split(',') {
        match component {
            "json" => {}
            "json-diagnostic-rendered-ansi" => format = MessageFormat::JsonDiagnosticRenderedAnsi,
            _ => return Err(format!("unsupported message format `{component}`")),
        }
    }
    Ok(format)
}

fn message_format(matches: &ArgMatches) -> MessageFormat {
    matches
        .try_get_one::<MessageFormat>("message-format")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(MessageFormat::Human)
}

fn tree_command() -> ClapCommand {
    ClapCommand::new("tree")
        .disable_help_flag(true)
        .dont_delimit_trailing_values(true)
        .arg(package_argument())
        .args(feature_selection_arguments())
        .args(workspace_selection_arguments())
        .arg(manifest_path_argument())
        .args(locked_offline_arguments())
        .arg(target_argument().value_parser(NonEmptyStringValueParser::new()))
}

fn locate_project_command() -> ClapCommand {
    ClapCommand::new("locate-project")
        .disable_help_flag(true)
        .dont_delimit_trailing_values(true)
        .arg(flag("workspace"))
        .arg(manifest_path_argument())
        .arg(
            Arg::new("message-format")
                .long("message-format")
                .value_name("FMT")
                .num_args(1)
                .value_parser(PossibleValuesParser::new(["json", "plain"]))
                .ignore_case(true),
        )
}

fn rustc_query_command() -> ClapCommand {
    ClapCommand::new("rustc")
        .disable_help_flag(true)
        .arg(manifest_path_argument())
        .arg(
            Arg::new("unstable-options")
                .short('Z')
                .value_parser(PossibleValuesParser::new(["unstable-options"]))
                .required(true),
        )
        .arg(
            Arg::new("print")
                .long("print")
                .value_parser(PossibleValuesParser::new(["cfg", "target-spec-json"]))
                .required(true),
        )
        .arg(
            Arg::new("target")
                .long("target")
                .value_name("TRIPLE")
                .num_args(1)
                .required(true),
        )
        .arg(
            Arg::new("rustc-arguments")
                .num_args(0..)
                .last(true)
                .allow_hyphen_values(true)
                .action(ArgAction::Append),
        )
}

fn build_command(name: &'static str) -> ClapCommand {
    ClapCommand::new(name)
        .disable_help_flag(true)
        .arg(manifest_path_argument())
        .args_override_self(false)
        .args(locked_offline_arguments())
        .arg(flag("release").short('r'))
        .arg(target_argument())
        .arg(target_dir_argument())
        .arg(package_argument())
}

fn clean_command() -> ClapCommand {
    build_command("clean")
        .arg(flag("workspace"))
        .arg(profile_argument())
}

fn package_argument() -> Arg {
    Arg::new("selected-package")
        .long("package")
        .short('p')
        .value_name("NAME")
        .num_args(1)
        .action(ArgAction::Append)
}

fn workspace_selection_arguments() -> [Arg; 2] {
    [
        flag("workspace"),
        Arg::new("exclude")
            .long("exclude")
            .value_name("SPEC")
            .num_args(1)
            .action(ArgAction::Append)
            .requires("workspace"),
    ]
}

fn feature_selection_arguments() -> [Arg; 3] {
    [
        Arg::new("features")
            .long("features")
            .short('F')
            .value_name("FEATURES")
            .num_args(1)
            .action(ArgAction::Append),
        flag("all-features"),
        flag("no-default-features"),
    ]
}

/// Declares the options that build, run, and test share.
fn compile_command(name: &'static str) -> ClapCommand {
    build_command(name)
        .arg(profile_argument())
        .args(feature_selection_arguments())
        .arg(jobs_argument())
        .arg(flag("strict-validation"))
}

fn jobs_argument() -> Arg {
    Arg::new("jobs")
        .long("jobs")
        .short('j')
        .value_name("N")
        .num_args(1)
        .allow_hyphen_values(true)
        .value_parser(Jobs::parse)
}

fn run_command() -> ClapCommand {
    compile_command("run")
        .mut_arg("selected-package", |argument| {
            argument.action(ArgAction::Set)
        })
        .arg(
            Arg::new("bin")
                .long("bin")
                .value_name("NAME")
                .num_args(1)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("example")
                .long("example")
                .value_name("NAME")
                .action(ArgAction::Set)
                .conflicts_with("bin")
                .value_parser(NonEmptyStringValueParser::new()),
        )
        .arg(message_format_argument())
        .arg(child_arguments())
}

fn test_command() -> ClapCommand {
    compile_command("test")
        .args(workspace_selection_arguments())
        .args(target_selection_arguments())
        .arg(message_format_argument())
        .arg(Arg::new("filter").value_name("NAME").num_args(0..=1))
        .arg(flag("no-run"))
        .arg(flag("no-fail-fast"))
        .arg(flag("keep-going").hide(true))
        .arg(flag("bundle"))
        .arg(child_arguments())
}

fn vendor_command() -> ClapCommand {
    ClapCommand::new("vendor")
        .disable_help_flag(true)
        .dont_delimit_trailing_values(true)
        .args_override_self(false)
        .arg(package_argument())
        .args(workspace_selection_arguments())
        .args(locked_offline_arguments())
        .args(feature_selection_arguments())
        .arg(manifest_path_argument())
        .arg(flag("accept-all"))
        .subcommand(
            ClapCommand::new("upgrade")
                .disable_help_flag(true)
                .dont_delimit_trailing_values(true)
                .arg(Arg::new("package").value_name("PACKAGE").required(true))
                .arg(
                    Arg::new("to")
                        .long("to")
                        .value_name("VERSION")
                        .num_args(1)
                        .required(true),
                ),
        )
}

fn child_arguments() -> Arg {
    Arg::new("arguments")
        .num_args(0..)
        .last(true)
        .allow_hyphen_values(true)
        .action(ArgAction::Append)
}

fn parse_command(matches: &ArgMatches) -> Result<Command> {
    match matches.subcommand() {
        Some(("build", options)) => Ok(Command::Build(build_options(options))),
        Some(("cache", options)) => match options.subcommand() {
            Some(("clean", _)) => Ok(Command::CacheClean),
            Some((name, _)) => unreachable!("unexpected cache subcommand {name}"),
            None => unreachable!("Clap requires a cache subcommand"),
        },
        Some((name @ ("check" | "clippy"), options)) => Ok(Command::Check(CheckOptions {
            build: build_options(options),
            clippy: (name == "clippy").then(|| {
                let mut arguments = values(options, "arguments");
                if options.get_flag("no-deps") {
                    arguments.insert(0, "--no-deps".to_owned());
                }
                arguments
            }),
            compile_time_deps: name == "check" && options.get_flag("compile-time-deps"),
        })),
        Some(("clean", options)) => Ok(Command::Clean(CleanOptions {
            build: build_options(options),
        })),
        Some(("fetch", options)) => Ok(Command::Fetch(FetchOptions {
            targets: values(options, "target"),
            offline: options.get_flag("offline") || options.get_flag("frozen"),
        })),
        Some(("locate-project", options)) => Ok(Command::LocateProject {
            workspace: options.get_flag("workspace"),
            plain: options
                .get_one::<String>("message-format")
                .is_some_and(|format| format.eq_ignore_ascii_case("plain")),
        }),
        Some(("metadata", options)) => Ok(Command::Metadata(MetadataOptions {
            no_deps: options.get_flag("no-deps"),
            filter_platform: options.get_one::<String>("filter-platform").cloned(),
            format_version_explicit: options.contains_id("format-version"),
        })),
        Some(("new", options)) => Ok(Command::New {
            path: options
                .get_one::<String>("path")
                .expect("Clap requires the new package path")
                .clone(),
        }),
        Some(("review", _)) => Ok(Command::Review),
        Some(("run", options)) => Ok(Command::Run(RunOptions {
            build: build_options(options),
            arguments: values(options, "arguments"),
        })),
        Some(("test", options)) => {
            if options.get_flag("keep-going") {
                return Err(Error::usage(
                    "`test --keep-going` is not supported",
                    "use `--no-fail-fast` to run all test targets after a failure",
                ));
            }
            let mut arguments = values(options, "arguments");
            if let Some(filter) = options.get_one::<String>("filter") {
                arguments.insert(0, filter.clone());
            }
            Ok(Command::Test(TestOptions {
                build: build_options(options),
                no_run: options.get_flag("no-run"),
                no_fail_fast: options.get_flag("no-fail-fast"),
                bundle: options.get_flag("bundle"),
                arguments,
            }))
        }
        Some(("tree", options)) => Ok(Command::Tree(TreeOptions {
            target: options.get_one::<String>("target").cloned(),
        })),
        Some(("rustc", options)) => {
            let print = options
                .get_one::<String>("print")
                .expect("Clap requires the rustc print kind");
            let trailing = values(options, "rustc-arguments");
            let kind = match (print.as_str(), trailing.as_slice()) {
                ("cfg", [optimize]) if optimize == "-O" => RustcQueryKind::Cfg,
                ("target-spec-json", [unstable, value])
                    if unstable == "-Z" && value == "unstable-options" =>
                {
                    RustcQueryKind::TargetSpecJson
                }
                _ => {
                    return Err(Error::usage(
                        "unsupported `lorry rustc` query form",
                        "use one of the exact rust-analyzer compatibility queries",
                    ));
                }
            };
            Ok(Command::RustcQuery(RustcQueryOptions {
                target: options
                    .get_one::<String>("target")
                    .expect("Clap requires the rustc target")
                    .clone(),
                kind,
            }))
        }
        Some(("vendor", options)) => {
            let mode = match options.subcommand() {
                None => VendorMode::Sync,
                Some(("upgrade", upgrade)) => {
                    let package = upgrade
                        .get_one::<String>("package")
                        .expect("Clap requires an upgrade package")
                        .clone();
                    let version = upgrade
                        .get_one::<String>("to")
                        .expect("Clap requires an upgrade version")
                        .clone();
                    if semver::Version::parse(&version).is_err() {
                        return Err(Error::usage(
                            format!(
                                "upgrade version `{version}` is not a complete semantic version"
                            ),
                            "use `--to MAJOR.MINOR.PATCH` with optional semantic prerelease/build components",
                        ));
                    }
                    VendorMode::Upgrade(UpgradeOptions { package, version })
                }
                Some((name, _)) => unreachable!("unexpected vendor subcommand {name}"),
            };
            Ok(Command::Vendor(VendorOptions {
                accept_all: options.get_flag("accept-all"),
                locked: options.get_flag("locked") || options.get_flag("frozen"),
                offline: options.get_flag("offline") || options.get_flag("frozen"),
                mode,
            }))
        }
        Some(("help", options)) => Ok(Command::Help(options.get_one::<String>("topic").cloned())),
        Some((name, _)) => unreachable!("unexpected Clap subcommand {name}"),
        None => Err(Error::usage(
            "no command was provided",
            "run `lorry --help` to see the available commands",
        )),
    }
}

fn build_options(matches: &ArgMatches) -> BuildOptions {
    BuildOptions {
        release: matches.get_flag("release"),
        profile: matches
            .try_get_one::<String>("profile")
            .ok()
            .flatten()
            .cloned(),
        keep_going: flag_set(matches, "keep-going"),
        target: matches.get_one::<String>("target").cloned(),
        target_dir: matches.get_one::<String>("target-dir").cloned(),
        targets: target_selection(matches),
        message_format: message_format(matches),
        jobs: matches.try_get_one::<Jobs>("jobs").ok().flatten().copied(),
        validation: if flag_set(matches, "strict-validation") {
            ValidationMode::Strict
        } else {
            ValidationMode::Trusted
        },
    }
}

/// False when the flag is absent or the command does not declare it.
fn flag_set(matches: &ArgMatches, name: &str) -> bool {
    matches
        .try_get_one::<bool>(name)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}

fn values(matches: &ArgMatches, name: &str) -> Vec<String> {
    matches
        .try_get_many::<String>(name)
        .ok()
        .flatten()
        .map(|values| values.cloned().collect())
        .unwrap_or_default()
}

fn clap_error(error: clap::Error) -> Error {
    let cause = match error.kind() {
        ClapErrorKind::UnknownArgument => "unknown option or argument",
        ClapErrorKind::InvalidSubcommand => "unknown command",
        ClapErrorKind::ArgumentConflict => "conflicting or duplicate option",
        ClapErrorKind::InvalidValue => "invalid option value",
        ClapErrorKind::TooManyValues => "too many command-line values",
        ClapErrorKind::TooFewValues | ClapErrorKind::WrongNumberOfValues => {
            "wrong number of option values"
        }
        ClapErrorKind::MissingRequiredArgument => "option is missing its value",
        _ => "invalid command line",
    };
    let rendered = error.to_string();
    let detail = rendered
        .strip_prefix("error: ")
        .unwrap_or(&rendered)
        .trim_end();
    if detail.is_empty() {
        Error::usage(cause, "run `lorry --help` to see the accepted options")
    } else {
        Error::usage(
            format!("{cause}\n{detail}"),
            "run `lorry --help` to see the accepted options",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &[&str]) -> Result<Cli> {
        Cli::parse(input.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn parses_build_with_toolchain_and_globals() {
        let cli = parse(&[
            "+motor-current",
            "--verbose",
            "--color=always",
            "--use-cargo-registry",
            "build",
            "-r",
            "--target",
            "x86_64-unknown-motor",
            "--bin",
            "server",
            "-p",
            "app",
            "--strict-validation",
        ])
        .unwrap();
        assert_eq!(cli.toolchain.as_deref(), Some("motor-current"));
        assert_eq!(cli.verbosity, Verbosity::Verbose);
        assert_eq!(cli.color, Color::Always);
        assert_eq!(cli.use_cargo_registry, Some(true));
        assert_eq!(cli.selection.packages, ["app"]);
        assert_eq!(
            cli.command,
            Command::Build(BuildOptions {
                release: true,
                profile: None,
                keep_going: false,
                target: Some("x86_64-unknown-motor".to_owned()),
                target_dir: None,
                targets: TargetSelection {
                    bin: vec!["server".to_owned()],
                    ..Default::default()
                },
                validation: ValidationMode::Strict,
                message_format: MessageFormat::Human,
                jobs: None,
            })
        );
    }

    #[test]
    fn parses_build_keep_going_without_adding_it_to_run_or_test() {
        let Command::Build(options) = parse(&["build", "--workspace", "--keep-going"])
            .unwrap()
            .command
        else {
            panic!("expected build");
        };
        assert!(options.keep_going);
        for command in ["run", "test"] {
            assert!(parse(&[command, "--keep-going"]).unwrap_err().is_usage());
        }
    }

    #[test]
    fn parses_workspace_package_sets_and_command_restrictions() {
        for command in ["build", "check", "clippy", "test", "tree"] {
            let cli = parse(&[
                command,
                "--workspace",
                "-p",
                "app",
                "-p",
                "tool",
                "--exclude",
                "s*",
                "--exclude",
                "missing",
            ])
            .unwrap();
            assert_eq!(cli.selection.packages, ["app", "tool"]);
            assert!(cli.selection.workspace);
            assert_eq!(cli.selection.exclude, ["s*", "missing"]);
            assert!(
                parse(&[command, "--exclude", "app"])
                    .unwrap_err()
                    .is_usage()
            );
        }
        assert_eq!(
            parse(&["clean", "-p", "app", "-p", "app", "--workspace"])
                .unwrap()
                .selection
                .packages,
            ["app", "app"]
        );
        for input in [
            &["run", "-p", "app", "-p", "app"][..],
            &["run", "--workspace"],
            &["run", "-p", "a*"],
            &["clean", "--workspace", "--exclude", "app"],
        ] {
            assert!(parse(input).unwrap_err().is_usage(), "{input:?}");
        }
    }

    #[test]
    fn parses_shared_feature_syntax_without_losing_qualified_or_weak_names() {
        for command in [
            "build", "check", "clippy", "run", "test", "tree", "metadata", "vendor",
        ] {
            let cli = parse(&[
                command,
                "--features",
                "local,package/feature local",
                "-F",
                "optional?/feature, other",
                "--all-features",
                "--no-default-features",
            ])
            .unwrap();
            assert_eq!(
                cli.features.features,
                ["local", "package/feature", "optional?/feature", "other"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            );
            assert!(cli.features.all && cli.features.no_default);
            assert_eq!(
                parse(&[command, "--features", " , "]).unwrap().features,
                FeatureSelection::default()
            );
            for invalid in ["dep:optional", "package/feature/other"] {
                assert!(
                    parse(&[command, "--features", invalid])
                        .unwrap_err()
                        .is_usage()
                );
            }
        }
        assert!(
            parse(&["clean", "--features", "local"])
                .unwrap_err()
                .is_usage()
        );
    }

    #[test]
    fn parses_clean_profile_and_target_selection() {
        assert_eq!(
            parse(&[
                "clean",
                "--release",
                "--target=x86_64-unknown-motor",
                "--target-dir",
                "/tmp/editor-target",
            ])
            .unwrap()
            .command,
            Command::Clean(CleanOptions {
                build: BuildOptions {
                    release: true,
                    profile: None,
                    keep_going: false,
                    target: Some("x86_64-unknown-motor".to_owned()),
                    target_dir: Some("/tmp/editor-target".to_owned()),
                    targets: TargetSelection::default(),
                    validation: ValidationMode::Trusted,
                    message_format: MessageFormat::Human,
                    jobs: None,
                },
            })
        );
        assert!(parse(&["--use-cargo-registry", "clean"]).is_err());
        assert!(parse(&["--no-use-cargo-registry", "clean"]).is_err());
        assert_eq!(
            parse(&["--no-use-cargo-registry", "build"])
                .unwrap()
                .use_cargo_registry,
            Some(false)
        );
        assert_eq!(parse(&["build"]).unwrap().use_cargo_registry, None);
        assert!(
            parse(&["--use-cargo-registry", "--no-use-cargo-registry", "build"])
                .unwrap_err()
                .to_string()
                .contains("conflicts")
        );
        assert!(parse(&["--no-use-cargo-registry", "review"]).is_ok());
        assert!(parse(&["clean", "--strict-validation"]).is_err());
        assert!(parse(&["clean", "--bin", "server"]).is_err());
        assert!(parse(&["clean", "--target-dir="]).is_err());
    }

    #[test]
    fn parses_exact_rust_analyzer_compatibility_queries() {
        let locate = parse(&[
            "locate-project",
            "--workspace",
            "--manifest-path",
            "/project/Cargo.toml",
        ])
        .unwrap();
        assert_eq!(locate.manifest_path.as_deref(), Some("/project/Cargo.toml"));
        assert_eq!(
            locate.command,
            Command::LocateProject {
                workspace: true,
                plain: false,
            }
        );
        assert_eq!(
            parse(&[
                "rustc",
                "-Z",
                "unstable-options",
                "--print",
                "cfg",
                "--target",
                "x86_64-unknown-motor",
                "--",
                "-O",
            ])
            .unwrap()
            .command,
            Command::RustcQuery(RustcQueryOptions {
                target: "x86_64-unknown-motor".to_owned(),
                kind: RustcQueryKind::Cfg,
            })
        );
        assert_eq!(
            parse(&[
                "rustc",
                "-Zunstable-options",
                "--print=target-spec-json",
                "--target=x86_64-unknown-motor",
                "--",
                "-Z",
                "unstable-options",
            ])
            .unwrap()
            .command,
            Command::RustcQuery(RustcQueryOptions {
                target: "x86_64-unknown-motor".to_owned(),
                kind: RustcQueryKind::TargetSpecJson,
            })
        );
    }

    #[test]
    fn parses_locate_formats_and_harness_filters() {
        for input in [&["locate-project"][..], &["locate-project", "--workspace"]] {
            assert_eq!(
                parse(input).unwrap().command,
                Command::LocateProject {
                    workspace: input.contains(&"--workspace"),
                    plain: false,
                }
            );
        }
        assert_eq!(
            parse(&["locate-project", "--message-format=PLAIN"])
                .unwrap()
                .command,
            Command::LocateProject {
                workspace: false,
                plain: true,
            }
        );
        for no_run in [false, true] {
            let mut input = vec!["test", "matching", "--test", "integration"];
            if no_run {
                input.push("--no-run");
            }
            input.extend(["--", "--exact"]);
            let Command::Test(options) = parse(&input).unwrap().command else {
                panic!("expected test command");
            };
            assert_eq!(options.build.targets.test, ["integration"]);
            assert_eq!(options.arguments, ["matching", "--exact"]);
            assert_eq!(options.no_run, no_run);
            assert!(!options.no_fail_fast);
        }
        let Command::Test(options) = parse(&["test", "--no-run", "--no-fail-fast"])
            .unwrap()
            .command
        else {
            panic!("expected test");
        };
        assert!(options.no_run && options.no_fail_fast);
        let error = parse(&["test", "--keep-going"]).unwrap_err();
        assert!(error.is_usage());
        assert!(error.render().contains("--no-fail-fast"));
    }

    #[test]
    fn rejects_other_cargo_compatibility_forms() {
        for input in [
            &["locate-project", "--message-format", "yaml"][..],
            &["locate-project", "--manifest-path="],
            &["rustc", "--print", "cfg", "--target", "triple", "--", "-O"],
            &[
                "rustc",
                "-Z",
                "unstable-options",
                "--print",
                "cfg",
                "--target",
                "triple",
            ],
            &[
                "rustc",
                "-Z",
                "unstable-options",
                "--print",
                "cfg",
                "--target",
                "triple",
                "--",
                "--crate-type",
                "lib",
            ],
            &["-Z", "unstable-options", "config", "get"],
        ] {
            assert!(parse(input).unwrap_err().is_usage(), "{input:?}");
        }
    }

    #[test]
    fn parses_cargo_form_metadata_and_tree() {
        let metadata = parse(&[
            "metadata",
            "--format-version=1",
            "--no-deps",
            "--manifest-path",
            "/project/Cargo.toml",
            "--filter-platform=x86_64-unknown-motor",
            "--locked",
        ])
        .unwrap();
        assert_eq!(metadata.selection, PackageSelection::default());
        assert_eq!(
            metadata.manifest_path.as_deref(),
            Some("/project/Cargo.toml")
        );
        assert!(parse(&["metadata", "-p", "app"]).unwrap_err().is_usage());
        assert_eq!(
            metadata.command,
            Command::Metadata(MetadataOptions {
                no_deps: true,
                filter_platform: Some("x86_64-unknown-motor".to_owned()),
                format_version_explicit: true,
            })
        );

        let tree = parse(&[
            "tree",
            "--manifest-path=/project/Cargo.toml",
            "--target",
            "x86_64-unknown-motor",
        ])
        .unwrap();
        assert_eq!(tree.manifest_path.as_deref(), Some("/project/Cargo.toml"));
        assert_eq!(
            tree.command,
            Command::Tree(TreeOptions {
                target: Some("x86_64-unknown-motor".to_owned()),
            })
        );
    }

    #[test]
    fn parses_both_rust_analyzer_check_forms() {
        let check = parse(&[
            "check",
            "--quiet",
            "--workspace",
            "--message-format=json",
            "--manifest-path=/project/Cargo.toml",
            "--target-dir=/project/target/rust-analyzer",
            "--target=x86_64-unknown-motor",
            "--keep-going",
            "--all-targets",
        ])
        .unwrap();
        assert_eq!(check.verbosity, Verbosity::Quiet);
        assert!(check.selection.workspace);
        assert_eq!(check.manifest_path.as_deref(), Some("/project/Cargo.toml"));
        assert_eq!(
            check.command,
            Command::Check(CheckOptions {
                build: BuildOptions {
                    release: false,
                    profile: None,
                    keep_going: true,
                    target: Some("x86_64-unknown-motor".to_owned()),
                    target_dir: Some("/project/target/rust-analyzer".to_owned()),
                    targets: TargetSelection {
                        all_targets: true,
                        ..TargetSelection::default()
                    },
                    validation: ValidationMode::Trusted,
                    message_format: MessageFormat::Json,
                    jobs: None,
                },
                clippy: None,
                compile_time_deps: false,
            })
        );

        let Command::Check(flycheck) = parse(&[
            "check",
            "--release",
            "--workspace",
            "--message-format=json-diagnostic-rendered-ansi",
            "--all-targets",
            "--lib",
            "--bins",
            "--examples",
        ])
        .unwrap()
        .command
        else {
            panic!("expected check");
        };
        let flycheck = flycheck.build;
        assert!(
            flycheck.targets.all_targets
                && flycheck.targets.lib
                && flycheck.targets.bins
                && flycheck.targets.examples
        );
        assert!(flycheck.release);
        assert_eq!(
            flycheck.message_format,
            MessageFormat::JsonDiagnosticRenderedAnsi
        );
    }

    #[test]
    fn parses_named_auxiliary_checks() {
        for command in ["check", "clippy"] {
            let Command::Check(options) = parse(&[command, "--example", "demo", "--bench=measure"])
                .unwrap()
                .command
            else {
                panic!("expected check");
            };
            assert_eq!(options.build.targets.example, ["demo"]);
            assert_eq!(options.build.targets.bench, ["measure"]);
            for selector in ["--example", "--bench"] {
                assert!(parse(&[command, selector]).is_err());
                assert!(parse(&[command, selector, ""]).is_err());
            }
        }
    }

    #[test]
    fn build_uses_common_repeated_and_plural_target_selectors() {
        let Command::Build(options) = parse(&[
            "build",
            "--lib",
            "--bin",
            "one",
            "--bin",
            "two",
            "--tests",
            "--test",
            "integration",
            "--examples",
            "--example",
            "demo",
            "--benches",
            "--bench",
            "measure",
            "--all-targets",
        ])
        .unwrap()
        .command
        else {
            panic!("expected build")
        };
        assert!(
            options.targets.lib
                && options.targets.all_targets
                && options.targets.tests
                && options.targets.examples
                && options.targets.benches
        );
        assert_eq!(options.targets.bin, ["one", "two"]);
        assert_eq!(options.targets.test, ["integration"]);
        assert_eq!(options.targets.example, ["demo"]);
        assert_eq!(options.targets.bench, ["measure"]);
    }

    #[test]
    fn test_uses_common_repeated_and_plural_target_selectors() {
        let Command::Test(options) = parse(&[
            "test",
            "--lib",
            "--bin",
            "one",
            "--bin",
            "two",
            "--tests",
            "--test",
            "first",
            "--test",
            "second",
            "--examples",
            "--example",
            "demo",
            "--benches",
            "--bench",
            "measure",
            "--all-targets",
            "filter",
            "--",
            "--nocapture",
        ])
        .unwrap()
        .command
        else {
            panic!("expected test")
        };
        assert!(
            options.build.targets.lib
                && options.build.targets.all_targets
                && options.build.targets.tests
                && options.build.targets.examples
                && options.build.targets.benches
        );
        assert_eq!(options.build.targets.bin, ["one", "two"]);
        assert_eq!(options.build.targets.test, ["first", "second"]);
        assert_eq!(options.build.targets.example, ["demo"]);
        assert_eq!(options.build.targets.bench, ["measure"]);
        assert_eq!(options.arguments, ["filter", "--nocapture"]);
    }

    #[test]
    fn check_targets_accept_repeated_names() {
        for command in ["check", "clippy"] {
            let Command::Check(options) = parse(&[
                command,
                "--bin",
                "one",
                "--bin=two",
                "--test",
                "first",
                "--test=second",
                "--example",
                "demo",
                "--example=library",
                "--bench",
                "a",
                "--bench=b",
            ])
            .unwrap()
            .command
            else {
                panic!("expected check");
            };
            assert_eq!(options.build.targets.bin, ["one", "two"]);
            assert_eq!(options.build.targets.test, ["first", "second"]);
            assert_eq!(options.build.targets.example, ["demo", "library"]);
            assert_eq!(options.build.targets.bench, ["a", "b"]);
        }
    }

    #[test]
    fn parses_plural_check_target_groups() {
        for command in ["check", "clippy"] {
            let Command::Check(options) =
                parse(&[command, "--tests", "--benches"]).unwrap().command
            else {
                panic!("expected check");
            };
            let targets = options.build.targets;
            assert!(targets.tests && targets.benches);
            assert!(targets.selects_dev_targets());
            assert!(!targets.selects_library() && !targets.selects_binaries());
        }
    }

    #[test]
    fn clippy_reuses_check_options_and_preserves_lint_arguments() {
        let cli = parse(&[
            "clippy",
            "--lib",
            "--no-deps",
            "--manifest-path",
            "/project/Cargo.toml",
            "--message-format=json",
            "--",
            "-D",
            "clippy::needless_return",
            "--color=always",
        ])
        .unwrap();
        assert!(cli.is_clippy());
        assert_eq!(cli.manifest_path.as_deref(), Some("/project/Cargo.toml"));
        let Command::Check(options) = cli.command else {
            panic!("expected the shared check path")
        };
        assert!(options.build.targets.lib);
        assert_eq!(
            options.clippy.unwrap(),
            [
                "--no-deps",
                "-D",
                "clippy::needless_return",
                "--color=always"
            ]
        );
        assert!(parse(&["clippy", "--fix"]).is_err());
        assert!(parse(&["check", "--no-deps"]).is_err());
        assert!(parse(&["check", "--", "-D", "warnings"]).is_err());
    }

    #[test]
    fn parses_shared_build_and_check_message_formats() {
        for command in ["build", "check", "clippy", "run", "test"] {
            for (value, expected) in [
                ("json", MessageFormat::Json),
                (
                    "json,json-diagnostic-rendered-ansi",
                    MessageFormat::JsonDiagnosticRenderedAnsi,
                ),
                (
                    "json-diagnostic-rendered-ansi,json",
                    MessageFormat::JsonDiagnosticRenderedAnsi,
                ),
            ] {
                let equals = format!("--message-format={value}");
                assert_eq!(
                    parse(&[command, &equals]).unwrap().message_format(),
                    expected
                );
                assert_eq!(
                    parse(&[command, "--message-format", value])
                        .unwrap()
                        .message_format(),
                    expected
                );
            }
            for value in [
                "",
                "json,",
                "human",
                "json-render-diagnostics",
                "json,short",
            ] {
                assert!(
                    parse(&[command, "--message-format", value])
                        .unwrap_err()
                        .is_usage()
                );
            }
        }
    }

    #[test]
    fn compiler_commands_accept_profiles_with_release_conflicts() {
        for command in ["build", "check", "clippy", "run", "test", "clean"] {
            let cli = parse(&[command, "--profile", "custom"]).unwrap();
            let profile = match cli.command {
                Command::Build(options) => options.profile,
                Command::Check(options) => options.build.profile,
                Command::Run(options) => options.build.profile,
                Command::Test(options) => options.build.profile,
                Command::Clean(options) => options.build.profile,
                _ => unreachable!(),
            };
            assert_eq!(profile.as_deref(), Some("custom"));
            assert!(parse(&[command, "--profile", "custom", "--release"]).is_err());
        }
    }

    #[test]
    fn run_selects_one_example_and_rejects_target_patterns() {
        let Command::Run(options) = parse(&["run", "--example", "demo", "--", "--bin", "arg"])
            .unwrap()
            .command
        else {
            panic!("expected run");
        };
        assert_eq!(options.build.targets.example, ["demo"]);
        assert_eq!(options.arguments, ["--bin", "arg"]);
        for args in [
            &["run", "--example", "demo", "--bin", "app"][..],
            &["run", "--example", "d*"],
            &["run", "--bin", "a?"],
        ] {
            assert!(parse(args).unwrap_err().is_usage());
        }
    }

    #[test]
    fn rejects_unsupported_cargo_form_options() {
        for input in [
            &["metadata", "--format-version", "2"][..],
            &["check", "--message-format=short"],
            &["check", "--target-dir="],
            &["tree", "--target-dir", "out"],
            &["tree", "--manifest-path="],
        ] {
            assert!(parse(input).unwrap_err().is_usage(), "{input:?}");
        }
        assert_eq!(
            parse(&["--quiet", "check", "--quiet"]).unwrap().verbosity,
            Verbosity::Quiet
        );
        assert!(parse(&["--verbose", "check", "--quiet"]).is_err());
    }

    #[test]
    fn global_presentation_options_follow_the_command() {
        for command in [
            "build", "check", "run", "test", "clean", "review", "tree", "vendor",
        ] {
            assert_eq!(
                parse(&[command, "--quiet", "--color=never"]).unwrap(),
                parse(&["--quiet", "--color=never", command]).unwrap()
            );
            assert_eq!(
                parse(&[command, "-v", "--color", "always"]).unwrap(),
                parse(&["-v", "--color", "always", command]).unwrap()
            );
        }
        let Command::Run(options) = parse(&["run", "--", "+value", "--quiet", "--color=never"])
            .unwrap()
            .command
        else {
            panic!("expected run");
        };
        assert_eq!(options.arguments, ["+value", "--quiet", "--color=never"]);
    }

    #[test]
    fn parses_global_cache_clean() {
        assert_eq!(
            parse(&["cache", "clean"]).unwrap().command,
            Command::CacheClean
        );
        assert!(parse(&["cache"]).is_err());
        assert!(parse(&["cache", "clean", "extra"]).is_err());
        assert!(parse(&["--use-cargo-registry", "cache", "clean"]).is_err());
    }

    #[test]
    fn preserves_run_arguments_verbatim() {
        let cli = parse(&[
            "run",
            "--strict-validation",
            "--",
            "--release",
            "two words",
            "",
        ])
        .unwrap();
        let Command::Run(run) = cli.command else {
            panic!("expected run");
        };
        assert_eq!(run.arguments, ["--release", "two words", ""]);
        assert_eq!(run.build.validation, ValidationMode::Strict);
    }

    #[test]
    fn parses_stage_two_test_surface() {
        let cli = parse(&[
            "test",
            "--test=cli",
            "--bundle",
            "--release",
            "--strict-validation",
            "--",
            "--nocapture",
        ])
        .unwrap();
        let Command::Test(test) = cli.command else {
            panic!("expected test");
        };
        assert_eq!(test.build.targets.test, ["cli"]);
        assert!(test.bundle);
        assert!(test.build.release);
        assert_eq!(test.build.validation, ValidationMode::Strict);
        assert_eq!(test.arguments, ["--nocapture"]);
    }

    #[test]
    fn parses_dependency_upgrade_surface() {
        assert_eq!(
            parse(&["vendor", "upgrade", "libc", "--to", "0.2.187"])
                .unwrap()
                .command,
            Command::Vendor(VendorOptions {
                accept_all: false,
                locked: false,
                offline: false,
                mode: VendorMode::Upgrade(UpgradeOptions {
                    package: "libc".to_owned(),
                    version: "0.2.187".to_owned(),
                }),
            })
        );
        let Command::Vendor(automated) = parse(&[
            "vendor",
            "--accept-all",
            "upgrade",
            "libc",
            "--to",
            "0.2.187",
        ])
        .unwrap()
        .command
        else {
            panic!("expected vendor upgrade");
        };
        assert!(automated.accept_all);
        for input in [
            &["vendor", "upgrade"][..],
            &["vendor", "upgrade", "libc"],
            &["vendor", "upgrade", "libc", "--to", "0.2"],
            &["vendor", "upgrade", "--from-cargo-lock"],
        ] {
            assert!(parse(input).is_err(), "{input:?}");
        }
        assert_eq!(
            parse(&["vendor", "-p", "app"]).unwrap().selection.packages,
            ["app"]
        );
    }

    #[test]
    fn parses_help_and_version() {
        assert_eq!(parse(&["-h"]).unwrap().command, Command::Help(None));
        assert_eq!(
            parse(&["help", "build"]).unwrap().command,
            Command::Help(Some("build".to_owned()))
        );
        assert_eq!(parse(&["-V"]).unwrap().command, Command::Version);
    }

    #[test]
    fn parses_new_package_path() {
        assert_eq!(
            parse(&["new", "nested/example-app"]).unwrap().command,
            Command::New {
                path: "nested/example-app".to_owned(),
            }
        );
        assert!(parse(&["--use-cargo-registry", "new", "example"]).is_err());
    }

    #[test]
    fn parses_positive_one_run_package_limits_before_or_after_the_command() {
        assert_eq!(
            parse(&["--max-packages", "384", "metadata"])
                .unwrap()
                .max_packages,
            Some(384)
        );
        assert_eq!(
            parse(&["vendor", "--max-packages=128"])
                .unwrap()
                .max_packages,
            Some(128)
        );
        assert_eq!(parse(&["build"]).unwrap().max_packages, None);
        for limit in ["0", "-1", "words", "18446744073709551616"] {
            assert!(parse(&["build", "--max-packages", limit]).is_err());
        }
    }

    #[test]
    fn parses_offline_review_surface() {
        let cli = parse(&["+motor-current", "--quiet", "--color=never", "review"]).unwrap();
        assert_eq!(cli.toolchain.as_deref(), Some("motor-current"));
        assert_eq!(cli.verbosity, Verbosity::Quiet);
        assert_eq!(cli.color, Color::Never);
        assert_eq!(cli.command, Command::Review);
        assert!(parse(&["review", "extra"]).is_err());
        assert!(parse(&["review", "--anything"]).is_err());
        assert!(parse(&["--use-cargo-registry", "review"]).is_err());
        for selector in [
            &["review", "-p", "app"][..],
            &["review", "--package", "app"],
            &["review", "--features", "extra"],
            &["review", "--all-features"],
            &["review", "--no-default-features"],
        ] {
            let error = parse(selector).unwrap_err();
            assert!(error.is_usage(), "{selector:?}");
            assert!(
                error
                    .render()
                    .contains("does not accept package or feature selection"),
                "{selector:?}"
            );
        }
    }

    #[test]
    fn rejects_duplicates_conflicts_and_missing_values() {
        for input in [
            &["-q", "--quiet", "build"][..],
            &["-q", "-v", "build"],
            &["--color", "auto", "--color=never", "build"],
            &["build", "-r", "--release"],
            &["build", "--target"],
            &["new"],
            &["new", "one", "two"],
            &["new", "example", "--lib"],
            &["test", "first", "second"],
        ] {
            assert!(parse(input).unwrap_err().is_usage(), "{input:?}");
        }
    }

    #[test]
    fn own_messages_are_global_and_stop_at_child_arguments() {
        assert!(
            parse(&["--lorry-messages", "build"])
                .unwrap()
                .lorry_messages
        );
        assert!(
            parse(&["build", "--lorry-messages"])
                .unwrap()
                .lorry_messages
        );
        let child = parse(&["run", "--", "--lorry-messages"]).unwrap();
        assert!(!child.lorry_messages);
        assert!(!Cli::lorry_messages_requested(&[
            "run".to_owned(),
            "--".to_owned(),
            "--lorry-messages".to_owned()
        ]));
    }

    #[test]
    fn parses_cargo_job_limits_for_every_compile_command() {
        for command in ["build", "check", "run", "test"] {
            assert_eq!(
                parse(&[command, "-j2"]).unwrap().jobs(),
                Some(Jobs::Number(2))
            );
            assert_eq!(
                parse(&[command, "--jobs", "default"]).unwrap().jobs(),
                Some(Jobs::Default)
            );
            assert_eq!(
                parse(&[command, "--jobs=-1"]).unwrap().jobs(),
                Some(Jobs::Number(-1))
            );
            assert_eq!(
                parse(&[command, "-j", "-2"]).unwrap().jobs(),
                Some(Jobs::Number(-2))
            );
            assert_eq!(
                parse(&[command, "-j", "+2"]).unwrap().jobs(),
                Some(Jobs::Number(2))
            );
            for value in ["0", "invalid", "1.5", "2147483648", ""] {
                assert!(parse(&[command, "--jobs", value]).unwrap_err().is_usage());
            }
        }
        assert!(parse(&["clean", "--jobs=2"]).is_err());
        assert_eq!(Jobs::Default.resolve(8), 8);
        assert_eq!(Jobs::Number(-1).resolve(8), 7);
        assert_eq!(Jobs::Number(i32::MIN).resolve(8), 1);
    }

    #[test]
    fn accepts_locked_offline_flags_without_changing_offline_commands() {
        for command in ["build", "check", "run", "test", "clean", "metadata", "tree"] {
            let ordinary = parse(&[command]).unwrap();
            for flag in ["--locked", "--offline", "--frozen"] {
                assert_eq!(parse(&[command, flag]).unwrap(), ordinary);
            }
            assert_eq!(
                parse(&[command, "--locked", "--offline", "--frozen"]).unwrap(),
                ordinary
            );
        }
        for command in ["review", "new", "cache"] {
            for flag in ["--locked", "--offline", "--frozen"] {
                assert!(parse(&[command, flag]).unwrap_err().is_usage());
            }
        }
        let Command::Run(run) = parse(&["run", "--offline", "--", "--frozen"])
            .unwrap()
            .command
        else {
            panic!("expected run");
        };
        assert_eq!(run.arguments, ["--frozen"]);
    }

    #[test]
    fn defaults_metadata_to_version_one_without_marking_it_explicit() {
        let Command::Metadata(default) = parse(&["metadata"]).unwrap().command else {
            panic!("expected metadata");
        };
        assert!(!default.format_version_explicit);
        assert!(parse(&["metadata", "--format-version=2"]).is_err());
    }

    #[test]
    fn rejects_misplaced_and_unknown_syntax() {
        for input in [
            &[][..],
            &["build", "+motor-current"],
            &["build", "--"],
            &["frobnicate"],
            &["help", "unknown"],
            &["--version", "build"],
            &["+"],
        ] {
            let result = parse(input);
            assert!(
                result.as_ref().is_err_and(Error::is_usage),
                "{input:?}: {result:?}"
            );
        }

        let unknown = parse(&["build", "--unknown-option"]).unwrap_err();
        assert!(unknown.render().starts_with("error: unknown option"));
        assert!(!unknown.render().contains("\nerror:"));
    }
}
