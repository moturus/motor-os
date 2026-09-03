use clap::builder::PossibleValuesParser;
use clap::error::ErrorKind as ClapErrorKind;
use clap::{Arg, ArgAction, ArgMatches, Command as ClapCommand};

use crate::diagnostic::{Error, Result};
use crate::validation::ValidationMode;

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
    pub use_cargo_registry: bool,
    pub package: Option<String>,
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Build(BuildOptions),
    CacheClean,
    Clean(BuildOptions),
    New { path: String },
    Review,
    Run(RunOptions),
    Test(TestOptions),
    Vendor(VendorOptions),
    Help(Option<String>),
    Version,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildOptions {
    pub release: bool,
    pub target: Option<String>,
    pub bin: Option<String>,
    pub validation: ValidationMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunOptions {
    pub build: BuildOptions,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestOptions {
    pub build: BuildOptions,
    pub test: Option<String>,
    pub no_run: bool,
    pub bundle: bool,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VendorOptions {
    pub accept_all: bool,
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

        if let Some(value) = arguments.iter().find(|value| value.starts_with('+')) {
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
        if !matches!(matches.subcommand_name(), Some("run") | Some("test"))
            && arguments.iter().any(|argument| argument == "--")
        {
            return Err(Error::usage(
                "this command does not accept arguments after `--`",
                "only `run` and executable `test` commands accept child arguments",
            ));
        }
        let color = match matches.get_one::<String>("color").map(String::as_str) {
            None | Some("auto") => Color::Auto,
            Some("always") => Color::Always,
            Some("never") => Color::Never,
            Some(_) => unreachable!("Clap restricts --color values"),
        };
        let verbosity = if matches.get_flag("quiet") {
            Verbosity::Quiet
        } else if matches.get_flag("verbose") {
            Verbosity::Verbose
        } else {
            Verbosity::Normal
        };
        let use_cargo_registry = matches.get_flag("use-cargo-registry");
        let package = matches
            .subcommand()
            .and_then(|(_, command)| {
                command
                    .try_get_one::<String>("selected-package")
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
        if use_cargo_registry
            && matches!(
                command,
                Command::New { .. } | Command::CacheClean | Command::Clean(_)
            )
        {
            return Err(Error::usage(
                "`--use-cargo-registry` does not apply to this command",
                "remove `--use-cargo-registry`",
            ));
        }
        if use_cargo_registry && matches!(command, Command::Review) {
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
            package,
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
        .arg(
            Arg::new("quiet")
                .long("quiet")
                .short('q')
                .action(ArgAction::SetTrue)
                .conflicts_with("verbose"),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .action(ArgAction::SetTrue)
                .conflicts_with("quiet"),
        )
        .arg(
            Arg::new("color")
                .long("color")
                .value_name("WHEN")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(PossibleValuesParser::new(["auto", "always", "never"])),
        )
        .arg(
            Arg::new("use-cargo-registry")
                .long("use-cargo-registry")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .action(ArgAction::SetTrue)
                .exclusive(true),
        )
        .arg(
            Arg::new("version")
                .long("version")
                .short('V')
                .action(ArgAction::SetTrue)
                .exclusive(true),
        )
        .subcommand(compile_command("build", true).dont_delimit_trailing_values(true))
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
        .subcommand(build_command("clean").dont_delimit_trailing_values(true))
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
                .arg(package_argument()),
        )
        .subcommand(run_command())
        .subcommand(test_command())
        .subcommand(vendor_command())
        .subcommand(
            ClapCommand::new("help")
                .disable_help_flag(true)
                .dont_delimit_trailing_values(true)
                .arg(
                    Arg::new("topic")
                        .num_args(0..=1)
                        .value_parser(PossibleValuesParser::new([
                            "build", "cache", "clean", "new", "review", "run", "test", "vendor",
                            "help",
                        ])),
                ),
        )
}

fn build_command(name: &'static str) -> ClapCommand {
    ClapCommand::new(name)
        .disable_help_flag(true)
        .args_override_self(false)
        .arg(
            Arg::new("release")
                .long("release")
                .short('r')
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("target")
                .long("target")
                .value_name("TRIPLE")
                .num_args(1)
                .action(ArgAction::Set),
        )
        .arg(package_argument())
}

fn package_argument() -> Arg {
    Arg::new("selected-package")
        .long("package")
        .short('p')
        .value_name("NAME")
        .num_args(1)
        .action(ArgAction::Set)
}

fn compile_command(name: &'static str, supports_bin: bool) -> ClapCommand {
    let command = build_command(name).arg(
        Arg::new("strict-validation")
            .long("strict-validation")
            .action(ArgAction::SetTrue),
    );
    if supports_bin {
        command.arg(
            Arg::new("bin")
                .long("bin")
                .value_name("NAME")
                .num_args(1)
                .action(ArgAction::Set),
        )
    } else {
        command
    }
}

fn run_command() -> ClapCommand {
    compile_command("run", true).arg(child_arguments())
}

fn test_command() -> ClapCommand {
    compile_command("test", false)
        .arg(
            Arg::new("test")
                .long("test")
                .value_name("NAME")
                .num_args(1)
                .action(ArgAction::Set),
        )
        .arg(Arg::new("no-run").long("no-run").action(ArgAction::SetTrue))
        .arg(Arg::new("bundle").long("bundle").action(ArgAction::SetTrue))
        .arg(child_arguments())
}

fn vendor_command() -> ClapCommand {
    ClapCommand::new("vendor")
        .disable_help_flag(true)
        .dont_delimit_trailing_values(true)
        .args_override_self(false)
        .arg(package_argument())
        .arg(
            Arg::new("accept-all")
                .long("accept-all")
                .action(ArgAction::SetTrue),
        )
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
        Some(("build", options)) => Ok(Command::Build(build_options(options, true))),
        Some(("cache", options)) => match options.subcommand() {
            Some(("clean", _)) => Ok(Command::CacheClean),
            Some((name, _)) => unreachable!("unexpected cache subcommand {name}"),
            None => unreachable!("Clap requires a cache subcommand"),
        },
        Some(("clean", options)) => Ok(Command::Clean(build_options(options, false))),
        Some(("new", options)) => Ok(Command::New {
            path: options
                .get_one::<String>("path")
                .expect("Clap requires the new package path")
                .clone(),
        }),
        Some(("review", _)) => Ok(Command::Review),
        Some(("run", options)) => Ok(Command::Run(RunOptions {
            build: build_options(options, true),
            arguments: values(options, "arguments"),
        })),
        Some(("test", options)) => {
            let arguments = values(options, "arguments");
            if options.get_flag("no-run") && !arguments.is_empty() {
                return Err(Error::usage(
                    "test arguments cannot be combined with `--no-run`",
                    "remove the arguments after `--` or remove `--no-run`",
                ));
            }
            Ok(Command::Test(TestOptions {
                build: build_options(options, true),
                test: options.get_one::<String>("test").cloned(),
                no_run: options.get_flag("no-run"),
                bundle: options.get_flag("bundle"),
                arguments,
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

fn build_options(matches: &ArgMatches, supports_validation: bool) -> BuildOptions {
    BuildOptions {
        release: matches.get_flag("release"),
        target: matches.get_one::<String>("target").cloned(),
        bin: matches.try_get_one::<String>("bin").ok().flatten().cloned(),
        validation: if supports_validation && matches.get_flag("strict-validation") {
            ValidationMode::Strict
        } else {
            ValidationMode::Trusted
        },
    }
}

fn values(matches: &ArgMatches, name: &str) -> Vec<String> {
    matches
        .get_many::<String>(name)
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
        assert!(cli.use_cargo_registry);
        assert_eq!(cli.package.as_deref(), Some("app"));
        assert_eq!(
            cli.command,
            Command::Build(BuildOptions {
                release: true,
                target: Some("x86_64-unknown-motor".to_owned()),
                bin: Some("server".to_owned()),
                validation: ValidationMode::Strict,
            })
        );
    }

    #[test]
    fn parses_clean_profile_and_target_selection() {
        assert_eq!(
            parse(&["clean", "--release", "--target=x86_64-unknown-motor",])
                .unwrap()
                .command,
            Command::Clean(BuildOptions {
                release: true,
                target: Some("x86_64-unknown-motor".to_owned()),
                bin: None,
                validation: ValidationMode::Trusted,
            })
        );
        assert!(parse(&["--use-cargo-registry", "clean"]).is_err());
        assert!(parse(&["clean", "--strict-validation"]).is_err());
        assert!(parse(&["clean", "--bin", "server"]).is_err());
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
        assert!(parse(&["test", "--bin", "server"]).is_err());
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
        assert_eq!(test.test.as_deref(), Some("cli"));
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
            parse(&["vendor", "-p", "app"]).unwrap().package.as_deref(),
            Some("app")
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
    fn parses_offline_review_surface() {
        let cli = parse(&["+motor-current", "--quiet", "--color=never", "review"]).unwrap();
        assert_eq!(cli.toolchain.as_deref(), Some("motor-current"));
        assert_eq!(cli.verbosity, Verbosity::Quiet);
        assert_eq!(cli.color, Color::Never);
        assert_eq!(cli.command, Command::Review);
        assert!(parse(&["review", "extra"]).is_err());
        assert!(parse(&["review", "--anything"]).is_err());
        assert!(parse(&["--use-cargo-registry", "review"]).is_err());
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
            &["test", "--test=x", "--test", "y"],
            &["test", "--no-run", "--", "filter"],
        ] {
            assert!(parse(input).unwrap_err().is_usage(), "{input:?}");
        }
    }

    #[test]
    fn rejects_misplaced_and_unknown_syntax() {
        for input in [
            &[][..],
            &["build", "+motor-current"],
            &["build", "--quiet"],
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

        let unknown = parse(&["build", "--jobs", "2"]).unwrap_err();
        assert!(unknown.render().starts_with("error: unknown option"));
        assert!(!unknown.render().contains("\nerror:"));
    }
}
