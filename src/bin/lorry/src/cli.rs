use clap::builder::PossibleValuesParser;
use clap::error::ErrorKind as ClapErrorKind;
use clap::{Arg, ArgAction, ArgMatches, Command as ClapCommand};

use crate::diagnostic::{Error, Result};

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
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Build(BuildOptions),
    Run(RunOptions),
    Test(TestOptions),
    Vendor { accept_all: bool },
    Help(Option<String>),
    Version,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildOptions {
    pub release: bool,
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
    pub test: Option<String>,
    pub no_run: bool,
    pub bundle: bool,
    pub arguments: Vec<String>,
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
                        "use `+stable`, `+nightly`, or another installed toolchain name",
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
        Ok(Self {
            toolchain,
            color,
            verbosity,
            use_cargo_registry,
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
        .subcommand(build_command("build").dont_delimit_trailing_values(true))
        .subcommand(run_command())
        .subcommand(test_command())
        .subcommand(
            ClapCommand::new("vendor")
                .disable_help_flag(true)
                .dont_delimit_trailing_values(true)
                .args_override_self(false)
                .arg(
                    Arg::new("accept-all")
                        .long("accept-all")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            ClapCommand::new("help")
                .disable_help_flag(true)
                .dont_delimit_trailing_values(true)
                .arg(
                    Arg::new("topic")
                        .num_args(0..=1)
                        .value_parser(PossibleValuesParser::new([
                            "build", "run", "test", "vendor", "help",
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
}

fn run_command() -> ClapCommand {
    build_command("run").arg(child_arguments())
}

fn test_command() -> ClapCommand {
    build_command("test")
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
        Some(("run", options)) => Ok(Command::Run(RunOptions {
            build: build_options(options),
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
                build: build_options(options),
                test: options.get_one::<String>("test").cloned(),
                no_run: options.get_flag("no-run"),
                bundle: options.get_flag("bundle"),
                arguments,
            }))
        }
        Some(("vendor", options)) => Ok(Command::Vendor {
            accept_all: options.get_flag("accept-all"),
        }),
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
        target: matches.get_one::<String>("target").cloned(),
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
            "+nightly",
            "--verbose",
            "--color=always",
            "--use-cargo-registry",
            "build",
            "-r",
            "--target",
            "x86_64-unknown-motor",
        ])
        .unwrap();
        assert_eq!(cli.toolchain.as_deref(), Some("nightly"));
        assert_eq!(cli.verbosity, Verbosity::Verbose);
        assert_eq!(cli.color, Color::Always);
        assert!(cli.use_cargo_registry);
        assert_eq!(
            cli.command,
            Command::Build(BuildOptions {
                release: true,
                target: Some("x86_64-unknown-motor".to_owned()),
            })
        );
    }

    #[test]
    fn preserves_run_arguments_verbatim() {
        let cli = parse(&["run", "--", "--release", "two words", ""]).unwrap();
        let Command::Run(run) = cli.command else {
            panic!("expected run");
        };
        assert_eq!(run.arguments, ["--release", "two words", ""]);
    }

    #[test]
    fn parses_stage_two_test_surface() {
        let cli = parse(&[
            "test",
            "--test=cli",
            "--bundle",
            "--release",
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
        assert_eq!(test.arguments, ["--nocapture"]);
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
    fn rejects_duplicates_conflicts_and_missing_values() {
        for input in [
            &["-q", "--quiet", "build"][..],
            &["-q", "-v", "build"],
            &["--color", "auto", "--color=never", "build"],
            &["build", "-r", "--release"],
            &["build", "--target"],
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
            &["build", "+nightly"],
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
