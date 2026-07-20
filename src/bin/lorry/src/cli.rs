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
        let mut args = arguments.into_iter().peekable();
        let toolchain = match args.peek() {
            Some(value) if value.starts_with('+') => {
                let value = args.next().unwrap();
                if value.len() == 1 {
                    return Err(Error::usage(
                        "toolchain selector `+` is empty",
                        "use `+stable`, `+nightly`, or another installed toolchain name",
                    ));
                }
                Some(value[1..].to_owned())
            }
            _ => None,
        };

        let mut color = Color::Auto;
        let mut color_seen = false;
        let mut verbosity = Verbosity::Normal;
        let mut quiet_seen = false;
        let mut verbose_seen = false;

        let command_name = loop {
            let Some(argument) = args.next() else {
                return Err(Error::usage(
                    "no command was provided",
                    "run `lorry --help` to see the available commands",
                ));
            };
            match argument.as_str() {
                "--quiet" | "-q" => {
                    if quiet_seen {
                        return Err(duplicate("--quiet"));
                    }
                    if verbose_seen {
                        return Err(Error::usage(
                            "`--quiet` conflicts with `--verbose`",
                            "choose at most one verbosity option",
                        ));
                    }
                    quiet_seen = true;
                    verbosity = Verbosity::Quiet;
                }
                "--verbose" | "-v" => {
                    if verbose_seen {
                        return Err(duplicate("--verbose"));
                    }
                    if quiet_seen {
                        return Err(Error::usage(
                            "`--verbose` conflicts with `--quiet`",
                            "choose at most one verbosity option",
                        ));
                    }
                    verbose_seen = true;
                    verbosity = Verbosity::Verbose;
                }
                "--color" => {
                    if color_seen {
                        return Err(duplicate("--color"));
                    }
                    let value = args.next().ok_or_else(|| missing("--color"))?;
                    color = parse_color(&value)?;
                    color_seen = true;
                }
                value if value.starts_with("--color=") => {
                    if color_seen {
                        return Err(duplicate("--color"));
                    }
                    color = parse_color(&value["--color=".len()..])?;
                    color_seen = true;
                }
                "--help" | "-h" => {
                    if args.next().is_some() {
                        return Err(Error::usage(
                            "`--help` does not accept trailing arguments",
                            "use `lorry help COMMAND` for command-specific help",
                        ));
                    }
                    return Ok(Self {
                        toolchain,
                        color,
                        verbosity,
                        command: Command::Help(None),
                    });
                }
                "--version" | "-V" => {
                    if args.next().is_some() {
                        return Err(Error::usage(
                            "`--version` does not accept trailing arguments",
                            "remove the trailing arguments",
                        ));
                    }
                    return Ok(Self {
                        toolchain,
                        color,
                        verbosity,
                        command: Command::Version,
                    });
                }
                value if value.starts_with('-') => return Err(unknown_option(value)),
                value if value.starts_with('+') => {
                    return Err(Error::usage(
                        format!("toolchain selector `{value}` is not first"),
                        "place `+toolchain` before global options and the command",
                    ));
                }
                value => break value.to_owned(),
            }
        };

        let command = match command_name.as_str() {
            "build" => Command::Build(parse_build(&mut args, "build")?),
            "run" => Command::Run(parse_run(&mut args)?),
            "test" => Command::Test(parse_test(&mut args)?),
            "vendor" => Command::Vendor {
                accept_all: parse_vendor(&mut args)?,
            },
            "help" => {
                let topic = args.next();
                if let Some(extra) = args.next() {
                    return Err(Error::usage(
                        format!("unexpected argument `{extra}` after help topic"),
                        "use `lorry help COMMAND` with at most one command",
                    ));
                }
                if let Some(topic) = topic.as_deref() {
                    if !matches!(topic, "build" | "run" | "test" | "vendor" | "help") {
                        return Err(Error::usage(
                            format!("unknown help topic `{topic}`"),
                            "choose build, run, test, or vendor",
                        ));
                    }
                }
                Command::Help(topic)
            }
            other => {
                return Err(Error::usage(
                    format!("unknown command `{other}`"),
                    "run `lorry --help` to see the available commands",
                ));
            }
        };

        Ok(Self {
            toolchain,
            color,
            verbosity,
            command,
        })
    }
}

fn parse_build<I>(args: &mut std::iter::Peekable<I>, command: &str) -> Result<BuildOptions>
where
    I: Iterator<Item = String>,
{
    let mut release = false;
    let mut target = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--release" | "-r" => {
                if release {
                    return Err(duplicate("--release"));
                }
                release = true;
            }
            "--target" => {
                if target.is_some() {
                    return Err(duplicate("--target"));
                }
                let value = args.next().ok_or_else(|| missing("--target"))?;
                target = Some(nonempty("--target", value)?);
            }
            value if value.starts_with("--target=") => {
                if target.is_some() {
                    return Err(duplicate("--target"));
                }
                target = Some(nonempty("--target", value["--target=".len()..].to_owned())?);
            }
            "--" => {
                return Err(Error::usage(
                    format!("`{command}` does not accept arguments after `--`"),
                    "only `run` and executable `test` commands accept child arguments",
                ));
            }
            value if value.starts_with('-') => return Err(unknown_option(value)),
            value => {
                return Err(Error::usage(
                    format!("unexpected argument `{value}` for `{command}`"),
                    format!("run `lorry help {command}` for accepted options"),
                ));
            }
        }
    }
    Ok(BuildOptions { release, target })
}

fn parse_run<I>(args: &mut std::iter::Peekable<I>) -> Result<RunOptions>
where
    I: Iterator<Item = String>,
{
    let mut build_args = Vec::new();
    let mut child_args = Vec::new();
    let mut separator = false;
    for argument in args.by_ref() {
        if !separator && argument == "--" {
            separator = true;
        } else if separator {
            child_args.push(argument);
        } else {
            build_args.push(argument);
        }
    }
    let build = parse_build(&mut build_args.into_iter().peekable(), "run")?;
    Ok(RunOptions {
        build,
        arguments: child_args,
    })
}

fn parse_test<I>(args: &mut std::iter::Peekable<I>) -> Result<TestOptions>
where
    I: Iterator<Item = String>,
{
    let mut build_args = Vec::new();
    let mut child_args = Vec::new();
    let mut test = None;
    let mut no_run = false;
    let mut bundle = false;
    let mut separator = false;

    while let Some(argument) = args.next() {
        if separator {
            child_args.push(argument);
            continue;
        }
        match argument.as_str() {
            "--" => separator = true,
            "--test" => {
                if test.is_some() {
                    return Err(duplicate("--test"));
                }
                let value = args.next().ok_or_else(|| missing("--test"))?;
                test = Some(nonempty("--test", value)?);
            }
            value if value.starts_with("--test=") => {
                if test.is_some() {
                    return Err(duplicate("--test"));
                }
                test = Some(nonempty("--test", value["--test=".len()..].to_owned())?);
            }
            "--no-run" => {
                if no_run {
                    return Err(duplicate("--no-run"));
                }
                no_run = true;
            }
            "--bundle" => {
                if bundle {
                    return Err(duplicate("--bundle"));
                }
                bundle = true;
            }
            _ => build_args.push(argument),
        }
    }

    if no_run && !child_args.is_empty() {
        return Err(Error::usage(
            "test arguments cannot be combined with `--no-run`",
            "remove the arguments after `--` or remove `--no-run`",
        ));
    }

    let build = parse_build(&mut build_args.into_iter().peekable(), "test")?;
    Ok(TestOptions {
        build,
        test,
        no_run,
        bundle,
        arguments: child_args,
    })
}

fn parse_vendor<I>(args: &mut std::iter::Peekable<I>) -> Result<bool>
where
    I: Iterator<Item = String>,
{
    let mut accept_all = false;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--accept-all" if !accept_all => accept_all = true,
            "--accept-all" => return Err(duplicate("--accept-all")),
            value if value.starts_with('-') => return Err(unknown_option(value)),
            value => {
                return Err(Error::usage(
                    format!("unexpected argument `{value}` for `vendor`"),
                    "run `lorry help vendor` for accepted options",
                ));
            }
        }
    }
    Ok(accept_all)
}

fn parse_color(value: &str) -> Result<Color> {
    match value {
        "auto" => Ok(Color::Auto),
        "always" => Ok(Color::Always),
        "never" => Ok(Color::Never),
        _ => Err(Error::usage(
            format!("invalid color value `{value}`"),
            "choose `auto`, `always`, or `never`",
        )),
    }
}

fn nonempty(option: &str, value: String) -> Result<String> {
    if value.is_empty() {
        Err(Error::usage(
            format!("`{option}` requires a non-empty value"),
            format!("pass the value as `{option} VALUE`"),
        ))
    } else {
        Ok(value)
    }
}

fn duplicate(option: &str) -> Error {
    Error::usage(
        format!("option `{option}` was provided more than once"),
        "remove the duplicate option",
    )
}

fn missing(option: &str) -> Error {
    Error::usage(
        format!("option `{option}` is missing its value"),
        format!("pass the value as `{option} VALUE`"),
    )
}

fn unknown_option(option: &str) -> Error {
    Error::usage(
        format!("unknown option `{option}`"),
        "run `lorry --help` to see the accepted options",
    )
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
            "build",
            "-r",
            "--target",
            "x86_64-unknown-motor",
        ])
        .unwrap();
        assert_eq!(cli.toolchain.as_deref(), Some("nightly"));
        assert_eq!(cli.verbosity, Verbosity::Verbose);
        assert_eq!(cli.color, Color::Always);
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
            assert!(parse(input).unwrap_err().is_usage(), "{input:?}");
        }
    }
}
