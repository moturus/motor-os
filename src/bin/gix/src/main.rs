use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use clap::{Arg, ArgAction, Command, value_parser};

mod log;

use motor_gix::{Result, repository, status};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let mut stderr = io::stderr().lock();
            _ = writeln!(stderr, "gix: {err}");
            let mut source = err.source();
            while let Some(err) = source {
                _ = writeln!(stderr, "  caused by: {err}");
                source = err.source();
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result {
    let matches = Command::new("gix")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Git for Motor OS")
        .disable_help_subcommand(true)
        .subcommand_required(true)
        .arg(
            Arg::new("repository")
                .short('r')
                .long("repository")
                .value_name("REPOSITORY")
                .value_parser(value_parser!(PathBuf))
                .default_value(".")
                .global(true),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .value_name("key=value")
                .action(ArgAction::Append)
                .global(true),
        )
        .arg(
            Arg::new("config-paths")
                .long("config-paths")
                .help("Report configuration files used while opening the repository")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .subcommand(Command::new("log").about("Show commit history"))
        .subcommand(Command::new("status").about("Show worktree status"))
        .get_matches();

    let path = matches
        .get_one::<PathBuf>("repository")
        .expect("the repository path has a default");
    let overrides = matches
        .get_many::<String>("config")
        .into_iter()
        .flatten()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let opened = repository::open(path, &overrides, matches.get_flag("config-paths"))?;

    match matches.subcommand_name() {
        Some("log") => log::show(&opened.repo),
        Some("status") => {
            let report = status::collect(&opened)?;
            Ok(report.write_to(io::stdout().lock())?)
        }
        _ => unreachable!("clap accepts only declared subcommands"),
    }
}
