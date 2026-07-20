mod cli;
mod config;
mod diagnostic;
mod manifest;

use cli::{Cli, Command};
use config::{Config, environment_rustflags};
use diagnostic::{Error, Result};
use manifest::Manifest;

const VERSION: &str = "0.1.0";

fn main() {
    let code = match run(std::env::args().skip(1)) {
        Ok(code) => code,
        Err(error) => {
            eprint!("{}", error.render());
            error.exit_code()
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}

fn run<I>(arguments: I) -> Result<i32>
where
    I: IntoIterator<Item = String>,
{
    let cli = Cli::parse(arguments)?;
    match cli.command {
        Command::Help(topic) => {
            print_help(topic.as_deref());
            Ok(0)
        }
        Command::Version => {
            println!("lorry {VERSION}");
            Ok(0)
        }
        Command::Vendor { .. } => Err(Error::unsupported("vendor", 1)),
        Command::Test(options) if options.test.is_some() || options.no_run || options.bundle => {
            let option = if options.test.is_some() {
                "--test"
            } else if options.no_run {
                "--no-run"
            } else {
                "--bundle"
            };
            Err(Error::unsupported(option, 1))
        }
        command @ (Command::Build(_) | Command::Run(_) | Command::Test(_)) => {
            let current = std::env::current_dir().map_err(|error| {
                Error::failure(format!("failed to read current directory: {error}"))
            })?;
            let _manifest = Manifest::load(&current)?;
            let config = Config::load(&current)?;
            let command_target = match &command {
                Command::Build(options) => options.target.as_deref(),
                Command::Run(options) => options.build.target.as_deref(),
                Command::Test(options) => options.build.target.as_deref(),
                _ => unreachable!(),
            };
            let target = config.selected_target(command_target)?;
            let _target_options = target
                .as_deref()
                .map(|target| config.target_options(target, &[]))
                .transpose()?;
            let _rustflags = environment_rustflags()?;
            Err(Error::failure(
                "the Stage-1 build engine is not available in this implementation slice",
            ))
        }
    }
}

fn print_help(topic: Option<&str>) {
    match topic {
        Some("build") => println!(
            "Build the package\n\nUsage: lorry [+toolchain] [GLOBAL] build [--release|-r] [--target TRIPLE]"
        ),
        Some("run") => println!(
            "Build and run the package binary\n\nUsage: lorry [+toolchain] [GLOBAL] run [--release|-r] [--target TRIPLE] [-- ARGS...]"
        ),
        Some("test") => println!(
            "Build and run package tests\n\nUsage: lorry [+toolchain] [GLOBAL] test [--release|-r] [--target TRIPLE] [-- ARGS...]"
        ),
        Some("vendor") => println!(
            "Vendor approved dependencies (Stage 2)\n\nUsage: lorry [+toolchain] [GLOBAL] vendor [--accept-all]"
        ),
        Some("help") => println!("Show help\n\nUsage: lorry help [COMMAND]"),
        _ => println!(
            "A small, deterministic Rust package builder\n\n\
             Usage:\n  \
             lorry [+toolchain] [GLOBAL] <COMMAND>\n  \
             lorry --help|-h\n  \
             lorry --version|-V\n  \
             lorry help [COMMAND]\n\n\
             Global options:\n  \
             -q, --quiet                 Suppress progress output\n  \
             -v, --verbose               Show commands and configuration\n  \
                 --color <WHEN>          auto, always, or never\n\n\
             Commands:\n  \
             build                       Build the package\n  \
             run                         Build and run its binary\n  \
             test                        Build and run its binary unit tests\n  \
             vendor                      Vendor dependencies (Stage 2)\n  \
             help                        Show this help"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_two_commands_fail_at_the_boundary() {
        let vendor = run(["vendor".to_owned()]).unwrap_err();
        assert_eq!(vendor.exit_code(), 101);
        assert!(vendor.to_string().contains("Stage 1"));

        let test = run(["test".to_owned(), "--bundle".to_owned()]).unwrap_err();
        assert_eq!(test.exit_code(), 101);
        assert!(test.to_string().contains("--bundle"));
    }
}
