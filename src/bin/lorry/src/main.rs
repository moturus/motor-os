mod archive;
mod atomic;
mod build_script;
mod bundle;
mod cache;
mod cargo_registry;
mod cli;
mod compile;
mod config;
mod dependency;
mod diagnostic;
mod engine;
mod executor;
mod hash;
mod identity;
mod json;
mod lockfile;
mod manifest;
mod offline;
mod patch;
mod policy;
mod process;
mod repository;
mod resolver;
mod sandbox;
mod source_tree;
mod sparse;
mod toml;
mod toolchain;
mod unit;

use cli::{Cli, Command};
use diagnostic::{Error, Result};

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
    match &cli.command {
        Command::Help(topic) => {
            print_help(topic.as_deref());
            Ok(0)
        }
        Command::Version => {
            println!("lorry {VERSION}");
            Ok(0)
        }
        Command::Vendor { .. } => Err(Error::unsupported("vendor", 1)),
        Command::Build(_) | Command::Run(_) | Command::Test(_) => engine::execute(&cli),
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
            "Build and run package tests\n\nUsage: lorry [+toolchain] [GLOBAL] test [--release|-r] [--target TRIPLE] [--test NAME] [--no-run] [--bundle] [-- ARGS...]"
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
                 --color <WHEN>          auto, always, or never\n  \
                 --use-cargo-registry    Use Cargo's verified offline registry cache\n\n\
             Commands:\n  \
             build                       Build the package\n  \
             run                         Build and run its binary\n  \
             test                        Build and run unit and integration tests\n  \
             vendor                      Vendor dependencies (Stage 2)\n  \
             help                        Show this help"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfinished_stage_two_commands_fail_at_the_boundary() {
        let vendor = run(["vendor".to_owned()]).unwrap_err();
        assert_eq!(vendor.exit_code(), 101);
        assert!(vendor.to_string().contains("Stage 1"));
    }
}
