mod admission_state;
mod archive;
mod atomic;
mod build_script;
mod bundle;
mod cache;
mod cache_clean;
mod cargo_registry;
mod change_review;
mod clean;
mod cli;
mod compile;
mod config;
#[allow(dead_code)]
mod curl;
mod dependency;
mod diagnostic;
mod engine;
mod executor;
mod git;
mod hash;
mod identity;
mod json;
mod lockfile;
mod manifest;
mod native_tool;
mod new_package;
mod offline;
mod patch;
mod policy;
mod process;
#[allow(dead_code)]
mod redirect;
mod repository;
mod resolver;
mod review;
mod sandbox;
mod source_tree;
mod sparse;
mod toml;
mod toolchain;
mod trace;
mod unit;
mod upgrade;
mod validation;
mod vendor;
mod vendor_lock;

use cli::{Cli, Command};
use diagnostic::Result;

const VERSION: &str = "0.1.0";

fn main() {
    #[cfg(target_os = "motor")]
    let code = match std::thread::Builder::new()
        .name("lorry".to_owned())
        .stack_size(4 * 1024 * 1024)
        .spawn(command_main)
    {
        Ok(worker) => worker.join().unwrap_or(101),
        Err(error) => {
            eprintln!("error: failed to start lorry command thread: {error}");
            101
        }
    };
    #[cfg(not(target_os = "motor"))]
    let code = command_main();
    if code != 0 {
        std::process::exit(code);
    }
}

fn command_main() -> i32 {
    match run(std::env::args().skip(1)) {
        Ok(code) => code,
        Err(error) => {
            eprint!("{}", error.render());
            error.exit_code()
        }
    }
}

fn run<I>(arguments: I) -> Result<i32>
where
    I: IntoIterator<Item = String>,
{
    let cli = Cli::parse(arguments)?;
    let command = match &cli.command {
        Command::Build(_) => Some("build started"),
        Command::Run(_) => Some("run started"),
        Command::Test(_) => Some("test started"),
        _ => None,
    };
    let _trace = trace::Session::new(
        cli.verbosity == cli::Verbosity::Verbose && command.is_some(),
        command.unwrap_or(""),
    );
    match &cli.command {
        Command::Help(topic) => {
            print_help(topic.as_deref());
            Ok(0)
        }
        Command::Version => {
            println!("lorry {VERSION}");
            Ok(0)
        }
        Command::New { path } => new_package::execute(path, cli.verbosity == cli::Verbosity::Quiet),
        Command::CacheClean => cache_clean::execute(cli.verbosity),
        Command::Clean(options) => clean::execute(options, cli.package.as_deref(), cli.verbosity),
        Command::Review => review::execute(&cli),
        Command::Vendor(options) => vendor::execute(&cli, options),
        Command::Build(_) | Command::Run(_) | Command::Test(_) => engine::execute(&cli),
    }
}

fn print_help(topic: Option<&str>) {
    match topic {
        Some("build") => println!(
            "Build the package\n\nUsage: lorry [+toolchain] [GLOBAL] build [-p NAME] [--release|-r] [--target TRIPLE] [--bin NAME] [--strict-validation]"
        ),
        Some("cache") => println!(
            "Manage the global Lorry cache\n\nUsage: lorry [+toolchain] [GLOBAL] cache clean"
        ),
        Some("clean") => println!(
            "Remove generated Lorry artifacts\n\nUsage: lorry [+toolchain] [GLOBAL] clean [-p NAME] [--release|-r] [--target TRIPLE]"
        ),
        Some("new") => {
            println!("Create a binary package\n\nUsage: lorry [+toolchain] [GLOBAL] new PATH")
        }
        Some("review") => println!(
            "Write the verified dependency review\n\nUsage: lorry [+toolchain] [GLOBAL] review [-p NAME]"
        ),
        Some("run") => println!(
            "Build and run a package binary\n\nUsage: lorry [+toolchain] [GLOBAL] run [-p NAME] [--release|-r] [--target TRIPLE] [--bin NAME] [--strict-validation] [-- ARGS...]"
        ),
        Some("test") => println!(
            "Build and run package tests\n\nUsage: lorry [+toolchain] [GLOBAL] test [-p NAME] [--release|-r] [--target TRIPLE] [--strict-validation] [--test NAME] [--no-run] [--bundle] [-- ARGS...]"
        ),
        Some("vendor") => println!(
            "Vendor dependencies or select a transitive update\n\nUsage:\n  lorry [+toolchain] [GLOBAL] vendor [-p NAME] [--accept-all]\n  lorry [+toolchain] [GLOBAL] vendor [-p NAME] upgrade PACKAGE[@OLD_VERSION] --to VERSION"
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
             -v, --verbose               Show commands, configuration, and timings\n  \
                 --color <WHEN>          auto, always, or never\n  \
                 --use-cargo-registry    Use Cargo's verified offline registry cache\n\n\
             Commands:\n  \
             build                       Build the package\n  \
             cache                       Manage the global Lorry cache\n  \
             clean                       Remove generated Lorry artifacts\n  \
             new                         Create a binary package\n  \
             review                      Write the verified dependency review\n  \
             run                         Build and run its binary\n  \
             test                        Build and run unit and integration tests\n  \
             vendor                      Vendor dependencies (Stage 2)\n  \
             help                        Show this help"
        ),
    }
}
