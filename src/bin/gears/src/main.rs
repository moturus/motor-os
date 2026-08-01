use std::process::ExitCode;

use gears::cli::{Action, Args};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match Args::parse(&argv) {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("gears: {msg}");
            eprintln!("Try 'gears --help'.");
            return ExitCode::from(2);
        }
    };

    match args.action {
        Action::Version => {
            println!("gears {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Action::Help => {
            print!("{}", gears::cli::USAGE);
            ExitCode::SUCCESS
        }
        Action::Run => run(&args),
    }
}

/// The agent loop arrives in step 4 of the plan; until then a plain
/// invocation loads the config and starts the tracer (so errors surface),
/// then reports itself honestly.
fn run(args: &Args) -> ExitCode {
    let config = match gears::config::Config::load(args.config.as_deref()) {
        Ok(config) => config,
        Err(msg) => {
            eprintln!("gears: config: {msg}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(path) = args.log_file.as_deref().or(config.log_file.as_deref()) {
        match gears::trace::Tracer::to_file(path, config.log_level) {
            Ok(tracer) => gears::trace::init(tracer),
            Err(e) => {
                eprintln!("gears: cannot open log file {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
        gears::trace::log(
            gears::trace::Level::Info,
            concat!("gears ", env!("CARGO_PKG_VERSION"), " starting"),
        );
    }

    if !gears::platform::install_interrupt_handler() {
        gears::trace::log(
            gears::trace::Level::Warn,
            "could not install the interrupt handler",
        );
    }

    eprintln!("gears: the interactive agent is not implemented yet");
    ExitCode::FAILURE
}
