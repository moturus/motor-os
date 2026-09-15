use std::process::ExitCode;

use clap::Command;

fn main() -> ExitCode {
    Command::new("gix")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Git for Motor OS")
        .disable_help_subcommand(true)
        .get_matches();

    eprintln!("gix: no commands are available in this bootstrap build");
    ExitCode::FAILURE
}
