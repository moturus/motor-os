use std::process::ExitCode;

use curl::{Action, CurlError, Options};

fn main() -> ExitCode {
    match Options::parse(std::env::args().skip(1)) {
        Ok(Action::Help) => {
            print!("{}", curl::help());
            ExitCode::SUCCESS
        }
        Ok(Action::Version) => {
            print!("{}", curl::version());
            ExitCode::SUCCESS
        }
        Ok(Action::Transfer(_)) => report(CurlError::new(
            CurlError::USAGE,
            "HTTPS transport is not implemented yet",
        )),
        Err(error) => report(error),
    }
}

fn report(error: CurlError) -> ExitCode {
    eprintln!("curl: ({}) {}", error.code(), error);
    ExitCode::from(error.code())
}
