use std::io::Write;
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
        Ok(Action::Transfer(options)) => run(options),
        Err(error) => report(error, true),
    }
}

fn run(options: Options) -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let result = curl::transfer(&options, &mut stdout).and_then(|info| {
        if let Some(format) = &options.write_out {
            curl::write_out(format, &info, &mut stdout, &mut stderr)?;
        }
        stdout.flush().map_err(|error| {
            CurlError::new(
                CurlError::LOCAL_WRITE,
                format!("failed flushing local output: {error}"),
            )
        })
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => report(error, !options.silent || options.show_error),
    }
}

fn report(error: CurlError, show: bool) -> ExitCode {
    if show {
        eprintln!("curl: ({}) {}", error.code(), error);
    }
    ExitCode::from(error.code())
}
