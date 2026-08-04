use std::io::Write;
use std::process::ExitCode;

use curl::{Action, CurlError, DataSource, Options};

#[cfg(target_os = "motor")]
struct TransferStdout;

#[cfg(target_os = "motor")]
impl Write for TransferStdout {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        moto_rt::fs::write(moto_rt::FD_STDOUT, buffer).map_err(motor_io_error)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        moto_rt::fs::flush(moto_rt::FD_STDOUT).map_err(motor_io_error)
    }
}

#[cfg(target_os = "motor")]
fn motor_io_error(error: moto_rt::Error) -> std::io::Error {
    let code: moto_rt::ErrorCode = error.into();
    std::io::Error::from_raw_os_error(code.into())
}

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
    curl::set_verbosity(options.verbosity);
    #[cfg(target_os = "motor")]
    let mut stdout = TransferStdout;
    #[cfg(not(target_os = "motor"))]
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let body = match &options.data {
        None => None,
        Some(DataSource::Literal(text)) => Some(text.clone().into_bytes()),
        Some(DataSource::Stdin) => {
            curl::verbose(1, "reading the request body from stdin");
            match read_stdin() {
                Ok(body) => {
                    curl::verbose(2, &format!("read {} request-body bytes", body.len()));
                    Some(body)
                }
                Err(error) => return report(error, !options.silent || options.show_error),
            }
        }
    };
    curl::verbose(1, "starting the HTTPS transfer");
    let result = curl::transfer(&options, body.as_deref(), &mut stdout).and_then(|info| {
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
        Ok(()) => {
            curl::verbose(1, "transfer completed successfully");
            ExitCode::SUCCESS
        }
        Err(error) => {
            curl::verbose(
                1,
                &format!("transfer failed with curl status {}", error.code()),
            );
            report(error, !options.silent || options.show_error)
        }
    }
}

/// The whole of stdin, for `--data-binary @-`. Through `std` on every
/// platform: on Motor OS a child's stdin is not the raw runtime handle 0
/// (`moto_rt::fs::read(FD_STDIN, ..)` answers `BadHandle` under a pipe);
/// `std::io::stdin` holds the actual handle, and is how every in-tree
/// program reads it.
fn read_stdin() -> Result<Vec<u8>, CurlError> {
    use std::io::Read;
    let mut body = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut body)
        .map_err(|error| {
            CurlError::new(
                CurlError::LOCAL_READ,
                format!("failed reading request body from stdin: {error}"),
            )
        })?;
    Ok(body)
}

fn report(error: CurlError, show: bool) -> ExitCode {
    if show {
        eprintln!("curl: ({}) {}", error.code(), error);
    }
    ExitCode::from(error.code())
}
