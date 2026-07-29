use std::io::Write;
use std::process::ExitCode;

use curl::{Action, CurlError, Options};

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
    #[cfg(target_os = "motor")]
    let mut stdout = TransferStdout;
    #[cfg(not(target_os = "motor"))]
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
