mod error;
mod http;
mod options;
mod tls;
mod transfer;
mod url;
mod write_out;

use std::sync::atomic::{AtomicU8, Ordering};

pub use error::{CurlError, CurlResult};
pub use http::{Response, receive_response, write_request};
pub use options::{Action, DataSource, Options};
pub use tls::client_config;
pub use transfer::transfer;
pub use url::HttpsUrl;
pub use write_out::{TransferInfo, write_out};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

static VERBOSITY: AtomicU8 = AtomicU8::new(0);

#[doc(hidden)]
pub fn set_verbosity(level: u8) {
    VERBOSITY.store(level.min(3), Ordering::Relaxed);
}

#[doc(hidden)]
pub fn verbose(level: u8, message: &str) {
    if VERBOSITY.load(Ordering::Relaxed) < level {
        return;
    }
    use std::io::Write;
    if std::env::var_os("MOTOR_CURL_VERBOSE_STDERR").is_some() {
        let mut output = std::io::stderr().lock();
        let _ = writeln!(output, "curl-v{level}: {message}");
        let _ = output.flush();
    } else {
        let mut output = std::io::stdout().lock();
        let _ = writeln!(output, "curl-v{level}: {message}");
        let _ = output.flush();
    }
}

#[cfg(target_os = "motor")]
fn motor_getrandom(destination: &mut [u8]) -> Result<(), getrandom::Error> {
    moto_rt::fill_random_bytes(destination);
    Ok(())
}

#[cfg(target_os = "motor")]
getrandom::register_custom_getrandom!(motor_getrandom);

pub fn help() -> &'static str {
    "Usage: curl [OPTIONS] --url <HTTPS-URL>\n\
\n\
Options:\n\
  -v, -vv, -vvv                     Print increasing detail to stdout\n\
      --disable                       Disable curl configuration files\n\
      --silent                        Suppress progress output\n\
      --show-error                    Show errors when used with --silent\n\
      --include                       Write the response head before the body\n\
      --no-buffer                     Unbuffered output (always on)\n\
      --globoff                       Disable URL globbing\n\
      --http1.1                       Use HTTP/1.1\n\
      --proto =https                  Permit HTTPS only\n\
      --noproxy *                     Disable proxies\n\
      --disallow-username-in-url      Reject URL user information\n\
      --tlsv1.2                       Require TLS 1.2 or newer\n\
      --tls-max 1.3                   Permit TLS 1.3 at most\n\
      --connect-timeout <SECONDS>     Bound connection establishment\n\
      --max-time <SECONDS>            Bound the complete transfer\n\
      --speed-limit <BYTES>           Set the low-speed byte threshold\n\
      --speed-time <SECONDS>          Set the low-speed interval\n\
      --user-agent <VALUE>            Set the User-Agent header\n\
      --header <HEADER>               Add a request header (`Name:` removes)\n\
      --variable %NAME                Import NAME from the environment\n\
      --expand-header <HEADER>        Add a header, expanding {{NAME}}\n\
      --data-binary <DATA | @->       POST the data (@- reads stdin)\n\
      --output -                      Write the response body to stdout\n\
      --write-out <FORMAT>            Write transfer metadata\n\
      --cacert <ABSOLUTE-PATH>        Load trust roots from a PEM file\n\
      --url <HTTPS-URL>               Set the request URL\n\
      --help                          Print help\n\
      --version                       Print version\n"
}

pub fn version() -> String {
    format!("curl {VERSION} (Motor OS) rustls\nProtocols: https\n")
}
