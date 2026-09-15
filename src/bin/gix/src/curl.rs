use std::{io, path::Path, process::Command};

#[cfg(not(target_os = "motor"))]
use std::{fs::File, io::Read};

use crate::https_url::HttpsUrl;

const MAX_HEADER_BYTES: usize = 8 * 1024;
const MARKER: &str = "MOTOR-GIX-CURL-1";
#[cfg(target_os = "motor")]
const CURL: &str = "/system/bin/curl";
#[cfg(not(target_os = "motor"))]
const CURL: &str = "/usr/bin/curl";

/// Prepare fixed anonymous HTTPS curl arguments. The caller bounds capture and validates the nonce trailer.
pub fn command(
    url: &HttpsUrl,
    ca_bundle: &Path,
    headers: &[String],
    has_body: bool,
) -> io::Result<(Command, String)> {
    let nonce = nonce()?;
    let prepared = command_with_nonce(url, ca_bundle, headers, has_body, &nonce)?;
    Ok((prepared, nonce))
}

fn command_with_nonce(
    url: &HttpsUrl,
    ca_bundle: &Path,
    headers: &[String],
    has_body: bool,
    nonce: &str,
) -> io::Result<Command> {
    validate_headers(headers)?;
    let write_out = format!(
        "%{{stderr}}\n{MARKER} {nonce}\n\
         status=%{{response_code}}\n\
         url=%{{url_effective}}\n\
         redirect=%{{redirect_url}}\n\
         type=%{{content_type}}\n\
         size=%{{size_download}}\n\
         END-{MARKER} {nonce}\n"
    );
    let mut command = Command::new(CURL);
    command.env_clear().env("LC_ALL", "C").args([
        "--disable",
        "--silent",
        "--show-error",
        "--globoff",
        "--http1.1",
        "--proto",
        "=https",
        "--noproxy",
        "*",
        "--disallow-username-in-url",
        "--tlsv1.2",
        "--tls-max",
        "1.3",
        "--connect-timeout",
        "30",
        "--max-time",
        "300",
        "--speed-limit",
        "1",
        "--speed-time",
        "30",
        "--user-agent",
        concat!("motor-gix/", env!("CARGO_PKG_VERSION")),
        "--header",
        "Accept-Encoding: identity",
    ]);
    for header in headers {
        command.args(["--header", header]);
    }
    if has_body {
        command.args(["--data-binary", "@-"]);
    }
    command
        .arg("--cacert")
        .arg(ca_bundle)
        .args(["--output", "-", "--write-out"])
        .arg(write_out)
        .args(["--url", url.as_str()]);
    Ok(command)
}

fn validate_headers(headers: &[String]) -> io::Result<()> {
    let mut bytes = 0usize;
    for header in headers {
        bytes = bytes
            .checked_add(header.len())
            .filter(|bytes| *bytes <= MAX_HEADER_BYTES)
            .ok_or_else(|| input("Git HTTP request headers exceed their byte limit"))?;
        let Some((name, value)) = header.split_once(':') else {
            return Err(input("malformed Git HTTP request header"));
        };
        if !matches!(
            name.to_ascii_lowercase().as_str(),
            "accept" | "content-type" | "git-protocol" | "user-agent"
        ) || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0x7f)
        {
            return Err(input("unsupported Git HTTP request header"));
        }
    }
    Ok(())
}

fn nonce() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    fill_random(&mut bytes)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut nonce = String::with_capacity(32);
    for byte in bytes {
        nonce.push(HEX[(byte >> 4) as usize] as char);
        nonce.push(HEX[(byte & 0xf) as usize] as char);
    }
    Ok(nonce)
}

#[cfg(target_os = "motor")]
fn fill_random(bytes: &mut [u8]) -> io::Result<()> {
    moto_rt::fill_random_bytes(bytes);
    Ok(())
}

#[cfg(not(target_os = "motor"))]
fn fill_random(bytes: &mut [u8]) -> io::Result<()> {
    File::open("/dev/urandom")?.read_exact(bytes)
}

fn input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};

    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn request_has_fixed_environment_arguments_and_bounded_headers() {
        let url = HttpsUrl::parse("https://example.com/repo.git?q=1").expect("valid URL");
        let headers = [
            "Accept: application/x-git-upload-pack-result",
            "Content-Type: application/x-git-upload-pack-request",
            "Git-Protocol: version=2",
            "User-Agent: git/2",
        ]
        .map(str::to_owned);
        let prepared = command_with_nonce(&url, Path::new("/ca.pem"), &headers, true, NONCE)
            .expect("valid request");
        assert_eq!(prepared.get_program(), CURL);
        assert_eq!(
            prepared.get_envs().collect::<Vec<_>>(),
            [(OsStr::new("LC_ALL"), Some(OsStr::new("C")))]
        );
        let arguments = prepared.get_args().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(arguments.first(), Some(&OsString::from("--disable")));
        assert!(!arguments.iter().any(|value| value == "--location"));
        for pair in [
            ["--proto", "=https"],
            ["--cacert", "/ca.pem"],
            ["--data-binary", "@-"],
            ["--header", "Git-Protocol: version=2"],
        ] {
            assert!(arguments.windows(2).any(|values| values == pair));
        }
        assert_eq!(
            &arguments[arguments.len() - 2..],
            ["--url", "https://example.com/repo.git?q=1"]
        );

        let (without_body, random) =
            command(&url, Path::new("/ca.pem"), &[], false).expect("random request");
        assert_eq!(random.len(), 32);
        assert!(
            random
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(
            !without_body
                .get_args()
                .any(|value| value == "--data-binary")
        );

        let oversized = format!("Accept: {}", "x".repeat(MAX_HEADER_BYTES));
        for rejected in [
            vec!["Authorization: secret".to_owned()],
            vec!["Accept".to_owned()],
            vec!["Accept: ok\rInjected: yes".to_owned()],
            vec![oversized],
        ] {
            assert!(
                command_with_nonce(&url, Path::new("/ca.pem"), &rejected, false, NONCE).is_err()
            );
        }
    }
}
