use std::{io, path::Path, process::Command};

#[cfg(not(target_os = "motor"))]
use std::{fs::File, io::Read};

use crate::https_url::HttpsUrl;

const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_CONTROL_BYTES: usize = 16 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const MARKER: &str = "MOTOR-GIX-CURL-1";
#[cfg(target_os = "motor")]
const CURL: &str = "/system/bin/curl";
#[cfg(not(target_os = "motor"))]
const CURL: &str = "/usr/bin/curl";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub status: u16,
    pub effective_url: HttpsUrl,
    pub redirect_url: Option<HttpsUrl>,
    pub content_type: String,
    pub size: u64,
}

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

/// Structurally validate one authenticated curl trailer.
/// The adapter checks status, content type, effective URL, and origin policy.
pub fn parse_metadata(
    stderr: &[u8],
    nonce: &str,
    observed_size: u64,
) -> io::Result<(Vec<u8>, Metadata)> {
    let opening = format!("\n{MARKER} {nonce}\n");
    let start = exactly_one(stderr, opening.as_bytes(), "control trailer")?;
    let after_opening = &stderr[start + opening.len()..];
    let closing = format!("END-{MARKER} {nonce}\n");
    let closing_start = exactly_one(after_opening, closing.as_bytes(), "control end marker")?;
    let control = after_opening
        .get(..closing_start)
        .filter(|control| control.len() <= MAX_CONTROL_BYTES)
        .ok_or_else(|| data("curl control trailer exceeds its byte limit"))?;
    let control =
        std::str::from_utf8(control).map_err(|_| data("curl control trailer is not UTF-8"))?;
    let mut lines = control.split('\n');
    let status = field(&mut lines, "status")?;
    let effective_url = field(&mut lines, "url")?;
    let redirect_url = field(&mut lines, "redirect")?;
    let content_type = field(&mut lines, "type")?;
    let size = field(&mut lines, "size")?;
    if lines.next() != Some("") || lines.next().is_some() {
        return Err(data("curl control trailer is malformed"));
    }
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(data("curl control trailer has an invalid response status"));
    }
    let status = status
        .parse()
        .map_err(|_| data("curl response status is out of range"))?;
    let effective_url = HttpsUrl::parse(effective_url)
        .map_err(|error| data(format!("curl reported an invalid effective URL: {error}")))?;
    let redirect_url = (!redirect_url.is_empty())
        .then(|| HttpsUrl::parse(redirect_url))
        .transpose()
        .map_err(|error| data(format!("curl reported an invalid redirect URL: {error}")))?;
    let size = decimal("download size", size)?;
    if size != observed_size {
        return Err(data(format!(
            "curl reported {size} downloaded bytes, but gix received {observed_size}"
        )));
    }

    let trailing = &after_opening[closing_start + closing.len()..];
    let diagnostic_len = start
        .checked_add(trailing.len())
        .filter(|len| *len <= MAX_DIAGNOSTIC_BYTES)
        .ok_or_else(|| data("curl diagnostic exceeds its byte limit"))?;
    let mut diagnostic = Vec::with_capacity(diagnostic_len);
    diagnostic.extend_from_slice(&stderr[..start]);
    diagnostic.extend_from_slice(trailing);
    Ok((
        diagnostic,
        Metadata {
            status,
            effective_url,
            redirect_url,
            content_type: content_type.to_owned(),
            size,
        },
    ))
}

fn exactly_one(haystack: &[u8], needle: &[u8], name: &str) -> io::Result<usize> {
    let mut positions = haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == needle).then_some(index));
    let position = positions
        .next()
        .ok_or_else(|| data(format!("curl stderr omitted its matching {name}")))?;
    if positions.next().is_some() {
        return Err(data(format!(
            "curl stderr contained duplicate matching {name}s"
        )));
    }
    Ok(position)
}

fn field<'a>(lines: &mut impl Iterator<Item = &'a str>, name: &str) -> io::Result<&'a str> {
    let line = lines
        .next()
        .ok_or_else(|| data(format!("curl control trailer is missing `{name}`")))?;
    let value = line
        .strip_prefix(&format!("{name}="))
        .ok_or_else(|| data(format!("curl control trailer expected `{name}`")))?;
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == 0x7f)
    {
        return Err(data(format!(
            "curl control trailer `{name}` contains a control character"
        )));
    }
    Ok(value)
}

fn decimal(name: &str, value: &str) -> io::Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(data(format!("curl control trailer has an invalid {name}")));
    }
    value
        .parse()
        .map_err(|_| data(format!("curl control trailer {name} is out of range")))
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

fn data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
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

    #[test]
    fn metadata_authenticates_and_bounds_the_control_trailer() -> io::Result<()> {
        let trailer = |size: u64| {
            format!(
                "certificate note\n\n{MARKER} {NONCE}\n\
                 status=200\n\
                 url=https://EXAMPLE.com:443/repo.git?q=1\n\
                 redirect=https://example.com/next\n\
                 type=application/x-git-upload-pack-result\n\
                 size={size}\n\
                 END-{MARKER} {NONCE}\n\
                 runtime note\n"
            )
            .into_bytes()
        };
        let valid = trailer(12);
        let (diagnostic, metadata) = parse_metadata(&valid, NONCE, 12).expect("valid metadata");
        assert_eq!(diagnostic, b"certificate note\nruntime note\n");
        assert_eq!(
            metadata,
            Metadata {
                status: 200,
                effective_url: HttpsUrl::parse("https://example.com/repo.git?q=1")?,
                redirect_url: Some(HttpsUrl::parse("https://example.com/next")?),
                content_type: "application/x-git-upload-pack-result".to_owned(),
                size: 12,
            }
        );

        let text = std::str::from_utf8(&valid).expect("ASCII");
        let oversized_control = text.replace(
            "type=application/x-git-upload-pack-result",
            &format!("type={}", "x".repeat(MAX_CONTROL_BYTES)),
        );
        let mut oversized_diagnostic = vec![b'x'; MAX_DIAGNOSTIC_BYTES + 1];
        oversized_diagnostic.extend_from_slice(&valid);
        for (stderr, nonce, size) in [
            (b"ordinary diagnostic".to_vec(), NONCE, 12),
            ([valid.as_slice(), valid.as_slice()].concat(), NONCE, 12),
            (
                text.replace(&format!("END-{MARKER} {NONCE}\n"), "")
                    .into_bytes(),
                NONCE,
                12,
            ),
            (
                text.replace("type=application", "type=bad\rapplication")
                    .into_bytes(),
                NONCE,
                12,
            ),
            (text.replace("size=12", "size=11").into_bytes(), NONCE, 12),
            (
                text.replace("url=https://EXAMPLE.com:443", "url=http://example.com")
                    .into_bytes(),
                NONCE,
                12,
            ),
            (oversized_control.into_bytes(), NONCE, 12),
            (oversized_diagnostic, NONCE, 12),
            (valid.clone(), "fedcba9876543210fedcba9876543210", 12),
            (valid.clone(), NONCE, 11),
        ] {
            assert!(parse_metadata(&stderr, nonce, size).is_err());
        }
        Ok(())
    }
}
