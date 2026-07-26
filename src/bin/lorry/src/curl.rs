use std::ffi::OsString;
use std::path::Path;

use crate::diagnostic::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub status: u16,
    pub effective_url: String,
    pub redirect_url: Option<String>,
    pub size: u64,
}

pub fn arguments(
    url: &str,
    nonce: &str,
    ca_bundle: Option<&Path>,
    lorry_version: &str,
) -> Result<Vec<OsString>> {
    validate_nonce(nonce)?;
    let write_out = format!(
        "%{{stderr}}\nLORRY-CURL-1 {nonce}\n\
         status=%{{response_code}}\n\
         url=%{{url_effective}}\n\
         redirect=%{{redirect_url}}\n\
         size=%{{size_download}}\n\
         END-LORRY-CURL-1 {nonce}\n"
    );
    let mut arguments = [
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
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    arguments.push(format!("lorry/{lorry_version}").into());
    arguments.extend(
        [
            "--header",
            "Accept-Encoding: identity",
            "--output",
            "-",
            "--write-out",
        ]
        .into_iter()
        .map(OsString::from),
    );
    arguments.push(write_out.into());
    if let Some(ca_bundle) = ca_bundle {
        arguments.push("--cacert".into());
        arguments.push(ca_bundle.as_os_str().to_owned());
    }
    arguments.push("--url".into());
    arguments.push(url.into());
    Ok(arguments)
}

pub fn parse_trailer(
    stderr: &[u8],
    nonce: &str,
    observed_size: u64,
) -> Result<(Vec<u8>, Metadata)> {
    validate_nonce(nonce)?;
    let opening = format!("\nLORRY-CURL-1 {nonce}\n");
    let positions = stderr
        .windows(opening.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == opening.as_bytes()).then_some(index))
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(Error::failure(format!(
            "curl stderr contained {} matching control trailers instead of one",
            positions.len()
        )));
    }
    let start = positions[0];
    let control = std::str::from_utf8(&stderr[start + opening.len()..])
        .map_err(|_| Error::failure("curl control trailer is not valid UTF-8"))?;
    let mut lines = control.split('\n');
    let status = field(&mut lines, "status")?;
    let effective_url = field(&mut lines, "url")?;
    let redirect_url = field(&mut lines, "redirect")?;
    let size = field(&mut lines, "size")?;
    if lines.next() != Some(&format!("END-LORRY-CURL-1 {nonce}"))
        || lines.next() != Some("")
        || lines.next().is_some()
    {
        return Err(Error::failure(
            "curl control trailer has a malformed or non-final end marker",
        ));
    }
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::failure(
            "curl control trailer has an invalid response status",
        ));
    }
    let status = status
        .parse::<u16>()
        .map_err(|_| Error::failure("curl response status is out of range"))?;
    if effective_url.is_empty() {
        return Err(Error::failure(
            "curl control trailer has an empty effective URL",
        ));
    }
    let size = decimal("download size", size)?;
    if size != observed_size {
        return Err(Error::failure(format!(
            "curl reported {size} downloaded bytes, but Lorry received {observed_size}"
        )));
    }
    Ok((
        stderr[..start].to_vec(),
        Metadata {
            status,
            effective_url: effective_url.to_owned(),
            redirect_url: (!redirect_url.is_empty()).then(|| redirect_url.to_owned()),
            size,
        },
    ))
}

fn field<'a>(lines: &mut impl Iterator<Item = &'a str>, name: &str) -> Result<&'a str> {
    let line = lines
        .next()
        .ok_or_else(|| Error::failure(format!("curl control trailer is missing `{name}`")))?;
    let value = line.strip_prefix(&format!("{name}=")).ok_or_else(|| {
        Error::failure(format!(
            "curl control trailer expected `{name}`, found `{line}`"
        ))
    })?;
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == 0x7f)
    {
        return Err(Error::failure(format!(
            "curl control trailer `{name}` contains a control character"
        )));
    }
    Ok(value)
}

fn decimal(name: &str, value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::failure(format!(
            "curl control trailer has an invalid {name}"
        )));
    }
    value
        .parse()
        .map_err(|_| Error::failure(format!("curl control trailer {name} is out of range")))
}

fn validate_nonce(nonce: &str) -> Result<()> {
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::failure(
            "internal curl control nonce is not 32 lowercase hexadecimal digits",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    fn trailer(size: u64) -> Vec<u8> {
        format!(
            "certificate note\n\
             \nLORRY-CURL-1 {NONCE}\n\
             status=302\n\
             url=https://index.crates.io/a\n\
             redirect=https://static.crates.io/b\n\
             size={size}\n\
             END-LORRY-CURL-1 {NONCE}\n"
        )
        .into_bytes()
    }

    #[test]
    fn renders_the_exact_bounded_request_surface() {
        let arguments = arguments(
            "https://index.crates.io/config.json",
            NONCE,
            Some(Path::new("/ca.pem")),
            "1.2.3",
        )
        .unwrap();
        assert_eq!(arguments[0], "--disable");
        assert!(!arguments.iter().any(|value| value == "--location"));
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--proto", "=https"])
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--cacert", "/ca.pem"])
        );
        assert_eq!(
            &arguments[arguments.len() - 2..],
            ["--url", "https://index.crates.io/config.json"]
        );
        let write_out = arguments
            .iter()
            .position(|value| value == "--write-out")
            .map(|index| arguments[index + 1].to_string_lossy())
            .unwrap();
        assert!(write_out.starts_with("%{stderr}\nLORRY-CURL-1"));
        assert!(write_out.ends_with(&format!("END-LORRY-CURL-1 {NONCE}\n")));
    }

    #[test]
    fn parses_one_final_trailer_and_checks_the_observed_size() {
        let (diagnostic, metadata) = parse_trailer(&trailer(17), NONCE, 17).unwrap();
        assert_eq!(diagnostic, b"certificate note\n");
        assert_eq!(metadata.status, 302);
        assert_eq!(metadata.effective_url, "https://index.crates.io/a");
        assert_eq!(
            metadata.redirect_url.as_deref(),
            Some("https://static.crates.io/b")
        );
        assert_eq!(metadata.size, 17);

        assert!(parse_trailer(&trailer(16), NONCE, 17).is_err());
    }

    #[test]
    fn rejects_missing_duplicate_nonfinal_and_malformed_control_data() {
        assert!(parse_trailer(b"ordinary diagnostic", NONCE, 0).is_err());

        let one = trailer(17);
        let mut duplicate = one.clone();
        duplicate.extend_from_slice(&one);
        assert!(parse_trailer(&duplicate, NONCE, 17).is_err());

        let mut trailing = one.clone();
        trailing.extend_from_slice(b"unexpected");
        assert!(parse_trailer(&trailing, NONCE, 17).is_err());

        let malformed = String::from_utf8(one)
            .unwrap()
            .replace("url=https://", "url=https://bad\u{7f}");
        assert!(parse_trailer(malformed.as_bytes(), NONCE, 17).is_err());
    }
}
