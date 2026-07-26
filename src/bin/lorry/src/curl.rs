use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use semver::Version;

use crate::config::NetworkConfig;
use crate::diagnostic::{Error, Result};

const MAX_STDERR_BYTES: u64 = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(305);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Client {
    pub executable: PathBuf,
    pub ca_bundle: Option<PathBuf>,
}

impl Client {
    pub fn discover(config: &NetworkConfig) -> Result<Self> {
        let executable = match &config.curl {
            Some(path) => executable(path, "configured curl")?,
            None => default_executable()?,
        };
        let ca_bundle = match &config.ca_bundle {
            Some(path) => Some(regular_file(path, "configured CA bundle")?),
            None if cfg!(target_os = "motor") => Some(regular_file(
                Path::new("/sys/cfg/ssl/ca-certificates.crt"),
                "Motor system CA bundle",
            )?),
            None => None,
        };
        Ok(Self {
            executable,
            ca_bundle,
        })
    }
}

pub fn sparse_url(name: &str) -> Result<String> {
    let name = canonical_name(name)?;
    let path = match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    };
    Ok(format!("https://index.crates.io/{path}"))
}

pub fn archive_url(name: &str, version: &Version) -> Result<String> {
    let name = canonical_name(name)?;
    Ok(format!(
        "https://static.crates.io/crates/{name}/{name}-{version}.crate"
    ))
}

fn canonical_name(name: &str) -> Result<String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !name.bytes().any(|byte| byte.is_ascii_alphabetic())
    {
        return Err(Error::failure(format!(
            "cannot construct a crates.io URL for invalid package name `{name}`"
        )));
    }
    Ok(name.to_ascii_lowercase())
}

#[cfg(target_os = "motor")]
fn default_executable() -> Result<PathBuf> {
    executable(Path::new("/bin/curl"), "Motor curl")
}

#[cfg(not(target_os = "motor"))]
fn default_executable() -> Result<PathBuf> {
    let path = std::env::var_os("PATH")
        .and_then(|path| find_in_path("curl", &path))
        .ok_or_else(|| {
            Error::failure("curl was not found in PATH")
                .with_help("install curl 7.63.0 or newer, or configure `network.curl`")
        })?;
    executable(&path, "curl from PATH")
}

#[cfg(not(target_os = "motor"))]
fn find_in_path(name: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|directory| directory.join(name))
        .find(|candidate| executable(candidate, "PATH candidate").is_ok())
}

fn executable(path: &Path, description: &str) -> Result<PathBuf> {
    let path = regular_file(path, description)?;
    let _metadata = fs::metadata(&path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect {description} `{}`: {error}",
            path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if _metadata.permissions().mode() & 0o111 == 0 {
            return Err(Error::failure(format!(
                "{description} `{}` is not executable",
                path.display()
            )));
        }
    }
    Ok(path)
}

fn regular_file(path: &Path, description: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        Error::failure(format!(
            "failed to resolve {description} `{}`: {error}",
            path.display()
        ))
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        Error::failure(format!(
            "failed to inspect {description} `{}`: {error}",
            canonical.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(Error::failure(format!(
            "{description} `{}` is not a regular file",
            canonical.display()
        )));
    }
    Ok(canonical)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub status: u16,
    pub effective_url: String,
    pub redirect_url: Option<String>,
    pub size: u64,
}

pub fn request(
    executable: &Path,
    url: &str,
    ca_bundle: Option<&Path>,
    destination: File,
    max_body_bytes: u64,
) -> Result<(Vec<u8>, Metadata)> {
    if max_body_bytes == 0 {
        return Err(Error::failure("curl response body limit must be nonzero"));
    }
    let nonce = nonce()?;
    let arguments = arguments(url, &nonce, ca_bundle, env!("CARGO_PKG_VERSION"))?;
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let captured = capture(&mut command, destination, max_body_bytes, REQUEST_TIMEOUT)?;
    let parsed = parse_trailer(&captured.stderr, &nonce, captured.body_size);
    if !captured.status.success() {
        let diagnostic = parsed.map(|value| value.0).unwrap_or(captured.stderr);
        let diagnostic = String::from_utf8_lossy(&diagnostic);
        return Err(Error::failure(format!(
            "curl `{}` failed{}{}",
            executable.display(),
            captured
                .status
                .code()
                .map_or_else(String::new, |code| format!(" with status {code}")),
            if diagnostic.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", diagnostic.trim())
            }
        )));
    }
    let (diagnostic, metadata) = parsed?;
    Ok((diagnostic, metadata))
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

struct Captured {
    status: ExitStatus,
    stderr: Vec<u8>,
    body_size: u64,
}

fn capture(
    command: &mut Command,
    destination: File,
    max_body_bytes: u64,
    timeout: Duration,
) -> Result<Captured> {
    let mut child = command.spawn().map_err(|error| {
        Error::failure(format!(
            "failed to start curl `{}`: {error}",
            Path::new(command.get_program()).display()
        ))
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::failure("curl stdout pipe was not created"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::failure("curl stderr pipe was not created"))?;
    let body_exceeded = Arc::new(AtomicBool::new(false));
    let stderr_exceeded = Arc::new(AtomicBool::new(false));
    let body_thread = copy_body(stdout, destination, body_exceeded.clone(), max_body_bytes);
    let stderr_thread = capture_stderr(stderr, stderr_exceeded.clone());
    let started = Instant::now();
    let status = loop {
        let failure = if body_exceeded.load(Ordering::Acquire) {
            Some(format!(
                "curl response body exceeded the {max_body_bytes}-byte limit"
            ))
        } else if stderr_exceeded.load(Ordering::Acquire) {
            Some(format!(
                "curl stderr exceeded the {MAX_STDERR_BYTES}-byte limit"
            ))
        } else if started.elapsed() >= timeout {
            Some(format!(
                "curl process did not exit within {} seconds",
                timeout.as_secs()
            ))
        } else {
            None
        };
        if let Some(message) = failure {
            let _ = child.kill();
            let _ = child.wait();
            let _ = body_thread.join();
            let _ = stderr_thread.join();
            return Err(Error::failure(message));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = body_thread.join();
                let _ = stderr_thread.join();
                return Err(Error::failure(format!(
                    "failed while waiting for curl: {error}"
                )));
            }
        }
    };
    let body_size = body_thread
        .join()
        .map_err(|_| Error::failure("curl body capture thread panicked"))?
        .map_err(|error| Error::failure(format!("failed to stage curl response: {error}")))?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| Error::failure("curl stderr capture thread panicked"))?
        .map_err(|error| Error::failure(format!("failed to read curl stderr: {error}")))?;
    if body_exceeded.load(Ordering::Acquire) {
        return Err(Error::failure(format!(
            "curl response body exceeded the {max_body_bytes}-byte limit"
        )));
    }
    if stderr_exceeded.load(Ordering::Acquire) {
        return Err(Error::failure(format!(
            "curl stderr exceeded the {MAX_STDERR_BYTES}-byte limit"
        )));
    }
    Ok(Captured {
        status,
        stderr,
        body_size,
    })
}

fn copy_body(
    mut source: impl Read + Send + 'static,
    mut destination: File,
    exceeded: Arc<AtomicBool>,
    limit: u64,
) -> std::thread::JoinHandle<std::io::Result<u64>> {
    std::thread::spawn(move || {
        let mut total = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                destination.flush()?;
                return Ok(total);
            }
            let available = limit.saturating_sub(total) as usize;
            destination.write_all(&buffer[..count.min(available)])?;
            total = total.saturating_add(count as u64);
            if count > available {
                exceeded.store(true, Ordering::Release);
                return Ok(total);
            }
        }
    })
}

fn capture_stderr(
    source: impl Read + Send + 'static,
    exceeded: Arc<AtomicBool>,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut captured = Vec::new();
        source
            .take(MAX_STDERR_BYTES + 1)
            .read_to_end(&mut captured)?;
        if captured.len() as u64 > MAX_STDERR_BYTES {
            captured.truncate(MAX_STDERR_BYTES as usize);
            exceeded.store(true, Ordering::Release);
        }
        Ok(captured)
    })
}

fn nonce() -> Result<String> {
    let mut bytes = [0_u8; 16];
    fill_random(&mut bytes)?;
    let mut nonce = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        nonce.push(HEX[(byte >> 4) as usize] as char);
        nonce.push(HEX[(byte & 0xf) as usize] as char);
    }
    Ok(nonce)
}

#[cfg(target_os = "motor")]
fn fill_random(bytes: &mut [u8]) -> Result<()> {
    moto_rt::fill_random_bytes(bytes);
    Ok(())
}

#[cfg(not(target_os = "motor"))]
fn fill_random(bytes: &mut [u8]) -> Result<()> {
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(bytes))
        .map_err(|error| Error::failure(format!("failed to obtain curl control nonce: {error}")))
}

#[cfg(test)]
mod tests {
    use std::fs;

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
        validate_nonce(&nonce().unwrap()).unwrap();
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
    fn constructs_only_canonical_crates_io_urls() {
        assert_eq!(sparse_url("A").unwrap(), "https://index.crates.io/1/a");
        assert_eq!(sparse_url("BC").unwrap(), "https://index.crates.io/2/bc");
        assert_eq!(
            sparse_url("AbC").unwrap(),
            "https://index.crates.io/3/a/abc"
        );
        assert_eq!(
            sparse_url("Serde_JSON").unwrap(),
            "https://index.crates.io/se/rd/serde_json"
        );
        assert_eq!(
            archive_url("Serde", &Version::parse("1.2.3-alpha.1").unwrap()).unwrap(),
            "https://static.crates.io/crates/serde/serde-1.2.3-alpha.1.crate"
        );
        assert!(sparse_url("../bad").is_err());
        assert!(sparse_url("123").is_err());
    }

    #[cfg(not(target_os = "motor"))]
    #[test]
    fn discovers_absolute_executable_and_ca_paths() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("lorry-curl-discovery-{}", nonce().unwrap()));
        fs::create_dir(&root).unwrap();
        let program = root.join("curl");
        let ca = root.join("ca.pem");
        fs::write(&program, b"fixture").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&ca, b"fixture").unwrap();
        let client = Client::discover(&NetworkConfig {
            curl: Some(program.clone()),
            ca_bundle: Some(ca.clone()),
        })
        .unwrap();
        assert_eq!(client.executable, fs::canonicalize(program).unwrap());
        assert_eq!(client.ca_bundle, Some(fs::canonicalize(ca).unwrap()));
        assert_eq!(
            find_in_path("curl", root.as_os_str()),
            Some(client.executable)
        );
        fs::remove_dir_all(root).unwrap();
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

    #[test]
    fn capture_child() {
        let Ok(action) = std::env::var("LORRY_CURL_CAPTURE_CHILD") else {
            return;
        };
        assert_eq!(std::env::var("LC_ALL").as_deref(), Ok("C"));
        assert!(std::env::var_os("HOME").is_none());
        if action == "stall" {
            std::thread::sleep(Duration::from_secs(10));
            return;
        }
        let mut output: Box<dyn Write> = match action.as_str() {
            "pipes" | "body-limit" => Box::new(std::io::stdout()),
            "stderr-limit" => Box::new(std::io::stderr()),
            _ => panic!("unknown capture-child action"),
        };
        let iterations = if action == "pipes" { 6_000 } else { 100_000 };
        for _ in 0..iterations {
            output.write_all(b"12345678").unwrap();
            if action == "pipes" {
                std::io::stderr().write_all(b"abcdefgh").unwrap();
            }
        }
    }

    fn child(action: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "curl::tests::capture_child", "--nocapture"])
            .env_clear()
            .env("LC_ALL", "C")
            .env("LORRY_CURL_CAPTURE_CHILD", action)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn destination() -> (std::path::PathBuf, File) {
        let path = std::env::temp_dir().join(format!("lorry-curl-capture-{}", nonce().unwrap()));
        let file = File::create(&path).unwrap();
        (path, file)
    }

    #[test]
    fn concurrently_drains_body_and_diagnostic_pipes() {
        let (path, file) = destination();
        let captured = capture(
            &mut child("pipes"),
            file,
            60 * 1024,
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(captured.status.success());
        assert!(captured.body_size >= 48_000);
        assert!(captured.stderr.len() >= 48_000);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn terminates_children_on_limits_and_timeout() {
        for (action, body_limit, timeout, expected) in [
            ("body-limit", 64, Duration::from_secs(10), "body exceeded"),
            (
                "stderr-limit",
                1024,
                Duration::from_secs(10),
                "stderr exceeded",
            ),
            ("stall", 1024, Duration::from_millis(20), "did not exit"),
        ] {
            let (path, file) = destination();
            let error = capture(&mut child(action), file, body_limit, timeout)
                .err()
                .unwrap();
            assert!(error.to_string().contains(expected), "{error}");
            fs::remove_file(path).unwrap();
        }
    }
}
