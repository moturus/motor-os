use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use semver::Version;

use crate::config::NetworkConfig;
use crate::diagnostic::{Error, Result};
use crate::redirect::{HttpsUrl, TrustPolicy, redact_url};

const MAX_STDERR_MEMORY_BYTES: usize = 64 * 1024;
const DEFAULT_STDERR_SPILL_BYTES: u64 = 2 * 1024 * 1024;
const STDERR_SPILL_LIMIT_ENV: &str = "LORRY_CURL_STDERR_SPILL_LIMIT_BYTES";
const MAX_REDIRECTS: usize = 5;
const TIMEOUT_RETRIES: usize = 2;
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
                Path::new("/system/cfg/ssl/ca-certificates.crt"),
                "Motor system CA bundle",
            )?),
            None => None,
        };
        Ok(Self {
            executable,
            ca_bundle,
        })
    }

    pub fn download(
        &self,
        url: &str,
        trust: &mut TrustPolicy,
        staging_parent: &Path,
        max_body_bytes: u64,
    ) -> Result<Download> {
        download_with(
            url,
            trust,
            staging_parent,
            max_body_bytes,
            |url, destination, limit| {
                request(
                    &self.executable,
                    url,
                    self.ca_bundle.as_deref(),
                    destination,
                    limit,
                )
            },
        )
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
    executable(Path::new("/system/bin/curl"), "Motor curl")
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

#[derive(Debug)]
pub struct Download {
    body: ResponseBody,
    pub diagnostic: Vec<u8>,
    pub metadata: Metadata,
}

impl Download {
    pub fn path(&self) -> &Path {
        &self.body.path
    }
}

#[derive(Debug)]
struct ResponseBody {
    path: PathBuf,
}

impl ResponseBody {
    fn create(parent: &Path) -> Result<(Self, File)> {
        let metadata = fs::symlink_metadata(parent).map_err(|error| {
            Error::failure(format!(
                "failed to inspect curl staging directory `{}`: {error}",
                parent.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::failure(format!(
                "curl staging path `{}` is not a real directory",
                parent.display()
            )));
        }
        for _ in 0..100 {
            let path = parent.join(format!(".curl-response-{}", nonce()?));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    if let Err(error) = crate::atomic::set_private_file(&file, &path) {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    return Ok((Self { path }, file));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(Error::failure(format!(
                        "failed to create curl response staging `{}`: {error}",
                        path.display()
                    )));
                }
            }
        }
        Err(Error::failure("could not allocate curl response staging"))
    }
}

impl Drop for ResponseBody {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn download_with<F>(
    initial_url: &str,
    trust: &mut TrustPolicy,
    staging_parent: &Path,
    max_body_bytes: u64,
    mut transfer: F,
) -> Result<Download>
where
    F: FnMut(&str, File, u64) -> Result<(Vec<u8>, Metadata)>,
{
    if max_body_bytes == 0 {
        return Err(Error::failure("curl response body limit must be nonzero"));
    }
    let mut current = HttpsUrl::parse(initial_url)?;
    let mut seen = BTreeSet::from([current.request_url.clone()]);
    let mut redirects = 0;
    loop {
        let (body, destination) = ResponseBody::create(staging_parent)?;
        let (diagnostic, metadata) = transfer(&current.request_url, destination, max_body_bytes)?;
        let effective = HttpsUrl::parse(&metadata.effective_url).map_err(|error| {
            Error::failure(format!("curl reported an invalid effective URL: {error}"))
        })?;
        if effective.request_url != current.request_url
            || metadata.effective_url != effective.request_url
        {
            return Err(Error::failure(format!(
                "curl reported effective URL `{}`, expected `{}`",
                redact_url(&metadata.effective_url),
                redact_url(&current.request_url)
            )));
        }
        if metadata.status == 200 {
            if metadata.redirect_url.is_some() {
                return Err(Error::failure(
                    "curl reported a redirect URL for successful HTTP status 200",
                ));
            }
            return Ok(Download {
                body,
                diagnostic,
                metadata,
            });
        }
        if !matches!(metadata.status, 301 | 302 | 303 | 307 | 308) {
            return Err(Error::failure(format!(
                "curl returned unsupported HTTP status {} for `{}`",
                metadata.status,
                redact_url(&current.request_url)
            )));
        }
        let next = metadata.redirect_url.as_deref().ok_or_else(|| {
            Error::failure(format!(
                "curl returned redirect status {} without a redirect URL",
                metadata.status
            ))
        })?;
        let next = HttpsUrl::parse(next)?;
        if redirects == MAX_REDIRECTS {
            return Err(Error::failure(format!(
                "curl response exceeded the {MAX_REDIRECTS}-redirect limit"
            )));
        }
        if !seen.insert(next.request_url.clone()) {
            return Err(Error::failure(format!(
                "curl redirect loop reached `{}`",
                redact_url(&next.request_url)
            )));
        }
        trust.authorize(&current, &next)?;
        redirects += 1;
        current = next;
    }
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
    execute_request(
        executable,
        arguments,
        &nonce,
        destination,
        max_body_bytes,
        REQUEST_TIMEOUT,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GitMetadata {
    pub status: u16,
    pub effective_url: String,
    pub redirect_url: Option<String>,
    pub content_type: String,
    pub size: u64,
}

pub(crate) fn git_request(
    executable: &Path,
    url: &str,
    ca_bundle: Option<&Path>,
    destination: File,
    max_body_bytes: u64,
    headers: &[String],
    body: Option<Vec<u8>>,
) -> Result<(Vec<u8>, GitMetadata)> {
    if max_body_bytes == 0 {
        return Err(Error::failure(
            "Git HTTP response body limit must be nonzero",
        ));
    }
    let nonce = nonce()?;
    let mut arguments = arguments(url, &nonce, ca_bundle, env!("CARGO_PKG_VERSION"))?;
    let write_out = arguments
        .iter()
        .position(|argument| argument == "--write-out")
        .ok_or_else(|| Error::failure("internal curl arguments omitted --write-out"))?;
    arguments[write_out + 1] = format!(
        "%{{stderr}}\nLORRY-CURL-GIT-1 {nonce}\n\
         status=%{{response_code}}\n\
         url=%{{url_effective}}\n\
         redirect=%{{redirect_url}}\n\
         type=%{{content_type}}\n\
         size=%{{size_download}}\n\
         END-LORRY-CURL-GIT-1 {nonce}\n"
    )
    .into();
    let url_position = arguments
        .iter()
        .position(|argument| argument == "--url")
        .ok_or_else(|| Error::failure("internal curl arguments omitted --url"))?;
    let mut request_arguments =
        Vec::with_capacity(headers.len() * 2 + usize::from(body.is_some()) * 2);
    for header in headers {
        request_arguments.push("--header".into());
        request_arguments.push(header.into());
    }
    if body.is_some() {
        request_arguments.push("--data-binary".into());
        request_arguments.push("@-".into());
    }
    arguments.splice(url_position..url_position, request_arguments);

    let captured = capture_request(
        executable,
        &arguments,
        destination,
        max_body_bytes,
        REQUEST_TIMEOUT,
        body.as_deref(),
    )?;
    let parsed = parse_git_trailer(&captured.stderr, &nonce, captured.body_size);
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
    parsed
}

fn execute_request(
    executable: &Path,
    arguments: Vec<OsString>,
    nonce: &str,
    destination: File,
    max_body_bytes: u64,
    process_timeout: Duration,
) -> Result<(Vec<u8>, Metadata)> {
    let captured = capture_request(
        executable,
        &arguments,
        destination,
        max_body_bytes,
        process_timeout,
        None,
    )?;
    let parsed = parse_trailer(&captured.stderr, nonce, captured.body_size);
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
    let (diagnostic, metadata, _) =
        parse_control_trailer(stderr, nonce, observed_size, "LORRY-CURL-1", false)?;
    Ok((diagnostic, metadata))
}

fn parse_git_trailer(
    stderr: &[u8],
    nonce: &str,
    observed_size: u64,
) -> Result<(Vec<u8>, GitMetadata)> {
    let (diagnostic, metadata, content_type) =
        parse_control_trailer(stderr, nonce, observed_size, "LORRY-CURL-GIT-1", true)?;
    Ok((
        diagnostic,
        GitMetadata {
            status: metadata.status,
            effective_url: metadata.effective_url,
            redirect_url: metadata.redirect_url,
            content_type: content_type.unwrap_or_default(),
            size: metadata.size,
        },
    ))
}

fn parse_control_trailer(
    stderr: &[u8],
    nonce: &str,
    observed_size: u64,
    marker: &str,
    has_content_type: bool,
) -> Result<(Vec<u8>, Metadata, Option<String>)> {
    validate_nonce(nonce)?;
    let opening = format!("\n{marker} {nonce}\n");
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
    let after_opening = &stderr[start + opening.len()..];
    let closing = format!("END-{marker} {nonce}\n");
    let closing_positions = after_opening
        .windows(closing.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == closing.as_bytes()).then_some(index))
        .collect::<Vec<_>>();
    if closing_positions.len() != 1 {
        return Err(Error::failure(format!(
            "curl stderr contained {} matching control end markers instead of one",
            closing_positions.len()
        )));
    }
    let closing_start = closing_positions[0];
    let control = std::str::from_utf8(&after_opening[..closing_start])
        .map_err(|_| Error::failure("curl control trailer is not valid UTF-8"))?;
    let mut lines = control.split('\n');
    let status = field(&mut lines, "status")?;
    let effective_url = field(&mut lines, "url")?;
    let redirect_url = field(&mut lines, "redirect")?;
    let content_type = has_content_type
        .then(|| field(&mut lines, "type").map(str::to_owned))
        .transpose()?;
    let size = field(&mut lines, "size")?;
    if lines.next() != Some("") || lines.next().is_some() {
        return Err(Error::failure("curl control trailer is malformed"));
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
    let trailing = &after_opening[closing_start + closing.len()..];
    let mut diagnostic = Vec::with_capacity(start + trailing.len());
    diagnostic.extend_from_slice(&stderr[..start]);
    diagnostic.extend_from_slice(trailing);
    Ok((
        diagnostic,
        Metadata {
            status,
            effective_url: effective_url.to_owned(),
            redirect_url: (!redirect_url.is_empty()).then(|| redirect_url.to_owned()),
            size,
        },
        content_type,
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

// Keep ordinary requests allocation-only. A noisy debug build moves the whole
// stream to a private file so curl's final control trailer is still retained.
enum CapturedStderr {
    Memory(Vec<u8>),
    Spill(StderrSpill),
}

impl CapturedStderr {
    fn into_bytes(self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Memory(bytes) => Ok(bytes),
            Self::Spill(spill) => spill.into_bytes(),
        }
    }
}

struct StderrSpill {
    path: PathBuf,
    file: File,
}

impl StderrSpill {
    fn create() -> std::io::Result<Self> {
        let parent = fs::canonicalize(std::env::temp_dir())?;
        for _ in 0..100 {
            let suffix = nonce().map_err(|error| std::io::Error::other(error.to_string()))?;
            let path = parent.join(format!(".lorry-curl-stderr-{suffix}"));
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    if let Err(error) = crate::atomic::set_private_file(&file, &path) {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(std::io::Error::other(error.to_string()));
                    }
                    return Ok(Self { path, file });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate curl stderr spill file",
        ))
    }

    fn into_bytes(mut self) -> std::io::Result<Vec<u8>> {
        self.file.flush()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

impl Drop for StderrSpill {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn capture_request(
    executable: &Path,
    arguments: &[OsString],
    destination: File,
    max_body_bytes: u64,
    timeout: Duration,
    input: Option<&[u8]>,
) -> Result<Captured> {
    retry_timeouts(destination, |destination| {
        let mut command = Command::new(executable);
        command
            .args(arguments)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        capture(
            &mut command,
            destination,
            max_body_bytes,
            timeout,
            input.map(<[u8]>::to_vec),
        )
    })
}

fn retry_timeouts(
    mut destination: File,
    mut attempt: impl FnMut(File) -> Result<Captured>,
) -> Result<Captured> {
    for retries in 0..=TIMEOUT_RETRIES {
        let captured = attempt(destination.try_clone().map_err(|error| {
            Error::failure(format!(
                "failed to duplicate curl response staging: {error}"
            ))
        })?)?;
        if captured.status.code() != Some(28) || retries == TIMEOUT_RETRIES {
            return Ok(captured);
        }
        destination.set_len(0).map_err(|error| {
            Error::failure(format!("failed to truncate curl response staging: {error}"))
        })?;
        destination.seek(SeekFrom::Start(0)).map_err(|error| {
            Error::failure(format!("failed to rewind curl response staging: {error}"))
        })?;
    }
    unreachable!()
}

fn capture(
    command: &mut Command,
    destination: File,
    max_body_bytes: u64,
    timeout: Duration,
    input: Option<Vec<u8>>,
) -> Result<Captured> {
    let stderr_spill_limit = stderr_spill_limit()?;
    capture_with_stderr_limit(
        command,
        destination,
        max_body_bytes,
        timeout,
        input,
        stderr_spill_limit,
    )
}

fn capture_with_stderr_limit(
    command: &mut Command,
    destination: File,
    max_body_bytes: u64,
    timeout: Duration,
    input: Option<Vec<u8>>,
    stderr_spill_limit: u64,
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
    let mut input_thread = if let Some(input) = input {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            Error::failure("curl stdin pipe was not created")
        })?;
        Some(std::thread::spawn(move || stdin.write_all(&input)))
    } else {
        None
    };
    let body_exceeded = Arc::new(AtomicBool::new(false));
    let stderr_exceeded = Arc::new(AtomicBool::new(false));
    let body_thread = copy_body(stdout, destination, body_exceeded.clone(), max_body_bytes);
    let stderr_thread = capture_stderr(stderr, stderr_exceeded.clone(), stderr_spill_limit);
    let started = Instant::now();
    let status = loop {
        let failure = if body_exceeded.load(Ordering::Acquire) {
            Some(format!(
                "curl response body exceeded the {max_body_bytes}-byte limit"
            ))
        } else if stderr_exceeded.load(Ordering::Acquire) {
            Some(format!(
                "curl stderr exceeded the {stderr_spill_limit}-byte spill limit"
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
            if let Some(thread) = input_thread.take() {
                let _ = thread.join();
            }
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
                if let Some(thread) = input_thread.take() {
                    let _ = thread.join();
                }
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
        .map_err(|error| Error::failure(format!("failed to read curl stderr: {error}")))?
        .into_bytes()
        .map_err(|error| Error::failure(format!("failed to read curl stderr: {error}")))?;
    if let Some(thread) = input_thread.take() {
        thread
            .join()
            .map_err(|_| Error::failure("curl request-body thread panicked"))?
            .map_err(|error| {
                Error::failure(format!("failed to write curl request body: {error}"))
            })?;
    }
    if body_exceeded.load(Ordering::Acquire) {
        return Err(Error::failure(format!(
            "curl response body exceeded the {max_body_bytes}-byte limit"
        )));
    }
    if stderr_exceeded.load(Ordering::Acquire) {
        return Err(Error::failure(format!(
            "curl stderr exceeded the {stderr_spill_limit}-byte spill limit"
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
    mut source: impl Read + Send + 'static,
    exceeded: Arc<AtomicBool>,
    limit: u64,
) -> std::thread::JoinHandle<std::io::Result<CapturedStderr>> {
    std::thread::spawn(move || {
        let mut memory = Vec::with_capacity(MAX_STDERR_MEMORY_BYTES);
        let mut spill = None;
        let mut total = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                return Ok(match spill {
                    Some(spill) => CapturedStderr::Spill(spill),
                    None => CapturedStderr::Memory(memory),
                });
            }

            let available = usize::try_from(limit.saturating_sub(total)).unwrap_or(usize::MAX);
            let stored = count.min(available);
            if spill.is_none() && total + stored as u64 > MAX_STDERR_MEMORY_BYTES as u64 {
                let mut file = StderrSpill::create()?;
                file.file.write_all(&memory)?;
                memory.clear();
                spill = Some(file);
            }
            if let Some(file) = &mut spill {
                file.file.write_all(&buffer[..stored])?;
            } else {
                memory.extend_from_slice(&buffer[..stored]);
            }
            total = total.saturating_add(count as u64);
            if stored < count {
                exceeded.store(true, Ordering::Release);
                return Ok(match spill {
                    Some(spill) => CapturedStderr::Spill(spill),
                    None => CapturedStderr::Memory(memory),
                });
            }
        }
    })
}

fn stderr_spill_limit() -> Result<u64> {
    let Some(value) = std::env::var_os(STDERR_SPILL_LIMIT_ENV) else {
        return Ok(DEFAULT_STDERR_SPILL_BYTES);
    };
    let value = value.to_str().ok_or_else(|| {
        Error::failure(format!(
            "environment variable `{STDERR_SPILL_LIMIT_ENV}` is not valid UTF-8"
        ))
    })?;
    parse_stderr_spill_limit(value)
}

fn parse_stderr_spill_limit(value: &str) -> Result<u64> {
    let limit = value.parse::<u64>().map_err(|_| {
        Error::failure(format!(
            "environment variable `{STDERR_SPILL_LIMIT_ENV}` must be a byte count"
        ))
    })?;
    if limit < DEFAULT_STDERR_SPILL_BYTES {
        return Err(Error::failure(format!(
            "environment variable `{STDERR_SPILL_LIMIT_ENV}` must be at least {DEFAULT_STDERR_SPILL_BYTES}"
        )));
    }
    Ok(limit)
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
    use std::io::{BufRead, BufReader};
    use std::process::{Child, ChildStdout};

    use crate::redirect::{Decision, TrustStore};

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

    fn git_trailer(size: u64) -> Vec<u8> {
        format!(
            "certificate note\n\
             \nLORRY-CURL-GIT-1 {NONCE}\n\
             status=200\n\
             url=https://example.com/repository.git/info/refs?service=git-upload-pack\n\
             redirect=\n\
             type=application/x-git-upload-pack-advertisement\n\
             size={size}\n\
             END-LORRY-CURL-GIT-1 {NONCE}\n"
        )
        .into_bytes()
    }

    fn root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("lorry-curl-{label}-{}", nonce().unwrap()));
        fs::create_dir(&path).unwrap();
        path
    }

    fn policy(root: &Path, allowed: &[&str]) -> TrustPolicy {
        let path = root.join("redirect-sites.toml");
        let mut store = TrustStore::load(&path).unwrap();
        for url in allowed {
            store
                .save(HttpsUrl::parse(url).unwrap().site, Decision::Allow)
                .unwrap();
        }
        TrustPolicy::load(&path).unwrap()
    }

    fn metadata(status: u16, effective: &str, redirect: Option<&str>) -> Metadata {
        Metadata {
            status,
            effective_url: effective.to_owned(),
            redirect_url: redirect.map(str::to_owned),
            size: 4,
        }
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

    #[test]
    fn follows_only_approved_redirects_and_retains_only_the_final_body() {
        let root = root("redirect");
        let mut trust = policy(&root, &["https://one.example/", "https://two.example/"]);
        let responses = [
            (
                "https://index.crates.io/start",
                metadata(
                    302,
                    "https://index.crates.io/start",
                    Some("https://one.example/a"),
                ),
            ),
            (
                "https://one.example/a",
                metadata(307, "https://one.example/a", Some("https://two.example/b")),
            ),
            (
                "https://two.example/b",
                metadata(200, "https://two.example/b", None),
            ),
        ];
        let mut call = 0;
        let download = download_with(responses[0].0, &mut trust, &root, 32, |url, mut body, _| {
            assert_eq!(url, responses[call].0);
            body.write_all(if call == 2 { b"done" } else { b"skip" })
                .unwrap();
            let result = responses[call].1.clone();
            call += 1;
            Ok((Vec::new(), result))
        })
        .unwrap();
        assert_eq!(fs::read(download.path()).unwrap(), b"done");
        let path = download.path().to_owned();
        drop(download);
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_redirect_loops_sixth_hops_and_effective_url_drift() {
        let root = root("redirect-errors");
        let mut trust = policy(&root, &["https://one.example/"]);
        let mut call = 0;
        let error = download_with(
            "https://index.crates.io/start",
            &mut trust,
            &root,
            32,
            |url, _, _| {
                call += 1;
                let next = if call == 1 {
                    "https://one.example/a"
                } else {
                    "https://index.crates.io/start"
                };
                Ok((Vec::new(), metadata(302, url, Some(next))))
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("loop"));

        let mut trust = policy(&root, &["https://hop.example/"]);
        call = 0;
        let error = download_with(
            "https://index.crates.io/start",
            &mut trust,
            &root,
            32,
            |url, _, _| {
                call += 1;
                let next = format!("https://hop.example/{call}");
                Ok((Vec::new(), metadata(308, url, Some(&next))))
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("5-redirect limit"));
        assert_eq!(call, 6);

        let mut trust = policy(&root, &[]);
        let error = download_with(
            "https://index.crates.io/start?secret",
            &mut trust,
            &root,
            32,
            |_, _, _| {
                Ok((
                    Vec::new(),
                    metadata(200, "https://index.crates.io/other?secret", None),
                ))
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("effective URL"));
        assert!(!error.to_string().contains("secret"));
        fs::remove_dir_all(root).unwrap();
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
    fn parses_git_content_type_from_the_authenticated_control_trailer() {
        let (diagnostic, metadata) = parse_git_trailer(&git_trailer(521), NONCE, 521).unwrap();
        assert_eq!(diagnostic, b"certificate note\n");
        assert_eq!(metadata.status, 200);
        assert_eq!(
            metadata.effective_url,
            "https://example.com/repository.git/info/refs?service=git-upload-pack"
        );
        assert_eq!(
            metadata.content_type,
            "application/x-git-upload-pack-advertisement"
        );
        assert_eq!(metadata.size, 521);
    }

    #[test]
    fn rejects_missing_duplicate_and_malformed_control_data() {
        assert!(parse_trailer(b"ordinary diagnostic", NONCE, 0).is_err());

        let one = trailer(17);
        let mut duplicate = one.clone();
        duplicate.extend_from_slice(&one);
        assert!(parse_trailer(&duplicate, NONCE, 17).is_err());

        let closing = format!("END-LORRY-CURL-1 {NONCE}\n");
        let mut duplicate_closing = one.clone();
        duplicate_closing.extend_from_slice(closing.as_bytes());
        assert!(parse_trailer(&duplicate_closing, NONCE, 17).is_err());

        let malformed = String::from_utf8(one)
            .unwrap()
            .replace("url=https://", "url=https://bad\u{7f}");
        assert!(parse_trailer(malformed.as_bytes(), NONCE, 17).is_err());
    }

    #[test]
    fn retains_diagnostics_before_and_after_the_control_trailer() {
        let mut stderr = trailer(17);
        stderr.extend_from_slice(b"runtime diagnostic after trailer\n");
        let (diagnostic, metadata) = parse_trailer(&stderr, NONCE, 17).unwrap();
        assert_eq!(
            diagnostic,
            b"certificate note\nruntime diagnostic after trailer\n"
        );
        assert_eq!(metadata.status, 302);
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
            "stderr-spill" | "stderr-limit" => Box::new(std::io::stderr()),
            _ => panic!("unknown capture-child action"),
        };
        let iterations = match action.as_str() {
            "pipes" => 6_000,
            "stderr-spill" => 16_384,
            "stderr-limit" => DEFAULT_STDERR_SPILL_BYTES as usize / 8 + 1_024,
            _ => 100_000,
        };
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

    fn selected_test_curl() -> Result<PathBuf> {
        let path = std::env::var_os("LORRY_TEST_CURL").ok_or_else(|| {
            Error::failure("the repository curl integration fixture was not configured")
        })?;
        executable(Path::new(&path), "selected test curl")
    }

    fn selected_test_path(variable: &str) -> PathBuf {
        std::env::var_os(variable)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("the repository integration fixture did not set {variable}"))
    }

    fn trusted_test_ca() -> PathBuf {
        selected_test_path("LORRY_TEST_CA")
    }

    fn untrusted_test_ca() -> PathBuf {
        selected_test_path("LORRY_TEST_UNTRUSTED_CA")
    }

    fn hostname_test_ca() -> PathBuf {
        selected_test_path("LORRY_TEST_HOSTNAME_CA")
    }

    struct TlsServer {
        child: Option<Child>,
        stdout: BufReader<ChildStdout>,
        url: String,
    }

    impl TlsServer {
        fn start(scenario: &str) -> Self {
            Self::start_attempts(scenario, 1)
        }

        fn start_attempts(scenario: &str, attempts: usize) -> Self {
            let server = std::env::var_os("LORRY_TEST_TLS_SERVER")
                .expect("the repository integration fixture did not set LORRY_TEST_TLS_SERVER");
            let mut command = Command::new(server);
            command
                .args(["--exact", "tls_server_child", "--nocapture"])
                .env("LORRY_TEST_TLS_SERVER_SCENARIO", scenario)
                .env("LORRY_TEST_TLS_SERVER_ATTEMPTS", attempts.to_string());
            let mut child = command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdout = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            let mut port = None;
            for _ in 0..16 {
                line.clear();
                if stdout.read_line(&mut line).unwrap() == 0 {
                    let output = child.wait_with_output().unwrap();
                    panic!(
                        "TLS server exited before reporting its port\nstderr: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                if let Some(marker) = line.find("LORRY_TLS_PORT=") {
                    let digits: String = line[marker + "LORRY_TLS_PORT=".len()..]
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .collect();
                    port = Some(digits.parse::<u16>().unwrap());
                    break;
                }
            }
            let port = port.expect("TLS server did not report its listening port");
            Self {
                child: Some(child),
                stdout,
                url: format!("https://127.0.0.1:{port}/object"),
            }
        }

        fn finish(mut self) {
            let mut trailing_stdout = Vec::new();
            self.stdout.read_to_end(&mut trailing_stdout).unwrap();
            let output = self.child.take().unwrap().wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&trailing_stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    impl Drop for TlsServer {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn tls_request(scenario: &str, ca: &Path, limit: u64) -> Result<(PathBuf, Metadata)> {
        let server = TlsServer::start(scenario);
        let (path, file) = destination();
        let result = request(&selected_test_curl()?, &server.url, Some(ca), file, limit);
        server.finish();
        result.map(|(_, metadata)| (path, metadata))
    }

    fn assert_tls_request_fails(scenario: &str, ca: &Path, limit: u64, expected: &str) {
        let server = TlsServer::start(scenario);
        let (path, file) = destination();
        let error = request(
            &selected_test_curl().unwrap(),
            &server.url,
            Some(ca),
            file,
            limit,
        )
        .unwrap_err();
        server.finish();
        assert!(
            error.to_string().to_ascii_lowercase().contains(expected),
            "{scenario}: {error}"
        );
        fs::remove_file(path).unwrap();
    }

    fn replace_argument(arguments: &mut [OsString], option: &str, value: &str) {
        let index = arguments
            .iter()
            .position(|argument| argument.as_os_str() == std::ffi::OsStr::new(option))
            .unwrap();
        arguments[index + 1] = value.into();
    }

    fn assert_tls_request_times_out(max_time: &str, speed_time: &str) {
        let server = TlsServer::start_attempts("stall", TIMEOUT_RETRIES + 1);
        let (path, file) = destination();
        let nonce = nonce().unwrap();
        let mut arguments = arguments(
            &server.url,
            &nonce,
            Some(&trusted_test_ca()),
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();
        replace_argument(&mut arguments, "--max-time", max_time);
        replace_argument(&mut arguments, "--speed-time", speed_time);
        let error = execute_request(
            &selected_test_curl().unwrap(),
            arguments,
            &nonce,
            file,
            1024,
            Duration::from_secs(5),
        )
        .unwrap_err();
        server.finish();
        assert!(error.to_string().contains("status 28"), "{error}");
        fs::remove_file(path).unwrap();
    }

    fn assert_tls_hostname_mismatch_fails() {
        let server = TlsServer::start("hostname");
        let (path, file) = destination();
        let error = request(
            &selected_test_curl().unwrap(),
            &server.url,
            Some(&hostname_test_ca()),
            file,
            5,
        )
        .unwrap_err();
        server.finish();
        assert!(error.to_string().contains("status 60"), "{error}");
        fs::remove_file(path).unwrap();
    }

    fn selected_command(url: &str, ca: Option<&Path>) -> Command {
        let arguments =
            arguments(url, NONCE, ca, env!("CARGO_PKG_VERSION")).expect("valid test arguments");
        let mut command = Command::new(selected_test_curl().unwrap());
        command
            .args(arguments)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null());
        command
    }

    fn assert_selected_request_status(url: &str, ca: Option<&Path>, status: i32) {
        let (path, file) = destination();
        let error = request(&selected_test_curl().unwrap(), url, ca, file, 1024).unwrap_err();
        assert!(
            error.to_string().contains(&format!("status {status}")),
            "{error}"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    #[ignore = "requires the repository curl integration fixture"]
    fn separates_body_and_control_streams_through_selected_curl() {
        let server = TlsServer::start("success");
        let url = server.url.clone();
        let output = selected_command(&url, Some(&trusted_test_ca()))
            .output()
            .unwrap();
        server.finish();

        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"hello");
        assert_eq!(
            output.stderr,
            format!(
                "\nLORRY-CURL-1 {NONCE}\n\
                 status=200\n\
                 url={}\n\
                 redirect=\n\
                 size=5\n\
                 END-LORRY-CURL-1 {NONCE}\n",
                url
            )
            .as_bytes()
        );
    }

    #[test]
    #[ignore = "requires the repository curl integration fixture"]
    fn reports_required_exit_codes_through_selected_curl() {
        let ca = trusted_test_ca();
        eprintln!("exit-code fixture: malformed URL");
        assert_selected_request_status("not a url", None, 3);
        eprintln!("exit-code fixture: name resolution");
        assert_selected_request_status("https://lorry-resolution.invalid/object", Some(&ca), 6);

        eprintln!("exit-code fixture: connection refusal");
        assert_selected_request_status("https://127.0.0.1:1/object", Some(&ca), 7);

        eprintln!("exit-code fixture: TLS handshake");
        assert_tls_request_fails("tls-failure", &ca, 5, "status 35");

        eprintln!("exit-code fixture: local write");
        let server = TlsServer::start("large");
        let mut command = selected_command(&server.url, Some(&ca));
        command.stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child = command.spawn().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut first_body_byte = [0];
        stdout.read_exact(&mut first_body_byte).unwrap();
        drop(stdout);
        let status = child.wait().unwrap();
        server.finish();
        assert_eq!(status.code(), Some(23), "{status:?}");
        eprintln!("exit-code fixture: complete");
    }

    #[test]
    #[ignore = "requires the repository curl integration fixture"]
    fn executes_verified_tls_and_redirect_requests_through_selected_curl() {
        let ca = trusted_test_ca();
        let (path, metadata) = tls_request("success", &ca, 5).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"hello");
        assert_eq!(metadata.status, 200);
        assert_eq!(metadata.size, 5);
        assert!(metadata.redirect_url.is_none());
        fs::remove_file(path).unwrap();

        let (path, metadata) = tls_request("redirect", &ca, 4).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"body");
        assert_eq!(metadata.status, 302);
        assert_eq!(metadata.size, 4);
        assert_eq!(
            metadata.redirect_url,
            Some(metadata.effective_url.replace("/object", "/next"))
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    #[ignore = "requires the repository curl integration fixture"]
    fn accepts_chunked_and_close_delimited_bodies_through_selected_curl() {
        for (scenario, expected) in [
            ("chunked", b"abcde".as_slice()),
            ("close", b"until close".as_slice()),
        ] {
            let (path, metadata) =
                tls_request(scenario, &trusted_test_ca(), expected.len() as u64).unwrap();
            assert_eq!(fs::read(&path).unwrap(), expected);
            assert_eq!(metadata.status, 200);
            assert_eq!(metadata.size, expected.len() as u64);
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    #[ignore = "requires the repository curl integration fixture"]
    fn reports_total_and_low_speed_timeouts_through_selected_curl() {
        assert_tls_request_times_out("1", "5");
        assert_tls_request_times_out("5", "1");
    }

    #[test]
    #[ignore = "requires the repository curl integration fixture"]
    fn rejects_an_untrusted_tls_certificate_through_selected_curl() {
        assert_tls_request_fails("success", &untrusted_test_ca(), 5, "status 60");
    }

    #[test]
    #[ignore = "requires the repository curl integration fixture"]
    fn rejects_a_tls_hostname_mismatch_through_selected_curl() {
        assert_tls_hostname_mismatch_fails();
    }

    #[test]
    #[ignore = "requires the repository curl integration fixture"]
    fn rejects_a_truncated_tls_response_through_selected_curl() {
        assert_tls_request_fails("truncated", &trusted_test_ca(), 5, "curl");
    }

    #[test]
    #[ignore = "requires the repository curl integration fixture"]
    fn rejects_a_malformed_tls_response_through_selected_curl() {
        assert_tls_request_fails("malformed", &trusted_test_ca(), 5, "curl");
    }

    #[test]
    #[ignore = "requires the repository curl integration fixture"]
    fn enforces_the_body_limit_through_selected_curl() {
        assert_tls_request_fails("success", &trusted_test_ca(), 4, "exceeded");
    }

    #[test]
    fn concurrently_drains_body_and_diagnostic_pipes() {
        let (path, file) = destination();
        let captured = capture_with_stderr_limit(
            &mut child("pipes"),
            file,
            60 * 1024,
            Duration::from_secs(10),
            None,
            DEFAULT_STDERR_SPILL_BYTES,
        )
        .unwrap();
        assert!(captured.status.success());
        assert!(captured.body_size >= 48_000);
        assert!(captured.stderr.len() >= 48_000);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn spills_large_stderr_and_preserves_it() {
        let (path, file) = destination();
        let captured = capture_with_stderr_limit(
            &mut child("stderr-spill"),
            file,
            1024,
            Duration::from_secs(10),
            None,
            DEFAULT_STDERR_SPILL_BYTES,
        )
        .unwrap();
        assert!(captured.status.success());
        assert_eq!(captured.stderr.len(), 16_384 * 8);
        assert!(
            captured
                .stderr
                .chunks_exact(8)
                .all(|chunk| chunk == b"12345678")
        );
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
            let error = capture_with_stderr_limit(
                &mut child(action),
                file,
                body_limit,
                timeout,
                None,
                DEFAULT_STDERR_SPILL_BYTES,
            )
            .err()
            .unwrap();
            assert!(error.to_string().contains(expected), "{error}");
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn validates_stderr_spill_limit_override() {
        assert_eq!(
            parse_stderr_spill_limit("104857600").unwrap(),
            100 * 1024 * 1024
        );
        for value in ["", "1MiB", "0", "2097151"] {
            assert!(parse_stderr_spill_limit(value).is_err(), "{value}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn retries_only_timeout_status_and_discards_partial_bodies() {
        use std::os::unix::process::ExitStatusExt;

        let (path, file) = destination();
        let mut calls = 0;
        let captured = retry_timeouts(file, |mut destination| {
            calls += 1;
            destination
                .write_all(match calls {
                    1 => b"first partial",
                    2 => b"second partial",
                    _ => b"complete",
                })
                .unwrap();
            Ok(Captured {
                status: ExitStatus::from_raw(if calls < 3 { 28 << 8 } else { 0 }),
                stderr: Vec::new(),
                body_size: 0,
            })
        })
        .unwrap();
        assert!(captured.status.success());
        assert_eq!(calls, 3);
        assert_eq!(fs::read(&path).unwrap(), b"complete");
        fs::remove_file(path).unwrap();

        let (path, file) = destination();
        calls = 0;
        let captured = retry_timeouts(file, |mut destination| {
            calls += 1;
            destination.write_all(b"failure").unwrap();
            Ok(Captured {
                status: ExitStatus::from_raw(7 << 8),
                stderr: Vec::new(),
                body_size: 0,
            })
        })
        .unwrap();
        assert_eq!(captured.status.code(), Some(7));
        assert_eq!(calls, 1);
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bounds_timeout_retries() {
        use std::os::unix::process::ExitStatusExt;

        let (path, file) = destination();
        let mut calls = 0;
        let captured = retry_timeouts(file, |_| {
            calls += 1;
            Ok(Captured {
                status: ExitStatus::from_raw(28 << 8),
                stderr: Vec::new(),
                body_size: 0,
            })
        })
        .unwrap();
        assert_eq!(captured.status.code(), Some(28));
        assert_eq!(calls, TIMEOUT_RETRIES + 1);
        fs::remove_file(path).unwrap();
    }
}
