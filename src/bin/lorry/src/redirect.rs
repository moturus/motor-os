use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use toml_edit::Item;

use crate::atomic::AtomicFile;
use crate::diagnostic::{Error, Result};
use crate::lockfile::write_toml_string;
use crate::prompt;
use crate::toml::Document;

const MAX_SITES: usize = 4096;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Site(String);

impl Site {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_stored(value: &str) -> Result<Self> {
        let parsed = HttpsUrl::parse(&format!("https://{value}/"))?;
        if parsed.site.as_str() != value {
            return Err(Error::failure(format!(
                "redirect trust site `{value}` is not canonical"
            )));
        }
        Ok(parsed.site)
    }
}

impl fmt::Display for Site {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustStore {
    path: PathBuf,
    allow: BTreeSet<Site>,
    deny: BTreeSet<Site>,
}

impl TrustStore {
    pub fn load(path: &Path) -> Result<Self> {
        let mut store = Self {
            path: path.to_owned(),
            allow: BTreeSet::new(),
            deny: BTreeSet::new(),
        };
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(store),
            Err(error) => {
                return Err(Error::failure(format!(
                    "failed to inspect redirect trust file `{}`: {error}",
                    path.display()
                )));
            }
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(Error::failure(format!(
                    "redirect trust file `{}` is not a real regular file",
                    path.display()
                )));
            }
            Ok(_) => {}
        }
        let document = Document::load(path, "redirect trust file")?;
        for (key, _) in document.root() {
            if !matches!(key, "format-version" | "allow" | "deny") {
                return Err(Error::failure(format!(
                    "redirect trust file `{}` has unknown key `{key}`",
                    path.display()
                )));
            }
        }
        if document
            .root()
            .get("format-version")
            .and_then(Item::as_integer)
            != Some(1)
        {
            return Err(Error::failure(format!(
                "redirect trust file `{}` requires `format-version = 1`",
                path.display()
            )));
        }
        store.allow = site_list(path, &document, "allow")?;
        store.deny = site_list(path, &document, "deny")?;
        if store.allow.len() + store.deny.len() > MAX_SITES {
            return Err(Error::failure(format!(
                "redirect trust file exceeds the {MAX_SITES}-site limit"
            )));
        }
        if let Some(site) = store.allow.intersection(&store.deny).next() {
            return Err(Error::failure(format!(
                "redirect trust site `{site}` appears in both allow and deny lists"
            )));
        }
        Ok(store)
    }

    pub fn decision(&self, site: &Site) -> Option<Decision> {
        if self.allow.contains(site) {
            Some(Decision::Allow)
        } else if self.deny.contains(site) {
            Some(Decision::Deny)
        } else {
            None
        }
    }

    pub fn save(&mut self, site: Site, decision: Decision) -> Result<()> {
        ensure_store_parent(&self.path)?;
        let _lock = TrustLock::acquire(&self.path)?;
        let mut latest = Self::load(&self.path)?;
        let (selected, opposite) = match decision {
            Decision::Allow => (&mut latest.allow, &latest.deny),
            Decision::Deny => (&mut latest.deny, &latest.allow),
        };
        if opposite.contains(&site) {
            return Err(Error::failure(format!(
                "redirect trust site `{site}` already has the opposite persistent decision"
            )));
        }
        selected.insert(site);
        if selected.len() + opposite.len() > MAX_SITES {
            return Err(Error::failure(format!(
                "redirect trust file exceeds the {MAX_SITES}-site limit"
            )));
        }
        let mut staged = AtomicFile::new(&self.path)?;
        staged.write_all(&latest.render())?;
        staged.commit()?;
        *self = latest;
        Ok(())
    }

    fn render(&self) -> Vec<u8> {
        let mut output = String::from("format-version = 1\nallow = [");
        render_sites(&mut output, &self.allow);
        output.push_str("]\ndeny = [");
        render_sites(&mut output, &self.deny);
        output.push_str("]\n");
        output.into_bytes()
    }
}

fn ensure_store_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::failure("redirect trust file has no parent directory"))?;
    fs::create_dir_all(parent).map_err(|error| {
        Error::failure(format!(
            "failed to create redirect trust directory `{}`: {error}",
            parent.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| {
        Error::failure(format!(
            "failed to inspect redirect trust directory `{}`: {error}",
            parent.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::failure(format!(
            "redirect trust directory `{}` is not a real directory",
            parent.display()
        )));
    }
    Ok(())
}

fn site_list(path: &Path, document: &Document, key: &str) -> Result<BTreeSet<Site>> {
    let values = document
        .root()
        .get(key)
        .and_then(Item::as_array)
        .ok_or_else(|| {
            Error::failure(format!(
                "redirect trust file `{}` requires `{key}` to be an array",
                path.display()
            ))
        })?;
    let mut sites = BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or_else(|| {
            Error::failure(format!(
                "redirect trust file `{}` has a non-string `{key}` entry",
                path.display()
            ))
        })?;
        if !sites.insert(Site::from_stored(value)?) {
            return Err(Error::failure(format!(
                "redirect trust file repeats site `{value}` in `{key}`"
            )));
        }
    }
    if sites.len() > MAX_SITES {
        return Err(Error::failure(format!(
            "redirect trust file exceeds the {MAX_SITES}-site limit"
        )));
    }
    Ok(sites)
}

fn render_sites(output: &mut String, sites: &BTreeSet<Site>) {
    for site in sites {
        output.push_str("\n  ");
        write_toml_string(output, site.as_str());
        output.push(',');
    }
    if !sites.is_empty() {
        output.push('\n');
    }
}

struct TrustLock {
    #[allow(dead_code)]
    file: File,
}

impl TrustLock {
    fn acquire(store: &Path) -> Result<Self> {
        let path = store.with_file_name(".redirect-sites.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
            #[cfg(target_os = "linux")]
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&path).map_err(|error| {
            Error::failure(format!(
                "failed to open redirect trust lock `{}`: {error}",
                path.display()
            ))
        })?;
        file.lock().map_err(|error| {
            Error::failure(format!(
                "failed to lock redirect trust file `{}`: {error}",
                store.display()
            ))
        })?;
        Ok(Self { file })
    }
}

pub struct TrustPolicy {
    persistent: TrustStore,
    operation_allow: BTreeSet<Site>,
    operation_deny: BTreeSet<Site>,
}

impl TrustPolicy {
    pub fn load_default() -> Result<Self> {
        Self::load(&default_trust_path()?)
    }

    pub(crate) fn load(path: &Path) -> Result<Self> {
        Ok(Self {
            persistent: TrustStore::load(path)?,
            operation_allow: BTreeSet::new(),
            operation_deny: BTreeSet::new(),
        })
    }

    pub fn authorize(&mut self, source: &HttpsUrl, destination: &HttpsUrl) -> Result<()> {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let mut output = io::stderr().lock();
        self.authorize_with_io(
            source,
            destination,
            stdin.is_terminal(),
            &mut input,
            &mut output,
        )
    }

    fn authorize_with_io<R: BufRead, W: Write>(
        &mut self,
        source: &HttpsUrl,
        destination: &HttpsUrl,
        terminal: bool,
        input: &mut R,
        output: &mut W,
    ) -> Result<()> {
        let site = &destination.site;
        match self
            .persistent
            .decision(site)
            .or_else(|| self.operation_decision(site))
        {
            Some(Decision::Allow) => return Ok(()),
            Some(Decision::Deny) => return Err(denied(site)),
            None => {}
        }
        if !terminal {
            return Err(Error::failure(format!(
                "redirect to unknown site `{site}` requires an interactive decision"
            ))
            .with_help("rerun Lorry from a terminal to allow or deny the redirect site"));
        }
        writeln!(
            output,
            "Lorry was redirected:\n  from: {}\n  to:   {}\n\
             [1] allow for this operation\n\
             [2] allow always\n\
             [3] deny for this operation\n\
             [4] deny always",
            redact_url(&source.request_url),
            redact_url(&destination.request_url)
        )
        .and_then(|()| {
            write!(output, "Redirect decision [3]: ")?;
            output.flush()
        })
        .map_err(|error| Error::failure(format!("failed to write redirect prompt: {error}")))?;

        let response = prompt::read_answer(input, output, prompt::echo_required(terminal))
            .map_err(|error| {
                Error::failure(format!("failed to read redirect decision: {error}"))
            })?;
        match response.trim() {
            "1" => {
                self.operation_allow.insert(site.clone());
                Ok(())
            }
            "2" => self.persistent.save(site.clone(), Decision::Allow),
            "4" => {
                self.persistent.save(site.clone(), Decision::Deny)?;
                Err(denied(site))
            }
            _ => {
                self.operation_deny.insert(site.clone());
                Err(denied(site))
            }
        }
    }

    fn operation_decision(&self, site: &Site) -> Option<Decision> {
        if self.operation_allow.contains(site) {
            Some(Decision::Allow)
        } else if self.operation_deny.contains(site) {
            Some(Decision::Deny)
        } else {
            None
        }
    }
}

fn default_trust_path() -> Result<PathBuf> {
    if cfg!(target_os = "motor") {
        return Ok(PathBuf::from("/user/cfg/lorry-redirect-sites.toml"));
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| Error::failure("HOME is required to locate redirect trust decisions"))?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err(Error::failure("HOME must be an absolute path")
            .with_help("set HOME to the absolute path of the current user's home directory"));
    }
    Ok(home.join(".config/lorry/redirect-sites.toml"))
}

pub(crate) fn redact_url(value: &str) -> String {
    match value.split_once('?') {
        Some((path, _)) => format!("{path}?[REDACTED]"),
        None => value.to_owned(),
    }
}

fn denied(site: &Site) -> Error {
    Error::failure(format!("redirect to site `{site}` was denied"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsUrl {
    pub site: Site,
    pub request_url: String,
}

impl HttpsUrl {
    pub fn parse(value: &str) -> Result<Self> {
        if !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\')
        {
            return Err(invalid(
                "contains non-ASCII, control, or backslash characters",
            ));
        }
        let remainder = value
            .strip_prefix("https://")
            .ok_or_else(|| invalid("must use the exact `https://` scheme"))?;
        if remainder.contains('#') {
            return Err(invalid("must not contain a fragment"));
        }
        let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        if authority.is_empty() || authority.contains('@') {
            return Err(invalid("has an empty authority or user information"));
        }
        let (host, port) = parse_authority(authority)?;
        let site = if port == 443 {
            Site(host.clone())
        } else {
            Site(format!("{host}:{port}"))
        };
        let suffix = match &remainder[authority_end..] {
            "" => "/".to_owned(),
            value if value.starts_with('?') => format!("/{value}"),
            value => value.to_owned(),
        };
        Ok(Self {
            request_url: format!("https://{site}{suffix}"),
            site,
        })
    }
}

fn parse_authority(authority: &str) -> Result<(String, u16)> {
    if let Some(value) = authority.strip_prefix('[') {
        let end = value
            .find(']')
            .ok_or_else(|| invalid("has an unterminated IPv6 address"))?;
        let address = Ipv6Addr::from_str(&value[..end])
            .map_err(|_| invalid("has an invalid IPv6 address"))?;
        let port = parse_port(&value[end + 1..])?;
        return Ok((format!("[{address}]"), port));
    }
    if authority.matches(':').count() > 1 {
        return Err(invalid("must bracket an IPv6 address"));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, Ok(443)), |(host, port)| {
            (host, parse_explicit_port(port))
        });
    Ok((canonical_dns_host(host)?, port?))
}

fn parse_port(suffix: &str) -> Result<u16> {
    if suffix.is_empty() {
        Ok(443)
    } else {
        let value = suffix
            .strip_prefix(':')
            .ok_or_else(|| invalid("has bytes after its IPv6 address"))?;
        parse_explicit_port(value)
    }
}

fn parse_explicit_port(value: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("has an invalid port"));
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid("has a port outside 1 through 65535"))
}

fn canonical_dns_host(host: &str) -> Result<String> {
    if let Ok(address) = Ipv4Addr::from_str(host) {
        return Ok(address.to_string());
    }
    if host.is_empty()
        || host.len() > 253
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(invalid("has an invalid DNS host"));
    }
    Ok(host.to_ascii_lowercase())
}

fn invalid(reason: &str) -> Error {
    Error::failure(format!("invalid redirect URL: {reason}"))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("lorry-redirect-trust-{}-{id}", std::process::id()));
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn path(&self) -> PathBuf {
            self.0.join("redirect-sites.toml")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn canonicalizes_https_sites_and_request_urls() {
        let url = HttpsUrl::parse("https://EXAMPLE.com:443/path?q=1").unwrap();
        assert_eq!(url.site.as_str(), "example.com");
        assert_eq!(url.request_url, "https://example.com/path?q=1");

        let url = HttpsUrl::parse("https://[2001:0db8::1]:8443?q").unwrap();
        assert_eq!(url.site.as_str(), "[2001:db8::1]:8443");
        assert_eq!(url.request_url, "https://[2001:db8::1]:8443/?q");
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_redirect_urls() {
        for value in [
            "http://example.com/",
            "HTTPS://example.com/",
            "https://user@example.com/",
            "https://example.com/#fragment",
            "https://example.com\\@other/",
            "https://example.com:0/",
            "https://example.com./",
            "https://-example.com/",
            "https://2001:db8::1/",
            "https://127.1/",
            "https://2130706433/",
            "https://exa_mple.com/",
        ] {
            assert!(HttpsUrl::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn missing_store_is_empty_and_saved_decisions_are_canonical() {
        let fixture = Fixture::new();
        let mut store = TrustStore::load(&fixture.path()).unwrap();
        let allowed = HttpsUrl::parse("https://allowed.example/path")
            .unwrap()
            .site;
        let denied = HttpsUrl::parse("https://denied.example:8443/path")
            .unwrap()
            .site;
        assert_eq!(store.decision(&allowed), None);
        store.save(denied.clone(), Decision::Deny).unwrap();
        store.save(allowed.clone(), Decision::Allow).unwrap();

        let loaded = TrustStore::load(&fixture.path()).unwrap();
        assert_eq!(loaded.decision(&allowed), Some(Decision::Allow));
        assert_eq!(loaded.decision(&denied), Some(Decision::Deny));
        assert_eq!(fs::read(fixture.path()).unwrap(), loaded.render());
    }

    #[test]
    fn rejects_malformed_duplicate_and_conflicting_stores() {
        let fixture = Fixture::new();
        for source in [
            "format-version = 2\nallow = []\ndeny = []\n",
            "format-version = 1\nallow = [\"Example.com\"]\ndeny = []\n",
            "format-version = 1\nallow = [\"a.test\", \"a.test\"]\ndeny = []\n",
            "format-version = 1\nallow = [\"a.test\"]\ndeny = [\"a.test\"]\n",
            "format-version = 1\nallow = []\ndeny = []\nextra = true\n",
        ] {
            fs::write(fixture.path(), source).unwrap();
            assert!(TrustStore::load(&fixture.path()).is_err(), "{source}");
        }
    }

    #[test]
    fn concurrent_persistent_decisions_merge_under_the_store_lock() {
        let fixture = Fixture::new();
        let path = fixture.path();
        let barrier = Arc::new(Barrier::new(2));
        let threads = ["a.example", "b.example"].map(|name| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store = TrustStore::load(&path).unwrap();
                let site = HttpsUrl::parse(&format!("https://{name}/")).unwrap().site;
                barrier.wait();
                store.save(site, Decision::Allow).unwrap();
            })
        });
        for thread in threads {
            thread.join().unwrap();
        }
        let store = TrustStore::load(&path).unwrap();
        for name in ["a.example", "b.example"] {
            let site = HttpsUrl::parse(&format!("https://{name}/")).unwrap().site;
            assert_eq!(store.decision(&site), Some(Decision::Allow));
        }
    }

    #[test]
    fn operation_and_persistent_prompt_choices_have_distinct_lifetimes() {
        let fixture = Fixture::new();
        let source = HttpsUrl::parse("https://source.example/archive?token=secret").unwrap();
        let once = HttpsUrl::parse("https://once.example/object?credential=secret").unwrap();
        let always = HttpsUrl::parse("https://always.example/object").unwrap();
        let mut policy = TrustPolicy::load(&fixture.path()).unwrap();
        let mut output = Vec::new();

        policy
            .authorize_with_io(
                &source,
                &once,
                true,
                &mut io::Cursor::new(b"1\n"),
                &mut output,
            )
            .unwrap();
        let prompt = String::from_utf8(output.clone()).unwrap();
        assert!(prompt.contains("source.example/archive?[REDACTED]"));
        assert!(prompt.contains("once.example/object?[REDACTED]"));
        assert!(!prompt.contains("secret"));
        output.clear();
        policy
            .authorize_with_io(&source, &once, false, &mut io::empty(), &mut output)
            .unwrap();
        assert!(output.is_empty());
        assert_eq!(
            TrustStore::load(&fixture.path())
                .unwrap()
                .decision(&once.site),
            None
        );

        policy
            .authorize_with_io(
                &source,
                &always,
                true,
                &mut io::Cursor::new(b"2\n"),
                &mut output,
            )
            .unwrap();
        assert_eq!(
            TrustStore::load(&fixture.path())
                .unwrap()
                .decision(&always.site),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn prompt_denials_are_safe_and_noninteractive_unknown_sites_fail() {
        let fixture = Fixture::new();
        let source = HttpsUrl::parse("https://source.example/").unwrap();
        let once = HttpsUrl::parse("https://once.example/").unwrap();
        let always = HttpsUrl::parse("https://always.example/").unwrap();
        let mut policy = TrustPolicy::load(&fixture.path()).unwrap();
        let mut output = Vec::new();

        let error = policy
            .authorize_with_io(
                &source,
                &once,
                true,
                &mut io::Cursor::new(b"invalid\n"),
                &mut output,
            )
            .unwrap_err();
        assert!(error.render().contains("was denied"));
        output.clear();
        assert!(
            policy
                .authorize_with_io(
                    &source,
                    &once,
                    true,
                    &mut io::Cursor::new(b"1\n"),
                    &mut output,
                )
                .is_err()
        );
        assert!(output.is_empty());

        assert!(
            policy
                .authorize_with_io(
                    &source,
                    &always,
                    true,
                    &mut io::Cursor::new(b"4\n"),
                    &mut output,
                )
                .is_err()
        );
        assert_eq!(
            TrustStore::load(&fixture.path())
                .unwrap()
                .decision(&always.site),
            Some(Decision::Deny)
        );
        let unknown = HttpsUrl::parse("https://unknown.example/").unwrap();
        let error = policy
            .authorize_with_io(&source, &unknown, false, &mut io::empty(), &mut output)
            .unwrap_err();
        assert!(error.render().contains("rerun Lorry from a terminal"));
    }

    #[test]
    fn saving_first_decision_creates_the_trust_directory() {
        let fixture = Fixture::new();
        let path = fixture.0.join("new/lorry/redirect-sites.toml");
        let site = HttpsUrl::parse("https://allowed.example/").unwrap().site;
        let mut store = TrustStore::load(&path).unwrap();
        store.save(site.clone(), Decision::Allow).unwrap();
        assert_eq!(
            TrustStore::load(&path).unwrap().decision(&site),
            Some(Decision::Allow)
        );
    }
}
