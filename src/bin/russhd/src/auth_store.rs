//! Login credentials: the user registry and one key file per name. Every check
//! re-reads them, so a change applies to the next authentication and nothing
//! outlives its file. Login names select credentials; they are not OS users.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh::keys::PublicKey;
use russh::keys::ssh_key::public::KeyData;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::trusted_file::{self, Readers, Reason};

const REGISTRY_VERSION: u32 = 1;
const MAX_NAME_BYTES: usize = 64;
const MAX_USERS: usize = 1024;
const MAX_KEYS: usize = 1024;
const MAX_KEY_LINE_BYTES: usize = 16 * 1024;
const PASSWORD_HASH_BYTES: usize = 32;

const SHIPPED_PASSWORD: &str = "vroomvroom";
const SHIPPED_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqjlUjeBcqvHyy+RvVL54pfyK7vj5kAkJRt+qLlZWPH";

/// The outcome of one check. A denial is the default, and failures read as one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Verdict {
    pub accepted: bool,
    /// The credentials loaded for this name include a shipped test credential.
    pub shipped_credentials: bool,
}

/// Why a whole file was refused, with no text from the file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Problem {
    reason: Reason,
    line: Option<usize>,
}

impl From<Reason> for Problem {
    fn from(reason: Reason) -> Self {
        Self { reason, line: None }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}: {}", self.reason),
            None => f.write_str(self.reason),
        }
    }
}

/// The line a TOML error refers to; its own text quotes the input.
pub(crate) fn toml_error_line(text: &str, error: &toml::de::Error) -> Option<usize> {
    let start = error.span()?.start;
    Some(
        text.as_bytes()[..start.min(text.len())]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            + 1,
    )
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    version: u32,
    #[serde(default)]
    users: BTreeMap<String, RecordFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    #[serde(default)]
    salt: String, // hex string
    #[serde(default)]
    password_hash: String, // hex string; absent or empty disables the password
}

struct Record {
    salt: Vec<u8>,
    password_hash: Option<Vec<u8>>,
}

impl Record {
    fn parse(file: &RecordFile) -> Result<Self, Reason> {
        let salt = hex::decode(&file.salt).map_err(|_| "a salt is not hexadecimal")?;
        if file.password_hash.is_empty() {
            return Ok(Self {
                salt,
                password_hash: None,
            });
        }
        let hash = hex::decode(&file.password_hash).map_err(|_| "a hash is not hexadecimal")?;
        if hash.len() != PASSWORD_HASH_BYTES {
            return Err("a hash is not 32 bytes");
        }
        Ok(Self {
            salt,
            password_hash: Some(hash),
        })
    }

    fn password_matches(&self, password: &str) -> bool {
        let Some(expected) = self.password_hash.as_ref() else {
            return false;
        };
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(password.as_bytes());
        expected.as_slice() == hasher.finalize().as_slice()
    }
}

fn parse_registry(bytes: &[u8]) -> Result<BTreeMap<String, Record>, Problem> {
    let text = std::str::from_utf8(bytes).map_err(|_| Problem::from("not UTF-8"))?;
    let registry = toml::from_str::<RegistryFile>(text).map_err(|error| Problem {
        reason: "malformed or unknown entry",
        line: toml_error_line(text, &error),
    })?;
    if registry.version != REGISTRY_VERSION {
        return Err("unsupported version".into());
    }
    if registry.users.len() > MAX_USERS {
        return Err("more than 1024 users".into());
    }
    let mut users = BTreeMap::new();
    for (name, file) in &registry.users {
        if !valid_name(name) {
            return Err("an invalid user name".into());
        }
        users.insert(name.clone(), Record::parse(file)?);
    }
    Ok(users)
}

/// One record, which must be exactly `KEYTYPE BASE64 [COMMENT]`. A record with
/// options has no key type where one has to be, so it can never parse: nothing
/// strips options to recover a key.
fn parse_key_record(line: &str) -> Result<KeyData, Reason> {
    let mut fields = line.split_ascii_whitespace();
    let (Some(key_type), Some(blob)) = (fields.next(), fields.next()) else {
        return Err("not a key record");
    };
    if key_type.contains("-cert-") {
        return Err("certificate records are not supported");
    }
    let key = PublicKey::from_openssh(&format!("{key_type} {blob}"))
        .map_err(|_| "not a plain key record")?;
    match key.key_data() {
        KeyData::Other(_) => Err("unsupported key type"),
        key_data => Ok(key_data.clone()),
    }
}

/// The keys of a file. A bad record authorizes nothing and costs only itself; a
/// file past a limit, or with bytes no key file has, is refused whole.
fn parse_key_file(bytes: &[u8], file_name: &str) -> Result<Vec<KeyData>, Problem> {
    if bytes.contains(&0) {
        return Err("contains NUL".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Problem::from("not UTF-8"))?;
    let mut keys = Vec::new();
    let mut records = 0;
    for (index, line) in text.split('\n').enumerate() {
        let number = index + 1;
        if line.len() > MAX_KEY_LINE_BYTES {
            return Err(Problem {
                reason: "line exceeds 16 KiB",
                line: Some(number),
            });
        }
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        records += 1;
        if records > MAX_KEYS {
            return Err(Problem {
                reason: "more than 1024 keys",
                line: Some(number),
            });
        }
        match parse_key_record(line) {
            Ok(key) => keys.push(key),
            Err(reason) => log::warn!("{file_name}: line {number}: skipped: {reason}"),
        }
    }
    Ok(keys)
}

pub struct AuthStore {
    users_file: PathBuf,
    keys_dir: PathBuf,
    trust_root: Option<PathBuf>,
    shipped_key: KeyData,
}

impl AuthStore {
    pub fn new(users_file: &Path, keys_dir: &Path) -> Self {
        Self::with_trust_root(users_file, keys_dir, trusted_file::default_trust_root())
    }

    pub fn with_trust_root(
        users_file: &Path,
        keys_dir: &Path,
        trust_root: Option<PathBuf>,
    ) -> Self {
        Self {
            users_file: users_file.to_owned(),
            keys_dir: keys_dir.to_owned(),
            trust_root,
            shipped_key: PublicKey::from_openssh(SHIPPED_KEY)
                .expect("the shipped key parses")
                .key_data()
                .clone(),
        }
    }

    fn load_registry(&self) -> Option<BTreeMap<String, Record>> {
        let bytes = trusted_file::read(
            &self.users_file,
            self.trust_root.as_deref(),
            Readers::TrustedOnly,
        );
        let parsed = match bytes {
            Ok(Some(bytes)) => parse_registry(&bytes),
            Ok(None) => Err("missing".into()),
            Err(reason) => Err(reason.into()),
        };
        parsed
            .inspect_err(|problem| {
                log::warn!("{}: {problem}", self.users_file.display());
            })
            .ok()
    }

    /// The keys of a configured `name`, which is what makes it safe in a path.
    /// `None` denies the key method; a missing file just lists no keys.
    fn load_keys(&self, name: &str) -> Option<Vec<KeyData>> {
        let path = self.keys_dir.join(format!("authorized_keys.{name}"));
        let file_name = format!("authorized_keys.{name}");
        let parsed = match trusted_file::read(&path, self.trust_root.as_deref(), Readers::Anyone) {
            Ok(Some(bytes)) => parse_key_file(&bytes, &file_name),
            Ok(None) => Ok(Vec::new()),
            Err(reason) => Err(reason.into()),
        };
        parsed
            .inspect_err(|problem| log::warn!("{file_name}: {problem}"))
            .ok()
    }

    /// Reads and validates the registry and answers for exactly `user`.
    pub fn check_password(&self, user: &str, password: &str) -> Verdict {
        let Some(users) = self.load_registry() else {
            return Verdict::default();
        };
        let Some(record) = users.get(user) else {
            return Verdict::default();
        };
        Verdict {
            accepted: record.password_matches(password),
            shipped_credentials: record.password_matches(SHIPPED_PASSWORD),
        }
    }

    /// The one key check, for offered and signed requests alike. Limits apply
    /// to the whole file before any record can match.
    pub fn check_key(&self, user: &str, key: &PublicKey) -> Verdict {
        let Some(users) = self.load_registry() else {
            return Verdict::default();
        };
        let Some(record) = users.get(user) else {
            return Verdict::default();
        };
        let mut verdict = Verdict {
            accepted: false,
            shipped_credentials: record.password_matches(SHIPPED_PASSWORD),
        };
        if let Some(keys) = self.load_keys(user) {
            // PublicKey equality includes the comment, which clients never send.
            verdict.accepted = keys.iter().any(|listed| listed == key.key_data());
            verdict.shipped_credentials |= keys.contains(&self.shipped_key);
        }
        verdict
    }
}

/// [`AuthStore::check_password`], off the SSH event loop.
pub async fn check_password(store: Arc<AuthStore>, user: String, password: String) -> Verdict {
    tokio::task::spawn_blocking(move || store.check_password(&user, &password))
        .await
        .unwrap_or_default()
}

/// [`AuthStore::check_key`], off the SSH event loop.
pub async fn check_key(store: Arc<AuthStore>, user: String, key: PublicKey) -> Verdict {
    tokio::task::spawn_blocking(move || store.check_key(&user, &key))
        .await
        .unwrap_or_default()
}
