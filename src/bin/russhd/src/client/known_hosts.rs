use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use russh::keys::ssh_key::PublicKey;

use super::args::HostKeyPolicy;

#[derive(Debug)]
struct Record {
    host: String,
    key: PublicKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyState {
    Matching,
    Changed,
    Unknown,
}

pub fn host_token(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

pub fn check(
    path: &Path,
    host: &str,
    port: u16,
    presented: &PublicKey,
) -> std::io::Result<KeyState> {
    if !path.exists() {
        return Ok(KeyState::Unknown);
    }
    let contents = std::fs::read_to_string(path)?;
    classify(&parse(&contents)?, &host_token(host, port), presented)
}

pub fn verify(
    path: &Path,
    host: &str,
    port: u16,
    presented: &PublicKey,
    policy: HostKeyPolicy,
    ask: impl FnOnce(&PublicKey) -> std::io::Result<bool>,
) -> std::io::Result<bool> {
    let token = host_token(host, port);
    match check(path, host, port, presented)? {
        KeyState::Matching => Ok(true),
        KeyState::Changed => Ok(false),
        KeyState::Unknown if policy == HostKeyPolicy::Yes => Ok(false),
        KeyState::Unknown => {
            if policy == HostKeyPolicy::Ask && !ask(presented)? {
                return Ok(false);
            }
            record(path, &token, presented)
        }
    }
}

fn classify(records: &[Record], host: &str, presented: &PublicKey) -> std::io::Result<KeyState> {
    let mut same_type = false;
    for record in records.iter().filter(|record| record.host == host) {
        if record.key == *presented {
            return Ok(KeyState::Matching);
        }
        if same_family(&record.key.algorithm(), &presented.algorithm()) {
            same_type = true;
        }
    }
    Ok(if same_type {
        KeyState::Changed
    } else {
        KeyState::Unknown
    })
}

pub fn prefer_algorithms(
    path: &Path,
    host: &str,
    port: u16,
    defaults: &[russh::keys::Algorithm],
) -> std::io::Result<Vec<russh::keys::Algorithm>> {
    if !path.exists() {
        return Ok(defaults.to_vec());
    }
    let records = parse(&std::fs::read_to_string(path)?)?;
    let token = host_token(host, port);
    let known = records
        .iter()
        .filter(|record| record.host == token)
        .map(|record| record.key.algorithm())
        .collect::<Vec<_>>();
    let mut preferred = Vec::with_capacity(defaults.len());
    for algorithm in defaults {
        if known.iter().any(|known| same_family(known, algorithm)) {
            preferred.push(algorithm.clone());
        }
    }
    for algorithm in defaults {
        if !preferred.contains(algorithm) {
            preferred.push(algorithm.clone());
        }
    }
    Ok(preferred)
}

fn same_family(left: &russh::keys::Algorithm, right: &russh::keys::Algorithm) -> bool {
    matches!(
        (left, right),
        (
            russh::keys::Algorithm::Rsa { .. },
            russh::keys::Algorithm::Rsa { .. }
        )
    ) || left == right
}

fn parse(contents: &str) -> std::io::Result<Vec<Record>> {
    let mut records = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let host = fields.next().unwrap();
        let key_type = fields.next();
        let blob = fields.next();
        if key_type.is_none()
            || blob.is_none()
            || host.starts_with('@')
            || host.starts_with('|')
            || host.contains([',', '*', '!', '?'])
        {
            return Err(invalid_line(index + 1));
        }
        let encoded = format!("{} {}", key_type.unwrap(), blob.unwrap());
        let key = PublicKey::from_openssh(&encoded).map_err(|_| invalid_line(index + 1))?;
        records.push(Record {
            host: host.to_owned(),
            key,
        });
    }
    Ok(records)
}

fn invalid_line(line: usize) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("malformed known_hosts line {line}"),
    )
}

pub(crate) fn record(path: &Path, host: &str, key: &PublicKey) -> std::io::Result<bool> {
    validate_parent(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "known_hosts is not a regular file",
        ));
    }
    file.lock()?;
    let result = record_locked(&mut file, host, key);
    let unlock = file.unlock();
    result.and(unlock.map(|_| true))
}

fn record_locked(file: &mut File, host: &str, key: &PublicKey) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    match classify(&parse(&contents)?, host, key)? {
        KeyState::Matching => return Ok(()),
        KeyState::Changed => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "host key changed while updating known_hosts",
            ));
        }
        KeyState::Unknown => {}
    }
    let encoded = key
        .to_openssh()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if !contents.is_empty() && !contents.ends_with('\n') {
        writeln!(file)?;
    }
    writeln!(file, "{host} {encoded}")?;
    file.flush()
}

fn validate_parent(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let metadata = parent.metadata()?;
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "known_hosts parent is not a directory",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::{Algorithm, private::PrivateKey};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn key() -> PublicKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    fn temp_path() -> std::path::PathBuf {
        static ID: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "motor-known-hosts-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn tokens_and_literal_grammar_are_strict() {
        assert_eq!(host_token("host", 22), "host");
        assert_eq!(host_token("2001:db8::1", 2222), "[2001:db8::1]:2222");
        let key = key();
        let valid = format!(
            "# comment\nhost {} trailing comment\n",
            key.to_openssh().unwrap()
        );
        assert_eq!(
            classify(&parse(&valid).unwrap(), "host", &key).unwrap(),
            KeyState::Matching
        );
        assert!(parse("@revoked host ssh-ed25519 AAAA").is_err());
        assert!(parse("host,other ssh-ed25519 AAAA").is_err());
        assert!(parse("|1|hash|hash ssh-ed25519 AAAA").is_err());
    }

    #[test]
    fn matching_wins_over_stale_records() {
        let current = key();
        let stale = key();
        let contents = format!(
            "host {}\nhost {}\n",
            stale.to_openssh().unwrap(),
            current.to_openssh().unwrap()
        );
        let records = parse(&contents).unwrap();
        assert_eq!(
            classify(&records, "host", &current).unwrap(),
            KeyState::Matching
        );
        assert_eq!(
            classify(&records, "host", &key()).unwrap(),
            KeyState::Changed
        );
    }

    #[test]
    fn recording_repairs_a_missing_final_newline() {
        let path = temp_path();
        let first = key();
        let second = key();
        std::fs::write(&path, format!("one {}", first.to_openssh().unwrap())).unwrap();
        record(&path, "two", &second).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn known_algorithm_is_moved_before_defaults() {
        let path = temp_path();
        let current = key();
        std::fs::write(&path, format!("host {}\n", current.to_openssh().unwrap())).unwrap();
        let defaults = [Algorithm::Rsa { hash: None }, Algorithm::Ed25519];
        assert_eq!(
            prefer_algorithms(&path, "host", 22, &defaults).unwrap(),
            [Algorithm::Ed25519, Algorithm::Rsa { hash: None }]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn policy_records_only_explicitly_accepted_unknown_keys() {
        let path = temp_path();
        let key = key();
        assert!(!verify(&path, "host", 22, &key, HostKeyPolicy::Yes, |_| Ok(true)).unwrap());
        assert!(!path.exists());
        assert!(!verify(&path, "host", 22, &key, HostKeyPolicy::Ask, |_| Ok(false)).unwrap());
        assert!(!path.exists());
        assert!(
            verify(&path, "host", 22, &key, HostKeyPolicy::AcceptNew, |_| Ok(
                false
            ))
            .unwrap()
        );
        assert_eq!(check(&path, "host", 22, &key).unwrap(), KeyState::Matching);
        assert!(verify(&path, "host", 22, &key, HostKeyPolicy::Yes, |_| Ok(false)).unwrap());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn locked_reread_deduplicates_and_rejects_conflicts() {
        let path = temp_path();
        let current = key();
        record(&path, "host", &current).unwrap();
        record(&path, "host", &current).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        assert_eq!(
            record(&path, "host", &key()).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::remove_file(path).unwrap();
    }
}
