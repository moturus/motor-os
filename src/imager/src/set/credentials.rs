use super::{invalid, Input};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub(super) const MAX_ARTIFACT_SIZE: usize = 1024 * 1024;
pub(super) const SSH_CONFIG: &str = "/system/cfg/sshd.toml";
pub(super) const TLS_CERT: &str = "/system/cfg/ssl/ssl-cert.pem";
pub(super) const TLS_KEY: &str = "/system/cfg/ssl/ssl-key.pem";

pub(crate) enum Credentials {
    Password { salt: String, hash: String },
    LoginKey(String),
    HostKey(String),
    Tls { cert: Vec<u8>, key: Vec<u8> },
}

fn read_artifact(path: &Path) -> io::Result<Vec<u8>> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(invalid("credential input must be a regular file"));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("credential input must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_ARTIFACT_SIZE as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_SIZE {
        return Err(invalid(
            "credential file must contain between 1 byte and 1 MiB",
        ));
    }
    Ok(bytes)
}

pub(crate) fn validate_password(password: &str) -> io::Result<()> {
    if password.is_empty()
        || password.len() > MAX_ARTIFACT_SIZE
        || password.contains(['\r', '\n', '\u{feff}'])
    {
        return Err(invalid(
            "password must be nonempty, at most 1 MiB, and contain no CR, LF, or byte-order mark",
        ));
    }
    Ok(())
}

/// A freshly generated SSH host key and the public line operators can pin.
pub(crate) struct GeneratedHostKey {
    pub(crate) credentials: Credentials,
    pub(crate) public_key: String,
    pub(crate) fingerprint: String,
}

impl Credentials {
    pub(crate) fn generate_host_key() -> io::Result<GeneratedHostKey> {
        use ssh_key::private::{Ed25519Keypair, KeypairData, PrivateKey};
        let mut seed = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut seed)?;
        let keypair = Ed25519Keypair::from_seed(&seed);
        let key = PrivateKey::new(KeypairData::Ed25519(keypair), "")
            .map_err(|_| io::Error::other("cannot build SSH host key"))?;
        let private = key
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|_| io::Error::other("cannot encode SSH host key"))?;
        let public_key = key
            .public_key()
            .to_openssh()
            .map_err(|_| io::Error::other("cannot encode SSH host public key"))?;
        Ok(GeneratedHostKey {
            credentials: Self::HostKey(private.as_str().to_owned()),
            public_key,
            fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        })
    }

    pub(crate) fn read(input: Input<'_>) -> io::Result<Self> {
        match input {
            Input::Password(password) => {
                validate_password(password)?;
                let mut salt = [0; 32];
                File::open("/dev/urandom")?.read_exact(&mut salt)?;
                let mut hasher = Sha256::new();
                hasher.update(salt);
                hasher.update(password.as_bytes());
                Ok(Self::Password {
                    salt: hex(&salt),
                    hash: hex(&hasher.finalize()),
                })
            }
            Input::LoginKey(path) => {
                let bytes = read_artifact(path)?;
                let text =
                    std::str::from_utf8(&bytes).map_err(|_| invalid("public key must be UTF-8"))?;
                let line = text.strip_suffix('\n').unwrap_or(text);
                let line = line.strip_suffix('\r').unwrap_or(line);
                if line.contains(['\r', '\n']) {
                    return Err(invalid("expected a single OpenSSH public key"));
                }
                Ok(Self::LoginKey(line.to_owned()))
            }
            Input::HostKey(path) => {
                let bytes = read_artifact(path)?;
                let text =
                    String::from_utf8(bytes).map_err(|_| invalid("private key must be UTF-8"))?;
                Ok(Self::HostKey(text))
            }
            Input::Tls(directory) => {
                let cert = read_artifact(&directory.join("ssl-cert.pem"))?;
                let key = read_artifact(&directory.join("ssl-key.pem"))?;
                Ok(Self::Tls { cert, key })
            }
        }
    }

    pub(super) fn update_ssh(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| invalid("SSH configuration must be UTF-8"))?;
        match self {
            Self::HostKey(key) => super::ssh_config::replace(text, "", &[("host_key", key)]),
            Self::Password { salt, hash } => super::ssh_config::replace(
                text,
                "users.motor",
                &[("salt", salt), ("password_hash", hash)],
            ),
            Self::LoginKey(key) => {
                super::ssh_config::replace(text, "users.motor", &[("authorized_key", key)])
            }
            Self::Tls { .. } => unreachable!(),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut result, "{byte:02x}").unwrap();
    }
    result
}
