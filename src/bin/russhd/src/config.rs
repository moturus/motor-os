//! russhd's service configuration. Login credentials have their own files; see
//! `auth_store`.
use std::{net::SocketAddr, path::Path, str::FromStr, sync::Arc};

use serde::Deserialize;

use crate::auth_store::{self, AuthStore};

const CONFIG_VERSION: u32 = 2;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceConfig {
    version: u32,      // Must be 2
    listen_on: String, // e.g. '0.0.0.0:2222'
    host_key: String,  // openssh host key (private)

    #[serde(default)]
    path: String,

    users_file: String,          // absolute path
    authorized_keys_dir: String, // absolute path
}

pub struct Config {
    listen_on: SocketAddr,
    host_key: russh::keys::PrivateKey,
    path: String,
    auth_store: Arc<AuthStore>,
}

fn invalid(message: String) -> russh::Error {
    russh::Error::InvalidConfig(message)
}

/// Absolute and without empty, `.` or `..` components: the path checks walk
/// them. `Path::components` would hide a `.`, so this looks at the text.
fn credential_path<'a>(field: &str, value: &'a str) -> Result<&'a Path, russh::Error> {
    let normalized = value
        .strip_prefix('/')
        .is_some_and(|rest| rest.split('/').all(|part| !matches!(part, "" | "." | "..")));
    if !normalized {
        return Err(invalid(format!(
            "{field} must be a normalized absolute path"
        )));
    }
    Ok(Path::new(value))
}

impl Config {
    const DEFAULT_HOST_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCOL5sIfuwv5TaS4iNec2TlPJ5fow/1nEQQVIy+eLk90wAAAIjvOC/D7zgv
wwAAAAtzc2gtZWQyNTUxOQAAACCOL5sIfuwv5TaS4iNec2TlPJ5fow/1nEQQVIy+eLk90w
AAAEAIyXvYqbau3uMgFiaVFLN+W1NGPW6XNXNfGKiRpyUXW44vmwh+7C/lNpLiI15zZOU8
nl+jD/WcRBBUjL54uT3TAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----"#;

    /// Whether the host key is the shipped test key. Shipped login credentials
    /// are reported per connection, when they are loaded.
    pub fn is_default(&self) -> bool {
        let default_host_key =
            russh::keys::PrivateKey::from_openssh(Self::DEFAULT_HOST_KEY).unwrap();
        default_host_key == *self.host_key()
    }

    fn new(conf: ServiceConfig) -> Result<Arc<Self>, russh::Error> {
        let listen_on = SocketAddr::from_str(&conf.listen_on)
            .map_err(|e| invalid(format!("Error parsing {}: {e:?}", conf.listen_on)))?;
        let host_key = russh::keys::PrivateKey::from_openssh(&conf.host_key)?;
        let auth_store = AuthStore::new(
            credential_path("users_file", &conf.users_file)?,
            credential_path("authorized_keys_dir", &conf.authorized_keys_dir)?,
        );

        Ok(Arc::new(Self {
            listen_on,
            host_key,
            path: conf.path,
            auth_store: Arc::new(auth_store),
        }))
    }

    pub fn listen_on(&self) -> SocketAddr {
        self.listen_on
    }

    pub fn host_key(&self) -> &russh::keys::PrivateKey {
        &self.host_key
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn auth_store(&self) -> &Arc<AuthStore> {
        &self.auth_store
    }
}

pub fn read_from_file(path: &str) -> Result<Arc<Config>, russh::Error> {
    let text = std::fs::read_to_string(path)?;
    let config = toml::from_str::<ServiceConfig>(&text).map_err(|error| {
        let line = auth_store::toml_error_line(&text, &error).unwrap_or_default();
        invalid(format!("malformed or unknown entry at line {line}"))
    })?;
    if config.version != CONFIG_VERSION {
        return Err(invalid(format!(
            "unsupported config version {}",
            config.version
        )));
    }

    Config::new(config)
}
