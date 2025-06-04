//! russhd config. See the test below on how to add users.
use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::Arc};

use serde::Deserialize;

#[derive(Clone, Deserialize, Debug, PartialEq, Eq)]
struct UserCfgV1 {
    #[serde(default)]
    salt: String, // hex string
    #[serde(default)]
    password_hash: String, // hex string
    #[serde(default)]
    authorized_key: String, // openssh pub key
}

#[derive(Clone, Deserialize, Debug, PartialEq, Eq)]
struct ConfigV1 {
    version: u32,      // Must be 1
    listen_on: String, // e.g. '0.0.0.0:2222'
    host_key: String,  // openssh host key (private)

    #[serde(default)]
    path: String,

    users: HashMap<String, UserCfgV1>,
}

pub struct Config {
    users: HashMap<String, User>,
    listen_on: SocketAddr,
    host_key: russh::keys::PrivateKey,
    path: String,
}

impl Config {
    const DEFAULT_HOST_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCOL5sIfuwv5TaS4iNec2TlPJ5fow/1nEQQVIy+eLk90wAAAIjvOC/D7zgv
wwAAAAtzc2gtZWQyNTUxOQAAACCOL5sIfuwv5TaS4iNec2TlPJ5fow/1nEQQVIy+eLk90w
AAAEAIyXvYqbau3uMgFiaVFLN+W1NGPW6XNXNfGKiRpyUXW44vmwh+7C/lNpLiI15zZOU8
nl+jD/WcRBBUjL54uT3TAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----"#;

    const DEFAULT_PWD: &str = "vroomvroom";
    const DEFAULT_USER_PUBKEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqjlUjeBcqvHyy+RvVL54pfyK7vj5kAkJRt+qLlZWPH";

    pub fn is_default(&self) -> bool {
        let default_host_key =
            russh::keys::PrivateKey::from_openssh(Self::DEFAULT_HOST_KEY).unwrap();
        if default_host_key == *self.host_key() {
            return true;
        }

        let default_pubkey =
            russh::keys::PublicKey::from_openssh(Self::DEFAULT_USER_PUBKEY).unwrap();

        for username in self.users.keys() {
            if self.authenticate_pwd(username, Self::DEFAULT_PWD).is_ok() {
                return true;
            }

            if self.authenticate_pubkey(username, &default_pubkey).is_ok() {
                return true;
            };
        }

        false
    }

    fn new(conf: ConfigV1) -> Result<Arc<Self>, russh::Error> {
        let listen_on = SocketAddr::from_str(&conf.listen_on).map_err(|e| {
            russh::Error::InvalidConfig(format!("Error parsing {}: {e:?}", &conf.listen_on))
        })?;
        let host_key = russh::keys::PrivateKey::from_openssh(&conf.host_key)?;

        let mut users = HashMap::new();
        for (username, user_cfg) in &conf.users {
            let salt = hex::decode(&user_cfg.salt).map_err(|e| {
                russh::Error::InvalidConfig(format!("Bad salt {}: {e:?}", &user_cfg.salt))
            })?;
            let password_hash = hex::decode(&user_cfg.password_hash).map_err(|e| {
                russh::Error::InvalidConfig(format!(
                    "Bad password hash {}: {e:?}",
                    &user_cfg.password_hash
                ))
            })?;
            let pub_key = if user_cfg.authorized_key.is_empty() {
                None
            } else {
                Some(russh::keys::PublicKey::from_openssh(
                    &user_cfg.authorized_key,
                )?)
            };

            users.insert(
                username.clone(),
                User {
                    username: username.clone(),
                    salt,
                    password_hash,
                    pubkey: pub_key,
                },
            );
        }

        Ok(Arc::new(Self {
            users,
            listen_on,
            host_key,
            path: conf.path,
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

    pub fn authenticate_pwd(&self, username: &str, password: &str) -> Result<(), russh::Error> {
        let Some(user) = self.users.get(username) else {
            return Err(russh::Error::NotAuthenticated);
        };

        user.autenticate_pwd(password)
    }

    pub fn authenticate_pubkey(
        &self,
        username: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<(), russh::Error> {
        let Some(user) = self.users.get(username) else {
            return Err(russh::Error::NotAuthenticated);
        };

        user.autenticate_pubkey(key)
    }

    pub fn can_auth_pwd(&self, username: &str) -> bool {
        let Some(user) = self.users.get(username) else {
            return false;
        };

        !user.password_hash.is_empty()
    }

    pub fn can_auth_pubkey(&self, username: &str) -> bool {
        let Some(user) = self.users.get(username) else {
            return false;
        };

        user.pubkey.is_some()
    }
}

pub struct User {
    #[allow(unused)]
    username: String,
    salt: Vec<u8>,
    password_hash: Vec<u8>,
    pubkey: Option<russh::keys::PublicKey>,
}

impl User {
    fn autenticate_pwd(&self, password: &str) -> Result<(), russh::Error> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(password.as_bytes());
        let password_hash = hasher.finalize();

        if !self.password_hash.eq(password_hash.as_slice()) {
            return Err(russh::Error::NotAuthenticated);
        }

        Ok(())
    }

    fn autenticate_pubkey(&self, key: &russh::keys::PublicKey) -> Result<(), russh::Error> {
        let Some(pubkey) = self.pubkey.as_ref() else {
            return Err(russh::Error::NotAuthenticated);
        };

        if pubkey.eq(key) {
            Ok(())
        } else {
            Err(russh::Error::NotAuthenticated)
        }
    }
}

pub fn read_from_file(path: &str) -> Result<Arc<Config>, russh::Error> {
    let toml_str = std::fs::read_to_string(path)?;
    let config_v1 = toml::from_str::<ConfigV1>(&toml_str)
        .map_err(|e| russh::Error::InvalidConfig(format!("Error parsing config toml: {e:?}.")))?;
    if config_v1.version != 1 {
        return Err(russh::Error::InvalidConfig(format!(
            "Unsupported config version {}.",
            config_v1.version
        )));
    }

    Config::new(config_v1)
}
