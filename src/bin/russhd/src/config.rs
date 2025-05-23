//! russhd config. See the test below on how to add users.
use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::Arc};

use serde::Deserialize;

#[derive(Clone, Deserialize, Debug, PartialEq, Eq)]
struct UserCfgV1 {
    salt: String,          // hex string
    password_hash: String, // hex string
}

#[derive(Clone, Deserialize, Debug, PartialEq, Eq)]
struct ConfigV1 {
    version: u32,      // Must be 1
    listen_on: String, // e.g. '0.0.0.0:2222'
    shell: String,     // e.g. 'bash'

    users: HashMap<String, UserCfgV1>,
}

pub struct Config {
    users: HashMap<String, User>,
    shell: String,
    listen_on: SocketAddr,
}

impl Config {
    fn new(conf: ConfigV1) -> anyhow::Result<Arc<Self>> {
        let listen_on = SocketAddr::from_str(&conf.listen_on)?;

        let mut users = HashMap::new();
        for (username, user_cfg) in &conf.users {
            let salt = hex::decode(&user_cfg.salt)?;
            let password_hash = hex::decode(&user_cfg.password_hash)?;
            users.insert(
                username.clone(),
                User {
                    username: username.clone(),
                    salt,
                    password_hash,
                },
            );
        }

        Ok(Arc::new(Self {
            users,
            shell: conf.shell,
            listen_on,
        }))
    }

    pub fn listen_on(&self) -> SocketAddr {
        self.listen_on
    }

    pub fn shell(&self) -> &str {
        &self.shell
    }

    pub fn authenticate(&self, username: &str, password: &str) -> anyhow::Result<()> {
        let Some(user) = self.users.get(username) else {
            anyhow::bail!("User not found.");
        };

        user.autenticate(password)
    }
}

pub struct User {
    #[allow(unused)]
    username: String,
    salt: Vec<u8>,
    password_hash: Vec<u8>,
}

impl User {
    fn autenticate(&self, password: &str) -> anyhow::Result<()> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(password.as_bytes());
        let password_hash = hasher.finalize();

        if !self.password_hash.eq(password_hash.as_slice()) {
            anyhow::bail!("Wrong password.");
        }

        Ok(())
    }
}

pub fn read_from_file(path: &str) -> anyhow::Result<Arc<Config>> {
    let toml_str = std::fs::read_to_string(path)?;
    let config_v1 = toml::from_str::<ConfigV1>(&toml_str)?;
    if config_v1.version != 1 {
        anyhow::bail!("Unsupported config version.");
    }

    Config::new(config_v1)
}

#[test]
fn basic_test() {
    use rand_core::RngCore;
    use sha2::{Digest, Sha256};

    let user = "motor";
    let password = "vroomvroom";

    let mut salt = [0_u8; 32];

    rand_core::OsRng.fill_bytes(&mut salt);

    let mut hasher = Sha256::new();
    hasher.update(&salt);
    hasher.update(password.as_bytes());
    let password_hash = hasher.finalize();

    let toml_str = format!(
        r#"
        version = 1
        listen_on = '0.0.0.0:2222'
        shell = 'bash'

        [users.{}]
        salt = '{}'
        password_hash = '{}'
    "#,
        user,
        hex::encode(salt),
        hex::encode(password_hash)
    );

    println!("{}", toml_str);

    let mut users = HashMap::new();

    let user_cfg = UserCfgV1 {
        salt: hex::encode(&salt),
        password_hash: hex::encode(&password_hash),
    };

    users.insert(user.to_owned(), user_cfg);
    let config = ConfigV1 {
        version: 1,
        listen_on: "0.0.0.0:2222".to_owned(),
        shell: "bash".to_owned(),
        users,
    };

    let config_parsed = toml::from_str::<ConfigV1>(&toml_str).unwrap();

    assert_eq!(config, config_parsed);

    let toml_str = std::fs::read_to_string("src/test_config.toml").unwrap();
    let _config_parsed = toml::from_str::<ConfigV1>(&toml_str).unwrap();
    // The assertion below will fail because our salt above is random.
    // assert_eq!(config, config_parsed);

    println!("basic_test PASS");
}
