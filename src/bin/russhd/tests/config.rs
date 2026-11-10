use std::path::{Path, PathBuf};

use russhd::config::*;

const CONFIG: &str = include_str!("sshd.toml");

fn read(name: &str, text: &str) -> Result<std::sync::Arc<Config>, String> {
    let path: PathBuf = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("russhd-config-{}-{name}.toml", std::process::id()));
    std::fs::write(&path, text).unwrap();
    let result = read_from_file(path.to_str().unwrap());
    std::fs::remove_file(&path).unwrap();
    result.map_err(|error| error.to_string())
}

fn check(name: &str, text: &str) -> Result<bool, String> {
    read(name, text).map(|config| config.allow_tcp_forwarding())
}

#[test]
fn gateway_ports_is_an_optional_boolean_defaulting_to_loopback() {
    assert!(!read("gateway-absent", CONFIG).unwrap().gateway_ports());
    for (value, expected) in [("true", true), ("false", false)] {
        assert_eq!(
            read(
                "gateway-policy",
                &format!("gateway_ports = {value}\n{CONFIG}")
            )
            .unwrap()
            .gateway_ports(),
            expected
        );
    }
    for value in ["1", "'true'", "[]"] {
        assert!(read("bad-gateway", &format!("gateway_ports = {value}\n{CONFIG}")).is_err());
    }
}

#[test]
fn forwarding_is_an_optional_boolean_in_version_2() {
    assert!(!check("absent", CONFIG).unwrap());
    for (value, expected) in [("true", true), ("false", false)] {
        assert_eq!(
            check(
                "policy",
                &format!("allow_tcp_forwarding = {value}\n{CONFIG}")
            )
            .unwrap(),
            expected
        );
    }
    for value in ["1", "'true'", "[]"] {
        assert!(
            check(
                "bad-policy",
                &format!("allow_tcp_forwarding = {value}\n{CONFIG}")
            )
            .is_err()
        );
    }
}

#[test]
fn default_config() {
    let test_config = read_from_file("tests/sshd.toml").unwrap();
    assert!(test_config.is_default());
}

#[test]
fn shipped_configs_parse() {
    for text in [
        include_str!("../../../../img_files/motor-os-base/user/cfg/sshd.toml"),
        include_str!("../../../../img_files/motor-os-dev/user/cfg/sshd.toml"),
    ] {
        assert!(!read("shipped", text).unwrap().gateway_ports());
    }
}

#[test]
fn only_the_version_2_schema_is_accepted() {
    check("good", CONFIG).unwrap();
    for (name, text) in [
        ("version-1", CONFIG.replace("version = 2", "version = 1")),
        ("version-3", CONFIG.replace("version = 2", "version = 3")),
        ("no-version", CONFIG.replace("version = 2\n", "")),
        (
            "embedded-users",
            format!("{CONFIG}\n[users.motor]\nsalt = 'ab'\npassword_hash = 'cd'\n"),
        ),
        ("legacy-key", format!("authorized_key = 'k'\n{CONFIG}")),
        ("unknown-field", format!("extra = 1\n{CONFIG}")),
        (
            "no-users-file",
            CONFIG.replace("users_file = '/user/cfg/russhd/users.toml'\n", ""),
        ),
        (
            "no-keys-dir",
            CONFIG.replace("authorized_keys_dir = '/user/cfg/ssh'\n", ""),
        ),
    ] {
        assert!(check(name, &text).is_err(), "{name}");
    }
}

#[test]
fn errors_do_not_quote_the_file() {
    let text = format!("{CONFIG}\nsecret-looking-entry = 'value'\n");
    let error = check("quote", &text).unwrap_err();
    assert!(!error.contains("secret-looking"), "{error}");
    assert!(!error.contains("PRIVATE KEY"), "{error}");
    assert!(error.contains("line"), "{error}");
}

#[test]
fn credential_locations_must_be_normalized_absolute_paths() {
    for bad in [
        "relative/keys",
        "keys",
        "",
        "/user/../system/cfg",
        "/user/./cfg",
    ] {
        let users = CONFIG.replace("/user/cfg/russhd/users.toml", bad);
        assert!(check("users", &users).is_err(), "{bad}");
        let keys = CONFIG.replace("'/user/cfg/ssh'", &format!("'{bad}'"));
        assert!(check("keys", &keys).is_err(), "{bad}");
    }
}

#[test]
fn vroom_vroom() {
    use rand::Rng;
    use sha2::{Digest, Sha256};

    let user = "motor";
    let password = "vroomvroom";

    let mut salt = [0_u8; 32];

    rand::rng().fill_bytes(&mut salt);

    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    let password_hash = hasher.finalize();

    let toml_str = format!(
        r#"
        [users.{}]
        salt = '{}'
        password_hash = '{}'
    "#,
        user,
        hex::encode(salt),
        hex::encode(password_hash)
    );

    println!("{}", toml_str);
}
