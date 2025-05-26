use russhd::config::*;

#[test]
fn default_config() {
    let test_config = read_from_file("tests/sshd.toml").unwrap();
    assert!(test_config.is_default());
}

#[test]
fn vroom_vroom() {
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
