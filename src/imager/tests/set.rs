mod set_support;

use async_fs::{AccessPermissions, FileSystem, Role, RolePermissions};
use set_support::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn config(raw: &std::path::Path) -> String {
    String::from_utf8(read(raw, SSH).0).unwrap()
}

fn field<'a>(config: &'a str, name: &str) -> &'a str {
    config
        .lines()
        .find_map(|line| {
            line.strip_prefix(&format!("{name} = \""))?
                .strip_suffix('"')
        })
        .unwrap()
}

fn replace_fixture_field(config: &str, name: &str, value: &str) -> String {
    let start = config.find(&format!("{name} = ")).unwrap() + name.len() + 3;
    let delimiter = if config[start..].starts_with("\"\"\"") {
        "\"\"\""
    } else if config[start..].starts_with('\'') {
        "'"
    } else {
        "\""
    };
    let end = start
        + delimiter.len()
        + config[start + delimiter.len()..].find(delimiter).unwrap()
        + delimiter.len();
    format!("{}{}{}", &config[..start], value, &config[end..])
}

fn authenticates(config: &str, password: &str) -> bool {
    let salt = field(config, "salt");
    let salt: Vec<u8> = (0..salt.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&salt[i..i + 2], 16).unwrap())
        .collect();
    let mut hash = Sha256::new();
    hash.update(salt);
    hash.update(password.as_bytes());
    format!("{:x}", hash.finalize()) == field(config, "password_hash")
}

#[test]
fn all_commands_preserve_other_credentials_permissions_and_boot_data() {
    for qcow2 in [false, true] {
        for source in [BASE, DEV] {
            let fixture = Fixture::new(qcow2, source);
            let before = fs::read(fixture.raw()).unwrap();
            let mut expected = source.to_owned();
            let password = " /not/a/file 'quoted' 雪 ";
            fixture.succeeds(&["ssh-password", password]);
            let actual = config(&fixture.raw());
            assert!(authenticates(&actual, password));
            assert!(!authenticates(&actual, "vroomvroom"));
            assert_eq!(field(&actual, "salt").len(), 64);
            for name in ["salt", "password_hash"] {
                expected = replace_fixture_field(
                    &expected,
                    name,
                    &format!("\"{}\"", field(&actual, name)),
                );
            }
            assert_eq!(actual, expected);
            assert!(!actual.contains(password));

            let public_file = fixture.root.join("login key.pub");
            let public_bytes = format!("{LOGIN_KEY}\r\n");
            fs::write(&public_file, &public_bytes).unwrap();
            fixture.succeeds(&["ssh-key", public_file.to_str().unwrap()]);
            assert_eq!(fs::read(&public_file).unwrap(), public_bytes.as_bytes());
            expected =
                replace_fixture_field(&expected, "authorized_key", &format!("\"{LOGIN_KEY}\""));
            assert_eq!(config(&fixture.raw()), expected);

            let host_file = fixture.root.join("host key");
            fs::write(&host_file, HOST_KEY).unwrap();
            fixture.succeeds(&["ssh-server-key", host_file.to_str().unwrap()]);
            expected = replace_fixture_field(
                &expected,
                "host_key",
                &format!("\"{}\"", HOST_KEY.replace('\n', "\\n")),
            );
            assert_eq!(config(&fixture.raw()), expected);
            assert_eq!(fs::read(&host_file).unwrap(), HOST_KEY.as_bytes());
            assert!(!fixture.root.join("host key.pub").exists());

            fs::write(fixture.root.join("ssl-cert.pem"), NEW_CERT).unwrap();
            fs::write(fixture.root.join("ssl-key.pem"), NEW_KEY).unwrap();
            fs::write(fixture.root.join("ca-certificates.crt"), b"do not import").unwrap();
            fixture.succeeds(&["ssl", "keys", fixture.root.to_str().unwrap()]);
            let raw = fixture.raw();
            assert_eq!(config(&raw), expected);
            assert_eq!(
                read(&raw, CERT),
                (
                    NEW_CERT.to_vec(),
                    RolePermissions::all(AccessPermissions::R)
                )
            );
            assert_eq!(read(&raw, KEY), (NEW_KEY.to_vec(), secret_permissions()));
            assert_eq!(read(&raw, SSH).1, secret_permissions());
            assert_eq!(read(&raw, CA).0, b"unchanged trust store");
            assert_eq!(fs::read(fixture.root.join("ssl-key.pem")).unwrap(), NEW_KEY);
            let after = fs::read(&raw).unwrap();
            assert_eq!(after.len(), before.len());
            assert_eq!(&after[..OFFSET as usize], &before[..OFFSET as usize]);
            assert_eq!(
                fs::metadata(&fixture.image).unwrap().permissions().mode() & 0o777,
                0o640
            );
            assert_eq!(&fs::read(&fixture.image).unwrap()[..4] == b"QFI\xfb", qcow2);
        }
    }
}

#[test]
fn repeated_password_updates_use_fresh_salts_and_preserve_custom_config() {
    let extra = "\n[users.other]\nauthorized_key = 'unchanged'\n[extra]\nvalue = 123\n";
    let source = format!("{DEV}{extra}");
    let fixture = Fixture::new(false, &source);
    let sealed = RolePermissions::new(
        AccessPermissions::R,
        AccessPermissions::R,
        AccessPermissions::None,
    );
    with_fs(&fixture.image, async |fs| {
        let id = resolve(fs, SSH).await?;
        fs.set_all_permissions_image_admin(Role::System, id, sealed)
            .await
    });
    fixture.succeeds(&["ssh-password", "new password"]);
    let first = config(&fixture.raw());
    fixture.succeeds(&["ssh-password", "new password"]);
    let second = config(&fixture.raw());
    assert_ne!(field(&first, "salt"), field(&second, "salt"));
    assert!(authenticates(&second, "new password"));
    assert!(second.ends_with(extra));
    assert_eq!(read(&fixture.raw(), SSH).1, sealed);
}

#[test]
fn invalid_credentials_and_config_leave_original_images_unchanged() {
    for qcow2 in [false, true] {
        let fixture = Fixture::new(qcow2, BASE);
        for password in ["", "secret\n", "\rsecret", "secret\u{feff}"] {
            let output = fixture.fails_unchanged(&["ssh-password", password]);
            assert!(!String::from_utf8_lossy(&output.stderr).contains("secret"));
        }
        let key_file = fixture.root.join("key input");
        fixture.fails_unchanged(&["ssh-key", key_file.to_str().unwrap()]);
        for content in [String::new(), format!("{LOGIN_KEY}\n{LOGIN_KEY}\n")] {
            fs::write(&key_file, content).unwrap();
            fixture.fails_unchanged(&["ssh-key", key_file.to_str().unwrap()]);
        }
        fs::write(&key_file, [0xff]).unwrap();
        fixture.fails_unchanged(&["ssh-server-key", key_file.to_str().unwrap()]);
        fixture.fails_unchanged(&["ssh-key", fixture.root.to_str().unwrap()]);

        fixture.fails_unchanged(&["ssl", "keys", fixture.root.to_str().unwrap()]);
        fs::write(fixture.root.join("ssl-cert.pem"), NEW_CERT).unwrap();
        fixture.fails_unchanged(&["ssl", "keys", fixture.root.to_str().unwrap()]);
        fs::write(fixture.root.join("ssl-key.pem"), b"").unwrap();
        fixture.fails_unchanged(&["ssl", "keys", fixture.root.to_str().unwrap()]);
    }
    for source in [
        "private-secret invalid TOML",
        "version = 2",
        "version = 1\n[users]",
    ] {
        let fixture = Fixture::new(false, source);
        let output = fixture.fails_unchanged(&["ssh-password", "new-password"]);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-secret"));
    }
}

#[test]
fn out_of_space_during_second_tls_write_does_not_publish_first_write() {
    for qcow2 in [false, true] {
        let fixture = Fixture::new(qcow2, BASE);
        fs::write(fixture.root.join("ssl-cert.pem"), NEW_CERT).unwrap();
        // Valid PEM with trailing whitespace, larger than this filesystem's
        // free space but within the input limit. Certificate replacement fits.
        let mut key = NEW_KEY.to_vec();
        key.resize(1024 * 1024, b'\n');
        fs::write(fixture.root.join("ssl-key.pem"), &key).unwrap();
        let output = fixture.fails_unchanged(&["ssl", "keys", fixture.root.to_str().unwrap()]);
        let storage_full = std::io::Error::from(std::io::ErrorKind::StorageFull).to_string();
        assert!(String::from_utf8_lossy(&output.stderr).contains(&storage_full));
        let raw = fixture.raw();
        assert_eq!(read(&raw, CERT).0, b"old certificate");
        assert_eq!(read(&raw, KEY).0, b"old private key");
    }
}

#[test]
fn shorter_tls_replacements_truncate_old_contents() {
    let fixture = Fixture::new(false, BASE);
    let cert_permissions = RolePermissions::all(AccessPermissions::Rx);
    with_fs(&fixture.image, async |fs| {
        let cert = resolve(fs, CERT).await?;
        fs.set_all_permissions_image_admin(Role::System, cert, cert_permissions)
            .await
    });
    let mut long_cert = NEW_CERT.to_vec();
    long_cert.resize(17000, b'\n');
    let mut long_key = NEW_KEY.to_vec();
    long_key.resize(19000, b'\n');
    fs::write(fixture.root.join("ssl-cert.pem"), long_cert).unwrap();
    fs::write(fixture.root.join("ssl-key.pem"), long_key).unwrap();
    fixture.succeeds(&["ssl", "keys", fixture.root.to_str().unwrap()]);
    fs::write(fixture.root.join("ssl-cert.pem"), NEW_CERT).unwrap();
    fs::write(fixture.root.join("ssl-key.pem"), NEW_KEY).unwrap();
    fixture.succeeds(&["ssl", "keys", fixture.root.to_str().unwrap()]);
    assert_eq!(read(&fixture.raw(), CERT).0, NEW_CERT);
    assert_eq!(read(&fixture.raw(), CERT).1, cert_permissions);
    assert_eq!(read(&fixture.raw(), KEY).0, NEW_KEY);
}

#[test]
fn invalid_destinations_and_secret_permissions_are_rejected() {
    for problem in ["missing", "directory", "permissions"] {
        let fixture = Fixture::new(false, BASE);
        with_fs(&fixture.image, async |fs| {
            let id = resolve(fs, SSH).await?;
            if problem == "permissions" {
                fs.set_all_permissions_image_admin(
                    Role::System,
                    id,
                    RolePermissions::all(AccessPermissions::Rw),
                )
                .await?;
            } else {
                fs.delete_entry(Role::System, id).await?;
                if problem == "directory" {
                    let parent = resolve(fs, "/system/cfg").await?;
                    fs.create_entry(
                        Role::System,
                        parent,
                        async_fs::EntryKind::Directory,
                        "sshd.toml",
                        secret_permissions(),
                    )
                    .await?;
                }
            }
            Ok(())
        });
        fixture.fails_unchanged(&["ssh-password", "new-password"]);
    }
}

#[test]
fn malformed_images_and_symlink_targets_are_rejected() {
    for problem in [
        "no-partition",
        "multiple",
        "overlap",
        "unaligned",
        "out-of-bounds",
        "zero-offset",
    ] {
        let fixture = Fixture::new(false, BASE);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fixture.image)
            .unwrap();
        let mut mbr = mbrman::MBR::read_from(&mut file, 512).unwrap();
        match problem {
            "no-partition" => mbr[1].sys = 0,
            "multiple" => mbr[2] = mbr[1].clone(),
            "overlap" => {
                mbr[2] = mbr[1].clone();
                mbr[2].sys = 0x83;
            }
            "unaligned" => mbr[1].sectors -= 1,
            "out-of-bounds" => mbr[1].sectors += 8,
            "zero-offset" => mbr[1].starting_lba = 0,
            _ => unreachable!(),
        }
        mbr.write_into(&mut file).unwrap();
        fixture.fails_unchanged(&["ssh-password", "new-password"]);
    }
    let fixture = Fixture::new(false, BASE);
    let original = fs::read(&fixture.image).unwrap();
    let alias = fixture.root.join("alias.raw");
    std::os::unix::fs::symlink(&fixture.image, &alias).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_imager"))
        .args(["set", "ssh-password", "new-password"])
        .arg(alias)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(&fixture.image).unwrap(), original);
    fixture.no_temporaries();
}

#[test]
fn copies_key_and_tls_inputs_without_crypto_validation() {
    let fixture = Fixture::new(false, BASE);
    let path = fixture.root.join("key input");
    fs::write(&path, "opaque login key").unwrap();
    fixture.succeeds(&["ssh-key", path.to_str().unwrap()]);
    assert!(config(&fixture.raw()).contains("authorized_key = \"opaque login key\""));
    fs::write(&path, "opaque private key").unwrap();
    fixture.succeeds(&["ssh-server-key", path.to_str().unwrap()]);
    assert!(config(&fixture.raw()).contains("host_key = \"opaque private key\""));
    fs::write(fixture.root.join("ssl-cert.pem"), b"opaque certificate").unwrap();
    fs::write(fixture.root.join("ssl-key.pem"), b"opaque TLS key").unwrap();
    fixture.succeeds(&["ssl", "keys", fixture.root.to_str().unwrap()]);
    assert_eq!(read(&fixture.raw(), CERT).0, b"opaque certificate");
    assert_eq!(read(&fixture.raw(), KEY).0, b"opaque TLS key");
}
