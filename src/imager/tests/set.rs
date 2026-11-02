mod set_support;

use moto_sdk::async_fs::{AccessPermissions, EntryKind, FileSystem, Role, RolePermissions};
use set_support::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn text(raw: &std::path::Path, path: &str) -> String {
    String::from_utf8(read(raw, path).0).unwrap()
}

fn users(raw: &std::path::Path) -> String {
    text(raw, USERS)
}

fn keys(name: &str) -> String {
    format!("/user/cfg/ssh/authorized_keys.{name}")
}

/// A field of `[users.NAME]`, read the way the editor writes it.
fn user_field<'a>(registry: &'a str, name: &str, field: &str) -> Option<&'a str> {
    let header = format!("[users.{name}]");
    let table = registry.split_once(&header)?.1;
    let table = table.split("\n[").next().unwrap();
    table.lines().find_map(|line| {
        let value = line.strip_prefix(&format!("{field} = "))?;
        Some(value.trim_matches(['"', '\'']))
    })
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

fn authenticates(registry: &str, name: &str, password: &str) -> bool {
    let salt = user_field(registry, name, "salt").unwrap();
    let salt: Vec<u8> = (0..salt.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&salt[i..i + 2], 16).unwrap())
        .collect();
    let mut hash = Sha256::new();
    hash.update(salt);
    hash.update(password.as_bytes());
    format!("{:x}", hash.finalize()) == user_field(registry, name, "password_hash").unwrap()
}

#[test]
fn all_commands_preserve_other_credentials_permissions_and_boot_data() {
    for qcow2 in [false, true] {
        for source in [BASE, DEV] {
            let fixture = Fixture::new(qcow2, source);
            let before = fs::read(fixture.raw()).unwrap();
            let password = " /not/a/file 'quoted' 雪 ";
            fixture.succeeds(&["--ssh-password", password]);
            let raw = fixture.raw();
            let registry = users(&raw);
            assert!(authenticates(&registry, "motor", password));
            assert!(!authenticates(&registry, "motor", "vroomvroom"));
            assert_eq!(user_field(&registry, "motor", "salt").unwrap().len(), 64);
            assert!(!registry.contains(password));
            assert_eq!(read(&raw, USERS).1, credential_permissions());
            assert_eq!(text(&raw, SSH), source);
            assert_eq!(text(&raw, MOTOR_KEYS), SHIPPED_KEYS);

            let public_file = fixture.root.join("login key.pub");
            let public_bytes = format!("{LOGIN_KEY}\r\n");
            fs::write(&public_file, &public_bytes).unwrap();
            fixture.succeeds(&["--ssh-key", public_file.to_str().unwrap()]);
            assert_eq!(fs::read(&public_file).unwrap(), public_bytes.as_bytes());
            let raw = fixture.raw();
            assert_eq!(text(&raw, MOTOR_KEYS), format!("{LOGIN_KEY}\n"));
            assert_eq!(read(&raw, MOTOR_KEYS).1, credential_permissions());
            assert_eq!(users(&raw), registry);
            assert_eq!(text(&raw, SSH), source);

            let host_file = fixture.root.join("host key");
            fs::write(&host_file, HOST_KEY).unwrap();
            fixture.succeeds(&["--ssh-server-key", host_file.to_str().unwrap()]);
            let expected = replace_fixture_field(
                source,
                "host_key",
                &format!("\"{}\"", HOST_KEY.replace('\n', "\\n")),
            );
            let raw = fixture.raw();
            assert_eq!(text(&raw, SSH), expected);
            assert_eq!(users(&raw), registry);
            assert_eq!(text(&raw, MOTOR_KEYS), format!("{LOGIN_KEY}\n"));
            assert_eq!(fs::read(&host_file).unwrap(), HOST_KEY.as_bytes());
            assert!(!fixture.root.join("host key.pub").exists());

            fs::write(fixture.root.join("ssl-cert.pem"), NEW_CERT).unwrap();
            fs::write(fixture.root.join("ssl-key.pem"), NEW_KEY).unwrap();
            fs::write(fixture.root.join("ca-certificates.crt"), b"do not import").unwrap();
            fixture.succeeds(&["--ssl-keys", fixture.root.to_str().unwrap()]);
            let raw = fixture.raw();
            assert_eq!(text(&raw, SSH), expected);
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
            assert_eq!(read(&raw, CLIENT_KEY).0, b"client private key");
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
fn names_are_created_selected_and_kept_apart() {
    for qcow2 in [false, true] {
        let fixture = Fixture::new(qcow2, BASE);
        let key_file = fixture.root.join("key.pub");
        let key = key_file.to_str().unwrap();
        fs::write(&key_file, "ssh-ed25519 ALICE first\n").unwrap();

        fixture.fails_unchanged(&["--ssh-user", "alice", "--ssh-password", "pw"]);
        fixture.fails_unchanged(&["--ssh-user", "alice", "--ssh-key", key]);
        fixture.fails_unchanged(&["--ssh-new-user", "motor", "--ssh-password", "pw"]);

        fixture.succeeds(&["--ssh-new-user", "alice", "--ssh-password", "alice pw"]);
        let raw = fixture.raw();
        let registry = users(&raw);
        assert!(authenticates(&registry, "alice", "alice pw"));
        assert!(authenticates(&registry, "motor", "vroomvroom"));
        assert!(registry.starts_with(SHIPPED_USERS), "the rest is preserved");

        fixture.succeeds(&["--ssh-user", "alice", "--ssh-key", key]);
        let raw = fixture.raw();
        assert_eq!(text(&raw, &keys("alice")), "ssh-ed25519 ALICE first\n");
        assert_eq!(read(&raw, &keys("alice")).1, credential_permissions());
        assert_eq!(text(&raw, MOTOR_KEYS), SHIPPED_KEYS);

        fixture.fails_unchanged(&["--ssh-new-user", "alice", "--ssh-password", "pw"]);

        // A key-only name, and the first password for it.
        fs::write(&key_file, "ssh-ed25519 BOB\n").unwrap();
        fixture.succeeds(&["--ssh-new-user", "bob", "--ssh-key", key]);
        let raw = fixture.raw();
        let registry = users(&raw);
        assert_eq!(user_field(&registry, "bob", "password_hash"), None);
        assert_eq!(text(&raw, &keys("bob")), "ssh-ed25519 BOB\n");
        fixture.succeeds(&["--ssh-user", "bob", "--ssh-password", "bob pw"]);
        let raw = fixture.raw();
        let registry = users(&raw);
        assert!(authenticates(&registry, "bob", "bob pw"));
        assert!(authenticates(&registry, "alice", "alice pw"));
        assert!(authenticates(&registry, "motor", "vroomvroom"));

        // A selected name changes alone, and a key replaces the whole list.
        fixture.succeeds(&["--ssh-user", "alice", "--ssh-password", "changed"]);
        let raw = fixture.raw();
        let updated = users(&raw);
        assert!(authenticates(&updated, "alice", "changed"));
        for name in ["motor", "bob"] {
            for field in ["salt", "password_hash"] {
                assert_eq!(
                    user_field(&updated, name, field),
                    user_field(&registry, name, field)
                );
            }
        }
        fs::write(&key_file, "ssh-ed25519 ALICE second\n").unwrap();
        fixture.succeeds(&["--ssh-user", "alice", "--ssh-key", key]);
        let raw = fixture.raw();
        assert_eq!(text(&raw, &keys("alice")), "ssh-ed25519 ALICE second\n");
        assert_eq!(text(&raw, &keys("bob")), "ssh-ed25519 BOB\n");
        assert_eq!(text(&raw, MOTOR_KEYS), SHIPPED_KEYS);
        assert_eq!(read(&raw, CLIENT_KEY).0, b"client private key");
    }
}

/// A registry of `count` users with no credentials yet.
fn registry_of(count: usize) -> String {
    let mut registry = "version = 1\n".to_owned();
    for index in 0..count {
        registry.push_str(&format!("\n[users.user-{index}]\n"));
    }
    registry
}

#[test]
fn the_registry_stops_at_the_limit_russhd_enforces() {
    let refuses = |fixture: &Fixture, args: &[&str]| {
        let stderr = String::from_utf8_lossy(&fixture.fails_unchanged(args).stderr).into_owned();
        assert!(stderr.contains("1024 SSH users"), "{stderr}");
    };
    for qcow2 in [false, true] {
        let fixture = Fixture::new(qcow2, BASE);
        fixture.set_file(USERS, registry_of(1023).as_bytes());
        fixture.succeeds(&["--ssh-new-user", "last", "--ssh-password", "pw"]);
        let registry = users(&fixture.raw());
        assert_eq!(registry.matches("[users.").count(), 1024);
        assert!(authenticates(&registry, "last", "pw"));

        refuses(
            &fixture,
            &["--ssh-new-user", "extra", "--ssh-password", "pw"],
        );

        // A full registry still takes changes to the users it has.
        fixture.succeeds(&["--ssh-user", "user-0", "--ssh-password", "new"]);
        assert!(authenticates(&users(&fixture.raw()), "user-0", "new"));

        // russhd denies every login past the limit, so no edit can look fine.
        fixture.set_file(USERS, registry_of(1025).as_bytes());
        refuses(&fixture, &["--ssh-user", "user-0", "--ssh-password", "new"]);
    }
}

#[test]
fn an_unchanged_key_still_gets_the_credential_mode() {
    for qcow2 in [false, true] {
        let fixture = Fixture::new(qcow2, BASE);
        let key_file = fixture.root.join("key.pub");
        fs::write(&key_file, LOGIN_KEY).unwrap();
        let key = key_file.to_str().unwrap();
        fixture.succeeds(&["--ssh-key", key]);
        fixture.edit(async |fs| {
            for path in [MOTOR_KEYS, USERS] {
                let id = resolve(fs, path).await?;
                fs.set_all_permissions_image_admin(Role::System, id, secret_permissions())
                    .await?;
            }
            Ok(())
        });

        fixture.succeeds(&["--ssh-key", key]);
        let raw = fixture.raw();
        assert_eq!(text(&raw, MOTOR_KEYS), format!("{LOGIN_KEY}\n"));
        assert_eq!(read(&raw, MOTOR_KEYS).1, credential_permissions());
        // This update only consulted the registry, so its mode is not this update's.
        assert_eq!(read(&raw, USERS).1, secret_permissions());
    }
}

#[test]
fn an_orphaned_key_file_is_not_reactivated() {
    let fixture = Fixture::new(false, BASE);
    with_fs(&fixture.image, async |fs| {
        let parent = resolve(fs, "/user/cfg/ssh").await?;
        fs.create_entry(
            Role::System,
            parent,
            EntryKind::File,
            "authorized_keys.ghost",
            credential_permissions(),
        )
        .await?;
        Ok(())
    });
    fixture.fails_unchanged(&["--ssh-new-user", "ghost", "--ssh-password", "pw"]);
    let key_file = fixture.root.join("key.pub");
    fs::write(&key_file, LOGIN_KEY).unwrap();
    fixture.fails_unchanged(&[
        "--ssh-new-user",
        "ghost",
        "--ssh-key",
        key_file.to_str().unwrap(),
    ]);
}

#[test]
fn repeated_password_updates_use_fresh_salts_and_preserve_custom_records() {
    let extra = "\n[users.other]\nsalt = 'unchanged'\n";
    let source = format!("{SHIPPED_USERS}{extra}");
    let fixture = Fixture::new(false, DEV);
    let sealed = RolePermissions::new(
        AccessPermissions::R,
        AccessPermissions::R,
        AccessPermissions::None,
    );
    fixture.set_file(USERS, source.as_bytes());
    with_fs(&fixture.image, async |fs| {
        let id = resolve(fs, USERS).await?;
        fs.set_all_permissions_image_admin(Role::System, id, sealed)
            .await
    });
    fixture.succeeds(&["--ssh-password", "new password"]);
    let first = users(&fixture.raw());
    fixture.succeeds(&["--ssh-password", "new password"]);
    let second = users(&fixture.raw());
    assert_ne!(
        user_field(&first, "motor", "salt"),
        user_field(&second, "motor", "salt")
    );
    assert!(authenticates(&second, "motor", "new password"));
    assert!(second.ends_with(extra));
    assert_eq!(read(&fixture.raw(), USERS).1, credential_permissions());
}

#[test]
fn invalid_credentials_and_config_leave_original_images_unchanged() {
    for qcow2 in [false, true] {
        let fixture = Fixture::new(qcow2, BASE);
        for password in ["", "secret\n", "\rsecret", "secret\u{feff}"] {
            let output = fixture.fails_unchanged(&["--ssh-password", password]);
            assert!(!String::from_utf8_lossy(&output.stderr).contains("secret"));
        }
        let key_file = fixture.root.join("key input");
        fixture.fails_unchanged(&["--ssh-key", key_file.to_str().unwrap()]);
        for content in [
            String::new(),
            "\n".to_owned(),
            format!("{LOGIN_KEY}\n{LOGIN_KEY}\n"),
            format!("{LOGIN_KEY}\0\n"),
            format!("{LOGIN_KEY} {}\n", "c".repeat(16 * 1024)),
        ] {
            fs::write(&key_file, content).unwrap();
            fixture.fails_unchanged(&["--ssh-key", key_file.to_str().unwrap()]);
        }
        fs::write(&key_file, [0xff]).unwrap();
        fixture.fails_unchanged(&["--ssh-server-key", key_file.to_str().unwrap()]);
        fixture.fails_unchanged(&["--ssh-key", fixture.root.to_str().unwrap()]);

        fixture.fails_unchanged(&["--ssl-keys", fixture.root.to_str().unwrap()]);
        fs::write(fixture.root.join("ssl-cert.pem"), NEW_CERT).unwrap();
        fixture.fails_unchanged(&["--ssl-keys", fixture.root.to_str().unwrap()]);
        fs::write(fixture.root.join("ssl-key.pem"), b"").unwrap();
        fixture.fails_unchanged(&["--ssl-keys", fixture.root.to_str().unwrap()]);
    }
}

#[test]
fn unsupported_layouts_fail_before_anything_is_written() {
    let host_file = std::env::temp_dir().join(format!("imager-host-{}", std::process::id()));
    fs::write(&host_file, HOST_KEY).unwrap();
    let host = host_file.to_str().unwrap();
    for source in [
        "private-secret invalid TOML".to_owned(),
        "version = 1".to_owned(),
        BASE.replace("version = 2", "version = 1"),
        format!("{BASE}\n[users.motor]\nsalt = 'private-secret'\n"),
        format!("{BASE}\nauthorized_key = 'private-secret'\n"),
        format!("{BASE}\nextra = 'private-secret'\n"),
        BASE.replace("/user/cfg/ssh", "/none/cfg"),
        BASE.replace("/user/cfg/russhd/users.toml", "/none/cfg/users.toml"),
    ] {
        let fixture = Fixture::new(false, &source);
        for args in [
            &["--ssh-password", "new-password"][..],
            &["--ssh-server-key", host],
        ] {
            let output = fixture.fails_unchanged(args);
            assert!(!String::from_utf8_lossy(&output.stderr).contains("private-secret"));
        }
    }
    for source in [
        "private-secret invalid TOML".to_owned(),
        SHIPPED_USERS.replace("version = 1", "version = 2"),
        format!("{SHIPPED_USERS}\n[users.bad]\nauthorized_key = 'private-secret'\n"),
        format!("{SHIPPED_USERS}\n[users.motor]\n"),
        format!("{SHIPPED_USERS}\n[users.\"quoted\"]\n"),
    ] {
        let fixture = Fixture::new(false, BASE);
        fixture.set_file(USERS, source.as_bytes());
        let output = fixture.fails_unchanged(&["--ssh-password", "new-password"]);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-secret"));
    }
    fs::remove_file(host_file).unwrap();
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
        let output = fixture.fails_unchanged(&["--ssl-keys", fixture.root.to_str().unwrap()]);
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
    fixture.succeeds(&["--ssl-keys", fixture.root.to_str().unwrap()]);
    fs::write(fixture.root.join("ssl-cert.pem"), NEW_CERT).unwrap();
    fs::write(fixture.root.join("ssl-key.pem"), NEW_KEY).unwrap();
    fixture.succeeds(&["--ssl-keys", fixture.root.to_str().unwrap()]);
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
                        EntryKind::Directory,
                        "sshd.toml",
                        secret_permissions(),
                    )
                    .await?;
                }
            }
            Ok(())
        });
        fixture.fails_unchanged(&["--ssh-password", "new-password"]);
    }
}

#[test]
fn credential_destinations_follow_the_trust_rules() {
    let open_file = RolePermissions::all(AccessPermissions::Rw);
    let open_directory = RolePermissions::all(AccessPermissions::Rwx);
    let none_reads = RolePermissions::new(
        AccessPermissions::Rw,
        AccessPermissions::Rw,
        AccessPermissions::R,
    );
    for (path, permissions) in [
        (USERS, open_file),
        (USERS, none_reads),
        (MOTOR_KEYS, open_file),
        ("/user/cfg/ssh", open_directory),
        ("/user/cfg/russhd", open_directory),
        ("/user/cfg", open_directory),
        ("/user", open_directory),
    ] {
        let fixture = Fixture::new(false, BASE);
        with_fs(&fixture.image, async |fs| {
            let id = resolve(fs, path).await?;
            fs.set_all_permissions_image_admin(Role::System, id, permissions)
                .await
        });
        let key_file = fixture.root.join("key.pub");
        fs::write(&key_file, LOGIN_KEY).unwrap();
        fixture.fails_unchanged(&["--ssh-key", key_file.to_str().unwrap()]);
    }

    // A key file may be None-readable: the write ends with the standard mode.
    let fixture = Fixture::new(false, BASE);
    with_fs(&fixture.image, async |fs| {
        let id = resolve(fs, MOTOR_KEYS).await?;
        fs.set_all_permissions_image_admin(Role::System, id, none_reads)
            .await
    });
    let key_file = fixture.root.join("key.pub");
    fs::write(&key_file, LOGIN_KEY).unwrap();
    fixture.succeeds(&["--ssh-key", key_file.to_str().unwrap()]);
    assert_eq!(read(&fixture.raw(), MOTOR_KEYS).1, credential_permissions());

    // Wrong kinds, and no store to write to.
    let fixture = Fixture::new(false, BASE);
    with_fs(&fixture.image, async |fs| {
        fs.delete_entry(Role::System, resolve(fs, MOTOR_KEYS).await?)
            .await?;
        let parent = resolve(fs, "/user/cfg/ssh").await?;
        fs.create_entry(
            Role::System,
            parent,
            EntryKind::Directory,
            "authorized_keys.motor",
            credential_permissions(),
        )
        .await?;
        fs.delete_entry(Role::System, resolve(fs, USERS).await?)
            .await
    });
    fs::write(&key_file, LOGIN_KEY).unwrap();
    let fixture_key = fixture.root.join("key.pub");
    fs::write(&fixture_key, LOGIN_KEY).unwrap();
    fixture.fails_unchanged(&["--ssh-key", fixture_key.to_str().unwrap()]);
    fixture.fails_unchanged(&["--ssh-password", "new-password"]);
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
        fixture.fails_unchanged(&["--ssh-password", "new-password"]);
    }
    let fixture = Fixture::new(false, BASE);
    let original = fs::read(&fixture.image).unwrap();
    let alias = fixture.root.join("alias.raw");
    std::os::unix::fs::symlink(&fixture.image, &alias).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_imager"))
        .args(["set", "--ssh-password", "new-password", "-i"])
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
    fixture.succeeds(&["--ssh-key", path.to_str().unwrap()]);
    assert_eq!(text(&fixture.raw(), MOTOR_KEYS), "opaque login key\n");
    fs::write(&path, "opaque private key").unwrap();
    fixture.succeeds(&["--ssh-server-key", path.to_str().unwrap()]);
    assert!(text(&fixture.raw(), SSH).contains("host_key = \"opaque private key\""));
    fs::write(fixture.root.join("ssl-cert.pem"), b"opaque certificate").unwrap();
    fs::write(fixture.root.join("ssl-key.pem"), b"opaque TLS key").unwrap();
    fixture.succeeds(&["--ssl-keys", fixture.root.to_str().unwrap()]);
    assert_eq!(read(&fixture.raw(), CERT).0, b"opaque certificate");
    assert_eq!(read(&fixture.raw(), KEY).0, b"opaque TLS key");
}

#[test]
fn publish_www_stages_every_credential_for_the_default_name() {
    for qcow2 in [false, true] {
        let fixture = Fixture::new(qcow2, BASE);
        fixture.edit(async |fs| {
            let user = resolve(fs, "/user").await?;
            let bin = fs
                .create_entry(
                    Role::System,
                    user,
                    EntryKind::Directory,
                    "bin",
                    RolePermissions::all(AccessPermissions::Rwx),
                )
                .await?;
            fs.create_entry(
                Role::System,
                bin,
                EntryKind::File,
                "httpd-axum",
                RolePermissions::all(AccessPermissions::Rx),
            )
            .await?;
            Ok(())
        });
        let site = fixture.root.join("site");
        fs::create_dir(&site).unwrap();
        fs::write(site.join("index.html"), b"hello").unwrap();
        let tls = fixture.root.join("tls");
        fs::create_dir(&tls).unwrap();
        fs::write(tls.join("ssl-cert.pem"), NEW_CERT).unwrap();
        fs::write(tls.join("ssl-key.pem"), NEW_KEY).unwrap();
        let key = fixture.root.join("key.pub");
        fs::write(&key, LOGIN_KEY).unwrap();
        let publish = |image: &std::path::Path| {
            std::process::Command::new(env!("CARGO_BIN_EXE_imager"))
                .arg("publish-www")
                .arg(&site)
                .args(["--ssh-password", "web password", "--ssh-key"])
                .arg(&key)
                .arg("--ssl-keys")
                .arg(&tls)
                .arg("-i")
                .arg(image)
                .output()
                .unwrap()
        };
        let output = publish(&fixture.image);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let raw = fixture.raw();
        assert!(authenticates(&users(&raw), "motor", "web password"));
        assert_eq!(text(&raw, MOTOR_KEYS), format!("{LOGIN_KEY}\n"));
        assert!(
            !text(&raw, SSH).contains("AAAEAIyXvYqbau3uMgFiaVFLN"),
            "new host key"
        );
        assert_eq!(read(&raw, "/user/www-home/index.html").0, b"hello");
        assert_eq!(read(&raw, CERT).0, NEW_CERT);
        assert_eq!(read(&raw, KEY).0, NEW_KEY);
        assert_eq!(read(&raw, CLIENT_KEY).0, b"client private key");

        // Without a motor record nothing is published, the site included.
        let fixture = Fixture::new(qcow2, BASE);
        fixture.set_file(USERS, b"version = 1\n");
        let original = fs::read(&fixture.image).unwrap();
        assert!(!publish(&fixture.image).status.success());
        assert_eq!(fs::read(&fixture.image).unwrap(), original);
    }
}
