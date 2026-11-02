#![cfg(unix)]

//! Credential parsing, limits and trust checks, driven through the files russhd
//! really reads. The guest's role checks are in src/tests/test-sshd-keys.sh.

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use russh::keys::ssh_key::{Algorithm, LineEnding};
use russh::keys::{PrivateKey, PublicKey};
use russhd::auth_store::{AuthStore, Verdict};
use sha2::{Digest, Sha256};

const SHIPPED_USERS: &str =
    include_str!("../../../../img_files/motor-os-base/user/cfg/russhd/users.toml");
const SHIPPED_KEYS: &str =
    include_str!("../../../../img_files/motor-os-base/user/cfg/ssh/authorized_keys.motor");

/// A private directory: every check below starts from a tree that passes.
struct Fixture {
    root: PathBuf,
    store: AuthStore,
}

impl Fixture {
    fn new() -> Self {
        static ID: AtomicU64 = AtomicU64::new(0);
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "russhd-auth-store-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        directory(&root);
        directory(&root.join("keys"));
        let store = AuthStore::with_trust_root(
            &root.join("users.toml"),
            &root.join("keys"),
            Some(root.clone()),
        );
        Self { root, store }
    }

    fn users(&self) -> PathBuf {
        self.root.join("users.toml")
    }

    fn key_file(&self, name: &str) -> PathBuf {
        self.root
            .join("keys")
            .join(format!("authorized_keys.{name}"))
    }

    fn write_users(&self, text: &str) {
        private_file(&self.users(), text.as_bytes());
    }

    fn write_keys(&self, name: &str, bytes: impl AsRef<[u8]>) {
        private_file(&self.key_file(name), bytes.as_ref());
    }

    fn password(&self, name: &str, password: &str) -> bool {
        self.store.check_password(name, password).accepted
    }

    fn key(&self, name: &str, key: &PublicKey) -> bool {
        self.store.check_key(name, key).accepted
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn directory(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
    let _ = std::fs::remove_file(path);
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn new_key() -> PublicKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .clone()
}

fn line(key: &PublicKey) -> String {
    key.to_openssh().unwrap()
}

fn user(name: &str, password: &str) -> String {
    let salt = [7_u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    format!(
        "[users.{name}]\nsalt = '{}'\npassword_hash = '{}'\n",
        hex::encode(salt),
        hex::encode(hasher.finalize())
    )
}

fn registry(users: &[(&str, &str)]) -> String {
    let mut text = String::from("version = 1\n");
    for (name, password) in users {
        text.push_str(&user(name, password));
    }
    text
}

#[test]
fn shipped_files_hold_the_test_credentials_and_nothing_else_authenticates() {
    let fixture = Fixture::new();
    fixture.write_users(SHIPPED_USERS);
    fixture.write_keys("motor", SHIPPED_KEYS);
    let test_key = PublicKey::from_openssh(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqjlUjeBcqvHyy+RvVL54pfyK7vj5kAkJRt+qLlZWPH",
    )
    .unwrap();
    assert_eq!(
        fixture.store.check_password("motor", "vroomvroom"),
        Verdict {
            accepted: true,
            shipped_credentials: true
        }
    );
    assert_eq!(
        fixture.store.check_key("motor", &test_key),
        Verdict {
            accepted: true,
            shipped_credentials: true
        }
    );
    assert!(!fixture.password("motor", "wrong"));
    assert!(!fixture.key("motor", &new_key()));
    assert!(!fixture.password("other", "vroomvroom"));
    assert!(!fixture.key("other", &test_key));
}

#[test]
fn replaced_credentials_are_not_reported_as_shipped() {
    let fixture = Fixture::new();
    fixture.write_users(&registry(&[("motor", "own password")]));
    let key = new_key();
    fixture.write_keys("motor", line(&key));
    assert_eq!(
        fixture.store.check_key("motor", &key),
        Verdict {
            accepted: true,
            shipped_credentials: false
        }
    );
    assert!(
        !fixture
            .store
            .check_password("motor", "own password")
            .shipped_credentials
    );
}

#[test]
fn each_name_has_its_own_credentials() {
    let fixture = Fixture::new();
    fixture.write_users(&registry(&[("alice", "a"), ("bob", "b")]));
    let (alice_1, alice_2, bob_1, bob_2) = (new_key(), new_key(), new_key(), new_key());
    let shared = new_key();
    fixture.write_keys(
        "alice",
        format!(
            "{}\n{}\n{}\n",
            line(&alice_1),
            line(&alice_2),
            line(&shared)
        ),
    );
    fixture.write_keys(
        "bob",
        format!("{}\n{}\n{}\n", line(&bob_1), line(&bob_2), line(&shared)),
    );

    for key in [&alice_1, &alice_2, &shared] {
        assert!(fixture.key("alice", key));
    }
    for key in [&bob_1, &bob_2, &shared] {
        assert!(fixture.key("bob", key));
    }
    assert!(!fixture.key("alice", &bob_1));
    assert!(!fixture.key("bob", &alice_2));
    assert!(fixture.password("alice", "a") && fixture.password("bob", "b"));
    assert!(!fixture.password("alice", "b") && !fixture.password("bob", "a"));

    fixture.write_keys("alice", line(&alice_1));
    assert!(!fixture.key("alice", &shared));
    assert!(fixture.key("bob", &shared));
}

#[test]
fn a_change_applies_to_the_next_check() {
    let fixture = Fixture::new();
    let key = new_key();
    fixture.write_users(&registry(&[("alice", "old")]));
    fixture.write_keys("alice", line(&key));
    assert!(fixture.key("alice", &key) && fixture.password("alice", "old"));

    fixture.write_users(&registry(&[("alice", "new")]));
    assert!(!fixture.password("alice", "old") && fixture.password("alice", "new"));

    fixture.write_keys("alice", "");
    assert!(!fixture.key("alice", &key));

    // A key file creates no name; a record does, and removing it ends the name.
    let other = new_key();
    fixture.write_keys("carol", line(&other));
    assert!(!fixture.key("carol", &other));
    fixture.write_users(&registry(&[("alice", "new"), ("carol", "c")]));
    assert!(fixture.key("carol", &other) && fixture.password("carol", "c"));
    fixture.write_users(&registry(&[("alice", "new")]));
    assert!(!fixture.key("carol", &other) && !fixture.password("carol", "c"));
}

#[test]
fn a_record_without_a_hash_has_no_password() {
    let fixture = Fixture::new();
    for record in ["", "password_hash = ''\n", "salt = 'ab'\n"] {
        fixture.write_users(&format!("version = 1\n[users.alice]\n{record}"));
        assert!(!fixture.password("alice", ""));
        assert!(!fixture.password("alice", "anything"));
    }
    let key = new_key();
    fixture.write_keys("alice", line(&key));
    assert!(fixture.key("alice", &key));
}

#[test]
fn a_missing_or_empty_key_file_leaves_the_password() {
    let fixture = Fixture::new();
    fixture.write_users(&registry(&[("alice", "a")]));
    assert!(!fixture.key("alice", &new_key()));
    assert!(fixture.password("alice", "a"));
    fixture.write_keys("alice", "");
    assert!(!fixture.key("alice", &new_key()));
    assert!(fixture.password("alice", "a"));
}

#[test]
fn any_registry_problem_denies_every_name() {
    let fixture = Fixture::new();
    let key = new_key();
    fixture.write_keys("alice", line(&key));
    let good = user("alice", "a");
    let long_name = "n".repeat(65);
    let bad_hash = format!(
        "[users.alice]\nsalt = 'ab'\npassword_hash = '{}'\n",
        "ab".repeat(31)
    );
    let long_hash = format!(
        "[users.alice]\nsalt = 'ab'\npassword_hash = '{}'\n",
        "ab".repeat(33)
    );
    for text in [
        format!("version = 2\n{good}"),
        good.clone(),
        format!("version = 1\nextra = 1\n{good}"),
        format!("version = 1\n{good}extra = 'field'\n"),
        format!("version = 1\n{good}authorized_key = 'legacy'\n"),
        format!("version = 1\n{good}[users.a]\nsalt = 'zz'\n"),
        format!("version = 1\n{good}[users.a]\npassword_hash = 'zz'\n"),
        format!("version = 1\n{good}[users.\"a b\"]\n"),
        format!("version = 1\n{good}[users.\"a/b\"]\n"),
        format!("version = 1\n{good}[users.\"\"]\n"),
        format!("version = 1\n{good}[users.{long_name}]\n"),
        format!("version = 1\n{bad_hash}"),
        format!("version = 1\n{long_hash}"),
        format!("version = 1\n{good}not toml"),
    ] {
        fixture.write_users(&text);
        assert!(!fixture.password("alice", "a"), "{text}");
        assert!(!fixture.key("alice", &key), "{text}");
    }
    private_file(&fixture.users(), &[b'#', 0xff, b'\n']);
    assert!(!fixture.password("alice", "a"));

    fixture.write_users(&registry(&[("alice", "a")]));
    assert!(fixture.password("alice", "a") && fixture.key("alice", &key));
    std::fs::remove_file(fixture.users()).unwrap();
    assert!(!fixture.password("alice", "a") && !fixture.key("alice", &key));
}

#[test]
fn names_of_every_legal_shape_work() {
    let fixture = Fixture::new();
    let longest = "n".repeat(64);
    let names = ["a", "Z9", "a_b", "a-b", "-", "_", longest.as_str()];
    let users = names.map(|name| (name, "pw"));
    fixture.write_users(&registry(&users));
    for name in names {
        let key = new_key();
        fixture.write_keys(name, line(&key));
        assert!(fixture.password(name, "pw"));
        assert!(fixture.key(name, &key));
    }
    assert!(!fixture.password("A", "pw"));
}

#[test]
fn the_registry_limits_are_exact() {
    let fixture = Fixture::new();
    let mut text = String::from("version = 1\n");
    for index in 0..1024 {
        text.push_str(&format!("[users.u{index}]\n"));
    }
    text.push_str(&user("alice", "a"));
    fixture.write_users(&text);
    assert!(
        !fixture.password("alice", "a"),
        "1025 users must be refused"
    );

    let text = text.replacen("[users.u0]\n", "", 1);
    fixture.write_users(&text);
    assert!(fixture.password("alice", "a"), "1024 users must work");

    let padded = format!("{text}{}", "#".repeat(1024 * 1024 - text.len()));
    assert_eq!(padded.len(), 1024 * 1024);
    fixture.write_users(&padded);
    assert!(fixture.password("alice", "a"), "1 MiB must work");
    fixture.write_users(&format!("{padded}#"));
    assert!(!fixture.password("alice", "a"), "1 MiB + 1 must be refused");
}

#[test]
fn key_files_take_comments_blank_lines_crlf_and_no_final_newline() {
    let fixture = Fixture::new();
    fixture.write_users(&registry(&[("alice", "a")]));
    let keys = [new_key(), new_key(), new_key(), new_key()];
    let text = format!(
        "# a comment\r\n\r\n{} with a comment\r\n\n   \n  {}\n{}\t\ttabbed comment\n{}",
        line(&keys[0]),
        line(&keys[1]),
        line(&keys[2]).replacen(' ', "\t", 1),
        line(&keys[3]),
    );
    fixture.write_keys("alice", text);
    for key in &keys {
        assert!(fixture.key("alice", key));
    }

    let commented = new_key();
    fixture.write_keys("alice", format!("# {}\n", line(&commented)));
    assert!(!fixture.key("alice", &commented));
}

#[test]
fn a_bad_record_authorizes_nothing_and_costs_only_itself() {
    let fixture = Fixture::new();
    fixture.write_users(&registry(&[("alice", "a")]));
    let good = new_key();
    let listed = new_key();
    let key = line(&listed);
    let (key_type, blob) = key.split_once(' ').unwrap();
    let wrong_type = key.replacen("ssh-ed25519", "ssh-rsa", 1);
    let certificate = format!("ssh-ed25519-cert-v01@openssh.com {blob}");
    for record in [
        format!("restrict {key}"),
        format!("command=\"/bin/true\" {key}"),
        format!("from=\"10.0.0.1\" {key}"),
        format!("no-pty {key}"),
        format!("cert-authority {key}"),
        format!("@cert-authority * {key}"),
        format!("@revoked {key}"),
        wrong_type,
        certificate,
        format!("{key_type} not-base64!"),
        format!("{key_type} {}", &blob[..blob.len() - 8]),
        key_type.to_owned(),
        blob.to_owned(),
        "garbage".to_owned(),
    ] {
        fixture.write_keys("alice", format!("{record}\n{}\n", line(&good)));
        assert!(!fixture.key("alice", &listed), "{record}");
        assert!(fixture.key("alice", &good), "{record}");
    }
    let opaque = "unknown@example.com AAAAE3Vua25vd25AZXhhbXBsZS5jb20AAAAEAAAAAA==";
    fixture.write_keys("alice", format!("{opaque}\n{}\n", line(&good)));
    assert!(fixture.key("alice", &good));
}

#[test]
fn a_key_file_past_a_limit_is_refused_whole_before_any_match() {
    let fixture = Fixture::new();
    fixture.write_users(&registry(&[("alice", "a")]));
    let good = new_key();
    let first = format!("{}\n", line(&good));

    let long_comment = |len: usize| format!("{} {}", line(&good), "c".repeat(len));
    let exact = long_comment(16 * 1024 - line(&good).len() - 1);
    assert_eq!(exact.len(), 16 * 1024);
    fixture.write_keys("alice", format!("{exact}\n"));
    assert!(fixture.key("alice", &good), "a 16 KiB line must work");
    fixture.write_keys("alice", format!("{first}{exact}c\n"));
    assert!(
        !fixture.key("alice", &good),
        "a longer line must be refused"
    );
    fixture.write_keys("alice", format!("{first}#{}\n", "c".repeat(16 * 1024)));
    assert!(!fixture.key("alice", &good), "comments have the limit too");

    let other = format!("{}\n", line(&new_key()));
    fixture.write_keys("alice", format!("{first}{}", other.repeat(1023)));
    assert!(fixture.key("alice", &good), "1024 keys must work");
    fixture.write_keys("alice", format!("{first}{}", other.repeat(1024)));
    assert!(!fixture.key("alice", &good), "1025 keys must be refused");
    fixture.write_keys("alice", format!("{first}{}", "bad record\n".repeat(1024)));
    assert!(!fixture.key("alice", &good), "bad records count");

    let padding = "#\n".repeat(600 * 1024);
    fixture.write_keys("alice", format!("{first}{padding}"));
    assert!(
        !fixture.key("alice", &good),
        "more than 1 MiB must be refused"
    );

    for bytes in [
        [first.as_bytes(), b"\0\n"].concat(),
        [first.as_bytes(), &[0xff, b'\n']].concat(),
    ] {
        fixture.write_keys("alice", bytes);
        assert!(!fixture.key("alice", &good));
        assert!(fixture.password("alice", "a"));
    }
}

#[test]
fn a_bad_key_file_denies_only_its_own_key_method() {
    let fixture = Fixture::new();
    fixture.write_users(&registry(&[("alice", "a"), ("bob", "b")]));
    let (alice, bob) = (new_key(), new_key());
    fixture.write_keys("alice", format!("{}\n\0", line(&alice)));
    fixture.write_keys("bob", line(&bob));
    assert!(!fixture.key("alice", &alice));
    assert!(fixture.password("alice", "a"));
    assert!(fixture.key("bob", &bob));
}

#[test]
fn unsafe_files_and_directories_deny() {
    let fixture = Fixture::new();
    fixture.write_users(&registry(&[("alice", "a")]));
    let key = new_key();
    fixture.write_keys("alice", line(&key));
    assert!(fixture.password("alice", "a") && fixture.key("alice", &key));

    // Group and other reads are fine for a key file, and not for the registry.
    chmod(&fixture.key_file("alice"), 0o644);
    assert!(fixture.key("alice", &key));
    for mode in [0o640, 0o604] {
        chmod(&fixture.users(), mode);
        assert!(!fixture.password("alice", "a"));
        assert!(!fixture.key("alice", &key));
    }
    chmod(&fixture.users(), 0o600);

    for mode in [0o620, 0o602] {
        chmod(&fixture.key_file("alice"), mode);
        assert!(!fixture.key("alice", &key));
        assert!(fixture.password("alice", "a"));
        chmod(&fixture.users(), mode);
        assert!(!fixture.password("alice", "a"));
        chmod(&fixture.users(), 0o600);
    }
    chmod(&fixture.key_file("alice"), 0o600);

    let keys = fixture.root.join("keys");
    for mode in [0o770, 0o707] {
        chmod(&keys, mode);
        assert!(!fixture.key("alice", &key));
        assert!(fixture.password("alice", "a"));
    }
    chmod(&keys, 0o700);
    assert!(fixture.key("alice", &key));

    for mode in [0o770, 0o707] {
        chmod(&fixture.root, mode);
        assert!(!fixture.password("alice", "a"));
        assert!(!fixture.key("alice", &key));
    }
    chmod(&fixture.root, 0o700);
    assert!(fixture.password("alice", "a") && fixture.key("alice", &key));
}

#[test]
fn ancestors_are_checked_through_the_trust_root_and_no_further() {
    let fixture = Fixture::new();
    let outer = fixture.root.join("outer");
    let inner = outer.join("inner");
    let keys = inner.join("keys");
    directory(&outer);
    directory(&inner);
    directory(&keys);
    private_file(
        &inner.join("users.toml"),
        registry(&[("alice", "a")]).as_bytes(),
    );

    let bounded = AuthStore::with_trust_root(&inner.join("users.toml"), &keys, Some(inner.clone()));
    let unbounded =
        AuthStore::with_trust_root(&inner.join("users.toml"), &keys, Some(outer.clone()));
    assert!(bounded.check_password("alice", "a").accepted);
    assert!(unbounded.check_password("alice", "a").accepted);
    chmod(&outer, 0o777);
    assert!(bounded.check_password("alice", "a").accepted);
    assert!(!unbounded.check_password("alice", "a").accepted);
    chmod(&outer, 0o700);
}

#[test]
fn wrong_file_kinds_deny() {
    let fixture = Fixture::new();
    fixture.write_users(&registry(&[("alice", "a")]));
    let key = new_key();
    let real = fixture.root.join("real-keys");
    private_file(&real, line(&key).as_bytes());
    fixture.write_keys("alice", line(&key));
    assert!(fixture.key("alice", &key));

    let target = fixture.key_file("alice");
    std::fs::remove_file(&target).unwrap();
    symlink(&real, &target).unwrap();
    assert!(!fixture.key("alice", &key), "a symlinked key file");
    assert!(fixture.password("alice", "a"));

    std::fs::remove_file(&target).unwrap();
    directory(&target);
    assert!(!fixture.key("alice", &key), "a directory");
    std::fs::remove_dir(&target).unwrap();

    let status = std::process::Command::new("mkfifo")
        .arg(&target)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(!fixture.key("alice", &key), "a FIFO");
    std::fs::remove_file(&target).unwrap();

    let moved = fixture.root.join("moved-keys");
    std::fs::rename(fixture.root.join("keys"), &moved).unwrap();
    symlink(&moved, fixture.root.join("keys")).unwrap();
    private_file(&moved.join("authorized_keys.alice"), line(&key).as_bytes());
    assert!(!fixture.key("alice", &key), "a symlinked directory");
    std::fs::remove_file(fixture.root.join("keys")).unwrap();
    std::fs::rename(&moved, fixture.root.join("keys")).unwrap();
    assert!(fixture.key("alice", &key));

    let users = fixture.users();
    let real_users = fixture.root.join("real-users");
    std::fs::rename(&users, &real_users).unwrap();
    symlink(&real_users, &users).unwrap();
    assert!(!fixture.password("alice", "a"), "a symlinked registry");
}

#[test]
fn hostile_names_cannot_reach_a_key_file() {
    let fixture = Fixture::new();
    let key = new_key();
    fixture.write_users(&registry(&[("alice", "a")]));
    fixture.write_keys("alice", line(&key));
    private_file(&fixture.root.join("outside"), line(&key).as_bytes());
    for name in [
        "../outside",
        "alice/../alice",
        "alice\n",
        "alice ",
        "ALICE",
        "",
        "/alice",
        "alice\0",
    ] {
        assert!(!fixture.key(name, &key), "{name:?}");
    }
}

#[test]
fn private_keys_are_not_public_keys() {
    let fixture = Fixture::new();
    fixture.write_users(&registry(&[("alice", "a")]));
    let private = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let text = private.to_openssh(LineEnding::LF).unwrap();
    fixture.write_keys("alice", text.as_bytes());
    assert!(!fixture.key("alice", private.public_key()));
}
