#![cfg(target_os = "motor")]

//! The checks of `trusted_file` in Motor OS's terms: what the None role may do
//! to a credential file and to the directories above it. tests/auth_store.rs
//! has the Unix half, and everything that is the same on both platforms.
//!
//! One test, a step at a time: every read opens its own filesystem connection.

use std::path::{Path, PathBuf};

use moto_sdk::io::fs::{AccessPermissions as Access, FsClient};
use moto_sdk::sys::caps::ProcessRole;
use russh::keys::PublicKey;
use russhd::auth_store::AuthStore;
use russhd::trusted_file::{self, MAX_BYTES, Readers};
use sha2::{Digest, Sha256};

const PASSWORD: &str = "a password";
// Any public key will do.
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqjlUjeBcqvHyy+RvVL54pfyK7vj5kAkJRt+qLlZWPH";

/// A registry with the name `motor` and that name's key file, in a new
/// directory under `parent`.
struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(parent: &str) -> Self {
        let root = Path::new(parent).join(format!("russhd-trust-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let tree = Self { root };
        std::fs::create_dir(tree.keys()).unwrap();
        std::fs::write(tree.users(), registry()).unwrap();
        std::fs::write(tree.key_file(), KEY).unwrap();
        tree
    }

    fn users(&self) -> PathBuf {
        self.root.join("users.toml")
    }

    fn keys(&self) -> PathBuf {
        self.root.join("keys")
    }

    fn key_file(&self) -> PathBuf {
        self.keys().join("authorized_keys.motor")
    }

    /// What russhd answers for this tree with the trust root it runs with.
    fn logs_in(&self) -> (bool, bool) {
        let store = AuthStore::new(&self.users(), &self.keys());
        let key = PublicKey::from_openssh(KEY).unwrap();
        (
            store.check_password("motor", PASSWORD).accepted,
            store.check_key("motor", &key).accepted,
        )
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn registry() -> String {
    let salt = [7_u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(PASSWORD);
    format!(
        "version = 1\n[users.motor]\nsalt = '{}'\npassword_hash = '{}'\n",
        hex::encode(salt),
        hex::encode(hasher.finalize())
    )
}

/// Changes what None may do with `path`, and nothing else.
fn set_none(path: &Path, access: Access) {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let (id, _) = client.stat(path.to_str().unwrap()).await.unwrap();
        let mut permissions = client.metadata(id).await.unwrap().permissions().unwrap();
        permissions.none = access;
        client.set_all_permissions(id, permissions).await.unwrap();
    })
}

#[test]
fn none_decides_what_is_trusted() {
    let capabilities = moto_sdk::sys::ProcessStaticPage::get().capabilities;
    if ProcessRole::from_caps(capabilities) == ProcessRole::None {
        return nothing_none_makes_is_trusted();
    }

    let tree = Tree::new("/user/tmp");
    let (users, keys, key_file) = (tree.users(), tree.keys(), tree.key_file());
    // As text: a failed assertion then shows the file, not a list of bytes.
    let read = |path: &Path, readers| {
        trusted_file::read(path, Some(&tree.root), readers)
            .map(|bytes| bytes.map(|bytes| String::from_utf8(bytes).unwrap()))
    };

    assert_eq!(read(&tree.root.join("missing"), Readers::Anyone), Ok(None));
    assert_eq!(read(&keys, Readers::Anyone), Err("not a regular file"));

    // A new file is readable by None: fine for keys, not for the registry.
    assert_eq!(read(&key_file, Readers::Anyone), Ok(Some(KEY.to_owned())));
    assert_eq!(
        read(&users, Readers::TrustedOnly),
        Err("None can read the file")
    );
    set_none(&users, Access::None);
    assert_eq!(read(&users, Readers::TrustedOnly), Ok(Some(registry())));

    // None must not be able to write the file ...
    set_none(&key_file, Access::Rw);
    assert_eq!(
        read(&key_file, Readers::Anyone),
        Err("None can write the file")
    );
    set_none(&key_file, Access::R);

    // ... or to replace it, which a writable directory above it allows. The
    // trust root is the last directory checked.
    set_none(&keys, Access::Rwx);
    assert_eq!(
        read(&key_file, Readers::Anyone),
        Err("None can write a path component")
    );
    set_none(&keys, Access::Rx);
    set_none(&tree.root, Access::Rwx);
    assert_eq!(
        read(&key_file, Readers::Anyone),
        Err("None can write a path component")
    );
    assert!(trusted_file::read(&key_file, Some(&keys), Readers::Anyone).is_ok());
    set_none(&tree.root, Access::Rx);

    // The size limit is exact. Only the length is compared: a megabyte makes
    // a poor assertion message.
    let length = || read(&key_file, Readers::Anyone).map(|text| text.map(|text| text.len()));
    std::fs::write(&key_file, vec![b'#'; MAX_BYTES]).unwrap();
    assert_eq!(length(), Ok(Some(MAX_BYTES)));
    std::fs::write(&key_file, vec![b'#'; MAX_BYTES + 1]).unwrap();
    assert_eq!(length(), Err("the file exceeds 1 MiB"));
    std::fs::write(&key_file, KEY).unwrap();

    // russhd's own trust root is /user. This tree is below it. One that is as
    // private, but in None's own directory, is checked through the root.
    assert_eq!(tree.logs_in(), (true, true));
    let outside = Tree::new("/none/tmp");
    set_none(&outside.users(), Access::None);
    assert!(
        trusted_file::read(&outside.users(), Some(&outside.root), Readers::TrustedOnly).is_ok()
    );
    assert_eq!(
        trusted_file::read(
            &outside.users(),
            trusted_file::default_trust_root().as_deref(),
            Readers::TrustedOnly
        ),
        Err("None can write a path component")
    );
    assert_eq!(outside.logs_in(), (false, false));
}

/// What None creates, None can write.
fn nothing_none_makes_is_trusted() {
    let tree = Tree::new("/none/tmp");
    for (path, readers) in [
        (tree.users(), Readers::TrustedOnly),
        (tree.key_file(), Readers::Anyone),
    ] {
        assert_eq!(
            trusted_file::read(&path, Some(&tree.root), readers),
            Err("None can write the file")
        );
    }
    assert_eq!(tree.logs_in(), (false, false));
}
