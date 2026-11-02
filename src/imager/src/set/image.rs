use super::bare_toml;
use super::credentials::{
    Credentials, Login, UserSecret, KEYS_DIR, MAX_ARTIFACT_SIZE, SSH_CONFIG, TLS_CERT, TLS_KEY,
    USERS_FILE,
};
use super::invalid;
use crate::chmod::{self, TemporaryImage};
use camino::Utf8Path;
use moto_sdk::async_fs::file_block_device::AsyncFileBlockDevice;
use moto_sdk::async_fs::{
    AccessPermissions, EntryId, EntryKind, FileSystem, Role, RolePermissions, BLOCK_SIZE,
};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

pub(crate) type Fs = motor_fs::MotorFs<AsyncFileBlockDevice>;

/// Where the path checks for a credential file stop, as in russhd.
const TRUST_ROOT: &str = "/user";

/// The mode of key files and the user registry: what SFTP gives a new file, so
/// that shipped and installed credentials match.
const CREDENTIAL_PERMISSIONS: RolePermissions = RolePermissions::new(
    AccessPermissions::Rwx,
    AccessPermissions::Rw,
    AccessPermissions::None,
);

/// Applies all `credentials` in one staged update; each file is rewritten once.
pub(crate) fn update(image: &Path, credentials: &[Credentials]) -> io::Result<()> {
    update_with(image, credentials, async |_| Ok(()), async |_| Ok(()))
}

/// Like `update`, with extra `write` and `verify` steps on the same staged image.
pub(crate) fn update_with(
    image: &Path,
    credentials: &[Credentials],
    write: impl AsyncFnOnce(&mut Fs) -> io::Result<()>,
    verify: impl AsyncFnOnce(&Fs) -> io::Result<()>,
) -> io::Result<()> {
    update_probed(image, credentials, write, verify, |_| Ok(()))
}

/// `probe` runs before each step, which is how tests fail every one of them.
fn update_probed(
    image: &Path,
    credentials: &[Credentials],
    write: impl AsyncFnOnce(&mut Fs) -> io::Result<()>,
    verify: impl AsyncFnOnce(&Fs) -> io::Result<()>,
    probe: impl Fn(&str) -> io::Result<()>,
) -> io::Result<()> {
    let probe = &probe;
    staged_update(image, |raw| {
        let replacements = with_fs(raw, async |fs| {
            let mut stage = Stage::default();
            for credential in credentials {
                stage.add(fs, credential).await?;
            }
            for replacement in stage.replacements.iter().filter(|r| r.changed) {
                probe(&replacement.path)?;
                replacement.write(fs).await?;
            }
            probe("extra write")?;
            write(fs).await?;
            probe("flush")?;
            fs.flush().await?;
            Ok(stage.replacements)
        })?;
        with_fs(raw, async |fs| {
            for expected in replacements
                .iter()
                .filter(|replacement| replacement.changed)
            {
                probe(&expected.path)?;
                let (actual, permissions) = read_back(fs, &expected.path).await?;
                if actual != expected.bytes || permissions != expected.permissions {
                    return Err(io::Error::other("image credential verification failed"));
                }
            }
            if replacements
                .iter()
                .any(|replacement| replacement.path == SSH_CONFIG)
            {
                probe("service configuration")?;
                bare_toml::check_service(utf8(&read_back(fs, SSH_CONFIG).await?.0)?)?;
            }
            probe("extra verification")?;
            verify(fs).await
        })
    })
}
/// Only the final rename touches the original, including for raw images.
fn staged_update(image: &Path, operation: impl FnOnce(&Path) -> io::Result<()>) -> io::Result<()> {
    let metadata = fs::symlink_metadata(image)?;
    if !metadata.is_file() {
        return Err(invalid("image must be a regular file, not a symlink"));
    }
    let qcow2 = chmod::is_qcow2(image)?;
    let raw = TemporaryImage::create_next_to(image, "raw")?;
    if qcow2 {
        crate::convert_qcow2_to_raw(image, raw.path())?;
    } else {
        // fs::copy would copy the source's potentially public permissions too.
        io::copy(
            &mut File::open(image)?,
            &mut OpenOptions::new().write(true).open(raw.path())?,
        )?;
    }
    operation(raw.path())?;
    let result = if qcow2 {
        let result = TemporaryImage::create_next_to(image, "qcow2")?;
        crate::convert_raw_to_qcow2(raw.path(), result.path())?;
        result
    } else {
        raw
    };
    fs::set_permissions(result.path(), metadata.permissions())?;
    File::open(result.path())?.sync_all()?;
    let parent = image
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = File::open(parent)?;
    result.publish(image)?;
    directory.sync_all().map_err(|_| {
        io::Error::other("image replaced, but directory sync failed; durability is unconfirmed")
    })
}

fn with_fs<T>(raw: &Path, operation: impl AsyncFnOnce(&mut Fs) -> io::Result<T>) -> io::Result<T> {
    let (offset, length) = chmod::motor_fs_region(raw)?;
    let file_len = fs::metadata(raw)?.len();
    if offset < u64::from(crate::SECTOR_SIZE)
        || length == 0
        || length % BLOCK_SIZE as u64 != 0
        || offset.checked_add(length).is_none_or(|end| end > file_len)
    {
        return Err(invalid("invalid Motor FS partition bounds or alignment"));
    }
    let mut disk = File::open(raw)?;
    let mbr = mbrman::MBR::read_from(&mut disk, crate::SECTOR_SIZE)
        .map_err(|_| invalid("invalid image partition table"))?;
    for (_, partition) in mbr.iter() {
        if partition.is_unused() || partition.sys == motor_fs::PARTITION_ID {
            continue;
        }
        let start = u64::from(partition.starting_lba) * u64::from(crate::SECTOR_SIZE);
        let end = start + u64::from(partition.sectors) * u64::from(crate::SECTOR_SIZE);
        if start < offset + length && end > offset {
            return Err(invalid("Motor FS partition overlaps another partition"));
        }
    }
    let raw = Utf8Path::from_path(raw).ok_or_else(|| invalid("image path must be UTF-8"))?;
    tokio::runtime::LocalRuntime::new()?.block_on(async {
        let device = AsyncFileBlockDevice::open_region(raw, offset, length).await?;
        let mut fs = Fs::open(Box::new(device)).await?;
        operation(&mut fs).await
    })
}

fn utf8(bytes: &[u8]) -> io::Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| invalid("SSH configuration must be UTF-8"))
}

/// What a destination holds, which decides how far its permissions may reach.
#[derive(Clone, Copy, PartialEq)]
enum Destination {
    Public,
    /// Limited to `rw-r-----`.
    Secret,
    /// May not grant None any access.
    UserRegistry,
    /// May be read by None, and does not have to exist yet.
    KeyList,
}

enum Target {
    Existing {
        id: EntryId,
        installed: RolePermissions,
    },
    New {
        parent: EntryId,
        name: String,
    },
}

struct Replacement {
    path: String,
    target: Target,
    permissions: RolePermissions,
    bytes: Vec<u8>,
    changed: bool,
}

/// The files an update changes, loaded once and edited in memory.
#[derive(Default)]
struct Stage {
    replacements: Vec<Replacement>,
}

impl Stage {
    async fn entry(
        &mut self,
        fs: &Fs,
        path: &str,
        destination: Destination,
    ) -> io::Result<&mut Replacement> {
        let index = match self.replacements.iter().position(|r| r.path == path) {
            Some(index) => index,
            None => {
                self.replacements
                    .push(Replacement::load(fs, path, destination).await?);
                self.replacements.len() - 1
            }
        };
        Ok(&mut self.replacements[index])
    }

    /// Every SSH credential needs a service configuration it can stand behind.
    async fn service(&mut self, fs: &Fs) -> io::Result<&mut Replacement> {
        let config = self.entry(fs, SSH_CONFIG, Destination::Secret).await?;
        bare_toml::check_service(utf8(&config.bytes)?)?;
        Ok(config)
    }

    async fn add(&mut self, fs: &Fs, credential: &Credentials) -> io::Result<()> {
        match credential {
            Credentials::Tls { cert, key } => {
                self.entry(fs, TLS_CERT, Destination::Public)
                    .await?
                    .replace(cert.clone());
                self.entry(fs, TLS_KEY, Destination::Secret)
                    .await?
                    .replace(key.clone());
            }
            Credentials::HostKey(key) => {
                let config = self.service(fs).await?;
                let bytes = bare_toml::set_host_key(utf8(&config.bytes)?, key)?;
                config.replace(bytes);
            }
            Credentials::User { login, secret } => {
                self.service(fs).await?;
                let users = self
                    .entry(fs, USERS_FILE, Destination::UserRegistry)
                    .await?;
                if let Some(registry) = bare_toml::update_user(utf8(&users.bytes)?, login, secret)?
                {
                    users.replace(registry);
                }

                let new = matches!(login, Login::New(_));
                if new || matches!(secret, UserSecret::PublicKey(_)) {
                    let path = format!("{KEYS_DIR}/authorized_keys.{}", login.name());
                    let keys = self.entry(fs, &path, Destination::KeyList).await?;
                    if new && matches!(keys.target, Target::Existing { .. }) {
                        return Err(invalid("a new SSH user's key file already exists"));
                    }
                    if let UserSecret::PublicKey(line) = secret {
                        keys.replace(format!("{line}\n").into_bytes());
                    }
                }
            }
        }
        Ok(())
    }
}

/// Applies the "Filesystem trust" rules of docs/plans/sshd-keys.md to the
/// directories above a credential file, and returns the file's parent.
async fn check_ancestors(fs: &Fs, path: &Path) -> io::Result<EntryId> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("credential destination has no parent"))?;
    for ancestor in parent.ancestors() {
        let id = chmod::resolve_path(fs, ancestor).await?;
        let metadata = fs.metadata(Role::System, id).await?;
        if metadata.try_kind()? != EntryKind::Directory || metadata.permissions()?.none.can_write()
        {
            return Err(invalid(
                "a credential directory is not a directory, or None can write it",
            ));
        }
        if ancestor == Path::new(TRUST_ROOT) {
            break;
        }
    }
    chmod::resolve_path(fs, parent).await
}

async fn read_entry(fs: &Fs, id: EntryId) -> io::Result<(Vec<u8>, RolePermissions)> {
    let metadata = fs.metadata(Role::System, id).await?;
    if metadata.try_kind()? != EntryKind::File || metadata.size > MAX_ARTIFACT_SIZE as u64 {
        return Err(invalid(
            "credential destination must be a regular file of at most 1 MiB",
        ));
    }
    let mut bytes = vec![0; metadata.size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let end = bytes.len().min(offset + BLOCK_SIZE - offset % BLOCK_SIZE);
        let size = fs
            .read(Role::System, id, offset as u64, &mut bytes[offset..end])
            .await?;
        if size == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        offset += size;
    }
    Ok((bytes, metadata.permissions()?))
}

async fn read_back(fs: &Fs, path: &str) -> io::Result<(Vec<u8>, RolePermissions)> {
    read_entry(fs, chmod::resolve_path(fs, Path::new(path)).await?).await
}

impl Replacement {
    async fn load(fs: &Fs, path: &str, destination: Destination) -> io::Result<Self> {
        let path_buf = Path::new(path);
        let credential = matches!(
            destination,
            Destination::UserRegistry | Destination::KeyList
        );
        let parent = if credential {
            Some(check_ancestors(fs, path_buf).await?)
        } else {
            None
        };
        let id = match chmod::resolve_path(fs, path_buf).await {
            Ok(id) => id,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let (Destination::KeyList, Some(parent), Some(name)) = (
                    destination,
                    parent,
                    path_buf.file_name().and_then(|name| name.to_str()),
                ) else {
                    return Err(error);
                };
                return Ok(Self {
                    path: path.to_owned(),
                    target: Target::New {
                        parent,
                        name: name.to_owned(),
                    },
                    permissions: CREDENTIAL_PERMISSIONS,
                    bytes: Vec::new(),
                    changed: false,
                });
            }
            Err(error) => return Err(error),
        };
        let (bytes, installed) = read_entry(fs, id).await?;
        match destination {
            Destination::Public => {}
            Destination::Secret => {
                if !AccessPermissions::Rw.can_narrow_to(installed.system)
                    || !AccessPermissions::R.can_narrow_to(installed.interactive)
                    || installed.none != AccessPermissions::None
                {
                    return Err(invalid("secret destination permissions exceed rw-r-----"));
                }
            }
            Destination::UserRegistry | Destination::KeyList => {
                if installed.none.can_write()
                    || (destination == Destination::UserRegistry && installed.none.can_read())
                {
                    return Err(invalid("None has too much access to a credential file"));
                }
            }
        }
        Ok(Self {
            path: path.to_owned(),
            target: Target::Existing { id, installed },
            permissions: if credential {
                CREDENTIAL_PERMISSIONS
            } else {
                installed
            },
            bytes,
            changed: false,
        })
    }

    /// Selects this file for update: to hold `bytes`, with `self.permissions`.
    fn replace(&mut self, bytes: Vec<u8>) {
        let mode_differs = match self.target {
            Target::Existing { installed, .. } => installed != self.permissions,
            Target::New { .. } => true,
        };
        self.changed |= mode_differs || self.bytes != bytes;
        self.bytes = bytes;
    }

    async fn write(&self, fs: &mut Fs) -> io::Result<()> {
        if self.bytes.len() > MAX_ARTIFACT_SIZE {
            return Err(invalid("replacement exceeds 1 MiB"));
        }
        let (id, installed) = match &self.target {
            Target::Existing { id, installed } => (*id, *installed),
            Target::New { parent, name } => {
                let id = fs
                    .create_entry(
                        Role::System,
                        *parent,
                        EntryKind::File,
                        name,
                        self.permissions,
                    )
                    .await?;
                (id, self.permissions)
            }
        };
        if !installed.system.can_write() {
            let mut writable = installed;
            writable.system = if installed.system.can_execute() {
                AccessPermissions::Rwx
            } else {
                AccessPermissions::Rw
            };
            fs.set_all_permissions_image_admin(Role::System, id, writable)
                .await?;
        }
        fs.resize(Role::System, id, 0).await?;
        let mut offset = 0;
        while offset < self.bytes.len() {
            let end = self
                .bytes
                .len()
                .min(offset + BLOCK_SIZE - offset % BLOCK_SIZE);
            let size = fs
                .write(Role::System, id, offset as u64, &self.bytes[offset..end])
                .await?;
            if size == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            offset += size;
        }
        if !installed.system.can_write() || installed != self.permissions {
            fs.set_all_permissions_image_admin(Role::System, id, self.permissions)
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../tests/set_support/mod.rs"]
mod set_support;

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn staging_is_private_and_failed_operation_preserves_original() {
        let original = TemporaryImage::create_in(
            &std::env::temp_dir(),
            Path::new("imager-set-staging"),
            "raw",
        )
        .unwrap();
        fs::write(original.path(), b"original image").unwrap();
        fs::set_permissions(original.path(), fs::Permissions::from_mode(0o644)).unwrap();
        let mut scratch_path = None;
        let error = staged_update(original.path(), |scratch| {
            scratch_path = Some(scratch.to_owned());
            assert_eq!(fs::metadata(scratch)?.permissions().mode() & 0o777, 0o600);
            fs::write(scratch, b"partially replaced credentials")?;
            Err(io::ErrorKind::StorageFull.into())
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert_eq!(fs::read(original.path()).unwrap(), b"original image");
        assert!(!scratch_path.unwrap().exists());
    }

    #[test]
    fn a_change_of_mode_alone_is_written_and_verified() {
        use set_support::{resolve, secret_permissions, Fixture, BASE, LOGIN_KEY};

        let fixture = Fixture::new(false, BASE);
        let credentials = [Credentials::User {
            login: Login::Existing("motor".to_owned()),
            secret: UserSecret::PublicKey(LOGIN_KEY.to_owned()),
        }];
        update(&fixture.image, &credentials).unwrap();
        let key_list = format!("{KEYS_DIR}/authorized_keys.motor");
        fixture.edit(async |fs| {
            let id = resolve(fs, &key_list).await?;
            fs.set_all_permissions_image_admin(Role::System, id, secret_permissions())
                .await
        });

        let steps = RefCell::new(Vec::new());
        update_probed(
            &fixture.image,
            &credentials,
            async |_| Ok(()),
            async |_| Ok(()),
            |step| {
                steps.borrow_mut().push(step.to_owned());
                Ok(())
            },
        )
        .unwrap();
        let steps = steps.into_inner();
        assert_eq!(steps.iter().filter(|step| **step == key_list).count(), 2);
    }

    #[test]
    fn a_failure_at_any_step_publishes_nothing() {
        use set_support::{Fixture, BASE, HOST_KEY, LOGIN_KEY, USERS};

        let credentials = [
            Credentials::User {
                login: Login::New("alice".to_owned()),
                secret: UserSecret::Password {
                    salt: "ab".to_owned(),
                    hash: "cd".to_owned(),
                },
            },
            Credentials::User {
                login: Login::Existing("motor".to_owned()),
                secret: UserSecret::PublicKey(LOGIN_KEY.to_owned()),
            },
            Credentials::HostKey(HOST_KEY.to_owned()),
            Credentials::Tls {
                cert: b"new certificate".to_vec(),
                key: b"new private key".to_vec(),
            },
        ];
        for qcow2 in [false, true] {
            let fixture = Fixture::new(qcow2, BASE);
            let original = fs::read(&fixture.image).unwrap();
            let mut failed_at = Vec::new();
            for step in 0.. {
                let seen = Cell::new(0);
                let name = Cell::new(String::new());
                let result = update_probed(
                    &fixture.image,
                    &credentials,
                    async |_| Ok(()),
                    async |_| Ok(()),
                    |what| {
                        let index = seen.get();
                        seen.set(index + 1);
                        if index != step {
                            return Ok(());
                        }
                        name.set(what.to_owned());
                        Err(io::Error::other("injected failure"))
                    },
                );
                if result.is_ok() {
                    break;
                }
                assert_eq!(result.unwrap_err().to_string(), "injected failure");
                assert_eq!(
                    fs::read(&fixture.image).unwrap(),
                    original,
                    "{}",
                    name.take()
                );
                fixture.no_temporaries();
                failed_at.push(name.take());
            }
            // The writes, the flush, and then the verification of each file.
            for step in [USERS, SSH_CONFIG, TLS_CERT, TLS_KEY, "flush"] {
                assert!(failed_at.iter().any(|name| name == step), "{step}");
            }
            let key_list = format!("{KEYS_DIR}/authorized_keys.motor");
            assert_eq!(
                failed_at.iter().filter(|name| **name == key_list).count(),
                2
            );
            assert_eq!(failed_at.iter().filter(|name| *name == USERS).count(), 2);
            assert!(failed_at.iter().any(|name| name == "service configuration"));
            assert_ne!(fs::read(&fixture.image).unwrap(), original);
        }
    }
}
