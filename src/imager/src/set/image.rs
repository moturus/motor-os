use super::credentials::{Credentials, MAX_ARTIFACT_SIZE, SSH_CONFIG, TLS_CERT, TLS_KEY};
use super::invalid;
use crate::chmod::{self, TemporaryImage};
use async_fs::file_block_device::AsyncFileBlockDevice;
use async_fs::{
    AccessPermissions, EntryId, EntryKind, FileSystem, Role, RolePermissions, BLOCK_SIZE,
};
use camino::Utf8Path;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

type Fs = motor_fs::MotorFs<AsyncFileBlockDevice>;

pub(super) fn update(image: &Path, credentials: &Credentials) -> io::Result<()> {
    staged_update(image, |raw| {
        let replacements = with_fs(raw, async |fs| {
            let replacements = match credentials {
                Credentials::Tls { cert, key } => vec![
                    Replacement::load(fs, TLS_CERT, false)
                        .await?
                        .with_bytes(cert.clone()),
                    Replacement::load(fs, TLS_KEY, true)
                        .await?
                        .with_bytes(key.clone()),
                ],
                _ => {
                    let old = Replacement::load(fs, SSH_CONFIG, true).await?;
                    let bytes = credentials.update_ssh(&old.bytes)?;
                    vec![old.with_bytes(bytes)]
                }
            };
            for replacement in &replacements {
                replacement.write(fs).await?;
            }
            fs.flush().await?;
            Ok(replacements)
        })?;
        with_fs(raw, async |fs| {
            for expected in &replacements {
                let actual = Replacement::load(fs, expected.path, false).await?;
                if actual.bytes != expected.bytes || actual.permissions != expected.permissions {
                    return Err(io::Error::other("image credential verification failed"));
                }
            }
            Ok(())
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

struct Replacement {
    path: &'static str,
    id: EntryId,
    permissions: RolePermissions,
    bytes: Vec<u8>,
}

impl Replacement {
    async fn load(fs: &Fs, path: &'static str, secret: bool) -> io::Result<Self> {
        let id = chmod::resolve_path(fs, Path::new(path)).await?;
        let metadata = fs.metadata(Role::System, id).await?;
        if metadata.try_kind()? != EntryKind::File || metadata.size > MAX_ARTIFACT_SIZE as u64 {
            return Err(invalid(
                "credential destination must be a regular file of at most 1 MiB",
            ));
        }
        let permissions = metadata.permissions()?;
        if secret
            && (!AccessPermissions::Rw.can_narrow_to(permissions.system)
                || !AccessPermissions::R.can_narrow_to(permissions.interactive)
                || permissions.none != AccessPermissions::None)
        {
            return Err(invalid("secret destination permissions exceed rw-r-----"));
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
        Ok(Self {
            path,
            id,
            permissions,
            bytes,
        })
    }

    fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.bytes = bytes;
        self
    }

    async fn write(&self, fs: &mut Fs) -> io::Result<()> {
        if self.bytes.len() > MAX_ARTIFACT_SIZE {
            return Err(invalid("replacement exceeds 1 MiB"));
        }
        if !self.permissions.system.can_write() {
            let mut writable = self.permissions;
            writable.system = if self.permissions.system.can_execute() {
                AccessPermissions::Rwx
            } else {
                AccessPermissions::Rw
            };
            fs.set_all_permissions_image_admin(Role::System, self.id, writable)
                .await?;
        }
        fs.resize(Role::System, self.id, 0).await?;
        let mut offset = 0;
        while offset < self.bytes.len() {
            let end = self
                .bytes
                .len()
                .min(offset + BLOCK_SIZE - offset % BLOCK_SIZE);
            let size = fs
                .write(
                    Role::System,
                    self.id,
                    offset as u64,
                    &self.bytes[offset..end],
                )
                .await?;
            if size == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            offset += size;
        }
        if !self.permissions.system.can_write() {
            fs.set_all_permissions_image_admin(Role::System, self.id, self.permissions)
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
