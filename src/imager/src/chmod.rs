use async_fs::file_block_device::AsyncFileBlockDevice;
use async_fs::{AccessPermissions, EntryId, FileSystem, Role, RolePermissions};
use camino::Utf8Path;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read};
use std::path::{Component, Path, PathBuf};

pub fn parse_mode(value: &str) -> Option<RolePermissions> {
    fn triplet(value: &[u8]) -> Option<AccessPermissions> {
        match value {
            b"rwx" => Some(AccessPermissions::Rwx),
            b"rw-" => Some(AccessPermissions::Rw),
            b"r-x" => Some(AccessPermissions::Rx),
            b"r--" => Some(AccessPermissions::R),
            b"---" => Some(AccessPermissions::None),
            _ => None,
        }
    }

    let bytes = value.as_bytes();
    if bytes.len() != 9 {
        return None;
    }
    let permissions = RolePermissions::new(
        triplet(&bytes[0..3])?,
        triplet(&bytes[3..6])?,
        triplet(&bytes[6..9])?,
    );
    if !permissions.system.can_narrow_to(permissions.interactive)
        || !permissions.interactive.can_narrow_to(permissions.none)
    {
        return None;
    }
    Some(permissions)
}

fn motor_fs_region(image: &Path) -> io::Result<(u64, u64)> {
    let mut file = File::open(image)?;
    let mbr = mbrman::MBR::read_from(&mut file, super::SECTOR_SIZE).map_err(|err| {
        io::Error::new(ErrorKind::InvalidData, format!("failed to read MBR: {err}"))
    })?;
    let mut result = None;
    for (_, partition) in mbr.iter() {
        if !partition.is_unused() && partition.sys == motor_fs::PARTITION_ID {
            if result.is_some() {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "image has multiple Motor FS partitions",
                ));
            }
            let offset = u64::from(partition.starting_lba)
                .checked_mul(u64::from(super::SECTOR_SIZE))
                .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "partition overflow"))?;
            let length = u64::from(partition.sectors)
                .checked_mul(u64::from(super::SECTOR_SIZE))
                .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "partition overflow"))?;
            result = Some((offset, length));
        }
    }
    result.ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "image has no Motor FS partition"))
}

async fn resolve_path(
    fs: &motor_fs::MotorFs<AsyncFileBlockDevice>,
    path: &Path,
) -> io::Result<EntryId> {
    let mut entry_id = motor_fs::ROOT_DIR_ID;
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let name = name
            .to_str()
            .ok_or_else(|| io::Error::from(ErrorKind::InvalidInput))?;
        entry_id = fs
            .stat(Role::System, entry_id, name)
            .await?
            .ok_or_else(|| io::Error::from(ErrorKind::NotFound))?
            .0;
    }
    Ok(entry_id)
}

fn chmod_raw(image: &Path, path: &Path, permissions: RolePermissions) -> io::Result<()> {
    let (offset, length) = motor_fs_region(image)?;
    let image = Utf8Path::from_path(image)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "image path is not UTF-8"))?;
    let runtime = tokio::runtime::LocalRuntime::new()?;
    runtime.block_on(async {
        let device = AsyncFileBlockDevice::open_region(image, offset, length).await?;
        let mut fs = motor_fs::MotorFs::open(Box::new(device)).await?;
        let entry_id = resolve_path(&fs, path).await?;
        fs.set_all_permissions_image_admin(Role::System, entry_id, permissions)
            .await?;
        fs.flush().await
    })
}

struct TemporaryImage(Option<PathBuf>);

impl TemporaryImage {
    fn create_next_to(image: &Path, extension: &str) -> io::Result<Self> {
        let parent = image.parent().unwrap_or_else(|| Path::new("."));
        let filename = image
            .file_name()
            .ok_or_else(|| io::Error::from(ErrorKind::InvalidInput))?;
        for counter in 0..1000_u32 {
            let mut name = OsString::from(".");
            name.push(filename);
            name.push(format!(
                ".chmod-{}-{counter}.{extension}",
                std::process::id()
            ));
            let path = parent.join(name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Self(Some(path))),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }
        Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "unable to reserve a temporary image name",
        ))
    }

    fn path(&self) -> &Path {
        self.0.as_deref().unwrap()
    }

    fn publish(mut self, destination: &Path) -> io::Result<()> {
        fs::rename(self.path(), destination)?;
        self.0 = None;
        Ok(())
    }
}

impl Drop for TemporaryImage {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn is_qcow2(image: &Path) -> io::Result<bool> {
    let mut magic = [0_u8; 4];
    File::open(image)?.read_exact(&mut magic)?;
    Ok(magic == *b"QFI\xfb")
}

pub fn chmod_image(image: &Path, path: &Path, permissions: RolePermissions) -> io::Result<()> {
    if !is_qcow2(image)? {
        return chmod_raw(image, path, permissions);
    }

    let raw = TemporaryImage::create_next_to(image, "raw")?;
    let qcow2 = TemporaryImage::create_next_to(image, "qcow2")?;
    super::convert_qcow2_to_raw(image, raw.path())?;
    chmod_raw(raw.path(), path, permissions)?;
    super::convert_raw_to_qcow2(raw.path(), qcow2.path())?;
    fs::set_permissions(qcow2.path(), fs::metadata(image)?.permissions())?;
    qcow2.publish(image)
}
