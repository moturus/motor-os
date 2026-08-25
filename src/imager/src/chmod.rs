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

#[cfg(test)]
mod tests {
    use super::*;
    use async_fs::{EntryKind, Metadata};
    use mbrman::{MBRPartitionEntry, BOOT_INACTIVE, CHS};
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::atomic::{AtomicU64, Ordering};

    const PARTITION_BLOCKS: u64 = 256;
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        raw: PathBuf,
    }

    impl Fixture {
        fn create() -> Self {
            let root = loop {
                let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "motor-imager-chmod-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => break path,
                    Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                    Err(err) => panic!("failed to create test directory: {err}"),
                }
            };
            let partition = root.join("data.partition");
            let raw = root.join("disk.raw");
            let partition_path = Utf8Path::from_path(&partition).unwrap();
            let runtime = tokio::runtime::LocalRuntime::new().unwrap();
            runtime
                .block_on(async {
                    let device =
                        AsyncFileBlockDevice::create(partition_path, PARTITION_BLOCKS).await?;
                    let mut fs = motor_fs::MotorFs::format(Box::new(device)).await?;
                    let full = RolePermissions::all(AccessPermissions::Rwx);
                    let sealed = RolePermissions::new(
                        AccessPermissions::Rx,
                        AccessPermissions::Rx,
                        AccessPermissions::R,
                    );
                    let file = fs
                        .create_entry(
                            Role::System,
                            motor_fs::ROOT_DIR_ID,
                            EntryKind::File,
                            "file",
                            full,
                        )
                        .await?;
                    fs.write(Role::System, file, 0, b"old").await?;
                    fs.create_entry(
                        Role::System,
                        motor_fs::ROOT_DIR_ID,
                        EntryKind::Directory,
                        "locked",
                        sealed,
                    )
                    .await?;
                    let denied = fs
                        .create_entry(
                            Role::System,
                            motor_fs::ROOT_DIR_ID,
                            EntryKind::Directory,
                            "denied",
                            full,
                        )
                        .await?;
                    fs.create_entry(Role::System, denied, EntryKind::File, "child", full)
                        .await?;
                    fs.set_all_permissions(
                        Role::System,
                        denied,
                        RolePermissions::all(AccessPermissions::R),
                    )
                    .await?;
                    fs.flush().await
                })
                .unwrap();

            let partition_len = fs::metadata(&partition).unwrap().len();
            assert_eq!(partition_len % u64::from(super::super::SECTOR_SIZE), 0);
            let mut disk = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&raw)
                .unwrap();
            let offset = u64::from(super::super::SECTOR_SIZE);
            disk.set_len(offset + partition_len).unwrap();
            let mut mbr = mbrman::MBR::new_from(
                &mut disk,
                super::super::SECTOR_SIZE,
                [0x11, 0x22, 0x33, 0x44],
            )
            .unwrap();
            mbr[1] = MBRPartitionEntry {
                boot: BOOT_INACTIVE,
                first_chs: CHS::empty(),
                sys: motor_fs::PARTITION_ID,
                last_chs: CHS::empty(),
                starting_lba: 1,
                sectors: (partition_len / u64::from(super::super::SECTOR_SIZE)) as u32,
            };
            mbr.write_into(&mut disk).unwrap();
            disk.seek(SeekFrom::Start(offset)).unwrap();
            io::copy(&mut File::open(&partition).unwrap(), &mut disk).unwrap();
            disk.flush().unwrap();

            Self { root, raw }
        }

        fn qcow2(&self) -> PathBuf {
            let path = self.root.join("disk.qcow2");
            super::super::convert_raw_to_qcow2(&self.raw, &path).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn with_raw_fs<T>(
        raw: &Path,
        operation: impl AsyncFnOnce(&mut motor_fs::MotorFs<AsyncFileBlockDevice>) -> io::Result<T>,
    ) -> io::Result<T> {
        let (offset, length) = motor_fs_region(raw)?;
        let raw = Utf8Path::from_path(raw).unwrap();
        tokio::runtime::LocalRuntime::new()?.block_on(async {
            let device = AsyncFileBlockDevice::open_region(raw, offset, length).await?;
            let mut fs = motor_fs::MotorFs::open(Box::new(device)).await?;
            operation(&mut fs).await
        })
    }

    fn metadata(raw: &Path, path: &Path) -> io::Result<Metadata> {
        with_raw_fs(raw, async |fs| {
            let entry = resolve_path(fs, path).await?;
            fs.metadata(Role::System, entry).await
        })
    }

    fn write_file(raw: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
        with_raw_fs(raw, async |fs| {
            let entry = resolve_path(fs, path).await?;
            fs.write(Role::System, entry, 0, bytes).await?;
            fs.flush().await
        })
    }

    fn read_file(raw: &Path, path: &Path) -> io::Result<Vec<u8>> {
        with_raw_fs(raw, async |fs| {
            let entry = resolve_path(fs, path).await?;
            let size = fs.metadata(Role::System, entry).await?.size as usize;
            let mut bytes = vec![0; size];
            fs.read(Role::System, entry, 0, &mut bytes).await?;
            Ok(bytes)
        })
    }

    fn create_child(raw: &Path, directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
        with_raw_fs(raw, async |fs| {
            let parent = resolve_path(fs, directory).await?;
            let child = fs
                .create_entry(
                    Role::System,
                    parent,
                    EntryKind::File,
                    name,
                    RolePermissions::all(AccessPermissions::Rw),
                )
                .await?;
            fs.write(Role::System, child, 0, bytes).await?;
            fs.flush().await
        })
    }

    #[test]
    fn edits_raw_image_permissions_and_sealed_entries() {
        let fixture = Fixture::create();
        let raw = &fixture.raw;
        for mode in ["rwxr--r--", "rwxrwxrw-", "r-xr-xr--", "rwxr-xr--"] {
            chmod_image(raw, Path::new("/file"), parse_mode(mode).unwrap()).unwrap();
            assert_eq!(
                metadata(raw, Path::new("/file"))
                    .unwrap()
                    .permissions()
                    .unwrap(),
                parse_mode(mode).unwrap()
            );
        }

        chmod_image(raw, Path::new("/file"), parse_mode("r-xr-xr--").unwrap()).unwrap();
        assert_eq!(
            write_file(raw, Path::new("/file"), b"new")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        chmod_image(raw, Path::new("/file"), parse_mode("rwxr-xr--").unwrap()).unwrap();
        write_file(raw, Path::new("/file"), b"new").unwrap();
        chmod_image(raw, Path::new("/file"), parse_mode("r-xr-xr--").unwrap()).unwrap();
        assert_eq!(read_file(raw, Path::new("/file")).unwrap(), b"new");
        assert_eq!(
            metadata(raw, Path::new("/file"))
                .unwrap()
                .permissions()
                .unwrap(),
            parse_mode("r-xr-xr--").unwrap()
        );

        assert_eq!(
            create_child(raw, Path::new("/locked"), "added", b"content")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        chmod_image(raw, Path::new("/locked"), parse_mode("rwxr-xr--").unwrap()).unwrap();
        create_child(raw, Path::new("/locked"), "added", b"content").unwrap();
        chmod_image(raw, Path::new("/locked"), parse_mode("r-xr-xr--").unwrap()).unwrap();
        assert_eq!(
            read_file(raw, Path::new("/locked/added")).unwrap(),
            b"content"
        );
        assert_eq!(
            metadata(raw, Path::new("/locked"))
                .unwrap()
                .permissions()
                .unwrap(),
            parse_mode("r-xr-xr--").unwrap()
        );

        let denied = chmod_image(
            raw,
            Path::new("/denied/child"),
            parse_mode("rwxr-xr--").unwrap(),
        )
        .unwrap_err();
        assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn edits_qcow2_and_preserves_it_on_failure() {
        let fixture = Fixture::create();
        let qcow2 = fixture.qcow2();
        let expected = parse_mode("r-xr--r--").unwrap();
        chmod_image(&qcow2, Path::new("/file"), expected).unwrap();

        let reopened = fixture.root.join("reopened.raw");
        super::super::convert_qcow2_to_raw(&qcow2, &reopened).unwrap();
        assert_eq!(
            metadata(&reopened, Path::new("/file"))
                .unwrap()
                .permissions()
                .unwrap(),
            expected
        );

        let original = fs::read(&qcow2).unwrap();
        assert_eq!(
            chmod_image(&qcow2, Path::new("/missing"), expected)
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
        assert_eq!(fs::read(&qcow2).unwrap(), original);
    }
}
