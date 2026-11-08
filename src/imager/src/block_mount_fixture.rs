//! Builds and edits test disk images; fixture creation preserves its input image.
use camino::Utf8Path;
use moto_sdk::async_fs::file_block_device::AsyncFileBlockDevice;
use moto_sdk::async_fs::{AccessPermissions, EntryKind, FileSystem, Role, RolePermissions};
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;

type Fs = motor_fs::MotorFs<AsyncFileBlockDevice>;
const DATA_BLOCKS: u64 = 16384;

fn invalid(message: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}

fn utf8(path: &Path) -> io::Result<&Utf8Path> {
    Utf8Path::from_path(path).ok_or_else(|| invalid("fixture path is not UTF-8"))
}

fn mbr(file: &mut File) -> io::Result<mbrman::MBR> {
    file.seek(SeekFrom::Start(0))?;
    mbrman::MBR::read_from(file, 512).map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
}

fn root_region(path: &Path) -> io::Result<(u64, u64)> {
    let mut file = File::open(path)?;
    let mut header = [0; 8];
    file.read_exact(&mut header)?;
    if motor_fs::has_superblock_magic(&header) {
        Ok((0, file.metadata()?.len()))
    } else {
        let mbr = mbr(&mut file)?;
        let (_, entry) = mbr
            .iter()
            .find(|(_, entry)| entry.sys == motor_fs::PARTITION_ID)
            .ok_or_else(|| invalid("no root filesystem"))?;
        Ok((
            u64::from(entry.starting_lba) * 512,
            u64::from(entry.sectors) * 512,
        ))
    }
}

async fn open_root(path: &Path) -> io::Result<Fs> {
    let (offset, length) = root_region(path)?;
    let device = AsyncFileBlockDevice::open_region(utf8(path)?, offset, length).await?;
    Fs::open(Box::new(device)).await
}

async fn data_fs(path: &Path, label: &[u8]) -> io::Result<()> {
    let device = AsyncFileBlockDevice::create(utf8(path)?, DATA_BLOCKS).await?;
    let mut fs = Fs::format(Box::new(device)).await?;
    // The mounted root keeps this mode, irrespective of its shadowed directory.
    let mode = RolePermissions::new(
        AccessPermissions::Rwx,
        AccessPermissions::Rwx,
        AccessPermissions::Rx,
    );
    fs.set_all_permissions_image_admin(Role::System, 0, mode)
        .await?;
    fs.create_entry(Role::System, 0, EntryKind::Directory, "nested", mode)
        .await?;
    let file = fs
        .create_entry(Role::System, 0, EntryKind::File, "label", mode)
        .await?;
    fs.write(Role::System, file, 0, label).await?;
    fs.flush().await
}

fn append_partition(root: &Path, data: &Path) -> io::Result<()> {
    let mut disk = OpenOptions::new().read(true).write(true).open(root)?;
    let mut table = mbr(&mut disk)?;
    if table[3].sys != motor_fs::PARTITION_ID || !table[4].is_unused() {
        return Err(invalid("fixture needs root in slot 3 and an unused slot 4"));
    }
    let length = disk.metadata()?.len();
    if length % 512 != 0 {
        return Err(invalid("unaligned source image"));
    }
    let data_length = fs::metadata(data)?.len();
    let lba = u32::try_from(length / 512).map_err(|_| invalid("image too large"))?;
    let sectors = u32::try_from(data_length / 512).map_err(|_| invalid("data too large"))?;
    lba.checked_add(sectors)
        .ok_or_else(|| invalid("extent overflow"))?;
    table[4] = mbrman::MBRPartitionEntry {
        boot: mbrman::BOOT_INACTIVE,
        first_chs: mbrman::CHS::empty(),
        sys: motor_fs::PARTITION_ID,
        last_chs: mbrman::CHS::empty(),
        starting_lba: lba,
        sectors,
    };
    disk.seek(SeekFrom::Start(length))?;
    io::copy(&mut File::open(data)?, &mut disk)?;
    disk.seek(SeekFrom::Start(0))?;
    table.write_into(&mut disk).map_err(io::Error::other)?;
    disk.sync_all()
}

async fn write_config(root: &Path, path: &str, config: &[u8]) -> io::Result<()> {
    let mut fs = open_root(root).await?;
    let file = crate::chmod::resolve_path(&fs, Path::new(path)).await?;
    fs.resize(Role::System, file, 0).await?;
    for (index, bytes) in config.chunks(4096).enumerate() {
        fs.write(Role::System, file, (index * 4096) as u64, bytes)
            .await?;
    }
    fs.flush().await
}

fn partitioned(data: &Path, output: &Path) -> io::Result<()> {
    use std::io::Write;
    let mut disk = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(output)?;
    let length = fs::metadata(data)?.len();
    disk.set_len(512 + length)?;
    let mut table =
        mbrman::MBR::new_from(&mut disk, 512, [5, 6, 7, 8]).map_err(io::Error::other)?;
    table[1] = mbrman::MBRPartitionEntry {
        boot: mbrman::BOOT_INACTIVE,
        first_chs: mbrman::CHS::empty(),
        sys: motor_fs::PARTITION_ID,
        last_chs: mbrman::CHS::empty(),
        starting_lba: 1,
        sectors: u32::try_from(length / 512).map_err(|_| invalid("data too large"))?,
    };
    table.write_into(&mut disk).map_err(io::Error::other)?;
    disk.seek(SeekFrom::Start(512))?;
    io::copy(&mut File::open(data)?, &mut disk)?;
    disk.flush()
}

fn extract_root(image: &Path, output: &Path) -> io::Result<()> {
    let (offset, length) = root_region(image)?;
    let mut input = File::open(image)?;
    input.seek(SeekFrom::Start(offset))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)?;
    if io::copy(&mut input.take(length), &mut output)? != length {
        return Err(ErrorKind::UnexpectedEof.into());
    }
    output.sync_all()
}

async fn dirty(image: &Path) -> io::Result<()> {
    use std::io::Write;
    let (offset, _) = root_region(image)?;
    let mut disk = OpenOptions::new().read(true).write(true).open(image)?;
    disk.seek(SeekFrom::Start(offset))?;
    let mut previous = [0; 8192];
    disk.read_exact(&mut previous)?;
    let mut fs = open_root(image).await?;
    fs.create_entry(
        Role::System,
        0,
        EntryKind::Directory,
        "recovery-probe",
        RolePermissions::all(AccessPermissions::Rwx),
    )
    .await?;
    fs.flush().await?;
    drop(fs);
    // A committed journal with an old main superblock/root models an interrupted
    // checkpoint. Never touch the journal itself or fabricate its contents.
    disk.seek(SeekFrom::Start(offset))?;
    disk.write_all(&previous)?;
    disk.sync_all()
}

async fn check_recovery(image: &Path) -> io::Result<()> {
    let (offset, length) = root_region(image)?;
    let device = AsyncFileBlockDevice::open_region(utf8(image)?, offset, length).await?;
    let fs = Fs::open_with_recovery_policy(
        Box::new(device),
        256,
        motor_fs::RecoveryPolicy::RequireClean,
    )
    .await?;
    if fs.stat(Role::System, 0, "recovery-probe").await?.is_none() {
        return Err(invalid("recovery probe is missing"));
    }
    Ok(())
}

fn corrupt(image: &Path, kind: &str) -> io::Result<()> {
    use std::io::Write;
    let mut file = OpenOptions::new().read(true).write(true).open(image)?;
    let length = file.metadata()?.len();
    let mut put = |offset, bytes: &[u8]| -> io::Result<()> {
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)
    };
    match kind {
        "magic" | "version" | "count" => {
            let (offset, size) = root_region(image)?;
            let (field, value) = match kind {
                "magic" => (0, 0),
                "version" => (8, 2),
                _ => (16, size / 4096 + 1),
            };
            put(offset + field, &value.to_le_bytes())?;
        }
        "mbr-signature" => put(510, &[0; 2])?,
        "mbr-start" => put(454, &[0; 4])?,
        "mbr-length" => put(458, &[0; 4])?,
        "mbr-outside" => put(458, &u32::MAX.to_le_bytes())?,
        "mbr-unaligned" => put(458, &127u32.to_le_bytes())?,
        "mbr-type" => put(450, &[0x83])?,
        "mbr-empty" => put(446, &[0; 16])?,
        "mbr-overlap" => {
            put(466, &[0x83])?;
            put(470, &1u32.to_le_bytes())?;
            put(474, &8u32.to_le_bytes())?;
        }
        "short" => file.set_len(64 * 4096)?,
        "unaligned" => file.set_len(length + 512)?,
        "resized" => file.set_len(length + 4096)?,
        _ => return Err(invalid("unknown fixture corruption")),
    }
    file.sync_all()
}

pub fn run(args: &[String]) -> io::Result<()> {
    let runtime = tokio::runtime::LocalRuntime::new()?;
    match args {
        [operation, source, directory] if operation == "create" => {
            let directory = Path::new(directory);
            fs::create_dir(directory)?;
            let root = directory.join("root.img");
            let data = directory.join("rootp4.fs");
            fs::copy(source, &root)?;
            runtime.block_on(async {
                data_fs(&data, b"virtio0p4\n").await?;
                data_fs(&directory.join("parted.fs"), b"virtio1p1\n").await?;
                data_fs(&directory.join("bare.img"), b"virtio2\n").await?;
                let mut fs = open_root(&root).await?;
                let user = crate::chmod::resolve_path(&fs, Path::new("/user")).await?;
                let mode = RolePermissions::all(AccessPermissions::Rwx);
                fs.create_entry(Role::System, user, EntryKind::Directory, "data", mode)
                    .await?;
                fs.create_entry(Role::System, user, EntryKind::Directory, "bare", mode)
                    .await?;
                fs.flush().await
            })?;
            partitioned(&directory.join("parted.fs"), &directory.join("parted.img"))?;
            fs::write(directory.join("unused.img"), [0; 4096])?;
            append_partition(&root, &data)
        }
        [operation, image, config] if matches!(operation.as_str(), "config" | "net-config") => {
            let path = if operation == "config" {
                "/system/cfg/sys-fs.toml"
            } else {
                "/system/cfg/sys-net.toml"
            };
            runtime.block_on(write_config(Path::new(image), path, &fs::read(config)?))
        }
        [operation, image, output] if operation == "extract-root" => {
            extract_root(Path::new(image), Path::new(output))
        }
        [operation, image, kind] if operation == "corrupt" => corrupt(Path::new(image), kind),
        [operation, image] if operation == "dirty" => runtime.block_on(dirty(Path::new(image))),
        [operation, image] if operation == "check-recovery" => {
            runtime.block_on(check_recovery(Path::new(image)))
        }
        _ => Err(invalid(
            "usage: block-mount-fixture create ROOT_RAW NEW_DIR | config IMAGE TOML | net-config IMAGE TOML | extract-root IMAGE OUTPUT | corrupt IMAGE KIND | dirty IMAGE | check-recovery IMAGE",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn partition_fixture_and_config() {
        let dir = std::env::temp_dir().join(format!(
            "motor-block-fixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let source = dir.join("source.img");
        let partition = dir.join("root.fs");
        let output = dir.join("output");
        let runtime = tokio::runtime::LocalRuntime::new().unwrap();
        runtime
            .block_on(async {
                data_fs(&partition, b"root\n").await?;
                let mut root = open_root(&partition).await?;
                let mode = RolePermissions::all(AccessPermissions::Rwx);
                root.create_entry(Role::System, 0, EntryKind::Directory, "user", mode)
                    .await?;
                let system = root
                    .create_entry(Role::System, 0, EntryKind::Directory, "system", mode)
                    .await?;
                let cfg = root
                    .create_entry(Role::System, system, EntryKind::Directory, "cfg", mode)
                    .await?;
                root.create_entry(Role::System, cfg, EntryKind::File, "sys-fs.toml", mode)
                    .await?;
                root.flush().await
            })
            .unwrap();
        let mut disk = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source)
            .unwrap();
        disk.set_len(512 + DATA_BLOCKS * 4096).unwrap();
        let mut table = mbrman::MBR::new_from(&mut disk, 512, [1, 2, 3, 4]).unwrap();
        table[3] = mbrman::MBRPartitionEntry {
            boot: mbrman::BOOT_INACTIVE,
            first_chs: mbrman::CHS::empty(),
            sys: motor_fs::PARTITION_ID,
            last_chs: mbrman::CHS::empty(),
            starting_lba: 1,
            sectors: (DATA_BLOCKS * 8) as u32,
        };
        table.write_into(&mut disk).unwrap();
        disk.seek(SeekFrom::Start(512)).unwrap();
        disk.write_all(&fs::read(&partition).unwrap()).unwrap();
        drop(disk);
        let before = fs::read(&source).unwrap();
        run(&[
            "create".into(),
            source.to_str().unwrap().into(),
            output.to_str().unwrap().into(),
        ])
        .unwrap();
        assert_eq!(fs::read(&source).unwrap(), before);
        let result = output.join("root.img");
        let mut disk = File::open(&result).unwrap();
        let table = mbr(&mut disk).unwrap();
        assert_eq!(table[3].starting_lba, 1);
        assert_eq!(table[4].starting_lba, (before.len() / 512) as u32);
        assert_eq!(table[4].sectors, (DATA_BLOCKS * 8) as u32);
        assert_eq!(&fs::read(&result).unwrap()[..494], &before[..494]);
        let text = b"[[mount]]\npath='/user/data'\ntype='motor-fs'\ndevice=0\npartition=4\n";
        runtime
            .block_on(async {
                write_config(&result, "/system/cfg/sys-fs.toml", text).await?;
                let root = open_root(&result).await?;
                let cfg =
                    crate::chmod::resolve_path(&root, Path::new("/system/cfg/sys-fs.toml")).await?;
                let mut bytes = [0; 256];
                let count = root.read(Role::System, cfg, 0, &mut bytes).await?;
                assert_eq!(&bytes[..count], text);
                let device = AsyncFileBlockDevice::open_region(
                    utf8(&result)?,
                    u64::from(table[4].starting_lba) * 512,
                    DATA_BLOCKS * 4096,
                )
                .await?;
                let data = Fs::open(Box::new(device)).await?;
                let (label, _) = data.stat(Role::None, 0, "label").await?.unwrap();
                let count = data.read(Role::None, label, 0, &mut bytes).await?;
                assert_eq!(&bytes[..count], b"virtio0p4\n");
                assert_eq!(
                    data.metadata(Role::None, 0).await?.permissions()?.none,
                    AccessPermissions::Rx
                );
                Ok::<(), io::Error>(())
            })
            .unwrap();
        assert!(append_partition(&result, &partition).is_err());
        let bare_root = output.join("bare-root.img");
        extract_root(&result, &bare_root).unwrap();
        assert_eq!(fs::metadata(&bare_root).unwrap().len(), DATA_BLOCKS * 4096);
        for image in [
            &result,
            &bare_root,
            &output.join("parted.img"),
            &output.join("bare.img"),
        ] {
            runtime
                .block_on(async {
                    dirty(image).await?;
                    assert_eq!(
                        check_recovery(image).await.unwrap_err().kind(),
                        ErrorKind::InvalidData
                    );
                    let fs = open_root(image).await?;
                    assert!(fs.replayed_txn_log_on_open());
                    drop(fs);
                    check_recovery(image).await
                })
                .unwrap();
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
