//! `mkfs` creates a bare Motor FS image; `mkdir` and `put` add entries to an image.
use crate::chmod::{self, TemporaryImage};
use crate::permissions::{self, ImageEntryKind, PermissionPolicy};
use crate::set::image::{staged_update, with_fs, Fs};
use camino::Utf8Path;
use moto_sdk::async_fs::file_block_device::AsyncFileBlockDevice;
use moto_sdk::async_fs::{
    AccessPermissions, EntryId, EntryKind, FileSystem, Role, RolePermissions,
};
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::path::Path;

const MKFS_USAGE: &str = "usage: imager mkfs --size X[M|G] [--mode MODE] OUTPUT_IMG";
const MKDIR_USAGE: &str = "usage: imager mkdir [--mode MODE] VM_IMAGE DIR_PATH";
const PUT_USAGE: &str = "usage: imager put [--mode MODE] VM_IMAGE HOST_FILE FILE_PATH";

/// A data filesystem's root, like `/user`: Interactive may write, None may read.
const MKFS_MODE: RolePermissions = RolePermissions::new(
    AccessPermissions::Rwx,
    AccessPermissions::Rwx,
    AccessPermissions::Rx,
);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

#[derive(Debug, Default)]
struct Args {
    mode: Option<RolePermissions>,
    size_mb: Option<u64>,
    positional: Vec<String>,
}

fn parse(args: &[String], usage: &str, allow_size: bool) -> io::Result<Args> {
    let mut parsed = Args::default();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if !arg.starts_with("--") {
            parsed.positional.push(arg.clone());
            continue;
        }
        let value = args
            .next()
            .ok_or_else(|| invalid(format!("'{arg}' requires a value\n{usage}")))?;
        let duplicate = match arg.as_str() {
            "--mode" => {
                let mode = chmod::parse_mode(value)
                    .ok_or_else(|| invalid(format!("invalid mode '{value}'")))?;
                parsed.mode.replace(mode).is_some()
            }
            "--size" if allow_size => {
                let size = crate::resize::parse_size_mb(value).ok_or_else(|| {
                    invalid(format!(
                        "invalid size '{value}': expected a positive number followed by M or G"
                    ))
                })?;
                parsed.size_mb.replace(size).is_some()
            }
            _ => return Err(invalid(format!("unknown option '{arg}'\n{usage}"))),
        };
        if duplicate {
            return Err(invalid(format!("duplicate '{arg}'")));
        }
    }
    Ok(parsed)
}

/// An explicit mode obeys the same rules as the image permission policy.
fn checked_mode(kind: ImageEntryKind, mode: RolePermissions) -> io::Result<RolePermissions> {
    permissions::validate_entry_mode(kind, mode).map_err(|reason| {
        invalid(format!(
            "mode '{}': {reason}",
            permissions::mode_string(mode)
        ))
    })?;
    Ok(mode)
}

fn policy() -> io::Result<PermissionPolicy> {
    PermissionPolicy::builtin().map_err(io::Error::other)
}

/// Splits a normalized absolute guest path other than `/` into parent and name.
fn guest_path(value: &str) -> io::Result<(&Path, &str)> {
    if value == "/" || !permissions::normalized_absolute_path(value) {
        return Err(invalid(format!(
            "guest path '{value}' must be normalized, absolute and not '/'"
        )));
    }
    let (parent, name) = value.rsplit_once('/').unwrap();
    Ok((
        Path::new(if parent.is_empty() { "/" } else { parent }),
        name,
    ))
}

async fn parent_dir(fs: &Fs, parent: &Path) -> io::Result<EntryId> {
    let missing = || {
        io::Error::new(
            ErrorKind::NotFound,
            format!("guest directory '{}' does not exist", parent.display()),
        )
    };
    let id = chmod::resolve_path(fs, parent)
        .await
        .map_err(|error| match error.kind() {
            ErrorKind::NotFound => missing(),
            _ => error,
        })?;
    if fs.metadata(Role::System, id).await?.try_kind()? != EntryKind::Directory {
        return Err(missing());
    }
    Ok(id)
}

pub(crate) fn mkfs(args: &[String]) -> io::Result<()> {
    let args = parse(args, MKFS_USAGE, true)?;
    let ([output], Some(size_mb)) = (args.positional.as_slice(), args.size_mb) else {
        return Err(invalid(MKFS_USAGE));
    };
    let output = Path::new(output);
    let mode = match args.mode {
        Some(mode) => checked_mode(ImageEntryKind::Directory, mode)?,
        None => MKFS_MODE,
    };
    let qcow2 = crate::resize::output_is_qcow2(output)?;
    let bytes = size_mb
        .checked_mul(1 << 20)
        .ok_or_else(|| invalid("size is too large"))?;
    if fs::symlink_metadata(output).is_ok() {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            format!("'{}' already exists", output.display()),
        ));
    }

    let raw = if qcow2 {
        TemporaryImage::create_in(&std::env::temp_dir(), output, "raw")?
    } else {
        TemporaryImage::create_next_to(output, "raw")?
    };
    OpenOptions::new()
        .write(true)
        .open(raw.path())?
        .set_len(bytes)?;
    let path = Utf8Path::from_path(raw.path()).ok_or_else(|| invalid("path must be UTF-8"))?;
    tokio::runtime::LocalRuntime::new()?.block_on(async {
        let device = AsyncFileBlockDevice::open(path).await?;
        let mut fs = Fs::format(Box::new(device)).await?;
        fs.set_all_permissions_image_admin(Role::System, motor_fs::ROOT_DIR_ID, mode)
            .await?;
        fs.flush().await
    })?;
    let result = if qcow2 {
        let result = TemporaryImage::create_next_to(output, "qcow2")?;
        crate::convert_raw_to_qcow2(raw.path(), result.path())?;
        result
    } else {
        raw
    };
    File::open(result.path())?.sync_all()?;
    // A hard link never replaces an output created in the meantime.
    fs::hard_link(result.path(), output)
}

pub(crate) fn mkdir(args: &[String]) -> io::Result<()> {
    let args = parse(args, MKDIR_USAGE, false)?;
    let [image, path] = args.positional.as_slice() else {
        return Err(invalid(MKDIR_USAGE));
    };
    let (parent, name) = guest_path(path)?;
    let mode = match args.mode {
        Some(mode) => checked_mode(ImageEntryKind::Directory, mode)?,
        None => policy()?.directory_permissions(Path::new(path)),
    };
    permissions::validate_path_mode(Path::new(path), mode).map_err(invalid)?;
    staged_update(Path::new(image), |raw| {
        with_fs(raw, async |fs| {
            let parent = parent_dir(fs, parent).await?;
            if fs.stat(Role::System, parent, name).await?.is_some() {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!("'{path}' already exists"),
                ));
            }
            fs.create_entry(Role::System, parent, EntryKind::Directory, name, mode)
                .await?;
            fs.flush().await
        })
    })
}

pub(crate) fn put(args: &[String]) -> io::Result<()> {
    let args = parse(args, PUT_USAGE, false)?;
    let [image, source, path] = args.positional.as_slice() else {
        return Err(invalid(PUT_USAGE));
    };
    let (parent, _) = guest_path(path)?;
    let mut file = File::open(source)?;
    if !file.metadata()?.is_file() {
        return Err(invalid(format!("'{source}' is not a regular file")));
    }
    let class = permissions::classify_source(Path::new(source)).map_err(invalid)?;
    let mode = match args.mode {
        Some(mode) => checked_mode(ImageEntryKind::File(class), mode)?,
        None => policy()?.file_permissions(Path::new(path), class),
    };
    permissions::validate_path_mode(Path::new(path), mode).map_err(invalid)?;
    staged_update(Path::new(image), |raw| {
        with_fs(raw, async |fs| {
            parent_dir(fs, parent).await?;
            crate::publish_www::write_file(fs, Path::new(path), mode, &mut file).await?;
            fs.flush().await
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    #[test]
    fn offline_edits_cannot_grant_none_write_in_protected_trees() {
        let temporary = TempDir::new();
        let image = temporary.path("image.raw");
        mkfs(&strings(&["--size", "1M", &image])).unwrap();
        let source = temporary.path("data");
        fs::write(&source, b"data").unwrap();
        for tree in ["/system", "/user"] {
            mkdir(&strings(&[&image, tree])).unwrap();
            let original = fs::read(&image).unwrap();
            let path = format!("{tree}/new");
            assert!(mkdir(&strings(&["--mode", "rwxrwxrwx", &image, &path])).is_err());
            assert!(put(&strings(&["--mode", "rw-rw-rw-", &image, &source, &path])).is_err());
            assert!(chmod::chmod_image(
                Path::new(&image),
                Path::new(tree),
                RolePermissions::all(AccessPermissions::Rwx)
            )
            .is_err());
            assert_eq!(fs::read(&image).unwrap(), original);
        }
        // A None workspace still accepts the same modes.
        mkdir(&strings(&["--mode", "rwxrwxrwx", &image, "/none"])).unwrap();
        put(&strings(&[
            "--mode",
            "rw-rw-rw-",
            &image,
            &source,
            "/none/data",
        ]))
        .unwrap();
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("motor-imager-edit-{}-{nanos}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> String {
            self.0.join(name).to_str().unwrap().to_owned()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    fn mode(value: &str) -> RolePermissions {
        chmod::parse_mode(value).unwrap()
    }

    /// Reads a guest entry back: its kind, mode and, for files, contents.
    fn entry(image: &str, path: &str) -> io::Result<(EntryKind, RolePermissions, Vec<u8>)> {
        let raw = if chmod::is_qcow2(Path::new(image))? {
            let raw = format!("{image}.check.raw");
            let _ = fs::remove_file(&raw);
            crate::convert_qcow2_to_raw(Path::new(image), Path::new(&raw))?;
            raw
        } else {
            image.to_owned()
        };
        with_fs(Path::new(&raw), async |fs| {
            let id = chmod::resolve_path(fs, Path::new(path)).await?;
            let metadata = fs.metadata(Role::System, id).await?;
            let kind = metadata.try_kind()?;
            let size = if kind == EntryKind::File {
                metadata.size
            } else {
                0
            };
            let mut bytes = vec![0; size as usize];
            let mut offset = 0;
            while offset < bytes.len() {
                offset += fs
                    .read(
                        Role::System,
                        id,
                        offset as u64,
                        &mut bytes[offset..(offset + 4096).min(size as usize)],
                    )
                    .await?;
            }
            Ok((kind, metadata.permissions()?, bytes))
        })
    }

    #[test]
    fn arguments_are_checked() {
        let error = |args: &[&str], run: fn(&[String]) -> io::Result<()>| {
            run(&strings(args)).unwrap_err().to_string()
        };
        assert!(error(&["out.img"], mkfs).contains("usage"));
        assert!(error(&["--size", "1M", "a.img", "b.img"], mkfs).contains("usage"));
        assert!(error(&["--size", "1K", "a.img"], mkfs).contains("invalid size"));
        assert!(error(&["--size", "1M", "--size", "2M", "a.img"], mkfs).contains("duplicate"));
        assert!(error(&["--size", "1M", "a.vmdk"], mkfs).contains("suffix"));
        assert!(error(&["--size", "1M", "a.img"], mkdir).contains("unknown option"));
        assert!(error(&["--mode", "rwxrwxrwz", "a.img", "/x"], mkdir).contains("invalid mode"));
        assert!(error(&["--mode"], put).contains("requires a value"));
        assert!(error(&["a.img", "/x"], put).contains("usage"));
        for path in ["/", "x", "/x/", "/x//y", "/x/../y"] {
            assert!(error(&["a.img", path], mkdir).contains("normalized"));
        }
        // Directories need System rwx, as in the image permission policy.
        assert!(
            error(&["--size", "1M", "--mode", "r-xr-xr-x", "a.img"], mkfs).contains("System rwx")
        );
    }

    #[test]
    fn mkfs_creates_bare_images_and_never_replaces_files() {
        let dir = TempDir::new();
        let raw = dir.path("data.img");
        mkfs(&strings(&["--size", "1M", &raw])).unwrap();
        assert_eq!(fs::metadata(&raw).unwrap().len(), 1 << 20);
        assert!(chmod::is_bare_motor_fs(Path::new(&raw)).unwrap());
        assert_eq!(
            entry(&raw, "/").unwrap(),
            (EntryKind::Directory, mode("rwxrwxr-x"), Vec::new())
        );

        let error = mkfs(&strings(&["--size", "2M", &raw])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        assert_eq!(fs::metadata(&raw).unwrap().len(), 1 << 20);

        let qcow2 = dir.path("data.qcow2");
        mkfs(&strings(&["--mode", "rwxr-xr-x", "--size", "1G", &qcow2])).unwrap();
        assert!(chmod::is_qcow2(Path::new(&qcow2)).unwrap());
        // The qcow2 image stays sparse.
        assert!(fs::metadata(&qcow2).unwrap().len() < 4 << 20);
        assert_eq!(entry(&qcow2, "/").unwrap().1, mode("rwxr-xr-x"));
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 3); // No temporaries left.
    }

    #[test]
    fn mkdir_and_put_edit_bare_images() {
        let dir = TempDir::new();
        let image = dir.path("data.qcow2");
        mkfs(&strings(&["--size", "1M", &image])).unwrap();
        mkdir(&strings(&[&image, "/user"])).unwrap();
        mkdir(&strings(&["--mode", "rwx------", &image, "/user/private"])).unwrap();
        assert_eq!(entry(&image, "/user").unwrap().1, mode("rwxrwxr-x"));
        assert_eq!(entry(&image, "/user/private").unwrap().1, mode("rwx------"));
        let error = mkdir(&strings(&[&image, "/user"])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        let error = mkdir(&strings(&[&image, "/missing/dir"])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);

        let source = dir.path("source");
        let long: Vec<u8> = (0..10_000).map(|index| index as u8).collect();
        fs::write(&source, &long).unwrap();
        put(&strings(&[&image, &source, "/user/file"])).unwrap();
        assert_eq!(
            entry(&image, "/user/file").unwrap(),
            (EntryKind::File, mode("rw-rw-r--"), long)
        );
        // A replacement takes the new contents and the policy (or explicit) mode.
        fs::write(&source, b"short").unwrap();
        put(&strings(&[
            "--mode",
            "rw-------",
            &image,
            &source,
            "/user/file",
        ]))
        .unwrap();
        assert_eq!(
            entry(&image, "/user/file").unwrap(),
            (EntryKind::File, mode("rw-------"), b"short".to_vec())
        );
        let error = put(&strings(&[&image, &source, "/user/private/x/y"])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        let error = put(&strings(&[&image, &source, "/user/file/y"])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert!(put(&strings(&[&image, &source, "/user/private"])).is_err());
        assert!(put(&strings(&[&image, &dir.path(""), "/user/x"])).is_err());

        // A script stays a script; an executable mode on a regular file is refused.
        fs::write(&source, b"#!/user/bin/rush\n").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        put(&strings(&[&image, &source, "/user/script"])).unwrap();
        assert_eq!(entry(&image, "/user/script").unwrap().1, mode("rwxrwxr-x"));
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        let error = put(&strings(&[
            "--mode",
            "rwxr-xr-x",
            &image,
            &source,
            "/user/x",
        ]));
        assert!(error.unwrap_err().to_string().contains("execute"));

        // chmod handles bare images too.
        chmod::chmod_image(Path::new(&image), Path::new("/"), mode("rwxr-xr-x")).unwrap();
        assert_eq!(entry(&image, "/").unwrap().1, mode("rwxr-xr-x"));
    }

    #[test]
    fn edits_keep_raw_images_sparse() {
        use std::os::unix::fs::MetadataExt;
        let dir = TempDir::new();
        let image = dir.path("data.img");
        mkfs(&strings(&["--size", "256M", &image])).unwrap();
        mkdir(&strings(&[&image, "/dir"])).unwrap();
        assert_eq!(fs::metadata(&image).unwrap().len(), 256 << 20);
        assert!(fs::metadata(&image).unwrap().blocks() * 512 < 4 << 20);
    }

    #[test]
    fn put_edits_partitioned_images() {
        let dir = TempDir::new();
        let partition = dir.path("partition.img");
        mkfs(&strings(&["--size", "1M", &partition])).unwrap();
        mkdir(&strings(&[&partition, "/system"])).unwrap();
        mkdir(&strings(&[&partition, "/system/cfg"])).unwrap();

        let image = dir.path("disk.img");
        let mut disk = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&image)
            .unwrap();
        let sectors = (1 << 20) / 512;
        disk.set_len(512 * (1 + sectors)).unwrap();
        let mut mbr = mbrman::MBR::new_from(&mut disk, 512, [1, 2, 3, 4]).unwrap();
        mbr[3] = mbrman::MBRPartitionEntry {
            boot: mbrman::BOOT_INACTIVE,
            first_chs: mbrman::CHS::empty(),
            sys: motor_fs::PARTITION_ID,
            last_chs: mbrman::CHS::empty(),
            starting_lba: 1,
            sectors: sectors as u32,
        };
        mbr.write_into(&mut disk).unwrap();
        disk.seek(SeekFrom::Start(512)).unwrap();
        disk.write_all(&fs::read(&partition).unwrap()).unwrap();
        drop(disk);

        let source = dir.path("sys-fs.toml");
        fs::write(&source, b"[[mount]]\n").unwrap();
        put(&strings(&[&image, &source, "/system/cfg/sys-fs.toml"])).unwrap();
        mkdir(&strings(&[&image, "/system/logs"])).unwrap();
        assert_eq!(
            entry(&image, "/system/cfg/sys-fs.toml").unwrap(),
            (EntryKind::File, mode("rw-r--r--"), b"[[mount]]\n".to_vec())
        );
        assert_eq!(entry(&image, "/system/logs").unwrap().1, mode("rwxr-x---"));
    }
}
