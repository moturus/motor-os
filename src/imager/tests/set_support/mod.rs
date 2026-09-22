use async_fs::file_block_device::AsyncFileBlockDevice;
use async_fs::{AccessPermissions as Access, EntryKind, FileSystem, Role, RolePermissions};
use camino::Utf8Path;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

pub const SSH: &str = "/system/cfg/sshd.toml";
pub const CERT: &str = "/system/cfg/ssl/ssl-cert.pem";
pub const KEY: &str = "/system/cfg/ssl/ssl-key.pem";
pub const CA: &str = "/system/cfg/ssl/ca-certificates.crt";
pub const OFFSET: u64 = 4096;
pub const BLOCKS: u64 = 256;
pub const BASE: &str = include_str!("../../../../img_files/motor-os-base/system/cfg/sshd.toml");
pub const DEV: &str = include_str!("../../../../img_files/motor-os-dev/system/cfg/sshd.toml");
pub const NEW_CERT: &[u8] = include_bytes!("../../../bin/httpd-axum/tests/fixtures/cert.pem");
pub const NEW_KEY: &[u8] = include_bytes!("../../../bin/httpd-axum/tests/fixtures/key.pem");

pub type Fs = motor_fs::MotorFs<AsyncFileBlockDevice>;

pub fn secret_permissions() -> RolePermissions {
    RolePermissions::new(Access::Rw, Access::R, Access::None)
}

pub fn with_fs<T>(raw: &Path, operation: impl AsyncFnOnce(&mut Fs) -> io::Result<T>) -> T {
    tokio::runtime::LocalRuntime::new()
        .unwrap()
        .block_on(async {
            let device = AsyncFileBlockDevice::open_region(
                Utf8Path::from_path(raw).unwrap(),
                OFFSET,
                BLOCKS * 4096,
            )
            .await?;
            let mut fs = Fs::open(Box::new(device)).await?;
            let result = operation(&mut fs).await?;
            fs.flush().await?;
            Ok::<_, io::Error>(result)
        })
        .unwrap()
}

pub async fn resolve(fs: &Fs, path: &str) -> io::Result<async_fs::EntryId> {
    let mut id = motor_fs::ROOT_DIR_ID;
    for name in path.split('/').filter(|name| !name.is_empty()) {
        id = fs.stat(Role::System, id, name).await?.unwrap().0;
    }
    Ok(id)
}

pub fn read(raw: &Path, path: &str) -> (Vec<u8>, RolePermissions) {
    with_fs(raw, async |fs| {
        let id = resolve(fs, path).await?;
        let metadata = fs.metadata(Role::System, id).await?;
        let mut bytes = vec![0; metadata.size as usize];
        for (index, chunk) in bytes.chunks_mut(4096).enumerate() {
            assert_eq!(
                fs.read(Role::System, id, (index * 4096) as u64, chunk)
                    .await?,
                chunk.len()
            );
        }
        Ok((bytes, metadata.permissions()?))
    })
}

pub struct Fixture {
    pub root: PathBuf,
    pub image: PathBuf,
    qcow2: bool,
}

impl Fixture {
    pub fn new(qcow2: bool, config: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "imager-set-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let partition = root.join("partition");
        tokio::runtime::LocalRuntime::new()
            .unwrap()
            .block_on(async {
                let device =
                    AsyncFileBlockDevice::create(Utf8Path::from_path(&partition).unwrap(), BLOCKS)
                        .await?;
                let mut fs = Fs::format(Box::new(device)).await?;
                let mut dirs = BTreeMap::from([(String::new(), motor_fs::ROOT_DIR_ID)]);
                for directory in ["/system", "/system/cfg", "/system/cfg/ssl"] {
                    let (parent, name) = directory.rsplit_once('/').unwrap();
                    let id = fs
                        .create_entry(
                            Role::System,
                            dirs[parent],
                            EntryKind::Directory,
                            name,
                            RolePermissions::all(Access::Rwx),
                        )
                        .await?;
                    dirs.insert(directory.into(), id);
                }
                for (path, bytes, permissions) in [
                    (SSH, config.as_bytes(), secret_permissions()),
                    (
                        CERT,
                        &b"old certificate"[..],
                        RolePermissions::all(Access::R),
                    ),
                    (KEY, &b"old private key"[..], secret_permissions()),
                    (
                        CA,
                        &b"unchanged trust store"[..],
                        RolePermissions::all(Access::R),
                    ),
                ] {
                    let (parent, name) = path.rsplit_once('/').unwrap();
                    let id = fs
                        .create_entry(
                            Role::System,
                            dirs[parent],
                            EntryKind::File,
                            name,
                            secret_permissions(),
                        )
                        .await?;
                    for (index, chunk) in bytes.chunks(4096).enumerate() {
                        assert_eq!(
                            fs.write(Role::System, id, (index * 4096) as u64, chunk)
                                .await?,
                            chunk.len()
                        );
                    }
                    fs.set_all_permissions_image_admin(Role::System, id, permissions)
                        .await?;
                }
                fs.flush().await
            })
            .unwrap();
        let raw = root.join("image with spaces.raw");
        let mut disk = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&raw)
            .unwrap();
        disk.set_len(OFFSET + BLOCKS * 4096).unwrap();
        let mut mbr = mbrman::MBR::new_from(&mut disk, 512, [1, 2, 3, 4]).unwrap();
        mbr[1] = mbrman::MBRPartitionEntry {
            boot: mbrman::BOOT_INACTIVE,
            first_chs: mbrman::CHS::empty(),
            sys: motor_fs::PARTITION_ID,
            last_chs: mbrman::CHS::empty(),
            starting_lba: (OFFSET / 512) as u32,
            sectors: (BLOCKS * 8) as u32,
        };
        mbr.write_into(&mut disk).unwrap();
        disk.seek(SeekFrom::Start(OFFSET)).unwrap();
        io::copy(&mut File::open(&partition).unwrap(), &mut disk).unwrap();
        drop(disk);
        fs::remove_file(partition).unwrap();
        let image = if qcow2 {
            let image = root.join("image with spaces.qcow2");
            convert(&raw, &image, "raw", "qcow2");
            fs::remove_file(raw).unwrap();
            image
        } else {
            raw
        };
        fs::set_permissions(&image, fs::Permissions::from_mode(0o640)).unwrap();
        Self { root, image, qcow2 }
    }

    pub fn raw(&self) -> PathBuf {
        if !self.qcow2 {
            return self.image.clone();
        }
        let raw = self.root.join("reopened.raw");
        convert(&self.image, &raw, "qcow2", "raw");
        raw
    }

    pub fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_imager"))
            .arg("set")
            .args(args)
            .arg(&self.image)
            .env("RUST_LOG", "trace")
            .output()
            .unwrap()
    }

    pub fn succeeds(&self, args: &[&str]) {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.no_temporaries();
    }

    pub fn fails_unchanged(&self, args: &[&str]) -> Output {
        let original = fs::read(&self.image).unwrap();
        let output = self.run(args);
        assert!(!output.status.success());
        assert_eq!(fs::read(&self.image).unwrap(), original);
        self.no_temporaries();
        output
    }

    pub fn no_temporaries(&self) {
        for entry in fs::read_dir(&self.root).unwrap() {
            assert!(!entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .contains(".tmp-"));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn convert(input: &Path, output: &Path, from: &str, to: &str) {
    let result = Command::new("qemu-img")
        .args(["convert", "-f", from, "-O", to])
        .arg(input)
        .arg(output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

pub const LOGIN_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPqBJXmK6lCHMhdaldFapWRqrkugRx4pgTOtD2J4R6yB imager fixture";
pub const HOST_KEY: &str = include_str!("../../../tests/test.key");
