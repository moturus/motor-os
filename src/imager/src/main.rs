// Motor OS image builder.
//
// Image: MBR
// 0 - mbr: master boot record: loads the second stage from [boot]
// 1 - boot: loads [initrd] at 1M adress, jumps into 1M + 512
// 2 - initrd
//     - the first 512 bytes: header, config
//     - kloader: initializes 64-bit, CPUs, loads the kernel in himem
//     - kernel: does what the kernels do, loads sys-io
//     - sys-io: FS, NET drivers in the userspace
// 3 - data: filesystem accessible to the userspace

use serde::Deserialize;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, PathBuf};
use std::process::Command;
use std::{collections::BTreeMap, fs, path::Path};

use mbrman::BOOT_ACTIVE;
use std::io::{self, Seek, SeekFrom};

mod util;

const SECTOR_SIZE: u32 = 512;

const SOURCE_TREE_EXCLUDED_DIRS: [&str; 4] = [".git", ".lorry", "__pycache__", "target"];

fn image_file_permissions(source: &Path) -> io::Result<async_fs::RolePermissions> {
    let executable = fs::metadata(source)?.permissions().mode() & 0o111 != 0;
    let access = if executable {
        async_fs::AccessPermissions::Rwx
    } else {
        async_fs::AccessPermissions::Rw
    };
    Ok(async_fs::RolePermissions::all(access))
}

#[derive(Debug, Deserialize)]
struct SourceDirectory {
    source: String,
    destination: String,
}

#[derive(Debug, Deserialize)]
struct Config {
    input_files: Vec<String>,
    directories: Vec<String>,
    static_dirs: Vec<String>,
    #[serde(default)]
    required_executables: Vec<String>,
    #[serde(default)]
    source_dirs: Vec<SourceDirectory>,
    filesystem: String,
    data_partition_size_mb: u64,
    img_name: String,
    image_format: ImageFormat,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ImageFormat {
    Raw,
    Qcow2,
}

async fn create_motorfs_partition_async(
    result_path: &Path,
    directories: &[String],
    files: &BTreeMap<PathBuf, String>,
    data_partition_size_mb: u64,
) {
    use async_fs::FileSystem;

    let data_partition_size = data_partition_size_mb * 1024 * 1024;

    let bd = async_fs::file_block_device::AsyncFileBlockDevice::create(
        result_path.to_str().unwrap().into(),
        data_partition_size / 4096,
    )
    .await
    .unwrap();
    let mut fs = motor_fs::MotorFs::format(Box::new(bd)).await.unwrap();
    println!("creating Motor FS in {:?}", result_path);

    for directory in directories {
        util::motor_fs_create_dir_all(&mut fs, Path::new(directory))
            .await
            .unwrap();
    }

    for (src, dst) in files {
        let target_path = Path::new(dst);
        let parent = target_path.parent().unwrap();
        let filename = target_path.file_name().unwrap().to_str().unwrap();
        let permissions = image_file_permissions(src)
            .unwrap_or_else(|err| panic!("Error reading permissions for file '{src:?}': {err:?}."));

        let parent_id = util::motor_fs_create_dir_all(&mut fs, parent)
            .await
            .unwrap();
        let new_file_id = fs
            .create_entry(
                async_fs::Role::System,
                parent_id,
                async_fs::EntryKind::File,
                filename,
                permissions,
            )
            .await
            .unwrap();

        let bytes = std::fs::read(src)
            .map_err(|err| panic!("Error reading file '{src:?}': {err:?}."))
            .unwrap();
        let hash = util::fnv1a_hash_64(bytes.as_slice());
        println!(
            "creating file {dst} of size {} and hash 0x{hash:x}.",
            bytes.len()
        );

        let mut buf_reader = BufReader::new(std::io::Cursor::new(bytes));

        let mut buf = [0_u8; 4096];
        let mut offset = 0;
        while let Ok(sz) = buf_reader.read(&mut buf) {
            if sz == 0 {
                break;
            }

            assert_eq!(
                sz,
                fs.write(async_fs::Role::System, new_file_id, offset, &buf[..sz])
                    .await
                    .unwrap()
            );
            offset += sz as u64;
        }
    }

    fs.flush().await.unwrap();
}

fn create_motorfs_partition(
    result_path: &Path,
    directories: &[String],
    files: &BTreeMap<PathBuf, String>,
    data_partition_size_mb: u64,
) {
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(create_motorfs_partition_async(
        result_path,
        directories,
        files,
        data_partition_size_mb,
    ));
}

#[repr(C)]
#[derive(Debug)]
struct InitrdHeader {
    magic: u32,
    kloader_start: u32,
    kloader_end: u32,
    kernel_start: u32,
    kernel_end: u32,
    sys_io_start: u32,
    sys_io_end: u32,
}

impl InitrdHeader {
    const MAGIC: u32 = 0xf402_100f; // Whatever.
}

fn create_initrd(result: &Path, kloader: &Path, kernel: &Path, sys_io: &Path) {
    // Open files.
    let mut f_kloader = File::open(kloader).unwrap();
    let mut f_kernel = File::open(kernel).unwrap();
    let mut f_sys_io = File::open(sys_io).unwrap();
    let mut initrd = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(result)
        .unwrap();

    // Prepare the header.
    let mut initrd_header = [0_u64; 512 / 8];

    let header = unsafe {
        (initrd_header.as_mut_ptr() as usize as *mut InitrdHeader)
            .as_mut()
            .unwrap()
    };

    header.magic = InitrdHeader::MAGIC;
    header.kloader_start = 512;
    header.kloader_end = header.kloader_start + f_kloader.metadata().unwrap().len() as u32;

    // Align kernel at 512 bytes.
    header.kernel_start = (header.kloader_end + 511) & !511;
    header.kernel_end = header.kernel_start + f_kernel.metadata().unwrap().len() as u32;

    // Align sys-io at 4K.
    header.sys_io_start = (header.kernel_end + 4095) & !4095;
    header.sys_io_end = header.sys_io_start + f_sys_io.metadata().unwrap().len() as u32;

    // Write the header.
    let header_bytes =
        unsafe { core::slice::from_raw_parts(initrd_header.as_ptr() as *const u8, 512) };
    initrd.write_all(header_bytes).unwrap();
    initrd.flush().unwrap();
    assert_eq!(
        header.kloader_start,
        initrd.stream_position().unwrap() as u32
    );

    // Write kloader.
    io::copy(&mut f_kloader, &mut initrd).unwrap();
    initrd.flush().unwrap();
    assert_eq!(header.kloader_end, initrd.stream_position().unwrap() as u32);

    // Add padding.
    for _ in 0..(header.kernel_start - header.kloader_end) {
        initrd.write_all(&[0_u8; 1]).unwrap();
    }

    // Write the kernel.
    assert_eq!(
        header.kernel_start,
        initrd.stream_position().unwrap() as u32
    );
    io::copy(&mut f_kernel, &mut initrd).unwrap();
    initrd.flush().unwrap();
    assert_eq!(header.kernel_end, initrd.stream_position().unwrap() as u32);

    // Add padding.
    for _ in 0..(header.sys_io_start - header.kernel_end) {
        initrd.write_all(&[0_u8; 1]).unwrap();
    }

    // Write sys-io.
    assert_eq!(
        header.sys_io_start,
        initrd.stream_position().unwrap() as u32
    );
    io::copy(&mut f_sys_io, &mut initrd).unwrap();
    initrd.flush().unwrap();
    assert_eq!(header.sys_io_end, initrd.stream_position().unwrap() as u32);
}

fn set_partition(
    mbr: &mut mbrman::MBR,
    idx: usize,
    partition: &Path,
    start_sector: u32,
    fs: Option<&str>,
) -> u32 {
    let data = File::open(partition).unwrap();
    let size = data.metadata().unwrap().len();
    let sectors = size.div_ceil(u64::from(SECTOR_SIZE)).try_into().unwrap();

    mbr[idx] = mbrman::MBRPartitionEntry {
        boot: BOOT_ACTIVE,
        starting_lba: start_sector,
        sectors,
        sys: match fs {
            Some("fat32") => 0xc,
            Some("motor-fs") => motor_fs::PARTITION_ID,
            Some(fs) => panic!("unknown partition '{fs}'"),
            None => 0x20,
        },
        first_chs: mbrman::CHS::empty(),
        last_chs: mbrman::CHS::empty(),
    };

    sectors
}

fn write_partition(mbr: &mbrman::MBR, idx: usize, partition: &Path, disk: &mut File) {
    disk.seek(SeekFrom::Start(
        (mbr[idx].starting_lba * SECTOR_SIZE).into(),
    ))
    .unwrap();
    let mut data = File::open(partition).unwrap();
    let written = io::copy(&mut data, disk).unwrap() as u32;

    // We need to pad to SECTOR_SIZE.
    let tail = (SECTOR_SIZE - (written % SECTOR_SIZE)) % SECTOR_SIZE;
    for _ in 0..tail {
        assert_eq!(1, disk.write(&[0]).unwrap());
    }
}

fn create_mbr_disk(
    mbr: &Path,
    part1: &Path,
    part2: &Path,
    part3: &Path,
    part3_fs: Option<&str>,
    result: &Path,
) {
    let mut boot_sector = File::open(mbr).unwrap();
    let mut mbr = mbrman::MBR::read_from(&mut boot_sector, SECTOR_SIZE).unwrap();

    for (index, partition) in mbr.iter() {
        if !partition.is_unused() {
            panic!("partition {index} should be unused");
        }
    }

    let mut current_sector = 1_u32;
    current_sector += set_partition(&mut mbr, 1, part1, current_sector, None);
    current_sector += set_partition(&mut mbr, 2, part2, current_sector, None);
    set_partition(&mut mbr, 3, part3, current_sector, part3_fs);

    let mut disk = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(result)
        .unwrap();

    mbr.write_into(&mut disk).unwrap();

    write_partition(&mbr, 1, part1, &mut disk);
    write_partition(&mbr, 2, part2, &mut disk);
    write_partition(&mbr, 3, part3, &mut disk);
}

fn convert_raw_to_qcow2(raw: &Path, qcow2: &Path) -> io::Result<()> {
    let output = Command::new("qemu-img")
        .args(["convert", "-f", "raw", "-O", "qcow2"])
        .arg("--")
        .arg(raw)
        .arg(qcow2)
        .output()
        .map_err(|err| io::Error::new(err.kind(), format!("failed to run qemu-img: {err}")))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(io::Error::other(format!(
        "qemu-img failed with {}: {}",
        output.status,
        stderr.trim()
    )))
}

fn add_dir(
    files: &mut BTreeMap<PathBuf, String>,
    dir_to_add: PathBuf,
    dest_path: &Path,
    excluded_dirs: &[&str],
) {
    assert!(dir_to_add.is_dir());

    for entry in dir_to_add
        .read_dir()
        .unwrap_or_else(|_| panic!("Error reading dir {dir_to_add:?}"))
        .flatten()
    {
        let filename = entry.file_name();
        let key = entry.path();
        let value = dest_path.join(&filename);
        if entry.file_type().unwrap().is_dir() {
            if excluded_dirs
                .iter()
                .any(|excluded| filename == OsStr::new(excluded))
            {
                continue;
            }
            add_dir(files, key, value.as_path(), excluded_dirs);
        } else if entry.file_type().unwrap().is_file() {
            let destination = value.as_os_str().to_str().unwrap().to_owned();
            files.retain(|_, existing_destination| existing_destination != &destination);
            files.insert(key, destination);
        }
    }
}

fn add_static_dir(files: &mut BTreeMap<PathBuf, String>, dir_to_add: PathBuf, dest_path: &Path) {
    add_dir(files, dir_to_add, dest_path, &[]);
}

fn add_source_dir(files: &mut BTreeMap<PathBuf, String>, dir_to_add: PathBuf, dest_path: &Path) {
    add_dir(files, dir_to_add, dest_path, &SOURCE_TREE_EXCLUDED_DIRS);
}

fn validate_directories(directories: &[String]) -> Result<(), String> {
    for directory in directories {
        let path = Path::new(directory);
        let mut components = path.components();
        if components.next() != Some(Component::RootDir)
            || components.any(|component| !matches!(component, Component::Normal(_)))
            || (directory != "/"
                && directory[1..]
                    .split('/')
                    .any(|component| component.is_empty() || matches!(component, "." | "..")))
        {
            return Err(format!(
                "image directory '{directory}' must be a normalized absolute path"
            ));
        }
    }
    Ok(())
}

fn validate_static_dirs(motorh: &Path, static_dirs: &[String]) -> Result<(), String> {
    for directory in static_dirs {
        let path = motorh.join(directory);
        if !path.is_dir() {
            return Err(format!("static image directory {path:?} is absent"));
        }
    }
    Ok(())
}

fn print_usage_and_exit() -> ! {
    eprintln!(
        "
Motor OS image builder usage:
    imager $MOTORH debug|release <config.yaml>
"
    );
    std::process::exit(1);
}

fn clear_dir_or_exit(dir: &PathBuf) {
    if dir.exists() && !dir.is_dir() {
        eprintln!("'{dir:?}': not a directory.");
        std::process::exit(1);
    }

    if dir.exists() {
        if let Err(err) = std::fs::remove_dir_all(dir.as_path()) {
            eprintln!("Error removing '{dir:?}': {err:?}");
            std::process::exit(1);
        }
    }

    if let Err(err) = std::fs::create_dir_all(dir.as_path()) {
        eprintln!("Error creating '{dir:?}': {err:?}");
        std::process::exit(1);
    }
}

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        print_usage_and_exit();
    }

    let motorh = Path::new(args[1].as_str());
    if !motorh.is_dir() {
        eprintln!("'{}': not a directory.\n", args[1].as_str());
        print_usage_and_exit()
    }

    let deb_rel = match args[2].as_str() {
        "debug" => "debug",
        "release" => "release",
        _ => print_usage_and_exit(),
    };

    let config_path = Path::new(args[3].as_str());
    let config_file = File::open(config_path).expect("Failed to open config file");
    let config: Config = serde_yaml::from_reader(config_file).expect("Failed to parse config file");
    validate_directories(&config.directories).unwrap_or_else(|err| panic!("{err}"));
    validate_static_dirs(motorh, &config.static_dirs).unwrap_or_else(|err| panic!("{err}"));

    let bin_dir = motorh.join("build").join("bin").join(deb_rel);
    if !bin_dir.is_dir() {
        eprintln!("'{bin_dir:?}': not a directory.\n");
        print_usage_and_exit()
    }

    let img_dir = motorh.join("vm_images").join(deb_rel);

    let tmp_img_dir = motorh.join("build").join("vm_images").join(deb_rel);
    clear_dir_or_exit(&tmp_img_dir);

    let initrd = img_dir.join("initrd");
    create_initrd(
        &initrd,
        &bin_dir.join("kloader.bin"),
        &bin_dir.join("kernel"),
        &bin_dir.join("sys-io"),
    );

    std::fs::copy(bin_dir.join("kloader"), img_dir.join("kloader")).unwrap();

    let mut files: BTreeMap<PathBuf, String> = BTreeMap::new();

    for executable in &config.required_executables {
        let path = motorh.join(executable);
        let metadata = fs::metadata(&path)
            .unwrap_or_else(|err| panic!("required image executable {path:?} is absent: {err}"));
        assert!(
            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            "required image executable {path:?} is not an executable file"
        );
    }

    for prog in &config.input_files {
        let filename = Path::new(prog).file_name().unwrap();
        files.insert(bin_dir.join(filename), (*prog).clone());
    }

    for dir in &config.static_dirs {
        let path = motorh.join(dir);
        add_static_dir(&mut files, path, Path::new("/"));
    }
    for dir in &config.source_dirs {
        let path = motorh.join(&dir.source);
        assert!(path.is_dir(), "source image directory {path:?} is absent");
        let destination = Path::new(&dir.destination);
        assert!(
            destination.is_absolute(),
            "source image destination {destination:?} is not absolute"
        );
        add_source_dir(&mut files, path, destination);
    }

    let fs_partition = tmp_img_dir.join("fs_part");
    match config.filesystem.as_str() {
        "motor-fs" => create_motorfs_partition(
            &fs_partition,
            &config.directories,
            &files,
            config.data_partition_size_mb,
        ),
        _ => panic!("Unknown filesystem: {}", config.filesystem),
    }

    let result = img_dir.join(&config.img_name);
    let raw = match config.image_format {
        ImageFormat::Raw => result.clone(),
        ImageFormat::Qcow2 => tmp_img_dir.join("disk.raw"),
    };
    create_mbr_disk(
        &bin_dir.join("mbr.bin"),
        &bin_dir.join("boot.bin"),
        &initrd,
        &fs_partition,
        Some(&config.filesystem),
        &raw,
    );
    if config.image_format == ImageFormat::Qcow2 {
        let qcow2 = tmp_img_dir.join("disk.qcow2");
        convert_raw_to_qcow2(&raw, &qcow2)
            .unwrap_or_else(|err| panic!("failed to create qcow2 image {result:?}: {err}"));
        fs::rename(qcow2, &result)
            .unwrap_or_else(|err| panic!("failed to publish qcow2 image {result:?}: {err}"));
    }

    println!("Motor OS {deb_rel} image built successfully in {img_dir:?}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_files_preserve_the_host_executable_bit() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let executable = std::env::current_exe().unwrap();

        assert_eq!(
            image_file_permissions(&source).unwrap(),
            async_fs::RolePermissions::all(async_fs::AccessPermissions::Rw)
        );
        assert_eq!(
            image_file_permissions(&executable).unwrap(),
            async_fs::RolePermissions::all(async_fs::AccessPermissions::Rwx)
        );
    }

    #[test]
    fn production_image_requires_ripgrep() {
        let config: Config = serde_yaml::from_str(include_str!("../motor-os.yaml")).unwrap();

        assert_eq!(config.img_name, "motor-os.qcow2");
        assert_eq!(config.image_format, ImageFormat::Qcow2);
        assert_eq!(config.data_partition_size_mb, 256);
        assert_eq!(
            config.static_dirs,
            [
                "img_files/motor-os-base",
                "img_files/motor-os",
                "img_files/generated/libc",
                "img_files/generated/rg"
            ]
        );
        assert_eq!(
            config.required_executables,
            ["img_files/generated/rg/system/bin/rg"]
        );
        assert!(config
            .directories
            .iter()
            .any(|path| path == "/system/cfg/libc"));
        assert!(!config.directories.iter().any(|path| path == "/devtools"));
        assert!(!config
            .input_files
            .iter()
            .any(|path| path.contains("/tests/")));
        assert!(!config
            .input_files
            .iter()
            .any(|path| path == "/system/bin/curl"));
    }

    #[test]
    fn dev_image_requires_the_native_toolchain() {
        let config: Config = serde_yaml::from_str(include_str!("../motor-os-dev.yaml")).unwrap();

        assert_eq!(config.img_name, "motor-os-dev.qcow2");
        assert_eq!(config.image_format, ImageFormat::Qcow2);
        assert!(config
            .input_files
            .iter()
            .any(|path| path == "/devtools/bin/lorry"));
        assert!(config
            .input_files
            .iter()
            .any(|path| path == "/devtools/bin/gears"));
        assert!(config
            .input_files
            .iter()
            .any(|path| path == "/system/bin/curl"));
        assert_eq!(
            config.static_dirs,
            [
                "img_files/motor-os-base",
                "img_files/motor-os",
                "img_files/generated/libc",
                "img_files/generated/rg",
                "img_files/motor-os-dev",
                "img_files/generated/llvm",
                "img_files/generated/rustc"
            ]
        );
        assert_eq!(config.required_executables.len(), 6);
        assert!(config
            .required_executables
            .iter()
            .any(|path| path.ends_with("/rustc")));
        assert!(config
            .required_executables
            .iter()
            .any(|path| path.ends_with("/rg")));
        assert!(config
            .directories
            .iter()
            .any(|path| path == "/devtools/tmp"));
        assert!(config
            .directories
            .iter()
            .any(|path| path == "/devtools/tests/gears"));
        assert_eq!(config.source_dirs.len(), 5);
        for (source, destination) in [
            ("src/bin/red", "/devtools/src/src/bin/red"),
            ("src/bin/lorry", "/devtools/src/src/bin/lorry"),
            ("src/bin/gears", "/devtools/src/src/bin/gears"),
            ("src/sys/lib/moto-rt", "/devtools/src/src/sys/lib/moto-rt"),
            ("src/sys/lib/moto-sys", "/devtools/src/src/sys/lib/moto-sys"),
        ] {
            assert!(config
                .source_dirs
                .iter()
                .any(|dir| dir.source == source && dir.destination == destination));
        }
    }

    #[test]
    fn base_image_has_no_dns_or_dev_content() {
        let config: Config = serde_yaml::from_str(include_str!("../motor-os-base.yaml")).unwrap();

        assert_eq!(config.img_name, "motor-os-base.img");
        assert_eq!(config.image_format, ImageFormat::Raw);
        assert_eq!(config.data_partition_size_mb, 64);
        assert_eq!(config.static_dirs, ["img_files/motor-os-base"]);
        assert!(config
            .input_files
            .iter()
            .all(|path| !path.contains("dns-resolver") && !path.starts_with("/devtools")));
        assert!(config
            .input_files
            .iter()
            .filter(|path| path.starts_with("/system/bin/"))
            .all(|path| !path.contains("services")));
    }

    #[test]
    fn image_directories_must_be_normalized_absolute_paths() {
        assert!(validate_directories(&["/system/tmp".into()]).is_ok());
        for invalid in ["system/tmp", "/system/../user", "/system/./tmp"] {
            assert!(
                validate_directories(&[invalid.into()]).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn static_roots_are_required() {
        let missing = std::env::temp_dir().join(format!(
            "motor-imager-missing-static-test-{}",
            std::process::id()
        ));
        assert!(validate_static_dirs(&missing, &["not-there".into()]).is_err());
    }

    #[test]
    fn later_static_overlay_wins() {
        let root =
            std::env::temp_dir().join(format!("motor-imager-overlay-test-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(root.join("first/system/cfg")).unwrap();
        fs::create_dir_all(root.join("second/system/cfg")).unwrap();
        fs::write(root.join("first/system/cfg/rush.cfg"), "first\n").unwrap();
        fs::write(root.join("second/system/cfg/rush.cfg"), "second\n").unwrap();

        let mut files = BTreeMap::new();
        add_static_dir(&mut files, root.join("first"), Path::new("/"));
        add_static_dir(&mut files, root.join("second"), Path::new("/"));

        assert_eq!(files.len(), 1);
        assert_eq!(
            files.keys().next().unwrap(),
            &root.join("second/system/cfg/rush.cfg")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_directories_exclude_generated_outputs() {
        let root =
            std::env::temp_dir().join(format!("motor-imager-source-test-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("target/nested")).unwrap();
        fs::create_dir_all(root.join("bootstrap/__pycache__")).unwrap();
        fs::create_dir_all(root.join("nested/.git")).unwrap();
        fs::create_dir_all(root.join("nested/.lorry/vendor")).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\n").unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("target/nested/artifact"), "generated\n").unwrap();
        fs::write(root.join("bootstrap/__pycache__/script.pyc"), "generated\n").unwrap();
        fs::write(root.join("nested/.git/config"), "generated\n").unwrap();
        fs::write(root.join("nested/.lorry/vendor/object"), "generated\n").unwrap();

        let mut files = BTreeMap::new();
        add_source_dir(&mut files, root.clone(), Path::new("/devtools/src/example"));

        let destinations: Vec<_> = files.values().map(String::as_str).collect();
        assert_eq!(
            destinations,
            [
                "/devtools/src/example/Cargo.toml",
                "/devtools/src/example/src/main.rs"
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn converts_raw_images_to_qcow2() {
        let root =
            std::env::temp_dir().join(format!("motor-imager-qcow2-test-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(&root).unwrap();
        let raw = root.join("disk.raw");
        let qcow2 = root.join("disk.qcow2");
        fs::write(&raw, [0_u8; 4096]).unwrap();

        convert_raw_to_qcow2(&raw, &qcow2).unwrap();
        assert_eq!(&fs::read(&qcow2).unwrap()[..4], b"QFI\xfb");

        let error = convert_raw_to_qcow2(&root.join("missing.raw"), &qcow2).unwrap_err();
        assert!(error.to_string().contains("qemu-img failed"));
        fs::remove_dir_all(root).unwrap();
    }
}
