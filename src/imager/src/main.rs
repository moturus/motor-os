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
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::{collections::BTreeMap, fs, path::Path};

use mbrman::BOOT_ACTIVE;
use std::io::{self, Seek, SeekFrom};

mod util;

const SECTOR_SIZE: u32 = 512;

#[derive(Debug, Deserialize)]
struct Config {
    input_files: Vec<String>,
    static_dirs: Vec<String>,
    filesystem: String,
    data_partition_size_mb: u64,
}

fn create_srfs_partition(
    result_path: &Path,
    files: &BTreeMap<PathBuf, String>,
    data_partition_size_mb: u64,
) {
    let data_partition_size = data_partition_size_mb * 1024 * 1024;
    srfs::FileSystem::create_volume(result_path, data_partition_size / srfs::BLOCK_SIZE as u64)
        .unwrap();

    let mut filesystem = srfs::FileSystem::open_volume(result_path).unwrap();

    for (src, dst) in files {
        let target_path = Path::new(dst);
        // Create parent directories.
        let parent = target_path.parent().unwrap().to_str().unwrap();
        if !filesystem.exists(parent.into()).unwrap() {
            filesystem.create_dir_all(parent.into()).unwrap();
        }

        let mut new_file = filesystem.create_file(dst.as_str().into()).unwrap();

        let source_file = File::open(src).unwrap();
        let mut buf_reader = BufReader::new(source_file);

        let mut buf = [0_u8; 512];
        while let Ok(sz) = buf_reader.read(&mut buf) {
            if sz == 0 {
                break;
            }
            new_file
                .write(&buf[0..sz])
                .expect("Failed to add a file to img.");
        }
    }
}

async fn create_motorfs_partition_async(
    result_path: &Path,
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

    for (src, dst) in files {
        let target_path = Path::new(dst);
        let parent = target_path.parent().unwrap();
        let filename = target_path.file_name().unwrap().to_str().unwrap();

        let parent_id = util::_motor_fs_create_dir_all(&mut fs, parent)
            .await
            .unwrap();
        let new_file_id = fs
            .create_entry(parent_id, srfs::EntryKind::File, filename)
            .await
            .unwrap();

        let source_file = File::open(src).unwrap();
        println!(
            "creating file {dst} of size {}",
            source_file.metadata().unwrap().len()
        );

        let mut buf_reader = BufReader::new(source_file);

        let mut buf = [0_u8; 4096];
        let mut offset = 0;
        while let Ok(sz) = buf_reader.read(&mut buf) {
            if sz == 0 {
                break;
            }

            assert_eq!(sz, fs.write(new_file_id, offset, &buf[..sz]).await.unwrap());
            offset += sz as u64;
        }
    }
}

fn create_motorfs_partition(
    result_path: &Path,
    files: &BTreeMap<PathBuf, String>,
    data_partition_size_mb: u64,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(create_motorfs_partition_async(
        result_path,
        files,
        data_partition_size_mb,
    ));
}

fn create_flatfs_partition(result: &Path, files: &BTreeMap<PathBuf, String>) {
    let mut writer = flatfs::Writer::new();

    for (src, dst) in files {
        let mut source_file = File::open(src).unwrap();
        let mut bytes: Vec<u8> = Vec::new();
        source_file.read_to_end(&mut bytes).unwrap();
        writer.add(dst, &bytes);
    }

    let o_bytes = writer.pack();
    let mut o_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(result)
        .unwrap();
    o_file.write_all(&o_bytes).unwrap();
    o_file.flush().unwrap();
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
            Some("flatfs") => flatfs::PARTITION_ID,
            Some("srfs") => srfs::PARTITION_ID,
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

fn add_static_dir(files: &mut BTreeMap<PathBuf, String>, dir_to_add: PathBuf, dest_path: &Path) {
    assert!(dir_to_add.is_dir());

    for entry in dir_to_add
        .read_dir()
        .unwrap_or_else(|_| panic!("Error reading dir {dir_to_add:?}"))
        .flatten()
    {
        let key = entry.path();
        let value = dest_path.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            // Recurse.
            add_static_dir(files, key, value.as_path());
        } else if entry.file_type().unwrap().is_file() {
            files.insert(key, value.as_os_str().to_str().unwrap().to_owned());
        }
    }
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

    let mut files: BTreeMap<PathBuf, String> = BTreeMap::new();

    for prog in &config.input_files {
        let filename = Path::new(prog).file_name().unwrap();
        files.insert(bin_dir.join(filename), (*prog).clone());
    }

    for dir in &config.static_dirs {
        add_static_dir(&mut files, motorh.join(dir), Path::new("/"));
    }

    let fs_partition = tmp_img_dir.join("fs_part");
    match config.filesystem.as_str() {
        "srfs" => create_srfs_partition(&fs_partition, &files, config.data_partition_size_mb),
        "motor-fs" => {
            create_motorfs_partition(&fs_partition, &files, config.data_partition_size_mb)
        }
        "flatfs" => create_flatfs_partition(&fs_partition, &files),
        _ => panic!("Unknown filesystem: {}", config.filesystem),
    }

    create_mbr_disk(
        &bin_dir.join("mbr.bin"),
        &bin_dir.join("boot.bin"),
        &initrd,
        &fs_partition,
        Some(&config.filesystem),
        &img_dir.join(
            format!(
                "motor.{}.img",
                config_path.file_stem().unwrap().to_str().unwrap()
            )
            .as_str(),
        ),
    );

    println!("Motor OS {deb_rel} image built successfully in {img_dir:?}");
}
