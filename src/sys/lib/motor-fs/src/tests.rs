use async_fs::EntryId;
use async_fs::EntryKind;
use async_fs::FileSystem;
use camino::Utf8PathBuf;
use std::io::ErrorKind;
use std::io::Result;
use std::sync::Once;
use std::time::SystemTime;

use crate::MotorFs;
use crate::RESERVED_BLOCKS;

static LOGGER: Once = Once::new();
fn init_logger() {
    LOGGER.call_once(|| {
        env_logger::init();
    });
}

async fn create_fs(tag: &str, num_blocks: u64) -> Result<MotorFs> {
    let path = std::env::temp_dir().join(tag);
    let path = Utf8PathBuf::from_path_buf(path).unwrap();
    std::fs::remove_file(path.clone()).ok();

    let bd = async_fs::file_block_device::AsyncFileBlockDevice::create(&path, num_blocks).await?;
    MotorFs::format(Box::new(bd)).await
}

async fn open_fs(tag: &str) -> Result<MotorFs> {
    let path = std::env::temp_dir().join(tag);
    let path = Utf8PathBuf::from_path_buf(path).unwrap();

    let bd = async_fs::file_block_device::AsyncFileBlockDevice::open(&path).await?;
    MotorFs::open(Box::new(bd)).await
}

#[test]
fn basic() {
    init_logger();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(basic_test()).unwrap();
}

#[test]
fn readdir() {
    init_logger();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(readdir_test()).unwrap();
}

#[test]
fn midsize_file() {
    init_logger();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(midsize_file_test()).unwrap();
}

#[test]
fn delete_reopen() {
    init_logger();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(delete_reopen_test()).unwrap();
}

async fn basic_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 256;

    let ts_format = SystemTime::now();
    let mut fs = create_fs("motor_fs_basic_test", NUM_BLOCKS).await?;

    assert_eq!(NUM_BLOCKS, fs.num_blocks());
    assert_eq!(NUM_BLOCKS - RESERVED_BLOCKS, fs.empty_blocks().await?);

    let root = crate::ROOT_DIR_ID;
    assert!(fs.get_parent(root).await?.is_none());

    assert!(ts_format <= fs.metadata(root).await?.created.into());
    assert!(ts_format <= fs.metadata(root).await?.modified.into());

    assert_eq!(0, fs.metadata(root).await?.size);
    assert!(fs.stat(root, "first").await?.is_none());

    let ts_first_dir = SystemTime::now();

    let first = fs
        .create_entry(root, async_fs::EntryKind::Directory, "first")
        .await?;
    assert_eq!(1, fs.metadata(root).await?.size);
    assert_eq!(0, fs.metadata(first).await?.size);
    assert_eq!(root, fs.get_parent(first).await?.unwrap());

    assert_eq!(
        fs.create_entry(first, async_fs::EntryKind::Directory, "/")
            .await
            .err()
            .unwrap()
            .kind(),
        ErrorKind::InvalidFilename
    );

    assert_eq!(
        (first, EntryKind::Directory),
        fs.stat(root, "first").await?.unwrap()
    );

    // Check timestamps.
    let root_metadata = fs.metadata(root).await?;
    let first_metadata = fs.metadata(first).await?;
    let ts_now = SystemTime::now();

    assert_eq!(root_metadata.kind(), EntryKind::Directory);
    assert_eq!(first_metadata.kind(), EntryKind::Directory);

    assert!(ts_format <= root_metadata.created.into());
    assert!(ts_format <= root_metadata.modified.into());

    assert!(ts_first_dir >= root_metadata.created.into());
    assert!(ts_first_dir <= root_metadata.modified.into());

    assert!(ts_first_dir <= first_metadata.created.into());
    assert!(ts_first_dir <= first_metadata.modified.into());

    assert!(ts_now >= root_metadata.modified.into());
    assert!(ts_now >= first_metadata.created.into());
    assert!(ts_now >= first_metadata.modified.into());

    fs.delete_entry(first).await.unwrap();
    assert_eq!(
        ErrorKind::InvalidInput,
        fs.delete_entry(first).await.err().unwrap().kind()
    );
    assert_eq!(
        ErrorKind::InvalidInput,
        fs.delete_entry(root).await.err().unwrap().kind()
    );

    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS
    );
    let root_metadata = fs.metadata(root).await?;
    assert!(ts_now <= root_metadata.modified.into());

    let dir1 = fs.create_entry(root, EntryKind::Directory, "dir1").await?;
    let dir2 = fs.create_entry(root, EntryKind::Directory, "dir2").await?;
    let dir3 = fs.create_entry(root, EntryKind::Directory, "dir3").await?;
    assert_eq!(3, fs.metadata(root).await?.size);

    let dir22 = fs.create_entry(dir2, EntryKind::Directory, "dir22").await?;
    assert_eq!(dir2, fs.get_parent(dir22).await?.unwrap());

    // File.
    let file = fs.create_entry(dir2, EntryKind::File, "file").await?;
    assert_eq!(dir2, fs.get_parent(file).await?.unwrap());
    assert_eq!(2, fs.metadata(dir2).await?.size);

    const BYTES: &[u8] = "once upon a time there was a tree upon a hill".as_bytes();
    assert_eq!(BYTES.len(), fs.write(file, 0, BYTES).await.unwrap());
    assert_eq!(BYTES.len() as u64, fs.metadata(file).await?.size);

    let mut buf = [0_u8; 256];
    assert_eq!(BYTES.len(), fs.read(file, 0, &mut buf).await.unwrap());
    for idx in 0..BYTES.len() {
        assert_eq!(BYTES[idx], buf[idx]);
    }

    // Truncate.
    fs.resize(file, 3).await.unwrap();
    assert_eq!(3, fs.read(file, 0, &mut buf).await.unwrap());
    for idx in 0..3 {
        assert_eq!(BYTES[idx], buf[idx]);
    }

    fs.resize(file, 0).await.unwrap();
    assert_eq!(0, fs.read(file, 0, &mut buf).await.unwrap());

    // Resize up: populate with zeroes.
    fs.resize(file, BYTES.len() as u64).await.unwrap();
    assert_eq!(BYTES.len(), fs.read(file, 0, &mut buf).await.unwrap());
    for idx in 0..BYTES.len() {
        assert_eq!(0, buf[idx]);
    }

    // Move.
    assert_eq!("dir22", fs.name(dir22).await?);
    fs.move_entry(dir22, dir2, "dir22_new").await?;
    assert_eq!("dir22_new", fs.name(dir22).await?);
    fs.move_entry(dir22, root, "dir22").await?;
    assert_eq!("dir22", fs.name(dir22).await?);
    assert_eq!(4, fs.metadata(root).await.unwrap().size);
    assert_eq!(root, fs.get_parent(dir22).await?.unwrap());

    // Add some bytes to the file before deleting it, so that it uses
    // more than one block.
    assert_eq!(BYTES.len(), fs.write(file, 0, BYTES).await.unwrap());
    assert_eq!(
        BYTES.len(),
        fs.write(file, BYTES.len() as u64, BYTES).await.unwrap()
    );

    // Clear out.
    fs.delete_entry(file).await.unwrap();
    fs.delete_entry(dir1).await.unwrap();
    fs.delete_entry(dir2).await.unwrap();
    fs.delete_entry(dir3).await.unwrap();
    fs.delete_entry(dir22).await.unwrap();
    assert_eq!(0, fs.metadata(root).await.unwrap().size);
    assert_eq!(NUM_BLOCKS - RESERVED_BLOCKS, fs.empty_blocks().await?);

    println!("basic_test PASS");
    Ok(())
}

async fn readdir_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 256;

    let mut fs = create_fs("motor_fs_readdir_test", NUM_BLOCKS).await?;

    let root = crate::ROOT_DIR_ID;
    let parent_id = fs
        .create_entry(root, EntryKind::Directory, "parent")
        .await
        .unwrap();

    let mut entries = std::collections::HashMap::<EntryId, (EntryKind, String)>::new();

    // Insert some dirs and files, while keeping track of them in entries.
    for idx in 0..23 {
        let name = format!("dir_{idx}");
        entries.insert(
            fs.create_entry(parent_id, EntryKind::Directory, name.as_str())
                .await
                .unwrap(),
            (EntryKind::Directory, name),
        );
    }
    for idx in 0..44 {
        let name = format!("file_{idx}");
        entries.insert(
            fs.create_entry(parent_id, EntryKind::File, name.as_str())
                .await
                .unwrap(),
            (EntryKind::File, name),
        );
    }

    // Now "readdir" parent.
    let mut entry_id = fs.get_first_entry(parent_id).await.unwrap().unwrap();
    loop {
        let stored_data = entries.remove(&entry_id).unwrap();
        let metadata = fs.metadata(entry_id).await.unwrap();
        assert_eq!(stored_data.0, metadata.kind());
        assert_eq!(stored_data.1, fs.name(entry_id).await.unwrap());

        if let Some(next_entry_id) = fs.get_next_entry(entry_id).await.unwrap() {
            entry_id = next_entry_id;
        } else {
            break;
        };
    }

    println!("readdir_test PASS");
    Ok(())
}

/// Create a ~9MB file on a 16MB partition. Should easily fit.
async fn midsize_file_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 16 / 4096;

    let mut fs = create_fs("motor_fs_midsize_file_test", NUM_BLOCKS).await?;

    let root = crate::ROOT_DIR_ID;
    let parent_id = fs
        .create_entry(root, EntryKind::Directory, "parent dir")
        .await
        .unwrap();

    let mut bytes = vec![0_u8; 1024 * 1024 * 9 + 1001];
    for byte in &mut bytes {
        *byte = std::random::random(..);
    }

    let file_id = fs
        .create_entry(parent_id, EntryKind::File, "foo")
        .await
        .unwrap();

    // Write.
    let mut file_offset = 0;
    while file_offset < bytes.len() {
        let len = 4096.min(bytes.len() - file_offset);
        let buf = &bytes.as_slice()[file_offset..(file_offset + len)];

        let written = fs.write(file_id, file_offset as u64, buf).await.unwrap();
        assert_eq!(written, len);
        file_offset += written;
    }

    // Read.
    let mut bytes_back = vec![];
    bytes_back.resize(bytes.len(), 0);

    let mut offset = 0;

    while offset < bytes.len() {
        let len = 4096.min(bytes.len() - offset);
        let buf = &mut bytes_back.as_mut_slice()[offset..(offset + len)];

        let read = fs.read(file_id, offset as u64, buf).await.unwrap();
        assert_eq!(read, len);

        offset += read;
    }

    assert_eq!(
        crate::shuffle::fnv1a_hash_64(bytes.as_slice()),
        crate::shuffle::fnv1a_hash_64(bytes_back.as_slice())
    );

    println!("midsize_file_test PASS");
    Ok(())
}

/// Create a ~9MB file on a 16MB partition. Should easily fit.
async fn delete_reopen_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 16 / 4096;
    const FS_TAG: &str = "motor_fs_delete_reopen_test";
    let mut fs = create_fs(FS_TAG, NUM_BLOCKS).await?;

    let root = crate::ROOT_DIR_ID;

    let foo_id = fs.create_entry(root, EntryKind::File, "foo").await.unwrap();
    fs.write(foo_id, 0, b"foobar").await.unwrap();
    assert_eq!(
        fs.stat(root, "foo").await.unwrap().unwrap(),
        (foo_id, EntryKind::File)
    );

    let bar_id = fs.create_entry(root, EntryKind::File, "bar").await.unwrap();
    fs.write(bar_id, 0, b"foobarbaz").await.unwrap();
    assert_eq!(
        fs.stat(root, "bar").await.unwrap().unwrap(),
        (bar_id, EntryKind::File)
    );

    fs.flush().await?;

    let mut fs = open_fs(FS_TAG).await?;
    assert_eq!(
        fs.stat(root, "foo").await.unwrap().unwrap(),
        (foo_id, EntryKind::File)
    );
    assert_eq!(
        fs.stat(root, "bar").await.unwrap().unwrap(),
        (bar_id, EntryKind::File)
    );

    fs.delete_entry(foo_id).await.unwrap();

    let baz_id = fs.create_entry(root, EntryKind::File, "baz").await.unwrap();
    fs.write(baz_id, 0, b"baz").await.unwrap();
    assert_eq!(
        fs.stat(root, "baz").await.unwrap().unwrap(),
        (baz_id, EntryKind::File)
    );

    fs.delete_entry(bar_id).await.unwrap();
    assert!(fs.stat(root, "foo").await.unwrap().is_none());
    assert!(fs.stat(root, "bar").await.unwrap().is_none());

    fs.flush().await?;

    let mut fs = open_fs(FS_TAG).await?;
    assert!(fs.stat(root, "foo").await.unwrap().is_none());
    assert!(fs.stat(root, "bar").await.unwrap().is_none());
    fs.delete_entry(baz_id).await.unwrap();
    assert!(fs.delete_entry(baz_id).await.is_err());

    assert_eq!(0, fs.metadata(root).await.unwrap().size);
    assert_eq!(NUM_BLOCKS - RESERVED_BLOCKS, fs.empty_blocks().await?);

    println!("delete_reopen_test PASS");
    Ok(())
}

/*
#[test]
#[ignore]
fn many_dirs() {
    env_logger::init();
    let rt = tokio::runtime::Builder::new_current_thread()
        // .thread_stack_size(1024 * 1024 * 256)
        .build()
        .unwrap();

    rt.block_on(many_dirs_test()).unwrap();
}

async fn many_dirs_test() -> Result<()> {
    const DIRS_TO_CREATE: u64 = 15_000; // crate::MAX_DIR_ENTRIES;
    const NUM_BLOCKS: u64 = 2 * crate::MAX_DIR_ENTRIES;
    let path = std::env::temp_dir().join("async_fs_dev_many_dirs");
    std::fs::remove_file(path.clone()).ok();
    let path = Utf8PathBuf::from_path_buf(path).unwrap();

    let mut rng = rand::thread_rng();

    let bd = async_fs::file_block_device::AsyncFileBlockDevice::create(&path, NUM_BLOCKS).await?;
    let _ = crate::fs_async::SrFs::format(bd).await.unwrap();
    let bd = async_fs::file_block_device::AsyncFileBlockDevice::open(&path).await?;
    let mut fs = crate::fs_async::SrFs::open_fs(bd).await.unwrap();
    assert_eq!(NUM_BLOCKS - 2, fs.empty_blocks().await.unwrap());

    let root = SyncFileSystem::root_dir_id();
    let dir = fs
        .create_entry(root, async_fs::EntryKind::Directory, "dir")
        .await
        .unwrap();

    println!("adding {DIRS_TO_CREATE} child dirs");
    let mut start = Instant::now();
    for idx in 0..DIRS_TO_CREATE {
        if idx % 1000 == 0 {
            let now = Instant::now();
            println!(
                "Creating dir_{idx}; elapsed: {}ms.",
                (now - start).as_millis()
            );
            start = now;
            // Flush to tickle out dirty blocks.
            fs.flush().await.unwrap();
        }
        let name = format!("dir_{idx}");
        let result = fs
            .create_entry(dir, async_fs::EntryKind::Directory, name.as_str())
            .await;

        if let Err(err) = result {
            panic!("add_directory failed at idx {} with {:?}", idx, err);
        }

        // TODO: Uncomment the lines below. They are commented out temporarily to only measure create_entry().
        /*
        let id = result.unwrap();
        let result = fs.stat(dir, name.as_str()).await;
        if let Err(err) = result {
            panic!(
                "get_directory_entry_by_name failed at idx {} with {:?}",
                idx, err
            );
        }
        let result = result.unwrap();

        assert_eq!(
            id,
            result,
            "id: {id:?} result: {result:?} idx: {idx} name: {name} result name: {}",
            fs.name(result).await.unwrap()
        );
        assert_eq!(
            name,
            fs.name(result).await.unwrap(),
            "idx: {idx} name: {name}",
        );
        */
    }
    // Flush to tickle out dirty blocks.
    fs.flush().await.unwrap();
    println!("Finished adding {DIRS_TO_CREATE} dirs.");

    let dir2 = fs
        .create_entry(root, async_fs::EntryKind::Directory, "dir2")
        .await
        .unwrap();

    if DIRS_TO_CREATE == crate::MAX_DIR_ENTRIES {
        assert_eq!(
            fs.create_entry(dir, async_fs::EntryKind::Directory, "foo")
                .await
                .err()
                .unwrap()
                .kind(),
            ErrorKind::FileTooLarge
        ); // Cannot add more than the limit.
    }

    // Flush to tickle out dirty blocks.
    fs.flush().await.unwrap();
    assert_eq!(DIRS_TO_CREATE, fs.size(dir).await.unwrap() as u64);

    println!("Validating dirs.");
    start = Instant::now();
    for idx in 0..DIRS_TO_CREATE {
        if idx % 1000 == 0 {
            let now = Instant::now();
            println!(
                "Validating dir_{idx}; elapsed: {}ms.",
                (now - start).as_millis()
            );
            start = now;
        }
        let entry = fs.get_entry_by_pos(dir, idx as usize).await.unwrap();
        assert_eq!(fs.name(entry).await.unwrap(), format!("dir_{idx}"));
    }

    // Flush to tickle out dirty blocks.
    fs.flush().await.unwrap();

    println!("Moving dir 12345");
    let entry = fs.get_entry_by_pos(dir, 12345).await.unwrap();
    assert_eq!(fs.name(entry).await.unwrap(), "dir_12345");
    println!("Moving dir 12345 100");
    fs.delete_entry(entry).await.unwrap();
    println!("Moving dir 12345 200");
    assert_eq!(
        fs.delete_entry(entry).await.err().unwrap().kind(),
        ErrorKind::InvalidData
    );
    println!("Moving dir 12345 300");
    let entry = fs.get_entry_by_pos(dir, 12345).await.unwrap();
    assert_eq!(
        fs.name(entry).await.unwrap(),
        format!("dir_{}", DIRS_TO_CREATE - 1)
    ); // When an entry is removed, the last one is put into its place.
    println!("Moving dir 12345 400");
    assert_eq!(DIRS_TO_CREATE - 1, fs.size(dir).await.unwrap() as u64);

    // Flush to tickle out dirty blocks.
    fs.flush().await.unwrap();

    // Move some children.
    println!("Moving dirs dir: {:?} dir2: {:?}.", dir, dir2);
    let idxs = [
        DIRS_TO_CREATE - 5,
        0,
        12,
        18,
        7000,
        7860,
        7740,
        7740,
        7741,
        7860,
        7861,
        7862,
    ];

    for idx in idxs {
        assert_eq!(0, fs.size(dir2).await.unwrap());
        assert_eq!(DIRS_TO_CREATE - 1, fs.size(dir).await.unwrap() as u64);
        let name1 = format!("dir_{}", idx);
        let name2 = format!("dir2_{}", idx);
        let e = fs.stat(dir, name1.as_str()).await.unwrap();
        fs.move_rename(e, dir2, name2.as_str()).await.unwrap();
        let e2 = fs.stat(dir2, name2.as_str()).await.unwrap();
        assert_eq!(e, e2);
        assert_eq!(1, fs.size(dir2).await.unwrap());
        assert_eq!(DIRS_TO_CREATE - 2, fs.size(dir).await.unwrap() as u64);
        let e3 = fs.stat(dir, name1.as_str()).await;
        if let Ok(e3) = e3 {
            panic!(
                "Something went wrong:\n\te1: {:?}\n\te2: {:?}\n\te3: {:?}",
                e, e2, e3
            );
        }
        fs.move_rename(e, dir, name1.as_str()).await.unwrap();
    }

    println!("Removing dirs.");
    let mut num_entries = DIRS_TO_CREATE - 1;
    start = Instant::now();
    for _idx in 0..(DIRS_TO_CREATE - 1) {
        if _idx % 1000 == 0 {
            let now = Instant::now();
            println!(
                "Deleting dir no {_idx}; elapsed: {}ms.",
                (now - start).as_millis()
            );
            start = now;
            // Flush to tickle out dirty blocks.
            fs.flush().await.unwrap();
        }
        let idx: u64 = rng.next_u64() % num_entries;
        let entry = fs.get_entry_by_pos(dir, idx as usize).await.unwrap();
        fs.delete_entry(entry).await.expect(
            format!("remove() failed for entry {entry:?} in dir {dir:?} at idx {idx} ({_idx})")
                .as_str(),
        );
        num_entries -= 1;
        assert_eq!(num_entries, fs.size(dir).await.unwrap());
    }
    assert_eq!(0, num_entries);
    assert_eq!(0, fs.size(dir).await.unwrap());

    // Flush to tickle out dirty blocks.
    fs.flush().await.unwrap();

    fs.delete_entry(dir).await.unwrap();
    let dir2 = fs.stat(root, "dir2").await.unwrap();
    fs.delete_entry(dir2).await.unwrap();
    assert_eq!(NUM_BLOCKS - 2, fs.empty_blocks().await.unwrap());

    // Flush to tickle out dirty blocks.
    fs.flush().await.unwrap();

    drop(fs);
    std::fs::remove_file(path.clone())
}

#[test]
#[ignore]
fn large_file() {
    const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 3;
    // const MAX_FILE_SIZE: u64 = 1024 * 1024 * 3;
    const NUM_BLOCKS: u64 = 2 * (MAX_FILE_SIZE / (BLOCK_SIZE as u64)) + 20;
    let path = std::env::temp_dir().join("fs_dev_large_file");
    std::fs::remove_file(path.clone()).ok();

    let mut bd = Box::new(FileBlockDevice::create(&path, NUM_BLOCKS).unwrap());
    crate::fs_sync::format(bd.as_mut()).unwrap();
    let mut fs = SyncFileSystem::open_fs(bd).unwrap();
    assert_eq!(NUM_BLOCKS, fs.num_blocks());
    assert_eq!(NUM_BLOCKS - 2, fs.empty_blocks());

    let root = SyncFileSystem::root_dir_id();
    let file = fs.add_file(root, "file".into()).unwrap();

    println!("writing {} bytes", MAX_FILE_SIZE);
    let mut pos = 0_u64;
    while pos < MAX_FILE_SIZE {
        // Write.
        let buf: &[u8] =
            unsafe { core::slice::from_raw_parts(&pos as *const _ as usize as *const u8, 8) };
        assert_eq!(
            fs.write(file, pos, buf)
                .expect(format!("pos {}", pos).as_str()),
            8,
        );

        // Read back.
        let mut incoming: u64 = 0_u64;
        let buf: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(&mut incoming as *mut _ as usize as *mut u8, 8)
        };

        if let Err(err) = fs.read(file, pos, buf) {
            println!("Read failed at pos {} with {:?}", pos, err);
        }
        assert_eq!(pos, incoming);

        // assert_eq!(8, fs.read(file, 0, buf).unwrap());
        // if incoming != 0 {
        //     panic!("bad write at pos {}", pos);
        // }

        pos += 8;
    }

    assert_eq!(MAX_FILE_SIZE, fs.get_file_size(file).unwrap());

    println!("reading back");
    pos = 0_u64;
    while pos < MAX_FILE_SIZE {
        let mut incoming: u64 = 0_u64;
        let buf: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(&mut incoming as *mut _ as usize as *mut u8, 8)
        };
        assert_eq!(fs.read(file, pos, buf).unwrap(), 8);
        assert_eq!(pos, incoming);
        pos += 8;
    }

    println!("updating");
    pos = 0_u64;
    while pos < MAX_FILE_SIZE {
        let bytes: u64 = 0xffffffff_ffffffff ^ pos;
        let buf: &[u8] =
            unsafe { core::slice::from_raw_parts(&bytes as *const _ as usize as *const u8, 8) };
        assert_eq!(fs.write(file, pos, buf).unwrap(), 8);
        pos += 8;
    }

    println!("reading back");
    pos = 0_u64;
    while pos < MAX_FILE_SIZE {
        let mut incoming: u64 = 0_u64;
        let buf: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(&mut incoming as *mut _ as usize as *mut u8, 8)
        };
        assert_eq!(fs.read(file, pos, buf).unwrap(), 8);
        assert_eq!(0xffffffff_ffffffff ^ pos, incoming);
        pos += 8;
    }

    println!("cleaning up");
    assert_eq!(
        fs.remove(file).err().unwrap().kind(),
        ErrorKind::DirectoryNotEmpty
    );

    let validate_file = |fs: &mut SyncFileSystem| {
        let sz = fs.get_file_size(file).unwrap();
        println!("validating file of size {}", sz);
        let mut pos = 0_u64;
        while pos < sz - 8 {
            let mut incoming: u64 = 0_u64;
            let buf: &mut [u8] = unsafe {
                core::slice::from_raw_parts_mut(&mut incoming as *mut _ as usize as *mut u8, 8)
            };
            assert_eq!(fs.read(file, pos, buf).unwrap(), 8);
            assert_eq!(0xffffffff_ffffffff ^ pos, incoming, "pos = {}", pos);
            pos += 8;
        }
    };

    const ONE_GB: u64 = 1024 * 1024 * 1024;
    let mut file_size = MAX_FILE_SIZE;
    while file_size > 0 {
        if file_size > ONE_GB + 65536 {
            fs.set_file_size(file, ONE_GB + 8192 + 123).unwrap();
            file_size = fs.get_file_size(file).unwrap();
            assert_eq!(file_size, ONE_GB + 8192 + 123);
            validate_file(&mut fs);
        } else if file_size > 1024 * 1024 * 2 + 65536 {
            fs.set_file_size(file, 1024 * 1024 + 8192 * 2 + 123)
                .unwrap();
            file_size = fs.get_file_size(file).unwrap();
            assert_eq!(file_size, 1024 * 1024 + 8192 * 2 + 123);
            validate_file(&mut fs);
        } else if file_size > 65536 {
            fs.set_file_size(file, 12345).unwrap();
            file_size = fs.get_file_size(file).unwrap();
            assert_eq!(file_size, 12345);
            validate_file(&mut fs);
        } else if file_size > 500 {
            fs.set_file_size(file, 123).unwrap();
            file_size = fs.get_file_size(file).unwrap();
            assert_eq!(file_size, 123);
            validate_file(&mut fs);
        } else {
            fs.set_file_size(file, 0).unwrap();
            file_size = fs.get_file_size(file).unwrap();
            assert_eq!(file_size, 0);
        }
    }

    fs.remove(file).unwrap();
    assert_eq!(NUM_BLOCKS - 2, fs.empty_blocks());

    drop(fs);
    std::fs::remove_file(path.clone()).unwrap();
}
*/

#[test]
fn test_hash_debug() {
    #[cfg(debug_assertions)]
    {
        assert_eq!(
            crate::DirEntryBlock::hash_debug("012345678"),
            crate::DirEntryBlock::hash_debug("0123456789")
        );
    }
}
