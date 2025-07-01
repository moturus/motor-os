use async_fs::BLOCK_SIZE;
use async_fs::EntryKind;
use async_fs::FileSystem;
use camino::Utf8PathBuf;
use rand::RngCore;
use std::io::ErrorKind;
use std::io::Result;
use std::time::Instant;
use std::time::SystemTime;

use crate::MotorFs;

// use crate::{SyncFileSystem, file_block_device::FileBlockDevice};

#[test]
fn basic() {
    env_logger::init();
    let rt = tokio::runtime::Builder::new_current_thread()
        // .thread_stack_size(1024 * 1024 * 256)
        .build()
        .unwrap();

    rt.block_on(basic_test()).unwrap();
}

async fn basic_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 256;

    let path = std::env::temp_dir().join("motor_fs_basic_test");
    let path = Utf8PathBuf::from_path_buf(path).unwrap();
    std::fs::remove_file(path.clone()).ok();

    let ts_format = SystemTime::now();

    let bd = async_fs::file_block_device::AsyncFileBlockDevice::create(&path, NUM_BLOCKS).await?;
    let mut fs = MotorFs::format(Box::new(bd)).await?;

    assert_eq!(NUM_BLOCKS, fs.num_blocks());
    assert_eq!(NUM_BLOCKS - 2, fs.empty_blocks().await?);

    let root = crate::ROOT_DIR_ID.into();

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

    assert_eq!(
        fs.create_entry(first, async_fs::EntryKind::Directory, "/")
            .await
            .err()
            .unwrap()
            .kind(),
        ErrorKind::InvalidFilename
    );

    assert_eq!(first, fs.stat(root, "first").await?.unwrap());

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

    /*
    const NUM_BLOCKS: u64 = 256;
    let path = std::env::temp_dir().join("fs_async_basic");
    let path = Utf8PathBuf::from_path_buf(path).unwrap();
    std::fs::remove_file(path.clone()).ok();

    // let mut bd = Box::new(FileBlockDevice::create(&path, NUM_BLOCKS).unwrap());
    let bd = async_fs::file_block_device::AsyncFileBlockDevice::create(&path, NUM_BLOCKS).await?;
    let mut fs = crate::fs_async::SrFs::format(bd).await.unwrap();
    // let mut fs = SyncFileSystem::open_fs(bd).unwrap();
    // assert_eq!(NUM_BLOCKS, fs.num_blocks());
    assert_eq!(NUM_BLOCKS - 2, fs.empty_blocks().await.unwrap());

    let root = async_fs::ROOT_DIR_ID;

    assert_eq!(0, fs.size(root).await.unwrap());
    let first = fs
        .create_entry(root, async_fs::EntryKind::Directory, "first")
        .await
        .unwrap();
    assert_eq!(1, fs.size(root).await.unwrap());
    assert_eq!(0, fs.size(first).await.unwrap());
    // assert_eq!(NUM_BLOCKS - 3, fs.empty_blocks());

    assert_eq!(
        fs.create_entry(first, async_fs::EntryKind::Directory, "/")
            .await
            .err()
            .unwrap()
            .kind(),
        ErrorKind::InvalidFilename
    );
    assert_eq!(
        fs.create_entry(first, async_fs::EntryKind::Directory, "/second")
            .await
            .err()
            .unwrap()
            .kind(),
        ErrorKind::InvalidFilename
    );
    let second = fs
        .create_entry(first, async_fs::EntryKind::Directory, "second")
        .await
        .unwrap();
    assert_eq!(1, fs.size(first).await.unwrap());
    assert_eq!(NUM_BLOCKS - 4, fs.empty_blocks().await.unwrap());

    assert_eq!(fs.get_entry_by_pos(first, 0).await.unwrap(), second);

    assert_eq!(fs.name(second).await.unwrap(), "second");
    assert_eq!(
        fs.get_entry_by_pos(first, 1).await.err().unwrap().kind(),
        ErrorKind::NotFound
    );

    fs.move_rename(first, root, "1st".into()).await.unwrap();
    let first_2 = fs.get_entry_by_pos(root, 0).await.unwrap();
    assert_eq!(first, first_2);
    assert_eq!(fs.name(first_2).await.unwrap(), "1st");

    assert_eq!(
        fs.write(first, 0, "foo".as_bytes())
            .await
            .err()
            .unwrap()
            .kind(),
        ErrorKind::InvalidInput
    ); // Writing is for files.

    // Add file.
    assert_eq!(
        fs.create_entry(first, async_fs::EntryKind::File, "second")
            .await
            .err()
            .unwrap()
            .kind(),
        ErrorKind::AlreadyExists
    ); // "second" already exists.
    let file = fs
        .create_entry(first, async_fs::EntryKind::File, "file_1")
        .await
        .unwrap();
    assert_eq!(0, fs.size(file).await.unwrap());

    const BYTES: &[u8] = "once upon a time there was a tree upon a hill".as_bytes();
    assert_eq!(BYTES.len(), fs.write(file, 0, BYTES).await.unwrap());
    let mut buf = [0_u8; 256];
    assert_eq!(BYTES.len(), fs.read(file, 0, &mut buf).await.unwrap());
    for idx in 0..BYTES.len() {
        assert_eq!(BYTES[idx], buf[idx]);
    }

    // Move.
    assert_eq!(first, fs.get_parent(file).await.unwrap().unwrap());
    assert_eq!("file_1", fs.name(file).await.unwrap().as_str());
    assert_eq!(0, fs.size(second).await.unwrap());
    assert_eq!(2, fs.size(first).await.unwrap());
    println!("will move");
    fs.move_rename(file, second, "file_one").await.unwrap();
    println!("did move");
    assert_eq!(1, fs.size(second).await.unwrap());
    assert_eq!(1, fs.size(first).await.unwrap());
    assert_eq!("file_one", fs.name(file).await.unwrap());
    assert_eq!(second, fs.get_parent(file).await.unwrap().unwrap());
    fs.move_rename(file, root, "foo2").await.unwrap();
    assert_eq!(0, fs.size(second).await.unwrap());
    assert_eq!(root, fs.get_parent(file).await.unwrap().unwrap());
    assert_eq!("foo2", fs.name(file).await.unwrap());
    fs.move_rename(file, second, "file_one").await.unwrap();
    assert_eq!(1, fs.size(second).await.unwrap());
    assert_eq!("file_one", fs.name(file).await.unwrap());

    // Remove stuff.
    assert_eq!(
        fs.create_entry(first_2, async_fs::EntryKind::Directory, "second")
            .await
            .err()
            .unwrap()
            .kind(),
        ErrorKind::AlreadyExists
    ); // "second" already exists.
    assert_eq!(
        fs.delete_entry(root).await.err().unwrap().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        fs.delete_entry(first).await.err().unwrap().kind(),
        ErrorKind::DirectoryNotEmpty
    ); // The directory is not empty.
    assert_eq!(
        fs.delete_entry(second).await.err().unwrap().kind(),
        ErrorKind::DirectoryNotEmpty
    );
    fs.move_rename(file, root, "foo").await.unwrap();
    fs.delete_entry(second).await.unwrap();
    fs.resize(file, 0).await.unwrap();
    fs.delete_entry(file).await.unwrap();
    fs.delete_entry(first).await.unwrap();
    assert_eq!(0, fs.size(root).await.unwrap());
    assert_eq!(NUM_BLOCKS - 2, fs.empty_blocks().await.unwrap());

    // Add file.
    let file = fs
        .create_entry(root, async_fs::EntryKind::File, "file")
        .await
        .unwrap();
    assert_eq!(0, fs.size(file).await.unwrap());

    // Write to file.
    for idx in 0..10000_u64 {
        let buf =
            unsafe { core::slice::from_raw_parts(&idx as *const u64 as usize as *const u8, 8) };
        assert_eq!(
            fs.write(file, idx * 8 + 2, buf).await.err().unwrap().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(8, fs.write(file, idx * 8, buf).await.unwrap());

        // Read it back.
        let mut out: u64 = 0;
        let buf =
            unsafe { core::slice::from_raw_parts_mut(&mut out as *mut u64 as usize as *mut u8, 8) };
        assert_eq!(8, fs.read(file, idx * 8, buf).await.unwrap());
        assert_eq!(idx, out);
    }

    // Read it back again.
    for idx in 0..10000_u64 {
        let mut out: u64 = 0;
        let buf =
            unsafe { core::slice::from_raw_parts_mut(&mut out as *mut u64 as usize as *mut u8, 8) };
        assert_eq!(8, fs.read(file, idx * 8, buf).await.unwrap());
        assert_eq!(idx, out);
    }

    drop(fs);
    std::fs::remove_file(path.clone()).unwrap();
    */

    println!("basic_test PASS");
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
