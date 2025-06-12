use async_fs::BLOCK_SIZE;
use rand::RngCore;
use std::io::ErrorKind;

use crate::{SyncFileSystem, file_block_device::FileBlockDevice};

#[test]
fn basic() {
    const NUM_BLOCKS: u64 = 256;
    let path = std::env::temp_dir().join("fs_dev_basic");
    std::fs::remove_file(path.clone()).ok();

    let mut bd = Box::new(FileBlockDevice::create(&path, NUM_BLOCKS).unwrap());
    crate::fs_sync::format(bd.as_mut()).unwrap();
    let mut fs = SyncFileSystem::open_fs(bd).unwrap();
    assert_eq!(NUM_BLOCKS, fs.num_blocks());
    assert_eq!(NUM_BLOCKS - 2, fs.empty_blocks());

    let root = SyncFileSystem::root_dir_id();

    assert_eq!(0, fs.get_num_entries(root).unwrap());
    let first = fs.add_directory(root, "first".into()).unwrap();
    assert_eq!(1, fs.get_num_entries(root).unwrap());
    assert_eq!(0, fs.get_num_entries(first).unwrap());
    assert_eq!(NUM_BLOCKS - 3, fs.empty_blocks());

    assert_eq!(
        fs.add_directory(first, "/".into()).err().unwrap().kind(),
        ErrorKind::InvalidFilename
    );
    assert_eq!(
        fs.add_directory(first, "/second".into())
            .err()
            .unwrap()
            .kind(),
        ErrorKind::InvalidFilename
    );
    let second = fs.add_directory(first, "second".into()).unwrap();
    assert_eq!(1, fs.get_num_entries(first).unwrap());
    assert_eq!(NUM_BLOCKS - 4, fs.empty_blocks());

    assert_eq!(
        fs.get_directory_entry(first, 0)
            .unwrap()
            .get_name()
            .unwrap()
            .as_str(),
        "second"
    );
    assert_eq!(
        fs.get_directory_entry(first, 1).err().unwrap().kind(),
        ErrorKind::NotFound
    );

    fs.move_rename(first, root, "1st".into()).unwrap();
    let first_2 = fs.get_directory_entry(root, 0).unwrap();
    assert_eq!(first, first_2.id);
    assert_eq!(first_2.get_name().unwrap().as_str(), "1st");

    assert_eq!(
        fs.write(first, 0, "foo".as_bytes()).err().unwrap().kind(),
        ErrorKind::InvalidInput
    ); // Writing is for files.

    // Add file.
    assert_eq!(
        fs.add_file(first, "second".into()).err().unwrap().kind(),
        ErrorKind::AlreadyExists
    ); // "second" already exists.
    let file = fs.add_file(first, "file_1".into()).unwrap();
    assert_eq!(NUM_BLOCKS - 5, fs.empty_blocks());
    assert_eq!(0, fs.get_file_size(file).unwrap());

    const BYTES: &[u8] = "once upon a time there was a tree upon a hill".as_bytes();
    assert_eq!(BYTES.len(), fs.write(file, 0, BYTES).unwrap());
    let mut buf = [0_u8; 256];
    assert_eq!(BYTES.len(), fs.read(file, 0, &mut buf).unwrap());
    for idx in 0..BYTES.len() {
        assert_eq!(BYTES[idx], buf[idx]);
    }

    // Move.
    assert_eq!(first, fs.get_parent(file).unwrap().unwrap());
    assert_eq!("file_1", fs.get_name(file).unwrap().as_str());
    fs.move_rename(file, second, "file_one".into()).unwrap();
    assert_eq!("file_one", fs.get_name(file).unwrap().as_str());
    assert_eq!(second, fs.get_parent(file).unwrap().unwrap());
    fs.move_rename(file, root, "foo2".into()).unwrap();
    fs.move_rename(file, second, "file_one".into()).unwrap();

    // Remove stuff.
    assert_eq!(
        fs.add_directory(first_2.id, "second".into())
            .err()
            .unwrap()
            .kind(),
        ErrorKind::AlreadyExists
    ); // "second" already exists.
    assert_eq!(
        fs.remove(root).err().unwrap().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(NUM_BLOCKS - 5, fs.empty_blocks());
    assert_eq!(
        fs.remove(first).err().unwrap().kind(),
        ErrorKind::DirectoryNotEmpty
    ); // The directory is not empty.
    assert_eq!(NUM_BLOCKS - 5, fs.empty_blocks());
    assert_eq!(
        fs.remove(second).err().unwrap().kind(),
        ErrorKind::DirectoryNotEmpty
    );
    fs.move_rename(file, root, "foo".into()).unwrap();
    fs.remove(second).unwrap();
    fs.set_file_size(file, 0).unwrap();
    fs.remove(file).unwrap();
    assert_eq!(NUM_BLOCKS - 3, fs.empty_blocks());
    fs.remove(first).unwrap();
    assert_eq!(0, fs.get_num_entries(root).unwrap());
    assert_eq!(NUM_BLOCKS - 2, fs.empty_blocks());

    // Add file.
    let file = fs.add_file(root, "file".into()).unwrap();
    assert_eq!(0, fs.get_file_size(file).unwrap());

    // Write to file.
    for idx in 0..10000_u64 {
        let buf =
            unsafe { core::slice::from_raw_parts(&idx as *const u64 as usize as *const u8, 8) };
        assert_eq!(
            fs.write(file, idx * 8 + 2, buf).err().unwrap().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(8, fs.write(file, idx * 8, buf).unwrap());

        // Read it back.
        let mut out: u64 = 0;
        let buf =
            unsafe { core::slice::from_raw_parts_mut(&mut out as *mut u64 as usize as *mut u8, 8) };
        assert_eq!(8, fs.read(file, idx * 8, buf).unwrap());
        assert_eq!(idx, out);
    }
    println!("writing done");

    // Read it back again.
    for idx in 0..10000_u64 {
        let mut out: u64 = 0;
        let buf =
            unsafe { core::slice::from_raw_parts_mut(&mut out as *mut u64 as usize as *mut u8, 8) };
        assert_eq!(8, fs.read(file, idx * 8, buf).unwrap());
        assert_eq!(idx, out);
    }

    drop(fs);
    std::fs::remove_file(path.clone()).unwrap();
}

#[test]
#[ignore]
fn many_dirs() {
    const NUM_BLOCKS: u64 = 2 * crate::MAX_DIR_ENTRIES;
    let path = std::env::temp_dir().join("fs_dev_many_dirs");
    std::fs::remove_file(path.clone()).ok();

    let mut rng = rand::thread_rng();

    let mut bd = Box::new(FileBlockDevice::create(&path, NUM_BLOCKS).unwrap());
    crate::fs_sync::format(bd.as_mut()).unwrap();
    let mut fs = SyncFileSystem::open_fs(bd).unwrap();
    assert_eq!(NUM_BLOCKS, fs.num_blocks());
    assert_eq!(NUM_BLOCKS - 2, fs.empty_blocks());

    let root = SyncFileSystem::root_dir_id();
    let dir = fs.add_directory(root, "dir".into()).unwrap();

    println!("adding MAX_DIR_ENTRIES child dirs");
    for idx in 0..crate::MAX_DIR_ENTRIES {
        let name = format!("dir_{}", idx);
        let result = fs.add_directory(dir, name.as_str().into());
        if let Err(err) = result {
            panic!("add_directory failed at idx {} with {:?}", idx, err);
        }
        let id = result.unwrap();
        let result = fs.get_directory_entry_by_name(dir, name.as_str().into());
        if let Err(err) = result {
            panic!(
                "get_directory_entry_by_name failed at idx {} with {:?}",
                idx, err
            );
        }

        assert_eq!(
            id,
            result.as_ref().unwrap().id,
            "idx: {} name: {} result name: {}",
            idx,
            name,
            result.as_ref().unwrap().get_name().unwrap().as_str()
        );
        assert_eq!(
            name,
            result.as_ref().unwrap().get_name().unwrap().as_str(),
            "idx: {} name: {}",
            idx,
            name
        );
    }
    println!("Finished adding MAX_DIR_ENTRIES dirs.");

    let dir2 = fs.add_directory(root, "dir2".into()).unwrap();
    assert_eq!(
        fs.add_directory(dir, "foo".into()).err().unwrap().kind(),
        ErrorKind::FileTooLarge
    ); // Cannot add more than the limit.
    assert_eq!(
        crate::MAX_DIR_ENTRIES,
        fs.get_num_entries(dir).unwrap() as u64
    );

    println!("Validating dirs.");
    for idx in 0..crate::MAX_DIR_ENTRIES {
        let entry = fs.get_directory_entry(dir, idx).unwrap();
        assert_eq!(entry.get_name().unwrap().as_str(), format!("dir_{}", idx));
    }

    let entry = fs.get_directory_entry(dir, 12345).unwrap();
    assert_eq!(entry.get_name().unwrap().as_str(), "dir_12345");
    fs.remove(entry.id).unwrap();
    assert_eq!(
        fs.remove(entry.id).err().unwrap().kind(),
        ErrorKind::InvalidData
    );
    let entry = fs.get_directory_entry(dir, 12345).unwrap();
    assert_eq!(entry.get_name().unwrap().as_str(), "dir_65535"); // When an entry is removed, the last one is put into its place.
    assert_eq!(
        crate::MAX_DIR_ENTRIES - 1,
        fs.get_num_entries(dir).unwrap() as u64
    );

    // Move some children.
    println!("Moving dirs dir: {:?} dir2: {:?}.", dir, dir2);
    let idxs = [
        65530_u64, 0, 12, 18, 7000, 7860, 7740, 7740, 7741, 7860, 7861, 7862,
    ];

    for idx in idxs {
        assert_eq!(0, fs.get_num_entries(dir2).unwrap());
        assert_eq!(
            crate::MAX_DIR_ENTRIES - 1,
            fs.get_num_entries(dir).unwrap() as u64
        );
        let name1 = format!("dir_{}", idx);
        let name2 = format!("dir2_{}", idx);
        let e = fs
            .get_directory_entry_by_name(dir, name1.as_str().into())
            .unwrap();
        fs.move_rename(e.id, dir2, name2.as_str().into()).unwrap();
        let e2 = fs
            .get_directory_entry_by_name(dir2, name2.as_str().into())
            .unwrap();
        assert_eq!(e.id, e2.id);
        assert_eq!(1, fs.get_num_entries(dir2).unwrap());
        assert_eq!(
            crate::MAX_DIR_ENTRIES - 2,
            fs.get_num_entries(dir).unwrap() as u64
        );
        let e3 = fs.get_directory_entry_by_name(dir, name1.as_str().into());
        if let Ok(e3) = e3 {
            panic!(
                "Something went wrong:\n\te1: {:?}\n\te2: {:?}\n\te3: {:?}",
                e, e2, e3
            );
        }
        fs.move_rename(e.id, dir, name1.as_str().into()).unwrap();
    }

    println!("Removing dirs.");
    let mut num_entries = crate::MAX_DIR_ENTRIES - 1;
    for _idx in 0..(crate::MAX_DIR_ENTRIES - 1) {
        let idx: u64 = rng.next_u64() % num_entries;
        let entry = fs.get_directory_entry(dir, idx).unwrap();
        fs.remove(entry.id)
            .expect(format!("remove() failed for dir {:?} at idx {}", entry, idx).as_str());
        num_entries -= 1;
        assert_eq!(num_entries, fs.get_num_entries(dir).unwrap());
    }
    assert_eq!(0, num_entries);
    assert_eq!(0, fs.get_num_entries(dir).unwrap());

    fs.remove(dir).unwrap();
    let dir2 = fs.get_directory_entry_by_name(root, "dir2".into()).unwrap();
    fs.remove(dir2.id).unwrap();
    assert_eq!(NUM_BLOCKS - 2, fs.empty_blocks());

    drop(fs);
    std::fs::remove_file(path.clone()).unwrap();
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
