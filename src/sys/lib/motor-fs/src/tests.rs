use async_fs::EntryId;
use async_fs::EntryKind;
use async_fs::FileSystem;
use camino::Utf8PathBuf;
use rand::Rng;
use std::io::ErrorKind;
use std::io::Result;
use std::io::Write;
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

#[test]
fn random_file() {
    init_logger();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(random_file_test()).unwrap();
}

#[test]
#[ignore]
fn write_speed() {
    init_logger();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(write_speed_test()).unwrap();
}

#[test]
#[ignore]
fn native_write_speed() {
    init_logger();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(native_write_speed_test()).unwrap();
}

#[test]
#[ignore]
fn native_write_speed_async() {
    init_logger();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(native_write_speed_async_test()).unwrap();
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
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS - 3
    );

    let dir22 = fs.create_entry(dir2, EntryKind::Directory, "dir22").await?;
    assert_eq!(dir2, fs.get_parent(dir22).await?.unwrap());

    // File.
    let file = fs.create_entry(dir2, EntryKind::File, "file").await?;
    assert_eq!(dir2, fs.get_parent(file).await?.unwrap());
    assert_eq!(2, fs.metadata(dir2).await?.size);

    const BYTES: &[u8] = "once upon a time there was a tree upon a hill".as_bytes();
    assert_eq!(BYTES.len(), fs.write(file, 0, BYTES).await.unwrap());
    assert_eq!(BYTES.len() as u64, fs.metadata(file).await?.size);
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS - 6
    );

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
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS - 5
    );

    // Resize up: populate with zeroes.
    fs.resize(file, BYTES.len() as u64).await.unwrap();
    assert_eq!(BYTES.len(), fs.read(file, 0, &mut buf).await.unwrap());
    for idx in 0..BYTES.len() {
        assert_eq!(0, buf[idx]);
    }
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS - 5
    );

    // Move.
    assert_eq!("dir22", fs.name(dir22).await?);
    fs.move_entry(dir22, dir2, "dir22_new").await?;
    assert_eq!("dir22_new", fs.name(dir22).await?);
    fs.move_entry(dir22, root, "dir22").await?;
    assert_eq!("dir22", fs.name(dir22).await?);
    assert_eq!(4, fs.metadata(root).await.unwrap().size);
    assert_eq!(root, fs.get_parent(dir22).await?.unwrap());
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS - 5
    );

    // Add some bytes to the file before deleting it, so that it uses
    // more than one block.
    assert_eq!(BYTES.len(), fs.write(file, 0, BYTES).await.unwrap());
    assert_eq!(
        BYTES.len(),
        fs.write(file, BYTES.len() as u64, BYTES).await.unwrap()
    );
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS - 6
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
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS,
        fs.empty_blocks().await.unwrap()
    );

    let root = crate::ROOT_DIR_ID;
    let parent_id = fs
        .create_entry(root, EntryKind::Directory, "parent dir")
        .await
        .unwrap();

    let mut bytes = vec![0_u8; 1024 * 1024 * 11 + 1001];
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

    // Clear: test free block accounting.
    fs.delete_entry(file_id).await.unwrap();
    assert!(
        fs.read(file_id, 4096, &mut bytes.as_mut_slice()[..4096])
            .await
            .is_err()
    );
    assert!(
        fs.write(file_id, 4096, &bytes.as_slice()[..4096])
            .await
            .is_err()
    );
    fs.delete_entry(parent_id).await.unwrap();
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS,
        fs.empty_blocks().await.unwrap()
    );

    // Recreate a large file: this tests reallocating blocks from a deleted file.
    let file_id = fs
        .create_entry(crate::ROOT_DIR_ID, EntryKind::File, "bar")
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

    fs.delete_entry(file_id).await.unwrap();
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS,
        fs.empty_blocks().await.unwrap()
    );

    println!("midsize_file_test PASS");
    Ok(())
}

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

async fn random_file_test() -> Result<()> {
    use rand::RngCore;
    use rand::thread_rng;
    let mut rng = thread_rng();

    const PARTITION_SZ: u64 = 1024 * 1024 * 8;
    const NUM_BLOCKS: u64 = PARTITION_SZ / 4096;

    // B+ tree overhead should be less than one block per 100.
    const FILE_SZ: u64 = PARTITION_SZ - (RESERVED_BLOCKS + NUM_BLOCKS / 100 + 1) * 4096;

    let mut fs = create_fs("motor_fs_random_file_test", NUM_BLOCKS).await?;
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS,
        fs.empty_blocks().await.unwrap()
    );

    let file_id = fs
        .create_entry(crate::ROOT_DIR_ID, EntryKind::File, "foo")
        .await
        .unwrap();

    let mut bytes = std::collections::HashMap::new();

    let mut blocks = Vec::with_capacity(FILE_SZ as usize / 4096);
    for idx in 0..(FILE_SZ / 4096) {
        blocks.push(idx as usize);
    }

    // Fill the file up to FILE_SZ at random offsets: this tests btree insertion.
    while !blocks.is_empty() {
        let block_idx: usize = rng.r#gen::<usize>() % blocks.len();
        let block_no = blocks.remove(block_idx);

        let mut block = Box::new(async_fs::Block::new_zeroed());
        rng.fill_bytes(block.as_bytes_mut());

        fs.write(file_id, (block_no * 4096) as u64, block.as_bytes())
            .await
            .unwrap();

        bytes.insert(block_no, block);
    }

    assert_eq!(FILE_SZ, fs.metadata(file_id).await?.size);

    // Fill the remainder.
    loop {
        let block_no = bytes.len();
        let mut block = Box::new(async_fs::Block::new_zeroed());
        rng.fill_bytes(block.as_bytes_mut());

        match fs
            .write(file_id, (block_no * 4096) as u64, block.as_bytes())
            .await
        {
            Ok(_) => {}
            Err(err) => {
                assert_eq!(err.kind(), ErrorKind::StorageFull);
                break;
            }
        }

        bytes.insert(block_no, block);
    }

    assert_eq!(0, fs.empty_blocks().await.unwrap());
    let file_sz = fs.metadata(file_id).await?.size;
    log::debug!("file size: {file_sz}; blocks: {}", file_sz / 4096);
    assert_eq!((file_sz / 4096) as usize, bytes.len());

    // Check the data.
    let mut file_bytes = async_fs::Block::new_zeroed();
    for idx in 0..bytes.len() {
        fs.read(file_id, (idx * 4096) as u64, file_bytes.as_bytes_mut())
            .await
            .unwrap();

        let block = bytes.get(&idx).unwrap();
        assert!(file_bytes.as_bytes() == block.as_bytes());
    }

    // Remove blocks at random offsets: this tests btree deletion.
    let mut blocks = Vec::with_capacity(bytes.len());
    for idx in 0..bytes.len() {
        blocks.push(idx as usize);
    }
    while !blocks.is_empty() {
        let block_idx: usize = rng.r#gen::<usize>() % blocks.len();
        let block_no = blocks.remove(block_idx);

        fs.test_remove_block_at_offset(file_id, (block_no * 4096) as u64)
            .await
            .unwrap();
    }

    assert_eq!(file_sz, fs.metadata(file_id).await?.size);
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS - 1, // The entry block is still there.
        fs.empty_blocks().await.unwrap()
    );

    println!("random_file_test PASS");
    Ok(())
}

async fn write_speed_test() -> Result<()> {
    // use futures::StreamExt;
    use rand::RngCore;
    use rand::thread_rng;

    let mut rng = thread_rng();

    const PARTITION_SZ: u64 = 1024 * 1024 * 256;
    const NUM_BLOCKS: u64 = PARTITION_SZ / 4096;

    // B+ tree overhead should be less than one block per 100.
    const FILE_BLOCKS: u64 = NUM_BLOCKS - (RESERVED_BLOCKS + NUM_BLOCKS / 100 + 1);

    let mut fs = create_fs("motor_fs_write_speed_test", NUM_BLOCKS).await?;

    let mut block = Box::new(async_fs::Block::new_zeroed());
    rng.fill_bytes(block.as_bytes_mut());

    let file_id = fs
        .create_entry(crate::ROOT_DIR_ID, EntryKind::File, "foo")
        .await
        .unwrap();

    let started = std::time::Instant::now();
    // let mut completion_queue = futures::stream::FuturesUnordered::new();

    for idx in 0..FILE_BLOCKS {
        // completion_queue.push(fs.write(file_id, idx * 4096, block.as_bytes()));
        fs.write(file_id, idx * 4096, block.as_bytes())
            .await
            .unwrap();
    }

    // while let Some(completion) = completion_queue.next().await {
    //     completion.unwrap();
    // }

    let elapsed = started.elapsed();

    // let file_sz = fs.metadata(file_id).await?.size;
    // assert_eq!(file_sz, FILE_BLOCKS * 4096);
    let file_sz = FILE_BLOCKS * 4096;

    let write_speed_mbps = (file_sz as f64) / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("Write speed: {:.3} MB/s", write_speed_mbps);

    println!("write_speed_test PASS");
    Ok(())
}

async fn native_write_speed_test() -> Result<()> {
    use rand::RngCore;
    use rand::thread_rng;

    let mut rng = thread_rng();

    const PARTITION_SZ: u64 = 1024 * 1024 * 256;
    const NUM_BLOCKS: u64 = PARTITION_SZ / 4096;

    const FILE_BLOCKS: u64 = NUM_BLOCKS - (RESERVED_BLOCKS + NUM_BLOCKS / 100 + 1);

    let mut block = Box::new(async_fs::Block::new_zeroed());
    rng.fill_bytes(block.as_bytes_mut());

    let mut file = std::fs::File::create("/tmp/motor_fs_native_write_speed_test").unwrap();

    let started = std::time::Instant::now();
    for _idx in 0..FILE_BLOCKS {
        file.write_all(block.as_bytes()).unwrap();
    }

    file.flush().unwrap();
    let elapsed = started.elapsed();

    let file_sz = FILE_BLOCKS * 4096;

    let write_speed_mbps = (file_sz as f64) / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("Native write speed: {:.3} MB/s", write_speed_mbps);

    println!("native_write_speed_test PASS");
    Ok(())
}

async fn native_write_speed_async_test() -> Result<()> {
    use rand::RngCore;
    use rand::thread_rng;
    use tokio::io::AsyncWriteExt;

    let mut rng = thread_rng();

    const PARTITION_SZ: u64 = 1024 * 1024 * 256;
    const NUM_BLOCKS: u64 = PARTITION_SZ / 4096;

    const FILE_BLOCKS: u64 = NUM_BLOCKS - (RESERVED_BLOCKS + NUM_BLOCKS / 100 + 1);

    let mut block = Box::new(async_fs::Block::new_zeroed());
    rng.fill_bytes(block.as_bytes_mut());

    let mut file = tokio::fs::File::create("/tmp/motor_fs_native_write_speed_async_test")
        .await
        .unwrap();

    let started = std::time::Instant::now();

    for _idx in 0..FILE_BLOCKS {
        file.write_all(block.as_bytes()).await.unwrap();
    }

    file.flush().await.unwrap();

    let elapsed = started.elapsed();

    // let file_sz = fs.metadata(file_id).await?.size;
    // assert_eq!(file_sz, FILE_BLOCKS * 4096);
    let file_sz = FILE_BLOCKS * 4096;

    let write_speed_mbps = (file_sz as f64) / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("Native async write speed: {:.3} MB/s", write_speed_mbps);

    println!("native_write_speed_async_test PASS");
    Ok(())
}
