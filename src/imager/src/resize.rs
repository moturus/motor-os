//! `imager resize`: copy an image, giving its Motor FS partition a new size.
//!
//! Everything in front of the data partition is copied verbatim. The data
//! partition is formatted anew and populated entry by entry, so the input is
//! only ever read.

use crate::chmod::{self, TemporaryImage};
use async_fs::block_cache::CheckpointedBlock;
use async_fs::file_block_device::AsyncFileBlockDevice;
use async_fs::{AccessPermissions, AsyncBlockDevice, EntryId, EntryKind, FileSystem};
use async_fs::{Metadata, Role, RolePermissions, BLOCK_SIZE};
use async_trait::async_trait;
use camino::Utf8Path;
use fittings::iobuf::IoBuf;
use motor_fs::MotorFs;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    input: PathBuf,
    output: PathBuf,
    size_mb: u64,
}

/// Parse `-i INPUT -o OUTPUT --size X[M|G]`; each flag exactly once, any order.
pub fn parse_args(args: &[String]) -> Result<Request, String> {
    let (mut input, mut output, mut size_mb) = (None, None, None);
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("'{flag}' requires a value"))?;
        let duplicate = match flag.as_str() {
            "-i" => input.replace(PathBuf::from(value)).is_some(),
            "-o" => output.replace(PathBuf::from(value)).is_some(),
            "--size" => {
                let size = parse_size_mb(value).ok_or_else(|| {
                    format!("invalid size '{value}': expected a positive number followed by M or G")
                })?;
                size_mb.replace(size).is_some()
            }
            _ => return Err(format!("unknown argument '{flag}'")),
        };
        if duplicate {
            return Err(format!("duplicate '{flag}'"));
        }
    }
    Ok(Request {
        input: input.ok_or("missing -i INPUT_IMG")?,
        output: output.ok_or("missing -o OUTPUT_IMG")?,
        size_mb: size_mb.ok_or("missing --size X[M|G]")?,
    })
}

fn parse_size_mb(value: &str) -> Option<u64> {
    let (digits, multiplier) = if let Some(digits) = value.strip_suffix('M') {
        (digits, 1)
    } else {
        (value.strip_suffix('G')?, 1024)
    };
    // `parse` alone would also accept a leading '+'.
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let size_mb = digits.parse::<u64>().ok()?.checked_mul(multiplier)?;
    (size_mb > 0).then_some(size_mb)
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

fn output_is_qcow2(output: &Path) -> io::Result<bool> {
    match output.extension().and_then(|extension| extension.to_str()) {
        Some("qcow2") => Ok(true),
        Some("img" | "raw") => Ok(false),
        _ => Err(invalid_input(
            "the output image must have a .qcow2, .img or .raw suffix",
        )),
    }
}

/// An output that does not exist yet cannot be the input.
fn same_file(input: &Path, output: &Path) -> io::Result<bool> {
    let input = fs::metadata(input)?;
    match fs::metadata(output) {
        Ok(output) => Ok(input.dev() == output.dev() && input.ino() == output.ino()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

pub fn resize_image(request: &Request) -> io::Result<()> {
    let Request {
        input,
        output,
        size_mb,
    } = request;
    if same_file(input, output)? {
        return Err(invalid_input(
            "the input and output images are the same file",
        ));
    }
    let qcow2_output = output_is_qcow2(output)?;

    // Raw intermediates live in the temporary directory; the result is built
    // next to the output and renamed into place only when complete.
    let scratch = std::env::temp_dir();
    let raw_input = if chmod::is_qcow2(input)? {
        let raw = TemporaryImage::create_in(&scratch, input, "raw")?;
        crate::convert_qcow2_to_raw(input, raw.path())?;
        Some(raw)
    } else {
        None
    };
    let raw_input = raw_input.as_ref().map_or(input.as_path(), |raw| raw.path());

    let result = if qcow2_output {
        let result = TemporaryImage::create_next_to(output, "qcow2")?;
        let raw_output = TemporaryImage::create_in(&scratch, output, "raw")?;
        resize_raw(raw_input, raw_output.path(), *size_mb)?;
        crate::convert_raw_to_qcow2(raw_output.path(), result.path())?;
        result
    } else {
        let result = TemporaryImage::create_next_to(output, "raw")?;
        resize_raw(raw_input, result.path(), *size_mb)?;
        result
    };
    // Temporaries are owner-only; the copy is as accessible as the input.
    fs::set_permissions(result.path(), fs::metadata(input)?.permissions())?;
    result.publish(output)
}

/// Write the resized copy of the raw image `input` into the file `output`.
fn resize_raw(input: &Path, output: &Path, size_mb: u64) -> io::Result<()> {
    let (offset, old_length) = chmod::motor_fs_region(input)?;
    let mut source = File::open(input)?;
    let mut mbr = mbrman::MBR::read_from(&mut source, crate::SECTOR_SIZE)
        .map_err(|err| io::Error::new(ErrorKind::InvalidData, format!("bad MBR: {err}")))?;
    let (index, start) = mbr
        .iter()
        .find(|(_, partition)| partition.is_used() && partition.sys == motor_fs::PARTITION_ID)
        .map(|(index, partition)| (index, partition.starting_lba))
        .unwrap(); // motor_fs_region() has found it.

    // Only the last partition can change its size without moving another one.
    if mbr.iter().any(|(other, partition)| {
        other != index && partition.is_used() && partition.starting_lba > start
    }) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "the Motor FS partition is not the last one",
        ));
    }

    let too_large = || invalid_input(format!("{size_mb} MB does not fit an MBR disk"));
    let new_length = size_mb.checked_mul(1024 * 1024).ok_or_else(too_large)?;
    let sectors =
        u32::try_from(new_length / u64::from(crate::SECTOR_SIZE)).map_err(|_| too_large())?;
    start.checked_add(sectors).ok_or_else(too_large)?;
    mbr[index].sectors = sectors;

    let mut disk = OpenOptions::new().write(true).truncate(true).open(output)?;
    source.seek(SeekFrom::Start(0))?;
    io::copy(&mut source.take(offset), &mut disk)?;
    disk.seek(SeekFrom::Start(0))?;
    mbr.write_into(&mut disk)
        .map_err(|err| io::Error::other(format!("failed to write MBR: {err}")))?;
    disk.set_len(offset + new_length)?;
    drop(disk);

    let output = Utf8Path::from_path(output)
        .ok_or_else(|| invalid_input("the output image path is not UTF-8"))?;
    tokio::runtime::LocalRuntime::new()?.block_on(async {
        let device = OverlayDevice::open(input, offset, old_length)?;
        let mut source = MotorFs::open(Box::new(device)).await?;
        if source.replayed_txn_log_on_open() {
            println!("imager resize: applying the transaction logged in the input image");
        }

        async {
            let device = AsyncFileBlockDevice::open_region(output, offset, new_length).await?;
            let mut target = MotorFs::format(Box::new(device)).await?;
            copy_tree(&mut source, &mut target).await?;
            target.flush().await
        }
        .await
        .map_err(|err| match err.kind() {
            ErrorKind::StorageFull => io::Error::new(
                ErrorKind::StorageFull,
                format!("{size_mb} MB is too small for the files of the input image"),
            ),
            _ => err,
        })
    })
}

/// A read-only block device over a byte range of the input image. Writes (the
/// transaction log replay, see `make_accessible`) are kept in memory, so the
/// filesystem reads as updated while the image stays as it was.
struct OverlayDevice {
    image: File,
    offset: u64,
    num_blocks: u64,
    written: RefCell<HashMap<u64, Vec<u8>>>,
}

impl OverlayDevice {
    fn open(image: &Path, offset: u64, length: u64) -> io::Result<Self> {
        let image = File::open(image)?;
        let image_length = image.metadata()?.len();
        let end = offset.checked_add(length);
        if !length.is_multiple_of(BLOCK_SIZE as u64) || end.is_none_or(|end| end > image_length) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "bad Motor FS partition bounds",
            ));
        }
        Ok(Self {
            image,
            offset,
            num_blocks: length / BLOCK_SIZE as u64,
            written: RefCell::default(),
        })
    }
}

#[async_trait(?Send)]
impl AsyncBlockDevice for OverlayDevice {
    type Completion = core::future::Ready<(Vec<CheckpointedBlock>, io::Result<()>)>;

    fn num_blocks(&self) -> u64 {
        self.num_blocks
    }

    async fn read_block<T: AsMut<IoBuf> + Unpin>(
        &self,
        block_no: u64,
        mut block: T,
    ) -> (T, io::Result<()>) {
        if block_no >= self.num_blocks {
            return (block, Err(ErrorKind::InvalidInput.into()));
        }
        let bytes = AsMut::<[u8]>::as_mut(block.as_mut());
        let result = match self.written.borrow().get(&block_no) {
            Some(written) => {
                bytes.copy_from_slice(written);
                Ok(())
            }
            None => self
                .image
                .read_exact_at(bytes, self.offset + block_no * BLOCK_SIZE as u64),
        };
        (block, result)
    }

    async fn write_block<T: AsRef<IoBuf> + Unpin>(
        &self,
        block_no: u64,
        block: T,
    ) -> (T, io::Result<()>) {
        if block_no >= self.num_blocks {
            return (block, Err(ErrorKind::InvalidInput.into()));
        }
        let bytes = AsRef::<[u8]>::as_ref(block.as_ref()).to_vec();
        self.written.borrow_mut().insert(block_no, bytes);
        (block, Ok(()))
    }

    async fn write_blocks_with_completion(
        &self,
        first_block_no: u64,
        blocks: Vec<CheckpointedBlock>,
    ) -> io::Result<Self::Completion> {
        let mut result = Ok(());
        for (idx, block) in blocks.iter().enumerate() {
            if result.is_ok() {
                result = self
                    .write_block(first_block_no + idx as u64, block.clone())
                    .await
                    .1;
            }
        }
        Ok(core::future::ready((blocks, result)))
    }

    async fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Let `Role::System` read or list a source entry that denies it. The source
/// device is an overlay, so this never reaches the input image.
async fn make_accessible(
    source: &mut MotorFs<OverlayDevice>,
    entry: EntryId,
    metadata: &Metadata,
) -> io::Result<()> {
    let access = metadata.access(Role::System)?;
    let sufficient = match metadata.kind() {
        EntryKind::Directory => access.can_execute(),
        EntryKind::File => access.can_read(),
    };
    if sufficient {
        return Ok(());
    }
    let open = RolePermissions::all(AccessPermissions::Rwx);
    source
        .set_all_permissions_image_admin(Role::System, entry, open)
        .await
}

async fn copy_file(
    source: &MotorFs<OverlayDevice>,
    target: &mut MotorFs<AsyncFileBlockDevice>,
    from: EntryId,
    to: EntryId,
    size: u64,
) -> io::Result<()> {
    let mut buf = [0_u8; BLOCK_SIZE];
    let mut offset = 0;
    while offset < size {
        let len = source.read(Role::System, from, offset, &mut buf).await?;
        if len == 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        // An unwritten block reads as zeroes either way: holes stay holes.
        if buf[..len].iter().any(|byte| *byte != 0) {
            let written = target.write(Role::System, to, offset, &buf[..len]).await?;
            assert_eq!(written, len);
        }
        offset += len as u64;
    }
    // A no-op unless the file ends with a hole.
    target.resize(Role::System, to, size).await
}

/// Copy every entry of `source` into the freshly formatted `target`.
async fn copy_tree(
    source: &mut MotorFs<OverlayDevice>,
    target: &mut MotorFs<AsyncFileBlockDevice>,
) -> io::Result<()> {
    let writable = RolePermissions::all(AccessPermissions::Rwx);
    let root = source.metadata(Role::System, motor_fs::ROOT_DIR_ID).await?;
    make_accessible(source, motor_fs::ROOT_DIR_ID, &root).await?;

    // Populating a directory needs write access to it and updates its
    // timestamps, so directories get their metadata once all entries exist.
    let mut directories = vec![(motor_fs::ROOT_DIR_ID, root)];
    let mut pending = vec![(motor_fs::ROOT_DIR_ID, motor_fs::ROOT_DIR_ID)];
    while let Some((source_dir, target_dir)) = pending.pop() {
        let mut next = source.get_first_entry(Role::System, source_dir).await?;
        while let Some(entry) = next {
            let metadata = source.metadata(Role::System, entry).await?;
            make_accessible(source, entry, &metadata).await?;
            let name = source.name(Role::System, entry).await?;
            let kind = metadata.kind();
            let copy = target
                .create_entry(Role::System, target_dir, kind, &name, writable)
                .await?;
            match kind {
                EntryKind::Directory => {
                    pending.push((entry, copy));
                    directories.push((copy, metadata));
                }
                EntryKind::File => {
                    copy_file(source, target, entry, copy, metadata.size).await?;
                    target
                        .copy_metadata_image_admin(Role::System, copy, &metadata)
                        .await?;
                }
            }
            next = source.get_next_entry(Role::System, entry).await?;
        }
    }

    for (directory, metadata) in &directories {
        target
            .copy_metadata_image_admin(Role::System, *directory, metadata)
            .await?;
    }
    Ok(())
}

// Run by the developer-image suite only (see src/tests/full-test.sh), hence
// `#[ignore]`: cargo test resize -- --ignored
#[cfg(test)]
mod tests {
    use super::*;
    use mbrman::{MBRPartitionEntry, BOOT_INACTIVE, CHS};
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    const MB: u64 = 1024 * 1024;
    /// Sector 0 is the MBR, sectors 1-7 a stand-in for the boot partitions.
    const DATA_OFFSET: u64 = 8 * crate::SECTOR_SIZE as u64;
    /// Motor FS keeps its transaction log in the last blocks of the partition.
    const TXN_LOG_BLOCKS: usize = 64;
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    type Fs = MotorFs<AsyncFileBlockDevice>;

    struct Fixture(PathBuf);

    impl Fixture {
        fn create() -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "motor-imager-resize-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        /// A raw image with a formatted data partition of `size_mb`.
        fn image(&self, name: &str, size_mb: u64) -> PathBuf {
            let path = self.path(name);
            let mut disk = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            disk.set_len(DATA_OFFSET + size_mb * MB).unwrap();
            let mut mbr =
                mbrman::MBR::new_from(&mut disk, crate::SECTOR_SIZE, [1, 2, 3, 4]).unwrap();
            let entry = |sys, starting_lba, sectors| MBRPartitionEntry {
                boot: BOOT_INACTIVE,
                first_chs: CHS::empty(),
                sys,
                last_chs: CHS::empty(),
                starting_lba,
                sectors,
            };
            mbr[1] = entry(0x20, 1, 7);
            let sectors = size_mb * MB / u64::from(crate::SECTOR_SIZE);
            mbr[3] = entry(motor_fs::PARTITION_ID, 8, sectors as u32);
            mbr.write_into(&mut disk).unwrap();
            disk.seek(SeekFrom::Start(u64::from(crate::SECTOR_SIZE)))
                .unwrap();
            disk.write_all(&[0xb0; 7 * crate::SECTOR_SIZE as usize])
                .unwrap();
            drop(disk);

            let utf8 = Utf8Path::from_path(&path).unwrap();
            tokio::runtime::LocalRuntime::new()
                .unwrap()
                .block_on(async {
                    let device =
                        AsyncFileBlockDevice::open_region(utf8, DATA_OFFSET, size_mb * MB).await?;
                    MotorFs::format(Box::new(device)).await?.flush().await
                })
                .unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn modify(raw: &Path, operation: impl AsyncFnOnce(&mut Fs) -> io::Result<()>) {
        let (offset, length) = chmod::motor_fs_region(raw).unwrap();
        let raw = Utf8Path::from_path(raw).unwrap();
        tokio::runtime::LocalRuntime::new()
            .unwrap()
            .block_on(async {
                let device = AsyncFileBlockDevice::open_region(raw, offset, length).await?;
                let mut fs = MotorFs::open(Box::new(device)).await?;
                operation(&mut fs).await?;
                fs.flush().await
            })
            .unwrap();
    }

    async fn create(fs: &mut Fs, parent: EntryId, kind: EntryKind, name: &str) -> EntryId {
        let open = RolePermissions::all(AccessPermissions::Rwx);
        fs.create_entry(Role::System, parent, kind, name, open)
            .await
            .unwrap()
    }

    /// Write whole blocks of a recognizable pattern, then the `tail`.
    async fn fill(fs: &mut Fs, file: EntryId, first_block: u64, blocks: u64, tail: &[u8]) {
        for block in first_block..first_block + blocks {
            let bytes = [(block % 251) as u8 + 1; BLOCK_SIZE];
            fs.write(Role::System, file, block * BLOCK_SIZE as u64, &bytes)
                .await
                .unwrap();
        }
        if !tail.is_empty() {
            let offset = (first_block + blocks) * BLOCK_SIZE as u64;
            fs.write(Role::System, file, offset, tail).await.unwrap();
        }
    }

    #[derive(PartialEq, Eq)]
    struct Entry {
        kind: EntryKind,
        permissions: RolePermissions,
        times: [u128; 3],
        data: Vec<u8>,
    }

    // Keeps a failed comparison readable: no file contents.
    impl std::fmt::Debug for Entry {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let Self {
                kind,
                permissions,
                times,
                data,
            } = self;
            let hash = crate::util::fnv1a_hash_64(data);
            write!(
                f,
                "{kind:?} {permissions:?} {times:?} {}:{hash:x}",
                data.len()
            )
        }
    }

    /// Everything in a raw image's filesystem by path, plus its total and used
    /// block counts. Read through the overlay: the image is not written to.
    fn snapshot(raw: &Path) -> (BTreeMap<String, Entry>, u64, u64) {
        let (offset, length) = chmod::motor_fs_region(raw).unwrap();
        tokio::runtime::LocalRuntime::new()
            .unwrap()
            .block_on(async {
                let device = OverlayDevice::open(raw, offset, length)?;
                let mut fs = MotorFs::open(Box::new(device)).await?;
                let used = fs.num_blocks() - fs.empty_blocks().await?;

                let mut entries = BTreeMap::new();
                let mut pending = vec![(motor_fs::ROOT_DIR_ID, String::new())];
                while let Some((id, path)) = pending.pop() {
                    let metadata = fs.metadata(Role::System, id).await?;
                    make_accessible(&mut fs, id, &metadata).await?;
                    let mut data = vec![];
                    if metadata.kind() == EntryKind::File {
                        let mut buf = [0_u8; BLOCK_SIZE];
                        while (data.len() as u64) < metadata.size {
                            let offset = data.len() as u64;
                            let len = fs.read(Role::System, id, offset, &mut buf).await?;
                            data.extend_from_slice(&buf[..len]);
                        }
                    } else {
                        let mut next = fs.get_first_entry(Role::System, id).await?;
                        while let Some(child) = next {
                            let name = fs.name(Role::System, child).await?;
                            pending.push((child, format!("{path}/{name}")));
                            next = fs.get_next_entry(Role::System, child).await?;
                        }
                    }
                    let entry = Entry {
                        kind: metadata.kind(),
                        permissions: metadata.permissions()?,
                        times: [metadata.created, metadata.modified, metadata.accessed]
                            .map(|time| time.as_nanos()),
                        data,
                    };
                    entries.insert(path, entry);
                }
                Ok::<_, io::Error>((entries, fs.num_blocks(), used))
            })
            .unwrap()
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o7777
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn request(input: &Path, output: &Path, size_mb: u64) -> Request {
        Request {
            input: input.to_owned(),
            output: output.to_owned(),
            size_mb,
        }
    }

    #[test]
    #[ignore = "developer-image suite"]
    fn resize_keeps_files_metadata_and_boot_area() {
        let fixture = Fixture::create();
        let input = fixture.image("input.raw", 1);
        modify(&input, async |fs| {
            let dir = create(fs, motor_fs::ROOT_DIR_ID, EntryKind::Directory, "dir").await;
            let sub = create(fs, dir, EntryKind::Directory, "sub").await;
            create(fs, sub, EntryKind::Directory, "empty").await;
            let inline = create(fs, sub, EntryKind::File, "inline.txt").await;
            fill(fs, inline, 0, 0, b"hello").await;
            let big = create(fs, dir, EntryKind::File, "big.bin").await;
            fill(fs, big, 0, 3, &[0xab; 100]).await;
            // Holes in front of and behind the only data block.
            let sparse = create(fs, dir, EntryKind::File, "sparse.bin").await;
            fill(fs, sparse, 8, 1, &[]).await;
            fs.resize(Role::System, sparse, 12 * BLOCK_SIZE as u64 + 5)
                .await?;

            // Entries that Role::System can neither read nor change.
            let secret = create(fs, motor_fs::ROOT_DIR_ID, EntryKind::File, "secret").await;
            fill(fs, secret, 0, 0, b"sealed").await;
            let none = RolePermissions::all(AccessPermissions::None);
            fs.set_all_permissions_image_admin(Role::System, secret, none)
                .await?;
            fs.set_all_permissions_image_admin(Role::System, sub, none)
                .await?;
            let listed = RolePermissions::all(AccessPermissions::Rx);
            fs.set_all_permissions_image_admin(Role::System, motor_fs::ROOT_DIR_ID, listed)
                .await
        });
        set_mode(&input, 0o600);
        let original = fs::read(&input).unwrap();
        let (entries, blocks, used) = snapshot(&input);
        assert_eq!(entries.len(), 8);
        assert_eq!(entries["/dir/sparse.bin"].data.len(), 12 * BLOCK_SIZE + 5);
        assert_eq!(entries["/secret"].data, b"sealed");
        assert_eq!(blocks, MB / BLOCK_SIZE as u64);

        let output = fixture.path("output.img");
        resize_image(&request(&input, &output, 2)).unwrap();

        assert_eq!(fs::read(&input).unwrap(), original);
        assert_eq!(mode(&output), 0o600);
        let (resized_entries, resized_blocks, resized_used) = snapshot(&output);
        assert_eq!(resized_entries, entries);
        assert_eq!(resized_blocks, 2 * MB / BLOCK_SIZE as u64);
        // Holes were not filled in.
        assert!(resized_used <= used, "{resized_used} > {used}");
        let resized = fs::read(&output).unwrap();
        assert_eq!(resized.len() as u64, DATA_OFFSET + 2 * MB);
        assert_eq!(
            chmod::motor_fs_region(&output).unwrap(),
            (DATA_OFFSET, 2 * MB)
        );
        // Only the size in the data partition's MBR entry differs up front.
        let sectors = 446 + 2 * 16 + 12..446 + 2 * 16 + 16;
        assert_eq!(resized[sectors.clone()], (2 * MB / 512).to_le_bytes()[..4]);
        assert_eq!(resized[..sectors.start], original[..sectors.start]);
        assert_eq!(
            resized[sectors.end..DATA_OFFSET as usize],
            original[sectors.end..DATA_OFFSET as usize]
        );
    }

    #[test]
    #[ignore = "developer-image suite"]
    fn resize_applies_a_logged_transaction() {
        let fixture = Fixture::create();
        let input = fixture.image("input.raw", 1);
        modify(&input, async |fs| {
            let early = create(fs, motor_fs::ROOT_DIR_ID, EntryKind::File, "early").await;
            fill(fs, early, 0, 2, b"tail").await;
            Ok(())
        });
        let checkpointed = fs::read(&input).unwrap();
        // One operation is one transaction, however the log gets flushed.
        modify(&input, async |fs| {
            create(fs, motor_fs::ROOT_DIR_ID, EntryKind::File, "late").await;
            Ok(())
        });

        // A crash between logging the transaction and applying it: the log,
        // at the end of the partition, is ahead of the main area.
        let mut crashed = fs::read(&input).unwrap();
        let log_start = crashed.len() - TXN_LOG_BLOCKS * BLOCK_SIZE;
        crashed[..log_start].copy_from_slice(&checkpointed[..log_start]);
        assert!(!crashed[..log_start].windows(4).any(|name| name == b"late"));
        fs::write(&input, &crashed).unwrap();
        set_mode(&input, 0o640);

        let qcow2 = fixture.path("output.qcow2");
        resize_image(&request(&input, &qcow2, 2)).unwrap();
        assert_eq!(fs::read(&input).unwrap(), crashed);
        assert!(chmod::is_qcow2(&qcow2).unwrap());
        assert_eq!(mode(&qcow2), 0o640);

        // And back, which also covers a qcow2 input and shrinking.
        let raw = fixture.path("output.raw");
        resize_image(&request(&qcow2, &raw, 1)).unwrap();
        assert_eq!(mode(&raw), 0o640);
        let (entries, blocks, _) = snapshot(&raw);
        assert_eq!(blocks, MB / BLOCK_SIZE as u64);
        assert_eq!(entries.keys().collect::<Vec<_>>(), ["", "/early", "/late"]);
        assert_eq!(entries["/early"].data.len(), 2 * BLOCK_SIZE + 4);
        // The replayed log is the only source of "/late".
        assert_eq!(entries, snapshot(&input).0);

        let leftovers: Vec<_> = fs::read_dir(std::env::temp_dir())
            .unwrap()
            .flatten()
            .filter(|entry| {
                let name = entry.file_name().into_string().unwrap_or_default();
                name.starts_with(".output.") && name.contains(&format!("-{}-", std::process::id()))
            })
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    #[ignore = "developer-image suite"]
    fn resize_rejects_unusable_requests() {
        let fixture = Fixture::create();
        let input = fixture.image("input.raw", 2);
        modify(&input, async |fs| {
            let large = create(fs, motor_fs::ROOT_DIR_ID, EntryKind::File, "large").await;
            fill(fs, large, 0, 300, &[]).await;
            Ok(())
        });
        let original = fs::read(&input).unwrap();

        // The files need more than a 1 MB partition; the old output survives.
        let output = fixture.path("output.img");
        fs::write(&output, b"previous").unwrap();
        let error = resize_image(&request(&input, &output, 1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::StorageFull);
        assert!(error.to_string().contains("too small"), "{error}");
        assert_eq!(fs::read(&output).unwrap(), b"previous");

        let link = fixture.path("link.img");
        fs::hard_link(&input, &link).unwrap();
        // The same file under its name, another spelling of it, and a link.
        for same in [&input, &fixture.path("./input.raw"), &link] {
            let error = resize_image(&request(&input, same, 4)).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
            assert!(error.to_string().contains("same file"), "{error}");
        }
        let error = resize_image(&request(&input, &fixture.path("output.vdi"), 4)).unwrap_err();
        assert!(error.to_string().contains("suffix"), "{error}");
        let error = resize_image(&request(&input, &output, 4 * 1024 * 1024)).unwrap_err();
        assert!(error.to_string().contains("MBR"), "{error}");

        // Intermediate copies of an image are for the owner only.
        let temporary = TemporaryImage::create_in(&fixture.0, &input, "raw").unwrap();
        assert_eq!(mode(temporary.path()), 0o600);
        drop(temporary);

        // Nothing was touched or left behind.
        assert_eq!(fs::read(&input).unwrap(), original);
        let mut names: Vec<_> = fs::read_dir(&fixture.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["input.raw", "link.img", "output.img"]);

        let args =
            |args: &[&str]| parse_args(&args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>());
        assert_eq!(
            args(&["--size", "3G", "-o", "out.qcow2", "-i", "in.img"]).unwrap(),
            request(Path::new("in.img"), Path::new("out.qcow2"), 3 * 1024)
        );
        assert_eq!(
            args(&["-i", "a", "-o", "b", "--size", "64M"])
                .unwrap()
                .size_mb,
            64
        );
        for size in [
            "",
            "M",
            "64",
            "0M",
            "+1G",
            "1.5G",
            "1g",
            "64MB",
            "-1M",
            "99999999999999999999G",
        ] {
            assert!(
                args(&["-i", "a", "-o", "b", "--size", size]).is_err(),
                "{size}"
            );
        }
        for invalid in [
            &["-i", "a", "-o", "b"][..],
            &["-i", "a", "--size", "1M"],
            &["-o", "b", "--size", "1M"],
            &["-i", "a", "-i", "a", "-o", "b", "--size", "1M"],
            &["-i", "a", "-o", "b", "--size"],
            &["-i", "a", "-o", "b", "--size", "1M", "--force", "yes"],
        ] {
            assert!(args(invalid).is_err(), "{invalid:?}");
        }
    }
}
