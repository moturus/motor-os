//! Motor FS.
//!
//! Note: it is relatively easy to corrupt the FS by crafting file data blocks
//!       to resemble dir entry or tree blocks, and then issue operations like
//!       insert/delete. This should be fixed at a higher (OS?) level.

use async_fs::block_cache::BlockCache;
use async_fs::{AsyncBlockDevice, BLOCK_SIZE, FileSystem};
use async_fs::{EntryId, EntryKind, Role};
use async_trait::async_trait;
use std::io::ErrorKind;
use std::io::Result;

#[cfg(not(target_os = "motor"))]
use fittings::iobuf::IoBuf;
#[cfg(target_os = "motor")]
use moto_tooling::iobuf::IoBuf;

use crate::{
    DirEntryBlock, EntryIdInternal, INLINE_CAPACITY, INLINE_DATA_OFFSET, MAX_BLOCKS_IN_TXN_LOG,
    RESERVED_BLOCKS, ROOT_DIR_ID, ROOT_DIR_ID_INTERNAL, Superblock, Txn, dir_entry,
    validate_filename,
};

pub const PARTITION_ID: u8 = 0x2e;

// Note: for some reason a smaller cache results in faster sequential reads/writes.
//       Claude Fable hypothesised that the smaller cache stays in L2/L3 CPU cache,
//       while a larger cache spills over to RAM.
// const CACHE_SIZE: usize = 4096; // 16MB.
const CACHE_SIZE: usize = 512; // 2MB.

#[cfg(test)]
pub const MAX_FLUSH_DELAY_MS: u64 = 50;

#[cfg(not(test))]
pub const MAX_FLUSH_DELAY_MS: u64 = 500;

/// The permission a Mode-E access check requires of the caller's role byte.
/// `Execute` gates directory traversal/listing (see PERMISSIONS_DESIGN.md §5).
#[derive(Clone, Copy)]
enum Need {
    Read,
    Write,
    Execute,
}

pub struct MotorFs<BD: AsyncBlockDevice + 'static> {
    block_cache: async_fs::block_cache::BlockCache<BD>,
    error: Result<()>,

    txn_logger: crate::txn_log::TxnLogger,
}

impl<BD: AsyncBlockDevice + 'static> MotorFs<BD> {
    #[inline(always)]
    pub fn check_err(&self) -> Result<()> {
        match &self.error {
            Ok(_) => Ok(()),
            Err(err) => Err(err.kind().into()),
        }
    }

    /// Mode-E access enforcement: require that `role` holds the `need`
    /// permission on `entry_id`, keyed off the entry's own per-role permission
    /// byte. `r` gates `w` and `x`, so a write/execute check also implies read.
    /// Directory traversal/listing needs `Execute`; file read/write need
    /// `Read`/`Write`. See PERMISSIONS_DESIGN.md §5.
    async fn require_access(
        &self,
        role: Role,
        entry_id: EntryIdInternal,
        need: Need,
    ) -> Result<()> {
        let block = self
            .block_cache
            .get_block(entry_id.block_no())
            .await?
            .clone();
        dir_entry!(block).validate_entry(entry_id)?;
        let access = dir_entry!(block).metadata().access(role)?;
        let ok = match need {
            Need::Read => access.can_read(),
            Need::Write => access.can_write(),
            Need::Execute => access.can_execute(),
        };
        if ok {
            Ok(())
        } else {
            log::debug!("access denied: {role:?} on {entry_id:?}");
            Err(ErrorKind::PermissionDenied.into())
        }
    }

    /// Look a name up in a directory *without* enforcing caller permissions --
    /// used both by `stat` (after it has checked `Execute`) and by internal
    /// bookkeeping (create/move existence checks), which are gated by their own
    /// `Write` checks rather than by traversal (`Execute`). Errors if
    /// `parent_id` is not a directory.
    #[allow(clippy::await_holding_refcell_ref)]
    pub(crate) async fn lookup_child(
        &self,
        parent_id: EntryIdInternal,
        filename: &str,
    ) -> Result<Option<(EntryId, EntryKind)>> {
        let parent_block = self
            .block_cache
            .get_block(parent_id.block_no())
            .await?
            .clone();
        dir_entry!(parent_block).validate_entry(parent_id)?;
        if dir_entry!(parent_block).kind() != EntryKind::Directory {
            return Err(ErrorKind::NotADirectory.into());
        }

        let hash = dir_entry!(parent_block).hash(filename);

        let mut txn = Txn::new_readonly(self);
        let Some(mut child_block_no) = dir_entry!(parent_block)
            .first_child_with_hash(&mut txn, hash)
            .await?
        else {
            return Ok(None);
        };
        drop(txn);

        loop {
            let child_block = self.block_cache.get_block(child_block_no.as_u64()).await?;
            assert_eq!(
                dir_entry!(parent_block).hash(dir_entry!(child_block).name()?),
                hash,
                "bad child hash: child: '{filename}', parent: {} child block: {}",
                parent_id.block_no.as_u64(),
                child_block_no.as_u64()
            );

            if dir_entry!(child_block).name()? == filename {
                let (id, kind) =
                    dir_entry!(child_block).entry_id_with_validation(child_block_no)?;
                return Ok(Some((id.into(), kind)));
            }

            child_block_no = if let Some(id) = dir_entry!(child_block).next_entry_id() {
                id.block_no
            } else {
                break;
            };
        }

        Ok(None)
    }

    pub(crate) fn block_cache(&self) -> &async_fs::block_cache::BlockCache<BD> {
        &self.block_cache
    }

    #[cfg(test)]
    pub(crate) async fn set_error_pct(&mut self, error_pct: u8) {
        self.txn_logger.set_error_pct(error_pct).await;
    }

    pub fn replayed_txn_log_on_open(&self) -> bool {
        self.txn_logger.replayed_txn_log_on_open()
    }

    pub async fn format(dev: Box<BD>) -> Result<Self> {
        let num_blocks = dev.num_blocks();
        if num_blocks <= RESERVED_BLOCKS as u64 {
            return Err(ErrorKind::StorageFull.into());
        }
        let (superblock, root_dir) = Superblock::format(dev.num_blocks());

        let mut iobuf = IoBuf::new_from_size_align(BLOCK_SIZE).unwrap();
        AsMut::<[u8]>::as_mut(&mut iobuf).clone_from_slice(superblock.as_bytes());
        let (mut iobuf, res) = dev.write_block(0, iobuf).await;
        res?;

        AsMut::<[u8]>::as_mut(&mut iobuf).clone_from_slice(root_dir.as_bytes());
        let (_, res) = dev.write_block(1, iobuf).await;
        res?;

        let mut block_cache = BlockCache::new(
            dev,
            CACHE_SIZE,
            num_blocks - MAX_BLOCKS_IN_TXN_LOG as u64,
            MAX_BLOCKS_IN_TXN_LOG,
        )
        .await?;

        let txn_logger = crate::txn_log::TxnLogger::new(&mut block_cache).await?;

        Ok(Self {
            block_cache,
            txn_logger,
            error: Ok(()),
        })
    }

    pub async fn open(dev: Box<BD>) -> Result<Self> {
        let num_blocks = dev.num_blocks();
        if num_blocks <= RESERVED_BLOCKS as u64 {
            return Err(ErrorKind::StorageFull.into());
        }

        log::debug!(
            "Opening a Motor FS partition: {} MB.",
            dev.num_blocks() / 256
        );

        let mut block_cache = BlockCache::new(
            dev,
            CACHE_SIZE,
            num_blocks - MAX_BLOCKS_IN_TXN_LOG as u64,
            MAX_BLOCKS_IN_TXN_LOG,
        )
        .await?;

        let txn_logger = crate::txn_log::TxnLogger::open(&mut block_cache).await?;

        Ok(Self {
            block_cache,
            txn_logger,
            error: Ok(()),
        })
    }

    pub(crate) async fn log_txn(
        &mut self,
        txn_blocks: [Option<(crate::BlockNo, async_fs::block_cache::CachedBlock)>;
            crate::MAX_BLOCKS_IN_TXN],
    ) -> Result<()> {
        if let Err(err) = self.txn_logger.log_txn(txn_blocks).await {
            log::error!("FS error: {err:?}.");
            let kind = err.kind();
            self.error = Err(err);
            Err(kind.into())
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub async fn test_remove_block_at_offset(
        &mut self,
        file_id: EntryId,
        offset: u64,
    ) -> Result<()> {
        Txn::test_remove_block_txn(self, file_id.into(), offset).await
    }

    /// Warm the block cache with up to `count` data blocks of `file_id`,
    /// starting at file block `first_key` (a file block key is
    /// `offset / BLOCK_SIZE`). Best-effort readahead: errors are swallowed,
    /// sparse holes are skipped. No data is returned, so no permission check
    /// is needed (callers issue this after a successful authorized read of
    /// the same file).
    pub async fn prefetch(&self, file_id: EntryId, first_key: u64, count: u64) {
        if self.check_err().is_err() {
            return;
        }
        let file_id: EntryIdInternal = file_id.into();
        let Ok(entry_block) = self.block_cache.get_block(file_id.block_no()).await else {
            return;
        };
        if dir_entry!(entry_block).validate_entry(file_id).is_err()
            || dir_entry!(entry_block).kind() != EntryKind::File
        {
            return;
        }
        let file_size = dir_entry!(entry_block).metadata().size;
        drop(entry_block);
        if file_size <= INLINE_CAPACITY {
            return; // Inline files live in the entry block, already cached.
        }

        let last_key = (file_size - 1) / (BLOCK_SIZE as u64);
        for key in first_key..(first_key + count).min(last_key + 1) {
            let mut txn = Txn::new_readonly(self);
            let data_block_no =
                DirEntryBlock::data_block_at_key(&mut txn, file_id.block_no, key).await;
            drop(txn);
            match data_block_no {
                Ok(Some(data_block_no)) => {
                    let _ = self.block_cache.get_block(data_block_no.as_u64()).await;
                }
                Ok(None) => continue, // A sparse hole.
                Err(_) => return,
            }
        }
    }
}

#[async_trait(?Send)]
impl<BD: AsyncBlockDevice + 'static> FileSystem for MotorFs<BD> {
    async fn stat(
        &self,
        role: Role,
        parent_id: EntryId,
        filename: &str,
    ) -> Result<Option<(EntryId, EntryKind)>> {
        self.check_err()?;
        // Note: parent is required here, so "/" is always invalid.
        validate_filename(filename)?;
        log::debug!("stat: {parent_id:x} '{filename}'");

        let parent_id = if parent_id == async_fs::ROOT_ID {
            ROOT_DIR_ID
        } else {
            parent_id
        };
        let id: EntryIdInternal = parent_id.into();

        {
            let parent_block = self.block_cache.get_block(id.block_no()).await?.clone();
            if dir_entry!(parent_block).kind() != EntryKind::Directory {
                return Err(ErrorKind::NotADirectory.into());
            }
        }

        // Resolving a name in a directory requires execute (traverse) on it;
        // `lookup_child` then performs the unenforced lookup.
        self.require_access(role, id, Need::Execute).await?;
        self.lookup_child(id, filename).await
    }

    async fn create_entry(
        &mut self,
        role: Role,
        parent_id: EntryId,
        kind: async_fs::EntryKind,
        filename: &str, // Leaf name.
        perms: [async_fs::AccessPermissions; 3],
    ) -> Result<EntryId> {
        self.check_err()?;
        validate_filename(filename)?;

        // Validate the requested initial permissions. Cross-role monotonicity
        // must hold, and the caller may set only its own and strictly-lower
        // roles (starting from the Rwx default, so any value is fine); a
        // strictly-higher role must be left fully permissive (Rwx), since the
        // caller cannot restrict what it does not control. (Note: this is the
        // corrected form of the may_set-based check in PERMISSIONS_DESIGN.md
        // §6.2 -- may_set forbids *touching* a higher role even to its unchanged
        // Rwx default, which would reject a lower-privileged caller using the
        // default perms.)
        if !async_fs::perms_monotonic(perms) {
            return Err(ErrorKind::PermissionDenied.into());
        }
        for target in [Role::None, Role::Interactive, Role::System] {
            let allowed = if (role as u8) >= (target as u8) {
                true
            } else {
                perms[target as usize] == async_fs::AccessPermissions::Rwx
            };
            if !allowed {
                return Err(ErrorKind::PermissionDenied.into());
            }
        }

        let parent_id = if parent_id == async_fs::ROOT_ID {
            ROOT_DIR_ID
        } else {
            parent_id
        };

        // Creating an entry requires write on the parent directory. The
        // existence check uses the unenforced lookup so that `w` alone suffices
        // (it does not additionally require traverse/`x`).
        self.require_access(role, parent_id.into(), Need::Write)
            .await?;

        if self
            .lookup_child(parent_id.into(), filename)
            .await?
            .is_some()
        {
            return Err(ErrorKind::AlreadyExists.into());
        }

        log::debug!("create_entry: parent_id: {parent_id:x} kind: {kind:?} fname: '{filename}'");
        Txn::do_create_entry_txn(self, parent_id.into(), kind, filename, perms)
            .await
            .map(|e| e.into())
    }

    async fn set_permissions(
        &mut self,
        caller: Role,
        entry_id: EntryId,
        target: Role,
        access: async_fs::AccessPermissions,
    ) -> Result<()> {
        self.check_err()?;
        let entry_id = if entry_id == async_fs::ROOT_ID {
            ROOT_DIR_ID
        } else {
            entry_id
        };
        Txn::do_set_permissions_txn(self, caller, entry_id.into(), target, access).await
    }

    async fn delete_entry(&mut self, role: Role, entry_id: EntryId) -> Result<()> {
        self.check_err()?;
        if entry_id == ROOT_DIR_ID_INTERNAL.into() {
            return Err(ErrorKind::InvalidInput.into());
        }

        // Deletion is gated by write on the parent directory.
        if let Some(parent) = self.get_parent(role, entry_id).await? {
            self.require_access(role, parent.into(), Need::Write)
                .await?;
        }

        log::debug!("delete_entry {entry_id:x}");
        Txn::do_delete_entry_txn(self, entry_id.into()).await
    }

    async fn move_entry(
        &mut self,
        role: Role,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<()> {
        self.check_err()?;
        let new_parent_id = if new_parent_id == async_fs::ROOT_ID {
            ROOT_DIR_ID
        } else {
            new_parent_id
        };

        if entry_id == ROOT_DIR_ID_INTERNAL.into() || entry_id == async_fs::ROOT_ID {
            return Err(ErrorKind::InvalidInput.into());
        }

        if entry_id == new_parent_id {
            return Err(ErrorKind::InvalidInput.into());
        }

        validate_filename(new_name)?;

        // Check that we are not moving an entry down to its own child,
        // which will create a detached cycle.
        let mut ancestor_id = new_parent_id;
        loop {
            let Some(grandparent_id) = self.get_parent(role, ancestor_id).await? else {
                assert_eq!(ancestor_id, ROOT_DIR_ID_INTERNAL.into());
                break;
            };
            if grandparent_id == entry_id {
                log::debug!("MotorFS::move_entry: cannot move an entry under its own child.");
                return Err(ErrorKind::InvalidInput.into());
            }
            ancestor_id = grandparent_id;
        }

        let old_parent_id = self.get_parent(role, entry_id).await?.unwrap();

        // Moving requires write on both the source and destination directories.
        self.require_access(role, old_parent_id.into(), Need::Write)
            .await?;
        self.require_access(role, new_parent_id.into(), Need::Write)
            .await?;

        log::debug!("move_entry {entry_id:x} to parent {new_parent_id:x} with name '{new_name}'");
        Txn::do_move_entry_txn(
            self,
            entry_id.into(),
            old_parent_id.into(),
            new_parent_id.into(),
            new_name,
        )
        .await
    }

    /// Get the first entry in a directory.
    #[allow(clippy::await_holding_refcell_ref)]
    async fn get_first_entry(&self, role: Role, parent_id: EntryId) -> Result<Option<EntryId>> {
        self.check_err()?;
        let parent_id = if parent_id == async_fs::ROOT_ID {
            ROOT_DIR_ID
        } else {
            parent_id
        };
        let parent_id: EntryIdInternal = parent_id.into();
        let parent_block = self
            .block_cache
            .get_block(parent_id.block_no())
            .await?
            .clone();
        dir_entry!(parent_block).validate_entry(parent_id)?;

        if dir_entry!(parent_block).kind() != EntryKind::Directory {
            return Err(ErrorKind::NotADirectory.into());
        }

        // Listing requires execute (traverse) on the directory.
        self.require_access(role, parent_id, Need::Execute).await?;

        let mut txn = Txn::new_readonly(self);
        let Some(child_block_no) = dir_entry!(parent_block).first_child(&mut txn).await? else {
            return Ok(None);
        };
        drop(txn);

        let child_block = self.block_cache.get_block(child_block_no.as_u64()).await?;
        let (id, _) = dir_entry!(child_block).entry_id_with_validation(child_block_no)?;

        Ok(Some(id.into()))
    }

    /// Get the next entry in a directory.
    #[allow(clippy::await_holding_refcell_ref)]
    async fn get_next_entry(&self, role: Role, entry_id: EntryId) -> Result<Option<EntryId>> {
        self.check_err()?;
        if entry_id == ROOT_DIR_ID_INTERNAL.into() || entry_id == async_fs::ROOT_ID {
            return Ok(None);
        }

        // Listing is gated by execute (traverse) on the directory (the entry's
        // parent).
        if let Some(parent) = self.get_parent(role, entry_id).await? {
            self.require_access(role, parent.into(), Need::Execute)
                .await?;
        }

        let entry_id: EntryIdInternal = entry_id.into();
        let entry_block = self
            .block_cache
            .get_block(entry_id.block_no())
            .await?
            .clone();
        dir_entry!(entry_block).validate_entry(entry_id)?;

        if let Some(next_id) = dir_entry!(entry_block).next_entry_id() {
            return Ok(Some(next_id.into()));
        }

        let parent_id = dir_entry!(entry_block).parent_id();
        let parent_block = self
            .block_cache
            .get_block(parent_id.block_no())
            .await?
            .clone();
        dir_entry!(parent_block).validate_entry(parent_id)?;

        if dir_entry!(parent_block).kind() != EntryKind::Directory {
            log::error!("Parent {parent_id:?} of {entry_id:?} is not a directory");
            return Err(ErrorKind::InvalidData.into());
        }

        let hash = dir_entry!(parent_block).hash(dir_entry!(entry_block).name()?);

        let mut txn = Txn::new_readonly(self);
        let Some(child_block_no) = dir_entry!(parent_block).next_child(&mut txn, hash).await?
        else {
            return Ok(None);
        };
        drop(txn);

        let child_block = self.block_cache.get_block(child_block_no.as_u64()).await?;
        let (id, _) = dir_entry!(child_block).entry_id_with_validation(child_block_no)?;
        Ok(Some(id.into()))
    }

    async fn get_parent(&self, role: Role, entry_id: EntryId) -> Result<Option<EntryId>> {
        self.check_err()?;
        let id: EntryIdInternal = entry_id.into();
        if id == ROOT_DIR_ID_INTERNAL || id == async_fs::ROOT_ID.into() {
            return Ok(None);
        }

        let block = self.block_cache.get_block(id.block_no()).await?;
        dir_entry!(block).validate_entry(id)?;

        #[allow(clippy::let_and_return)]
        let res = Ok(Some(dir_entry!(block).parent_id().into()));
        res
    }

    async fn name(&self, role: Role, entry_id: EntryId) -> Result<String> {
        self.check_err()?;
        let entry_id = if entry_id == async_fs::ROOT_ID {
            ROOT_DIR_ID
        } else {
            entry_id
        };
        let id: EntryIdInternal = entry_id.into();
        let block = self.block_cache.get_block(id.block_no()).await?;
        dir_entry!(block).validate_entry(id)?;

        #[allow(clippy::let_and_return)]
        let res = dir_entry!(block).name().map(|s| s.to_owned());
        res
    }

    async fn metadata(&self, role: Role, entry_id: EntryId) -> Result<async_fs::Metadata> {
        self.check_err()?;
        let entry_id = if entry_id == async_fs::ROOT_ID {
            ROOT_DIR_ID
        } else {
            entry_id
        };
        let id: EntryIdInternal = entry_id.into();
        let block = self.block_cache.get_block(id.block_no()).await?;
        dir_entry!(block).validate_entry(id)?;

        let res = *dir_entry!(block).metadata();
        Ok(res)
    }

    async fn read(
        &self,
        role: Role,
        file_id: EntryId,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        self.check_err()?;
        let file_id: EntryIdInternal = file_id.into();
        self.require_access(role, file_id, Need::Read).await?;
        let entry_block = self.block_cache.get_block(file_id.block_no()).await?;
        dir_entry!(entry_block).validate_entry(file_id)?;

        if dir_entry!(entry_block).kind() != EntryKind::File {
            return Err(ErrorKind::IsADirectory.into());
        }

        let file_size = dir_entry!(entry_block).metadata().size;
        if offset >= file_size {
            return Ok(0);
        }

        // Inline files keep their data in the entry block; the whole file is
        // below one block, so no read can cross a block boundary.
        if file_size <= INLINE_CAPACITY {
            let to_read = buf.len().min((file_size - offset) as usize);
            let start = INLINE_DATA_OFFSET + offset as usize;
            buf[..to_read].copy_from_slice(&entry_block.block().as_bytes()[start..start + to_read]);
            return Ok(to_read);
        }

        let block_start = offset & !(BLOCK_SIZE as u64 - 1);
        if (offset + (buf.len() as u64)) > (block_start + (BLOCK_SIZE as u64)) {
            log::debug!("MotorFs::read() error: cross-block reads are not supported (yet?).");
            return Err(ErrorKind::InvalidInput.into());
        }

        let block_key = block_start / (BLOCK_SIZE as u64);

        assert!(buf.len() <= BLOCK_SIZE);

        let to_read = if (file_size - offset) >= (BLOCK_SIZE as u64) {
            buf.len()
        } else {
            buf.len().min((file_size - offset) as usize)
        };

        let mut txn = Txn::new_readonly(self);
        let Some(data_block_no) =
            DirEntryBlock::data_block_at_key(&mut txn, file_id.block_no, block_key).await?
        else {
            log::debug!(
                "MotorFs::Read(): block not found:\n\tkey {block_key:x} offset {offset} file_block: {:x}.",
                file_id.block_no()
            );
            // No data block => "read" zeroes.
            for byte in &mut buf[..to_read] {
                *byte = 0;
            }

            return Ok(to_read);
        };
        drop(txn);

        let data_block = self.block_cache.get_block(data_block_no.as_u64()).await?;
        let offset_within_block = (offset - block_start) as usize;
        buf[..to_read].copy_from_slice(
            &data_block.block().as_bytes()[offset_within_block..(offset_within_block + to_read)],
        );

        Ok(to_read)
    }

    async fn write(
        &mut self,
        role: Role,
        file_id: EntryId,
        offset: u64,
        buf: &[u8],
    ) -> Result<usize> {
        self.check_err()?;
        self.require_access(role, file_id.into(), Need::Write)
            .await?;
        log::trace!(
            "write to file {file_id:x} at offset 0x{offset:x} len 0x{:x}",
            buf.len()
        );
        Txn::do_write_txn(self, file_id.into(), offset, buf).await
    }

    async fn resize(&mut self, role: Role, file_id: EntryId, new_size: u64) -> Result<()> {
        self.check_err()?;
        self.require_access(role, file_id.into(), Need::Write)
            .await?;
        Txn::do_resize_txn(self, file_id.into(), new_size).await
    }

    async fn empty_blocks(&self) -> Result<u64> {
        self.check_err()?;
        let sb = self.block_cache.get_block(0).await?;
        let res = sb.block().get_at_offset::<Superblock>(0).free_blocks();
        sb.block()
            .get_at_offset::<Superblock>(0)
            .check_accounting()?;
        Ok(res)
    }

    /// Copies bytes from one file to another.
    async fn copy_file_range(
        &mut self,
        role: Role,
        from: EntryId,
        from_offset: u64,
        to: EntryId,
        to_offset: u64,
        size: u64,
    ) -> Result<u64> {
        self.check_err()?;

        let mut buf = [0_u8; BLOCK_SIZE];
        let mut from_offset = from_offset;
        let mut to_offset = to_offset;
        let mut remaining = size;
        let mut copied = 0_u64;

        while remaining > 0 {
            // Cross-block reads/writes are not supported, so each chunk must
            // stay within a single block on both the source and the dest side.
            let src_room = BLOCK_SIZE as u64 - (from_offset % BLOCK_SIZE as u64);
            let dst_room = BLOCK_SIZE as u64 - (to_offset % BLOCK_SIZE as u64);
            let chunk = remaining.min(src_room).min(dst_room) as usize;

            let read = self
                .read(role, from, from_offset, &mut buf[..chunk])
                .await?;
            if read == 0 {
                break; // Reached the end of the source file.
            }

            let mut written = 0;
            while written < read {
                written += self
                    .write(role, to, to_offset + written as u64, &buf[written..read])
                    .await?;
            }

            from_offset += read as u64;
            to_offset += read as u64;
            copied += read as u64;
            remaining -= read as u64;
        }

        Ok(copied)
    }

    async fn flush(&mut self) -> Result<()> {
        self.check_err()?;
        self.txn_logger.flush().await
    }

    fn num_blocks(&self) -> u64 {
        self.block_cache.total_blocks()
    }
}
