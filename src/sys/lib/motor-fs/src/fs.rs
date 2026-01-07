//! Motor FS.
//!
//! Note: it is relatively easy to corrupt the FS by crafting file data blocks
//!       to resemble dir entry or tree blocks, and then issue operations like
//!       insert/delete. This should be fixed at a higher (OS?) level.

// Note: quite often the following construct is used to create a second
//       mutable reference to an object:
//
//   // TODO: remove unsafe when NLL Problem #3 is solved.
//   // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
//   let this = unsafe {
//       let this = self as *mut Self;
//       this.as_mut().unwrap_unchecked()
//   };
//
// Sometimes it is indeed because the compiler has the NLL Problem #3 bug.
// But sometimes it is because an async function takes '&mut txn' parameter
// and returns a future that borrows it; if the future were to outlive the txn,
// we would have a dangling reference. But all of the functions here are only
// called from trait Filesystem (async) methods, and the assumption is that
// the client/caller keeps the filesystem object around long enough to outlive
// all futures "in flight".
//
// This is an unsafe assumption, but we present (and implement) trait Filesystem
// as a safe interface.
//
// TODO: fix the unsafety described above. One option is to take &'static mut self
//       in all trait Filesystem methods, thus explicitly indicating that we assume
//       the filesystem object to outlive anything the implementation can do.
//
//       This will be too harsh, though: the client code won't be able to unmount
//       filesystems once mounted...

use async_fs::block_cache::BlockCache;
use async_fs::{AsyncBlockDevice, BLOCK_SIZE, FileSystem};
use async_fs::{EntryId, EntryKind};
use async_trait::async_trait;
use std::io::ErrorKind;
use std::io::Result;

use crate::{
    DirEntryBlock, EntryIdInternal, RESERVED_BLOCKS, ROOT_DIR_ID, ROOT_DIR_ID_INTERNAL, Superblock,
    Txn, dir_entry, validate_filename,
};

pub const PARTITION_ID: u8 = 0x2e;

const CACHE_SIZE: usize = 512; // 2MB.

pub struct MotorFs {
    block_cache: async_fs::block_cache::BlockCache,
    error: Result<()>,
}

impl MotorFs {
    pub fn check_err(&self) -> Result<()> {
        match &self.error {
            Ok(_) => Ok(()),
            Err(err) => Err(err.kind().into()),
        }
    }

    pub async fn format(mut dev: Box<dyn AsyncBlockDevice>) -> Result<Self> {
        if dev.num_blocks() <= RESERVED_BLOCKS {
            return Err(ErrorKind::StorageFull.into());
        }
        let (superblock, root_dir) = Superblock::format(dev.num_blocks());

        dev.write_block(0, &superblock).await?;
        dev.write_block(1, &root_dir).await?;

        Ok(Self {
            block_cache: BlockCache::new(dev, CACHE_SIZE).await?,
            error: Ok(()),
        })
    }

    pub fn block_cache(&mut self) -> &mut async_fs::block_cache::BlockCache {
        &mut self.block_cache
    }

    pub async fn open(dev: Box<dyn AsyncBlockDevice>) -> Result<Self> {
        if dev.num_blocks() <= RESERVED_BLOCKS {
            return Err(ErrorKind::StorageFull.into());
        }

        // TODO: do we need to do any kind of (superficial) validation?
        // On the one hand, it could be useful; on the other, it will
        // slow down the bootup, which is a priority. So for now
        // no explicit validation other than the num blocks check above.

        log::debug!(
            "Opening a Motor FS partition: {} MB.",
            dev.num_blocks() / 256
        );

        Ok(Self {
            block_cache: BlockCache::new(dev, CACHE_SIZE).await?,
            error: Ok(()),
        })
    }
}

#[async_trait(?Send)]
impl FileSystem for MotorFs {
    #[allow(clippy::await_holding_refcell_ref)]
    async fn stat(
        &mut self,
        parent_id: EntryId,
        filename: &str,
    ) -> Result<Option<(EntryId, EntryKind)>> {
        // Note: parent is required here, so "/" is always invalid.
        validate_filename(filename)?;

        let parent_id = if parent_id == async_fs::ROOT_ID {
            ROOT_DIR_ID
        } else {
            parent_id
        };

        let id: EntryIdInternal = parent_id.into();
        let parent_block = self.block_cache.get_block(id.block_no()).await?.clone();
        assert!(!parent_block.is_dirty());
        dir_entry!(parent_block).validate_entry(id)?;

        if dir_entry!(parent_block).kind() != EntryKind::Directory {
            return Err(ErrorKind::NotADirectory.into());
        }

        let hash = dir_entry!(parent_block).hash(filename);

        let mut txn = Txn::new_readonly(self);

        assert!(!parent_block.is_dirty());
        let Some(mut child_block_no) = dir_entry!(parent_block)
            .first_child_with_hash(&mut txn, hash)
            .await?
        else {
            assert!(!parent_block.is_dirty());
            return Ok(None);
        };
        drop(txn);

        loop {
            let child_block = self.block_cache.get_block(child_block_no.as_u64()).await?;
            assert_eq!(
                dir_entry!(parent_block).hash(dir_entry!(child_block).name()?),
                hash
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

    async fn create_entry(
        &mut self,
        parent_id: EntryId,
        kind: async_fs::EntryKind,
        filename: &str, // Leaf name.
    ) -> Result<EntryId> {
        let parent_id = if parent_id == async_fs::ROOT_ID {
            ROOT_DIR_ID
        } else {
            parent_id
        };

        if self.stat(parent_id, filename).await?.is_some() {
            return Err(ErrorKind::AlreadyExists.into());
        }

        Txn::do_create_entry_txn(self, parent_id.into(), kind, filename)
            .await
            .map(|e| e.into())
    }

    async fn delete_entry(&mut self, entry_id: EntryId) -> Result<()> {
        if entry_id == ROOT_DIR_ID_INTERNAL.into() {
            return Err(ErrorKind::InvalidInput.into());
        }
        Txn::do_delete_entry_txn(self, entry_id.into()).await?;
        self.block_cache.flush().await
    }

    async fn move_entry(
        &mut self,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<()> {
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
            let Some(grandparent_id) = self.get_parent(ancestor_id).await? else {
                assert_eq!(ancestor_id, ROOT_DIR_ID_INTERNAL.into());
                break;
            };
            if grandparent_id == entry_id {
                log::debug!("MotorFS::move_entry: cannot move an entry under its own child.");
                return Err(ErrorKind::InvalidInput.into());
            }
            ancestor_id = grandparent_id;
        }

        let old_parent_id = self.get_parent(entry_id).await?.unwrap();

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
    async fn get_first_entry(&mut self, parent_id: EntryId) -> Result<Option<EntryId>> {
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
    async fn get_next_entry(&mut self, entry_id: EntryId) -> Result<Option<EntryId>> {
        if entry_id == ROOT_DIR_ID_INTERNAL.into() || entry_id == async_fs::ROOT_ID {
            return Ok(None);
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

    async fn get_parent(&mut self, entry_id: EntryId) -> Result<Option<EntryId>> {
        let id: EntryIdInternal = entry_id.into();
        if id == ROOT_DIR_ID_INTERNAL || id == async_fs::ROOT_ID.into() {
            return Ok(None);
        }

        let block = self.block_cache.get_block(id.block_no()).await?;
        dir_entry!(block).validate_entry(id)?;

        let res = Ok(Some(dir_entry!(block).parent_id().into()));
        res
    }

    async fn name(&mut self, entry_id: EntryId) -> Result<String> {
        let entry_id = if entry_id == async_fs::ROOT_ID {
            ROOT_DIR_ID
        } else {
            entry_id
        };
        let id: EntryIdInternal = entry_id.into();
        let block = self.block_cache.get_block(id.block_no()).await?;
        dir_entry!(block).validate_entry(id)?;

        let res = dir_entry!(block).name().map(|s| s.to_owned());
        res
    }

    async fn metadata(&mut self, entry_id: EntryId) -> Result<async_fs::Metadata> {
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

    async fn read(&mut self, file_id: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let file_id: EntryIdInternal = file_id.into();
        let entry_block = self.block_cache.get_block(file_id.block_no()).await?;
        dir_entry!(entry_block).validate_entry(file_id)?;

        if dir_entry!(entry_block).kind() != EntryKind::File {
            return Err(ErrorKind::IsADirectory.into());
        }

        let file_size = dir_entry!(entry_block).metadata().size;
        if offset >= file_size {
            return Ok(0);
        }

        let block_start = offset & !(BLOCK_SIZE as u64 - 1);
        if (offset + (buf.len() as u64)) > (block_start + (BLOCK_SIZE as u64)) {
            log::debug!("MotorFs::read() error: cross-block reads are not supported (yet?).");
            return Err(ErrorKind::InvalidInput.into());
        }

        let block_key = dir_entry!(entry_block).hash_u64(block_start);

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
            log::debug!("MotorFs::Read(): block not found: key {block_key} offset {offset}.");
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

    async fn write(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize> {
        Txn::do_write_txn(self, file_id.into(), offset, buf).await
    }

    async fn resize(&mut self, file_id: EntryId, new_size: u64) -> Result<()> {
        Txn::do_resize_txn(self, file_id.into(), new_size).await
    }

    async fn empty_blocks(&mut self) -> Result<u64> {
        self.check_err()?;
        let sb = self.block_cache.get_block(0).await?;
        let res = sb.block().get_at_offset::<Superblock>(0).free_blocks();
        Ok(res)
    }

    async fn flush(&mut self) -> Result<()> {
        self.block_cache.flush().await
    }

    fn num_blocks(&self) -> u64 {
        self.block_cache.total_blocks()
    }
}
