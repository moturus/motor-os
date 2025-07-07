//! Each moderately complex FS operation is a transaction.
//!
//! Mutating transactions:
//! - create entry
//! - delete entry
//! - move entry
//! - write to file
//! - set file size
//!
//! Non-mutating operaions have txn type None.

use async_fs::{
    EntryKind,
    block_cache::{BlockCache, CachedBlock},
};

use crate::{BlockNo, DirEntryBlock, EntryIdInternal, MotorFs, ROOT_DIR_ID, Superblock, dir_entry};

use std::io::{ErrorKind, Result};

struct TxnBase<'a, const N: usize> {
    fs: &'a mut MotorFs,
    txn_cache: micromap::Map<BlockNo, CachedBlock, N>,
}

pub struct ReadOnlyTxn<'a> {
    txn_base: TxnBase<'a, 0>,
}

impl<'a> ReadOnlyTxn<'a> {
    fn block_cache<'b>(&'b mut self) -> &'b mut BlockCache {
        self.txn_base.fs.block_cache()
    }
}

pub(crate) struct CreateEntryTxn<'a> {
    txn_base: TxnBase<'a, 8>,
    parent_id: EntryIdInternal,
    kind: EntryKind,
    filename: &'a str,
}

impl<'a> CreateEntryTxn<'a> {
    fn block_cache<'b>(&'b mut self) -> &'b mut BlockCache {
        self.txn_base.fs.block_cache()
    }

    async fn commit<'b>(&'b mut self) -> Result<()> {
        log::warn!("{}:{} do a proper txn", file!(), line!());

        let TxnBase { fs, txn_cache } = &mut self.txn_base;

        // For now, just save all dirty blocks.
        for (block_no, block) in txn_cache.drain() {
            assert_eq!(block_no.as_u64(), block.block_no());
            fs.block_cache().push(block);
            fs.block_cache()
                .write_block_if_dirty(block_no.as_u64())
                .await?;
        }

        Ok(())
    }
}

pub(crate) struct DeleteEntryTxn<'a> {
    txn_base: TxnBase<'a, 8>,
    entry_id: EntryIdInternal,
}

impl<'a> DeleteEntryTxn<'a> {
    fn block_cache<'b>(&'b mut self) -> &'b mut BlockCache {
        self.txn_base.fs.block_cache()
    }

    async fn commit<'b>(&'b mut self) -> Result<()> {
        log::warn!("{}:{} do a proper txn", file!(), line!());

        let TxnBase { fs, txn_cache } = &mut self.txn_base;

        // For now, just save all dirty blocks.
        for (block_no, block) in txn_cache.drain() {
            assert_eq!(block_no.as_u64(), block.block_no());
            fs.block_cache().push(block);
            fs.block_cache()
                .write_block_if_dirty(block_no.as_u64())
                .await?;
        }

        Ok(())
    }
}

pub(crate) struct MoveEntryTxn<'a> {
    entry_id: EntryIdInternal,
    new_parent_id: EntryIdInternal,
    new_name: &'a str,
}

pub(crate) enum Txn<'a> {
    CreateEntry(CreateEntryTxn<'a>),
    DeleteEntry(DeleteEntryTxn<'a>),
    MoveEntry(MoveEntryTxn<'a>),
    ReadOnly(ReadOnlyTxn<'a>),
}

impl<'a> Txn<'a> {
    pub fn new_readonly(fs: &'a mut MotorFs) -> Self {
        Self::ReadOnly(ReadOnlyTxn {
            txn_base: TxnBase {
                fs,
                txn_cache: micromap::Map::new(),
            },
        })
    }

    pub async fn create_entry(
        fs: &'a mut MotorFs,
        parent_id: EntryIdInternal,
        kind: EntryKind,
        filename: &'a str,
    ) -> Result<EntryIdInternal> {
        let mut txn = Self::CreateEntry(CreateEntryTxn {
            txn_base: TxnBase {
                fs,
                txn_cache: micromap::Map::new(),
            },
            parent_id,
            kind,
            filename,
        });

        let parent_id: EntryIdInternal = parent_id.into();
        let hash = {
            // TODO: remove unsafe when NLL Problem #3 is solved.
            // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
            let this_txn = unsafe {
                let this = &mut txn as *mut Self;
                this.as_mut().unwrap_unchecked()
            };
            let parent_block = this_txn.get_block(parent_id.block_no).await?;
            dir_entry!(parent_block).validate_entry(parent_id)?;

            if dir_entry!(parent_block).kind() != EntryKind::Directory {
                return Err(ErrorKind::NotADirectory.into());
            }

            dir_entry!(parent_block).hash(filename)
        };

        let entry_id = Superblock::allocate_block(&mut txn).await?;
        DirEntryBlock::init_child_entry(&mut txn, parent_id, entry_id, kind, filename);
        DirEntryBlock::link_child_block(&mut txn, parent_id.block_no, entry_id.block_no, hash)
            .await?;
        DirEntryBlock::increment_dir_size(&mut txn, parent_id).await?;
        txn.commit().await?;
        Ok(entry_id)
    }

    pub async fn delete_entry(fs: &'a mut MotorFs, entry_id: EntryIdInternal) -> Result<()> {
        let mut txn = Self::DeleteEntry(DeleteEntryTxn {
            txn_base: TxnBase {
                fs,
                txn_cache: micromap::Map::new(),
            },
            entry_id,
        });

        let entry_id: EntryIdInternal = entry_id.into();
        if entry_id == ROOT_DIR_ID {
            return Err(ErrorKind::InvalidInput.into());
        }

        let parent_id = {
            // TODO: remove unsafe when NLL Problem #3 is solved.
            // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
            let this_txn = unsafe {
                let this = &mut txn as *mut Self;
                this.as_mut().unwrap_unchecked()
            };
            let entry_block = this_txn.get_block(entry_id.block_no).await?;
            dir_entry!(entry_block).validate_entry(entry_id)?;
            if dir_entry!(entry_block).metadata().size > 0 {
                return match dir_entry!(entry_block).kind() {
                    EntryKind::Directory => Err(ErrorKind::DirectoryNotEmpty.into()),
                    EntryKind::File => {
                        log::error!("TODO: implement deleting non-empty files.");
                        Err(ErrorKind::FileTooLarge.into())
                    }
                };
            }

            dir_entry!(entry_block).parent_id()
        };
        DirEntryBlock::delete_entry(&mut txn, parent_id, entry_id).await
    }

    pub async fn get_block(&'a mut self, block_no: BlockNo) -> std::io::Result<&'a CachedBlock> {
        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        let this = unsafe {
            let this = self as *mut Self;
            this.as_mut().unwrap_unchecked()
        };

        if let Some(txn_block) = match this {
            Txn::CreateEntry(create_entry_txn) => {
                create_entry_txn.txn_base.txn_cache.get(&block_no)
            }
            Txn::DeleteEntry(_txn) => todo!(),
            Txn::MoveEntry(_txn) => todo!(),
            Txn::ReadOnly(_) => None,
        } {
            return Ok(txn_block);
        }

        self.block_cache().get_block(block_no.as_u64()).await
    }

    /// Unlike get_block() above, get_txn_block() ensures the block is part of the transaction,
    /// i.e. will be saved in Txn::commit().
    pub async fn get_txn_block<'b>(
        &'b mut self,
        block_no: BlockNo,
    ) -> std::io::Result<&'b mut CachedBlock> {
        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        let this_1 = unsafe {
            let this = self as *mut Self;
            this.as_mut().unwrap_unchecked()
        };
        let this_2 = unsafe {
            let this = self as *mut Self;
            this.as_mut().unwrap_unchecked()
        };

        if let Some(txn_block) = match this_1 {
            Txn::CreateEntry(txn) => txn.txn_base.txn_cache.get_mut(&block_no),
            Txn::DeleteEntry(_txn) => todo!(),
            Txn::MoveEntry(_txn) => todo!(),
            Txn::ReadOnly(_) => panic!(),
        } {
            return Ok(txn_block);
        }

        let block = self.block_cache().get_block(block_no.as_u64()).await?;
        match this_2 {
            Txn::CreateEntry(txn) => txn.txn_base.txn_cache.insert(block_no, block.clone()),
            Txn::DeleteEntry(_txn) => todo!(),
            Txn::MoveEntry(_txn) => todo!(),
            Txn::ReadOnly(_) => panic!(),
        };

        // Recursion.
        let Some(txn_block) = (match this_2 {
            Txn::CreateEntry(txn) => txn.txn_base.txn_cache.get_mut(&block_no),
            Txn::DeleteEntry(_txn) => todo!(),
            Txn::MoveEntry(_txn) => todo!(),
            Txn::ReadOnly(_) => panic!(),
        }) else {
            panic!();
        };

        Ok(txn_block)
    }

    fn block_cache<'b>(&'b mut self) -> &'b mut BlockCache {
        match self {
            Txn::CreateEntry(txn) => txn.block_cache(),
            Txn::DeleteEntry(_txn) => todo!(),
            Txn::MoveEntry(_txn) => todo!(),
            Txn::ReadOnly(txn) => txn.block_cache(),
        }
    }

    pub fn get_empty_block_mut<'b>(&'b mut self, block_no: BlockNo) -> &'b mut CachedBlock {
        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        let this_1 = unsafe {
            let this = self as *mut Self;
            this.as_mut().unwrap_unchecked()
        };
        let this_2 = unsafe {
            let this = self as *mut Self;
            this.as_mut().unwrap_unchecked()
        };

        if let Some(txn_block) = match this_1 {
            Txn::CreateEntry(txn) => txn.txn_base.txn_cache.get_mut(&block_no),
            Txn::DeleteEntry(_txn) => todo!(),
            Txn::MoveEntry(_txn) => todo!(),
            Txn::ReadOnly(_) => panic!(),
        } {
            txn_block.block_mut().clear();
            return txn_block;
        }

        let block = self.block_cache().get_empty_block(block_no.as_u64());
        match this_2 {
            Txn::CreateEntry(txn) => txn.txn_base.txn_cache.insert(block_no, block.clone()),
            Txn::DeleteEntry(_txn) => todo!(),
            Txn::MoveEntry(_txn) => todo!(),
            Txn::ReadOnly(_) => panic!(),
        };

        // Recursion.
        let Some(txn_block) = (match this_2 {
            Txn::CreateEntry(txn) => txn.txn_base.txn_cache.get_mut(&block_no),
            Txn::DeleteEntry(_txn) => todo!(),
            Txn::MoveEntry(_txn) => todo!(),
            Txn::ReadOnly(_) => panic!(),
        }) else {
            panic!();
        };

        txn_block
    }

    async fn commit(&mut self) -> Result<()> {
        match self {
            Txn::CreateEntry(txn) => txn.commit().await?,
            Txn::DeleteEntry(_txn) => todo!(),
            Txn::MoveEntry(_txn) => todo!(),
            Txn::ReadOnly(_) => panic!(),
        }

        #[cfg(debug_assertions)]
        self.block_cache().debug_check_clean();

        Ok(())
    }
}
