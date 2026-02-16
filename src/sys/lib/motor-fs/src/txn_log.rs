//! Transaction-log related routines here.
//!
//! Terminology: TXN is committed when it is written
//! to the txn log. TXN is checkpointed when the blocks
//! it modified are copied out of the txn log into the
//! main filesystem block area.

use crate::BLOCKS_IN_TXN_LOG;
use crate::BlockNo;
use crate::MAX_BLOCKS_IN_TXN;
use crate::MotorFs;
use crate::Superblock;
use async_fs::AsyncBlockDevice;
use async_fs::block_cache::BlockCache;
use async_fs::block_cache::CachedBlock;
use std::io::{ErrorKind, Result};

// In-memory.
pub(crate) struct TxnLogger {
    last_checkpointed_txn_id: u128, // Committed to the main area.
    next_txn_id: u128,              // A future txn.
    next_txn_idx: u64,              // Where to put the future txn in the log area.
    txn_log_start: u64,
}

impl TxnLogger {
    pub(crate) fn new<BD: AsyncBlockDevice + 'static>(block_cache: &mut BlockCache<BD>) -> Self {
        let num_blocks = block_cache.total_blocks();
        let txn_log_start = num_blocks - BLOCKS_IN_TXN_LOG;

        Self {
            last_checkpointed_txn_id: 0,
            next_txn_id: 1,
            next_txn_idx: 0,
            txn_log_start,
        }
    }

    pub(crate) async fn open<BD: AsyncBlockDevice + 'static>(
        block_cache: &mut BlockCache<BD>,
    ) -> Result<Self> {
        let num_blocks = block_cache.total_blocks();
        let txn_log_start = num_blocks - BLOCKS_IN_TXN_LOG;

        let sb_block = block_cache.get_block(0).await?;
        let superblock_ref = sb_block.block();
        let superblock = superblock_ref.get_at_offset::<Superblock>(0);
        let last_committed_txn_id = superblock.last_committed_txn_id();

        Ok(Self {
            last_checkpointed_txn_id: last_committed_txn_id,
            next_txn_id: last_committed_txn_id + 1,
            next_txn_idx: 0,
            txn_log_start,
        })
    }

    fn new_txn_id(&mut self) -> u128 {
        let result = self.next_txn_id;
        debug_assert!(self.last_checkpointed_txn_id < result);
        self.next_txn_id += 1;
        result
    }
}

pub(crate) async fn log_txn<BD: AsyncBlockDevice + 'static>(
    fs: &mut MotorFs<BD>,
    txn_blocks: [Option<(BlockNo, CachedBlock)>; MAX_BLOCKS_IN_TXN],
) -> Result<()> {
    for entry in txn_blocks {
        let Some((block_no, block)) = entry else {
            break;
        };
        fs.block_cache()
            .write_block(block_no.as_u64(), block)
            .await?;
    }

    fs.block_cache().start_flushing().await;

    #[cfg(debug_assertions)]
    fs.block_cache().debug_check_clean();

    Ok(())
}
