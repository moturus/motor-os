//! Transaction-log related routines here.
//!
//! Terminology: TXN is committed when it is written
//! to the txn log. TXN is checkpointed when the blocks
//! it modified are copied out of the txn log into the
//! main filesystem block area.

use crate::BLOCKS_IN_TXN_LOG;
use crate::BlockNo;
use crate::MAX_BLOCKS_IN_TXN;
use crate::MAX_TXNS_IN_LOG;
use crate::Superblock;
use async_fs::AsyncBlockDevice;
use async_fs::block_cache::BlockCache;
use async_fs::block_cache::CachedBlock;
use std::io::Result;

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
        let last_checkpointed_txn_id = superblock.last_checkpointed_txn_id();

        let mut this = Self {
            last_checkpointed_txn_id,
            next_txn_id: last_checkpointed_txn_id + 1,
            next_txn_idx: 0,
            txn_log_start,
        };

        drop(superblock_ref);

        this.replay_txn_log(block_cache).await?;

        Ok(this)
    }

    fn new_txn_id(&mut self) -> u128 {
        let result = self.next_txn_id;
        debug_assert!(self.last_checkpointed_txn_id < result);
        self.next_txn_id += 1;
        result
    }

    // Write each txn twice: once into the txn log, and then into the
    // main FS block area.
    pub(crate) async fn log_txn<BD: AsyncBlockDevice + 'static>(
        &mut self,
        block_cache: &mut BlockCache<BD>,
        mut txn_blocks: [Option<(BlockNo, CachedBlock)>; MAX_BLOCKS_IN_TXN],
    ) -> Result<()> {
        let mut blocks_in_txn = 0;
        let mut superblock_index = usize::MAX;

        for entry in &txn_blocks {
            let Some((block_no, _)) = entry else {
                break;
            };

            if block_no.as_u64() == 0 {
                superblock_index = blocks_in_txn;
            }
            blocks_in_txn += 1;
        }

        // Make sure the superblock is the last written ("commits" the transaction).
        if superblock_index == usize::MAX {
            superblock_index = blocks_in_txn;
            assert!(blocks_in_txn < MAX_BLOCKS_IN_TXN);
            blocks_in_txn += 1;

            let superblock = block_cache.get_block(0).await.unwrap();
            txn_blocks[superblock_index] = Some((BlockNo::from_u64(0), superblock));
        } else if superblock_index < (blocks_in_txn - 1) {
            // Make it last.
            txn_blocks.swap(superblock_index, blocks_in_txn - 1);
            superblock_index = blocks_in_txn - 1;
        }

        let this_txn_id = self.new_txn_id();
        let this_txn_idx = self.next_txn_idx % MAX_TXNS_IN_LOG as u64;
        self.next_txn_idx += 1;
        if self.next_txn_idx >= (MAX_TXNS_IN_LOG as u64) {
            self.next_txn_idx = 0;
        }

        let txn_area_start = self.txn_log_start + this_txn_idx * MAX_BLOCKS_IN_TXN as u64;

        // Prepare the superblock.
        let mut sb_block = txn_blocks[superblock_index].as_ref().unwrap().1.clone();
        let mut superblock_ref = sb_block.block_mut();
        let superblock = superblock_ref.get_mut_at_offset::<Superblock>(0);
        superblock.last_checkpointed_txn_id = this_txn_id;

        // Prepare txn log data and write blocks to the txn log.
        let txn_log_data = &mut superblock.txn_log_data[this_txn_idx as usize];
        for idx in 0..blocks_in_txn {
            txn_log_data.txn_blocks[idx] = txn_blocks[idx].as_ref().unwrap().0;
        }

        drop(superblock_ref);

        // Write to the txn log.
        /*
        for idx in 0..blocks_in_txn {
            block_cache
                .write_block(
                    txn_area_start + idx as u64,
                    txn_blocks[idx].as_ref().unwrap().1.clone(),
                )
                .await?;
        }
        block_cache.start_flushing().await; // REMOVE
        */

        // Write to the main data area.
        for idx in 0..blocks_in_txn {
            let (block_no, block) = txn_blocks[idx].take().unwrap();
            block_cache.write_block(block_no.as_u64(), block).await?;
        }
        block_cache.start_flushing().await; // REMOVE

        // if self.next_txn_idx == 0 {
        //     block_cache.start_flushing().await;
        // }

        #[cfg(debug_assertions)]
        block_cache.debug_check_clean();

        Ok(())
    }

    async fn replay_txn_log<BD: AsyncBlockDevice + 'static>(
        &mut self,
        block_cache: &mut BlockCache<BD>,
    ) -> Result<()> {
        let mut txns_to_replay = Vec::new();

        // First, find txns we need to replay.
        for idx in 0..MAX_TXNS_IN_LOG {
            let txn_area_start = self.txn_log_start + MAX_BLOCKS_IN_TXN as u64 * idx as u64;
            for block_idx in 0..MAX_BLOCKS_IN_TXN {
                let block = block_cache
                    .get_block(txn_area_start + block_idx as u64)
                    .await?;
                if block.block_no() != 0 {
                    continue;
                }

                let superblock_ref = block.block();
                let superblock = superblock_ref.get_at_offset::<Superblock>(0);
                let last_checkpointed_txn_id = superblock.last_checkpointed_txn_id();
                if last_checkpointed_txn_id <= self.last_checkpointed_txn_id {
                    break;
                }

                txns_to_replay.push((idx, last_checkpointed_txn_id));
                break;
            }
        }

        if txns_to_replay.is_empty() {
            return Ok(());
        }

        log::info!(
            "Motor FS txn log: {} transactions to replay.",
            txns_to_replay.len()
        );

        todo!()
        // Ok(())
    }
}
