//! Transaction-log related routines here.
//!
//! Terminology: TXN is committed when it is written
//! to the txn log. TXN is checkpointed when the blocks
//! it modified are copied out of the txn log into the
//! main filesystem block area.
//!
//! Algorithm:
//! (1) batch txns in-memory until reached BLOCKS_IN_TXN_LOG
//! (2) prepare superblock
//! (3) write all blocks in the txn log to the txn log on BD
//! (4) write block 0 in the txn log #0
//! (5) copy blocks from the txn log to the main block area
//! (6) writhe block 0

use crate::BlockNo;
use crate::MAX_BLOCKS_IN_TXN;
use crate::MAX_BLOCKS_IN_TXN_LOG;
use crate::Superblock;
use async_fs::AsyncBlockDevice;
use async_fs::block_cache::BlockCache;
use async_fs::block_cache::CachedBlock;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::io::Result;

// In-memory.
pub(crate) struct TxnLogger {
    last_checkpointed_txn_id: u64, // Committed to the main area.
    next_txn_id: u64,              // A future txn.
    txn_log_start: u64,

    superblock: CachedBlock,
    txn_batch: HashMap<u64, CachedBlock>,
}

impl TxnLogger {
    pub(crate) async fn new<BD: AsyncBlockDevice + 'static>(
        block_cache: &mut BlockCache<BD>,
    ) -> Result<Self> {
        let num_blocks = block_cache.total_blocks();
        let txn_log_start = num_blocks - MAX_BLOCKS_IN_TXN_LOG as u64;

        Ok(Self {
            last_checkpointed_txn_id: 0,
            next_txn_id: 1,
            superblock: block_cache.get_block(0).await?,
            txn_log_start,
            txn_batch: HashMap::new(),
        })
    }

    pub(crate) async fn open<BD: AsyncBlockDevice + 'static>(
        block_cache: &mut BlockCache<BD>,
    ) -> Result<Self> {
        let num_blocks = block_cache.total_blocks();
        let txn_log_start = num_blocks - MAX_BLOCKS_IN_TXN_LOG as u64;

        let sb_block = block_cache.get_block(0).await?;
        let superblock_ref = sb_block.block();
        let superblock = superblock_ref.get_at_offset::<Superblock>(0);
        let last_checkpointed_txn_id = superblock.txn_log_data.txn_id;
        drop(superblock_ref);

        let mut this = Self {
            last_checkpointed_txn_id,
            next_txn_id: last_checkpointed_txn_id + 1,
            superblock: sb_block,
            txn_log_start,
            txn_batch: HashMap::new(),
        };

        this.replay_txn_log(block_cache).await?;

        Ok(this)
    }

    fn new_txn_id(&mut self) -> u64 {
        let result = self.next_txn_id;
        debug_assert_eq!(self.last_checkpointed_txn_id, result - 1);
        self.next_txn_id += 1;
        result
    }

    // Write each txn twice: once into the txn log, and then into the
    // main FS block area.
    pub(crate) async fn log_txn<BD: AsyncBlockDevice + 'static>(
        &mut self,
        block_cache: &mut BlockCache<BD>,
        txn_blocks: [Option<(BlockNo, CachedBlock)>; MAX_BLOCKS_IN_TXN],
    ) -> Result<()> {
        let mut blocks_in_txn = 0;

        // First, check if we need to flush the log.
        for entry in &txn_blocks {
            let Some((block_no, block)) = entry else {
                break;
            };

            block.consume_dirty();
            if block_no.as_u64() == 0 {
                continue;
            }
            blocks_in_txn += 1;
        }

        if blocks_in_txn + self.txn_batch.len() >= MAX_BLOCKS_IN_TXN_LOG {
            self.flush_txn_batch(block_cache).await?;
            assert!(self.txn_batch.is_empty());
        }

        for entry in &txn_blocks {
            let Some((block_no, block)) = entry else {
                break;
            };

            if block_no.as_u64() == 0 {
                assert_eq!(self.superblock.unique_id(), block.unique_id());
                continue;
            }

            if let Some(prev) = self.txn_batch.insert(block_no.as_u64(), block.clone()) {
                assert_eq!(prev.unique_id(), block.unique_id());
            }
        }

        Ok(())
    }

    async fn replay_txn_log<BD: AsyncBlockDevice + 'static>(
        &mut self,
        block_cache: &mut BlockCache<BD>,
    ) -> Result<()> {
        let sb_main = block_cache.get_block(0).await?;
        let sb_in_log = block_cache.get_block(self.txn_log_start).await?;
        let sb_main_ref = sb_main.block();
        let sb_in_log_ref = sb_in_log.block();
        let superblock_main = sb_main_ref.get_at_offset::<Superblock>(0);
        let superblock_in_log = sb_in_log_ref.get_at_offset::<Superblock>(0);

        if superblock_main.txn_log_data.txn_id > superblock_in_log.txn_log_data.txn_id {
            log::error!("Motor FS: corrupted TXN log.");
            return Err(ErrorKind::InvalidData.into());
        }
        if superblock_main.txn_log_data.txn_id == superblock_in_log.txn_log_data.txn_id {
            log::warn!("Motor FS: empty TXN log: some data may be lost.");
            return Ok(());
        }
        if superblock_main.txn_log_data.txn_id + 1 != superblock_in_log.txn_log_data.txn_id {
            log::error!("Motor FS: corrupted TXN log.");
            return Err(ErrorKind::InvalidData.into());
        }

        todo!("")
    }

    async fn flush_txn_batch<BD: AsyncBlockDevice + 'static>(
        &mut self,
        block_cache: &mut BlockCache<BD>,
    ) -> Result<()> {
        assert!(self.txn_batch.len() < MAX_BLOCKS_IN_TXN_LOG);

        // First, flush the log.
        let txn_id = self.new_txn_id();
        let mut txn_batch = HashMap::new();
        core::mem::swap(&mut txn_batch, &mut self.txn_batch);
        let txn_log_start = self.txn_log_start;

        let mut sb_ref = self.superblock.block_mut();
        let sb = sb_ref.get_mut_at_offset::<Superblock>(0);
        sb.txn_log_data.clear();
        sb.txn_log_data.txn_id = txn_id;
        sb.txn_log_data.num_blocks = txn_batch.len() as u64;

        let mut idx = 1; // Start with "1" because "0" is for the superblock.
        for (block_no, block) in txn_batch.iter() {
            sb.txn_log_data.txn_blocks[idx] = *block_no;
            block_cache
                .write_block(txn_log_start + idx as u64, block.clone())
                .await?;

            idx += 1;
        }
        block_cache.start_flushing().await;
        drop(sb_ref);
        self.superblock.consume_dirty();

        // Commit the log.
        block_cache
            .write_block(txn_log_start, self.superblock.clone())
            .await?;
        block_cache.start_flushing().await;

        // Then flush blocks to the main area.
        for (block_no, block) in txn_batch.drain() {
            block_cache.write_block(block_no, block).await?;
        }

        block_cache.start_flushing().await;

        block_cache.write_block(0, self.superblock.clone()).await?;
        block_cache.start_flushing().await;

        self.last_checkpointed_txn_id = txn_id;

        Ok(())
    }

    pub(crate) async fn flush<BD: AsyncBlockDevice + 'static>(
        &mut self,
        block_cache: &mut BlockCache<BD>,
    ) -> Result<()> {
        self.flush_txn_batch(block_cache).await?;
        block_cache.flush().await?;
        Ok(())
        // todo!()
    }
}
