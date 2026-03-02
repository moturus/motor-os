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
// use crate::MAX_FLUSH_DELAY_MS;
use crate::Superblock;
use crate::TxnLogData;
use async_fs::AsyncBlockDevice;
use async_fs::block_cache::BlockCache;
use async_fs::block_cache::CachedBlock;
use async_fs::block_cache::FlushingBlock;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::io::Result;
use std::rc::Rc;
// use std::time::Instant;

#[cfg(target_os = "motor")]
type LocalMutex<T> = moto_async::LocalMutex<T>;

#[cfg(not(target_os = "motor"))]
type LocalMutex<T> = tokio::sync::Mutex<T>;

// In-memory.
pub(crate) struct TxnLogger {
    last_checkpointed_txn_id: u64, // Committed to the main area.
    next_txn_id: u64,              // A future txn.
    txn_log_start: u64,

    superblock: CachedBlock,
    txn_batch: Rc<LocalMutex<HashMap<u64, FlushingBlock>>>,

    block_cache_stub: async_fs::block_cache::AsyncStub,
}

impl TxnLogger {
    pub(crate) async fn new<BD: AsyncBlockDevice + 'static>(
        block_cache: &mut BlockCache<BD>,
    ) -> Result<Self> {
        let num_blocks = block_cache.total_blocks();
        let txn_log_start = num_blocks - MAX_BLOCKS_IN_TXN_LOG as u64;

        let txn_batch = Rc::new(LocalMutex::new(HashMap::new()));

        Ok(Self {
            last_checkpointed_txn_id: 0,
            next_txn_id: 1,
            superblock: block_cache.get_block(0).await?,
            txn_log_start,
            txn_batch,
            block_cache_stub: block_cache.async_stub(),
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

        let txn_batch = Rc::new(LocalMutex::new(HashMap::new()));

        let mut this = Self {
            last_checkpointed_txn_id,
            next_txn_id: last_checkpointed_txn_id + 1,
            superblock: sb_block,
            txn_log_start,
            txn_batch,
            block_cache_stub: block_cache.async_stub(),
        };

        this.replay_txn_log(block_cache).await?;

        Ok(this)
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

        let main_txn_id = superblock_main.txn_log_data.txn_id;
        let last_logged_txn_id = superblock_in_log.txn_log_data.txn_id;

        if main_txn_id > last_logged_txn_id {
            log::error!(
                "Motor FS: corrupted TXN log:\n\tmain txn id {main_txn_id} vs last logged txn id {last_logged_txn_id}."
            );
            return Err(ErrorKind::InvalidData.into());
        }
        if main_txn_id == last_logged_txn_id {
            log::warn!("Motor FS: empty TXN log: some data may be lost.");
            return Ok(());
        }
        if main_txn_id + 1 != last_logged_txn_id {
            log::error!(
                "Motor FS: corrupted TXN log:\n\tmain txn id {main_txn_id} vs last logged txn id {last_logged_txn_id}."
            );
            return Err(ErrorKind::InvalidData.into());
        }

        todo!("")
    }

    fn new_txn_id(&mut self) -> u64 {
        let result = self.next_txn_id;
        debug_assert_eq!(self.last_checkpointed_txn_id, result - 1);
        self.next_txn_id += 1;
        result
    }

    // Write each txn twice: once into the txn log, and then into the
    // main FS block area.
    pub(crate) async fn log_txn(
        &mut self,
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

        if blocks_in_txn + self.txn_batch.lock().await.len() >= MAX_BLOCKS_IN_TXN_LOG {
            self.flush_txn_batch().await?;
            debug_assert!(self.txn_batch.lock().await.is_empty());
        }

        let mut txn_batch = self.txn_batch.lock().await;

        for entry in &txn_blocks {
            let Some((block_no, block)) = entry else {
                break;
            };

            if block_no.as_u64() == 0 {
                assert_eq!(self.superblock.unique_id(), block.unique_id());
                continue;
            }

            txn_batch.insert(block_no.as_u64(), FlushingBlock::new(block));
        }
        txn_batch.insert(0, FlushingBlock::new(&self.superblock));

        Ok(())
    }

    async fn flush_txn_batch(&mut self) -> Result<()> {
        use bytemuck::Zeroable;

        // First, flush the log.
        let txn_id = self.new_txn_id();
        let mut txn_batch = HashMap::new();
        core::mem::swap(&mut txn_batch, &mut *self.txn_batch.lock().await);
        assert!(txn_batch.len() < MAX_BLOCKS_IN_TXN_LOG);

        let txn_log_start = self.txn_log_start;

        let mut sb = txn_batch.remove(&0).unwrap();
        let mut txn_log_data = TxnLogData::zeroed();

        // let mut sb_ref = self.superblock.block_mut();
        // let sb = sb_ref.get_mut_at_offset::<Superblock>(0);
        // sb.txn_log_data.clear();
        txn_log_data.txn_id = txn_id;
        txn_log_data.num_blocks = txn_batch.len() as u64;
        txn_log_data.txn_blocks[0] = 0;

        let mut idx = 1; // Start with "1" because "0" is for the superblock.
        for (block_no, block) in txn_batch.iter() {
            txn_log_data.txn_blocks[idx] = *block_no;
            self.block_cache_stub
                .write_block(txn_log_start + idx as u64, block.clone())
                .await?;
            idx += 1;
        }
        self.block_cache_stub.commit().await;
        sb.block_mut()
            .get_mut_at_offset::<Superblock>(0)
            .txn_log_data = txn_log_data;

        // Commit the log.
        self.block_cache_stub
            .write_block(txn_log_start, sb.clone())
            .await?;
        self.block_cache_stub.commit().await;

        // Then flush blocks to the main area.
        for (block_no, block) in txn_batch.drain() {
            self.block_cache_stub.write_block(block_no, block).await?;
        }

        self.block_cache_stub.commit().await;
        self.block_cache_stub.write_block(0, sb).await?;
        self.block_cache_stub.commit().await;

        self.last_checkpointed_txn_id = txn_id;

        Ok(())
    }

    pub(crate) async fn flush(&mut self) -> Result<()> {
        self.flush_txn_batch().await?;
        self.block_cache_stub.flush().await?;
        Ok(())
    }
}
