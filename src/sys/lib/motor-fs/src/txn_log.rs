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
//!
//! We also need a single long-running task to checkpoint
//! (= write to disk) tnx batches asynchronously:
//! - asynchronously because of timeouts
//! - a single task to serialize batch writing (to avoid
//!   out of order writes)

use crate::BlockNo;
use crate::MAX_BLOCKS_IN_TXN;
use crate::MAX_BLOCKS_IN_TXN_LOG;
use crate::MAX_FLUSH_DELAY_MS;
use crate::Superblock;
use crate::TxnLogData;
use async_fs::AsyncBlockDevice;
use async_fs::block_cache::BlockCache;
use async_fs::block_cache::CachedBlock;
use async_fs::block_cache::CheckpointedBlock;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::io::Result;
use std::rc::Rc;

#[cfg(target_os = "motor")]
use moto_async::Instant;
#[cfg(not(target_os = "motor"))]
use tokio::time::Instant;

struct TxnBatch {
    block_map: HashMap<u64, CheckpointedBlock>,
    txn_id: u64,
    started: Instant,
}

impl TxnBatch {
    fn new(txn_id: u64) -> Self {
        Self {
            block_map: HashMap::new(),
            txn_id,
            started: Instant::now(),
        }
    }

    fn renew(&mut self) -> Self {
        let mut taken = HashMap::new();
        core::mem::swap(&mut taken, &mut self.block_map);
        self.txn_id += 1;
        let started = self.started;
        self.started = Instant::now();

        Self {
            block_map: taken,
            txn_id: self.txn_id - 1,
            started,
        }
    }
}

type TxnBatchHolder = Rc<RefCell<TxnBatch>>;

enum CommitterMessage {
    TxnBatch(TxnBatch),

    #[cfg(target_os = "motor")]
    Flush(moto_async::oneshot::Sender<()>),

    #[cfg(not(target_os = "motor"))]
    Flush(tokio::sync::oneshot::Sender<()>),

    #[cfg(test)]
    SetErrorPct(u8),
}

#[cfg(target_os = "motor")]
type TxnBatchSender = moto_async::channel::Sender<CommitterMessage>;

#[cfg(not(target_os = "motor"))]
type TxnBatchSender = tokio::sync::mpsc::Sender<CommitterMessage>;

#[cfg(test)]
fn maybe_inject_test_error(error_pct: u8) -> Result<()> {
    use rand::RngCore;
    use rand::thread_rng;

    if error_pct == 0 {
        return Ok(());
    }

    let mut rng = thread_rng();

    let rng_val: u32 = rng.next_u32();
    if rng_val as f64 / (u32::MAX as f64) < (error_pct as f64) * 0.01 {
        log::warn!("MOTOR FS: Injecting an error.");
        Err(std::io::Error::from(ErrorKind::InvalidData))
    } else {
        Ok(())
    }
}

// In-memory.
pub(crate) struct TxnLogger {
    superblock: CachedBlock,
    txn_batch_holder: TxnBatchHolder,

    txn_batch_sink: TxnBatchSender,
    block_cache_stub: async_fs::block_cache::AsyncStub,
    replayed_log_on_open: bool,
}

impl TxnLogger {
    #[cfg(test)]
    pub(crate) async fn set_error_pct(&mut self, error_pct: u8) {
        self.txn_batch_sink
            .send(CommitterMessage::SetErrorPct(error_pct))
            .await
            .unwrap();
    }

    pub(crate) fn replayed_txn_log_on_open(&self) -> bool {
        self.replayed_log_on_open
    }

    fn txn_log_start(block_cache_stub: &async_fs::block_cache::AsyncStub) -> u64 {
        block_cache_stub.num_blocks() - MAX_BLOCKS_IN_TXN_LOG as u64
    }

    fn spawn_timeout_flusher(txn_batch_holder: TxnBatchHolder, sender: TxnBatchSender) {
        let holder_lock = txn_batch_holder.borrow();

        let timeout = holder_lock.started + std::time::Duration::from_millis(MAX_FLUSH_DELAY_MS);
        let txn_id = holder_lock.txn_id;
        drop(holder_lock);

        let timeout_task = async move {
            #[cfg(target_os = "motor")]
            moto_async::sleep_until(timeout).await;

            #[cfg(not(target_os = "motor"))]
            tokio::time::sleep_until(timeout).await;

            let mut holder_lock = txn_batch_holder.borrow_mut();
            if holder_lock.txn_id != txn_id {
                return;
            }

            if !holder_lock.block_map.is_empty() {
                let txn_batch = holder_lock.renew();
                drop(holder_lock);

                log::debug!("commiting batch {txn_id} on timeout");
                let _ = sender.send(CommitterMessage::TxnBatch(txn_batch)).await;
            }
        };

        #[cfg(target_os = "motor")]
        let _handle = moto_async::LocalRuntime::spawn(timeout_task);

        #[cfg(not(target_os = "motor"))]
        let _handle = tokio::task::spawn_local(timeout_task);
    }

    fn spawn_txn_committer_task(
        block_cache_stub: async_fs::block_cache::AsyncStub,
        txn_batch_holder: TxnBatchHolder,
    ) -> TxnBatchSender {
        let sender = {
            #[cfg(target_os = "motor")]
            let (sender, mut receiver) = moto_async::channel(2);

            #[cfg(not(target_os = "motor"))]
            let (sender, mut receiver) = tokio::sync::mpsc::channel(2);

            let committer_task = async move {
                #[cfg(test)]
                let mut error_pct = 0;

                while let Some(msg) = receiver.recv().await {
                    match msg {
                        CommitterMessage::TxnBatch(txn_batch) => {
                            if let Err(err) = Self::commit_txn_batch(
                                txn_batch,
                                block_cache_stub.clone(),
                                #[cfg(test)]
                                error_pct,
                            )
                            .await
                            {
                                log::error!("FS error: {err:?}.");
                                return;
                            }
                        }

                        CommitterMessage::Flush(sender) => {
                            let mut holder_lock = txn_batch_holder.borrow_mut();
                            if !holder_lock.block_map.is_empty() {
                                let txn_batch = holder_lock.renew();
                                drop(holder_lock);

                                if let Err(err) = Self::commit_txn_batch(
                                    txn_batch,
                                    block_cache_stub.clone(),
                                    #[cfg(test)]
                                    error_pct,
                                )
                                .await
                                {
                                    log::error!("FS error: {err:?}.");
                                    return;
                                }
                            }
                            log::debug!("Motor FS: flushing the Block Device.");
                            let _ = block_cache_stub.flush().await;
                            sender.send(()).unwrap();
                        }

                        #[cfg(test)]
                        CommitterMessage::SetErrorPct(val) => error_pct = val,
                    }
                }
            };

            #[cfg(target_os = "motor")]
            let _handle = moto_async::LocalRuntime::spawn(committer_task);

            #[cfg(not(target_os = "motor"))]
            let _handle = tokio::task::spawn_local(committer_task);

            sender
        };

        sender
    }

    pub(crate) async fn new<BD: AsyncBlockDevice + 'static>(
        block_cache: &mut BlockCache<BD>,
    ) -> Result<Self> {
        let txn_batch_holder = Rc::new(RefCell::new(TxnBatch::new(1)));
        let holder_clone = txn_batch_holder.clone();

        Ok(Self {
            superblock: block_cache.get_block(0).await?,
            txn_batch_holder,
            txn_batch_sink: Self::spawn_txn_committer_task(block_cache.async_stub(), holder_clone),
            block_cache_stub: block_cache.async_stub(),
            replayed_log_on_open: false,
        })
    }

    pub(crate) async fn open<BD: AsyncBlockDevice + 'static>(
        block_cache: &mut BlockCache<BD>,
    ) -> Result<Self> {
        let sb_block = block_cache.get_block(0).await?;
        let superblock_ref = sb_block.block();
        let superblock = superblock_ref.get_at_offset::<Superblock>(0);
        let last_checkpointed_txn_id = superblock.txn_log_data.txn_id;
        drop(superblock_ref);

        let txn_batch_holder = Rc::new(RefCell::new(TxnBatch::new(last_checkpointed_txn_id + 1)));
        let holder_clone = txn_batch_holder.clone();

        let mut this = Self {
            superblock: sb_block,
            txn_batch_holder,
            txn_batch_sink: Self::spawn_txn_committer_task(block_cache.async_stub(), holder_clone),
            block_cache_stub: block_cache.async_stub(),
            replayed_log_on_open: false,
        };

        this.replay_txn_log_if_needed(block_cache).await?;

        Ok(this)
    }

    async fn replay_txn_log_if_needed<BD: AsyncBlockDevice + 'static>(
        &mut self,
        block_cache: &mut BlockCache<BD>,
    ) -> Result<()> {
        let txn_log_start = Self::txn_log_start(&self.block_cache_stub);
        let sb_main = block_cache.get_block(0).await?;
        let sb_in_log = block_cache.get_block(txn_log_start).await?;
        let sb_main_ref = sb_main.block();
        let sb_in_log_ref = sb_in_log.block();
        let superblock_main = sb_main_ref.get_at_offset::<Superblock>(0);
        let superblock_in_log = sb_in_log_ref.get_at_offset::<Superblock>(0);

        let main_txn_id = superblock_main.txn_log_data.txn_id;
        let last_logged_txn_id = superblock_in_log.txn_log_data.txn_id;

        if main_txn_id == last_logged_txn_id {
            // There could be something in txn log, but we can't recover it.
            // The main area is clean.
            return Ok(());
        }

        if main_txn_id + 1 != last_logged_txn_id {
            log::error!(
                "Motor FS: corrupted TXN log:\n\tmain txn id {main_txn_id} vs last logged txn id {last_logged_txn_id}."
            );
            return Err(ErrorKind::InvalidData.into());
        }

        // The last TXN was committed to the txn log, but not to the main block area.
        // We must replay the txn, otherwise the main block area may contain partial
        // transacitons.
        log::info!("Motor FS: replaying TXN log.");
        self.replayed_log_on_open = true;

        let txn_log_data = superblock_in_log.txn_log_data;
        drop(sb_main_ref);
        drop(sb_in_log_ref);

        let mut txn_batch = self.txn_batch_holder.borrow_mut().renew();
        assert_eq!(txn_batch.txn_id, last_logged_txn_id);
        assert!(txn_batch.block_map.is_empty());
        let num_blocks = txn_log_data.num_blocks;
        if num_blocks > MAX_BLOCKS_IN_TXN_LOG as u64 {
            log::error!("Motor FS: corrupted TXN log:\n\ttoo many blocks: {num_blocks}.");
            return Err(ErrorKind::InvalidData.into());
        }

        for idx in 0..num_blocks {
            let block_no = txn_log_data.txn_blocks[idx as usize];
            let block_in_txn_log = block_cache.get_block(txn_log_start + idx).await?;
            let mut block_in_main = block_cache.get_block(block_no).await?;
            *block_in_main.block_mut() = *block_in_txn_log.block();
            block_in_main.consume_dirty();

            txn_batch
                .block_map
                .insert(block_no, CheckpointedBlock::new(&block_in_main));
        }

        self.txn_batch_sink
            .send(CommitterMessage::TxnBatch(txn_batch))
            .await
            .map_err(|_err| std::io::Error::from(ErrorKind::NotConnected))
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

        if blocks_in_txn + self.txn_batch_holder.borrow().block_map.len() >= MAX_BLOCKS_IN_TXN_LOG {
            // Create a new txn batch, send the old one to be committed to disk.
            let prev = self.txn_batch_holder.borrow_mut().renew();
            self.txn_batch_sink
                .send(CommitterMessage::TxnBatch(prev))
                .await
                .map_err(|_err| std::io::Error::from(ErrorKind::NotConnected))?;
        }

        let mut txn_batch = self.txn_batch_holder.borrow_mut();
        let need_to_spawn_watcher = txn_batch.block_map.is_empty();

        for entry in &txn_blocks {
            let Some((block_no, block)) = entry else {
                break;
            };

            if block_no.as_u64() == 0 {
                debug_assert_eq!(self.superblock.unique_id(), block.unique_id());
                continue;
            }

            txn_batch
                .block_map
                .insert(block_no.as_u64(), CheckpointedBlock::new(block));
        }
        txn_batch
            .block_map
            .insert(0, CheckpointedBlock::new(&self.superblock));

        drop(txn_batch);

        if need_to_spawn_watcher {
            Self::spawn_timeout_flusher(self.txn_batch_holder.clone(), self.txn_batch_sink.clone());
        }

        Ok(())
    }

    async fn commit_txn_batch(
        mut txn_batch: TxnBatch,
        block_cache_stub: async_fs::block_cache::AsyncStub,
        #[cfg(test)] error_pct: u8,
    ) -> Result<()> {
        use bytemuck::Zeroable;

        // First, flush the log.
        assert!(txn_batch.block_map.len() < MAX_BLOCKS_IN_TXN_LOG);
        assert!(!txn_batch.block_map.is_empty());

        let txn_log_start = Self::txn_log_start(&block_cache_stub);

        let mut txn_log_data = TxnLogData::zeroed();

        txn_log_data.txn_id = txn_batch.txn_id;
        txn_log_data.num_blocks = txn_batch.block_map.len() as u64;
        txn_log_data.txn_blocks[0] = 0;

        let mut sb = txn_batch.block_map.remove(&0).unwrap();

        let mut idx = 1; // Start with "1" because "0" is for the superblock.
        for (block_no, block) in txn_batch.block_map.iter() {
            txn_log_data.txn_blocks[idx] = *block_no;

            #[cfg(test)]
            maybe_inject_test_error(error_pct)?;

            block_cache_stub
                .write_block(txn_log_start + idx as u64, block.clone())
                .await?;
            idx += 1;
        }

        #[cfg(test)]
        maybe_inject_test_error(error_pct)?;

        block_cache_stub.commit().await;
        sb.block_mut()
            .get_mut_at_offset::<Superblock>(0)
            .txn_log_data = txn_log_data;

        #[cfg(test)]
        maybe_inject_test_error(error_pct)?;

        // Commit the log.
        block_cache_stub
            .write_block(txn_log_start, sb.clone())
            .await?;

        #[cfg(test)]
        maybe_inject_test_error(error_pct)?;

        block_cache_stub.commit().await;

        // Then flush blocks to the main area.
        for (block_no, block) in txn_batch.block_map.drain() {
            #[cfg(test)]
            maybe_inject_test_error(error_pct)?;

            block_cache_stub.write_block(block_no, block).await?;
        }

        #[cfg(test)]
        maybe_inject_test_error(error_pct)?;

        block_cache_stub.commit().await;
        block_cache_stub.write_block(0, sb).await?;

        #[cfg(test)]
        maybe_inject_test_error(error_pct)?;

        block_cache_stub.commit().await;

        Ok(())
    }

    pub(crate) async fn flush(&mut self) -> Result<()> {
        #[cfg(target_os = "motor")]
        let (sender, receiver) = moto_async::oneshot();

        #[cfg(not(target_os = "motor"))]
        let (sender, receiver) = tokio::sync::oneshot::channel();

        self.txn_batch_sink
            .send(CommitterMessage::Flush(sender))
            .await
            .map_err(|_err| std::io::Error::from(ErrorKind::NotConnected))?;

        // Need to wait for flush to complete.
        receiver
            .await
            .map_err(|_err| std::io::Error::from(ErrorKind::NotConnected))
    }
}
