use crate::BlockNo;
use crate::MAX_BLOCKS_IN_TXN;
use crate::MotorFs;
use async_fs::block_cache::CachedBlock;
use std::io::{ErrorKind, Result};

pub(crate) async fn log_txn<BD: async_fs::AsyncBlockDevice + 'static>(
    fs: &mut MotorFs<BD>,
    txn_blocks: [Option<(BlockNo, CachedBlock)>; MAX_BLOCKS_IN_TXN],
) -> Result<()> {
    for entry in txn_blocks {
        let Some((block_no, block)) = entry else {
            break;
        };
        fs.block_cache().write_block_if_dirty(block).await?;
    }

    fs.block_cache().start_flushing().await;

    #[cfg(debug_assertions)]
    fs.block_cache().debug_check_clean();

    Ok(())
}
