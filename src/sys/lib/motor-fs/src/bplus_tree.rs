//! B+ tree.
use async_fs::block_cache::CachedBlock;

use crate::BlockNo;
use crate::TreeNodeBlock;
use crate::Txn;
use std::io::ErrorKind;
use std::io::Result;

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct KV {
    /// Key is dir name hash for when children are dir entries,
    /// ond ffset for when children are file content bytes.
    pub key: u64,

    pub child_block_no: BlockNo,
}

impl Default for KV {
    fn default() -> Self {
        Self {
            key: 0,
            child_block_no: BlockNo::null(),
        }
    }
}

/// B+ Tree node. Size: ORDER * 16 + 24.
#[repr(C)]
pub(crate) struct Node<const ORDER: usize> {
    this: BlockNo,

    parent_node: BlockNo, // if parent.is_null(), this is root.
    num_keys: u8,         // The number of keys in use.
    is_leaf: u8,
    _padding: [u8; 6],
    kv: [KV; ORDER],
}

unsafe impl<const ORDER: usize> plain::Plain for Node<ORDER> {}

impl<const ORDER: usize> Node<ORDER> {
    pub fn this(&self) -> BlockNo {
        self.this
    }

    pub fn init_new_root(&mut self, this: BlockNo, parent: BlockNo) {
        self.this = this;
        self.parent_node = parent;
        self.num_keys = 0;
        self.is_leaf = 1;
    }

    pub async fn first_child(&self, txn: &mut Txn<'_>) -> Result<Option<BlockNo>> {
        todo!()
        // if self.num_keys as usize > ORDER || self.is_leaf > 1 {
        //     log::error!("Bad B+ Tree Node {:?}(?).", self.this);
        //     return Err(ErrorKind::InvalidData.into());
        // }

        // if self.num_keys == 0 {
        //     return Ok(None);
        // }

        // let first_child_block_no = self.kv[0].child_block_no;
        // if self.is_leaf == 1 {
        //     return Ok(Some(first_child_block_no));
        // }

        // // Recursion in an async fn requires boxing: rustc --explain E0733.
        // Box::pin(TreeNodeBlock::first_child(first_child_block_no, txn)).await
    }

    pub async fn first_child_with_key(
        &self,
        _ctx: &mut Txn<'_>,
        key: u64,
    ) -> Result<Option<BlockNo>> {
        if self.num_keys as usize > ORDER || self.is_leaf > 1 {
            log::error!("Bad B+ Tree Node {:?}(?).", self.this);
            return Err(ErrorKind::InvalidData.into());
        }

        if self.num_keys == 0 {
            return Ok(None);
        }

        if self.is_leaf == 1 {
            return match self.kv[..(self.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key)
            {
                Ok(pos) => Ok(Some(self.kv[pos].child_block_no)),
                Err(_) => Ok(None),
            };
        }

        todo!()
    }

    // Inserts link `val` at `key`, returns the list of blocks to save.
    pub async fn insert_link(
        txn: &mut Txn<'_>,
        node_block_no: BlockNo,
        node_offset_in_block: usize,
        key: u64,
        val: BlockNo,
    ) -> Result<()> {
        let node_block = txn.get_txn_block(node_block_no).await?;
        let node_block_ref = node_block.block();
        let node = node_block_ref.get_at_offset::<Self>(node_offset_in_block);

        if node.is_leaf == 1 {
            // Insert a link unconditionally (if there is space).
            if node.num_keys as usize == ORDER {
                // Have to split self.
                todo!()
            }

            let Err(pos) =
                node.kv[..(node.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key)
            else {
                return Err(ErrorKind::AlreadyExists.into());
            };

            core::mem::drop(node_block_ref);

            let mut node_ref_mut = node_block.block_mut();
            let node_mut = node_ref_mut.get_mut_at_offset::<Self>(node_offset_in_block);
            for idx in (pos..((node_mut.num_keys + 1) as usize)).rev() {
                node_mut.kv[idx + 1] = node_mut.kv[idx];
            }

            node_mut.kv[pos] = KV {
                key,
                child_block_no: val,
            };

            node_mut.num_keys += 1;
            return Ok(());
        }

        todo!()
    }

    // Deletes link `val` at `key`, returns the list of blocks to save.
    pub async fn delete_link(
        &mut self,
        ctx: &mut Txn<'_>,
        key: u64,
        block_no: BlockNo,
    ) -> Result<Vec<BlockNo>> {
        let mut result = vec![];

        if self.is_leaf == 1 {
            let Ok(pos) =
                self.kv[..(self.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key)
            else {
                return Err(ErrorKind::NotFound.into());
            };

            if self.kv[pos].child_block_no != block_no {
                log::error!(
                    "Node::delete_link(): bad link: {} vs {}.",
                    self.kv[pos].child_block_no.as_u64(),
                    block_no.as_u64()
                );
                return Err(ErrorKind::InvalidData.into());
            }

            for idx in pos..((self.num_keys - 1) as usize) {
                self.kv[idx] = self.kv[idx + 1];
            }

            self.num_keys -= 1;

            result.push(self.this);
            return Ok(result);
        }

        todo!()
    }
}
