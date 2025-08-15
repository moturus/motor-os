//! B+ tree.
use crate::BTREE_NODE_OFFSET;
use crate::BTREE_NODE_ORDER;
use crate::BTREE_ROOT_ORDER;
use crate::BlockNo;
use crate::Superblock;
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

    pub fn init_new_root(&mut self, this: BlockNo) {
        self.this = this;
        self.parent_node = BlockNo::null();
        self.num_keys = 0;
        self.is_leaf = 1;
    }

    pub async fn first_child<'a>(
        txn: &mut Txn<'a>,
        this_block_no: BlockNo,
        this_offset: usize,
    ) -> Result<Option<BlockNo>> {
        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        let this_txn = unsafe { (txn as *mut Txn).as_mut().unwrap_unchecked() };

        let block = this_txn.get_block(this_block_no).await?;
        let block_ref = block.block();
        let this = block_ref.get_at_offset::<Self>(this_offset);

        if this.num_keys as usize > ORDER || this.is_leaf > 1 {
            log::error!("Bad B+ Tree Node {:?}(?).", this.this);
            return Err(ErrorKind::InvalidData.into());
        }

        if this.num_keys == 0 {
            return Ok(None);
        }

        if this.is_leaf == 1 {
            return Ok(Some(this.kv[0].child_block_no));
        }

        todo!()
    }

    pub async fn first_child_with_key(
        txn: &mut Txn<'_>,
        this_block_no: BlockNo,
        this_offset: usize,
        key: u64,
    ) -> Result<Option<BlockNo>> {
        let block = txn.get_block(this_block_no).await?;
        let block_ref = block.block();
        let node = block_ref.get_at_offset::<Self>(this_offset);

        if node.num_keys as usize > ORDER || node.is_leaf > 1 {
            log::error!("Bad B+ Tree Node {:?}(?).", node.this);
            return Err(ErrorKind::InvalidData.into());
        }

        if node.num_keys == 0 {
            return Ok(None);
        }

        if node.is_leaf == 1 {
            return match node.kv[..(node.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key)
            {
                Ok(pos) => Ok(Some(node.kv[pos].child_block_no)),
                Err(_) => Ok(None),
            };
        }

        // This is not a leaf -> go one step down.
        let pos = match node.kv[..(node.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key)
        {
            Ok(pos) => pos,
            Err(pos) => {
                assert!(pos > 0);
                pos - 1
            }
        };

        let child_block_no = node.kv[pos].child_block_no;
        core::mem::drop(block_ref);

        log::debug!(
            "first_child_with_key() recursive: key: {key}, child_block: {}",
            child_block_no.as_u64()
        );

        // Recursive call (modulo ORDER).
        Box::pin(Node::<BTREE_NODE_ORDER>::first_child_with_key(
            txn,
            child_block_no,
            BTREE_NODE_OFFSET,
            key,
        ))
        .await
    }

    pub async fn next_child<'a>(
        txn: &mut Txn<'a>,
        this_block_no: BlockNo,
        this_offset: usize,
        key: u64,
    ) -> Result<Option<BlockNo>> {
        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        let this_txn = unsafe { (txn as *mut Txn).as_mut().unwrap_unchecked() };

        let block = this_txn.get_block(this_block_no).await?;
        let block_ref = block.block();
        let this = block_ref.get_at_offset::<Self>(this_offset);

        if this.num_keys as usize > ORDER || this.is_leaf > 1 {
            log::error!("Bad B+ Tree Node {:?}(?).", this.this);
            return Err(ErrorKind::InvalidData.into());
        }

        if this.num_keys == 0 {
            return Ok(None);
        }

        if this.is_leaf == 1 {
            return match this.kv[..(this.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key)
            {
                Ok(pos) => {
                    if pos < ((this.num_keys as usize) - 1) {
                        Ok(Some(this.kv[pos + 1].child_block_no))
                    } else {
                        Ok(None)
                    }
                }
                Err(_) => Ok(None),
            };
        }

        todo!()
    }

    async fn split_root(
        txn: &mut Txn<'_>,
        root_block_no: BlockNo,
        root_offset_in_block: usize,
    ) -> Result<()> {
        assert_eq!(ORDER, BTREE_ROOT_ORDER);

        // Allocate two new blocks.
        let left_block_no = Superblock::allocate_block(txn).await?.block_no;
        let right_block_no = Superblock::allocate_block(txn).await?.block_no;

        // Get the root block.
        let root_block = txn.get_txn_block(root_block_no).await?;
        let mut root_block_ref = root_block.block_mut();
        let root = root_block_ref.get_mut_at_offset::<Self>(root_offset_in_block);
        assert_eq!(root.num_keys as usize, ORDER);

        // Save root values for later use.
        let root_entries = root.kv;
        let left_key = u64::MIN;
        let split_pos = (ORDER >> 1) + 1;
        assert!(split_pos <= u8::MAX as usize);
        let right_key = root_entries[split_pos].key;

        log::debug!(
            "split_root(): root: {} key: {right_key} left: {} right: {}",
            root_block_no.as_u64(),
            left_block_no.as_u64(),
            right_block_no.as_u64()
        );

        // Update root.
        root.is_leaf = 0;
        root.num_keys = 2;
        root.kv[0].key = left_key;
        root.kv[0].child_block_no = left_block_no;
        root.kv[1].key = right_key;
        root.kv[1].child_block_no = right_block_no;

        core::mem::drop(root_block_ref);

        // Update the left block.
        let left_block = txn.get_empty_block_mut(left_block_no);
        let mut left_block_ref = left_block.block_mut();
        let left_node =
            left_block_ref.get_mut_at_offset::<Node<BTREE_NODE_ORDER>>(BTREE_NODE_OFFSET);

        left_node.this = left_block_no;
        left_node.parent_node = root_block_no;
        left_node.num_keys = split_pos as u8;
        left_node.is_leaf = 1;
        left_node.kv[..split_pos].clone_from_slice(&root_entries[..split_pos]);

        core::mem::drop(left_block_ref);

        // Update the right block.
        let right_block = txn.get_empty_block_mut(right_block_no);
        let mut right_block_ref = right_block.block_mut();
        let right_node =
            right_block_ref.get_mut_at_offset::<Node<BTREE_NODE_ORDER>>(BTREE_NODE_OFFSET);

        right_node.this = right_block_no;
        right_node.parent_node = root_block_no;
        right_node.num_keys = (BTREE_ROOT_ORDER - split_pos) as u8;
        right_node.is_leaf = 1;
        right_node.kv[..(right_node.num_keys as usize)]
            .clone_from_slice(&root_entries[split_pos..]);

        Ok(())
    }

    // Inserts link `val` at `key`, returns the list of blocks to save.
    pub async fn node_insert_link(
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
                if node.parent_node.is_null() {
                    // This is root.
                    core::mem::drop(node_block_ref);
                    Self::split_root(txn, node_block_no, node_offset_in_block).await?;

                    // Recursive call.
                    return Box::pin(Self::node_insert_link(
                        txn,
                        node_block_no,
                        node_offset_in_block,
                        key,
                        val,
                    ))
                    .await;
                } else {
                    todo!("Split a non-root node: key = {key}, order = {ORDER}.")
                }
            }

            let Err(pos) =
                node.kv[..(node.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key)
            else {
                return Err(ErrorKind::AlreadyExists.into());
            };

            core::mem::drop(node_block_ref);

            let mut node_ref_mut = node_block.block_mut();
            let node_mut = node_ref_mut.get_mut_at_offset::<Self>(node_offset_in_block);
            for idx in (pos..(node_mut.num_keys as usize)).rev() {
                node_mut.kv[idx + 1] = node_mut.kv[idx];
            }

            node_mut.kv[pos] = KV {
                key,
                child_block_no: val,
            };

            node_mut.num_keys += 1;
            return Ok(());
        }

        // This is not a leaf -> go one step down.
        let pos = match node.kv[..(node.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key)
        {
            Ok(pos) => pos,
            Err(pos) => {
                assert!(pos > 0);
                pos - 1
            }
        };

        let child_block_no = node.kv[pos].child_block_no;
        core::mem::drop(node_block_ref);

        // Recursive call (modulo ORDER).
        Box::pin(Node::<BTREE_NODE_ORDER>::node_insert_link(
            txn,
            child_block_no,
            BTREE_NODE_OFFSET,
            key,
            val,
        ))
        .await
    }

    // Deletes link `val` at `key`.
    pub async fn root_delete_link<'a>(
        txn: &mut Txn<'a>,
        this_block_no: BlockNo,
        this_offset: usize,
        key: u64,
        block_no: BlockNo,
    ) -> Result<()> {
        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        let this_txn = unsafe { (txn as *mut Txn).as_mut().unwrap_unchecked() };

        let block = this_txn.get_block(this_block_no).await?;
        let block_ref = block.block();
        let this = block_ref.get_at_offset::<Self>(this_offset);

        if this.is_leaf == 1 {
            let Ok(pos) =
                this.kv[..(this.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key)
            else {
                return Err(ErrorKind::NotFound.into());
            };

            if this.kv[pos].child_block_no != block_no {
                log::error!(
                    "Node::delete_link(): bad link: {} vs {}.",
                    this.kv[pos].child_block_no.as_u64(),
                    block_no.as_u64()
                );
                return Err(ErrorKind::InvalidData.into());
            }

            core::mem::drop(block_ref);

            let block = txn.get_txn_block(this_block_no).await?;
            let mut block_ref = block.block_mut();
            let this_mut = block_ref.get_mut_at_offset::<Self>(this_offset);
            for idx in pos..((this_mut.num_keys - 1) as usize) {
                this_mut.kv[idx] = this_mut.kv[idx + 1];
            }

            this_mut.num_keys -= 1;

            return Ok(());
        }

        todo!()
    }
}
