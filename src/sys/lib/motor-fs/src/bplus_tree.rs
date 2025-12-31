//! B+ tree.
use crate::BTREE_NODE_OFFSET;
use crate::BTREE_NODE_ORDER;
use crate::BTREE_ROOT_OFFSET;
use crate::BTREE_ROOT_ORDER;
use crate::BlockHeader;
use crate::BlockNo;
use crate::Superblock;
use crate::Txn;
use bytemuck::Pod;
use std::io::ErrorKind;
use std::io::Result;

#[derive(Clone, Copy, Pod)]
#[repr(C, align(8))]
pub(crate) struct KV {
    /// Key is dir name hash for when children are dir entries,
    /// ond ffset for when children are file content bytes.
    pub key: u64,

    pub child_block_no: BlockNo,
}

unsafe impl bytemuck::Zeroable for KV {}

impl Default for KV {
    fn default() -> Self {
        Self {
            key: 0,
            child_block_no: BlockNo::null(),
        }
    }
}

/// B+ Tree node. Size: ORDER * 16 + 8.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub(crate) struct Node<const ORDER: usize> {
    num_keys: u8, // The number of keys in use.
    kind: u8,
    _padding: [u8; 6],
    kv: [KV; ORDER],
}

unsafe impl<const ORDER: usize> bytemuck::Zeroable for Node<ORDER> {}
unsafe impl<const ORDER: usize> bytemuck::Pod for Node<ORDER> {}

impl<const ORDER: usize> Node<ORDER> {
    const KIND_LEAF: u8 = 1;
    const KIND_ROOT: u8 = 2;

    pub fn init_new_root(&mut self) {
        self.num_keys = 0;
        self.kind = Self::KIND_ROOT | Self::KIND_LEAF;
    }

    fn offset_in_block() -> usize {
        match ORDER {
            BTREE_ROOT_ORDER => BTREE_ROOT_OFFSET,
            BTREE_NODE_ORDER => BTREE_NODE_OFFSET,
            val => panic!("Bad order {val}"),
        }
    }

    #[allow(unused)]
    fn is_root(&self) -> bool {
        self.kind & Self::KIND_ROOT != 0
    }

    fn is_leaf(&self) -> bool {
        self.kind & Self::KIND_LEAF != 0
    }

    fn is_full(&self) -> bool {
        self.num_keys == (ORDER as u8)
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

        if this.num_keys as usize > ORDER {
            log::error!("Bad B+ Tree Node {:?}(?).", this_block_no.as_u64());
            return Err(ErrorKind::InvalidData.into());
        }

        if this.num_keys == 0 {
            return Ok(None);
        }

        if this.is_leaf() {
            return Ok(Some(this.kv[0].child_block_no));
        }

        todo!()
    }

    pub async fn first_child_with_key(
        txn: &mut Txn<'_>,
        this_block_no: BlockNo,
        key: u64,
    ) -> Result<Option<BlockNo>> {
        let block = txn.get_block(this_block_no).await?;

        let (child_block_no, key) = {
            let block_ref = block.block();
            let node = block_ref.get_at_offset::<Self>(Self::offset_in_block());

            if node.num_keys as usize > ORDER {
                log::error!("Bad B+ Tree Node {:?}(?).", this_block_no.as_u64());
                return Err(ErrorKind::InvalidData.into());
            }

            if node.num_keys == 0 {
                return Ok(None);
            }

            if node.is_leaf() {
                return match node.kv[..(node.num_keys as usize)]
                    .binary_search_by_key(&key, |kv| kv.key)
                {
                    Ok(pos) => Ok(Some(node.kv[pos].child_block_no)),
                    Err(_) => Ok(None),
                };
            }

            // This is not a leaf -> go one step down.
            let pos =
                match node.kv[..(node.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key) {
                    Ok(pos) => pos,
                    Err(pos) => {
                        assert!(pos > 0);
                        pos - 1
                    }
                };

            let child_block_no = node.kv[pos].child_block_no;

            log::debug!(
                "first_child_with_key() recursive: key: {key}, child_block: {}",
                child_block_no.as_u64()
            );

            (child_block_no, key)
        };

        // Recursive call (modulo ORDER).
        Box::pin(Node::<BTREE_NODE_ORDER>::first_child_with_key(
            txn,
            child_block_no,
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

        if this.num_keys as usize > ORDER {
            log::error!("Bad B+ Tree Node {:?}(?).", this_block_no.as_u64());
            return Err(ErrorKind::InvalidData.into());
        }

        if this.num_keys == 0 {
            return Ok(None);
        }

        if this.is_leaf() {
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

    async fn split_root(txn: &mut Txn<'_>, root_block_no: BlockNo) -> Result<()> {
        assert_eq!(ORDER, BTREE_ROOT_ORDER);

        // Allocate two new blocks.
        let left_block_no = Superblock::allocate_block(txn).await?.block_no;
        let right_block_no = Superblock::allocate_block(txn).await?.block_no;

        // Get the root block.
        let root_block = txn.get_txn_block(root_block_no).await?;
        let mut root_block_ref = root_block.block_mut();
        let root = root_block_ref.get_mut_at_offset::<Self>(Self::offset_in_block());
        assert_eq!(root.num_keys as usize, ORDER);

        // Save data to copy.
        let root_entries = root.kv;
        let left_key = u64::MIN;
        let split_pos = (ORDER >> 1) + 1;
        assert!(split_pos <= u8::MAX as usize);
        let right_key = root_entries[split_pos].key;
        let leaf_flag = root.kind & Self::KIND_LEAF;

        log::debug!(
            "split_root(): root: {} key: {right_key} left: {} right: {}",
            root_block_no.as_u64(),
            left_block_no.as_u64(),
            right_block_no.as_u64()
        );

        // Update root.
        root.kind &= !Self::KIND_LEAF;
        root.num_keys = 2;
        root.kv[0].key = left_key;
        root.kv[0].child_block_no = left_block_no;
        root.kv[1].key = right_key;
        root.kv[1].child_block_no = right_block_no;

        core::mem::drop(root_block_ref);

        // Update the left block.
        let left_block = txn.get_empty_block_mut(left_block_no);
        let mut left_block_ref = left_block.block_mut();

        let bh = left_block_ref.get_mut_at_offset::<BlockHeader>(0);
        bh.set_block_type(crate::BlockType::TreeNode);

        let left_node =
            left_block_ref.get_mut_at_offset::<Node<BTREE_NODE_ORDER>>(BTREE_NODE_OFFSET);

        left_node.num_keys = split_pos as u8;
        left_node.kind = leaf_flag;
        left_node.kv[..split_pos].clone_from_slice(&root_entries[..split_pos]);

        core::mem::drop(left_block_ref);

        // Update the right block.
        let right_block = txn.get_empty_block_mut(right_block_no);
        let mut right_block_ref = right_block.block_mut();
        let right_node =
            right_block_ref.get_mut_at_offset::<Node<BTREE_NODE_ORDER>>(BTREE_NODE_OFFSET);

        right_node.num_keys = (BTREE_ROOT_ORDER - split_pos) as u8;
        right_node.kind = leaf_flag;
        right_node.kv[..(right_node.num_keys as usize)]
            .clone_from_slice(&root_entries[split_pos..]);

        Ok(())
    }

    async fn split_node(
        txn: &mut Txn<'_>,
        node_block_no: BlockNo,
        parent_node_block_no: BlockNo,
        level: u8,
    ) -> Result<()> {
        let is_root = parent_node_block_no.is_null();

        if is_root {
            assert_eq!(ORDER, BTREE_ROOT_ORDER);
            assert_eq!(level, 0);
            return Self::split_root(txn, node_block_no).await;
        } else {
            assert_eq!(ORDER, BTREE_NODE_ORDER);
            assert!(level > 0);
        }

        // Allocate a new block.
        let right_block_no = Superblock::allocate_block(txn).await?.block_no;

        // Get this block.
        let this_block = txn.get_txn_block(node_block_no).await?;

        let right_key = {
            let mut this_block_ref = this_block.block_mut();
            let this = this_block_ref.get_mut_at_offset::<Self>(Self::offset_in_block());
            assert!(this.is_full());

            // Save data to copy.
            let split_pos = (ORDER >> 1) + 1;
            assert!(split_pos <= u8::MAX as usize);

            // TODO: we don't need to copy all KV below; but the Rust version in use
            // as of 2025-08-15 won't allow to have `split_pos` as const and thus
            // initialize kv on stack, so we have this little inefficiency.
            let kv_entries = this.kv;
            let right_key = kv_entries[split_pos].key;
            let leaf_flag = this.kind & Self::KIND_LEAF;

            log::debug!(
                "split_node(): node: {} key: {right_key} right: {}",
                node_block_no.as_u64(),
                right_block_no.as_u64()
            );

            // Update this node.
            this.num_keys = split_pos as u8;
            core::mem::drop(this_block_ref);

            // Update the right block.
            // TODO: the code below is very similar to a piece in split_root().
            let right_block = txn.get_empty_block_mut(right_block_no);
            let mut right_block_ref = right_block.block_mut();
            let right_node =
                right_block_ref.get_mut_at_offset::<Node<BTREE_NODE_ORDER>>(BTREE_NODE_OFFSET);

            right_node.num_keys = (ORDER - split_pos) as u8;
            right_node.kind = leaf_flag;
            right_node.kv[..(right_node.num_keys as usize)]
                .clone_from_slice(&kv_entries[split_pos..]);

            right_key
        };

        // Insert the link to the new node into the parent.
        if level == 1 {
            // The parent is root.
            Node::<BTREE_ROOT_ORDER>::insert_kv(
                txn,
                parent_node_block_no,
                right_key,
                right_block_no,
            )
            .await
        } else {
            Node::<BTREE_NODE_ORDER>::insert_kv(
                txn,
                parent_node_block_no,
                right_key,
                right_block_no,
            )
            .await
        }
    }

    pub async fn insert_kv(
        txn: &mut Txn<'_>,
        node_block_no: BlockNo,
        key: u64,
        val: BlockNo,
    ) -> Result<()> {
        let node_block = txn.get_txn_block(node_block_no).await?;
        let mut node_ref_mut = node_block.block_mut();
        let node_mut = node_ref_mut.get_mut_at_offset::<Self>(Self::offset_in_block());
        assert!((node_mut.num_keys as usize) < ORDER);

        let Err(pos) =
            node_mut.kv[..(node_mut.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key)
        else {
            return Err(ErrorKind::AlreadyExists.into());
        };

        for idx in (pos..(node_mut.num_keys as usize)).rev() {
            node_mut.kv[idx + 1] = node_mut.kv[idx];
        }

        node_mut.kv[pos] = KV {
            key,
            child_block_no: val,
        };

        node_mut.num_keys += 1;
        Ok(())
    }

    // Inserts link `val` at `key`, returns the list of blocks to save.
    // Note: we split full nodes "preemptively", so that there is no need to
    // do cascading splits up the tree.
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn node_insert_link(
        txn: &mut Txn<'_>,
        node_block_no: BlockNo,
        key: u64,
        val: BlockNo,
        parent_node_block_no: BlockNo,
        level: u8,
    ) -> Result<()> {
        let node_block = txn.get_txn_block(node_block_no).await?;

        let child_block_no = {
            // We explicitly drop node_block_ref below. Clippy is reporting false positives.
            let node_block_ref = node_block.block();
            let node = node_block_ref.get_at_offset::<Self>(Self::offset_in_block());

            if node.is_full() {
                core::mem::drop(node_block_ref);
                Self::split_node(txn, node_block_no, parent_node_block_no, level).await?;

                // Because the split may result in the inserted link going to the sibling
                // node, we need to restart this op.
                return Err(ErrorKind::Interrupted.into());
            }

            if node.is_leaf() {
                core::mem::drop(node_block_ref);
                return Self::insert_kv(txn, node_block_no, key, val).await;
            }

            // This is not a leaf -> go one step down.
            let pos =
                match node.kv[..(node.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key) {
                    Ok(pos) => pos,
                    Err(pos) => {
                        assert!(pos > 0);
                        pos - 1
                    }
                };

            node.kv[pos].child_block_no
        };

        // Recursive call (modulo ORDER).
        Box::pin(Node::<BTREE_NODE_ORDER>::node_insert_link(
            txn,
            child_block_no,
            key,
            val,
            node_block_no,
            level + 1,
        ))
        .await
    }

    // Deletes link `val` at `key`.
    #[allow(clippy::await_holding_refcell_ref)]
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

        if this.is_leaf() {
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
