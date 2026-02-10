//! B+ tree.
use crate::BTREE_NODE_OFFSET;
use crate::BTREE_NODE_ORDER; // = 253
use crate::BTREE_ROOT_OFFSET;
use crate::BTREE_ROOT_ORDER; // = 226
use crate::BlockHeader;
use crate::BlockNo;
use crate::Superblock;
use crate::Txn;
use async_fs::AsyncBlockDevice;
use bytemuck::Pod;
use std::io::ErrorKind;
use std::io::Result;

// Note: we keep min keys at less than half to prevent insert/delete thrashing.
// TODO: figure out the best value for this constant.
// Note: because root nodes and non-root nodes have different orders,
// we need to have min keys less than half the root node order, to avoid complexity.
const BTREE_NODE_MIN_KEYS: usize = BTREE_ROOT_ORDER / 2 - 5; // = 108

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

pub(crate) type RootNode = Node<BTREE_ROOT_ORDER>;
pub(crate) type NonRootNode = Node<BTREE_NODE_ORDER>;

impl<const ORDER: usize> Node<ORDER> {
    const KIND_LEAF: u8 = 1;
    const KIND_ROOT: u8 = 2;

    const fn order() -> usize {
        ORDER
    }

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

    /// Get the (key, block_no) of the first child, if any.
    pub async fn first_child<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        this_block_no: BlockNo,
    ) -> Result<Option<KV>> {
        let block = txn.get_block(this_block_no).await?;
        let block_ref = block.block();
        let this = block_ref.get_at_offset::<Self>(Self::offset_in_block());

        if this.num_keys as usize > ORDER {
            log::error!("Bad B+ Tree Node {:?}(?).", this_block_no.as_u64());
            return Err(ErrorKind::InvalidData.into());
        }

        if this.num_keys == 0 {
            return Ok(None);
        }

        if this.is_leaf() {
            return Ok(Some(this.kv[0]));
        }

        let child_block_no = this.kv[0].child_block_no;
        // Recursive call (modulo ORDER).
        Box::pin(NonRootNode::first_child(txn, child_block_no)).await
    }

    pub async fn first_child_with_key<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
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
            (child_block_no, key)
        };

        // Recursive call (modulo ORDER).
        Box::pin(NonRootNode::first_child_with_key(txn, child_block_no, key)).await
    }

    pub async fn next_child<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        this_block_no: BlockNo,
        this_offset: usize,
        key: u64,
    ) -> Result<Option<BlockNo>> {
        let block = txn.get_block(this_block_no).await?;
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

    async fn split_node<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        node_block_no: BlockNo,
        parent_node_block_no: BlockNo,
        level: u8,
    ) -> Result<()> {
        let is_root = parent_node_block_no.is_null();

        if is_root {
            assert_eq!(ORDER, BTREE_ROOT_ORDER);
            assert_eq!(level, 0);
            return RootNode::split_root(txn, node_block_no).await;
        } else {
            assert_eq!(ORDER, BTREE_NODE_ORDER);
            assert!(level > 0);
        }

        // Allocate a new block.
        let right_block_no = Superblock::allocate_block(txn).await?.block_no;

        // Get this block.
        let mut this_block = txn.get_block(node_block_no).await?;

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

            // Update this node.
            this.num_keys = split_pos as u8;
            core::mem::drop(this_block_ref);

            // Update the right block.
            // TODO: the code below is very similar to a piece in split_root().
            let mut right_block = txn.get_empty_block_mut(right_block_no);
            let mut right_block_ref = right_block.block_mut();
            let right_node = right_block_ref.get_mut_at_offset::<NonRootNode>(BTREE_NODE_OFFSET);

            right_node.num_keys = (ORDER - split_pos) as u8;
            right_node.kind = leaf_flag;
            right_node.kv[..(right_node.num_keys as usize)]
                .clone_from_slice(&kv_entries[split_pos..]);

            right_key
        };

        // Insert the link to the new node into the parent.
        if level == 1 {
            // The parent is root.
            RootNode::insert_kv(txn, parent_node_block_no, right_key, right_block_no).await
        } else {
            NonRootNode::insert_kv(txn, parent_node_block_no, right_key, right_block_no).await
        }
    }

    async fn insert_kv<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        node_block_no: BlockNo,
        key: u64,
        val: BlockNo,
    ) -> Result<()> {
        let mut node_block = txn.get_block(node_block_no).await?;
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
    pub async fn node_insert_link<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        node_block_no: BlockNo,
        key: u64,
        val: BlockNo,
        parent_node_block_no: BlockNo,
        level: u8,
    ) -> Result<()> {
        let node_block = txn.get_block(node_block_no).await?;

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
        Box::pin(NonRootNode::node_insert_link(
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
    // Returns KV from _this_block_no_ to be removed, if any.
    #[allow(clippy::await_holding_refcell_ref)]
    async fn node_delete_link<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        this_block_no: BlockNo,
        key: u64,
        block_no_to_delete: BlockNo,
        parent_node_block_no: BlockNo,
        level: u8,
    ) -> Result<Option<(u64, BlockNo)>> {
        let block = txn.get_block(this_block_no).await?;
        let block_ref = block.block();
        let this = block_ref.get_at_offset::<Self>(Self::offset_in_block());

        let pos = match this.kv[..(this.num_keys as usize)].binary_search_by_key(&key, |kv| kv.key)
        {
            Ok(pos) => pos,
            Err(pos) => {
                if pos == 0 {
                    log::error!("node_delete_link(): not found");
                    return Err(ErrorKind::NotFound.into());
                }
                pos - 1
            }
        };

        if this.is_leaf() {
            if this.kv[pos].child_block_no != block_no_to_delete {
                log::error!(
                    "Node::delete_link(): bad link: {} vs {}.",
                    this.kv[pos].child_block_no.as_u64(),
                    block_no_to_delete.as_u64()
                );
                return Err(ErrorKind::InvalidData.into());
            }

            core::mem::drop(block_ref);

            let mut block = txn.get_block(this_block_no).await?;
            let mut block_ref = block.block_mut();
            let this_mut = block_ref.get_mut_at_offset::<Self>(Self::offset_in_block());
            for idx in pos..((this_mut.num_keys - 1) as usize) {
                this_mut.kv[idx] = this_mut.kv[idx + 1];
            }

            this_mut.num_keys -= 1;

            if !this_mut.is_root() && (usize::from(this_mut.num_keys) < BTREE_NODE_MIN_KEYS) {
                core::mem::drop(block_ref);

                return NonRootNode::fix_node_underflow(
                    txn,
                    this_block_no,
                    parent_node_block_no,
                    level,
                )
                .await;
            }
            return Ok(None);
        }

        // Need to go down.
        let child_block_no = this.kv[pos].child_block_no;
        core::mem::drop(block_ref);

        // Recursive call (modulo ORDER).
        if let Some((key, node_block_no)) = Box::pin(NonRootNode::node_delete_link(
            txn,
            child_block_no,
            key,
            block_no_to_delete,
            this_block_no,
            level + 1,
        ))
        .await?
        {
            // log::debug!(
            //     "node_delete_link: block {} at key {key} and level {} has expired",
            //     node_block_no.as_u64(),
            //     level + 1
            // );

            // Remove {key, node_block_no} from this.
            let mut block = txn.get_block(this_block_no).await?;
            let mut block_ref = block.block_mut();
            let this_mut = block_ref.get_mut_at_offset::<Self>(Self::offset_in_block());

            let pos = match this_mut.kv[..(this_mut.num_keys as usize)]
                .binary_search_by_key(&key, |kv| kv.key)
            {
                Ok(pos) => pos,
                Err(pos) => {
                    assert!(pos > 0);
                    pos - 1
                }
            };

            for idx in pos..((this_mut.num_keys - 1) as usize) {
                this_mut.kv[idx] = this_mut.kv[idx + 1];
            }

            this_mut.num_keys -= 1;

            Superblock::free_single_block(txn, node_block_no).await?;

            // We don't bother fixing root node underflow here. We let the number
            // of root children go down to one, and then if the child underflows,
            // we just copy it into the parent.
            if !this_mut.is_root() && (usize::from(this_mut.num_keys) < BTREE_NODE_MIN_KEYS) {
                core::mem::drop(block_ref);

                return NonRootNode::fix_node_underflow(
                    txn,
                    this_block_no,
                    parent_node_block_no,
                    level,
                )
                .await;
            }
            return Ok(None);
        } else {
            Ok(None)
        }
    }

    // Fixes the underflow of this_block_no. Returns, optionally, the key and block no
    // of the link that should be removed in the parent.
    #[allow(clippy::await_holding_refcell_ref)]
    async fn fix_node_underflow<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        this_block_no: BlockNo,
        parent_node_block_no: BlockNo,
        level: u8,
    ) -> Result<Option<(u64, BlockNo)>> {
        assert!(level > 0);
        assert!(!parent_node_block_no.is_null());

        // Either move keys from siblings that have keys to spare, or merge with a sibling
        // if can't borrow any keys. Merging will trigger a key removal in the parent, which
        // may result in the undeflow and thus a recursive call here.

        let block = txn.get_block(this_block_no).await?;
        let block_ref = block.block();
        let this = block_ref.get_at_offset::<Self>(Self::offset_in_block());
        assert_eq!(this.num_keys as usize, BTREE_NODE_MIN_KEYS - 1);
        let this_first_key = this.kv[0].key;
        let this_last_key = this.kv[(this.num_keys - 1) as usize].key;

        drop(block_ref);
        drop(block);

        // log::debug!(
        //     "fix_node_underflow: this: {} parent: {} level: {level} this_first_key: {this_first_key} this_last_key: {this_last_key}",
        //     this_block_no.as_u64(),
        //     parent_node_block_no.as_u64()
        // );

        // Try rebalance left.
        if level > 1 {
            if Self::try_rebalance_left(txn, parent_node_block_no, this_block_no, this_first_key)
                .await?
            {
                return Ok(None);
            }
        } else {
            if RootNode::try_rebalance_left(
                txn,
                parent_node_block_no,
                this_block_no,
                this_first_key,
            )
            .await?
            {
                return Ok(None);
            }
        }

        // Try rebalance right.
        if level > 1 {
            if Self::try_rebalance_right(txn, parent_node_block_no, this_block_no, this_last_key)
                .await?
            {
                return Ok(None);
            }
        } else {
            if RootNode::try_rebalance_right(
                txn,
                parent_node_block_no,
                this_block_no,
                this_last_key,
            )
            .await?
            {
                return Ok(None);
            }
        }

        // Try merge left. Either merge left or merge right will succeed.
        if level > 1 {
            if let Some(kv) =
                Self::try_merge_left(txn, parent_node_block_no, this_block_no, this_first_key)
                    .await?
            {
                return Ok(Some(kv));
            }
        } else {
            if let Some(kv) =
                RootNode::try_merge_left(txn, parent_node_block_no, this_block_no, this_first_key)
                    .await?
            {
                return Ok(Some(kv));
            }
        }

        // Try merge right. Either merge left or merge right will succeed.
        if level > 1 {
            if let Some(kv) =
                Self::try_merge_right(txn, parent_node_block_no, this_block_no, this_last_key)
                    .await?
            {
                return Ok(Some(kv));
            }
        } else {
            if let Some(kv) =
                RootNode::try_merge_right(txn, parent_node_block_no, this_block_no, this_last_key)
                    .await?
            {
                return Ok(Some(kv));
            }
        }

        // Nothing worked. This means that this node is the only child of a root node.
        // Just move things up.
        assert_eq!(level, 1);
        RootNode::assimilate_single_child(txn, parent_node_block_no, this_block_no).await?;
        Ok(None)
    }

    async fn try_rebalance_left<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        block_no: BlockNo,
        child_block_no: BlockNo,
        child_left_key: u64,
    ) -> Result<bool> {
        let left_sibling = Self::get_left_child(txn, block_no, child_left_key).await?;
        if left_sibling.is_null() {
            return Ok(false);
        }

        let mut sibling_block = txn.get_block(left_sibling).await?;
        let sibling_ref = sibling_block.block();
        let sibling = sibling_ref.get_at_offset::<NonRootNode>(NonRootNode::offset_in_block());
        if sibling.num_keys as usize <= BTREE_NODE_MIN_KEYS {
            return Ok(false);
        }

        // Extract the last element from the left sibling.
        let kv = sibling.kv[(sibling.num_keys as usize) - 1];
        let new_key = kv.key;

        drop(sibling_ref);
        let mut sibling_ref = sibling_block.block_mut();
        let sibling = sibling_ref.get_mut_at_offset::<NonRootNode>(NonRootNode::offset_in_block());
        sibling.num_keys -= 1;

        // Insert it into _this_ node.
        let mut child_block = txn.get_block(child_block_no).await?;
        let mut block_ref = child_block.block_mut();
        let this = block_ref.get_mut_at_offset::<NonRootNode>(NonRootNode::offset_in_block());
        this.kv[this.num_keys as usize] = kv;

        this.num_keys += 1;
        this.kv[..(this.num_keys as usize)].rotate_right(1);

        // Update this node's key in the parent.
        Self::set_child_key(txn, block_no, child_block_no, child_left_key, new_key).await?;

        Ok(true)
    }

    async fn try_rebalance_right<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        block_no: BlockNo,
        child_block_no: BlockNo,
        child_right_key: u64,
    ) -> Result<bool> {
        let right_sibling = Self::get_right_child(txn, block_no, child_right_key).await?;
        if right_sibling.is_null() {
            return Ok(false);
        }

        let mut sibling_block = txn.get_block(right_sibling).await?;
        let sibling_ref = sibling_block.block();
        let sibling = sibling_ref.get_at_offset::<NonRootNode>(NonRootNode::offset_in_block());
        if sibling.num_keys as usize <= BTREE_NODE_MIN_KEYS {
            return Ok(false);
        }

        // Extract the first element from the right sibling.
        let kv = sibling.kv[0];
        let old_key = kv.key;
        let new_key = sibling.kv[1].key;

        drop(sibling_ref);
        let mut sibling_ref = sibling_block.block_mut();
        let sibling = sibling_ref.get_mut_at_offset::<NonRootNode>(NonRootNode::offset_in_block());
        sibling.kv[..(sibling.num_keys as usize)].rotate_left(1);
        sibling.num_keys -= 1;

        // Insert it into _this_ node.
        let mut child_block = txn.get_block(child_block_no).await?;
        let mut block_ref = child_block.block_mut();
        let this = block_ref.get_mut_at_offset::<NonRootNode>(NonRootNode::offset_in_block());

        this.kv[this.num_keys as usize] = kv;
        this.num_keys += 1;

        // Update this node's key in the parent.
        Self::set_child_key(txn, block_no, right_sibling, old_key, new_key).await?;

        Ok(true)
    }

    async fn set_child_key<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        parent_block_no: BlockNo,
        child_block_no: BlockNo,
        old_key: u64,
        new_key: u64,
    ) -> Result<()> {
        let mut parent_block = txn.get_block(parent_block_no).await?;
        let mut parent_ref = parent_block.block_mut();
        let parent = parent_ref.get_mut_at_offset::<Self>(Self::offset_in_block());

        let child_pos = match parent.kv[..(parent.num_keys as usize)]
            .binary_search_by_key(&old_key, |kv| kv.key)
        {
            Ok(pos) => pos,
            Err(pos) => {
                assert!(pos > 0);
                pos - 1
            }
        };
        assert!(child_pos < (parent.num_keys as usize));
        assert_eq!(child_block_no, parent.kv[child_pos].child_block_no);

        parent.kv[child_pos].key = new_key;

        Ok(())
    }

    /// Return the block number of the child to the left of the key specified (if any).
    async fn get_left_child<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        block_no: BlockNo,
        child_key: u64,
    ) -> Result<BlockNo> {
        if child_key == 0 {
            return Ok(BlockNo::null());
        }

        let block = txn.get_block(block_no).await?;
        let block_ref = block.block();
        let this = block_ref.get_at_offset::<Self>(Self::offset_in_block());

        let child_pos = match this.kv[..(this.num_keys as usize)]
            .binary_search_by_key(&child_key, |kv| kv.key)
        {
            Ok(pos) => pos,
            Err(pos) => {
                if pos == 0 {
                    return Ok(BlockNo::null());
                } else {
                    pos - 1
                }
            }
        };

        assert!(child_pos < (this.num_keys as usize));

        if child_pos == 0 {
            Ok(BlockNo::null())
        } else {
            // log::error!(
            //     "get_left_child: key: {child_key} pos {child_pos}\nkv[{}] = {}:{} kv[{}] = {}:{}",
            //     child_pos - 1,
            //     this.kv[child_pos - 1].key,
            //     this.kv[child_pos - 1].child_block_no.as_u64(),
            //     child_pos,
            //     this.kv[child_pos].key,
            //     this.kv[child_pos].child_block_no.as_u64()
            // );
            Ok(this.kv[child_pos - 1].child_block_no)
        }
    }

    /// Return the block number of the child to the right of the key specified (if any).
    async fn get_right_child<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        block_no: BlockNo,
        child_key: u64,
    ) -> Result<BlockNo> {
        if child_key == u64::MAX {
            return Ok(BlockNo::null());
        }

        let block = txn.get_block(block_no).await?;
        let block_ref = block.block();
        let this = block_ref.get_at_offset::<Self>(Self::offset_in_block());

        let child_pos = match this.kv[..(this.num_keys as usize)]
            .binary_search_by_key(&(child_key + 1), |kv| kv.key)
        {
            Ok(pos) => pos,
            Err(pos) => pos,
        };

        if child_pos >= (this.num_keys as usize) {
            Ok(BlockNo::null())
        } else {
            Ok(this.kv[child_pos].child_block_no)
        }
    }

    async fn try_merge_left<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        block_no: BlockNo,
        child_block_no: BlockNo,
        child_left_key: u64,
    ) -> Result<Option<(u64, BlockNo)>> {
        let left_sibling = Self::get_left_child(txn, block_no, child_left_key).await?;
        if left_sibling.is_null() {
            return Ok(None);
        }

        // Merge this node into the left sibling; this node will be deleted.
        let mut sibling_block = txn.get_block(left_sibling).await?;
        let mut sibling_ref = sibling_block.block_mut();
        let sibling = sibling_ref.get_mut_at_offset::<NonRootNode>(NonRootNode::offset_in_block());

        // Because we first tried (unsuccessfully) borrowing from the sibling, the sibling
        // must have the min number of keys.
        if sibling.num_keys as usize != BTREE_NODE_MIN_KEYS {
            log::error!(
                "merge left: bad num keys: {} child block: {} sibling block: {} child key: {child_left_key}",
                sibling.num_keys,
                child_block_no.as_u64(),
                left_sibling.as_u64()
            );
            return Err(ErrorKind::InvalidData.into());
        }

        let this_block = txn.get_block(child_block_no).await?;
        let this_ref = this_block.block();
        let this = this_ref.get_at_offset::<NonRootNode>(NonRootNode::offset_in_block());

        if sibling.kv[BTREE_NODE_MIN_KEYS - 1].key >= this.kv[0].key {
            log::error!(
                "merge left: bad keys: {} >= {}",
                sibling.kv[BTREE_NODE_MIN_KEYS - 1].key,
                this.kv[0].key
            );
            return Err(ErrorKind::InvalidData.into());
        }

        // Some assertions.
        assert_eq!(this.num_keys as usize, BTREE_NODE_MIN_KEYS - 1);
        assert_eq!(this.kind, sibling.kind);
        assert!(!this.is_root());
        assert!(!sibling.is_root());

        // Copy the keys over.
        sibling.kv[BTREE_NODE_MIN_KEYS..(BTREE_NODE_MIN_KEYS * 2 - 1)]
            .clone_from_slice(&this.kv[..(BTREE_NODE_MIN_KEYS - 1)]);
        sibling.num_keys = (BTREE_NODE_MIN_KEYS * 2 - 1) as u8;

        Ok(Some((child_left_key, child_block_no)))
    }

    async fn try_merge_right<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        block_no: BlockNo,
        child_block_no: BlockNo,
        child_right_key: u64,
    ) -> Result<Option<(u64, BlockNo)>> {
        let right_sibling = Self::get_right_child(txn, block_no, child_right_key).await?;
        if right_sibling.is_null() {
            return Ok(None);
        }

        // Merge the right sibling into this node. The right sibling will be deleted.
        let sibling_block = txn.get_block(right_sibling).await?;
        let sibling_ref = sibling_block.block();
        let sibling = sibling_ref.get_at_offset::<NonRootNode>(NonRootNode::offset_in_block());

        // Because we first tried (unsuccessfully) borrowing from the sibling, the sibling
        // must have the min number of keys.
        if sibling.num_keys as usize != BTREE_NODE_MIN_KEYS {
            log::error!(
                "merge right: bad num keys: {} child block: {} sibling block: {} child key: {child_right_key}",
                sibling.num_keys,
                child_block_no.as_u64(),
                right_sibling.as_u64()
            );
            return Err(ErrorKind::InvalidData.into());
        }

        let mut this_block = txn.get_block(child_block_no).await?;
        let mut this_ref = this_block.block_mut();
        let this = this_ref.get_mut_at_offset::<NonRootNode>(NonRootNode::offset_in_block());

        // Some assertions.
        assert_eq!(this.num_keys as usize, BTREE_NODE_MIN_KEYS - 1);
        assert_eq!(this.kind, sibling.kind);
        assert!(!this.is_root());
        assert!(!sibling.is_root());

        if this.kv[BTREE_NODE_MIN_KEYS - 2].key >= sibling.kv[0].key {
            log::error!(
                "merge right: bad keys: {} >= {}",
                this.kv[BTREE_NODE_MIN_KEYS - 2].key,
                sibling.kv[0].key
            );
            return Err(ErrorKind::InvalidData.into());
        }

        // Copy the keys over.
        this.kv[(BTREE_NODE_MIN_KEYS - 1)..(BTREE_NODE_MIN_KEYS * 2 - 1)]
            .clone_from_slice(&sibling.kv[..BTREE_NODE_MIN_KEYS]);
        this.num_keys = (BTREE_NODE_MIN_KEYS * 2 - 1) as u8;

        Ok(Some((sibling.kv[0].key, right_sibling)))
    }

    #[allow(unused)]
    #[cfg(test)]
    pub async fn test_log_tree<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        node_block_no: BlockNo,
    ) -> Result<()> {
        let node_block = txn.get_block(node_block_no).await?;
        let node_block_ref = node_block.block();
        let node = node_block_ref.get_at_offset::<Self>(Self::offset_in_block());

        let mut output = format!(
            "\nnode {}: num_keys: {} is_root: {} is_leaf: {}\n",
            node_block_no.as_u64(),
            node.num_keys,
            node.is_root(),
            node.is_leaf()
        );

        for kv in &node.kv[..(node.num_keys as usize)] {
            output.push_str(format!("{}:{} ", kv.key, kv.child_block_no.as_u64()).as_str());
        }

        log::info!("{}", output);

        if !node.is_leaf() {
            for kv in &node.kv[..(node.num_keys as usize)] {
                Box::pin(NonRootNode::test_log_tree(txn, kv.child_block_no)).await?;
            }
        }

        Ok(())
    }
}

impl RootNode {
    async fn split_root<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        root_block_no: BlockNo,
    ) -> Result<()> {
        // Allocate two new blocks.
        let left_block_no = Superblock::allocate_block(txn).await?.block_no;
        let right_block_no = Superblock::allocate_block(txn).await?.block_no;

        // Get the root block.
        let mut root_block = txn.get_block(root_block_no).await?;
        let mut root_block_ref = root_block.block_mut();
        let root = root_block_ref.get_mut_at_offset::<Self>(Self::offset_in_block());
        assert_eq!(root.num_keys as usize, Self::order());

        // Save data to copy.
        let root_entries = root.kv;
        let left_key = u64::MIN;
        let split_pos = (Self::order() >> 1) + 1;
        assert!(split_pos <= u8::MAX as usize);
        let right_key = root_entries[split_pos].key;
        let leaf_flag = root.kind & Self::KIND_LEAF;

        // log::debug!(
        //     "split_root(): root: {} key: {right_key} left: {} right: {}",
        //     root_block_no.as_u64(),
        //     left_block_no.as_u64(),
        //     right_block_no.as_u64()
        // );

        // Update root.
        root.kind &= !Self::KIND_LEAF;
        root.num_keys = 2;
        root.kv[0].key = left_key;
        root.kv[0].child_block_no = left_block_no;
        root.kv[1].key = right_key;
        root.kv[1].child_block_no = right_block_no;

        core::mem::drop(root_block_ref);

        // Update the left block.
        let mut left_block = txn.get_empty_block_mut(left_block_no);
        let mut left_block_ref = left_block.block_mut();

        let bh = left_block_ref.get_mut_at_offset::<BlockHeader>(0);
        bh.set_block_type(crate::BlockType::TreeNode);

        let left_node = left_block_ref.get_mut_at_offset::<NonRootNode>(BTREE_NODE_OFFSET);

        left_node.num_keys = split_pos as u8;
        left_node.kind = leaf_flag;
        left_node.kv[..split_pos].clone_from_slice(&root_entries[..split_pos]);

        core::mem::drop(left_block_ref);

        // Update the right block.
        let mut right_block = txn.get_empty_block_mut(right_block_no);
        let mut right_block_ref = right_block.block_mut();
        let right_node = right_block_ref.get_mut_at_offset::<NonRootNode>(BTREE_NODE_OFFSET);

        right_node.num_keys = (BTREE_ROOT_ORDER - split_pos) as u8;
        right_node.kind = leaf_flag;
        right_node.kv[..(right_node.num_keys as usize)]
            .clone_from_slice(&root_entries[split_pos..]);

        Ok(())
    }

    /// Return the number of freed btree nodes.
    pub async fn root_delete_link<'a, BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'a, BD>,
        this_block_no: BlockNo,
        key: u64,
        block_no_to_delete: BlockNo,
    ) -> Result<()> {
        Self::node_delete_link(
            txn,
            this_block_no,
            key,
            block_no_to_delete,
            BlockNo::null(),
            0,
        )
        .await
        .map(|kv| {
            assert!(kv.is_none());
        })
    }

    async fn assimilate_single_child<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        root_block_no: BlockNo,
        child_block_no: BlockNo,
    ) -> Result<()> {
        // Get the root block.
        let mut root_block = txn.get_block(root_block_no).await?;
        let mut root_block_ref = root_block.block_mut();
        let root = root_block_ref.get_mut_at_offset::<RootNode>(RootNode::offset_in_block());

        /*
        log::error!(
            "assimilate: root {} child {} root num keys {} kv0 {}:{} kv1 {}:{}",
            root_block_no.as_u64(),
            child_block_no.as_u64(),
            root.num_keys,
            root.kv[0].key,
            root.kv[0].child_block_no.as_u64(),
            root.kv[1].key,
            root.kv[1].child_block_no.as_u64()
        );
        */

        assert_eq!(root.num_keys as usize, 1);
        assert!(!root.is_leaf());
        assert!(root.is_root());

        // Get the child.
        let child_block = txn.get_block(child_block_no).await?;
        let child_block_ref = child_block.block();
        let child = child_block_ref.get_at_offset::<NonRootNode>(NonRootNode::offset_in_block());
        assert_eq!(child.num_keys as usize, BTREE_NODE_MIN_KEYS - 1);

        // Move data.
        root.num_keys = (BTREE_NODE_MIN_KEYS - 1) as u8;
        if child.is_leaf() {
            root.kind |= Self::KIND_LEAF;
        }
        root.kv[..(BTREE_NODE_MIN_KEYS - 1)]
            .clone_from_slice(&child.kv[..(BTREE_NODE_MIN_KEYS - 1)]);

        drop(root_block_ref);
        drop(child_block_ref);

        // Delete the child.
        Superblock::free_single_block(txn, child_block_no).await?;

        Ok(())
    }
}
