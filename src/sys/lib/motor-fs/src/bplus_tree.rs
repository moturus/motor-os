//! B+ tree.
use crate::BTREE_NODE_OFFSET;
use crate::BTREE_NODE_ORDER; // = 253
use crate::BTREE_ROOT_OFFSET;
use crate::BTREE_ROOT_ORDER; // = 226
use crate::BlockHeader;
use crate::BlockNo;
use crate::BlockType;
use crate::DirEntryBlock;
use crate::Superblock;
use crate::Txn;
use async_fs::AsyncBlockDevice;
use async_fs::BLOCK_SIZE;
use bytemuck::Pod;
use std::io::ErrorKind;
use std::io::Result;

#[cfg(test)]
thread_local! {
    /// Test instrumentation: counts how many tree nodes
    /// [`Node::count_subtree_blocks`] visits, so tests can assert that a
    /// truncation walks the smaller side rather than the whole chopped forest.
    pub(crate) static COUNT_SUBTREE_VISITS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

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

/// What [`Node::take_spare_block`] pulled off a chopped-off branch's right
/// spine to repurpose as an orphan container.
struct SpareBlock {
    /// The block to reuse as an orphan container (the entry, or a mid node).
    block: BlockNo,
    /// Blocks handed straight to the free list while pulling the spare: the
    /// emptied right-most leaf's lone data block, plus any single-child nodes
    /// above it that collapsed. The orphan's `blocks_in_use` is the chopped
    /// total minus this count.
    freed: u64,
    /// Set when the descended branch was itself taken whole (its right spine
    /// collapsed all the way up), so it no longer belongs under the orphan.
    consumed_branch: bool,
}

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

        let child_block_no = {
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

            this.kv[0].child_block_no
        };

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

    /// Swaps the child a `key` points at from `old_child` to `new_child`, in
    /// place. The key itself is unchanged, so the tree's shape does not change
    /// (no split, merge, or rebalance).
    ///
    /// A directory's tree stores one link per name hash, pointing at the head of
    /// that hash's collision list. When the head changes -- a colliding entry is
    /// unlinked and its successor promoted -- only that one child pointer moves;
    /// this performs exactly that.
    pub async fn replace_link<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        this_block_no: BlockNo,
        key: u64,
        old_child: BlockNo,
        new_child: BlockNo,
    ) -> Result<()> {
        // Find the key: either this node is a leaf holding it, or we learn which
        // child to descend into. Read in its own scope so no borrow is held
        // across the recursive await below.
        let (is_leaf, pos, child_block_no) = {
            let block = txn.get_block(this_block_no).await?;
            let block_ref = block.block();
            let node = block_ref.get_at_offset::<Self>(Self::offset_in_block());
            if node.num_keys as usize > ORDER {
                log::error!("Bad B+ Tree Node {}.", this_block_no.as_u64());
                return Err(ErrorKind::InvalidData.into());
            }
            let pos = match node.kv[..(node.num_keys as usize)]
                .binary_search_by_key(&key, |kv| kv.key)
            {
                Ok(pos) => pos,
                Err(pos) => {
                    if node.is_leaf() {
                        log::error!("replace_link: key {key} not found");
                        return Err(ErrorKind::NotFound.into());
                    }
                    assert!(pos > 0);
                    pos - 1
                }
            };
            (node.is_leaf(), pos, node.kv[pos].child_block_no)
        };

        if !is_leaf {
            return Box::pin(NonRootNode::replace_link(
                txn,
                child_block_no,
                key,
                old_child,
                new_child,
            ))
            .await;
        }

        // Leaf: swap the child pointer in place.
        if child_block_no != old_child {
            log::error!(
                "replace_link: child {} != expected {}",
                child_block_no.as_u64(),
                old_child.as_u64()
            );
            return Err(ErrorKind::InvalidData.into());
        }
        let mut block = txn.get_block(this_block_no).await?;
        let mut block_ref = block.block_mut();
        block_ref
            .get_mut_at_offset::<Self>(Self::offset_in_block())
            .kv[pos]
            .child_block_no = new_child;
        Ok(())
    }

    /// Returns the child of the smallest key in this subtree that is strictly
    /// greater than `key` -- i.e. the in-order successor's child block -- or
    /// `None` if `key` is at or past the last key. Directory iteration uses it to
    /// step from one name-hash bucket to the next (see `MotorFs::get_next_entry`).
    ///
    /// Leaves here hold no sibling links, so the successor of the last key in a
    /// leaf lives in a different subtree: the descent looks for it under `key`'s
    /// own child first, and on failure falls back to the left-most entry of the
    /// next child. A miss with no next child propagates `None` up so the caller,
    /// one level higher, tries *its* next child.
    pub async fn next_child<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        this_block_no: BlockNo,
        this_offset: usize,
        key: u64,
    ) -> Result<Option<BlockNo>> {
        // Inspect this node and decide where to go, dropping the borrow before
        // any recursive await. Leaf and empty/error cases return outright; the
        // internal case yields the child to descend into plus the next child as
        // a fallback.
        let (child, sibling) = {
            let block = txn.get_block_untracked(this_block_no).await?;
            let block_ref = block.block();
            let this = block_ref.get_at_offset::<Self>(this_offset);

            if this.num_keys as usize > ORDER {
                log::error!("Bad B+ Tree Node {:?}(?).", this_block_no.as_u64());
                return Err(ErrorKind::InvalidData.into());
            }
            let num_keys = this.num_keys as usize;
            if num_keys == 0 {
                return Ok(None);
            }

            if this.is_leaf() {
                // The first key strictly greater than `key`, if any, is in this
                // same leaf.
                let pos = this.kv[..num_keys].partition_point(|kv| kv.key <= key);
                return Ok((pos < num_keys).then(|| this.kv[pos].child_block_no));
            }

            // Internal node: descend into the child whose range covers `key`,
            // remembering the next child (its left-most entry is the successor if
            // `key`'s own subtree has none).
            let pos = match this.kv[..num_keys].binary_search_by_key(&key, |kv| kv.key) {
                Ok(pos) => pos,
                Err(pos) => {
                    assert!(pos > 0);
                    pos - 1
                }
            };
            (
                this.kv[pos].child_block_no,
                (pos + 1 < num_keys).then(|| this.kv[pos + 1].child_block_no),
            )
        };

        // Successor within `key`'s own subtree?
        if let Some(found) =
            Box::pin(NonRootNode::next_child(txn, child, BTREE_NODE_OFFSET, key)).await?
        {
            return Ok(Some(found));
        }

        // Otherwise it is the left-most entry of the next subtree, if any.
        match sibling {
            Some(sibling) => Ok(Box::pin(NonRootNode::first_child(txn, sibling))
                .await?
                .map(|kv| kv.child_block_no)),
            None => Ok(None),
        }
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
            Ok(None)
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
        // Normal deletes only ever underflow a node to exactly MIN - 1 keys, but
        // draining an under-full (truncated) tree can present nodes with far
        // fewer keys, so this is `<` rather than `==`.
        let num_keys = this.num_keys as usize;
        debug_assert!(num_keys < BTREE_NODE_MIN_KEYS);

        if num_keys == 0 {
            // An empty node only arises while draining an under-full tree, and
            // only as the sole child of its parent (otherwise it would have
            // borrowed/merged with a sibling before emptying). Move it up.
            drop(block_ref);
            drop(block);
            assert_eq!(level, 1);
            RootNode::assimilate_single_child(txn, parent_node_block_no, this_block_no).await?;
            return Ok(None);
        }

        let this_first_key = this.kv[0].key;
        let this_last_key = this.kv[num_keys - 1].key;

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

        let (kv, new_key) = {
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
            let sibling =
                sibling_ref.get_mut_at_offset::<NonRootNode>(NonRootNode::offset_in_block());
            sibling.num_keys -= 1;

            (kv, new_key)
        };

        {
            // Insert it into _this_ node.
            let mut child_block = txn.get_block(child_block_no).await?;
            let mut block_ref = child_block.block_mut();
            let this = block_ref.get_mut_at_offset::<NonRootNode>(NonRootNode::offset_in_block());
            this.kv[this.num_keys as usize] = kv;

            this.num_keys += 1;
            this.kv[..(this.num_keys as usize)].rotate_right(1);
        }

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

        let (kv, old_key, new_key) = {
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
            let sibling =
                sibling_ref.get_mut_at_offset::<NonRootNode>(NonRootNode::offset_in_block());
            sibling.kv[..(sibling.num_keys as usize)].rotate_left(1);
            sibling.num_keys -= 1;

            (kv, old_key, new_key)
        };

        {
            // Insert it into _this_ node.
            let mut child_block = txn.get_block(child_block_no).await?;
            let mut block_ref = child_block.block_mut();
            let this = block_ref.get_mut_at_offset::<NonRootNode>(NonRootNode::offset_in_block());

            this.kv[this.num_keys as usize] = kv;
            this.num_keys += 1;
        }

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

    #[allow(clippy::await_holding_refcell_ref)]
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

        // Because we first tried (unsuccessfully) borrowing from the sibling, the
        // sibling has at most the min number of keys (it can have fewer when
        // draining an under-full tree).
        if sibling.num_keys as usize > BTREE_NODE_MIN_KEYS {
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

        // The sibling has min keys; this node has at most min - 1 (it may have
        // fewer when draining an under-full tree). The merged node therefore
        // always fits.
        let sibling_keys = sibling.num_keys as usize;
        let this_keys = this.num_keys as usize;
        assert!(sibling_keys + this_keys <= NonRootNode::order());

        if sibling.kv[sibling_keys - 1].key >= this.kv[0].key {
            log::error!(
                "merge left: bad keys: {} >= {}",
                sibling.kv[sibling_keys - 1].key,
                this.kv[0].key
            );
            return Err(ErrorKind::InvalidData.into());
        }

        // Some assertions.
        assert_eq!(this.kind, sibling.kind);
        assert!(!this.is_root());
        assert!(!sibling.is_root());

        // Copy the keys over.
        sibling.kv[sibling_keys..(sibling_keys + this_keys)]
            .clone_from_slice(&this.kv[..this_keys]);
        sibling.num_keys = (sibling_keys + this_keys) as u8;

        Ok(Some((child_left_key, child_block_no)))
    }

    #[allow(clippy::await_holding_refcell_ref)]
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

        // Because we first tried (unsuccessfully) borrowing from the sibling, the
        // sibling has at most the min number of keys (it can have fewer when
        // draining an under-full tree).
        if sibling.num_keys as usize > BTREE_NODE_MIN_KEYS {
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

        // The sibling has min keys; this node has at most min - 1 (it may have
        // fewer when draining an under-full tree). The merged node always fits.
        let sibling_keys = sibling.num_keys as usize;
        let this_keys = this.num_keys as usize;
        assert!(this_keys + sibling_keys <= NonRootNode::order());
        assert_eq!(this.kind, sibling.kind);
        assert!(!this.is_root());
        assert!(!sibling.is_root());

        if this.kv[this_keys - 1].key >= sibling.kv[0].key {
            log::error!(
                "merge right: bad keys: {} >= {}",
                this.kv[this_keys - 1].key,
                sibling.kv[0].key
            );
            return Err(ErrorKind::InvalidData.into());
        }

        // Copy the keys over.
        this.kv[this_keys..(this_keys + sibling_keys)]
            .clone_from_slice(&sibling.kv[..sibling_keys]);
        this.num_keys = (this_keys + sibling_keys) as u8;

        Ok(Some((sibling.kv[0].key, right_sibling)))
    }

    /// Counts the total number of blocks (tree nodes plus data blocks) occupied
    /// by the subtree rooted at `node_block_no`, including the node itself.
    ///
    /// The walk uses untracked reads so that it does not bloat the transaction's
    /// (bounded) block cache: the visited nodes are not modified, only counted.
    async fn count_subtree_blocks<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        node_block_no: BlockNo,
    ) -> Result<u64> {
        #[cfg(test)]
        COUNT_SUBTREE_VISITS.with(|c| c.set(c.get() + 1));

        let block = txn.get_block_untracked(node_block_no).await?;
        let (is_leaf, num_keys, children) = {
            let block_ref = block.block();
            let node = block_ref.get_at_offset::<NonRootNode>(BTREE_NODE_OFFSET);
            let num_keys = node.num_keys as usize;
            if num_keys > BTREE_NODE_ORDER {
                log::error!("Bad B+ Tree Node {}.", node_block_no.as_u64());
                return Err(ErrorKind::InvalidData.into());
            }
            let is_leaf = node.is_leaf();
            let children: Vec<BlockNo> = if is_leaf {
                Vec::new()
            } else {
                node.kv[..num_keys]
                    .iter()
                    .map(|kv| kv.child_block_no)
                    .collect()
            };
            (is_leaf, num_keys, children)
        };

        if is_leaf {
            // This (leaf) node block, plus its data-block children.
            return Ok(1 + num_keys as u64);
        }

        let mut total = 1u64; // This node.
        for child in children {
            total += Box::pin(NonRootNode::count_subtree_blocks(txn, child)).await?;
        }
        Ok(total)
    }

    /// Appends every block strictly below this node -- all descendant tree nodes
    /// and all data blocks -- to `out`. The node at `this_block_no` itself is not
    /// included (for a file that is the entry/root block, which is kept).
    ///
    /// Reads untracked. Intended for collapsing a *small* tree (a file reduced to
    /// at most one data block) into inline storage, where the caller then frees
    /// exactly these blocks; it must not be called on a large tree.
    pub(crate) async fn collect_blocks_below<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        this_block_no: BlockNo,
        out: &mut Vec<BlockNo>,
    ) -> Result<()> {
        let (is_leaf, children) = {
            let block = txn.get_block_untracked(this_block_no).await?;
            let block_ref = block.block();
            let node = block_ref.get_at_offset::<Self>(Self::offset_in_block());
            let num_keys = node.num_keys as usize;
            if num_keys > ORDER {
                log::error!("Bad B+ Tree Node {}.", this_block_no.as_u64());
                return Err(ErrorKind::InvalidData.into());
            }
            let children: Vec<BlockNo> = node.kv[..num_keys]
                .iter()
                .map(|kv| kv.child_block_no)
                .collect();
            (node.is_leaf(), children)
        };

        if is_leaf {
            // Children are data blocks.
            out.extend(children);
        } else {
            // Children are tree nodes: collect each and recurse below it.
            for child in children {
                out.push(child);
                Box::pin(NonRootNode::collect_blocks_below(txn, child, out)).await?;
            }
        }
        Ok(())
    }

    /// Pulls a spare container block off the *right* spine of the subtree rooted
    /// at `branch`, sourcing it from the chopped-off forest itself so truncation
    /// never allocates -- which keeps it from draining the free list (and
    /// triggering a B+ rebalance that could blow the transaction's block budget)
    /// and lets it succeed even on a full device.
    ///
    /// Walks down the right spine to the right-most leaf and takes its right-most
    /// data block (O(1): just shrink `num_keys`). If that leaf has only a single
    /// data block -- so taking it would leave the leaf empty -- the leaf node
    /// *itself* is taken instead: its lone data block is freed and the leaf is
    /// detached from its parent. Truncation chops the right side without
    /// rebalancing, so the right spine of an already-truncated file can be a thin
    /// residue chain; detaching the leaf can therefore empty its parent, which is
    /// then freed too, walking up until a node still has a child to keep (or the
    /// branch collapses entirely -- see `consumed_branch`). The chain is at most
    /// a few levels deep, so the freed-block count stays small.
    ///
    /// Interior nodes are read untracked; only the blocks actually taken, freed,
    /// or trimmed are modified.
    async fn take_spare_block<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        branch: BlockNo,
    ) -> Result<SpareBlock> {
        // Descend the right-most spine to a leaf, recording the path so we can
        // walk back up if the leaf cannot spare a data block. The tree is at most
        // a few levels deep; the bound also guards a corrupted (cyclic) tree.
        let mut path: Vec<BlockNo> = Vec::with_capacity(8);
        let mut node_no = branch;
        let leaf_num_keys = loop {
            if path.len() >= 8 {
                log::error!("take_spare_block: spine too deep from {}", branch.as_u64());
                return Err(ErrorKind::InvalidData.into());
            }
            let (is_leaf, num_keys, rightmost_child) = {
                let block = txn.get_block_untracked(node_no).await?;
                let block_ref = block.block();
                let node = block_ref.get_at_offset::<NonRootNode>(BTREE_NODE_OFFSET);
                let num_keys = node.num_keys as usize;
                if num_keys == 0 || num_keys > BTREE_NODE_ORDER {
                    log::error!("take_spare_block: bad node {}", node_no.as_u64());
                    return Err(ErrorKind::InvalidData.into());
                }
                (
                    node.is_leaf(),
                    num_keys,
                    node.kv[num_keys - 1].child_block_no,
                )
            };
            path.push(node_no);
            if is_leaf {
                break num_keys;
            }
            node_no = rightmost_child;
        };
        let leaf_no = *path.last().unwrap();

        // TODO: carefully review the rest of the fn below: feels off.
        //
        // Common case: the right-most leaf has a data block to spare. Detach its
        // right-most data block and hand it over; the leaf stays valid.
        if leaf_num_keys >= 2 {
            let mut leaf_block = txn.get_block(leaf_no).await?;
            let mut leaf_ref = leaf_block.block_mut();
            let leaf = leaf_ref.get_mut_at_offset::<NonRootNode>(BTREE_NODE_OFFSET);
            let data_block_no = leaf.kv[leaf_num_keys - 1].child_block_no;
            leaf.num_keys = (leaf_num_keys - 1) as u8;
            return Ok(SpareBlock {
                block: data_block_no,
                freed: 0,
                consumed_branch: false,
            });
        }

        // The right-most leaf holds a single data block: take the leaf node
        // itself. Free its lone data block, then detach the leaf from its parent,
        // freeing each ancestor that the detach leaves empty.
        let data_block_no = {
            let block = txn.get_block_untracked(leaf_no).await?;
            let block_ref = block.block();
            block_ref.get_at_offset::<NonRootNode>(BTREE_NODE_OFFSET).kv[0].child_block_no
        };
        Superblock::free_single_block(txn, data_block_no).await?;
        let mut freed = 1u64;

        // `path` is [branch, .., leaf]. Drop the right-most child from each
        // ancestor, bottom-up: the leaf's parent loses the leaf, the next loses
        // whatever we just freed, and so on. Stop at the first ancestor that
        // keeps a child; if none do, the whole branch is consumed.
        for idx in (0..path.len() - 1).rev() {
            let parent_no = path[idx];
            let parent_keys = {
                let block = txn.get_block_untracked(parent_no).await?;
                let block_ref = block.block();
                block_ref
                    .get_at_offset::<NonRootNode>(BTREE_NODE_OFFSET)
                    .num_keys as usize
            };
            if parent_keys >= 2 {
                let mut block = txn.get_block(parent_no).await?;
                let mut block_ref = block.block_mut();
                block_ref
                    .get_mut_at_offset::<NonRootNode>(BTREE_NODE_OFFSET)
                    .num_keys = (parent_keys - 1) as u8;
                return Ok(SpareBlock {
                    block: leaf_no,
                    freed,
                    consumed_branch: false,
                });
            }
            // The parent's only child was the node we just removed: it is now
            // empty, so free it and keep walking up.
            Superblock::free_single_block(txn, parent_no).await?;
            freed += 1;
        }

        // Every node on the spine collapsed: the branch is wholly consumed, and
        // the (now detached) leaf block is the spare.
        Ok(SpareBlock {
            block: leaf_no,
            freed,
            consumed_branch: true,
        })
    }

    /// Moves the chopped-off `branches` into an orphan file and hands that file
    /// off to [`Superblock::free_complex_block`], which reclaims the whole
    /// sub-forest lazily via the free list. `blocks_under` is the total number of
    /// blocks reachable through `branches` (data blocks and tree nodes).
    ///
    /// The orphan's container block(s) -- its entry, plus a middle node when the
    /// branches don't fit under one root -- are sourced from the blocks being
    /// truncated away, never from the allocator (see [`Self::take_spare_block`]).
    /// Sourcing a container can hand a few blocks straight to the free list (when
    /// the right-most leaf cannot spare a data block), so the orphan's
    /// `blocks_in_use` is `blocks_under` minus whatever was freed that way; the
    /// orphan and those freed blocks together account for exactly `blocks_under`.
    async fn orphan_branches<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        branches: &[KV],
        is_leaf: bool,
        blocks_under: u64,
    ) -> Result<()> {
        let leaf_flag = if is_leaf { Self::KIND_LEAF } else { 0 };
        let n = branches.len();
        debug_assert!(n >= 1);

        // Pick the container block(s) and the branches that go under them, along
        // with the orphan's resulting `blocks_in_use`.
        let (entry_no, mid_no, under, blocks_in_use): (BlockNo, Option<BlockNo>, &[KV], u64) =
            if is_leaf {
                // A leaf chop hands us data blocks directly, so repurpose the last
                // one(s) (the end of the truncated range) as the container(s) and
                // put the rest under them. Nothing is freed here, so the orphan
                // holds all of `blocks_under`.
                if n - 1 > BTREE_ROOT_ORDER {
                    log::debug!("orphan_branches: {n} branches need an intermediate node");
                    (
                        branches[n - 1].child_block_no,
                        Some(branches[n - 2].child_block_no),
                        &branches[..n - 2],
                        blocks_under,
                    )
                } else {
                    (
                        branches[n - 1].child_block_no,
                        None,
                        &branches[..n - 1],
                        blocks_under,
                    )
                }
            } else {
                // An internal chop hands us subtree roots, all of which must hang
                // under the orphan. Source the container(s) from the chopped-off
                // forest by walking the right spine (see take_spare_block).
                let spare = Self::take_spare_block(txn, branches[n - 1].child_block_no).await?;
                let mut freed = spare.freed;
                let under: &[KV] = if spare.consumed_branch {
                    &branches[..n - 1]
                } else {
                    branches
                };

                if under.is_empty() {
                    // The whole chopped forest was a single thin residue chain that
                    // collapsed into the spare block; there is nothing left to hang
                    // under an orphan, so just free that block too.
                    debug_assert_eq!(freed + 1, blocks_under);
                    return Superblock::free_single_block(txn, spare.block).await;
                }

                let mid = if under.len() > BTREE_ROOT_ORDER {
                    // The orphan root holds at most BTREE_ROOT_ORDER children, so a
                    // wider forest needs an intermediate node. Source it from the
                    // left-most branch, which is never on the (possibly under-full)
                    // right spine and so always has a leaf with a data block to
                    // spare.
                    log::debug!(
                        "orphan_branches: {} branches need an intermediate node",
                        under.len()
                    );
                    let mid_spare = Self::take_spare_block(txn, under[0].child_block_no).await?;
                    debug_assert_eq!(mid_spare.freed, 0);
                    debug_assert!(!mid_spare.consumed_branch);
                    freed += mid_spare.freed;
                    Some(mid_spare.block)
                } else {
                    None
                };

                (spare.block, mid, under, blocks_under - freed)
            };

        if let Some(mid_no) = mid_no {
            {
                let mut mid_block = txn.get_empty_block_mut(mid_no);
                let mut mid_ref = mid_block.block_mut();
                mid_ref
                    .get_mut_at_offset::<BlockHeader>(0)
                    .set_block_type(BlockType::TreeNode);
                let mid = mid_ref.get_mut_at_offset::<NonRootNode>(BTREE_NODE_OFFSET);
                mid.num_keys = under.len() as u8;
                mid.kind = leaf_flag;
                mid.kv[..under.len()].clone_from_slice(under);
            }
            let mut entry_block = txn.get_empty_block_mut(entry_no);
            let mut entry_ref = entry_block.block_mut();
            let bh = entry_ref.get_mut_at_offset::<BlockHeader>(0);
            bh.set_block_type(BlockType::FileEntry);
            bh.set_in_use(true);
            let root = entry_ref.get_mut_at_offset::<RootNode>(BTREE_ROOT_OFFSET);
            root.num_keys = 1;
            root.kind = Self::KIND_ROOT;
            root.kv[0] = KV {
                key: 0,
                child_block_no: mid_no,
            };
        } else {
            let mut entry_block = txn.get_empty_block_mut(entry_no);
            let mut entry_ref = entry_block.block_mut();
            let bh = entry_ref.get_mut_at_offset::<BlockHeader>(0);
            bh.set_block_type(BlockType::FileEntry);
            bh.set_in_use(true);
            let root = entry_ref.get_mut_at_offset::<RootNode>(BTREE_ROOT_OFFSET);
            root.num_keys = under.len() as u8;
            root.kind = Self::KIND_ROOT | leaf_flag;
            root.kv[..under.len()].clone_from_slice(under);
        }

        let mut entry_block = txn.get_block(entry_no).await?;
        entry_block
            .block_mut()
            .get_mut_at_offset::<BlockHeader>(0)
            .set_blocks_in_use(blocks_in_use);

        Superblock::free_complex_block(txn, entry_no).await
    }

    /// Chops off the right-most branches of the node at `this_block_no` whose
    /// keys are at or above `first_stale_key` (i.e. they hold only data above the
    /// truncation point), moving them into an orphan file that is then freed.
    /// `file_block_no` is the file entry whose `blocks_in_use` is decremented.
    ///
    /// `subtree_total`, when known, is the number of blocks below this node (all
    /// of its children's subtrees combined). It lets the chopped-block count be
    /// derived by subtraction after walking only the *surviving* side, so a
    /// truncation that drops most of the tree (e.g. truncate-to-zero) need not
    /// walk the whole chopped-off forest. See [`Self::count_subtree_blocks`].
    ///
    /// Returns the right-most surviving child to descend into next together with
    /// *its* `subtree_total` (when cheaply known), or `None` when this node is a
    /// leaf (only data blocks were chopped) or when the whole node was stale (no
    /// surviving child remains).
    pub async fn truncate_right<BD: AsyncBlockDevice + 'static>(
        txn: &mut Txn<'_, BD>,
        this_block_no: BlockNo,
        file_block_no: BlockNo,
        first_stale_key: u64,
        subtree_total: Option<u64>,
    ) -> Result<Option<(BlockNo, Option<u64>)>> {
        let block = txn.get_block(this_block_no).await?;
        let (is_leaf, cut, chopped, survivors) = {
            let block_ref = block.block();
            let this = block_ref.get_at_offset::<Self>(Self::offset_in_block());
            let num_keys = this.num_keys as usize;
            if num_keys > ORDER {
                log::error!("Bad B+ Tree Node {}.", this_block_no.as_u64());
                return Err(ErrorKind::InvalidData.into());
            }
            let is_leaf = this.is_leaf();
            // Keys are sorted, so `cut` splits live (< first_stale_key) from stale.
            let cut = this.kv[..num_keys].partition_point(|kv| kv.key < first_stale_key);
            let chopped: Vec<KV> = this.kv[cut..num_keys].to_vec();
            let survivors: Vec<BlockNo> =
                this.kv[..cut].iter().map(|kv| kv.child_block_no).collect();
            (is_leaf, cut, chopped, survivors)
        };

        // `subtree_total` of the child we descend into, propagated to the next
        // level when we learn it for free (i.e. when we walk the surviving side).
        let mut next_subtree_total: Option<u64> = None;

        if !chopped.is_empty() {
            // Count the blocks that are about to leave this file, walking whichever
            // side (surviving or chopped) is smaller.
            let blocks_under = if is_leaf {
                // Each chopped branch is a single data block; no walk needed.
                chopped.len() as u64
            } else if let Some(total) = subtree_total.filter(|_| cut <= chopped.len()) {
                // The surviving side has no more branches than the chopped side, so
                // walk it and derive the chopped count by subtraction. This is the
                // win for truncate-to-zero (cut == 0, nothing to walk) and small
                // truncations (only the thin surviving spine is walked).
                let mut survivors_count = 0u64;
                for (idx, child) in survivors.iter().enumerate() {
                    let sub = Box::pin(NonRootNode::count_subtree_blocks(txn, *child)).await?;
                    survivors_count += sub;
                    // The last survivor is the child we descend into next; its
                    // blocks (minus the child node itself) are that level's total.
                    if idx + 1 == cut {
                        next_subtree_total = Some(sub - 1);
                    }
                }
                debug_assert!(
                    survivors_count <= total,
                    "survivors {survivors_count} exceed subtree total {total}"
                );
                total - survivors_count
            } else {
                // The chopped side is the smaller one (or no total is known): walk
                // it directly. The descend child's total stays unknown.
                let mut total = 0u64;
                for kv in &chopped {
                    total +=
                        Box::pin(NonRootNode::count_subtree_blocks(txn, kv.child_block_no)).await?;
                }
                total
            };

            Self::orphan_branches(txn, &chopped, is_leaf, blocks_under).await?;

            // Detach the chopped branches from this node.
            {
                let mut block = txn.get_block(this_block_no).await?;
                let mut block_ref = block.block_mut();
                let this = block_ref.get_mut_at_offset::<Self>(Self::offset_in_block());
                this.num_keys = cut as u8;
                if cut == 0 {
                    // The whole node became stale. This only happens at the root
                    // (a node on the path always keeps its left-most child), so
                    // reset it to a valid empty leaf root: the now-empty file must
                    // remain writable.
                    assert_eq!(this_block_no, file_block_no);
                    this.kind = Self::KIND_ROOT | Self::KIND_LEAF;
                }
            }

            DirEntryBlock::decrement_blocks_in_use(txn, file_block_no, blocks_under).await?;

            // Lower the recorded file size in step with the chop: every block
            // from `chopped[0].key` onward has just left the file, so nothing
            // survives at or above that key. Doing this here, atomically with the
            // detach, keeps the recorded size from ever dropping below the file's
            // surviving extent at a committed step, so a crash mid-truncation can
            // never leave stale data reachable above EOF (e.g. once the file is
            // grown again). `do_large_truncate` pins the exact final size at the
            // end.
            let surviving_extent = chopped[0].key * (BLOCK_SIZE as u64);
            DirEntryBlock::set_file_size_in_entry(txn, file_block_no, surviving_extent).await?;
        }

        // A leaf chops data blocks directly: there is nothing deeper. An empty
        // cut means the whole node was stale, so no surviving child remains.
        if is_leaf || cut == 0 {
            return Ok(None);
        }

        let next = {
            let block = txn.get_block(this_block_no).await?;
            let block_ref = block.block();
            let this = block_ref.get_at_offset::<Self>(Self::offset_in_block());
            this.kv[cut - 1].child_block_no
        };
        Ok(Some((next, next_subtree_total)))
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

    #[allow(clippy::await_holding_refcell_ref)]
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
        // A normal collapse moves a child of min - 1 keys, but draining an
        // under-full tree can collapse a child with any number of keys.
        let child_keys = child.num_keys as usize;

        // Move data.
        root.num_keys = child_keys as u8;
        if child.is_leaf() {
            root.kind |= Self::KIND_LEAF;
        }
        root.kv[..child_keys].clone_from_slice(&child.kv[..child_keys]);

        drop(root_block_ref);
        drop(child_block_ref);

        // Delete the child.
        Superblock::free_single_block(txn, child_block_no).await?;

        Ok(())
    }
}
