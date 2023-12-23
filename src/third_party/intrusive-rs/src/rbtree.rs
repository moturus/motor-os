// Copyright 2016 Amanieu d'Antras
// Copyright 2020 Amari Robinson
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Intrusive red-black tree.

use core::borrow::Borrow;
use core::cell::Cell;
use core::cmp::Ordering;
use core::fmt;
use core::mem;
use core::ptr::NonNull;
use core::sync::atomic::{self, AtomicUsize};

use crate::Bound::{self, Excluded, Included, Unbounded};

use crate::link_ops::{self, DefaultLinkOps};
use crate::linked_list::LinkedListOps;
use crate::pointer_ops::PointerOps;
use crate::singly_linked_list::SinglyLinkedListOps;
use crate::xor_linked_list::XorLinkedListOps;
use crate::Adapter;
use crate::KeyAdapter;
// Necessary for Rust 1.56 compatability
#[allow(unused_imports)]
use crate::unchecked_option::UncheckedOptionExt;

// =============================================================================
// RBTreeOps
// =============================================================================

/// The color of a red-black tree node.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[allow(missing_docs)]
pub enum Color {
    Red,
    Black,
}

/// Link operations for `RBTree`.
pub unsafe trait RBTreeOps: link_ops::LinkOps {
    /// Returns the left child of `ptr`.
    ///
    /// # Safety
    /// An implementation of `left` must not panic.
    unsafe fn left(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr>;

    /// Returns the right child of `ptr`.
    ///
    /// # Safety
    /// An implementation of `right` must not panic.
    unsafe fn right(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr>;

    /// Returns the parent of `ptr`.
    ///
    /// # Safety
    /// An implementation of `parent` must not panic.
    unsafe fn parent(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr>;

    /// Returns the color of `ptr`.
    ///
    /// # Safety
    /// An implementation of `color` must not panic.
    unsafe fn color(&self, ptr: Self::LinkPtr) -> Color;

    /// Sets the left child of `ptr`.
    ///
    /// # Safety
    /// An implementation of `set_left` must not panic.
    unsafe fn set_left(&mut self, ptr: Self::LinkPtr, left: Option<Self::LinkPtr>);

    /// Sets the right child of `ptr`.
    ///
    /// # Safety
    /// An implementation of `set_right` must not panic.
    unsafe fn set_right(&mut self, ptr: Self::LinkPtr, right: Option<Self::LinkPtr>);

    /// Sets the parent of `ptr`.
    ///
    /// # Safety
    /// An implementation of `set_parent` must not panic.
    unsafe fn set_parent(&mut self, ptr: Self::LinkPtr, parent: Option<Self::LinkPtr>);

    /// Sets the color of `ptr`.
    ///
    /// # Safety
    /// An implementation of `set_color` must not panic.
    unsafe fn set_color(&mut self, ptr: Self::LinkPtr, color: Color);
}

// =============================================================================
// Link
// =============================================================================

/// Intrusive link that allows an object to be inserted into a
/// `RBTree`.
#[repr(align(2))]
pub struct Link {
    left: Cell<Option<NonNull<Link>>>,
    right: Cell<Option<NonNull<Link>>>,
    parent_color: Cell<usize>,
}

// Use a special value to indicate an unlinked node. This value represents a
// red root node, which is impossible in a valid red-black tree.
const UNLINKED_MARKER: usize = 0;

impl Link {
    /// Creates a new `Link`.
    #[inline]
    pub const fn new() -> Link {
        Link {
            left: Cell::new(None),
            right: Cell::new(None),
            parent_color: Cell::new(UNLINKED_MARKER),
        }
    }

    /// Checks whether the `Link` is linked into a `RBTree`.
    #[inline]
    pub fn is_linked(&self) -> bool {
        self.parent_color.get() != UNLINKED_MARKER
    }

    /// Forcibly unlinks an object from a `RBTree`.
    ///
    /// # Safety
    ///
    /// It is undefined behavior to call this function while still linked into a
    /// `RBTree`. The only situation where this function is useful is
    /// after calling `fast_clear` on a `RBTree`, since this clears
    /// the collection without marking the nodes as unlinked.
    #[inline]
    pub unsafe fn force_unlink(&self) {
        self.parent_color.set(UNLINKED_MARKER);
    }
}

impl DefaultLinkOps for Link {
    type Ops = LinkOps;

    const NEW: Self::Ops = LinkOps;
}

// An object containing a link can be sent to another thread if it is unlinked.
unsafe impl Send for Link {}

// Provide an implementation of Clone which simply initializes the new link as
// unlinked. This allows structs containing a link to derive Clone.
impl Clone for Link {
    #[inline]
    fn clone(&self) -> Link {
        Link::new()
    }
}

// Same as above
impl Default for Link {
    #[inline]
    fn default() -> Link {
        Link::new()
    }
}

// Provide an implementation of Debug so that structs containing a link can
// still derive Debug.
impl fmt::Debug for Link {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // There isn't anything sensible to print here except whether the link
        // is currently in a tree.
        if self.is_linked() {
            write!(f, "linked")
        } else {
            write!(f, "unlinked")
        }
    }
}

// =============================================================================
// LinkOps
// =============================================================================

/// Default `LinkOps` implementation for `RBTree`.
#[derive(Clone, Copy, Default)]
pub struct LinkOps;

impl LinkOps {
    #[inline]
    unsafe fn set_parent_color(
        self,
        ptr: <Self as link_ops::LinkOps>::LinkPtr,
        parent: Option<<Self as link_ops::LinkOps>::LinkPtr>,
        color: Color,
    ) {
        assert!(mem::align_of::<Link>() >= 2);
        let bit = match color {
            Color::Red => 0,
            Color::Black => 1,
        };
        let parent_usize = parent.map(|x| x.as_ptr() as usize).unwrap_or(0);
        ptr.as_ref().parent_color.set((parent_usize & !1) | bit);
    }
}

unsafe impl link_ops::LinkOps for LinkOps {
    type LinkPtr = NonNull<Link>;

    #[inline]
    unsafe fn acquire_link(&mut self, ptr: Self::LinkPtr) -> bool {
        if ptr.as_ref().is_linked() {
            false
        } else {
            self.set_parent_color(ptr, None, Color::Black);
            true
        }
    }

    #[inline]
    unsafe fn release_link(&mut self, ptr: Self::LinkPtr) {
        ptr.as_ref().parent_color.set(UNLINKED_MARKER);
    }
}

unsafe impl RBTreeOps for LinkOps {
    #[inline]
    unsafe fn left(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().left.get()
    }

    #[inline]
    unsafe fn right(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().right.get()
    }

    #[inline]
    unsafe fn parent(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        let parent_usize = ptr.as_ref().parent_color.get() & !1;
        NonNull::new(parent_usize as *mut Link)
    }

    #[inline]
    unsafe fn color(&self, ptr: Self::LinkPtr) -> Color {
        if ptr.as_ref().parent_color.get() & 1 == 1 {
            Color::Black
        } else {
            Color::Red
        }
    }

    #[inline]
    unsafe fn set_left(&mut self, ptr: Self::LinkPtr, left: Option<Self::LinkPtr>) {
        ptr.as_ref().left.set(left);
    }

    #[inline]
    unsafe fn set_right(&mut self, ptr: Self::LinkPtr, right: Option<Self::LinkPtr>) {
        ptr.as_ref().right.set(right);
    }

    #[inline]
    unsafe fn set_parent(&mut self, ptr: Self::LinkPtr, parent: Option<Self::LinkPtr>) {
        self.set_parent_color(ptr, parent, self.color(ptr));
    }

    #[inline]
    unsafe fn set_color(&mut self, ptr: Self::LinkPtr, color: Color) {
        self.set_parent_color(ptr, self.parent(ptr), color);
    }
}

unsafe impl SinglyLinkedListOps for LinkOps {
    #[inline]
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        self.right(ptr)
    }

    #[inline]
    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>) {
        self.set_right(ptr, next);
    }
}

unsafe impl LinkedListOps for LinkOps {
    #[inline]
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        self.right(ptr)
    }

    #[inline]
    unsafe fn prev(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        self.left(ptr)
    }

    #[inline]
    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>) {
        self.set_right(ptr, next);
    }

    #[inline]
    unsafe fn set_prev(&mut self, ptr: Self::LinkPtr, prev: Option<Self::LinkPtr>) {
        self.set_left(ptr, prev);
    }
}

unsafe impl XorLinkedListOps for LinkOps {
    #[inline]
    unsafe fn next(
        &self,
        ptr: Self::LinkPtr,
        prev: Option<Self::LinkPtr>,
    ) -> Option<Self::LinkPtr> {
        let packed = self.right(ptr).map(|x| x.as_ptr() as usize).unwrap_or(0);
        let raw = packed ^ prev.map(|x| x.as_ptr() as usize).unwrap_or(0);
        NonNull::new(raw as *mut _)
    }

    #[inline]
    unsafe fn prev(
        &self,
        ptr: Self::LinkPtr,
        next: Option<Self::LinkPtr>,
    ) -> Option<Self::LinkPtr> {
        let packed = self.right(ptr).map(|x| x.as_ptr() as usize).unwrap_or(0);
        let raw = packed ^ next.map(|x| x.as_ptr() as usize).unwrap_or(0);
        NonNull::new(raw as *mut _)
    }

    #[inline]
    unsafe fn set(
        &mut self,
        ptr: Self::LinkPtr,
        prev: Option<Self::LinkPtr>,
        next: Option<Self::LinkPtr>,
    ) {
        let new_packed = prev.map(|x| x.as_ptr() as usize).unwrap_or(0)
            ^ next.map(|x| x.as_ptr() as usize).unwrap_or(0);

        let new_next = NonNull::new(new_packed as *mut _);
        self.set_right(ptr, new_next);
    }

    #[inline]
    unsafe fn replace_next_or_prev(
        &mut self,
        ptr: Self::LinkPtr,
        old: Option<Self::LinkPtr>,
        new: Option<Self::LinkPtr>,
    ) {
        let packed = self.right(ptr).map(|x| x.as_ptr() as usize).unwrap_or(0);
        let new_packed = packed
            ^ old.map(|x| x.as_ptr() as usize).unwrap_or(0)
            ^ new.map(|x| x.as_ptr() as usize).unwrap_or(0);

        let new_next = NonNull::new(new_packed as *mut _);
        self.set_right(ptr, new_next);
    }
}

// =============================================================================
// AtomicLink
// =============================================================================

/// Intrusive link that allows an object to be inserted into a
/// `RBTree`. This link allows the structure to be shared between threads.

#[repr(align(2))]
pub struct AtomicLink {
    left: Cell<Option<NonNull<AtomicLink>>>,
    right: Cell<Option<NonNull<AtomicLink>>>,
    parent_color: AtomicUsize,
}

impl AtomicLink {
    #[inline]
    /// Creates a new `AtomicLink`.
    pub const fn new() -> AtomicLink {
        AtomicLink {
            left: Cell::new(None),
            right: Cell::new(None),
            parent_color: AtomicUsize::new(UNLINKED_MARKER),
        }
    }

    /// Checks whether the `AtomicLink` is linked into a `RBTree`.
    #[inline]
    pub fn is_linked(&self) -> bool {
        self.parent_color.load(atomic::Ordering::Relaxed) != UNLINKED_MARKER
    }

    /// Forcibly unlinks an object from a `RBTree`.
    ///
    /// # Safety
    ///
    /// It is undefined behavior to call this function while still linked into a
    /// `RBTree`. The only situation where this function is useful is
    /// after calling `fast_clear` on a `RBTree`, since this clears
    /// the collection without marking the nodes as unlinked.
    #[inline]
    pub unsafe fn force_unlink(&self) {
        self.parent_color
            .store(UNLINKED_MARKER, atomic::Ordering::Release);
    }

    /// Access `parent_color` in an exclusive context.
    ///
    /// # Safety
    ///
    /// This can only be called after `acquire_link` has been succesfully called.
    #[inline]
    unsafe fn parent_color_exclusive(&self) -> &Cell<usize> {
        // This is safe because currently AtomicUsize has the same representation Cell<usize>.
        core::mem::transmute(&self.parent_color)
    }
}

impl DefaultLinkOps for AtomicLink {
    type Ops = AtomicLinkOps;

    const NEW: Self::Ops = AtomicLinkOps;
}

// An object containing a link can be sent to another thread since `acquire_link` is atomic.
unsafe impl Send for AtomicLink {}

// An object containing a link can be shared between threads since `acquire_link` is atomic.
unsafe impl Sync for AtomicLink {}

impl Clone for AtomicLink {
    #[inline]
    fn clone(&self) -> AtomicLink {
        AtomicLink::new()
    }
}

impl Default for AtomicLink {
    #[inline]
    fn default() -> AtomicLink {
        AtomicLink::new()
    }
}

// Provide an implementation of Debug so that structs containing a link can
// still derive Debug.
impl fmt::Debug for AtomicLink {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // There isn't anything sensible to print here except whether the link
        // is currently in a list.
        if self.is_linked() {
            write!(f, "linked")
        } else {
            write!(f, "unlinked")
        }
    }
}

// =============================================================================
// AtomicLinkOps
// =============================================================================

/// Default `LinkOps` implementation for `RBTree`.
#[derive(Clone, Copy, Default)]
pub struct AtomicLinkOps;

impl AtomicLinkOps {
    #[inline]
    unsafe fn set_parent_color(
        self,
        ptr: <Self as link_ops::LinkOps>::LinkPtr,
        parent: Option<<Self as link_ops::LinkOps>::LinkPtr>,
        color: Color,
    ) {
        assert!(mem::align_of::<Link>() >= 2);
        let bit = match color {
            Color::Red => 0,
            Color::Black => 1,
        };
        let parent_usize = parent.map(|x| x.as_ptr() as usize).unwrap_or(0);
        ptr.as_ref()
            .parent_color_exclusive()
            .set((parent_usize & !1) | bit);
    }
}

const LINKED_DEFAULT_VALUE: usize = 1;

unsafe impl link_ops::LinkOps for AtomicLinkOps {
    type LinkPtr = NonNull<AtomicLink>;

    #[inline]
    unsafe fn acquire_link(&mut self, ptr: Self::LinkPtr) -> bool {
        ptr.as_ref()
            .parent_color
            .compare_exchange(
                UNLINKED_MARKER,
                LINKED_DEFAULT_VALUE,
                atomic::Ordering::Acquire,
                atomic::Ordering::Relaxed,
            )
            .is_ok()
    }

    #[inline]
    unsafe fn release_link(&mut self, ptr: Self::LinkPtr) {
        ptr.as_ref()
            .parent_color
            .store(UNLINKED_MARKER, atomic::Ordering::Release)
    }
}

unsafe impl RBTreeOps for AtomicLinkOps {
    #[inline]
    unsafe fn left(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().left.get()
    }

    #[inline]
    unsafe fn right(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().right.get()
    }

    #[inline]
    unsafe fn parent(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        let parent_usize = ptr.as_ref().parent_color_exclusive().get() & !1;
        NonNull::new(parent_usize as *mut AtomicLink)
    }

    #[inline]
    unsafe fn color(&self, ptr: Self::LinkPtr) -> Color {
        if ptr.as_ref().parent_color_exclusive().get() & 1 == 1 {
            Color::Black
        } else {
            Color::Red
        }
    }

    #[inline]
    unsafe fn set_left(&mut self, ptr: Self::LinkPtr, left: Option<Self::LinkPtr>) {
        ptr.as_ref().left.set(left);
    }

    #[inline]
    unsafe fn set_right(&mut self, ptr: Self::LinkPtr, right: Option<Self::LinkPtr>) {
        ptr.as_ref().right.set(right);
    }

    #[inline]
    unsafe fn set_parent(&mut self, ptr: Self::LinkPtr, parent: Option<Self::LinkPtr>) {
        self.set_parent_color(ptr, parent, self.color(ptr));
    }

    #[inline]
    unsafe fn set_color(&mut self, ptr: Self::LinkPtr, color: Color) {
        self.set_parent_color(ptr, self.parent(ptr), color);
    }
}

unsafe impl SinglyLinkedListOps for AtomicLinkOps {
    #[inline]
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        self.right(ptr)
    }

    #[inline]
    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>) {
        self.set_right(ptr, next);
    }
}

unsafe impl LinkedListOps for AtomicLinkOps {
    #[inline]
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        self.right(ptr)
    }

    #[inline]
    unsafe fn prev(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        self.left(ptr)
    }

    #[inline]
    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>) {
        self.set_right(ptr, next);
    }

    #[inline]
    unsafe fn set_prev(&mut self, ptr: Self::LinkPtr, prev: Option<Self::LinkPtr>) {
        self.set_left(ptr, prev);
    }
}

unsafe impl XorLinkedListOps for AtomicLinkOps {
    #[inline]
    unsafe fn next(
        &self,
        ptr: Self::LinkPtr,
        prev: Option<Self::LinkPtr>,
    ) -> Option<Self::LinkPtr> {
        let packed = self.right(ptr).map(|x| x.as_ptr() as usize).unwrap_or(0);
        let raw = packed ^ prev.map(|x| x.as_ptr() as usize).unwrap_or(0);
        NonNull::new(raw as *mut _)
    }

    #[inline]
    unsafe fn prev(
        &self,
        ptr: Self::LinkPtr,
        next: Option<Self::LinkPtr>,
    ) -> Option<Self::LinkPtr> {
        let packed = self.right(ptr).map(|x| x.as_ptr() as usize).unwrap_or(0);
        let raw = packed ^ next.map(|x| x.as_ptr() as usize).unwrap_or(0);
        NonNull::new(raw as *mut _)
    }

    #[inline]
    unsafe fn set(
        &mut self,
        ptr: Self::LinkPtr,
        prev: Option<Self::LinkPtr>,
        next: Option<Self::LinkPtr>,
    ) {
        let new_packed = prev.map(|x| x.as_ptr() as usize).unwrap_or(0)
            ^ next.map(|x| x.as_ptr() as usize).unwrap_or(0);

        let new_next = NonNull::new(new_packed as *mut _);
        self.set_right(ptr, new_next);
    }

    #[inline]
    unsafe fn replace_next_or_prev(
        &mut self,
        ptr: Self::LinkPtr,
        old: Option<Self::LinkPtr>,
        new: Option<Self::LinkPtr>,
    ) {
        let packed = self.right(ptr).map(|x| x.as_ptr() as usize).unwrap_or(0);
        let new_packed = packed
            ^ old.map(|x| x.as_ptr() as usize).unwrap_or(0)
            ^ new.map(|x| x.as_ptr() as usize).unwrap_or(0);

        let new_next = NonNull::new(new_packed as *mut _);
        self.set_right(ptr, new_next);
    }
}

#[inline]
unsafe fn is_left_child<T: RBTreeOps>(link_ops: &T, ptr: T::LinkPtr, parent: T::LinkPtr) -> bool {
    link_ops.left(parent) == Some(ptr)
}

#[inline]
unsafe fn first_child<T: RBTreeOps>(link_ops: &T, ptr: T::LinkPtr) -> T::LinkPtr {
    let mut x = ptr;
    while let Some(y) = link_ops.left(x) {
        x = y;
    }
    x
}

#[inline]
unsafe fn last_child<T: RBTreeOps>(link_ops: &T, ptr: T::LinkPtr) -> T::LinkPtr {
    let mut x = ptr;
    while let Some(y) = link_ops.right(x) {
        x = y;
    }
    x
}

#[inline]
unsafe fn next<T: RBTreeOps>(link_ops: &T, ptr: T::LinkPtr) -> Option<T::LinkPtr> {
    if let Some(right) = link_ops.right(ptr) {
        Some(first_child(link_ops, right))
    } else {
        let mut x = ptr;
        loop {
            if let Some(parent) = link_ops.parent(x) {
                if is_left_child(link_ops, x, parent) {
                    return Some(parent);
                }

                x = parent;
            } else {
                return None;
            }
        }
    }
}

#[inline]
unsafe fn prev<T: RBTreeOps>(link_ops: &T, ptr: T::LinkPtr) -> Option<T::LinkPtr> {
    if let Some(left) = link_ops.left(ptr) {
        Some(last_child(link_ops, left))
    } else {
        let mut x = ptr;
        loop {
            if let Some(parent) = link_ops.parent(x) {
                if !is_left_child(link_ops, x, parent) {
                    return Some(parent);
                }

                x = parent;
            } else {
                return None;
            }
        }
    }
}

#[inline]
unsafe fn replace_with<T: RBTreeOps>(
    link_ops: &mut T,
    ptr: T::LinkPtr,
    new: T::LinkPtr,
    root: &mut Option<T::LinkPtr>,
) {
    if let Some(parent) = link_ops.parent(ptr) {
        if is_left_child(link_ops, ptr, parent) {
            link_ops.set_left(parent, Some(new));
        } else {
            link_ops.set_right(parent, Some(new));
        }
    } else {
        *root = Some(new);
    }
    if let Some(left) = link_ops.left(ptr) {
        link_ops.set_parent(left, Some(new));
    }
    if let Some(right) = link_ops.right(ptr) {
        link_ops.set_parent(right, Some(new));
    }
    link_ops.set_left(new, link_ops.left(ptr));
    link_ops.set_right(new, link_ops.right(ptr));
    link_ops.set_parent(new, link_ops.parent(ptr));
    link_ops.set_color(new, link_ops.color(ptr));
    link_ops.release_link(ptr);
}

#[inline]
unsafe fn insert_left<T: RBTreeOps>(
    link_ops: &mut T,
    ptr: T::LinkPtr,
    new: T::LinkPtr,
    root: &mut Option<T::LinkPtr>,
) {
    link_ops.set_parent(new, Some(ptr));
    link_ops.set_color(new, Color::Red);
    link_ops.set_left(new, None);
    link_ops.set_right(new, None);
    link_ops.set_left(ptr, Some(new));
    post_insert(link_ops, new, root);
}

#[inline]
unsafe fn insert_right<T: RBTreeOps>(
    link_ops: &mut T,
    ptr: T::LinkPtr,
    new: T::LinkPtr,
    root: &mut Option<T::LinkPtr>,
) {
    link_ops.set_parent(new, Some(ptr));
    link_ops.set_color(new, Color::Red);
    link_ops.set_left(new, None);
    link_ops.set_right(new, None);
    link_ops.set_right(ptr, Some(new));
    post_insert(link_ops, new, root);
}

unsafe fn rotate_left<T: RBTreeOps>(
    link_ops: &mut T,
    ptr: T::LinkPtr,
    root: &mut Option<T::LinkPtr>,
) {
    let y = link_ops.right(ptr).unwrap_unchecked();
    link_ops.set_right(ptr, link_ops.left(y));
    if let Some(right) = link_ops.right(ptr) {
        link_ops.set_parent(right, Some(ptr));
    }
    link_ops.set_parent(y, link_ops.parent(ptr));
    if let Some(parent) = link_ops.parent(ptr) {
        if is_left_child(link_ops, ptr, parent) {
            link_ops.set_left(parent, Some(y));
        } else {
            link_ops.set_right(parent, Some(y));
        }
    } else {
        *root = Some(y);
    }
    link_ops.set_left(y, Some(ptr));
    link_ops.set_parent(ptr, Some(y));
}

unsafe fn rotate_right<T: RBTreeOps>(
    link_ops: &mut T,
    ptr: T::LinkPtr,
    root: &mut Option<T::LinkPtr>,
) {
    let y = link_ops.left(ptr).unwrap_unchecked();
    link_ops.set_left(ptr, link_ops.right(y));
    if let Some(left) = link_ops.left(ptr) {
        link_ops.set_parent(left, Some(ptr));
    }
    link_ops.set_parent(y, link_ops.parent(ptr));
    if let Some(parent) = link_ops.parent(ptr) {
        if is_left_child(link_ops, ptr, parent) {
            link_ops.set_left(parent, Some(y));
        } else {
            link_ops.set_right(parent, Some(y));
        }
    } else {
        *root = Some(y);
    }
    link_ops.set_right(y, Some(ptr));
    link_ops.set_parent(ptr, Some(y));
}

// This code is based on the red-black tree implementation in libc++
unsafe fn post_insert<T: RBTreeOps>(
    link_ops: &mut T,
    ptr: T::LinkPtr,
    root: &mut Option<T::LinkPtr>,
) {
    let mut x = ptr;
    while let Some(parent) = link_ops.parent(x) {
        if link_ops.color(parent) != Color::Red {
            break;
        }
        // SAFETY: The root of the tree must be black, and `parent` cannot be the root if it is red.
        let grandparent = link_ops.parent(parent).unwrap_unchecked();

        if is_left_child(link_ops, parent, grandparent) {
            let y = link_ops.right(grandparent);
            if let Some(y) = y {
                if link_ops.color(y) == Color::Red {
                    x = parent;
                    link_ops.set_color(x, Color::Black);
                    x = grandparent;

                    if link_ops.parent(x).is_none() {
                        link_ops.set_color(x, Color::Black);
                    } else {
                        link_ops.set_color(x, Color::Red);
                    }
                    link_ops.set_color(y, Color::Black);
                    continue;
                }
            }
            if !is_left_child(link_ops, x, parent) {
                x = parent;
                rotate_left(link_ops, x, root);
            }
            x = link_ops.parent(x).unwrap_unchecked();
            link_ops.set_color(x, Color::Black);
            x = link_ops.parent(x).unwrap_unchecked();
            link_ops.set_color(x, Color::Red);
            rotate_right(link_ops, x, root);
        } else {
            let y = link_ops.left(grandparent);
            if let Some(y) = y {
                if link_ops.color(y) == Color::Red {
                    x = parent;
                    link_ops.set_color(x, Color::Black);
                    x = grandparent;
                    if link_ops.parent(x).is_none() {
                        link_ops.set_color(x, Color::Black);
                    } else {
                        link_ops.set_color(x, Color::Red);
                    }
                    link_ops.set_color(y, Color::Black);
                    continue;
                }
            }
            if is_left_child(link_ops, x, parent) {
                x = parent;
                rotate_right(link_ops, x, root);
            }
            x = link_ops.parent(x).unwrap_unchecked();
            link_ops.set_color(x, Color::Black);
            x = link_ops.parent(x).unwrap_unchecked();
            link_ops.set_color(x, Color::Red);
            rotate_left(link_ops, x, root);
        }
        break;
    }
}

// This code is based on the red-black tree implementation in libc++
unsafe fn remove<T: RBTreeOps>(link_ops: &mut T, ptr: T::LinkPtr, root: &mut Option<T::LinkPtr>) {
    let y = if link_ops.left(ptr).is_none() || link_ops.right(ptr).is_none() {
        ptr
    } else {
        next(link_ops, ptr).unwrap_unchecked()
    };
    let x = if link_ops.left(y).is_some() {
        link_ops.left(y)
    } else {
        link_ops.right(y)
    };
    let mut w = None;
    if let Some(x) = x {
        link_ops.set_parent(x, link_ops.parent(y));
    }
    if let Some(y_parent) = link_ops.parent(y) {
        if is_left_child(link_ops, y, y_parent) {
            link_ops.set_left(y_parent, x);
            w = link_ops.right(y_parent);
        } else {
            link_ops.set_right(y_parent, x);
            w = link_ops.left(y_parent);
        }
    } else {
        *root = x;
    }
    let removed_black = link_ops.color(y) == Color::Black;
    if y != ptr {
        if let Some(parent) = link_ops.parent(ptr) {
            link_ops.set_parent(y, Some(parent));
            if is_left_child(link_ops, ptr, parent) {
                link_ops.set_left(parent, Some(y));
            } else {
                link_ops.set_right(parent, Some(y));
            }
        } else {
            link_ops.set_parent(y, None);
            *root = Some(y);
        }
        link_ops.set_left(y, link_ops.left(ptr));
        link_ops.set_parent(link_ops.left(y).unwrap_unchecked(), Some(y));
        link_ops.set_right(y, link_ops.right(ptr));
        if let Some(y_right) = link_ops.right(y) {
            link_ops.set_parent(y_right, Some(y));
        }
        link_ops.set_color(y, link_ops.color(ptr));
    }
    if removed_black && !root.is_none() {
        if let Some(x) = x {
            link_ops.set_color(x, Color::Black);
        } else {
            let mut w = w.unwrap_unchecked();
            loop {
                let mut w_parent = link_ops.parent(w).unwrap_unchecked();
                if !is_left_child(link_ops, w, w_parent) {
                    if link_ops.color(w) == Color::Red {
                        link_ops.set_color(w, Color::Black);
                        link_ops.set_color(w_parent, Color::Red);
                        rotate_left(link_ops, w_parent, root);
                        w = link_ops
                            .right(link_ops.left(w).unwrap_unchecked())
                            .unwrap_unchecked();
                        w_parent = link_ops.parent(w).unwrap_unchecked();
                    }

                    let left_color = link_ops.left(w).map(|x| link_ops.color(x));
                    let right_color = link_ops.right(w).map(|x| link_ops.color(x));
                    if (left_color != Some(Color::Red)) && (right_color != Some(Color::Red)) {
                        link_ops.set_color(w, Color::Red);
                        if link_ops.parent(w_parent).is_none()
                            || link_ops.color(w_parent) == Color::Red
                        {
                            link_ops.set_color(w_parent, Color::Black);
                            break;
                        }
                        let w_grandparent = link_ops.parent(w_parent).unwrap_unchecked();
                        w = if is_left_child(link_ops, w_parent, w_grandparent) {
                            link_ops.right(w_grandparent).unwrap_unchecked()
                        } else {
                            link_ops.left(w_grandparent).unwrap_unchecked()
                        };
                    } else {
                        if link_ops.right(w).map(|x| link_ops.color(x)) != Some(Color::Red) {
                            link_ops.set_color(link_ops.left(w).unwrap_unchecked(), Color::Black);
                            link_ops.set_color(w, Color::Red);
                            rotate_right(link_ops, w, root);
                            w = link_ops.parent(w).unwrap_unchecked();
                            w_parent = link_ops.parent(w).unwrap_unchecked();
                        }
                        link_ops.set_color(w, link_ops.color(w_parent));
                        link_ops.set_color(w_parent, Color::Black);
                        link_ops.set_color(link_ops.right(w).unwrap_unchecked(), Color::Black);
                        rotate_left(link_ops, w_parent, root);
                        break;
                    }
                } else {
                    if link_ops.color(w) == Color::Red {
                        link_ops.set_color(w, Color::Black);
                        link_ops.set_color(w_parent, Color::Red);
                        rotate_right(link_ops, w_parent, root);
                        w = link_ops
                            .left(link_ops.right(w).unwrap_unchecked())
                            .unwrap_unchecked();
                        w_parent = link_ops.parent(w).unwrap_unchecked();
                    }
                    let left_color = link_ops.left(w).map(|x| link_ops.color(x));
                    let right_color = link_ops.right(w).map(|x| link_ops.color(x));
                    if (left_color != Some(Color::Red)) && (right_color != Some(Color::Red)) {
                        link_ops.set_color(w, Color::Red);
                        if link_ops.parent(w_parent).is_none()
                            || link_ops.color(w_parent) == Color::Red
                        {
                            link_ops.set_color(w_parent, Color::Black);
                            break;
                        }
                        w = if is_left_child(
                            link_ops,
                            w_parent,
                            link_ops.parent(w_parent).unwrap_unchecked(),
                        ) {
                            link_ops
                                .right(link_ops.parent(w_parent).unwrap_unchecked())
                                .unwrap_unchecked()
                        } else {
                            link_ops
                                .left(link_ops.parent(w_parent).unwrap_unchecked())
                                .unwrap_unchecked()
                        };
                    } else {
                        if link_ops.left(w).map(|x| link_ops.color(x)) != Some(Color::Red) {
                            link_ops.set_color(link_ops.right(w).unwrap_unchecked(), Color::Black);
                            link_ops.set_color(w, Color::Red);
                            rotate_left(link_ops, w, root);
                            w = link_ops.parent(w).unwrap_unchecked();
                            w_parent = link_ops.parent(w).unwrap_unchecked();
                        }
                        link_ops.set_color(w, link_ops.color(w_parent));
                        link_ops.set_color(w_parent, Color::Black);
                        link_ops.set_color(link_ops.left(w).unwrap_unchecked(), Color::Black);
                        rotate_right(link_ops, w_parent, root);
                        break;
                    }
                }
            }
        }
    }
    link_ops.release_link(ptr);
}

// =============================================================================
// Cursor, CursorMut, CursorOwning
// =============================================================================

/// A cursor which provides read-only access to a `RBTree`.
pub struct Cursor<'a, A: Adapter>
where
    A::LinkOps: RBTreeOps,
{
    current: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    tree: &'a RBTree<A>,
}

impl<'a, A: Adapter> Clone for Cursor<'a, A>
where
    A::LinkOps: RBTreeOps,
{
    #[inline]
    fn clone(&self) -> Cursor<'a, A> {
        Cursor {
            current: self.current,
            tree: self.tree,
        }
    }
}

impl<'a, A: Adapter> Cursor<'a, A>
where
    A::LinkOps: RBTreeOps,
{
    /// Checks if the cursor is currently pointing to the null object.
    #[inline]
    pub fn is_null(&self) -> bool {
        self.current.is_none()
    }

    /// Returns a reference to the object that the cursor is currently
    /// pointing to.
    ///
    /// This returns `None` if the cursor is currently pointing to the null
    /// object.
    #[inline]
    pub fn get(&self) -> Option<&'a <A::PointerOps as PointerOps>::Value> {
        Some(unsafe { &*self.tree.adapter.get_value(self.current?) })
    }

    /// Clones and returns the pointer that points to the element that the
    /// cursor is referencing.
    ///
    /// This returns `None` if the cursor is currently pointing to the null
    /// object.
    #[inline]
    pub fn clone_pointer(&self) -> Option<<A::PointerOps as PointerOps>::Pointer>
    where
        <A::PointerOps as PointerOps>::Pointer: Clone,
    {
        let raw_pointer = unsafe { self.tree.adapter.get_value(self.current?) };
        Some(unsafe {
            crate::pointer_ops::clone_pointer_from_raw(self.tree.adapter.pointer_ops(), raw_pointer)
        })
    }

    /// Moves the cursor to the next element of the `RBTree`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the first element of the `RBTree`. If it is pointing to the last
    /// element of the `RBTree` then this will move it to the null object.
    #[inline]
    pub fn move_next(&mut self) {
        if let Some(current) = self.current {
            self.current = unsafe { next(self.tree.adapter.link_ops(), current) };
        } else if let Some(root) = self.tree.root {
            self.current = Some(unsafe { first_child(self.tree.adapter.link_ops(), root) });
        } else {
            self.current = None;
        }
    }

    /// Moves the cursor to the previous element of the `RBTree`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the last element of the `RBTree`. If it is pointing to the first
    /// element of the `RBTree` then this will move it to the null object.
    #[inline]
    pub fn move_prev(&mut self) {
        if let Some(current) = self.current {
            self.current = unsafe { prev(self.tree.adapter.link_ops(), current) };
        } else if let Some(root) = self.tree.root {
            self.current = Some(unsafe { last_child(self.tree.adapter.link_ops(), root) });
        } else {
            self.current = None;
        }
    }

    /// Returns a cursor pointing to the next element of the `RBTree`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// first element of the `RBTree`. If it is pointing to the last
    /// element of the `RBTree` then this will return a null cursor.
    #[inline]
    pub fn peek_next(&self) -> Cursor<'_, A> {
        let mut next = self.clone();
        next.move_next();
        next
    }

    /// Returns a cursor pointing to the previous element of the `RBTree`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// last element of the `RBTree`. If it is pointing to the first
    /// element of the `RBTree` then this will return a null cursor.
    #[inline]
    pub fn peek_prev(&self) -> Cursor<'_, A> {
        let mut prev = self.clone();
        prev.move_prev();
        prev
    }
}

/// A cursor which provides mutable access to a `RBTree`.
pub struct CursorMut<'a, A: Adapter>
where
    A::LinkOps: RBTreeOps,
{
    current: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    tree: &'a mut RBTree<A>,
}

impl<'a, A: Adapter> CursorMut<'a, A>
where
    A::LinkOps: RBTreeOps,
{
    /// Checks if the cursor is currently pointing to the null object.
    #[inline]
    pub fn is_null(&self) -> bool {
        self.current.is_none()
    }

    /// Returns a reference to the object that the cursor is currently
    /// pointing to.
    ///
    /// This returns None if the cursor is currently pointing to the null
    /// object.
    #[inline]
    pub fn get(&self) -> Option<&<A::PointerOps as PointerOps>::Value> {
        Some(unsafe { &*self.tree.adapter.get_value(self.current?) })
    }

    /// Returns a read-only cursor pointing to the current element.
    ///
    /// The lifetime of the returned `Cursor` is bound to that of the
    /// `CursorMut`, which means it cannot outlive the `CursorMut` and that the
    /// `CursorMut` is frozen for the lifetime of the `Cursor`.
    #[inline]
    pub fn as_cursor(&self) -> Cursor<'_, A> {
        Cursor {
            current: self.current,
            tree: self.tree,
        }
    }

    /// Moves the cursor to the next element of the `RBTree`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the first element of the `RBTree`. If it is pointing to the last
    /// element of the `RBTree` then this will move it to the null object.
    #[inline]
    pub fn move_next(&mut self) {
        if let Some(current) = self.current {
            self.current = unsafe { next(self.tree.adapter.link_ops(), current) };
        } else if let Some(root) = self.tree.root {
            self.current = Some(unsafe { first_child(self.tree.adapter.link_ops(), root) });
        } else {
            self.current = None;
        }
    }

    /// Moves the cursor to the previous element of the `RBTree`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the last element of the `RBTree`. If it is pointing to the first
    /// element of the `RBTree` then this will move it to the null object.
    #[inline]
    pub fn move_prev(&mut self) {
        if let Some(current) = self.current {
            self.current = unsafe { prev(self.tree.adapter.link_ops(), current) };
        } else if let Some(root) = self.tree.root {
            self.current = Some(unsafe { last_child(self.tree.adapter.link_ops(), root) });
        } else {
            self.current = None;
        }
    }

    /// Returns a cursor pointing to the next element of the `RBTree`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// first element of the `RBTree`. If it is pointing to the last
    /// element of the `RBTree` then this will return a null cursor.
    #[inline]
    pub fn peek_next(&self) -> Cursor<'_, A> {
        let mut next = self.as_cursor();
        next.move_next();
        next
    }

    /// Returns a cursor pointing to the previous element of the `RBTree`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// last element of the `RBTree`. If it is pointing to the first
    /// element of the `RBTree` then this will return a null cursor.
    #[inline]
    pub fn peek_prev(&self) -> Cursor<'_, A> {
        let mut prev = self.as_cursor();
        prev.move_prev();
        prev
    }

    /// Removes the current element from the `RBTree`.
    ///
    /// A pointer to the element that was removed is returned, and the cursor is
    /// moved to point to the next element in the `RBTree`.
    ///
    /// If the cursor is currently pointing to the null object then no element
    /// is removed and `None` is returned.
    #[inline]
    pub fn remove(&mut self) -> Option<<A::PointerOps as PointerOps>::Pointer> {
        unsafe {
            if let Some(current) = self.current {
                let next = next(self.tree.adapter.link_ops(), current);
                let result = current;
                remove(
                    self.tree.adapter.link_ops_mut(),
                    current,
                    &mut self.tree.root,
                );
                self.current = next;
                Some(
                    self.tree
                        .adapter
                        .pointer_ops()
                        .from_raw(self.tree.adapter.get_value(result)),
                )
            } else {
                None
            }
        }
    }

    /// Removes the current element from the `RBTree` and inserts another
    /// object in its place.
    ///
    /// A pointer to the element that was removed is returned, and the cursor is
    /// modified to point to the newly added element.
    ///
    /// When using this function you must ensure that the elements in the
    /// collection are maintained in increasing order. Failure to do this may
    /// lead to `find`, `upper_bound`, `lower_bound` and `range` returning
    /// incorrect results.
    ///
    /// If the cursor is currently pointing to the null object then an error is
    /// returned containing the given `val` parameter.
    ///
    /// # Panics
    ///
    /// Panics if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn replace_with(
        &mut self,
        val: <A::PointerOps as PointerOps>::Pointer,
    ) -> Result<<A::PointerOps as PointerOps>::Pointer, <A::PointerOps as PointerOps>::Pointer>
    {
        unsafe {
            if let Some(current) = self.current {
                let new = self.tree.node_from_value(val);
                let result = current;
                replace_with(
                    self.tree.adapter.link_ops_mut(),
                    current,
                    new,
                    &mut self.tree.root,
                );
                self.current = Some(new);
                Ok(self
                    .tree
                    .adapter
                    .pointer_ops()
                    .from_raw(self.tree.adapter.get_value(result)))
            } else {
                Err(val)
            }
        }
    }

    /// Inserts a new element into the `RBTree` after the current one.
    ///
    /// When using this function you must ensure that the elements in the
    /// collection are maintained in increasing order. Failure to do this may
    /// lead to `find`, `upper_bound`, `lower_bound` and `range` returning
    /// incorrect results.
    ///
    /// If the cursor is pointing at the null object then the new element is
    /// inserted at the start of the `RBTree`.
    ///
    /// # Panics
    ///
    /// Panics if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn insert_after(&mut self, val: <A::PointerOps as PointerOps>::Pointer) {
        unsafe {
            let new = self.tree.node_from_value(val);
            let link_ops = self.tree.adapter.link_ops_mut();

            if let Some(root) = self.tree.root {
                if let Some(current) = self.current {
                    if link_ops.right(current).is_some() {
                        let next = next(link_ops, current).unwrap_unchecked();
                        insert_left(link_ops, next, new, &mut self.tree.root);
                    } else {
                        insert_right(link_ops, current, new, &mut self.tree.root);
                    }
                } else {
                    insert_left(
                        link_ops,
                        first_child(link_ops, root),
                        new,
                        &mut self.tree.root,
                    );
                }
            } else {
                self.tree.insert_root(new);
            }
        }
    }

    /// Inserts a new element into the `RBTree` before the current one.
    ///
    /// When using this function you must ensure that the elements in the
    /// collection are maintained in increasing order. Failure to do this may
    /// lead to `find`, `upper_bound`, `lower_bound` and `range` returning
    /// incorrect results.
    ///
    /// If the cursor is pointing at the null object then the new element is
    /// inserted at the end of the `RBTree`.
    ///
    /// # Panics
    ///
    /// Panics if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn insert_before(&mut self, val: <A::PointerOps as PointerOps>::Pointer) {
        unsafe {
            let new = self.tree.node_from_value(val);
            let link_ops = self.tree.adapter.link_ops_mut();

            if let Some(root) = self.tree.root {
                if let Some(current) = self.current {
                    if link_ops.left(current).is_some() {
                        let prev = prev(link_ops, current).unwrap_unchecked();
                        insert_right(link_ops, prev, new, &mut self.tree.root);
                    } else {
                        insert_left(link_ops, current, new, &mut self.tree.root);
                    }
                } else {
                    insert_right(
                        link_ops,
                        last_child(link_ops, root),
                        new,
                        &mut self.tree.root,
                    );
                }
            } else {
                self.tree.insert_root(new);
            }
        }
    }

    /// Consumes `CursorMut` and returns a reference to the object that
    /// the cursor is currently pointing to. Unlike [get](Self::get),
    /// the returned reference's lifetime is tied to `RBTree`'s lifetime.
    ///
    /// This returns None if the cursor is currently pointing to the null object.
    #[inline]
    pub fn into_ref(self) -> Option<&'a <A::PointerOps as PointerOps>::Value> {
        Some(unsafe { &*self.tree.adapter.get_value(self.current?) })
    }
}

impl<'a, A: for<'b> KeyAdapter<'b>> CursorMut<'a, A>
where
    <A as Adapter>::LinkOps: RBTreeOps,
{
    /// Inserts a new element into the `RBTree`.
    ///
    /// The new element will be inserted at the correct position in the tree
    /// based on its key, regardless of the current cursor position.
    ///
    /// # Panics
    ///
    /// Panics if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn insert<'c>(&'c mut self, val: <A::PointerOps as PointerOps>::Pointer)
    where
        <A as KeyAdapter<'c>>::Key: Ord,
    {
        // We explicitly drop the returned CursorMut here, otherwise we would
        // end up with multiple CursorMut in the same collection.
        self.tree.insert(val);
    }
}

/// A cursor with ownership over the `RBTree` it points into.
pub struct CursorOwning<A: Adapter>
where
    A::LinkOps: RBTreeOps,
{
    current: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    tree: RBTree<A>,
}

impl<A: Adapter> CursorOwning<A>
where
    A::LinkOps: RBTreeOps,
{
    /// Consumes self and returns the inner `RBTree`.
    #[inline]
    pub fn into_inner(self) -> RBTree<A> {
        self.tree
    }

    /// Returns a read-only cursor pointing to the current element.
    ///
    /// The lifetime of the returned `Cursor` is bound to that of the
    /// `CursorOwning`, which means it cannot outlive the `CursorOwning` and that the
    /// `CursorOwning` is frozen for the lifetime of the `Cursor`.
    ///
    /// Mutations of the returned cursor are _not_ reflected in the original.
    #[inline]
    pub fn as_cursor(&self) -> Cursor<'_, A> {
        Cursor {
            current: self.current,
            tree: &self.tree,
        }
    }

    /// Perform action with mutable reference to the cursor.
    ///
    /// All mutations of the cursor are reflected in the original.
    #[inline]
    pub fn with_cursor_mut<T>(&mut self, f: impl FnOnce(&mut CursorMut<'_, A>) -> T) -> T {
        let mut cursor = CursorMut {
            current: self.current,
            tree: &mut self.tree,
        };
        let ret = f(&mut cursor);
        self.current = cursor.current;
        ret
    }
}
unsafe impl<A: Adapter> Send for CursorOwning<A>
where
    RBTree<A>: Send,
    A::LinkOps: RBTreeOps,
{
}

// =============================================================================
// RBTree
// =============================================================================

/// An intrusive red-black tree.
///
/// When this collection is dropped, all elements linked into it will be
/// converted back to owned pointers and dropped.
///
/// Note that you are responsible for ensuring that the elements in a `RBTree`
/// remain in ascending key order. This property can be violated, either because
/// the key of an element was modified, or because the
/// `insert_before`/`insert_after` methods of `CursorMut` were incorrectly used.
/// If this situation occurs, memory safety will not be violated but the `find`,
/// `upper_bound`, `lower_bound` and `range` may return incorrect results.
pub struct RBTree<A: Adapter>
where
    A::LinkOps: RBTreeOps,
{
    root: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    adapter: A,
}

impl<A: Adapter> RBTree<A>
where
    A::LinkOps: RBTreeOps,
{
    #[inline]
    fn node_from_value(
        &mut self,
        val: <A::PointerOps as PointerOps>::Pointer,
    ) -> <A::LinkOps as link_ops::LinkOps>::LinkPtr {
        use link_ops::LinkOps;

        unsafe {
            let raw = self.adapter.pointer_ops().into_raw(val);
            let link = self.adapter.get_link(raw);

            if !self.adapter.link_ops_mut().acquire_link(link) {
                // convert the node back into a pointer
                self.adapter.pointer_ops().from_raw(raw);

                panic!("attempted to insert an object that is already linked");
            }

            link
        }
    }

    /// Creates an empty `RBTree`.
    #[cfg(not(feature = "nightly"))]
    #[inline]
    pub fn new(adapter: A) -> RBTree<A> {
        RBTree {
            root: None,
            adapter,
        }
    }

    /// Creates an empty `RBTree`.
    #[cfg(feature = "nightly")]
    #[inline]
    pub const fn new(adapter: A) -> RBTree<A> {
        RBTree {
            root: None,
            adapter,
        }
    }

    /// Returns `true` if the `RBTree` is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Returns a null `Cursor` for this tree.
    #[inline]
    pub fn cursor(&self) -> Cursor<'_, A> {
        Cursor {
            current: None,
            tree: self,
        }
    }

    /// Returns a null `CursorMut` for this tree.
    #[inline]
    pub fn cursor_mut(&mut self) -> CursorMut<'_, A> {
        CursorMut {
            current: None,
            tree: self,
        }
    }

    /// Returns a null `CursorOwning` for this tree.
    #[inline]
    pub fn cursor_owning(self) -> CursorOwning<A> {
        CursorOwning {
            current: None,
            tree: self,
        }
    }

    /// Creates a `Cursor` from a pointer to an element.
    ///
    /// # Safety
    ///
    /// `ptr` must be a pointer to an object that is part of this tree.
    #[inline]
    pub unsafe fn cursor_from_ptr(
        &self,
        ptr: *const <A::PointerOps as PointerOps>::Value,
    ) -> Cursor<'_, A> {
        Cursor {
            current: Some(self.adapter.get_link(ptr)),
            tree: self,
        }
    }

    /// Creates a `CursorMut` from a pointer to an element.
    ///
    /// # Safety
    ///
    /// `ptr` must be a pointer to an object that is part of this tree.
    #[inline]
    pub unsafe fn cursor_mut_from_ptr(
        &mut self,
        ptr: *const <A::PointerOps as PointerOps>::Value,
    ) -> CursorMut<'_, A> {
        CursorMut {
            current: Some(self.adapter.get_link(ptr)),
            tree: self,
        }
    }

    /// Creates a `CursorOwning` from a pointer to an element.
    ///
    /// # Safety
    ///
    /// `ptr` must be a pointer to an object that is part of this tree.
    #[inline]
    pub unsafe fn cursor_owning_from_ptr(
        self,
        ptr: *const <A::PointerOps as PointerOps>::Value,
    ) -> CursorOwning<A> {
        CursorOwning {
            current: Some(self.adapter.get_link(ptr)),
            tree: self,
        }
    }

    /// Returns a `Cursor` pointing to the first element of the tree. If the
    /// tree is empty then a null cursor is returned.
    #[inline]
    pub fn front(&self) -> Cursor<'_, A> {
        let mut cursor = self.cursor();
        cursor.move_next();
        cursor
    }

    /// Returns a `CursorMut` pointing to the first element of the tree. If the
    /// the tree is empty then a null cursor is returned.
    #[inline]
    pub fn front_mut(&mut self) -> CursorMut<'_, A> {
        let mut cursor = self.cursor_mut();
        cursor.move_next();
        cursor
    }

    /// Returns a `CursorOwning` pointing to the first element of the tree. If the
    /// the tree is empty then a null cursor is returned.
    #[inline]
    pub fn front_owning(self) -> CursorOwning<A> {
        let mut cursor = self.cursor_owning();
        cursor.with_cursor_mut(|c| c.move_next());
        cursor
    }

    /// Returns a `Cursor` pointing to the last element of the tree. If the tree
    /// is empty then a null cursor is returned.
    #[inline]
    pub fn back(&self) -> Cursor<'_, A> {
        let mut cursor = self.cursor();
        cursor.move_prev();
        cursor
    }

    /// Returns a `CursorMut` pointing to the last element of the tree. If the
    /// tree is empty then a null cursor is returned.
    #[inline]
    pub fn back_mut(&mut self) -> CursorMut<'_, A> {
        let mut cursor = self.cursor_mut();
        cursor.move_prev();
        cursor
    }

    /// Returns a `CursorOwning` pointing to the last element of the tree. If the
    /// tree is empty then a null cursor is returned.
    #[inline]
    pub fn back_owning(self) -> CursorOwning<A> {
        let mut cursor = self.cursor_owning();
        cursor.with_cursor_mut(|c| c.move_prev());
        cursor
    }

    #[inline]
    unsafe fn insert_root(&mut self, node: <A::LinkOps as link_ops::LinkOps>::LinkPtr) {
        self.adapter.link_ops_mut().set_parent(node, None);
        self.adapter.link_ops_mut().set_color(node, Color::Black);
        self.adapter.link_ops_mut().set_left(node, None);
        self.adapter.link_ops_mut().set_right(node, None);
        self.root = Some(node);
    }

    /// Gets an iterator over the objects in the `RBTree`.
    #[inline]
    pub fn iter(&self) -> Iter<'_, A> {
        let link_ops = self.adapter.link_ops();

        if let Some(root) = self.root {
            Iter {
                head: Some(unsafe { first_child(link_ops, root) }),
                tail: Some(unsafe { last_child(link_ops, root) }),
                tree: self,
            }
        } else {
            Iter {
                head: None,
                tail: None,
                tree: self,
            }
        }
    }

    #[inline]
    fn clear_recurse(&mut self, current: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>) {
        use link_ops::LinkOps;
        // If adapter.get_value or Pointer::from_raw panic here, it will leak
        // the nodes and keep them linked. However this is harmless since there
        // is nothing you can do with just a Link.
        if let Some(current) = current {
            unsafe {
                let left = self.adapter.link_ops_mut().left(current);
                let right = self.adapter.link_ops_mut().right(current);
                self.clear_recurse(left);
                self.clear_recurse(right);
                self.adapter.link_ops_mut().release_link(current);
                self.adapter
                    .pointer_ops()
                    .from_raw(self.adapter.get_value(current));
            }
        }
    }

    /// Removes all elements from the `RBTree`.
    ///
    /// This will unlink all object currently in the tree, which requires
    /// iterating through all elements in the `RBTree`. Each element is
    /// converted back to an owned pointer and then dropped.
    #[inline]
    pub fn clear(&mut self) {
        let root = self.root.take();
        self.clear_recurse(root);
    }

    /// Empties the `RBTree` without unlinking or freeing objects in it.
    ///
    /// Since this does not unlink any objects, any attempts to link these
    /// objects into another `RBTree` will fail but will not cause any
    /// memory unsafety. To unlink those objects manually, you must call the
    /// `force_unlink` function on them.
    #[inline]
    pub fn fast_clear(&mut self) {
        self.root = None;
    }

    /// Takes all the elements out of the `RBTree`, leaving it empty. The
    /// taken elements are returned as a new `RBTree`.
    #[inline]
    pub fn take(&mut self) -> RBTree<A>
    where
        A: Clone,
    {
        let tree = RBTree {
            root: self.root,
            adapter: self.adapter.clone(),
        };
        self.root = None;
        tree
    }
}

impl<A: for<'a> KeyAdapter<'a>> RBTree<A>
where
    <A as Adapter>::LinkOps: RBTreeOps,
{
    #[inline]
    fn find_internal<'a, Q: ?Sized + Ord>(
        &self,
        key: &Q,
    ) -> Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>
    where
        <A as KeyAdapter<'a>>::Key: Borrow<Q>,
        <A::PointerOps as PointerOps>::Value: 'a,
    {
        let link_ops = self.adapter.link_ops();

        let mut tree = self.root;
        while let Some(x) = tree {
            let current = unsafe { &*self.adapter.get_value(x) };
            match key.cmp(self.adapter.get_key(current).borrow()) {
                Ordering::Less => tree = unsafe { link_ops.left(x) },
                Ordering::Equal => return tree,
                Ordering::Greater => tree = unsafe { link_ops.right(x) },
            }
        }
        None
    }

    /// Returns a `Cursor` pointing to an element with the given key. If no such
    /// element is found then a null cursor is returned.
    ///
    /// If multiple elements with an identical key are found then an arbitrary
    /// one is returned.
    #[inline]
    pub fn find<'a, 'b, Q: ?Sized + Ord>(&'a self, key: &Q) -> Cursor<'a, A>
    where
        <A as KeyAdapter<'b>>::Key: Borrow<Q>,
        'a: 'b,
    {
        Cursor {
            current: self.find_internal(key),
            tree: self,
        }
    }

    /// Returns a `CursorMut` pointing to an element with the given key. If no
    /// such element is found then a null cursor is returned.
    ///
    /// If multiple elements with an identical key are found then an arbitrary
    /// one is returned.
    #[inline]
    pub fn find_mut<'a, 'b, Q: ?Sized + Ord>(&'a mut self, key: &Q) -> CursorMut<'a, A>
    where
        <A as KeyAdapter<'b>>::Key: Borrow<Q>,
        'a: 'b,
    {
        CursorMut {
            current: self.find_internal(key),
            tree: self,
        }
    }

    // Returns a `CursorOwning` pointing to an element with the given key. If no
    /// such element is found then a null cursor is returned.
    ///
    /// If multiple elements with an identical key are found then an arbitrary
    /// one is returned.
    #[inline]
    pub fn find_owning<'a, Q: ?Sized + Ord>(self, key: &Q) -> CursorOwning<A>
    where
        <A as KeyAdapter<'a>>::Key: Borrow<Q>,
        Self: 'a,
    {
        CursorOwning {
            current: self.find_internal(key),
            tree: self,
        }
    }

    #[inline]
    fn lower_bound_internal<'a, Q: ?Sized + Ord>(
        &self,
        bound: Bound<&Q>,
    ) -> Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>
    where
        <A as KeyAdapter<'a>>::Key: Borrow<Q>,
        <A::PointerOps as PointerOps>::Value: 'a,
    {
        let link_ops = self.adapter.link_ops();

        let mut tree = self.root;
        let mut result = None;
        while let Some(x) = tree {
            let current = unsafe { &*self.adapter.get_value(x) };
            let cond = match bound {
                Unbounded => true,
                Included(key) => key <= self.adapter.get_key(current).borrow(),
                Excluded(key) => key < self.adapter.get_key(current).borrow(),
            };
            if cond {
                result = tree;
                tree = unsafe { link_ops.left(x) };
            } else {
                tree = unsafe { link_ops.right(x) };
            }
        }
        result
    }

    /// Returns a `Cursor` pointing to the lowest element whose key is above
    /// the given bound. If no such element is found then a null cursor is
    /// returned.
    #[inline]
    pub fn lower_bound<'a, 'b, Q: ?Sized + Ord>(&'a self, bound: Bound<&Q>) -> Cursor<'a, A>
    where
        <A as KeyAdapter<'b>>::Key: Borrow<Q>,
        'a: 'b,
    {
        Cursor {
            current: self.lower_bound_internal(bound),
            tree: self,
        }
    }

    /// Returns a `CursorMut` pointing to the first element whose key is
    /// above the given bound. If no such element is found then a null
    /// cursor is returned.
    #[inline]
    pub fn lower_bound_mut<'a, 'b, Q: ?Sized + Ord>(
        &'a mut self,
        bound: Bound<&Q>,
    ) -> CursorMut<'a, A>
    where
        <A as KeyAdapter<'b>>::Key: Borrow<Q>,
        'a: 'b,
    {
        CursorMut {
            current: self.lower_bound_internal(bound),
            tree: self,
        }
    }

    /// Returns a `CursorOwning` pointing to the first element whose key is
    /// above the given bound. If no such element is found then a null
    /// cursor is returned.
    #[inline]
    pub fn lower_bound_owning<'a, Q: ?Sized + Ord>(self, bound: Bound<&Q>) -> CursorOwning<A>
    where
        <A as KeyAdapter<'a>>::Key: Borrow<Q>,
        Self: 'a,
    {
        CursorOwning {
            current: self.lower_bound_internal(bound),
            tree: self,
        }
    }

    #[inline]
    fn upper_bound_internal<'a, Q: ?Sized + Ord>(
        &self,
        bound: Bound<&Q>,
    ) -> Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>
    where
        <A as KeyAdapter<'a>>::Key: Borrow<Q>,
        <A::PointerOps as PointerOps>::Value: 'a,
    {
        let link_ops = self.adapter.link_ops();

        let mut tree = self.root;
        let mut result = None;
        while let Some(x) = tree {
            let current = unsafe { &*self.adapter.get_value(x) };
            let cond = match bound {
                Unbounded => false,
                Included(key) => key < self.adapter.get_key(current).borrow(),
                Excluded(key) => key <= self.adapter.get_key(current).borrow(),
            };
            if cond {
                tree = unsafe { link_ops.left(x) };
            } else {
                result = tree;
                tree = unsafe { link_ops.right(x) };
            }
        }
        result
    }

    /// Returns a `Cursor` pointing to the last element whose key is below
    /// the given bound. If no such element is found then a null cursor is
    /// returned.
    #[inline]
    pub fn upper_bound<'a, 'b, Q: ?Sized + Ord>(&'a self, bound: Bound<&Q>) -> Cursor<'a, A>
    where
        <A as KeyAdapter<'b>>::Key: Borrow<Q>,
        'a: 'b,
    {
        Cursor {
            current: self.upper_bound_internal(bound),
            tree: self,
        }
    }

    /// Returns a `CursorMut` pointing to the last element whose key is
    /// below the given bound. If no such element is found then a null
    /// cursor is returned.
    #[inline]
    pub fn upper_bound_mut<'a, 'b, Q: ?Sized + Ord>(
        &'a mut self,
        bound: Bound<&Q>,
    ) -> CursorMut<'a, A>
    where
        <A as KeyAdapter<'b>>::Key: Borrow<Q>,
        'a: 'b,
    {
        CursorMut {
            current: self.upper_bound_internal(bound),
            tree: self,
        }
    }

    /// Returns a `CursorOwning` pointing to the last element whose key is
    /// below the given bound. If no such element is found then a null
    /// cursor is returned.
    #[inline]
    pub fn upper_bound_owning<'a, Q: ?Sized + Ord>(self, bound: Bound<&Q>) -> CursorOwning<A>
    where
        <A as KeyAdapter<'a>>::Key: Borrow<Q>,
        Self: 'a,
    {
        CursorOwning {
            current: self.upper_bound_internal(bound),
            tree: self,
        }
    }

    /// Inserts a new element into the `RBTree`.
    ///
    /// The new element will be inserted at the correct position in the tree
    /// based on its key.
    ///
    /// Returns a mutable cursor pointing to the newly added element.
    ///
    /// # Panics
    ///
    /// Panics if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn insert<'a>(&'a mut self, val: <A::PointerOps as PointerOps>::Pointer) -> CursorMut<'_, A>
    where
        <A as KeyAdapter<'a>>::Key: Ord,
    {
        unsafe {
            let new = self.node_from_value(val);
            let raw = self.adapter.get_value(new);
            if let Some(root) = self.root {
                let key = self.adapter.get_key(&*raw);
                let mut tree = root;
                loop {
                    let current = &*self.adapter.get_value(tree);
                    if key < self.adapter.get_key(current) {
                        if let Some(left) = self.adapter.link_ops().left(tree) {
                            tree = left;
                        } else {
                            insert_left(self.adapter.link_ops_mut(), tree, new, &mut self.root);
                            break;
                        }
                    } else {
                        if let Some(right) = self.adapter.link_ops().right(tree) {
                            tree = right;
                        } else {
                            insert_right(self.adapter.link_ops_mut(), tree, new, &mut self.root);
                            break;
                        }
                    }
                }
            } else {
                self.insert_root(new);
            }

            CursorMut {
                current: Some(new),
                tree: self,
            }
        }
    }

    /// Returns an `Entry` for the given key which contains a `CursorMut` to an
    /// element with the given key or an `InsertCursor` which points to a place
    /// in which to insert a new element with the given key.
    ///
    /// This is more efficient than calling `find` followed by `insert` since
    /// the tree does not have to be searched a second time to find a place to
    /// insert the new element.
    ///
    /// If multiple elements with an identical key are found then an arbitrary
    /// one is returned.
    #[inline]
    pub fn entry<'a, Q: ?Sized + Ord>(&'a mut self, key: &Q) -> Entry<'a, A>
    where
        <A as KeyAdapter<'a>>::Key: Borrow<Q>,
    {
        unsafe {
            if let Some(root) = self.root {
                let mut tree = root;
                loop {
                    let current = &*self.adapter.get_value(tree);
                    match key.cmp(self.adapter.get_key(current).borrow()) {
                        Ordering::Less => {
                            if let Some(left) = self.adapter.link_ops().left(tree) {
                                tree = left;
                            } else {
                                return Entry::Vacant(InsertCursor {
                                    parent: Some(tree),
                                    insert_left: true,
                                    tree: self,
                                });
                            }
                        }
                        Ordering::Equal => {
                            return Entry::Occupied(CursorMut {
                                current: Some(tree),
                                tree: self,
                            });
                        }
                        Ordering::Greater => {
                            if let Some(right) = self.adapter.link_ops().right(tree) {
                                tree = right;
                            } else {
                                return Entry::Vacant(InsertCursor {
                                    parent: Some(tree),
                                    insert_left: false,
                                    tree: self,
                                });
                            }
                        }
                    }
                }
            } else {
                Entry::Vacant(InsertCursor {
                    parent: None,
                    insert_left: false,
                    tree: self,
                })
            }
        }
    }

    /// Constructs a double-ended iterator over a sub-range of elements in the
    /// tree, starting at min, and ending at max. If min is `Unbounded`, then it
    /// will be treated as "negative infinity", and if max is `Unbounded`, then
    /// it will be treated as "positive infinity". Thus
    /// `range(Unbounded, Unbounded)` will yield the whole collection.
    #[inline]
    pub fn range<'a, Min: ?Sized + Ord, Max: ?Sized + Ord>(
        &'a self,
        min: Bound<&Min>,
        max: Bound<&Max>,
    ) -> Iter<'a, A>
    where
        <A as KeyAdapter<'a>>::Key: Borrow<Min> + Borrow<Max>,
        <A as KeyAdapter<'a>>::Key: Ord,
    {
        let lower = self.lower_bound_internal(min);
        let upper = self.upper_bound_internal(max);

        if let (Some(lower), Some(upper)) = (lower, upper) {
            let lower_key = unsafe { self.adapter.get_key(&*self.adapter.get_value(lower)) };
            let upper_key = unsafe { self.adapter.get_key(&*self.adapter.get_value(upper)) };
            if upper_key >= lower_key {
                return Iter {
                    head: Some(lower),
                    tail: Some(upper),
                    tree: self,
                };
            }
        }
        Iter {
            head: None,
            tail: None,
            tree: self,
        }
    }
}

// Allow read-only access to values from multiple threads
unsafe impl<A: Adapter + Sync> Sync for RBTree<A>
where
    <A::PointerOps as PointerOps>::Value: Sync,
    A::LinkOps: RBTreeOps,
{
}

// Allow sending to another thread if the ownership (represented by the <A::PointerOps as PointerOps>::Pointer owned
// pointer type) can be transferred to another thread.
unsafe impl<A: Adapter + Send> Send for RBTree<A>
where
    <A::PointerOps as PointerOps>::Pointer: Send,
    A::LinkOps: RBTreeOps,
{
}

// Drop all owned pointers if the collection is dropped
impl<A: Adapter> Drop for RBTree<A>
where
    A::LinkOps: RBTreeOps,
{
    #[inline]
    fn drop(&mut self) {
        self.clear();
    }
}

impl<A: Adapter> IntoIterator for RBTree<A>
where
    A::LinkOps: RBTreeOps,
{
    type Item = <A::PointerOps as PointerOps>::Pointer;
    type IntoIter = IntoIter<A>;

    #[inline]
    fn into_iter(self) -> IntoIter<A> {
        let link_ops = self.adapter.link_ops();

        if let Some(root) = self.root {
            IntoIter {
                head: Some(unsafe { first_child(link_ops, root) }),
                tail: Some(unsafe { last_child(link_ops, root) }),
                tree: self,
            }
        } else {
            IntoIter {
                head: None,
                tail: None,
                tree: self,
            }
        }
    }
}

impl<'a, A: Adapter + 'a> IntoIterator for &'a RBTree<A>
where
    A::LinkOps: RBTreeOps,
{
    type Item = &'a <A::PointerOps as PointerOps>::Value;
    type IntoIter = Iter<'a, A>;

    #[inline]
    fn into_iter(self) -> Iter<'a, A> {
        self.iter()
    }
}

impl<A: Adapter + Default> Default for RBTree<A>
where
    A::LinkOps: RBTreeOps,
{
    fn default() -> RBTree<A> {
        RBTree::new(A::default())
    }
}

impl<A: Adapter> fmt::Debug for RBTree<A>
where
    A::LinkOps: RBTreeOps,
    <A::PointerOps as PointerOps>::Value: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

// =============================================================================
// InsertCursor, Entry
// =============================================================================

/// A cursor pointing to a slot in which an element can be inserted into a
/// `RBTree`.
pub struct InsertCursor<'a, A: Adapter>
where
    A::LinkOps: RBTreeOps,
{
    parent: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    insert_left: bool,
    tree: &'a mut RBTree<A>,
}

impl<'a, A: Adapter + 'a> InsertCursor<'a, A>
where
    A::LinkOps: RBTreeOps,
{
    /// Inserts a new element into the `RBTree` at the location indicated by
    /// this `InsertCursor`.
    ///
    /// # Panics
    ///
    /// Panics if the new element is already linked to a different intrusive
    /// collection.
    pub fn insert(self, val: <A::PointerOps as PointerOps>::Pointer) -> CursorMut<'a, A> {
        unsafe {
            let new = self.tree.node_from_value(val);
            let link_ops = self.tree.adapter.link_ops_mut();
            if let Some(parent) = self.parent {
                if self.insert_left {
                    insert_left(link_ops, parent, new, &mut self.tree.root);
                } else {
                    insert_right(link_ops, parent, new, &mut self.tree.root);
                }
            } else {
                self.tree.insert_root(new);
            }
            CursorMut {
                current: Some(new),
                tree: self.tree,
            }
        }
    }
}

/// An entry in a `RBTree`.
///
/// See the documentation for `RBTree::entry`.
pub enum Entry<'a, A: Adapter>
where
    A::LinkOps: RBTreeOps,
{
    /// An occupied entry.
    Occupied(CursorMut<'a, A>),

    /// A vacant entry.
    Vacant(InsertCursor<'a, A>),
}

impl<'a, A: Adapter + 'a> Entry<'a, A>
where
    A::LinkOps: RBTreeOps,
{
    /// Inserts an element into the `RBTree` if the entry is vacant, returning
    /// a `CursorMut` to the resulting value. If the entry is occupied then a
    /// `CursorMut` pointing to the element is returned.
    ///
    /// # Panics
    ///
    /// Panics if the `Entry` is vacant and the new element is already linked to
    /// a different intrusive collection.
    pub fn or_insert(self, val: <A::PointerOps as PointerOps>::Pointer) -> CursorMut<'a, A> {
        match self {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(entry) => entry.insert(val),
        }
    }

    /// Calls the given function and inserts the result into the `RBTree` if the
    /// entry is vacant, returning a `CursorMut` to the resulting value. If the
    /// entry is occupied then a `CursorMut` pointing to the element is
    /// returned and the function is not executed.
    ///
    /// # Panics
    ///
    /// Panics if the `Entry` is vacant and the new element is already linked to
    /// a different intrusive collection.
    pub fn or_insert_with<F>(self, default: F) -> CursorMut<'a, A>
    where
        F: FnOnce() -> <A::PointerOps as PointerOps>::Pointer,
    {
        match self {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(entry) => entry.insert(default()),
        }
    }
}

// =============================================================================
// Iter
// =============================================================================

/// An iterator over references to the items of a `RBTree`.
pub struct Iter<'a, A: Adapter>
where
    A::LinkOps: RBTreeOps,
{
    head: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    tail: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    tree: &'a RBTree<A>,
}
impl<'a, A: Adapter + 'a> Iterator for Iter<'a, A>
where
    A::LinkOps: RBTreeOps,
{
    type Item = &'a <A::PointerOps as PointerOps>::Value;

    #[inline]
    fn next(&mut self) -> Option<&'a <A::PointerOps as PointerOps>::Value> {
        let head = self.head?;

        if Some(head) == self.tail {
            self.head = None;
            self.tail = None;
        } else {
            self.head = unsafe { next(self.tree.adapter.link_ops(), head) };
        }
        Some(unsafe { &*self.tree.adapter.get_value(head) })
    }
}
impl<'a, A: Adapter + 'a> DoubleEndedIterator for Iter<'a, A>
where
    A::LinkOps: RBTreeOps,
{
    #[inline]
    fn next_back(&mut self) -> Option<&'a <A::PointerOps as PointerOps>::Value> {
        let tail = self.tail?;

        if Some(tail) == self.head {
            self.head = None;
            self.tail = None;
        } else {
            self.tail = unsafe { prev(self.tree.adapter.link_ops(), tail) };
        }
        Some(unsafe { &*self.tree.adapter.get_value(tail) })
    }
}
impl<'a, A: Adapter + 'a> Clone for Iter<'a, A>
where
    A::LinkOps: RBTreeOps,
{
    #[inline]
    fn clone(&self) -> Iter<'a, A> {
        Iter {
            head: self.head,
            tail: self.tail,
            tree: self.tree,
        }
    }
}

// =============================================================================
// IntoIter
// =============================================================================

/// An iterator which consumes a `RBTree`.
pub struct IntoIter<A: Adapter>
where
    A::LinkOps: RBTreeOps,
{
    head: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    tail: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    tree: RBTree<A>,
}
impl<A: Adapter> Iterator for IntoIter<A>
where
    A::LinkOps: RBTreeOps,
{
    type Item = <A::PointerOps as PointerOps>::Pointer;

    #[inline]
    fn next(&mut self) -> Option<<A::PointerOps as PointerOps>::Pointer> {
        use link_ops::LinkOps;

        let head = self.head?;
        let link_ops = self.tree.adapter.link_ops_mut();
        unsafe {
            // Remove the node from the tree. Since head is always the
            // left-most node, we can infer the following:
            // - head.left is null.
            // - head is a left child of its parent (or the root node).
            if let Some(parent) = link_ops.parent(head) {
                link_ops.set_left(parent, link_ops.right(head));
            } else {
                self.tree.root = link_ops.right(head);
                if link_ops.right(head).is_none() {
                    self.tail = None;
                }
            }
            if let Some(right) = link_ops.right(head) {
                link_ops.set_parent(right, link_ops.parent(head));
                self.head = Some(first_child(link_ops, right));
            } else {
                self.head = link_ops.parent(head);
            }
            link_ops.release_link(head);
            Some(
                self.tree
                    .adapter
                    .pointer_ops()
                    .from_raw(self.tree.adapter.get_value(head)),
            )
        }
    }
}
impl<A: Adapter> DoubleEndedIterator for IntoIter<A>
where
    A::LinkOps: RBTreeOps,
{
    #[inline]
    fn next_back(&mut self) -> Option<<A::PointerOps as PointerOps>::Pointer> {
        use link_ops::LinkOps;

        let tail = self.tail?;
        let link_ops = self.tree.adapter.link_ops_mut();
        unsafe {
            // Remove the node from the tree. Since tail is always the
            // right-most node, we can infer the following:
            // - tail.right is null.
            // - tail is a right child of its parent (or the root node).
            if let Some(parent) = link_ops.parent(tail) {
                link_ops.set_right(parent, link_ops.left(tail));
            } else {
                self.tree.root = link_ops.left(tail);
                if link_ops.left(tail).is_none() {
                    self.tail = None;
                }
            }
            if let Some(left) = link_ops.left(tail) {
                link_ops.set_parent(left, link_ops.parent(tail));
                self.tail = Some(last_child(link_ops, left));
            } else {
                self.tail = link_ops.parent(tail);
            }
            link_ops.release_link(tail);
            Some(
                self.tree
                    .adapter
                    .pointer_ops()
                    .from_raw(self.tree.adapter.get_value(tail)),
            )
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::{CursorOwning, Entry, KeyAdapter, Link, PointerOps, RBTree};
    use crate::{Bound::*, UnsafeRef};
    use alloc::boxed::Box;
    use rand::prelude::*;
    use rand_xorshift::XorShiftRng;
    use std::fmt;
    use std::rc::Rc;
    use std::vec::Vec;
    use std::{format, vec};

    #[derive(Clone)]
    struct Obj {
        link: Link,
        value: i32,
    }
    impl fmt::Debug for Obj {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.value)
        }
    }
    intrusive_adapter!(RcObjAdapter = Rc<Obj>: Obj { link: Link });

    impl<'a> KeyAdapter<'a> for RcObjAdapter {
        type Key = i32;
        fn get_key(&self, value: &'a <Self::PointerOps as PointerOps>::Value) -> i32 {
            value.value
        }
    }

    intrusive_adapter!(UnsafeRefObjAdapter = UnsafeRef<Obj>: Obj { link: Link });

    impl<'a> KeyAdapter<'a> for UnsafeRefObjAdapter {
        type Key = i32;
        fn get_key(&self, value: &'a <Self::PointerOps as PointerOps>::Value) -> i32 {
            value.value
        }
    }

    fn make_rc_obj(value: i32) -> Rc<Obj> {
        Rc::new(make_obj(value))
    }

    fn make_obj(value: i32) -> Obj {
        Obj {
            link: Link::new(),
            value,
        }
    }

    #[test]
    fn test_link() {
        let a = make_rc_obj(1);
        assert!(!a.link.is_linked());
        assert_eq!(format!("{:?}", a.link), "unlinked");

        let mut b = RBTree::<RcObjAdapter>::default();
        assert!(b.is_empty());

        assert_eq!(b.insert(a.clone()).get().unwrap().value, 1);
        assert!(!b.is_empty());
        assert!(a.link.is_linked());
        assert_eq!(format!("{:?}", a.link), "linked");

        let c = a.as_ref().clone();
        assert!(!c.link.is_linked());

        unsafe {
            assert_eq!(b.cursor_from_ptr(a.as_ref()).get().unwrap().value, 1);
            assert_eq!(b.cursor_mut_from_ptr(a.as_ref()).get().unwrap().value, 1);
        }

        assert_eq!(
            b.front_mut().remove().unwrap().as_ref() as *const _,
            a.as_ref() as *const _
        );
        assert!(b.is_empty());
        assert!(!a.link.is_linked());
    }

    #[test]
    fn test_cursor() {
        let a = make_rc_obj(1);
        let b = make_rc_obj(2);
        let c = make_rc_obj(3);
        let mut t = RBTree::new(RcObjAdapter::new());
        let mut cur = t.cursor_mut();
        assert!(cur.is_null());
        assert!(cur.get().is_none());
        assert!(cur.remove().is_none());

        cur.insert_before(a.clone());
        cur.insert_before(c.clone());
        cur.move_prev();
        cur.insert(b.clone());
        assert!(cur.peek_next().is_null());
        cur.move_next();
        assert!(cur.is_null());

        cur.move_next();
        assert!(cur.peek_prev().is_null());
        assert!(!cur.is_null());
        assert_eq!(cur.get().unwrap() as *const _, a.as_ref() as *const _);

        {
            let mut cur2 = cur.as_cursor();
            assert_eq!(cur2.get().unwrap() as *const _, a.as_ref() as *const _);
            assert_eq!(cur2.peek_next().get().unwrap().value, 2);
            cur2.move_next();
            assert_eq!(cur2.get().unwrap().value, 2);
            cur2.move_next();
            assert_eq!(cur2.peek_prev().get().unwrap().value, 2);
            assert_eq!(cur2.get().unwrap() as *const _, c.as_ref() as *const _);
            cur2.move_prev();
            assert_eq!(cur2.get().unwrap() as *const _, b.as_ref() as *const _);
            cur2.move_next();
            assert_eq!(cur2.get().unwrap() as *const _, c.as_ref() as *const _);
            cur2.move_next();
            assert!(cur2.is_null());
            assert!(cur2.clone().get().is_none());
        }
        assert_eq!(cur.get().unwrap() as *const _, a.as_ref() as *const _);

        let a2 = make_rc_obj(1);
        let b2 = make_rc_obj(2);
        let c2 = make_rc_obj(3);
        assert_eq!(
            cur.replace_with(a2).unwrap().as_ref() as *const _,
            a.as_ref() as *const _
        );
        assert!(!a.link.is_linked());
        cur.move_next();
        assert_eq!(
            cur.replace_with(b2).unwrap().as_ref() as *const _,
            b.as_ref() as *const _
        );
        assert!(!b.link.is_linked());
        cur.move_next();
        assert_eq!(
            cur.replace_with(c2).unwrap().as_ref() as *const _,
            c.as_ref() as *const _
        );
        assert!(!c.link.is_linked());
        cur.move_next();
        assert_eq!(
            cur.replace_with(c.clone()).unwrap_err().as_ref() as *const _,
            c.as_ref() as *const _
        );
    }

    #[test]
    fn test_cursor_owning() {
        struct Container {
            cur: CursorOwning<RcObjAdapter>,
        }

        let mut t = RBTree::new(RcObjAdapter::new());
        t.insert(make_rc_obj(1));
        t.insert(make_rc_obj(2));
        t.insert(make_rc_obj(3));
        t.insert(make_rc_obj(4));
        let mut con = Container {
            cur: t.cursor_owning(),
        };
        assert!(con.cur.as_cursor().is_null());

        con.cur = con.cur.into_inner().front_owning();
        assert_eq!(con.cur.as_cursor().get().unwrap().value, 1);

        con.cur = con.cur.into_inner().back_owning();
        assert_eq!(con.cur.as_cursor().get().unwrap().value, 4);

        con.cur = con.cur.into_inner().find_owning(&2);
        assert_eq!(con.cur.as_cursor().get().unwrap().value, 2);

        con.cur.with_cursor_mut(|c| c.move_next());
        assert_eq!(con.cur.as_cursor().get().unwrap().value, 3);
    }

    #[test]
    fn test_insert_remove() {
        let len = if cfg!(miri) { 10 } else { 100 };
        let v = (0..len).map(make_rc_obj).collect::<Vec<_>>();
        assert!(v.iter().all(|x| !x.link.is_linked()));
        let mut t = RBTree::new(RcObjAdapter::new());
        assert!(t.is_empty());
        let mut rng = XorShiftRng::seed_from_u64(0);

        {
            let mut expected = Vec::new();
            for x in v.iter() {
                t.insert(x.clone());
                expected.push(x.value);
                assert_eq!(t.iter().map(|x| x.value).collect::<Vec<_>>(), expected);
            }

            while let Some(x) = t.front_mut().remove() {
                assert_eq!(x.value, expected.remove(0));
                assert_eq!(t.iter().map(|x| x.value).collect::<Vec<_>>(), expected);
            }
            assert!(expected.is_empty());
            assert!(t.is_empty());
        }

        {
            let mut expected = Vec::new();
            for x in v.iter().rev() {
                t.insert(x.clone());
                expected.insert(0, x.value);
                assert_eq!(t.iter().map(|x| x.value).collect::<Vec<_>>(), expected);
            }

            while let Some(x) = t.back_mut().remove() {
                assert_eq!(x.value, expected.pop().unwrap());
                assert_eq!(t.iter().map(|x| x.value).collect::<Vec<_>>(), expected);
            }
            assert!(expected.is_empty());
            assert!(t.is_empty());
        }

        {
            let mut indices = (0..v.len()).collect::<Vec<_>>();
            indices.shuffle(&mut rng);
            let mut expected = Vec::new();
            for i in indices {
                t.insert(v[i].clone());
                expected.push(v[i].value);
                expected[..].sort_unstable();
                assert_eq!(t.iter().map(|x| x.value).collect::<Vec<_>>(), expected);
            }

            while !expected.is_empty() {
                {
                    let index = rng.gen_range(0..expected.len());
                    let mut c = t.cursor_mut();
                    for _ in 0..(index + 1) {
                        c.move_next();
                    }
                    assert_eq!(c.remove().unwrap().value, expected.remove(index));
                }
                assert_eq!(t.iter().map(|x| x.value).collect::<Vec<_>>(), expected);
            }
            assert!(t.is_empty());
        }

        {
            let mut indices = (0..v.len()).collect::<Vec<_>>();
            indices.shuffle(&mut rng);
            let mut expected = Vec::new();
            for i in indices {
                {
                    let mut c = t.front_mut();
                    loop {
                        if let Some(x) = c.get() {
                            if x.value > v[i].value {
                                break;
                            }
                        } else {
                            break;
                        }
                        c.move_next();
                    }
                    c.insert_before(v[i].clone());
                }
                expected.push(v[i].value);
                expected[..].sort_unstable();
                assert_eq!(t.iter().map(|x| x.value).collect::<Vec<_>>(), expected);
            }

            t.clear();
            assert!(t.is_empty());
        }

        {
            let mut indices = (0..v.len()).collect::<Vec<_>>();
            indices.shuffle(&mut rng);
            let mut expected = Vec::new();
            for i in indices {
                {
                    let mut c = t.back_mut();
                    loop {
                        if let Some(x) = c.get() {
                            if x.value < v[i].value {
                                break;
                            }
                        } else {
                            break;
                        }
                        c.move_prev();
                    }
                    c.insert_after(v[i].clone());
                }
                expected.push(v[i].value);
                expected[..].sort_unstable();
                assert_eq!(t.iter().map(|x| x.value).collect::<Vec<_>>(), expected);
            }
        }
    }

    #[test]
    fn test_iter() {
        let v = (0..10).map(|x| make_rc_obj(x * 10)).collect::<Vec<_>>();
        let mut t = RBTree::new(RcObjAdapter::new());
        for x in v.iter() {
            t.insert(x.clone());
        }

        assert_eq!(
            format!("{:?}", t),
            "{0, 10, 20, 30, 40, 50, 60, 70, 80, 90}"
        );

        assert_eq!(
            t.iter().clone().map(|x| x.value).collect::<Vec<_>>(),
            vec![0, 10, 20, 30, 40, 50, 60, 70, 80, 90]
        );
        assert_eq!(
            (&t).into_iter().rev().map(|x| x.value).collect::<Vec<_>>(),
            vec![90, 80, 70, 60, 50, 40, 30, 20, 10, 0]
        );
        assert_eq!(
            t.range(Unbounded, Unbounded)
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![0, 10, 20, 30, 40, 50, 60, 70, 80, 90]
        );

        assert_eq!(
            t.range(Included(&0), Unbounded)
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![0, 10, 20, 30, 40, 50, 60, 70, 80, 90]
        );
        assert_eq!(
            t.range(Excluded(&0), Unbounded)
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![10, 20, 30, 40, 50, 60, 70, 80, 90]
        );
        assert_eq!(
            t.range(Included(&25), Unbounded)
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![30, 40, 50, 60, 70, 80, 90]
        );
        assert_eq!(
            t.range(Excluded(&25), Unbounded)
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![30, 40, 50, 60, 70, 80, 90]
        );
        assert_eq!(
            t.range(Included(&70), Unbounded)
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![70, 80, 90]
        );
        assert_eq!(
            t.range(Excluded(&70), Unbounded)
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![80, 90]
        );
        assert_eq!(
            t.range(Included(&100), Unbounded)
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );
        assert_eq!(
            t.range(Excluded(&100), Unbounded)
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );

        assert_eq!(
            t.range(Unbounded, Included(&90))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![0, 10, 20, 30, 40, 50, 60, 70, 80, 90]
        );
        assert_eq!(
            t.range(Unbounded, Excluded(&90))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![0, 10, 20, 30, 40, 50, 60, 70, 80]
        );
        assert_eq!(
            t.range(Unbounded, Included(&25))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![0, 10, 20]
        );
        assert_eq!(
            t.range(Unbounded, Excluded(&25))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![0, 10, 20]
        );
        assert_eq!(
            t.range(Unbounded, Included(&70))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![0, 10, 20, 30, 40, 50, 60, 70]
        );
        assert_eq!(
            t.range(Unbounded, Excluded(&70))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![0, 10, 20, 30, 40, 50, 60]
        );
        assert_eq!(
            t.range(Unbounded, Included(&-1))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );
        assert_eq!(
            t.range(Unbounded, Excluded(&-1))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );

        assert_eq!(
            t.range(Included(&25), Included(&80))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![30, 40, 50, 60, 70, 80]
        );
        assert_eq!(
            t.range(Included(&25), Excluded(&80))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![30, 40, 50, 60, 70]
        );
        assert_eq!(
            t.range(Excluded(&25), Included(&80))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![30, 40, 50, 60, 70, 80]
        );
        assert_eq!(
            t.range(Excluded(&25), Excluded(&80))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![30, 40, 50, 60, 70]
        );

        assert_eq!(
            t.range(Included(&25), Included(&25))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );
        assert_eq!(
            t.range(Included(&25), Excluded(&25))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );
        assert_eq!(
            t.range(Excluded(&25), Included(&25))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );
        assert_eq!(
            t.range(Excluded(&25), Excluded(&25))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );

        assert_eq!(
            t.range(Included(&50), Included(&50))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![50]
        );
        assert_eq!(
            t.range(Included(&50), Excluded(&50))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );
        assert_eq!(
            t.range(Excluded(&50), Included(&50))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );
        assert_eq!(
            t.range(Excluded(&50), Excluded(&50))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );

        assert_eq!(
            t.range(Included(&100), Included(&-2))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );
        assert_eq!(
            t.range(Included(&100), Excluded(&-2))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );
        assert_eq!(
            t.range(Excluded(&100), Included(&-2))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );
        assert_eq!(
            t.range(Excluded(&100), Excluded(&-2))
                .map(|x| x.value)
                .collect::<Vec<_>>(),
            vec![]
        );

        let mut v2 = Vec::new();
        for x in t.take() {
            v2.push(x.value);
        }
        assert_eq!(v2, vec![0, 10, 20, 30, 40, 50, 60, 70, 80, 90]);
        assert!(t.is_empty());
        for _ in t.take() {
            unreachable!();
        }

        for x in v.iter() {
            t.insert(x.clone());
        }
        v2.clear();
        for x in t.into_iter().rev() {
            v2.push(x.value);
        }
        assert_eq!(v2, vec![90, 80, 70, 60, 50, 40, 30, 20, 10, 0]);
    }

    #[test]
    fn test_find() {
        let v = (0..10).map(|x| make_rc_obj(x * 10)).collect::<Vec<_>>();
        let mut t = RBTree::new(RcObjAdapter::new());
        for x in v.iter() {
            t.insert(x.clone());
        }

        for i in -9..100 {
            fn mod10(x: i32) -> i32 {
                if x < 0 {
                    10 + x % 10
                } else {
                    x % 10
                }
            }
            {
                let c = t.find(&i);
                assert_eq!(
                    c.get().map(|x| x.value),
                    if i % 10 == 0 { Some(i) } else { None }
                );
            }
            {
                let c = t.find_mut(&i);
                assert_eq!(
                    c.get().map(|x| x.value),
                    if i % 10 == 0 { Some(i) } else { None }
                );
            }
            {
                let c = t.upper_bound(Unbounded);
                assert_eq!(c.get().map(|x| x.value), Some(90));
            }
            {
                let c = t.upper_bound_mut(Unbounded);
                assert_eq!(c.get().map(|x| x.value), Some(90));
            }
            {
                let c = t.upper_bound(Included(&i));
                assert_eq!(
                    c.get().map(|x| x.value),
                    if i >= 0 { Some(i - mod10(i)) } else { None }
                );
            }
            {
                let c = t.upper_bound_mut(Included(&i));
                assert_eq!(
                    c.get().map(|x| x.value),
                    if i >= 0 { Some(i - mod10(i)) } else { None }
                );
            }
            {
                let c = t.upper_bound(Excluded(&i));
                assert_eq!(
                    c.get().map(|x| x.value),
                    if i > 0 {
                        Some(i - 1 - mod10(i - 1))
                    } else {
                        None
                    }
                );
            }
            {
                let c = t.upper_bound_mut(Excluded(&i));
                assert_eq!(
                    c.get().map(|x| x.value),
                    if i > 0 {
                        Some(i - 1 - mod10(i - 1))
                    } else {
                        None
                    }
                );
            }
            {
                let c = t.lower_bound(Unbounded);
                assert_eq!(c.get().map(|x| x.value), Some(0));
            }
            {
                let c = t.lower_bound_mut(Unbounded);
                assert_eq!(c.get().map(|x| x.value), Some(0));
            }
            {
                let c = t.lower_bound(Included(&i));
                assert_eq!(
                    c.get().map(|x| x.value),
                    if i <= 90 {
                        Some((i + 9) - mod10(i + 9))
                    } else {
                        None
                    }
                );
            }
            {
                let c = t.lower_bound_mut(Included(&i));
                assert_eq!(
                    c.get().map(|x| x.value),
                    if i <= 90 {
                        Some((i + 9) - mod10(i + 9))
                    } else {
                        None
                    }
                );
            }
            {
                let c = t.lower_bound(Excluded(&i));
                assert_eq!(
                    c.get().map(|x| x.value),
                    if i < 90 {
                        Some((i + 10) - mod10(i + 10))
                    } else {
                        None
                    }
                );
            }
            {
                let c = t.lower_bound_mut(Excluded(&i));
                assert_eq!(
                    c.get().map(|x| x.value),
                    if i < 90 {
                        Some((i + 10) - mod10(i + 10))
                    } else {
                        None
                    }
                );
            }
        }
    }

    #[test]
    fn test_fast_clear_force_unlink() {
        let mut t = RBTree::new(UnsafeRefObjAdapter::new());
        let a = UnsafeRef::from_box(Box::new(make_obj(1)));
        let b = UnsafeRef::from_box(Box::new(make_obj(2)));
        let c = UnsafeRef::from_box(Box::new(make_obj(3)));
        t.insert(a.clone());
        t.insert(b.clone());
        t.insert(c.clone());

        t.fast_clear();
        assert!(t.is_empty());

        unsafe {
            assert!(a.link.is_linked());
            assert!(b.link.is_linked());
            assert!(c.link.is_linked());

            a.link.force_unlink();
            b.link.force_unlink();
            c.link.force_unlink();

            assert!(t.is_empty());

            assert!(!a.link.is_linked());
            assert!(!b.link.is_linked());
            assert!(!c.link.is_linked());
        }

        unsafe {
            UnsafeRef::into_box(a);
            UnsafeRef::into_box(b);
            UnsafeRef::into_box(c);
        }
    }

    #[test]
    fn test_entry() {
        let mut t = RBTree::new(RcObjAdapter::new());
        let a = make_rc_obj(1);
        let b = make_rc_obj(2);
        let c = make_rc_obj(3);
        let d = make_rc_obj(4);
        let e = make_rc_obj(5);
        let f = make_rc_obj(6);
        t.entry(&3).or_insert(c);
        t.entry(&2).or_insert(b.clone());
        t.entry(&1).or_insert(a);

        match t.entry(&2) {
            Entry::Vacant(_) => unreachable!(),
            Entry::Occupied(c) => assert_eq!(c.get().unwrap().value, 2),
        }
        assert_eq!(t.entry(&2).or_insert(b.clone()).get().unwrap().value, 2);
        assert_eq!(
            t.entry(&2)
                .or_insert_with(|| b.clone())
                .get()
                .unwrap()
                .value,
            2
        );

        match t.entry(&5) {
            Entry::Vacant(c) => assert_eq!(c.insert(e.clone()).get().unwrap().value, 5),
            Entry::Occupied(_) => unreachable!(),
        }
        assert!(e.link.is_linked());
        assert_eq!(t.entry(&4).or_insert(d.clone()).get().unwrap().value, 4);
        assert!(d.link.is_linked());
        assert_eq!(
            t.entry(&6)
                .or_insert_with(|| f.clone())
                .get()
                .unwrap()
                .value,
            6
        );
        assert!(f.link.is_linked());
    }

    #[test]
    fn test_non_static() {
        #[derive(Clone)]
        struct Obj<'a, T> {
            link: Link,
            value: &'a T,
        }
        intrusive_adapter!(RcObjAdapter<'a, T> = &'a Obj<'a, T>: Obj<'a, T> {link: Link} where T: 'a);
        impl<'a, 'b, T: 'a + 'b> KeyAdapter<'a> for RcObjAdapter<'b, T> {
            type Key = &'a T;
            fn get_key(&self, value: &'a Obj<'b, T>) -> &'a T {
                value.value
            }
        }

        let v = 5;
        let a = Obj {
            link: Link::default(),
            value: &v,
        };
        let b = a.clone();
        let mut l = RBTree::new(RcObjAdapter::new());
        l.insert(&a);
        l.insert(&b);
        assert_eq!(*l.front().get().unwrap().value, 5);
        assert_eq!(*l.back().get().unwrap().value, 5);
    }

    macro_rules! test_clone_pointer {
        ($ptr: ident, $ptr_import: path) => {
            use $ptr_import;

            #[derive(Clone)]
            struct Obj {
                link: Link,
                value: usize,
            }
            intrusive_adapter!(RcObjAdapter = $ptr<Obj>: Obj { link: Link });
            impl<'a> KeyAdapter<'a> for RcObjAdapter {
                type Key = usize;
                fn get_key(&self, value: &'a Obj) -> usize {
                    value.value
                }
            }

            let a = $ptr::new(Obj {
                link: Link::new(),
                value: 5,
            });
            let mut l = RBTree::new(RcObjAdapter::new());
            l.insert(a.clone());
            assert_eq!(2, $ptr::strong_count(&a));

            let pointer = l.front().clone_pointer().unwrap();
            assert_eq!(pointer.value, 5);
            assert_eq!(3, $ptr::strong_count(&a));

            l.front_mut().remove();
            assert!(l.front().clone_pointer().is_none());
        };
    }

    #[test]
    fn test_clone_pointer_rc() {
        test_clone_pointer!(Rc, std::rc::Rc);
    }

    #[test]
    fn test_clone_pointer_arc() {
        test_clone_pointer!(Arc, std::sync::Arc);
    }
}
