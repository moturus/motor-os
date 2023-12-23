// Copyright 2016 Amanieu d'Antras
// Copyright 2020 Amari Robinson
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Intrusive doubly-linked list.

use core::cell::Cell;
use core::fmt;
use core::ptr::{null_mut, NonNull};
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::link_ops::{self, DefaultLinkOps};
use crate::pointer_ops::PointerOps;
use crate::singly_linked_list::SinglyLinkedListOps;
use crate::xor_linked_list::XorLinkedListOps;
use crate::Adapter;
// Necessary for Rust 1.56 compatability
#[allow(unused_imports)]
use crate::unchecked_option::UncheckedOptionExt;

// =============================================================================
// LinkedListOps
// =============================================================================

/// Link operations for `LinkedList`.
pub unsafe trait LinkedListOps: link_ops::LinkOps {
    /// Returns the "next" link pointer of `ptr`.
    ///
    /// # Safety
    /// An implementation of `next` must not panic.
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr>;

    /// Returns the "prev" link pointer of `ptr`.
    ///
    /// # Safety
    /// An implementation of `prev` must not panic.
    unsafe fn prev(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr>;

    /// Sets the "next" link pointer of `ptr`.
    ///
    /// # Safety
    /// An implementation of `set_next` must not panic.
    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>);

    /// Sets the "prev" link pointer of `ptr`.
    ///
    /// # Safety
    /// An implementation of `set_prev` must not panic.
    unsafe fn set_prev(&mut self, ptr: Self::LinkPtr, prev: Option<Self::LinkPtr>);
}

// =============================================================================
// Link
// =============================================================================

/// Intrusive link that allows an object to be inserted into a
/// `LinkedList`.
#[repr(align(2))]
pub struct Link {
    next: Cell<Option<NonNull<Link>>>,
    prev: Cell<Option<NonNull<Link>>>,
}

// Use a special value to indicate an unlinked node
const UNLINKED_MARKER: Option<NonNull<Link>> =
    unsafe { Some(NonNull::new_unchecked(1 as *mut Link)) };

impl Link {
    /// Creates a new `Link`.
    #[inline]
    pub const fn new() -> Link {
        Link {
            next: Cell::new(UNLINKED_MARKER),
            prev: Cell::new(UNLINKED_MARKER),
        }
    }

    /// Checks whether the `Link` is linked into a `LinkedList`.
    #[inline]
    pub fn is_linked(&self) -> bool {
        self.next.get() != UNLINKED_MARKER
    }

    /// Forcibly unlinks an object from a `LinkedList`.
    ///
    /// # Safety
    ///
    /// It is undefined behavior to call this function while still linked into a
    /// `LinkedList`. The only situation where this function is useful is
    /// after calling `fast_clear` on a `LinkedList`, since this clears
    /// the collection without marking the nodes as unlinked.
    #[inline]
    pub unsafe fn force_unlink(&self) {
        self.next.set(UNLINKED_MARKER);
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
        // is currently in a list.
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

/// Default `LinkOps` implementation for `LinkedList`.
#[derive(Clone, Copy, Default)]
pub struct LinkOps;

unsafe impl link_ops::LinkOps for LinkOps {
    type LinkPtr = NonNull<Link>;

    #[inline]
    unsafe fn acquire_link(&mut self, ptr: Self::LinkPtr) -> bool {
        if ptr.as_ref().is_linked() {
            false
        } else {
            ptr.as_ref().next.set(None);
            true
        }
    }

    #[inline]
    unsafe fn release_link(&mut self, ptr: Self::LinkPtr) {
        ptr.as_ref().next.set(UNLINKED_MARKER);
    }
}

unsafe impl LinkedListOps for LinkOps {
    #[inline]
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().next.get()
    }

    #[inline]
    unsafe fn prev(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().prev.get()
    }

    #[inline]
    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>) {
        ptr.as_ref().next.set(next);
    }

    #[inline]
    unsafe fn set_prev(&mut self, ptr: Self::LinkPtr, prev: Option<Self::LinkPtr>) {
        ptr.as_ref().prev.set(prev);
    }
}

unsafe impl SinglyLinkedListOps for LinkOps {
    #[inline]
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().next.get()
    }

    #[inline]
    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>) {
        ptr.as_ref().next.set(next);
    }
}

unsafe impl XorLinkedListOps for LinkOps {
    #[inline]
    unsafe fn next(
        &self,
        ptr: Self::LinkPtr,
        prev: Option<Self::LinkPtr>,
    ) -> Option<Self::LinkPtr> {
        let packed = ptr
            .as_ref()
            .next
            .get()
            .map(|x| x.as_ptr() as usize)
            .unwrap_or(0);
        let raw = packed ^ prev.map(|x| x.as_ptr() as usize).unwrap_or(0);
        NonNull::new(raw as *mut _)
    }

    #[inline]
    unsafe fn prev(
        &self,
        ptr: Self::LinkPtr,
        next: Option<Self::LinkPtr>,
    ) -> Option<Self::LinkPtr> {
        let packed = ptr
            .as_ref()
            .next
            .get()
            .map(|x| x.as_ptr() as usize)
            .unwrap_or(0);
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
        ptr.as_ref().next.set(new_next);
    }

    #[inline]
    unsafe fn replace_next_or_prev(
        &mut self,
        ptr: Self::LinkPtr,
        old: Option<Self::LinkPtr>,
        new: Option<Self::LinkPtr>,
    ) {
        let packed = ptr
            .as_ref()
            .next
            .get()
            .map(|x| x.as_ptr() as usize)
            .unwrap_or(0);
        let new_packed = packed
            ^ old.map(|x| x.as_ptr() as usize).unwrap_or(0)
            ^ new.map(|x| x.as_ptr() as usize).unwrap_or(0);

        let new_next = NonNull::new(new_packed as *mut _);
        ptr.as_ref().next.set(new_next);
    }
}

// =============================================================================
// AtomicLink
// =============================================================================

/// Intrusive atomic link that allows an object to be inserted into a
/// `LinkedList`. This link allows the structure to be shared between threads.
#[repr(align(2))]
pub struct AtomicLink {
    next: AtomicPtr<AtomicLink>,
    prev: Cell<Option<NonNull<AtomicLink>>>,
}

// Use a special value to indicate an unlinked node
const ATOMIC_UNLINKED_MARKER_PTR: *mut AtomicLink = 1 as *mut AtomicLink;

// Use a special value to indicate an unlinked node
const ATOMIC_UNLINKED_MARKER: Option<NonNull<AtomicLink>> =
    unsafe { Some(NonNull::new_unchecked(ATOMIC_UNLINKED_MARKER_PTR)) };

impl AtomicLink {
    /// Creates a new `AtomicLink`.
    #[inline]
    pub const fn new() -> AtomicLink {
        Self {
            next: AtomicPtr::new(ATOMIC_UNLINKED_MARKER_PTR),
            prev: Cell::new(ATOMIC_UNLINKED_MARKER),
        }
    }

    /// Checks whether the `AtomicLink` is linked into a `LinkedList`.
    #[inline]
    pub fn is_linked(&self) -> bool {
        self.next.load(Ordering::Relaxed) != ATOMIC_UNLINKED_MARKER_PTR
    }

    /// Forcibly unlinks an object from a `LinkedList`.
    ///
    /// # Safety
    ///
    /// It is undefined behavior to call this function while still linked into a
    /// `LinkedList`. The only situation where this function is useful is
    /// after calling `fast_clear` on a `LinkedList`, since this clears
    /// the collection without marking the nodes as unlinked.
    #[inline]
    pub unsafe fn force_unlink(&self) {
        self.next
            .store(ATOMIC_UNLINKED_MARKER_PTR, Ordering::Release)
    }

    /// Access the `next` pointer in an exclusive context.
    ///
    /// # Safety
    ///
    /// This can only be called after `acquire_link` has been succesfully called.
    #[inline]
    unsafe fn next_exclusive(&self) -> &Cell<Option<NonNull<AtomicLink>>> {
        // This is safe because currently AtomicPtr<AtomicLink> has the same representation Cell<Option<NonNull<AtomicLink>>>.
        core::mem::transmute(&self.next)
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

/// Default `AtomicLinkOps` implementation for `LinkedList`.
#[derive(Clone, Copy, Default)]
pub struct AtomicLinkOps;

unsafe impl link_ops::LinkOps for AtomicLinkOps {
    type LinkPtr = NonNull<AtomicLink>;

    #[inline]
    unsafe fn acquire_link(&mut self, ptr: Self::LinkPtr) -> bool {
        ptr.as_ref()
            .next
            .compare_exchange(
                ATOMIC_UNLINKED_MARKER_PTR,
                null_mut(),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    #[inline]
    unsafe fn release_link(&mut self, ptr: Self::LinkPtr) {
        ptr.as_ref()
            .next
            .store(ATOMIC_UNLINKED_MARKER_PTR, Ordering::Release)
    }
}

unsafe impl LinkedListOps for AtomicLinkOps {
    #[inline]
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().next_exclusive().get()
    }

    #[inline]
    unsafe fn prev(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().prev.get()
    }

    #[inline]
    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>) {
        ptr.as_ref().next_exclusive().set(next);
    }

    #[inline]
    unsafe fn set_prev(&mut self, ptr: Self::LinkPtr, prev: Option<Self::LinkPtr>) {
        ptr.as_ref().prev.set(prev);
    }
}

unsafe impl SinglyLinkedListOps for AtomicLinkOps {
    #[inline]
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        ptr.as_ref().next_exclusive().get()
    }

    #[inline]
    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>) {
        ptr.as_ref().next_exclusive().set(next);
    }
}

unsafe impl XorLinkedListOps for AtomicLinkOps {
    #[inline]
    unsafe fn next(
        &self,
        ptr: Self::LinkPtr,
        prev: Option<Self::LinkPtr>,
    ) -> Option<Self::LinkPtr> {
        let packed = ptr
            .as_ref()
            .next_exclusive()
            .get()
            .map(|x| x.as_ptr() as usize)
            .unwrap_or(0);
        let raw = packed ^ prev.map(|x| x.as_ptr() as usize).unwrap_or(0);
        NonNull::new(raw as *mut _)
    }

    #[inline]
    unsafe fn prev(
        &self,
        ptr: Self::LinkPtr,
        next: Option<Self::LinkPtr>,
    ) -> Option<Self::LinkPtr> {
        let packed = ptr
            .as_ref()
            .next_exclusive()
            .get()
            .map(|x| x.as_ptr() as usize)
            .unwrap_or(0);
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
        ptr.as_ref().next_exclusive().set(new_next);
    }

    #[inline]
    unsafe fn replace_next_or_prev(
        &mut self,
        ptr: Self::LinkPtr,
        old: Option<Self::LinkPtr>,
        new: Option<Self::LinkPtr>,
    ) {
        let packed = ptr
            .as_ref()
            .next_exclusive()
            .get()
            .map(|x| x.as_ptr() as usize)
            .unwrap_or(0);
        let new_packed = packed
            ^ old.map(|x| x.as_ptr() as usize).unwrap_or(0)
            ^ new.map(|x| x.as_ptr() as usize).unwrap_or(0);

        let new_next = NonNull::new(new_packed as *mut _);
        ptr.as_ref().next_exclusive().set(new_next);
    }
}

#[inline]
unsafe fn link_between<T: LinkedListOps>(
    link_ops: &mut T,
    ptr: T::LinkPtr,
    prev: Option<T::LinkPtr>,
    next: Option<T::LinkPtr>,
) {
    if let Some(prev) = prev {
        link_ops.set_next(prev, Some(ptr));
    }
    if let Some(next) = next {
        link_ops.set_prev(next, Some(ptr));
    }
    link_ops.set_next(ptr, next);
    link_ops.set_prev(ptr, prev);
}

#[inline]
unsafe fn link_after<T: LinkedListOps>(link_ops: &mut T, ptr: T::LinkPtr, prev: T::LinkPtr) {
    link_between(link_ops, ptr, Some(prev), link_ops.next(prev));
}

#[inline]
unsafe fn link_before<T: LinkedListOps>(link_ops: &mut T, ptr: T::LinkPtr, next: T::LinkPtr) {
    link_between(link_ops, ptr, link_ops.prev(next), Some(next));
}

#[inline]
unsafe fn replace_with<T: LinkedListOps>(link_ops: &mut T, ptr: T::LinkPtr, new: T::LinkPtr) {
    let prev = link_ops.prev(ptr);
    let next = link_ops.next(ptr);

    if let Some(prev) = prev {
        link_ops.set_next(prev, Some(new));
    }
    if let Some(next) = next {
        link_ops.set_prev(next, Some(new));
    }
    link_ops.set_next(new, next);
    link_ops.set_prev(new, prev);
    link_ops.release_link(ptr);
}

#[inline]
unsafe fn remove<T: LinkedListOps>(link_ops: &mut T, ptr: T::LinkPtr) {
    let prev = link_ops.prev(ptr);
    let next = link_ops.next(ptr);

    if let Some(next) = next {
        link_ops.set_prev(next, prev);
    }
    if let Some(prev) = prev {
        link_ops.set_next(prev, next);
    }
    link_ops.release_link(ptr);
}

#[inline]
unsafe fn splice<T: LinkedListOps>(
    link_ops: &mut T,
    start: T::LinkPtr,
    end: T::LinkPtr,
    prev: Option<T::LinkPtr>,
    next: Option<T::LinkPtr>,
) {
    link_ops.set_prev(start, prev);
    link_ops.set_next(end, next);
    if let Some(prev) = prev {
        link_ops.set_next(prev, Some(start));
    }
    if let Some(next) = next {
        link_ops.set_prev(next, Some(end));
    }
}

// =============================================================================
// Cursor, CursorMut, CursorOwning
// =============================================================================

/// A cursor which provides read-only access to a `LinkedList`.
pub struct Cursor<'a, A: Adapter>
where
    A::LinkOps: LinkedListOps,
{
    current: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    list: &'a LinkedList<A>,
}

impl<'a, A: Adapter> Clone for Cursor<'a, A>
where
    A::LinkOps: LinkedListOps,
{
    #[inline]
    fn clone(&self) -> Cursor<'a, A> {
        Cursor {
            current: self.current,
            list: self.list,
        }
    }
}

impl<'a, A: Adapter> Cursor<'a, A>
where
    A::LinkOps: LinkedListOps,
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
        Some(unsafe { &*self.list.adapter.get_value(self.current?) })
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
        let raw_pointer = unsafe { self.list.adapter.get_value(self.current?) };
        Some(unsafe {
            crate::pointer_ops::clone_pointer_from_raw(self.list.adapter.pointer_ops(), raw_pointer)
        })
    }

    /// Moves the cursor to the next element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the first element of the `LinkedList`. If it is pointing to the
    /// last element of the `LinkedList` then this will move it to the
    /// null object.
    #[inline]
    pub fn move_next(&mut self) {
        if let Some(current) = self.current {
            self.current = unsafe { self.list.adapter.link_ops().next(current) };
        } else {
            self.current = self.list.head;
        }
    }

    /// Moves the cursor to the previous element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the last element of the `LinkedList`. If it is pointing to the first
    /// element of the `LinkedList` then this will move it to the null object.
    #[inline]
    pub fn move_prev(&mut self) {
        if let Some(current) = self.current {
            self.current = unsafe { self.list.adapter.link_ops().prev(current) };
        } else {
            self.current = self.list.tail;
        }
    }

    /// Returns a cursor pointing to the next element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// first element of the `LinkedList`. If it is pointing to the last
    /// element of the `LinkedList` then this will return a null cursor.
    #[inline]
    pub fn peek_next(&self) -> Cursor<'_, A> {
        let mut next = self.clone();
        next.move_next();
        next
    }

    /// Returns a cursor pointing to the previous element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// last element of the `LinkedList`. If it is pointing to the first
    /// element of the `LinkedList` then this will return a null cursor.
    #[inline]
    pub fn peek_prev(&self) -> Cursor<'_, A> {
        let mut prev = self.clone();
        prev.move_prev();
        prev
    }
}

/// A cursor which provides mutable access to a `LinkedList`.
pub struct CursorMut<'a, A: Adapter>
where
    A::LinkOps: LinkedListOps,
{
    current: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    list: &'a mut LinkedList<A>,
}

impl<'a, A: Adapter> CursorMut<'a, A>
where
    A::LinkOps: LinkedListOps,
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
        Some(unsafe { &*self.list.adapter.get_value(self.current?) })
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
            list: self.list,
        }
    }

    /// Moves the cursor to the next element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the first element of the `LinkedList`. If it is pointing to the
    /// last element of the `LinkedList` then this will move it to the
    /// null object.
    #[inline]
    pub fn move_next(&mut self) {
        if let Some(current) = self.current {
            self.current = unsafe { self.list.adapter.link_ops().next(current) };
        } else {
            self.current = self.list.head;
        }
    }

    /// Moves the cursor to the previous element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will move it to
    /// the last element of the `LinkedList`. If it is pointing to the first
    /// element of the `LinkedList` then this will move it to the null object.
    #[inline]
    pub fn move_prev(&mut self) {
        if let Some(current) = self.current {
            self.current = unsafe { self.list.adapter.link_ops().prev(current) };
        } else {
            self.current = self.list.tail;
        }
    }

    ///Returns a cursor pointing to the next element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// first element of the `LinkedList`. If it is pointing to the last
    /// element of the `LinkedList` then this will return a null cursor.
    #[inline]
    pub fn peek_next(&self) -> Cursor<'_, A> {
        let mut next = self.as_cursor();
        next.move_next();
        next
    }

    /// Returns a cursor pointing to the previous element of the `LinkedList`.
    ///
    /// If the cursor is pointer to the null object then this will return the
    /// last element of the `LinkedList`. If it is pointing to the first
    /// element of the `LinkedList` then this will return a null cursor.
    #[inline]
    pub fn peek_prev(&self) -> Cursor<'_, A> {
        let mut prev = self.as_cursor();
        prev.move_prev();
        prev
    }

    /// Removes the current element from the `LinkedList`.
    ///
    /// A pointer to the element that was removed is returned, and the cursor is
    /// moved to point to the next element in the `LinkedList`.
    ///
    /// If the cursor is currently pointing to the null object then no element
    /// is removed and `None` is returned.
    #[inline]
    pub fn remove(&mut self) -> Option<<A::PointerOps as PointerOps>::Pointer> {
        unsafe {
            if let Some(current) = self.current {
                if self.list.head == self.current {
                    self.list.head = self.list.adapter.link_ops().next(current);
                }
                if self.list.tail == self.current {
                    self.list.tail = self.list.adapter.link_ops().prev(current);
                }
                let next = self.list.adapter.link_ops().next(current);
                let result = current;
                remove(self.list.adapter.link_ops_mut(), current);
                self.current = next;
                Some(
                    self.list
                        .adapter
                        .pointer_ops()
                        .from_raw(self.list.adapter.get_value(result)),
                )
            } else {
                None
            }
        }
    }

    /// Removes the current element from the `LinkedList` and inserts another
    /// object in its place.
    ///
    /// A pointer to the element that was removed is returned, and the cursor is
    /// modified to point to the newly added element.
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
                let new = self.list.node_from_value(val);
                if self.list.head == self.current {
                    self.list.head = Some(new);
                }
                if self.list.tail == self.current {
                    self.list.tail = Some(new);
                }
                let result = current;
                replace_with(self.list.adapter.link_ops_mut(), current, new);
                self.current = Some(new);
                Ok(self
                    .list
                    .adapter
                    .pointer_ops()
                    .from_raw(self.list.adapter.get_value(result)))
            } else {
                Err(val)
            }
        }
    }

    /// Inserts a new element into the `LinkedList` after the current one.
    ///
    /// If the cursor is pointing at the null object then the new element is
    /// inserted at the front of the `LinkedList`.
    ///
    /// # Panics
    ///
    /// Panics if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn insert_after(&mut self, val: <A::PointerOps as PointerOps>::Pointer) {
        unsafe {
            let new = self.list.node_from_value(val);
            if let Some(current) = self.current {
                link_after(self.list.adapter.link_ops_mut(), new, current);
            } else {
                link_between(self.list.adapter.link_ops_mut(), new, None, self.list.head);
                self.list.head = Some(new);
            }
            if self.list.tail == self.current {
                self.list.tail = Some(new);
            }
        }
    }

    /// Inserts a new element into the `LinkedList` before the current one.
    ///
    /// If the cursor is pointing at the null object then the new element is
    /// inserted at the end of the `LinkedList`.
    ///
    /// # Panics
    ///
    /// Panics if the new element is already linked to a different intrusive
    /// collection.
    #[inline]
    pub fn insert_before(&mut self, val: <A::PointerOps as PointerOps>::Pointer) {
        unsafe {
            let new = self.list.node_from_value(val);

            let link_ops = self.list.adapter.link_ops_mut();

            if let Some(current) = self.current {
                link_before(link_ops, new, current);
            } else {
                link_between(link_ops, new, self.list.tail, None);
                self.list.tail = Some(new);
            }
            if self.list.head == self.current {
                self.list.head = Some(new);
            }
        }
    }

    /// Inserts the elements from the given `LinkedList` after the current one.
    ///
    /// If the cursor is pointing at the null object then the new elements are
    /// inserted at the start of the `LinkedList`.
    #[inline]
    pub fn splice_after(&mut self, mut list: LinkedList<A>) {
        if !list.is_empty() {
            unsafe {
                let head = list.head.unwrap_unchecked();
                let tail = list.tail.unwrap_unchecked();

                let link_ops = self.list.adapter.link_ops_mut();

                if let Some(current) = self.current {
                    splice(link_ops, head, tail, Some(current), link_ops.next(current));
                } else {
                    splice(link_ops, head, tail, None, self.list.head);
                    self.list.head = list.head;
                }
                if self.list.tail == self.current {
                    self.list.tail = list.tail;
                }
                list.head = None;
                list.tail = None;
            }
        }
    }

    /// Moves all element from the given `LinkedList` before the current one.
    ///
    /// If the cursor is pointing at the null object then the new elements are
    /// inserted at the end of the `LinkedList`.
    #[inline]
    pub fn splice_before(&mut self, mut list: LinkedList<A>) {
        if !list.is_empty() {
            unsafe {
                let head = list.head.unwrap_unchecked();
                let tail = list.tail.unwrap_unchecked();

                let link_ops = self.list.adapter.link_ops_mut();

                if let Some(current) = self.current {
                    splice(link_ops, head, tail, link_ops.prev(current), Some(current));
                } else {
                    splice(link_ops, head, tail, self.list.tail, None);
                    self.list.tail = list.tail;
                }
                if self.list.head == self.current {
                    self.list.head = list.head;
                }
                list.head = None;
                list.tail = None;
            }
        }
    }

    /// Splits the list into two after the current element. This will return a
    /// new list consisting of everything after the cursor, with the original
    /// list retaining everything before.
    ///
    /// If the cursor is pointing at the null object then the entire contents
    /// of the `LinkedList` are moved.
    #[inline]
    pub fn split_after(&mut self) -> LinkedList<A>
    where
        A: Clone,
    {
        if let Some(current) = self.current {
            unsafe {
                let mut list = LinkedList {
                    head: self.list.adapter.link_ops().next(current),
                    tail: self.list.tail,
                    adapter: self.list.adapter.clone(),
                };
                if let Some(head) = list.head {
                    self.list.adapter.link_ops_mut().set_prev(head, None);
                } else {
                    list.tail = None;
                }
                self.list.adapter.link_ops_mut().set_next(current, None);
                self.list.tail = self.current;
                list
            }
        } else {
            let list = LinkedList {
                head: self.list.head,
                tail: self.list.tail,
                adapter: self.list.adapter.clone(),
            };
            self.list.head = None;
            self.list.tail = None;
            list
        }
    }

    /// Splits the list into two before the current element. This will return a
    /// new list consisting of everything before the cursor, with the original
    /// list retaining everything after.
    ///
    /// If the cursor is pointing at the null object then the entire contents
    /// of the `LinkedList` are moved.
    #[inline]
    pub fn split_before(&mut self) -> LinkedList<A>
    where
        A: Clone,
    {
        if let Some(current) = self.current {
            unsafe {
                let mut list = LinkedList {
                    head: self.list.head,
                    tail: self.list.adapter.link_ops().prev(current),
                    adapter: self.list.adapter.clone(),
                };
                if let Some(tail) = list.tail {
                    self.list.adapter.link_ops_mut().set_prev(tail, None);
                } else {
                    list.head = None;
                }
                self.list.adapter.link_ops_mut().set_prev(current, None);
                self.list.head = self.current;
                list
            }
        } else {
            let list = LinkedList {
                head: self.list.head,
                tail: self.list.tail,
                adapter: self.list.adapter.clone(),
            };
            self.list.head = None;
            self.list.tail = None;
            list
        }
    }

    /// Consumes `CursorMut` and returns a reference to the object that
    /// the cursor is currently pointing to. Unlike [get](Self::get),
    /// the returned reference's lifetime is tied to `LinkedList`'s lifetime.
    ///
    /// This returns None if the cursor is currently pointing to the null object.
    #[inline]
    pub fn into_ref(self) -> Option<&'a <A::PointerOps as PointerOps>::Value> {
        Some(unsafe { &*self.list.adapter.get_value(self.current?) })
    }
}

/// A cursor with ownership over the `LinkedList` it points into.
pub struct CursorOwning<A: Adapter>
where
    A::LinkOps: LinkedListOps,
{
    current: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    list: LinkedList<A>,
}

impl<A: Adapter> CursorOwning<A>
where
    A::LinkOps: LinkedListOps,
{
    /// Consumes self and returns the inner `LinkedList`.
    #[inline]
    pub fn into_inner(self) -> LinkedList<A> {
        self.list
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
            list: &self.list,
        }
    }

    /// Perform action with mutable reference to the cursor.
    ///
    /// All mutations of the cursor are reflected in the original.
    #[inline]
    pub fn with_cursor_mut<T>(&mut self, f: impl FnOnce(&mut CursorMut<'_, A>) -> T) -> T {
        let mut cursor = CursorMut {
            current: self.current,
            list: &mut self.list,
        };
        let ret = f(&mut cursor);
        self.current = cursor.current;
        ret
    }
}
unsafe impl<A: Adapter> Send for CursorOwning<A>
where
    LinkedList<A>: Send,
    A::LinkOps: LinkedListOps,
{
}

// =============================================================================
// LinkedList
// =============================================================================

/// An intrusive doubly-linked list.
///
/// When this collection is dropped, all elements linked into it will be
/// converted back to owned pointers and dropped.
pub struct LinkedList<A: Adapter>
where
    A::LinkOps: LinkedListOps,
{
    head: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    tail: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    adapter: A,
}

impl<A: Adapter> LinkedList<A>
where
    A::LinkOps: LinkedListOps,
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

    /// Creates an empty `LinkedList`.
    #[cfg(not(feature = "nightly"))]
    #[inline]
    pub fn new(adapter: A) -> LinkedList<A> {
        LinkedList {
            head: None,
            tail: None,
            adapter,
        }
    }

    /// Creates an empty `LinkedList`.
    #[cfg(feature = "nightly")]
    #[inline]
    pub const fn new(adapter: A) -> LinkedList<A> {
        LinkedList {
            head: None,
            tail: None,
            adapter,
        }
    }

    /// Returns `true` if the `LinkedList` is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Returns a null `Cursor` for this list.
    #[inline]
    pub fn cursor(&self) -> Cursor<'_, A> {
        Cursor {
            current: None,
            list: self,
        }
    }

    /// Returns a null `CursorMut` for this list.
    #[inline]
    pub fn cursor_mut(&mut self) -> CursorMut<'_, A> {
        CursorMut {
            current: None,
            list: self,
        }
    }

    /// Returns a null `CursorOwning` for this list.
    #[inline]
    pub fn cursor_owning(self) -> CursorOwning<A> {
        CursorOwning {
            current: None,
            list: self,
        }
    }

    /// Creates a `Cursor` from a pointer to an element.
    ///
    /// # Safety
    ///
    /// `ptr` must be a pointer to an object that is part of this list.
    #[inline]
    pub unsafe fn cursor_from_ptr(
        &self,
        ptr: *const <A::PointerOps as PointerOps>::Value,
    ) -> Cursor<'_, A> {
        Cursor {
            current: Some(self.adapter.get_link(ptr)),
            list: self,
        }
    }

    /// Creates a `CursorMut` from a pointer to an element.
    ///
    /// # Safety
    ///
    /// `ptr` must be a pointer to an object that is part of this list.
    #[inline]
    pub unsafe fn cursor_mut_from_ptr(
        &mut self,
        ptr: *const <A::PointerOps as PointerOps>::Value,
    ) -> CursorMut<'_, A> {
        CursorMut {
            current: Some(self.adapter.get_link(ptr)),
            list: self,
        }
    }

    /// Creates a `CursorOwning` from a pointer to an element.
    ///
    /// # Safety
    ///
    /// `ptr` must be a pointer to an object that is part of this list.
    #[inline]
    pub unsafe fn cursor_owning_from_ptr(
        self,
        ptr: *const <A::PointerOps as PointerOps>::Value,
    ) -> CursorOwning<A> {
        CursorOwning {
            current: Some(self.adapter.get_link(ptr)),
            list: self,
        }
    }

    /// Returns a `Cursor` pointing to the first element of the list. If the
    /// list is empty then a null cursor is returned.
    #[inline]
    pub fn front(&self) -> Cursor<'_, A> {
        let mut cursor = self.cursor();
        cursor.move_next();
        cursor
    }

    /// Returns a `CursorMut` pointing to the first element of the list. If the
    /// the list is empty then a null cursor is returned.
    #[inline]
    pub fn front_mut(&mut self) -> CursorMut<'_, A> {
        let mut cursor = self.cursor_mut();
        cursor.move_next();
        cursor
    }

    /// Returns a `CursorOwning` pointing to the first element of the list. If the
    /// the list is empty then a null cursor is returned.
    #[inline]
    pub fn front_owning(self) -> CursorOwning<A> {
        let mut cursor = self.cursor_owning();
        cursor.with_cursor_mut(|c| c.move_next());
        cursor
    }

    /// Returns a `Cursor` pointing to the last element of the list. If the list
    /// is empty then a null cursor is returned.
    #[inline]
    pub fn back(&self) -> Cursor<'_, A> {
        let mut cursor = self.cursor();
        cursor.move_prev();
        cursor
    }

    /// Returns a `CursorMut` pointing to the last element of the list. If the
    /// list is empty then a null cursor is returned.
    #[inline]
    pub fn back_mut(&mut self) -> CursorMut<'_, A> {
        let mut cursor = self.cursor_mut();
        cursor.move_prev();
        cursor
    }

    /// Returns a `CursorOwning` pointing to the last element of the list. If the
    /// list is empty then a null cursor is returned.
    #[inline]
    pub fn back_owning(self) -> CursorOwning<A> {
        let mut cursor = self.cursor_owning();
        cursor.with_cursor_mut(|c| c.move_prev());
        cursor
    }

    /// Gets an iterator over the objects in the `LinkedList`.
    #[inline]
    pub fn iter(&self) -> Iter<'_, A> {
        Iter {
            head: self.head,
            tail: self.tail,
            list: self,
        }
    }

    /// Removes all elements from the `LinkedList`.
    ///
    /// This will unlink all object currently in the list, which requires
    /// iterating through all elements in the `LinkedList`. Each element is
    /// converted back to an owned pointer and then dropped.
    #[inline]
    pub fn clear(&mut self) {
        use link_ops::LinkOps;

        let mut current = self.head;
        self.head = None;
        self.tail = None;
        while let Some(x) = current {
            unsafe {
                let next = self.adapter.link_ops().next(x);
                self.adapter.link_ops_mut().release_link(x);
                self.adapter
                    .pointer_ops()
                    .from_raw(self.adapter.get_value(x));
                current = next;
            }
        }
    }

    /// Empties the `LinkedList` without unlinking or freeing objects in it.
    ///
    /// Since this does not unlink any objects, any attempts to link these
    /// objects into another `LinkedList` will fail but will not cause any
    /// memory unsafety. To unlink those objects manually, you must call the
    /// `force_unlink` function on them.
    #[inline]
    pub fn fast_clear(&mut self) {
        self.head = None;
        self.tail = None;
    }

    /// Takes all the elements out of the `LinkedList`, leaving it empty.
    /// The taken elements are returned as a new `LinkedList`.
    #[inline]
    pub fn take(&mut self) -> LinkedList<A>
    where
        A: Clone,
    {
        let list = LinkedList {
            head: self.head,
            tail: self.tail,
            adapter: self.adapter.clone(),
        };
        self.head = None;
        self.tail = None;
        list
    }

    /// Inserts a new element at the start of the `LinkedList`.
    #[inline]
    pub fn push_front(&mut self, val: <A::PointerOps as PointerOps>::Pointer) {
        self.cursor_mut().insert_after(val);
    }

    /// Inserts a new element at the end of the `LinkedList`.
    #[inline]
    pub fn push_back(&mut self, val: <A::PointerOps as PointerOps>::Pointer) {
        self.cursor_mut().insert_before(val);
    }

    /// Removes the first element of the `LinkedList`.
    ///
    /// This returns `None` if the `LinkedList` is empty.
    #[inline]
    pub fn pop_front(&mut self) -> Option<<A::PointerOps as PointerOps>::Pointer> {
        self.front_mut().remove()
    }

    /// Removes the last element of the `LinkedList`.
    ///
    /// This returns `None` if the `LinkedList` is empty.
    #[inline]
    pub fn pop_back(&mut self) -> Option<<A::PointerOps as PointerOps>::Pointer> {
        self.back_mut().remove()
    }
}

// Allow read-only access to values from multiple threads
unsafe impl<A: Adapter + Sync> Sync for LinkedList<A>
where
    <A::PointerOps as PointerOps>::Value: Sync,
    A::LinkOps: LinkedListOps,
{
}

// Allow sending to another thread if the ownership (represented by the <A::PointerOps as PointerOps>::Pointer owned
// pointer type) can be transferred to another thread.
unsafe impl<A: Adapter + Send> Send for LinkedList<A>
where
    <A::PointerOps as PointerOps>::Pointer: Send,
    A::LinkOps: LinkedListOps,
{
}

// Drop all owned pointers if the collection is dropped
impl<A: Adapter> Drop for LinkedList<A>
where
    A::LinkOps: LinkedListOps,
{
    #[inline]
    fn drop(&mut self) {
        self.clear();
    }
}

impl<A: Adapter> IntoIterator for LinkedList<A>
where
    A::LinkOps: LinkedListOps,
{
    type Item = <A::PointerOps as PointerOps>::Pointer;
    type IntoIter = IntoIter<A>;

    #[inline]
    fn into_iter(self) -> IntoIter<A> {
        IntoIter { list: self }
    }
}

impl<'a, A: Adapter + 'a> IntoIterator for &'a LinkedList<A>
where
    A::LinkOps: LinkedListOps,
{
    type Item = &'a <A::PointerOps as PointerOps>::Value;
    type IntoIter = Iter<'a, A>;

    #[inline]
    fn into_iter(self) -> Iter<'a, A> {
        self.iter()
    }
}

impl<A: Adapter + Default> Default for LinkedList<A>
where
    A::LinkOps: LinkedListOps,
{
    fn default() -> LinkedList<A> {
        LinkedList::new(A::default())
    }
}

impl<A: Adapter> fmt::Debug for LinkedList<A>
where
    A::LinkOps: LinkedListOps,
    <A::PointerOps as PointerOps>::Value: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

// =============================================================================
// Iter
// =============================================================================

/// An iterator over references to the items of a `LinkedList`.
pub struct Iter<'a, A: Adapter>
where
    A::LinkOps: LinkedListOps,
{
    head: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    tail: Option<<A::LinkOps as link_ops::LinkOps>::LinkPtr>,
    list: &'a LinkedList<A>,
}
impl<'a, A: Adapter + 'a> Iterator for Iter<'a, A>
where
    A::LinkOps: LinkedListOps,
{
    type Item = &'a <A::PointerOps as PointerOps>::Value;

    #[inline]
    fn next(&mut self) -> Option<&'a <A::PointerOps as PointerOps>::Value> {
        let head = self.head?;

        if Some(head) == self.tail {
            self.head = None;
            self.tail = None;
        } else {
            self.head = unsafe { self.list.adapter.link_ops().next(head) };
        }
        Some(unsafe { &*self.list.adapter.get_value(head) })
    }
}
impl<'a, A: Adapter + 'a> DoubleEndedIterator for Iter<'a, A>
where
    A::LinkOps: LinkedListOps,
{
    #[inline]
    fn next_back(&mut self) -> Option<&'a <A::PointerOps as PointerOps>::Value> {
        let tail = self.tail?;

        if Some(tail) == self.head {
            self.head = None;
            self.tail = None;
        } else {
            self.tail = unsafe { self.list.adapter.link_ops().prev(tail) };
        }
        Some(unsafe { &*self.list.adapter.get_value(tail) })
    }
}
impl<'a, A: Adapter + 'a> Clone for Iter<'a, A>
where
    A::LinkOps: LinkedListOps,
{
    #[inline]
    fn clone(&self) -> Iter<'a, A> {
        Iter {
            head: self.head,
            tail: self.tail,
            list: self.list,
        }
    }
}

// =============================================================================
// IntoIter
// =============================================================================

/// An iterator which consumes a `LinkedList`.
pub struct IntoIter<A: Adapter>
where
    A::LinkOps: LinkedListOps,
{
    list: LinkedList<A>,
}
impl<A: Adapter> Iterator for IntoIter<A>
where
    A::LinkOps: LinkedListOps,
{
    type Item = <A::PointerOps as PointerOps>::Pointer;

    #[inline]
    fn next(&mut self) -> Option<<A::PointerOps as PointerOps>::Pointer> {
        self.list.pop_front()
    }
}
impl<A: Adapter> DoubleEndedIterator for IntoIter<A>
where
    A::LinkOps: LinkedListOps,
{
    #[inline]
    fn next_back(&mut self) -> Option<<A::PointerOps as PointerOps>::Pointer> {
        self.list.pop_back()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use crate::UnsafeRef;

    use super::{CursorOwning, Link, LinkedList};
    use std::fmt;
    use std::format;
    use std::rc::Rc;
    use std::vec::Vec;

    struct Obj {
        link1: Link,
        link2: Link,
        value: u32,
    }
    impl fmt::Debug for Obj {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.value)
        }
    }
    intrusive_adapter!(ObjAdapter1 = Rc<Obj>: Obj { link1: Link });
    intrusive_adapter!(ObjAdapter2 = Rc<Obj>: Obj { link2: Link });
    intrusive_adapter!(UnsafeRefObjAdapter1 = UnsafeRef<Obj>: Obj { link1: Link });

    fn make_rc_obj(value: u32) -> Rc<Obj> {
        Rc::new(make_obj(value))
    }

    fn make_obj(value: u32) -> Obj {
        Obj {
            link1: Link::new(),
            link2: Link::default(),
            value,
        }
    }

    #[test]
    fn test_link() {
        let a = make_rc_obj(1);
        assert!(!a.link1.is_linked());
        assert!(!a.link2.is_linked());

        let mut b = LinkedList::<ObjAdapter1>::default();
        assert!(b.is_empty());

        b.cursor_mut().insert_after(a.clone());
        assert!(!b.is_empty());
        assert!(a.link1.is_linked());
        assert!(!a.link2.is_linked());
        assert_eq!(format!("{:?}", a.link1), "linked");
        assert_eq!(format!("{:?}", a.link2), "unlinked");

        assert_eq!(
            b.front_mut().remove().unwrap().as_ref() as *const _,
            a.as_ref() as *const _
        );
        assert!(b.is_empty());
        assert!(!a.link1.is_linked());
        assert!(!a.link2.is_linked());
    }

    #[test]
    fn test_cursor() {
        let a = make_rc_obj(1);
        let b = make_rc_obj(2);
        let c = make_rc_obj(3);

        let mut l = LinkedList::new(ObjAdapter1::new());
        let mut cur = l.cursor_mut();
        assert!(cur.is_null());
        assert!(cur.get().is_none());
        assert!(cur.remove().is_none());
        assert_eq!(
            cur.replace_with(a.clone()).unwrap_err().as_ref() as *const _,
            a.as_ref() as *const _
        );

        cur.insert_before(a.clone());
        cur.insert_before(c.clone());
        cur.move_prev();
        cur.insert_before(b.clone());
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

        cur.move_next();
        assert_eq!(
            cur.remove().unwrap().as_ref() as *const _,
            b.as_ref() as *const _
        );
        assert_eq!(cur.get().unwrap() as *const _, c.as_ref() as *const _);
        cur.insert_after(b.clone());
        assert_eq!(cur.get().unwrap() as *const _, c.as_ref() as *const _);
        cur.move_prev();
        assert_eq!(cur.get().unwrap() as *const _, a.as_ref() as *const _);
        assert_eq!(
            cur.remove().unwrap().as_ref() as *const _,
            a.as_ref() as *const _
        );
        assert!(!a.link1.is_linked());
        assert!(c.link1.is_linked());
        assert_eq!(cur.get().unwrap() as *const _, c.as_ref() as *const _);
        assert_eq!(
            cur.replace_with(a.clone()).unwrap().as_ref() as *const _,
            c.as_ref() as *const _
        );
        assert!(a.link1.is_linked());
        assert!(!c.link1.is_linked());
        assert_eq!(cur.get().unwrap() as *const _, a.as_ref() as *const _);
        cur.move_next();
        assert_eq!(
            cur.replace_with(c.clone()).unwrap().as_ref() as *const _,
            b.as_ref() as *const _
        );
        assert!(a.link1.is_linked());
        assert!(!b.link1.is_linked());
        assert!(c.link1.is_linked());
        assert_eq!(cur.get().unwrap() as *const _, c.as_ref() as *const _);
    }

    #[test]
    fn test_cursor_owning() {
        struct Container {
            cur: CursorOwning<ObjAdapter1>,
        }

        let mut l = LinkedList::new(ObjAdapter1::new());
        l.push_back(make_rc_obj(1));
        l.push_back(make_rc_obj(2));
        l.push_back(make_rc_obj(3));
        l.push_back(make_rc_obj(4));
        let mut con = Container {
            cur: l.cursor_owning(),
        };
        assert!(con.cur.as_cursor().is_null());

        con.cur = con.cur.into_inner().front_owning();
        assert_eq!(con.cur.as_cursor().get().unwrap().value, 1);

        con.cur.with_cursor_mut(|c| c.move_next());
        assert_eq!(con.cur.as_cursor().get().unwrap().value, 2);

        con.cur = con.cur.into_inner().back_owning();
        assert_eq!(con.cur.as_cursor().get().unwrap().value, 4);
    }

    #[test]
    fn test_push_pop() {
        let a = make_rc_obj(1);
        let b = make_rc_obj(2);
        let c = make_rc_obj(3);

        let mut l = LinkedList::new(ObjAdapter1::new());
        l.push_front(a);
        assert_eq!(l.iter().map(|x| x.value).collect::<Vec<_>>(), [1]);
        l.push_front(b);
        assert_eq!(l.iter().map(|x| x.value).collect::<Vec<_>>(), [2, 1]);
        l.push_back(c);
        assert_eq!(l.iter().map(|x| x.value).collect::<Vec<_>>(), [2, 1, 3]);
        assert_eq!(l.pop_front().unwrap().value, 2);
        assert_eq!(l.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 3]);
        assert_eq!(l.pop_back().unwrap().value, 3);
        assert_eq!(l.iter().map(|x| x.value).collect::<Vec<_>>(), [1]);
        assert_eq!(l.pop_front().unwrap().value, 1);
        assert_eq!(l.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        assert!(l.pop_front().is_none());
        assert_eq!(l.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        assert!(l.pop_back().is_none());
        assert_eq!(l.iter().map(|x| x.value).collect::<Vec<_>>(), []);
    }

    #[test]
    fn test_split_splice() {
        let mut l1 = LinkedList::new(ObjAdapter1::new());
        let mut l2 = LinkedList::new(ObjAdapter1::new());
        let mut l3 = LinkedList::new(ObjAdapter1::new());

        let a = make_rc_obj(1);
        let b = make_rc_obj(2);
        let c = make_rc_obj(3);
        let d = make_rc_obj(4);
        l1.cursor_mut().insert_before(a);
        l1.cursor_mut().insert_before(b);
        l1.cursor_mut().insert_before(c);
        l1.cursor_mut().insert_before(d);
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 2, 3, 4]);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        assert_eq!(l3.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        {
            let mut cur = l1.front_mut();
            cur.move_next();
            l2 = cur.split_after();
        }
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), [3, 4]);
        assert_eq!(l3.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        {
            let mut cur = l2.back_mut();
            l3 = cur.split_before();
        }
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), [4]);
        assert_eq!(l3.iter().map(|x| x.value).collect::<Vec<_>>(), [3]);
        {
            let mut cur = l1.front_mut();
            cur.splice_after(l2.take());
        }
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 4, 2]);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        assert_eq!(l3.iter().map(|x| x.value).collect::<Vec<_>>(), [3]);
        {
            let mut cur = l1.front_mut();
            cur.move_next();
            cur.splice_before(l3.take());
        }
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 3, 4, 2]);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        assert_eq!(l3.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        {
            let mut cur = l2.cursor_mut();
            cur.splice_after(l1.take());
        }
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 3, 4, 2]);
        assert_eq!(l3.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        {
            let mut cur = l1.cursor_mut();
            cur.splice_before(l2.take());
        }
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 3, 4, 2]);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        assert_eq!(l3.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        {
            let mut cur = l1.cursor_mut();
            l2 = cur.split_after();
        }
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 3, 4, 2]);
        assert_eq!(l3.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        {
            let mut cur = l2.cursor_mut();
            l1 = cur.split_before();
        }
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 3, 4, 2]);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        assert_eq!(l3.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        {
            let mut cur = l1.front_mut();
            l2 = cur.split_before();
        }
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 3, 4, 2]);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        assert_eq!(l3.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        {
            let mut cur = l1.back_mut();
            l2 = cur.split_after();
        }
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 3, 4, 2]);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), []);
        assert_eq!(l3.iter().map(|x| x.value).collect::<Vec<_>>(), []);
    }

    #[test]
    fn test_iter() {
        let mut l = LinkedList::new(ObjAdapter1::new());
        let a = make_rc_obj(1);
        let b = make_rc_obj(2);
        let c = make_rc_obj(3);
        let d = make_rc_obj(4);
        l.cursor_mut().insert_before(a.clone());
        l.cursor_mut().insert_before(b.clone());
        l.cursor_mut().insert_before(c.clone());
        l.cursor_mut().insert_before(d.clone());

        assert_eq!(l.front().get().unwrap().value, 1);
        assert_eq!(l.back().get().unwrap().value, 4);
        unsafe {
            assert_eq!(l.cursor_from_ptr(b.as_ref()).get().unwrap().value, 2);
            assert_eq!(l.cursor_mut_from_ptr(c.as_ref()).get().unwrap().value, 3);
        }

        let mut v = Vec::new();
        for x in &l {
            v.push(x.value);
        }
        assert_eq!(v, [1, 2, 3, 4]);
        assert_eq!(
            l.iter().clone().map(|x| x.value).collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        assert_eq!(
            l.iter().rev().map(|x| x.value).collect::<Vec<_>>(),
            [4, 3, 2, 1]
        );
        assert_eq!(l.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 2, 3, 4]);

        assert_eq!(format!("{:?}", l), "[1, 2, 3, 4]");

        let mut v = Vec::new();
        for x in l.take() {
            v.push(x.value);
        }
        assert_eq!(v, [1, 2, 3, 4]);
        assert!(l.is_empty());
        assert!(!a.link1.is_linked());
        assert!(!b.link1.is_linked());
        assert!(!c.link1.is_linked());
        assert!(!d.link1.is_linked());

        l.cursor_mut().insert_before(a.clone());
        l.cursor_mut().insert_before(b.clone());
        l.cursor_mut().insert_before(c.clone());
        l.cursor_mut().insert_before(d.clone());
        l.clear();
        assert!(l.is_empty());
        assert!(!a.link1.is_linked());
        assert!(!b.link1.is_linked());
        assert!(!c.link1.is_linked());
        assert!(!d.link1.is_linked());

        v.clear();
        l.cursor_mut().insert_before(a.clone());
        l.cursor_mut().insert_before(b.clone());
        l.cursor_mut().insert_before(c.clone());
        l.cursor_mut().insert_before(d.clone());
        for x in l.into_iter().rev() {
            v.push(x.value);
        }
        assert_eq!(v, [4, 3, 2, 1]);
        assert!(!a.link1.is_linked());
        assert!(!b.link1.is_linked());
        assert!(!c.link1.is_linked());
        assert!(!d.link1.is_linked());
    }

    #[test]
    fn test_multi_list() {
        let mut l1 = LinkedList::new(ObjAdapter1::new());
        let mut l2 = LinkedList::new(ObjAdapter2::new());
        let a = make_rc_obj(1);
        let b = make_rc_obj(2);
        let c = make_rc_obj(3);
        let d = make_rc_obj(4);
        l1.cursor_mut().insert_before(a.clone());
        l1.cursor_mut().insert_before(b.clone());
        l1.cursor_mut().insert_before(c.clone());
        l1.cursor_mut().insert_before(d.clone());
        l2.cursor_mut().insert_after(a);
        l2.cursor_mut().insert_after(b);
        l2.cursor_mut().insert_after(c);
        l2.cursor_mut().insert_after(d);
        assert_eq!(l1.iter().map(|x| x.value).collect::<Vec<_>>(), [1, 2, 3, 4]);
        assert_eq!(l2.iter().map(|x| x.value).collect::<Vec<_>>(), [4, 3, 2, 1]);
    }

    #[test]
    fn test_fast_clear_force_unlink() {
        let mut l = LinkedList::new(UnsafeRefObjAdapter1::new());
        let a = UnsafeRef::from_box(Box::new(make_obj(1)));
        let b = UnsafeRef::from_box(Box::new(make_obj(2)));
        let c = UnsafeRef::from_box(Box::new(make_obj(3)));
        l.cursor_mut().insert_before(a.clone());
        l.cursor_mut().insert_before(b.clone());
        l.cursor_mut().insert_before(c.clone());

        l.fast_clear();
        assert!(l.is_empty());

        unsafe {
            assert!(a.link1.is_linked());
            assert!(b.link1.is_linked());
            assert!(c.link1.is_linked());

            a.link1.force_unlink();
            b.link1.force_unlink();
            c.link1.force_unlink();

            assert!(l.is_empty());

            assert!(!a.link1.is_linked());
            assert!(!b.link1.is_linked());
            assert!(!c.link1.is_linked());
        }

        unsafe {
            UnsafeRef::into_box(a);
            UnsafeRef::into_box(b);
            UnsafeRef::into_box(c);
        }
    }

    #[test]
    fn test_non_static() {
        #[derive(Clone)]
        struct Obj<'a, T> {
            link: Link,
            value: &'a T,
        }
        intrusive_adapter!(ObjAdapter<'a, T> = &'a Obj<'a, T>: Obj<'a, T> {link: Link} where T: 'a);

        let v = 5;
        let a = Obj {
            link: Link::new(),
            value: &v,
        };
        let b = a.clone();
        let mut l = LinkedList::new(ObjAdapter::new());
        l.cursor_mut().insert_before(&a);
        l.cursor_mut().insert_before(&b);
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
            intrusive_adapter!(ObjAdapter = $ptr<Obj>: Obj { link: Link });

            let a = $ptr::new(Obj {
                link: Link::new(),
                value: 5,
            });
            let mut l = LinkedList::new(ObjAdapter::new());
            l.cursor_mut().insert_before(a.clone());
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
