// Copyright 2016 Amanieu d'Antras
// Copyright 2020 Amari Robinson
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Intrusive collections for Rust.
//!
//! This library provides a set of high-performance intrusive collections which
//! can offer better performance and more flexibility than standard collections.
//!
//! The main difference between an intrusive collection and a normal one is that
//! while normal collections allocate memory behind your back to keep track of a
//! set of *values*, intrusive collections never allocate memory themselves and
//! instead keep track of a set of *objects*. Such collections are called
//! intrusive because they requires explicit support in objects to allow them to
//! be inserted into a collection.
//!
//! # Example
//!
//! ```
//! use intrusive_collections::intrusive_adapter;
//! use intrusive_collections::{LinkedList, LinkedListLink};
//! use std::cell::Cell;
//!
//! // A simple struct containing an instrusive link and a value
//! struct Test {
//!     link: LinkedListLink,
//!     value: Cell<i32>,
//! }
//!
//! // The adapter describes how an object can be inserted into an intrusive
//! // collection. This is automatically generated using a macro.
//! intrusive_adapter!(TestAdapter = Box<Test>: Test { link: LinkedListLink });
//!
//! // Create a list and some objects
//! let mut list = LinkedList::new(TestAdapter::new());
//! let a = Box::new(Test {
//!     link: LinkedListLink::new(),
//!     value: Cell::new(1),
//! });
//! let b = Box::new(Test {
//!     link: LinkedListLink::new(),
//!     value: Cell::new(2),
//! });
//! let c = Box::new(Test {
//!     link: LinkedListLink::new(),
//!     value: Cell::new(3),
//! });
//!
//! // Insert the objects at the front of the list
//! list.push_front(a);
//! list.push_front(b);
//! list.push_front(c);
//! assert_eq!(list.iter().map(|x| x.value.get()).collect::<Vec<_>>(), [3, 2, 1]);
//!
//! // At this point, the objects are owned by the list, and we can modify
//! // them through the list.
//! list.front().get().unwrap().value.set(4);
//! assert_eq!(list.iter().map(|x| x.value.get()).collect::<Vec<_>>(), [4, 2, 1]);
//!
//! // Removing an object from an instrusive collection gives us back the
//! // Box<Test> that we originally inserted into it.
//! let a = list.pop_front().unwrap();
//! assert_eq!(a.value.get(), 4);
//! assert_eq!(list.iter().map(|x| x.value.get()).collect::<Vec<_>>(), [2, 1]);
//!
//! // Dropping the collection will automatically free b and c by
//! // transforming them back into Box<Test> and dropping them.
//! drop(list);
//! ```
//!
//! # Links and adapters
//!
//! Intrusive collections track objects through links which are embedded within
//! the objects themselves. It also allows a single object to be part of
//! multiple intrusive collections at once by having multiple links in it.
//!
//! The relationship between an object and a link inside it is described by the
//! `Adapter` trait. Intrusive collections use an implementation of this trait
//! to determine which link in an object should be used by the collection. In
//! most cases you do not need to write an implementation manually: the
//! `intrusive_adapter!` macro will automatically generate the necessary code.
//!
//! For red-black trees, the adapter must also implement the `KeyAdapter` trait
//! which allows a key to be extracted from an object. This key is then used to
//! keep all elements in the tree in ascending order.
//!
//! ```
//! use intrusive_collections::intrusive_adapter;
//! use intrusive_collections::{SinglyLinkedListLink, SinglyLinkedList};
//! use intrusive_collections::{LinkedListLink, LinkedList};
//! use intrusive_collections::{XorLinkedList, XorLinkedListLink};
//! use intrusive_collections::{RBTreeLink, RBTree, KeyAdapter};
//! use std::rc::Rc;
//!
//! // This struct can be inside three lists and one tree simultaneously
//! #[derive(Default)]
//! struct Test {
//!     link: LinkedListLink,
//!     link2: SinglyLinkedListLink,
//!     link3: XorLinkedListLink,
//!     link4: RBTreeLink,
//!     value: i32,
//! }
//!
//! intrusive_adapter!(MyAdapter = Rc<Test>: Test { link: LinkedListLink });
//! intrusive_adapter!(MyAdapter2 = Rc<Test>: Test { link2: SinglyLinkedListLink });
//! intrusive_adapter!(MyAdapter3 = Rc<Test>: Test { link3: XorLinkedListLink });
//! intrusive_adapter!(MyAdapter4 = Rc<Test>: Test { link4: RBTreeLink });
//! impl<'a> KeyAdapter<'a> for MyAdapter4 {
//!     type Key = i32;
//!     fn get_key(&self, x: &'a Test) -> i32 { x.value }
//! }
//!
//! let mut a = LinkedList::new(MyAdapter::new());
//! let mut b = SinglyLinkedList::new(MyAdapter2::new());
//! let mut c = XorLinkedList::new(MyAdapter3::new());
//! let mut d = RBTree::new(MyAdapter4::new());
//!
//! let test = Rc::new(Test::default());
//! a.push_front(test.clone());
//! b.push_front(test.clone());
//! c.push_front(test.clone());
//! d.insert(test);
//! ```
//!
//! # Cursors
//!
//! Intrusive collections are manipulated using cursors. A cursor is similar to
//! an iterator, except that it can freely seek back-and-forth, and can safely
//! mutate the list during iteration. This is similar to how a C++ iterator
//! works.
//!
//! A cursor views an intrusive collection as a circular list, with a special
//! null object between the last and first elements of the collection. A cursor
//! will either point to a valid object in the collection or to this special
//! null object.
//!
//! Cursors come in two forms: `Cursor` and `CursorMut`. A `Cursor` gives a
//! read-only view of a collection, but you are allowed to use multiple `Cursor`
//! objects simultaneously on the same collection. On the other hand,
//! `CursorMut` can be used to mutate the collection, but you may only use one
//! of them at a time.
//!
//! Cursors are a very powerful abstraction since they allow a collection to be
//! mutated safely while it is being iterated on. For example, here is a
//! function which removes all values within a given range from a `RBTree`:
//!
//! ```
//! use intrusive_collections::intrusive_adapter;
//! use intrusive_collections::{RBTreeLink, RBTree, KeyAdapter, Bound};
//!
//! struct Element {
//!     link: RBTreeLink,
//!     value: i32,
//! }
//!
//! intrusive_adapter!(ElementAdapter = Box<Element>: Element { link: RBTreeLink });
//! impl<'a> KeyAdapter<'a> for ElementAdapter {
//!     type Key = i32;
//!     fn get_key(&self, e: &'a Element) -> i32 { e.value }
//! }
//!
//! fn remove_range(tree: &mut RBTree<ElementAdapter>, min: i32, max: i32) {
//!     // Find the first element which is greater than or equal to min
//!     let mut cursor = tree.lower_bound_mut(Bound::Included(&min));
//!
//!     // Iterate over all elements in the range [min, max]
//!     while cursor.get().map_or(false, |e| e.value <= max) {
//!         // CursorMut::remove will return a Some(<Box<Element>), which we
//!         // simply drop here. This will also advance the cursor to the next
//!         // element.
//!         cursor.remove();
//!     }
//! }
//! ```
//!
//! # Scoped collections
//!
//! Instead of taking ownership of objects inserted into them, intrusive
//! collections can also work with borrowed values. This works by using
//! lifetimes and the borrow checker to ensure that any objects inserted into an
//! intrusive collection will outlive the collection itself.
//!
//! ```
//! use intrusive_collections::intrusive_adapter;
//! use intrusive_collections::{LinkedListLink, LinkedList};
//! use typed_arena::Arena;
//! use std::cell::Cell;
//!
//! struct Value {
//!     link: LinkedListLink,
//!     value: Cell<i32>,
//! }
//!
//! // Note that we use a plain reference as the pointer type for the collection.
//! intrusive_adapter!(ValueAdapter<'a> = &'a Value: Value { link: LinkedListLink });
//!
//! // Create an arena and a list. Note that since stack objects are dropped in
//! // reverse order, the Arena must be created before the LinkedList. This
//! // ensures that the list is dropped before the values are freed by the
//! // arena. This is enforced by the Rust lifetime system.
//! let arena = Arena::new();
//! let mut list = LinkedList::new(ValueAdapter::new());
//!
//! // We can now insert values allocated from the arena into the linked list
//! list.push_back(arena.alloc(Value {
//!     link: LinkedListLink::new(),
//!     value: Cell::new(1),
//! }));
//! list.push_back(arena.alloc(Value {
//!     link: LinkedListLink::new(),
//!     value: Cell::new(2),
//! }));
//! list.push_back(arena.alloc(Value {
//!     link: LinkedListLink::new(),
//!     value: Cell::new(3),
//! }));
//! assert_eq!(list.iter().map(|x| x.value.get()).collect::<Vec<_>>(), [1, 2, 3]);
//!
//! // We can also insert stack allocated values into an intrusive list.
//! // Again, the values must outlive the LinkedList.
//! let a = Value {
//!     link: LinkedListLink::new(),
//!     value: Cell::new(4),
//! };
//! let b = Value {
//!     link: LinkedListLink::new(),
//!     value: Cell::new(5),
//! };
//! let c = Value {
//!     link: LinkedListLink::new(),
//!     value: Cell::new(6),
//! };
//! let mut list2 = LinkedList::new(ValueAdapter::new());
//! list2.push_back(&a);
//! list2.push_back(&b);
//! list2.push_back(&c);
//! assert_eq!(list2.iter().map(|x| x.value.get()).collect::<Vec<_>>(), [4, 5, 6]);
//!
//! // Since these are shared references, any changes in the values are reflected in
//! // the list.
//! a.value.set(7);
//! assert_eq!(list2.iter().map(|x| x.value.get()).collect::<Vec<_>>(), [7, 5, 6]);
//! ```
//!
//! # Safety
//!
//! While it is possible to use intrusive collections without any unsafe code,
//! this crate also exposes a few unsafe features.
//!
//! The `cursor_from_ptr` and `cursor_mut_from_ptr` allow you to create a
//! cursor pointing to a specific element in the collection from a pointer to
//! that element. This is unsafe because it assumes that the objected pointed to
//! is currently inserted in the collection.
//!
//! The `UnsafeRef` type acts like `Rc`, except without the reference count.
//! Instead, you are responsible for keeping track of the number of active
//! references to an object and for freeing it once the last reference is
//! dropped. The advantage of `UnsafeRef` over `Rc` is that it reduces the size
//! of the allocation by two `usize` and avoids the overhead of maintaining
//! reference counts.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![no_std]
#![cfg_attr(feature = "nightly", feature(const_fn_trait_bound))]
#![allow(
    clippy::declare_interior_mutable_const,
    clippy::collapsible_if,
    clippy::collapsible_else_if
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
extern crate std;

mod unsafe_ref;
#[macro_use]
mod adapter;
mod key_adapter;
mod link_ops;
mod pointer_ops;
mod unchecked_option;

pub mod linked_list;
pub mod rbtree;
pub mod singly_linked_list;
pub mod xor_linked_list;

pub use crate::adapter::Adapter;
pub use crate::key_adapter::KeyAdapter;
pub use crate::link_ops::{DefaultLinkOps, LinkOps};
pub use crate::linked_list::AtomicLink as LinkedListAtomicLink;
pub use crate::linked_list::Link as LinkedListLink;
pub use crate::linked_list::LinkedList;
pub use crate::pointer_ops::{DefaultPointerOps, PointerOps};
pub use crate::rbtree::AtomicLink as RBTreeAtomicLink;
pub use crate::rbtree::Link as RBTreeLink;
pub use crate::rbtree::RBTree;
pub use crate::singly_linked_list::AtomicLink as SinglyLinkedListAtomicLink;
pub use crate::singly_linked_list::Link as SinglyLinkedListLink;
pub use crate::singly_linked_list::SinglyLinkedList;
pub use crate::unsafe_ref::UnsafeRef;
pub use crate::xor_linked_list::AtomicLink as XorLinkedListAtomicLink;
pub use crate::xor_linked_list::Link as XorLinkedListLink;
pub use crate::xor_linked_list::XorLinkedList;
pub use memoffset::offset_of;

/// An endpoint of a range of keys.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Bound<T> {
    /// An inclusive bound.
    Included(T),
    /// An exclusive bound.
    Excluded(T),
    /// An infinite endpoint. Indicates that there is no bound in this direction.
    Unbounded,
}
