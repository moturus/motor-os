// Copyright 2016 Amanieu d'Antras
// Copyright 2020 Amari Robinson
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::adapter::Adapter;
use crate::pointer_ops::PointerOps;

/// Extension of the `Adapter` trait to provide a way of extracting a key from
/// an object. This key can then be used as an index in certain intrusive
/// collections (currently only `RBTree` uses this).
///
/// The key can be returned either as a value or as a reference, which allows
/// you to
///
/// # Examples
///
/// ```
/// use intrusive_collections::intrusive_adapter;
/// use intrusive_collections::{RBTreeLink, KeyAdapter};
///
/// struct S {
///     link: RBTreeLink,
///     key: u32,
///     value: u64,
/// }
///
/// // Adapter which returns a key by value
/// intrusive_adapter!(MyAdapter = Box<S>: S { link : RBTreeLink });
/// impl<'a> KeyAdapter<'a> for MyAdapter {
///     type Key = u32;
///     fn get_key(&self, s: &'a S) -> u32 { s.key }
/// }
///
/// // Adapter which returns a key by reference
/// intrusive_adapter!(MyAdapter2 = Box<S>: S { link : RBTreeLink });
/// impl<'a> KeyAdapter<'a> for MyAdapter2 {
///     type Key = &'a u32;
///     fn get_key(&self, s: &'a S) -> &'a u32 { &s.key }
/// }
///
/// struct U {
///     link: RBTreeLink,
///     key1: i32,
///     key2: String,
///     key3: f64,
/// }
///
/// // Adapter which returns a tuple as a key. When used in a RBTree, this will
/// // keep all elements sorted by `key1` first, then `key2` and finally `key3`.
/// intrusive_adapter!(MyAdapter3 = Box<U>: U { link : RBTreeLink });
/// impl<'a> KeyAdapter<'a> for MyAdapter3 {
///     type Key = (i32, &'a str, f64);
///     fn get_key(&self, u: &'a U) -> Self::Key { (u.key1, &u.key2, u.key3) }
/// }
/// ```
pub trait KeyAdapter<'a>: Adapter {
    /// Type of the key returned by `get_key`.
    type Key;

    /// Gets the key for the given object.
    fn get_key(&self, value: &'a <Self::PointerOps as PointerOps>::Value) -> Self::Key;
}
