// Copyright 2020 Amari Robinson
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/// Base trait for link operations.
///
/// `LinkPtr` is the representation of a link pointer.
/// Typically this is `NonNull`, but compact representations such
/// as `u8` or `u16` are possible.
pub unsafe trait LinkOps {
    /// The link pointer type.
    type LinkPtr: Copy + Eq;

    /// Attempts to acquire ownership of a link so that it can be used in an
    /// intrusive collection.
    ///
    /// If this function succeeds then the intrusive collection will have
    /// exclusive access to the link until `release_link` is called.
    unsafe fn acquire_link(&mut self, ptr: Self::LinkPtr) -> bool;

    /// Releases ownership of a link that was previously acquired with `acquire_link`.
    ///
    /// # Safety
    /// An implementation of `release_link` must not panic.
    unsafe fn release_link(&mut self, ptr: Self::LinkPtr);
}

/// The default implementation of `LinkOps` associated with a link type.
pub trait DefaultLinkOps {
    /// The default link operations.
    type Ops: LinkOps + Default;

    /// The associated constant that represents `Ops::default()`.
    ///
    /// This exists because `Default::default()` is not a constant function.
    const NEW: Self::Ops;
}
