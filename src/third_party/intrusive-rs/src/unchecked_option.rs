// Copyright 2020 Amari Robinson
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::hint;

/// An extension trait on `Option`.
pub trait UncheckedOptionExt<T> {
    /// Returns the contained value.
    ///
    /// # Safety
    ///
    /// It is up to the caller to guarantee that the `Option<T>` is `Some(v)`.
    /// Calling this when it is `None` causes undefined behavior.
    unsafe fn unwrap_unchecked(self) -> T;
}

impl<T> UncheckedOptionExt<T> for Option<T> {
    #[inline]
    unsafe fn unwrap_unchecked(self) -> T {
        match self {
            Some(x) => x,
            None => {
                if cfg!(debug_assertions) {
                    unreachable!()
                } else {
                    hint::unreachable_unchecked()
                }
            }
        }
    }
}
