// Multi-producer multi-consumer channels for message passing.
// Ported from crossbeam-channel.

#![no_std]
mod channel;
mod context;
mod counter;
mod err;
mod flavors;
mod select;
mod select_macro;
mod utils;
mod waker;

extern crate alloc;

// Crate internals used by the `select!` macro.
#[doc(hidden)]
pub mod internal {
    pub use crate::select::{select, select_timeout, try_select, SelectHandle};
}

pub use crate::{
    channel::{bounded, IntoIter, Iter, Receiver, Sender, TryIter},
    err::{
        ReadyTimeoutError, RecvError, RecvTimeoutError, SelectTimeoutError, SendError,
        SendTimeoutError, TryReadyError, TryRecvError, TrySelectError, TrySendError,
    },
    select::{Select, SelectedOperation},
};
