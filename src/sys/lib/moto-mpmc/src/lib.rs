// Multi-producer multi-consumer channels for message passing.
// Ported from crossbeam-channel.

#![no_std]
#![feature(allocator_api)]
mod channel;
mod context;
mod counter;
mod err;
mod flavors;
mod select;
mod utils;
mod waker;

extern crate alloc;

pub use crate::{
    channel::{IntoIter, Iter, Receiver, Sender, TryIter, bounded, try_bounded},
    err::{RecvError, RecvTimeoutError, SendError, SendTimeoutError, TryRecvError, TrySendError},
};
