//! Multi-producer multi-consumer channels for message passing: a port of the
//! bounded [crossbeam-channel](https://github.com/crossbeam-rs/crossbeam/tree/master/crossbeam-channel)
//! to Motor OS.

mod channel;
mod context;
mod counter;
mod err;
mod flavors;
mod select;
mod utils;
mod waker;

pub use self::{
    channel::{IntoIter, Iter, Receiver, Sender, TryIter, bounded, try_bounded},
    err::{RecvError, RecvTimeoutError, SendError, SendTimeoutError, TryRecvError, TrySendError},
};
