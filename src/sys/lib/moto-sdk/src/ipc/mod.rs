//! Motor OS IPC: shared-memory I/O channels and synchronous RPC channels.

pub mod io_channel;
pub mod sync;

#[doc(hidden)]
pub mod stdio_pipe;
