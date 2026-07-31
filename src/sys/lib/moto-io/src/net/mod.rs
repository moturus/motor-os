//! Motor OS native networking client (design section 5).
//!
//! Sibling of [`crate::fs`]: the TCP/UDP channel runtime and socket state
//! machines, plus an async-first API. Unlike `fs`, the net stack is
//! multi-threaded (thread-per-channel, caller-thread copies), so it uses
//! `Arc`/`Mutex`/atomics rather than the single-threaded `Rc`/`Cell` of `fs`.
//!
//! The Stage-F extraction moves the pieces here in dependency order; the vdso
//! keeps a thin veneer (poll-registry synthesis, the FD table, ABI shims).

pub mod channel;
pub mod inner_rx_stream;
pub mod readiness;
pub mod tcp;
pub mod udp;
mod wait;

/// The POSIX option ABI reports an outcome as a bare `ErrorCode`, while the
/// typed async setters report a `Result`.
fn into_error_code(result: Result<(), moto_rt::ErrorCode>) -> moto_rt::ErrorCode {
    match result {
        Ok(()) => moto_rt::E_OK,
        Err(err) => err,
    }
}
