//! Motor OS native networking client (design section 5).
//!
//! Sibling of [`crate::fs`]: the TCP/UDP channel runtime and socket state
//! machines, plus an async-first API. Unlike `fs`, the net stack is
//! multi-threaded (thread-per-channel, caller-thread copies), so it uses
//! `Arc`/`Mutex`/atomics rather than the single-threaded `Rc`/`Cell` of `fs`.
//!
//! The Stage-F extraction moves the pieces here in dependency order; the vdso
//! keeps a thin veneer (poll-registry synthesis, the FD table, ABI shims).

pub mod readiness;
