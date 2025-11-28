//! Low-level no-std async stuff for Motor OS.
//!
//! We try to build Motor OS Rust runtime (as in rt.vdso, and in sys-io)
//! using async Rust, so we cannot use Rust stdlib, as it depends on
//! Motor OS runtime. And we couldn't find a no-std async framework/executor
//! that we liked in 2025-08.
//!
//! More specifically, we need a weird system that
//! (a) allows local async (i.e. !Send, !Sync, no 'static runtimes, no boxing), and
//! (b) delegates I/O to a separate "I/O runtime", which runs in its own thread,
//!     and is also using a local executor/futures.
//!
//! Example: an in-process "runtime" built around an IO channel (a ring buffer),
//!          and the ability to do (async) I/O from many threads in the process.
//!
//! Thus we need two types of "tasks": a purely local task that can be "executed"
//! on the local thread, and an "IO task" that is "posted" to the IO executor, gets
//! executed there until completion, and then "completed" in the original local
//! executor/thread. All without arc/mutex/static stuff (well, we'll need some
//! of that for cross-thread communication, but hopefully copy types + atomics
//! will be enough).

#![no_std]
#![feature(box_as_ptr)]
#![feature(likely_unlikely)]
#![feature(local_waker)]

mod local_runtime;
mod mutex;
pub mod oneshot;
mod time;
mod timeq;

pub use local_runtime::*;
pub use mutex::{LocalMutex, LocalMutexGuard};
pub use oneshot::oneshot;
pub use time::{Instant, Sleep, sleep};
